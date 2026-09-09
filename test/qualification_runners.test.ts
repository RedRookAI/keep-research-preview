import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const fullRunner = resolve("tools/run_full_tests.mjs");
const installedRunner = resolve("tools/run_installed_golden_journeys.mjs");
function fixture() {
  const root = mkdtempSync(join(tmpdir(), "keep-runner-controls-"));
  mkdirSync(join(root, "dist/test"), { recursive: true });
  writeFileSync(join(root, "dist/test/_netguard.js"), "");
  writeFileSync(join(root, "package.json"), JSON.stringify({ type: "module", name: "keep", version: "1.0.0", scripts: { prepare: "node -e 'process.exit(88)'" } }));
  const events = join(root, "events.jsonl");
  for (const name of ["ordinary", "tenant_deployment_admission", "capability_graph_v2", "native_fixture"]) {
    writeFileSync(join(root, `dist/test/${name}.test.js`), `import {test} from 'node:test'; import {appendFileSync} from 'node:fs'; test('${name}',async()=>{const emit=kind=>appendFileSync(${JSON.stringify(events)},JSON.stringify({kind,name:${JSON.stringify(name)},profile:process.env.KEEP_ASSURANCE_PROFILE})+'\\n');emit('start');await new Promise(r=>setTimeout(r,80));emit('end');});`);
  }
  return { root, events, dispose: () => rmSync(root, { recursive: true, force: true }) };
}
function run(script: string, root: string, args: string[] = [], extra: NodeJS.ProcessEnv = {}) {
  return spawnSync(process.execPath, [script, ...args], { cwd: root, env: { ...process.env, ...extra }, encoding: "utf8", timeout: 30_000, maxBuffer: 2 * 1024 * 1024 });
}
function rows(path: string): { kind: string; name: string; profile: string }[] {
  return existsSync(path) ? readFileSync(path, "utf8").trim().split("\n").map(line => JSON.parse(line)) : [];
}
function nativeFixtures(root: string) {
  const target = join(root, "native/target/x86_64-unknown-linux-musl/debug");
  mkdirSync(target, { recursive: true });
  for (const name of ["keep-native-protocol-oracle", "keep-native-p2-d2-overlay-oracle"]) writeFileSync(join(target, name), "fixture, not a native qualification oracle");
}

test("qualification runner defaults to serial complete profile and overrides ambient portable skips", () => {
  const f = fixture();
  try {
    nativeFixtures(f.root);
    const result = run(fullRunner, f.root, [], { KEEP_ASSURANCE_PROFILE: "portable" });
    assert.equal(result.status, 0, result.stderr);
    const seen = rows(f.events); let live = 0, peak = 0;
    for (const row of seen) { live += row.kind === "start" ? 1 : -1; peak = Math.max(peak, live); assert.equal(row.profile, "full"); }
    assert.equal(peak, 1); assert.equal(live, 0);
    assert.deepEqual(seen.filter(r => r.kind === "start").map(r => r.name), ["ordinary", "tenant_deployment_admission", "capability_graph_v2", "native_fixture"]);
  } finally { f.dispose(); }
});

test("explicit workers and partial phases schedule only the declared work without claiming full qualification", () => {
  const f = fixture();
  try {
    const result = run(fullRunner, f.root, ["--workers=2", "--phase=ordinary", "--reporter=tap"]);
    assert.equal(result.status, 0, result.stderr); assert.match(result.stdout, /PARTIAL phase only/);
    const seen = rows(f.events); let live = 0, peak = 0;
    for (const row of seen) { live += row.kind === "start" ? 1 : -1; peak = Math.max(peak, live); }
    assert.ok(peak <= 2); assert.equal(seen.filter(r => r.kind === "start").length, 2);
    assert.ok(seen.every(r => ["ordinary", "tenant_deployment_admission"].includes(r.name)));
  } finally { f.dispose(); }
});

test("portable profile retains ordinary/security assertions and does not implicitly build native fixtures", () => {
  const f = fixture();
  try {
    const result = run(fullRunner, f.root, ["--portable"]);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(rows(f.events).filter(r => r.kind === "start").map(r => r.name), ["ordinary", "capability_graph_v2"]);
    assert.ok(rows(f.events).every(r => r.profile === "portable"));
    assert.equal(existsSync(join(f.root, "native")), false);
  } finally { f.dispose(); }
});

test("invalid selection, absent native fixtures, empty phase and exhausted budget refuse without unrelated dispatch", () => {
  const f = fixture();
  try {
    for (const args of [["--workers=0"], ["--workers=2", "--workers=3"], ["--portable", "--phase=native"], ["--unknown"], []]) {
      const result = run(fullRunner, f.root, args); assert.notEqual(result.status, 0); assert.deepEqual(rows(f.events), []);
    }
    rmSync(join(f.root, "dist/test/capability_graph_v2.test.js"));
    const empty = run(fullRunner, f.root, ["--phase=release-security"]);
    assert.notEqual(empty.status, 0); assert.match(empty.stderr, /required phase has no test files/);
    const timeout = run(fullRunner, f.root, ["--phase=ordinary", "--timeout-ms=1"]);
    assert.notEqual(timeout.status, 0); assert.doesNotMatch(timeout.stdout, /release\/security:|native: 1/);
  } finally { f.dispose(); }
});

test("fixture preparation requires explicit selection and is not repeated once outputs exist", () => {
  const f = fixture();
  try {
    mkdirSync(join(f.root, "tools"));
    writeFileSync(join(f.root, "tools/native_p1_gate.mjs"), `import {mkdirSync,writeFileSync,appendFileSync} from 'node:fs';const target='native/target/x86_64-unknown-linux-musl/debug';mkdirSync(target,{recursive:true});for(const n of ['keep-native-protocol-oracle','keep-native-p2-d2-overlay-oracle'])writeFileSync(target+'/'+n,'fixture');appendFileSync('builds','one\\n');`);
    for (let i = 0; i < 2; i++) { const r = run(fullRunner, f.root, ["--phase=native", "--build-native-fixtures"]); assert.equal(r.status, 0, r.stderr); }
    assert.equal(readFileSync(join(f.root, "builds"), "utf8"), "one\n");
  } finally { f.dispose(); }
});

test("named child failure is streamed and prevents later qualification phases", () => {
  const f = fixture();
  try {
    writeFileSync(join(f.root, "dist/test/ordinary.test.js"), "import {test} from 'node:test';test('actual failing invariant',()=>{throw Error('runner control falsifier')});");
    const r = run(fullRunner, f.root, ["--portable"]); assert.notEqual(r.status, 0); assert.match(r.stdout, /actual failing invariant/);
    assert.deepEqual(rows(f.events), []);
  } finally { f.dispose(); }
});

test("installed runner consumes exact retained bytes through real offline npm without pack or prepare", () => {
  const f = fixture();
  try {
    const packageDir = join(f.root, "payload/package"); mkdirSync(packageDir, { recursive: true });
    writeFileSync(join(packageDir, "package.json"), JSON.stringify({ name: "keep", version: "1.0.0", type: "module", scripts: { install: "node -e 'process.exit(89)'" } }));
    writeFileSync(join(packageDir, "index.js"), "export const retained = 'exact-payload';");
    mkdirSync(join(packageDir, "native"));
    writeFileSync(join(packageDir, "native/toolchain-lock.json"), JSON.stringify({ toolchain: "fixture-pinned-compiler" }));
    const tarball = join(f.root, "input.tgz");
    const packed = spawnSync("tar", ["-czf", tarball, "-C", join(f.root, "payload"), "package"], { encoding: "utf8" }); assert.equal(packed.status, 0, packed.stderr);
    const digest = createHash("sha256").update(readFileSync(tarball)).digest("hex");
    mkdirSync(join(f.root, "acceptance"));
    for (const name of ["n1_golden_journey", "enterprise_golden_journey", "sg01_recovery_journey", "bounded_recovery", "sg02_capture_journey"]) {
      writeFileSync(join(f.root, `acceptance/installed_${name}.test.mjs`), `import {test} from 'node:test';import assert from 'node:assert/strict';import {pathToFileURL} from 'node:url';const keep=await import(pathToFileURL(process.env.KEEP_INSTALLED_PACKAGE_ROOT+'/index.js'));test(${JSON.stringify(name)},()=>{assert.equal(keep.retained,'exact-payload');assert.equal(process.env.KEEP_P1_TOOLCHAIN_ROOT,'/fixture/explicit-pinned-compiler');});`);
    }
    const r = run(installedRunner, f.root, [`--tarball=${tarball}`, `--sha256=${digest}`], { KEEP_P1_TOOLCHAIN_ROOT: "/fixture/explicit-pinned-compiler" });
    assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, /paired n1\/enterprise selection/); assert.match(r.stdout, /# pass 5/);
    assert.doesNotMatch(r.stdout, /building one new package/); assert.match(r.stdout, new RegExp(digest));
    const fixtureMatch = /fixture=([^\n]+); paired/u.exec(r.stdout);
    assert.ok(fixtureMatch?.[1]);
    const installedFixture = fixtureMatch[1];
    assert.ok(installedFixture.startsWith(join(tmpdir(), "keep-installed-journeys-")));
    assert.equal(createHash("sha256").update(readFileSync(join(installedFixture, "retained-input.tgz"))).digest("hex"), digest);
    rmSync(installedFixture, { recursive: true, force: true });
    const wrong = run(installedRunner, f.root, [`--tarball=${tarball}`, `--sha256=${"0".repeat(64)}`]); assert.notEqual(wrong.status, 0); assert.match(wrong.stderr, /SHA256 mismatch/); assert.doesNotMatch(wrong.stdout, /fixture=/);
    const missing = run(installedRunner, f.root, [`--tarball=${tarball}`]); assert.notEqual(missing.status, 0); assert.match(missing.stderr, /supplied together/);
    symlinkSync(tarball, join(f.root, "linked.tgz"));
    const linked = run(installedRunner, f.root, [`--tarball=${join(f.root, "linked.tgz")}`, `--sha256=${digest}`]); assert.notEqual(linked.status, 0); assert.doesNotMatch(linked.stdout, /fixture=/);
  } finally { f.dispose(); }
});
