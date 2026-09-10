import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { delimiter, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";

const root = process.cwd();
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
  scripts: Record<string, string>; files: string[];
  repository?: unknown; bugs?: unknown; homepage?: unknown;
};
const publicDocs = ["README.md", "WORKFLOW.md", "CLAUDE.md", "SECURITY.md",
  "docs/research-preview.md", "docs/research.md", "docs/evidence.md", "docs/licensing.md", "docs/semantic-memory.md", "docs/skill-registry.md"];

test("public instructions have existing local links and no private planning or card prerequisites", () => {
  for (const name of publicDocs) {
    const text = readFileSync(join(root, name), "utf8");
    assert.doesNotMatch(text, /\/root\/keep|keep-canonical|keep-tarball-backup/u, name);
    assert.doesNotMatch(text, /npm run (?:workflow:status|writer:|discipline:)/u, name);
    for (const match of text.matchAll(/\[[^\]]+\]\(([^)]+)\)/gu)) {
      const target = match[1]!;
      if (/^(?:https?:|#)/u.test(target)) continue;
      const local = target.split("#")[0]!;
      assert.ok(existsSync(resolve(root, dirname(name), local)), `${name}: broken link ${target}`);
      const fragment = target.split("#")[1];
      if (fragment && local.endsWith(".md")) {
        const contents = readFileSync(resolve(root, dirname(name), local), "utf8");
        const headings = [...contents.matchAll(/^#{1,6} (.+)$/gmu)].map(m => m[1]!.toLowerCase().replace(/[^\p{L}\p{N}_\- ]/gu, "").replace(/ /gu, "-"));
        assert.ok(headings.includes(fragment), `${name}: missing heading ${target}`);
      }
    }
  }
});

test("public npm interface resolves real source commands and exposes no archived workflow aliases", () => {
  for (const [name, command] of Object.entries(pkg.scripts)) {
    assert.doesNotMatch(name, /^(?:workflow:|writer:|discipline:|guard$|evidence:freeze-)/u);
    assert.doesNotMatch(command, /discipline_|writer_lease|outcome_card|round_guard|review_evidence_guard|research_evidence_guard|capture_claude_review|canonical_consolidation_guard/u);
    for (const match of command.matchAll(/\bnode ((?:tools|acceptance)\/[^\s]+\.mjs)/gu))
      assert.ok(existsSync(join(root, match[1]!)), `${name}: missing command ${match[1]}`);
  }
  assert.equal(pkg.scripts.test, "npm run test:full");
  assert.match(pkg.scripts["test:full"]!, /npm run build.*run_full_tests/u);
  assert.doesNotMatch(pkg.scripts["test:portable"]!, /build_native_transport|npm run build/u);
  assert.equal(pkg.scripts["demo:recovery"], "node acceptance/installed_sg32_resources.mjs");
});

test("npm demo and swe-eval execute compiled targets without destroying or rebuilding the distribution", () => {
  for (const [name, target] of [["demo", "dist/src/demo/flagship.js"], ["swe-eval", "dist/src/eval/swe_eval.js"]] as const) {
    const fixture = mkdtempSync(join(tmpdir(), "keep-public-script-"));
    try {
      mkdirSync(dirname(join(fixture, target)), { recursive: true });
      writeFileSync(join(fixture, target), `process.stdout.write(${JSON.stringify(name + ":executed")});\n`);
      writeFileSync(join(fixture, "dist/sentinel"), "existing distribution");
      writeFileSync(join(fixture, "package.json"), JSON.stringify({ private: true, scripts: { [name]: pkg.scripts[name] } }));
      writeFileSync(join(fixture, "user.npmrc"), "");
      writeFileSync(join(fixture, "global.npmrc"), "");
      const result = spawnSync("npm", ["run", "--silent", name,
        "--userconfig=" + join(fixture, "user.npmrc"), "--globalconfig=" + join(fixture, "global.npmrc")], {
        cwd: fixture, encoding: "utf8", timeout: 15000,
        env: { PATH: [dirname(process.execPath), process.env.PATH ?? ""].join(delimiter), LANG: "C", npm_config_offline: "true", npm_config_update_notifier: "false" },
      });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, name + ":executed");
      assert.equal(readFileSync(join(fixture, "dist/sentinel"), "utf8"), "existing distribution");
    } finally { rmSync(fixture, { recursive: true, force: true }); }
  }
});

test("preview's installed demo and limitations are included without inventing a public repository", () => {
  for (const path of ["acceptance/installed_sg32_resources.mjs", "docs/research-preview.md", "docs/research.md", "docs/evidence.md", "docs/skill-registry.md", "SECURITY.md", "WORKFLOW.md"])
    assert.ok(pkg.files.includes(path), "package missing " + path);
  // Publication approval must choose a real destination; no private or invented URL.
  for (const value of [pkg.repository, pkg.bugs, pkg.homepage])
    assert.ok(value === undefined || !JSON.stringify(value).includes("keep-canonical"));
});

test("full runner retains product tests and distinguishes partial/portable profiles", () => {
  const runner = readFileSync(join(root, "tools/run_full_tests.mjs"), "utf8");
  assert.match(runner, /endsWith\("\.test\.js"\)/u);
  assert.match(runner, /run\("ordinary"[\s\S]*run\("native"/u);
  assert.match(runner, /PARTIAL phase only/u);
  assert.match(runner, /portable && completeArtifact\.includes\(name\)/u);
  assert.match(runner, /delete childEnv\.NODE_TEST_CONTEXT/u);
  assert.doesNotMatch(runner, /outcome_card|writer_lease|discipline_guard/u);
});

test("documented expected-checksum gate stops before install on mismatch or missing inputs", () => {
  const guide = readFileSync(join(root, "docs/research-preview.md"), "utf8");
  const block = guide.match(/~~~sh\n(\(\n[\s\S]*?\n\))\n~~~/u)?.[1];
  assert.ok(block, "documented install block missing");
  for (const variant of ["matching", "mismatch", "malformed", "unset", "missing-archive"] as const) {
    const fixture = mkdtempSync(join(tmpdir(), "keep-checksum-guide-"));
    try {
      const bytes = Buffer.from("synthetic archive: never installed or executed\n");
      if (variant !== "missing-archive") writeFileSync(join(fixture, "keep-0.0.1.tgz"), bytes);
      const bin = join(fixture, "bin"), sentinel = join(fixture, "calls");
      mkdirSync(bin);
      for (const name of ["npm", "node"])
        writeFileSync(join(bin, name), `#!/bin/sh\nprintf '%s\\n' '${name}' >> "$KEEP_CHECK_SENTINEL"\n`, { mode: 0o755 });
      const env: NodeJS.ProcessEnv = { PATH: `${bin}:/usr/bin:/bin`, LANG: "C", TMPDIR: fixture, KEEP_CHECK_SENTINEL: sentinel };
      if (variant !== "unset") env.KEEP_RELEASE_SHA256 = variant === "mismatch" ? "0".repeat(64) : variant === "malformed" ? "not-a-checksum" : createHash("sha256").update(bytes).digest("hex");
      const result: ReturnType<typeof spawnSync> = spawnSync("/bin/sh", ["-c", block], { cwd: fixture, env, encoding: "utf8", timeout: 5000 });
      if (variant === "matching") {
        assert.equal(result.status, 0, String(result.stderr));
        assert.equal(readFileSync(sentinel, "utf8"), "npm\nnode\n");
      } else {
        assert.notEqual(result.status, 0, variant);
        assert.equal(existsSync(sentinel), false, `${variant} reached installation`);
      }
    } finally { rmSync(fixture, { recursive: true, force: true }); }
  }
});
