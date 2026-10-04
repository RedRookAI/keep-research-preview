// Local qualification only. This runner never prepares or changes a shared host.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { ProcessIsolationAdapter } from "../dist/src/infra/process_isolation.js";

if (process.argv.length !== 2) throw new Error("usage: node tools/qualify_project_jail.mjs");
const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const output = join(root, "docs/qualification/project-jail-evidence.json");
const tests = ["required_project_jail", "required_project_jail_layout", "required_project_jail_options",
  "default_execution_jail", "sandboxed_runner", "namespace_jail_default"];
const inputs = ["tools/qualify_project_jail.mjs", "tools/bubblewrap/identity.json",
  "src/infra/required_project_jail.ts", "src/infra/process_isolation.ts",
  "dist/src/infra/required_project_jail.js", "dist/src/infra/process_isolation.js", "dist/test/_netguard.js",
  ...tests.flatMap(name => [`test/${name}.test.ts`, `dist/test/${name}.test.js`])];
const sha = bytes => createHash("sha256").update(bytes).digest("hex");
const inventory = () => Object.fromEntries(inputs.map(path => [path, sha(readFileSync(join(root, path)))]));
const before = inventory();
const deadline = Date.now() + 20 * 60_000;
const evidence = { schema: "keep.project-jail-qualification/v1", status: "INCOMPLETE", startedAt: new Date().toISOString(),
  sourceInputs: before, executable: JSON.parse(readFileSync(join(root, "tools/bubblewrap/identity.json"), "utf8")),
  runtime: { node: process.version, platform: process.platform, arch: process.arch, uid: process.getuid?.() },
  selectedTests: tests, phases: [],
  limits: "Local TypeScript required-jail qualification only; no native, aggregate resource, organization custody or deployment claim. Run under an externally enforced 2 CPU/4 GiB/512 PID envelope; this runner supplies a shared 20-minute deadline." };
const fixture = mkdtempSync(join(tmpdir(), "keep-jail-qualification-"));
try {
  const project = join(fixture, "project"), input = join(fixture, "input"), sibling = join(fixture, "sibling");
  for (const path of [project, input, sibling]) mkdirSync(path, { mode: 0o700 });
  const readonly = join(input, "value"), outside = join(sibling, "value"), marker = join(project, "entered");
  writeFileSync(readonly, "qualified-input"); writeFileSync(outside, "unchanged");
  const code = `const fs=require('node:fs'),a=require('node:assert/strict');
    a.equal(fs.readFileSync(${JSON.stringify(readonly)},'utf8'),'qualified-input');
    a.throws(()=>fs.writeFileSync(${JSON.stringify(readonly)},'wrong'));
    a.throws(()=>fs.writeFileSync(${JSON.stringify(outside)},'wrong'));
    fs.writeFileSync(${JSON.stringify(marker)},'useful-work');`;
  const result = await new ProcessIsolationAdapter().run(process.execPath, ["-e", code], {
    cwd: project, timeoutMs: 10_000, maxOutputBytes: 64 * 1024,
    namespaceJail: { mode: "required", projectDir: project, readOnlyPaths: [input] },
  });
  const actual = { taskEntered: existsSync(marker), marker: existsSync(marker) ? readFileSync(marker, "utf8") : null,
    input: readFileSync(readonly, "utf8"), outside: readFileSync(outside, "utf8") };
  evidence.phases.push({ name: "actual-useful-work-preflight", result, actual });
  assert.equal(result.processIsolation?.namespaceSetup, "launcher-confirmed", "real required setup remains unqualified");
  assert.equal(result.code, 0, "preflight task failed");
  assert.deepEqual(actual, { taskEntered: true, marker: "useful-work", input: "qualified-input", outside: "unchanged" });
  const childEnv = { ...process.env }; delete childEnv.NODE_TEST_CONTEXT;
  const args = ["--import", "./dist/test/_netguard.js", "--test", "--test-concurrency=1", "--test-reporter=tap",
    ...tests.map(name => `dist/test/${name}.test.js`)];
  const testResult = spawnSync(process.execPath, args, { cwd: root, env: childEnv, encoding: "utf8",
    timeout: Math.max(1, deadline - Date.now()), maxBuffer: 8 * 1024 * 1024, killSignal: "SIGKILL" });
  evidence.phases.push({ name: "complete-selected-jail-tests", command: [process.execPath, ...args],
    status: testResult.status, signal: testResult.signal, error: testResult.error?.message,
    stdout: testResult.stdout, stderr: testResult.stderr });
  assert.equal(testResult.error, undefined); assert.equal(testResult.status, 0);
  const count = Number(testResult.stdout.match(/^# tests (\d+)$/mu)?.[1]);
  assert.ok(count > 0, "no executed test count");
  assert.match(testResult.stdout, /^# fail 0$/mu);
  assert.doesNotMatch(testResult.stdout, /^# skipped [1-9]/mu, "missing cases cannot qualify this profile");
  assert.deepEqual(inventory(), before, "qualification inputs changed");
  assert.ok(Date.now() <= deadline, "shared qualification deadline exceeded");
  evidence.status = "PASS";
} catch (error) {
  evidence.failure = error instanceof Error ? error.message : String(error);
  evidence.status = "NOT_QUALIFIED";
  process.exitCode = 1;
} finally {
  rmSync(fixture, { recursive: true, force: true });
  evidence.completedAt = new Date().toISOString();
  evidence.sourceInputsUnchanged = JSON.stringify(inventory()) === JSON.stringify(before);
  if (!evidence.sourceInputsUnchanged) { evidence.status = "NOT_QUALIFIED"; process.exitCode = 1; }
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, JSON.stringify(evidence, null, 2) + "\n", { mode: 0o600 });
  process.stdout.write(JSON.stringify({ status: evidence.status, evidence: output, failure: evidence.failure }) + "\n");
}
