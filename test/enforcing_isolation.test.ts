import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ProcessIsolationExecutor, buildEnforcingRunner } from "../src/isolation/isolated_executor.js";
import { SandboxedCommandRunner } from "../src/solve/sandboxed_runner.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";

function spine(): Spine { return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-enf-"))), new InProcessLock(), new SchemaRegistry()); }
function isoEvents(s: Spine): string[] {
  return s.replay().map((e: any) => e.payload as Record<string, unknown>).filter((p) => p?.["event"] === "isolated_execution").map((p) => String(p["detail"]));
}

test("REALPATH JAIL (executor): a symlink-out repoRef is REFUSED — inner never runs", async () => {
  const base = mkdtempSync(join(tmpdir(), "keep-enf-jail-"));
  mkdirSync(join(base, "src"));
  symlinkSync("/etc", join(base, "escape")); // a link inside the project pointing OUT
  let innerRuns = 0;
  const inner: TestRunner = { async run(): Promise<TestRunResult> { innerRuns++; return { results: [{ name: "x", passed: true }] }; } };
  const exec = new ProcessIsolationExecutor(spine());
  const out = await exec.runIsolated(inner, { projectDir: base, repoRef: "escape/passwd", patchRisk: "medium" });
  assert.equal(out.executed, false, "the symlink-out scope was refused");
  assert.equal(innerRuns, 0, "the untrusted runner never ran outside the jail");
});

test("EXECUTOR TIMEOUT: an opaque in-process runner that hangs is bounded (fail-closed), never a green", async () => {
  const base = mkdtempSync(join(tmpdir(), "keep-enf-to-"));
  const hanging: TestRunner = { run(): Promise<TestRunResult> { return new Promise(() => {}); } }; // never resolves
  const exec = new ProcessIsolationExecutor(spine(), { timeoutMs: 400 });
  const out = await exec.runIsolated(hanging, { projectDir: base, repoRef: ".", patchRisk: "medium" });
  assert.equal(out.executed, true, "the callback was invoked; timing out does not undo that fact");
  assert.equal(out.completion, "unconfirmed");
  assert.equal(out.lifecycleContractVersion, 2);
  assert.match(out.result?.runnerError ?? "", /exceeded.*unconfirmed/i);
  assert.equal(out.result?.results.length, 0, "a hang never supplies passing test evidence");
  assert.doesNotMatch(JSON.stringify(out), /killed/i, "no kill mechanism exists for the opaque callback");
});

test("ENFORCING PATH (crown): buildEnforcingRunner runs a REAL command resource-bounded + jailed + audited", async () => {
  const base = mkdtempSync(join(tmpdir(), "keep-enf-e2e-"));
  writeFileSync(join(base, "ok.test.mjs"),
    `import { test } from "node:test"; import assert from "node:assert/strict";\ntest("passes", () => assert.equal(2+2, 4));\n`);
  const s = spine();
  const runner = buildEnforcingRunner(base, "node", ["--test"], { spine: s, timeoutMs: 30_000 });
  const r = await runner.run(base);
  assert.equal(r.runnerError, undefined, "the sandboxed command executed");
  assert.ok(r.results.length > 0 && r.results.every((c) => c.passed), "the real test passed inside the boundary");
  await s.seal();
  const details = isoEvents(s);
  assert.ok(details.some((d) => d.includes("resource-bounded command")), "the executor audited a resource-bounded command run");
});

test("ENFORCING PATH refuses a hostile CPU-hog command within its CPU bound", async () => {
  const base = mkdtempSync(join(tmpdir(), "keep-enf-cpu-"));
  // The 'test command' is a CPU spinner — bounded by the sandbox CPU limit, surfaced as a runner error (not a pass).
  const runner = buildEnforcingRunner(base, "node", ["-e", "while(true){ Math.sqrt(Math.random()); }"], { timeoutMs: 20_000, cpuLimitSec: 2 });
  const r = await runner.run(base);
  assert.notEqual(r.results.length > 0 && r.results.every((c) => c.passed), true, "a CPU-hog never reports a clean pass");
});

test("the fully-enforcing runner IS command-bounded (audit distinguishes it from an in-process runner)", async () => {
  const base = mkdtempSync(join(tmpdir(), "keep-enf-kind-"));
  writeFileSync(join(base, "t.test.mjs"), `import { test } from "node:test"; test("p", () => {});\n`);
  const inner = new SandboxedCommandRunner({ command: "node", args: ["--test"], projectDir: base, timeoutMs: 20_000 });
  const s = spine();
  const exec = new ProcessIsolationExecutor(s);
  await exec.runIsolated(inner, { projectDir: base, repoRef: ".", patchRisk: "medium" });
  await s.seal();
  assert.ok(isoEvents(s).some((d) => d.includes("resource-bounded command")), "a SandboxedCommandRunner is recognized as resource-bounded");
});
