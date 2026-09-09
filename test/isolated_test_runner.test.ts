import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IsolatedTestRunner, ProcessIsolationExecutor } from "../src/isolation/isolated_executor.js";
import { SandboxedCommandRunner } from "../src/solve/sandboxed_runner.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";

function spine(): Spine { return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-iso-"))), new InProcessLock(), new SchemaRegistry()); }
let innerRuns = 0;
const green: TestRunner = { async run(): Promise<TestRunResult> { innerRuns++; return { results: [{ name: "t", passed: true }] }; } };
const events = (s: Spine) => s.currentEvents().map((e) => (e.payload as Record<string, unknown>)["event"]);

test("ISO: a normal run executes inside process isolation and emits a signed audit event", async () => {
  const s = spine();
  const dir = mkdtempSync(join(tmpdir(), "keep-iso-project-"));
  const inner = new SandboxedCommandRunner({ command: "node", args: ["-e", `console.log("ok 1 - t")`], projectDir: dir });
  const runner = new IsolatedTestRunner(inner, new ProcessIsolationExecutor(s), dir, () => "medium");
  const r = await runner.run("proj/pkg");
  assert.equal(r.results[0]!.passed, true, "the inner tests ran");
  assert.ok(events(s).includes("isolated_execution"), "every isolated execution is audited");
});

test("ISO SAFETY: ticket repository metadata cannot redirect execution away from the resolved project root", async () => {
  const s = spine();
  const dir = mkdtempSync(join(tmpdir(), "keep-iso-project-"));
  const check = `if (process.cwd() !== ${JSON.stringify(dir)}) process.exit(9); console.log("ok 1 - rooted")`;
  const runner = new IsolatedTestRunner(new SandboxedCommandRunner({ command: "node", args: ["-e", check], projectDir: dir }), new ProcessIsolationExecutor(s), dir, () => "low");
  const r = await runner.run("../../etc/passwd");
  assert.equal(r.results[0]!.passed, true);
});

test("ISO SAFETY: a HIGH-risk patch under process isolation is REFUSED (insufficient boundary)", async () => {
  innerRuns = 0;
  const s = spine();
  const runner = new IsolatedTestRunner(green, new ProcessIsolationExecutor(s), "/proj", () => "high");
  const r = await runner.run("proj/pkg");
  assert.equal(innerRuns, 0, "high-risk untrusted code is not executed under mere process scoping");
  assert.ok(r.runnerError, "refused → runner error, not a pass");
});

test("ISO: the refusal is FAIL-CLOSED — validate reads it as not-passed", async () => {
  const { validate } = await import("../src/solve/validate.js");
  const s = spine();
  const runner = new IsolatedTestRunner(green, new ProcessIsolationExecutor(s), "/proj", () => "high");
  const v = await validate("proj/pkg", runner);
  assert.equal(v.testsPassed, false, "a refused (non-)execution can never report tests passing");
});
