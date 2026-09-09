import { test } from "node:test";
import assert from "node:assert/strict";

import { runLoadedEvalSuite } from "../src/eval/eval_run.js";
import type { SwebenchRecord } from "../src/eval/swebench_loader.js";
import type { InstanceRunner } from "../src/eval/harness.js";
import type { EvalTask, TestExecution } from "../src/eval/swebench_task.js";
import type { SolveResult } from "../src/solve/issue_model.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function spine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-evalrun-"))), new InProcessLock(), new SchemaRegistry());
}

function record(id: string, over: Partial<SwebenchRecord> = {}): SwebenchRecord {
  return {
    instance_id: id, repo: "acme/widget", base_commit: "c0ffee",
    problem_statement: "Fix the thing.",
    patch: "--- a/x.py\n+++ b/x.py\n@@\n-old\n+a new implementation line here\n",
    FAIL_TO_PASS: JSON.stringify([`${id}::ftp`]),
    PASS_TO_PASS: JSON.stringify([`${id}::ptp`]),
    ...over,
  };
}

/** A configurable fake runner: resolves a task iff its id is in `resolveIds`. Counts invocations (spy). */
function fakeRunner(resolveIds: ReadonlySet<string>): InstanceRunner & { solves: string[] } {
  const solves: string[] = [];
  return {
    solves,
    solve: async (task: EvalTask): Promise<SolveResult> => {
      solves.push(task.instanceId);
      return { issueId: task.instanceId, solved: true, stagesRun: [], repairRounds: 0 };
    },
    runTests: async (task: EvalTask, testNames: readonly string[]): Promise<TestExecution> => {
      const ok = resolveIds.has(task.instanceId);
      const passed: Record<string, boolean> = {};
      for (const t of testNames) passed[t] = ok; // resolve → all pass; else fail-to-pass stays red
      return { passed };
    },
  };
}

test("EVAL-RUN: well-formed records load → run → aggregate; resolve-rate matches the runner's verdicts", async () => {
  const recs = [record("a"), record("b"), record("c")];
  const runner = fakeRunner(new Set(["a", "b"])); // 2 of 3 resolve
  const { report } = await runLoadedEvalSuite(recs, runner, {}, spine());
  assert.equal(report.instanceCount, 3, "all three admitted tasks ran");
  assert.ok(Math.abs(report.resolveAt1 - 2 / 3) < 0.01, `expected ~0.667, got ${report.resolveAt1}`);
});

test("EVAL-RUN: a malformed record is surfaced and NEVER run (excluded from the denominator)", async () => {
  const recs = [record("a"), record("b"), record("bad", { FAIL_TO_PASS: "not-json[" })];
  const runner = fakeRunner(new Set(["a", "b"]));
  const { report, malformed } = await runLoadedEvalSuite(recs, runner, {}, spine());
  assert.equal(malformed.length, 1, "the malformed record is surfaced");
  assert.equal(report.instanceCount, 2, "only the two well-formed tasks ran");
  assert.ok(!runner.solves.includes("bad"), "the malformed record was never solved");
});

test("EVAL-RUN: a leaked task is excluded by decontamination (honest denominator)", async () => {
  const leaked = record("leak", {
    patch: "--- a/x.py\n+++ b/x.py\n@@\n+return compute_the_special_total(items)\n",
    problem_statement: "The fix is: return compute_the_special_total(items).",
  });
  const recs = [record("a"), record("b"), leaked];
  const runner = fakeRunner(new Set(["a", "b"]));
  const { report, decontamination } = await runLoadedEvalSuite(recs, runner, { maxLeakageOverlap: 0.5 }, spine());
  assert.equal(report.instanceCount, 2, "the leaked task is not in the denominator");
  assert.ok(decontamination.rejected.length >= 1, "the leak is recorded in the ledger");
});

test("EVAL-RUN: the injected runner is invoked once per admitted task (not stubbed)", async () => {
  const recs = [record("a"), record("b")];
  const runner = fakeRunner(new Set(["a"]));
  await runLoadedEvalSuite(recs, runner, {}, spine());
  assert.deepEqual([...runner.solves].sort(), ["a", "b"], "the runner solved each admitted task exactly once");
});

test("EVAL-RUN: the report carries both honesty caveats (loading ≠ a run; injected runner ≠ official)", async () => {
  const { report } = await runLoadedEvalSuite([record("a")], fakeRunner(new Set(["a"])), {}, spine());
  assert.ok(report.caveats.some((c) => /not a benchmark result|real ModelProvider/i.test(c)), "loader caveat carried");
  assert.ok(report.caveats.some((c) => /INJECTED InstanceRunner|seam S-1/i.test(c)), "injected-runner caveat carried");
});
