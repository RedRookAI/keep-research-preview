import { test } from "node:test";
import assert from "node:assert/strict";

import { judgeResolutionStable, type EvalTask, type TestExecution } from "../src/eval/swebench_task.js";

const task: EvalTask = {
  instanceId: "demo-1",
  repo: "demo",
  baseCommit: "abc",
  problemStatement: "fix add",
  failToPass: ["t_target"],
  passToPass: ["t_existing"],
};
const exec = (target: boolean, existing: boolean): TestExecution => ({ passed: { t_target: target, t_existing: existing } });

test("FLAKE-ORACLE (a): a stable red→green that holds across reruns is resolved", () => {
  const v = judgeResolutionStable(task, [exec(true, true), exec(true, true), exec(true, true)], { minRuns: 3 });
  assert.equal(v.resolved, true, "stable across 3 reruns → resolved");
  assert.equal(v.flaky, false);
  assert.match(v.reason, /stably resolved/);
});

test("FLAKE-ORACLE (b): a target that passes once then fails on rerun is FLAKY, not resolved", () => {
  const v = judgeResolutionStable(task, [exec(true, true), exec(false, true)], { minRuns: 2 });
  assert.equal(v.resolved, false, "a flaky green is not a fix");
  assert.equal(v.flaky, true);
  assert.deepEqual(v.flakyTests, ["t_target"]);
  assert.match(v.reason, /FLAKY|lucky-pass/);
});

test("FLAKE-ORACLE (c): a previously-green test that regresses on any rerun fails the gate", () => {
  const v = judgeResolutionStable(task, [exec(true, true), exec(true, false)], { minRuns: 2 });
  assert.equal(v.resolved, false, "a pass-to-pass regression on any rerun → not resolved");
  assert.equal(v.flaky, true);
  assert.deepEqual(v.flakyTests, ["t_existing"]);
});

test("FLAKE-ORACLE (d): flakiness is reported honestly (flaky verdict + reason + tests)", () => {
  const v = judgeResolutionStable(task, [exec(true, true), exec(false, true)], { minRuns: 2 });
  assert.equal(v.flaky, true);
  assert.ok(v.flakyTests.length > 0, "the varying test is named");
  assert.ok(v.reason.includes("t_target"), "the reason names the flaky test");
  assert.deepEqual(v.perRunResolved, [true, false], "per-run verdicts are exposed");
});

test("FLAKE-ORACLE (e): the single-run default still resolves a clean fix (n=1 fast path)", () => {
  const v = judgeResolutionStable(task, [exec(true, true)]); // minRuns defaults to 1
  assert.equal(v.resolved, true, "one clean run resolves under the n=1 default");
  assert.equal(v.flaky, false);
  assert.equal(v.runs, 1);
});

test("FLAKE-ORACLE (f): a consistently-unresolved fix is unresolved (not flaky)", () => {
  const v = judgeResolutionStable(task, [exec(false, true), exec(false, true)], { minRuns: 2 });
  assert.equal(v.resolved, false);
  assert.equal(v.flaky, false, "consistent failure is a genuine miss, not flakiness");
  assert.match(v.reason, /unresolved/);
});

test("FLAKE-ORACLE (g): insufficient reruns → not resolved under a strict policy", () => {
  const v = judgeResolutionStable(task, [exec(true, true)], { minRuns: 3 });
  assert.equal(v.resolved, false, "one run does not satisfy a 3-rerun policy");
  assert.match(v.reason, /insufficient reruns/);
});
