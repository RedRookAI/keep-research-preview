import { test } from "node:test";
import assert from "node:assert/strict";
import { judgeResolution, type EvalTask } from "../src/eval/swebench_task.js";

const task: EvalTask = {
  instanceId: "repo__issue-1",
  repo: "acme/widget",
  baseCommit: "abc123",
  problemStatement: "add() returns wrong value",
  failToPass: ["test_add_positive", "test_add_negative"],
  passToPass: ["test_subtract", "test_multiply"],
};

test("INVARIANT: resolved iff all fail-to-pass flip AND all pass-to-pass hold", () => {
  const v = judgeResolution(task, {
    passed: { test_add_positive: true, test_add_negative: true, test_subtract: true, test_multiply: true },
  });
  assert.equal(v.resolved, true);
  assert.deepEqual(v.failToPassCleared, ["test_add_positive", "test_add_negative"]);
  assert.equal(v.failToPassMissed.length, 0);
  assert.equal(v.passToPassRegressed.length, 0);
});

test("INVARIANT: an incomplete fix (a fail-to-pass still failing) is UNRESOLVED", () => {
  const v = judgeResolution(task, {
    passed: { test_add_positive: true, test_add_negative: false, test_subtract: true, test_multiply: true },
  });
  assert.equal(v.resolved, false);
  assert.deepEqual(v.failToPassMissed, ["test_add_negative"]);
  assert.match(v.reason, /fix incomplete/);
});

test("INVARIANT: a regression (pass-to-pass broke) is UNRESOLVED even if the bug is fixed", () => {
  // This is the critical SOTA point: fixing the bug but breaking existing tests = NOT resolved.
  const v = judgeResolution(task, {
    passed: { test_add_positive: true, test_add_negative: true, test_subtract: true, test_multiply: false },
  });
  assert.equal(v.resolved, false, "a regression fails the task even with the bug fixed");
  assert.deepEqual(v.passToPassRegressed, ["test_multiply"]);
  assert.match(v.reason, /regression/);
});

test("INVARIANT: both failing — reports both classes", () => {
  const v = judgeResolution(task, {
    passed: { test_add_positive: false, test_add_negative: true, test_subtract: false, test_multiply: true },
  });
  assert.equal(v.resolved, false);
  assert.deepEqual(v.failToPassMissed, ["test_add_positive"]);
  assert.deepEqual(v.passToPassRegressed, ["test_subtract"]);
  assert.match(v.reason, /AND/);
});

test("INVARIANT: a test that didn't run counts as a failure (0-tests-is-not-a-pass)", () => {
  const v = judgeResolution(task, {
    passed: { test_add_positive: true /* test_add_negative absent */, test_subtract: true, test_multiply: true },
  });
  assert.equal(v.resolved, false, "a fail-to-pass test that didn't execute is not a pass");
  assert.ok(v.failToPassMissed.includes("test_add_negative"));
});

test("resolved reason names the counts", () => {
  const v = judgeResolution(task, {
    passed: { test_add_positive: true, test_add_negative: true, test_subtract: true, test_multiply: true },
  });
  assert.match(v.reason, /all 2 fail-to-pass cleared/);
  assert.match(v.reason, /no regression in 2 pass-to-pass/);
});
