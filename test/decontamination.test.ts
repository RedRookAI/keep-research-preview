import { test } from "node:test";
import assert from "node:assert/strict";
import { decontaminate, solutionLeakageOverlap } from "../src/eval/decontamination.js";
import type { EvalTask } from "../src/eval/swebench_task.js";

function task(over: Partial<EvalTask> = {}): EvalTask {
  return {
    instanceId: "repo__issue-1", repo: "acme/widget", baseCommit: "abc123",
    problemStatement: "The parser crashes on empty input; it should return an empty list instead.",
    failToPass: ["test_empty_input"], passToPass: ["test_basic"], ...over,
  };
}

test("TEMPORAL: a task created ON/BEFORE the model cutoff is rejected; AFTER is admitted", () => {
  const before = task({ instanceId: "old", createdAt: "2024-01-01" });
  const after = task({ instanceId: "new", createdAt: "2026-07-01" });
  const r = decontaminate([before, after], { modelCutoff: "2026-01-31" });
  assert.deepEqual(r.admitted.map((t) => t.instanceId), ["new"], "only the post-cutoff task is eligible");
  assert.equal(r.rejected[0]!.reasons[0], "temporal-leakage: created on/before the model cutoff");
  assert.equal(r.excludedByReason["temporal-leakage"], 1);
});

test("SOLUTION LEAKAGE: a task whose problem statement contains the gold-patch code is rejected", () => {
  const gold = "--- a/parser.py\n+++ b/parser.py\n@@\n+    if not tokens:\n+        return []   # handle the empty-input case cleanly\n";
  const leaky = task({
    instanceId: "leaky",
    problemStatement: "The parser crashes. Fix: if not tokens:\n        return []   # handle the empty-input case cleanly",
    goldPatch: gold, createdAt: "2026-07-01",
  });
  const clean = task({ instanceId: "clean", goldPatch: gold, createdAt: "2026-07-01" });
  assert.ok(solutionLeakageOverlap(leaky) > 0.5, "the leaky task's gold code overlaps the problem statement");
  assert.equal(solutionLeakageOverlap(clean), 0, "the clean task has no overlap");
  const r = decontaminate([leaky, clean], {});
  assert.deepEqual(r.admitted.map((t) => t.instanceId), ["clean"]);
  assert.equal(r.excludedByReason["solution-leakage"], 1);
});

test("KNOWN-EVAL: a task on the known-eval denylist is rejected", () => {
  const r = decontaminate([task({ instanceId: "in-verified" }), task({ instanceId: "fresh" })], {
    knownEvalIds: new Set(["in-verified"]),
  });
  assert.deepEqual(r.admitted.map((t) => t.instanceId), ["fresh"]);
  assert.equal(r.excludedByReason["known-eval"], 1);
});

test("A clean, post-cutoff, leak-free, unknown task is ADMITTED", () => {
  const r = decontaminate([task({ instanceId: "good", createdAt: "2026-07-01" })], {
    modelCutoff: "2026-01-31", knownEvalIds: new Set(["other"]),
  });
  assert.equal(r.admitted.length, 1);
  assert.equal(r.rejected.length, 0);
});

test("multiple contamination reasons stack on one task", () => {
  const gold = "+++ b/x.py\n+    return fixed_value_here_long_enough\n";
  const bad = task({
    instanceId: "in-verified", createdAt: "2020-01-01",
    problemStatement: "bug. return fixed_value_here_long_enough", goldPatch: gold,
  });
  const r = decontaminate([bad], { modelCutoff: "2026-01-31", knownEvalIds: new Set(["in-verified"]) });
  assert.equal(r.admitted.length, 0);
  assert.ok(r.rejected[0]!.reasons.length >= 3, "temporal + known-eval + solution-leakage all fire");
});
