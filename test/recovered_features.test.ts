import { test } from "node:test";
import assert from "node:assert/strict";

import { dryRun, type PlannedStep } from "../src/control/dry_run.js";
import { buildBatchDigest, type PrReviewItem } from "../src/review/batch_digest.js";
import type { MergeReadiness } from "../src/review/merge_readiness.js";

// --- #28 Dry-run mode ---

test("dry-run produces a plan + cost + approval prediction with ZERO writes", () => {
  const plan: PlannedStep[] = [
    { action: { kind: "capture_goal", args: {}, rationale: "note the goal" }, similarPastCosts: [1, 2, 1, 2, 1] },
    { action: { kind: "set_preference", args: {}, rationale: "set tone" }, similarPastCosts: [1, 1, 1, 1, 1] },
  ];
  const report = dryRun(plan);
  assert.equal(report.writesPerformed, 0); // proven zero
  assert.equal(report.steps.length, 2);
  assert.ok(report.totalCostP50 >= 0);
  assert.equal(report.stepsNeedingApproval, 0); // both reversible
  assert.ok(/nothing has been changed/i.test(report.summary));
});

test("a destructive action in a dry-run plan is flagged (would need approval, is destructive)", () => {
  const plan: PlannedStep[] = [
    { action: { kind: "drop_database", args: {}, rationale: "reset" } },
  ];
  const report = dryRun(plan);
  assert.equal(report.steps[0]!.wouldRequireApproval, true);
  assert.equal(report.steps[0]!.isDestructive, true);
  assert.equal(report.stepsNeedingApproval, 1);
  assert.equal(report.writesPerformed, 0); // still zero writes — it only predicts
});

test("dry-run cost band reflects the forecast (credible with enough samples)", () => {
  const plan: PlannedStep[] = [{ action: { kind: "capture_goal", args: {}, rationale: "x" }, similarPastCosts: [10, 10, 10, 10, 10] }];
  const report = dryRun(plan);
  assert.equal(report.steps[0]!.costBand.p50, 10);
  assert.equal(report.steps[0]!.costBand.credible, true);
});

// --- #20 Batch review digests ---

function readiness(overall: number, hasBlockers: boolean): MergeReadiness {
  return {
    card: { security: overall, reliability: overall, complexity: overall, hygiene: overall, coverage: overall },
    overall,
    hasBlockers,
    reviewDepth: "standard",
  };
}
function pr(prId: string, overall: number, hasBlockers: boolean, lines = 50): PrReviewItem {
  return {
    prId,
    title: `PR ${prId}`,
    readiness: readiness(overall, hasBlockers),
    effortSignals: { linesChanged: lines, filesTouched: 2, crossCutting: false, inlineFindings: 0 },
  };
}

test("batch digest orders blockers first, then lowest readiness", () => {
  const items = [pr("A", 0.9, false), pr("B", 0.3, false), pr("C", 0.95, true)];
  const digest = buildBatchDigest(items);
  assert.equal(digest.entries[0]!.prId, "C"); // blocked -> first
  assert.equal(digest.entries[1]!.prId, "B"); // lowest readiness among non-blocked
  assert.equal(digest.entries[2]!.prId, "A");
});

test("batch digest counts blocked and ready-to-merge", () => {
  const items = [pr("A", 0.9, false), pr("B", 0.85, false), pr("C", 0.5, true)];
  const digest = buildBatchDigest(items);
  assert.equal(digest.total, 3);
  assert.equal(digest.blocked, 1);
  assert.equal(digest.readyToMerge, 2); // A and B: no blockers, >=80%
});

test("batch digest one-liners flag ready vs blocked", () => {
  const digest = buildBatchDigest([pr("A", 0.9, false), pr("C", 0.5, true)]);
  const cLine = digest.entries.find((e) => e.prId === "C")!.line;
  const aLine = digest.entries.find((e) => e.prId === "A")!.line;
  assert.ok(/blocked/i.test(cLine));
  assert.ok(/ready/i.test(aLine));
});

test("empty batch is handled gracefully", () => {
  const digest = buildBatchDigest([]);
  assert.equal(digest.total, 0);
  assert.ok(/no prs/i.test(digest.summary));
});
