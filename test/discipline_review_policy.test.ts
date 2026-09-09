import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateReviewYield,
  evaluateReviewYieldStructure,
  reviewAdverseHistoryDigest,
  MAX_MEANINGFUL_CROSS_FAMILY_PASSES,
  MIN_MEANINGFUL_CROSS_FAMILY_PASSES,
  type MeaningfulReviewPass,
} from "../src/discipline/review_policy.js";
import type { Sha256Digest, StableOperationId } from "../src/discipline/contracts.js";

const digest = (character: string): Sha256Digest => character.repeat(64) as Sha256Digest;
const operationId = "operation-1" as StableOperationId;
const pass = (index: number, candidate = digest("a"), overrides: Partial<MeaningfulReviewPass> = {}): MeaningfulReviewPass => ({
  campaignId: "campaign-1" as StableOperationId,
  operationId,
  operationPredecessorId: null,
  pass: index,
  candidateDigest: candidate,
  adverseHistoryDigest: reviewAdverseHistoryDigest([]),
  adverseObservationDigests: [],
  independence: "cross-family-external-technical",
  disposition: "go",
  findings: [],
  authoritySurfaceChanged: false,
  transaction: { transactionDigest: digest("f"), kind: "monolithic", exactSubjectCoverage: true, allChildResultsPresent: true, compositionVerified: true, unresolvedCrossPartCriticalCount: 0 },
  ...overrides,
});

test("review policy freezes the two-to-four meaningful-pass bounds", () => {
  assert.equal(MIN_MEANINGFUL_CROSS_FAMILY_PASSES, 2);
  assert.equal(MAX_MEANINGFUL_CROSS_FAMILY_PASSES, 4);
  assert.equal(evaluateReviewYieldStructure([pass(1)]).status, "continue");
  assert.equal(evaluateReviewYieldStructure([pass(1), pass(2)]).status, "eligible");
  assert.equal(evaluateReviewYield([pass(1), pass(2)]).reason, "invalid-review-lineage", "structural lookalikes never authorize");
});

test("repair drift requires a clean confirmation over the exact cumulative candidate", () => {
  const repaired = digest("c");
  assert.deepEqual(evaluateReviewYieldStructure([pass(1), pass(2, repaired), pass(3, repaired)]), {
    status: "eligible", countedPasses: 3, reason: "exact-candidate-confirmed-clean",
  });
  assert.equal(evaluateReviewYieldStructure([pass(1), pass(2, repaired)]).reason, "candidate-needs-confirmation");
});

test("critical findings and changed authority surfaces cannot promote", () => {
  const finding = { findingDigest: digest("d"), severity: "sev1" as const, resolved: false };
  assert.equal(evaluateReviewYieldStructure([pass(1), pass(2, digest("a"), { disposition: "revise", findings: [finding] })]).reason, "material-findings-require-repair");
  assert.equal(evaluateReviewYieldStructure([pass(1), pass(2), pass(3), pass(4, digest("a"), { findings: [finding] })]).status, "held");
  assert.equal(evaluateReviewYieldStructure([pass(1), pass(2, digest("a"), { authoritySurfaceChanged: true })]).status, "continue");
});

test("same-family substitution, pass gaps, fifth passes, and adverse-history churn fail closed", () => {
  assert.equal(evaluateReviewYieldStructure([pass(1), pass(2, digest("a"), { independence: "same-family" })]).reason, "invalid-review-lineage");
  assert.equal(evaluateReviewYieldStructure([pass(1), pass(3)]).reason, "invalid-review-lineage");
  assert.equal(evaluateReviewYieldStructure([pass(1), pass(2), pass(3), pass(4), pass(5)]).reason, "invalid-review-lineage");
  const adverse = [digest("e")];
  assert.equal(evaluateReviewYieldStructure([pass(1), pass(2, digest("a"), { adverseHistoryDigest: reviewAdverseHistoryDigest(adverse), adverseObservationDigests: adverse })]).reason, "candidate-needs-confirmation");
  assert.equal(evaluateReviewYieldStructure([pass(1, digest("a"), { adverseHistoryDigest: reviewAdverseHistoryDigest(adverse), adverseObservationDigests: adverse }), pass(2)]).reason, "invalid-review-lineage");
});

test("descendant repair operations inherit the campaign pass ceiling and cannot reset it", () => {
  const operation2 = "operation-2" as StableOperationId;
  const descendant = (index: number, overrides: Partial<MeaningfulReviewPass> = {}) => pass(index, digest("c"), { operationId: operation2, operationPredecessorId: operationId, ...overrides });
  assert.equal(evaluateReviewYieldStructure([pass(1), descendant(2), descendant(3)]).countedPasses, 3);
  assert.equal(evaluateReviewYieldStructure([pass(1), descendant(2), descendant(3)]).status, "eligible");
  assert.equal(evaluateReviewYieldStructure([pass(1), { ...descendant(2), pass: 1 }]).reason, "invalid-review-lineage");
  assert.equal(evaluateReviewYieldStructure([pass(1), { ...descendant(2), operationPredecessorId: null }]).reason, "invalid-review-lineage");
  assert.equal(evaluateReviewYieldStructure([pass(1), { ...descendant(2), campaignId: "campaign-2" as StableOperationId }]).reason, "invalid-review-lineage");
  const cycled = pass(3, digest("c"), { operationPredecessorId: operation2 });
  assert.equal(evaluateReviewYieldStructure([pass(1), descendant(2), cycled]).reason, "invalid-review-lineage");
});

test("partition children never count as meaningful passes without complete composition", () => {
  const incomplete = pass(1, digest("a"), { transaction: { transactionDigest: digest("c"), kind: "partitioned-composed", exactSubjectCoverage: true, allChildResultsPresent: false, compositionVerified: false, unresolvedCrossPartCriticalCount: 1 } });
  assert.equal(evaluateReviewYieldStructure([incomplete]).reason, "invalid-review-lineage");
  const complete = pass(1, digest("a"), { transaction: { transactionDigest: digest("d"), kind: "partitioned-composed", exactSubjectCoverage: true, allChildResultsPresent: true, compositionVerified: true, unresolvedCrossPartCriticalCount: 0 } });
  assert.equal(evaluateReviewYieldStructure([complete]).reason, "minimum-passes-not-met");
});

test("hostile review arrays and records are captured inertly without executing traps", () => {
  let reads = 0;
  const hostile = [{
    get operationId() { reads++; return operationId; }, pass: 1, candidateDigest: digest("a"), adverseHistoryDigest: reviewAdverseHistoryDigest([]), adverseObservationDigests: [],
    independence: "cross-family-external-technical", disposition: "go", findings: [], authoritySurfaceChanged: false,
    transaction: { transactionDigest: digest("f"), kind: "monolithic", exactSubjectCoverage: true, allChildResultsPresent: true, compositionVerified: true, unresolvedCrossPartCriticalCount: 0 },
  }];
  assert.equal(evaluateReviewYield(hostile).reason, "invalid-review-lineage");
  assert.equal(reads, 0);
  const proxy = new Proxy([pass(1), pass(2)], { ownKeys() { reads++; throw new Error("trap"); } });
  assert.equal(evaluateReviewYield(proxy).reason, "invalid-review-lineage");
  assert.equal(reads, 0);
});
