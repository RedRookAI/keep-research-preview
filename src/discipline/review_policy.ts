import type { EvidenceIndependence, Sha256Digest, StableOperationId } from "./contracts.js";
import type { VerifiedExternalReview } from "./contracts.js";
import { isVerifierMintedExternalReview } from "./external_review_corroboration.js";
import { isVerifiedReviewTransactionEvidence, type ReviewTransactionEvidence, type VerifiedReviewTransactionEvidence } from "./review_composition.js";
import { createHash } from "node:crypto";
import { types } from "node:util";
import { canonicalize } from "../spine/event.js";

export const MIN_MEANINGFUL_CROSS_FAMILY_PASSES = 2 as const;
export const MAX_MEANINGFUL_CROSS_FAMILY_PASSES = 4 as const;

export type MaterialFindingSeverity = "sev0" | "sev1" | "sev2" | "note";

export interface ReviewFindingState {
  readonly findingDigest: Sha256Digest;
  readonly severity: MaterialFindingSeverity;
  readonly resolved: boolean;
}

export interface MeaningfulReviewPass {
  readonly campaignId: StableOperationId;
  readonly operationId: StableOperationId;
  readonly operationPredecessorId: StableOperationId | null;
  readonly pass: number;
  readonly candidateDigest: Sha256Digest;
  readonly adverseHistoryDigest: Sha256Digest;
  readonly adverseObservationDigests: readonly Sha256Digest[];
  readonly independence: EvidenceIndependence;
  readonly disposition: "go" | "revise" | "refuse" | "unavailable";
  readonly findings: readonly ReviewFindingState[];
  readonly authoritySurfaceChanged: boolean;
  readonly transaction: ReviewTransactionEvidence;
}

export interface ReviewPassReceiptV1 {
  readonly schema: "keep.review-pass-receipt/v1";
  readonly campaignId: StableOperationId;
  readonly operationId: StableOperationId;
  readonly operationPredecessorId: StableOperationId | null;
  readonly pass: number;
  readonly candidateDigest: Sha256Digest;
  readonly adverseHistoryDigest: Sha256Digest;
  readonly adverseObservationDigests: readonly Sha256Digest[];
  readonly disposition: "go" | "revise" | "refuse" | "unavailable";
  readonly findings: readonly ReviewFindingState[];
  readonly authoritySurfaceChanged: boolean;
  readonly transaction: ReviewTransactionEvidence;
}

/** A pass minted only after external corroboration and exact transaction recomputation. */
export type VerifiedMeaningfulReviewPass = MeaningfulReviewPass & { readonly __verifiedMeaningfulReviewPass: unique symbol };
const VERIFIED_PASSES = new WeakSet<object>();

const sha256 = (bytes: Uint8Array): Sha256Digest => createHash("sha256").update(bytes).digest("hex") as Sha256Digest;
export function reviewAdverseHistoryDigest(rows: readonly Sha256Digest[]): Sha256Digest {
  return sha256(Buffer.from(`keep.review-adverse-history/v1\0${canonicalize(rows)}`, "utf8"));
}

export type { ReviewTransactionEvidence } from "./review_composition.js";

export interface ReviewYieldDecision {
  readonly status: "continue" | "eligible" | "held";
  readonly countedPasses: number;
  readonly reason:
    | "minimum-passes-not-met"
    | "candidate-needs-confirmation"
    | "material-findings-require-repair"
    | "exact-candidate-confirmed-clean"
    | "maximum-passes-reached-unresolved"
    | "invalid-review-lineage";
}

const hasOpenCritical = (pass: MeaningfulReviewPass): boolean =>
  pass.findings.some((finding) => !finding.resolved && (finding.severity === "sev0" || finding.severity === "sev1"));

const DIGEST = /^[0-9a-f]{64}$/;
const exactRecord = (input: unknown, keys: readonly string[]): Record<string, unknown> | null => {
  if (input === null || typeof input !== "object" || Array.isArray(input) || types.isProxy(input) || Object.getPrototypeOf(input) !== Object.prototype || Object.getOwnPropertySymbols(input).length !== 0) return null;
  const descriptors = Object.getOwnPropertyDescriptors(input) as Record<string, PropertyDescriptor>;
  if (Object.keys(descriptors).sort().join("\0") !== [...keys].sort().join("\0")) return null;
  const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true || !("value" in descriptor)) return null;
    result[key] = descriptor.value;
  }
  return result;
};
const denseArray = (input: unknown, maximum: number): readonly unknown[] | null => {
  if (!Array.isArray(input) || types.isProxy(input) || Object.getOwnPropertySymbols(input).length !== 0) return null;
  const descriptors = Object.getOwnPropertyDescriptors(input) as Record<string, PropertyDescriptor>;
  const length = descriptors.length?.value;
  if (!Number.isSafeInteger(length) || length < 0 || length > maximum) return null;
  const expected = new Set(["length", ...Array.from({ length }, (_, index) => String(index))]);
  if (Object.keys(descriptors).length !== expected.size || Object.keys(descriptors).some((key) => !expected.has(key))) return null;
  const result: unknown[] = [];
  for (let index = 0; index < length; index++) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true || !("value" in descriptor)) return null;
    result.push(descriptor.value);
  }
  return result;
};

function capturePasses(input: unknown, requireVerified = true): readonly MeaningfulReviewPass[] | null {
  const rows = denseArray(input, MAX_MEANINGFUL_CROSS_FAMILY_PASSES + 1);
  if (!rows) return null;
  const result: MeaningfulReviewPass[] = [];
  for (const inputRow of rows) {
    if (inputRow === null || typeof inputRow !== "object" || (requireVerified && !VERIFIED_PASSES.has(inputRow))) return null;
    const row = exactRecord(inputRow, ["campaignId", "operationId", "operationPredecessorId", "pass", "candidateDigest", "adverseHistoryDigest", "adverseObservationDigests", "independence", "disposition", "findings", "authoritySurfaceChanged", "transaction"]);
    if (!row || typeof row.campaignId !== "string" || row.campaignId.length < 1 || row.campaignId.length > 256 || typeof row.operationId !== "string" || row.operationId.length < 1 || row.operationId.length > 256 || (row.operationPredecessorId !== null && (typeof row.operationPredecessorId !== "string" || row.operationPredecessorId.length < 1 || row.operationPredecessorId.length > 256)) || !Number.isSafeInteger(row.pass) || !DIGEST.test(String(row.candidateDigest)) || !DIGEST.test(String(row.adverseHistoryDigest)) || !["self-review", "same-family", "cross-family-external-technical"].includes(String(row.independence)) || !["go", "revise", "refuse", "unavailable"].includes(String(row.disposition)) || typeof row.authoritySurfaceChanged !== "boolean") return null;
    const findingInputs = denseArray(row.findings, 4096); const adverseInputs = denseArray(row.adverseObservationDigests, 16384); if (!findingInputs || !adverseInputs || adverseInputs.some((value) => !DIGEST.test(String(value))) || new Set(adverseInputs).size !== adverseInputs.length || adverseInputs.some((value, index) => index > 0 && String(adverseInputs[index - 1]) >= String(value)) || reviewAdverseHistoryDigest(adverseInputs as readonly Sha256Digest[]) !== row.adverseHistoryDigest) return null;
    if (requireVerified && !isVerifiedReviewTransactionEvidence(row.transaction)) return null;
    const transaction = exactRecord(row.transaction, ["transactionDigest", "kind", "exactSubjectCoverage", "allChildResultsPresent", "compositionVerified", "unresolvedCrossPartCriticalCount"]);
    if (!transaction || !DIGEST.test(String(transaction.transactionDigest)) || !["monolithic", "partitioned-composed"].includes(String(transaction.kind)) || typeof transaction.exactSubjectCoverage !== "boolean" || typeof transaction.allChildResultsPresent !== "boolean" || typeof transaction.compositionVerified !== "boolean" || !Number.isSafeInteger(transaction.unresolvedCrossPartCriticalCount) || Number(transaction.unresolvedCrossPartCriticalCount) < 0 || Number(transaction.unresolvedCrossPartCriticalCount) > 4096) return null;
    const findings: ReviewFindingState[] = [];
    for (const inputFinding of findingInputs) {
      const finding = exactRecord(inputFinding, ["findingDigest", "severity", "resolved"]);
      if (!finding || !DIGEST.test(String(finding.findingDigest)) || !["sev0", "sev1", "sev2", "note"].includes(String(finding.severity)) || typeof finding.resolved !== "boolean") return null;
      findings.push({ findingDigest: finding.findingDigest as Sha256Digest, severity: finding.severity as MaterialFindingSeverity, resolved: finding.resolved });
    }
    result.push({ campaignId: row.campaignId as StableOperationId, operationId: row.operationId as StableOperationId, operationPredecessorId: row.operationPredecessorId as StableOperationId | null, pass: row.pass as number, candidateDigest: row.candidateDigest as Sha256Digest, adverseHistoryDigest: row.adverseHistoryDigest as Sha256Digest, adverseObservationDigests: Object.freeze(adverseInputs as readonly Sha256Digest[]), independence: row.independence as EvidenceIndependence, disposition: row.disposition as MeaningfulReviewPass["disposition"], findings, authoritySurfaceChanged: row.authoritySurfaceChanged, transaction: { transactionDigest: transaction.transactionDigest as Sha256Digest, kind: transaction.kind as ReviewTransactionEvidence["kind"], exactSubjectCoverage: transaction.exactSubjectCoverage, allChildResultsPresent: transaction.allChildResultsPresent, compositionVerified: transaction.compositionVerified, unresolvedCrossPartCriticalCount: transaction.unresolvedCrossPartCriticalCount as number } });
  }
  return result;
}

/**
 * Joins a verifier-minted external result to the canonical transaction receipt.
 * Neither the caller nor a structurally identical object can mint an admissible pass.
 */
export function mintVerifiedMeaningfulReviewPass(external: VerifiedExternalReview, receiptInput: unknown, verifiedTransaction: VerifiedReviewTransactionEvidence): VerifiedMeaningfulReviewPass {
  if (!isVerifierMintedExternalReview(external)) throw new Error("review result was not minted by the configured external verifier");
  if (!isVerifiedReviewTransactionEvidence(verifiedTransaction)) throw new Error("review transaction was not independently recomputed");
  const row = exactRecord(receiptInput, ["schema", "campaignId", "operationId", "operationPredecessorId", "pass", "candidateDigest", "adverseHistoryDigest", "adverseObservationDigests", "disposition", "findings", "authoritySurfaceChanged", "transaction"]);
  if (!row || row.schema !== "keep.review-pass-receipt/v1") throw new Error("review pass receipt is malformed");
  const findingInputs = denseArray(row.findings, 4096);
  const adverseInputs = denseArray(row.adverseObservationDigests, 16384);
  const transaction = exactRecord(row.transaction, ["transactionDigest", "kind", "exactSubjectCoverage", "allChildResultsPresent", "compositionVerified", "unresolvedCrossPartCriticalCount"]);
  if (!findingInputs || !adverseInputs || adverseInputs.some((value) => !DIGEST.test(String(value))) || !transaction || canonicalize(transaction) !== canonicalize(verifiedTransaction)) throw new Error("review pass receipt is malformed");
  const findings: ReviewFindingState[] = findingInputs.map((input, index) => {
    const finding = exactRecord(input, ["findingDigest", "severity", "resolved"]);
    if (!finding || !DIGEST.test(String(finding.findingDigest)) || !["sev0", "sev1", "sev2", "note"].includes(String(finding.severity)) || typeof finding.resolved !== "boolean") throw new Error(`review finding[${index}] is malformed`);
    return Object.freeze({ findingDigest: finding.findingDigest as Sha256Digest, severity: finding.severity as MaterialFindingSeverity, resolved: finding.resolved });
  });
  const receipt: ReviewPassReceiptV1 = Object.freeze({
    schema: "keep.review-pass-receipt/v1",
    campaignId: row.campaignId as StableOperationId, operationId: row.operationId as StableOperationId,
    operationPredecessorId: row.operationPredecessorId as StableOperationId | null, pass: row.pass as number,
    candidateDigest: row.candidateDigest as Sha256Digest, adverseHistoryDigest: row.adverseHistoryDigest as Sha256Digest, adverseObservationDigests: Object.freeze(adverseInputs as readonly Sha256Digest[]),
    disposition: row.disposition as ReviewPassReceiptV1["disposition"], findings: Object.freeze(findings),
    authoritySurfaceChanged: row.authoritySurfaceChanged as boolean,
    transaction: Object.freeze({ transactionDigest: transaction.transactionDigest as Sha256Digest, kind: transaction.kind as ReviewTransactionEvidence["kind"], exactSubjectCoverage: transaction.exactSubjectCoverage as boolean, allChildResultsPresent: transaction.allChildResultsPresent as boolean, compositionVerified: transaction.compositionVerified as boolean, unresolvedCrossPartCriticalCount: transaction.unresolvedCrossPartCriticalCount as number }),
  });
  /* Reuse the same strict capture used by the policy before any equality is trusted. */
  const structurallyCaptured = capturePassesForMint([{
    campaignId: receipt.campaignId, operationId: receipt.operationId, operationPredecessorId: receipt.operationPredecessorId,
    pass: receipt.pass, candidateDigest: receipt.candidateDigest, adverseHistoryDigest: receipt.adverseHistoryDigest, adverseObservationDigests: receipt.adverseObservationDigests,
    independence: external.independence, disposition: receipt.disposition, findings: receipt.findings,
    authoritySurfaceChanged: receipt.authoritySurfaceChanged, transaction: receipt.transaction,
  }]);
  if (!structurallyCaptured) throw new Error("review pass receipt is malformed");
  const captured = structurallyCaptured[0]!;
  if (captured.transaction.transactionDigest !== external.transactionDigest) throw new Error("review transaction digest does not match external evidence");
  if (captured.campaignId !== external.campaignId || captured.operationId !== external.operationId || captured.operationPredecessorId !== external.operationPredecessorId || captured.pass !== external.round || captured.candidateDigest !== external.candidateDigest || captured.disposition !== external.verdict) throw new Error("review receipt identity does not match external evidence");
  const receiptFindingDigests = [...captured.findings.map((finding) => finding.findingDigest)].sort();
  if (canonicalize(receiptFindingDigests) !== canonicalize(external.findingDigests)) throw new Error("review findings do not match external evidence");
  if (external.independence !== "cross-family-external-technical" || (external.corroboration !== "provider-signed" && external.corroboration !== "independent-witness")) throw new Error("review evidence lacks independent promotion-grade corroboration");
  const verified = Object.freeze({ ...captured, transaction: verifiedTransaction }) as unknown as VerifiedMeaningfulReviewPass;
  VERIFIED_PASSES.add(verified);
  return verified;
}

/* Minting needs the structural parser before branding; ordinary evaluation never does. */
function capturePassesForMint(input: unknown): readonly MeaningfulReviewPass[] | null {
  const rows = denseArray(input, 1); if (!rows) return null;
  const row = rows[0];
  const priorBrand = row !== null && typeof row === "object" && VERIFIED_PASSES.has(row);
  if (!priorBrand && row !== null && typeof row === "object") VERIFIED_PASSES.add(row);
  const result = capturePasses(input, false);
  if (!priorBrand && row !== null && typeof row === "object") VERIFIED_PASSES.delete(row);
  return result;
}

/**
 * Provider-neutral, non-effectful policy evaluation. Review adapters produce evidence;
 * this function only decides whether the evidence lineage is sufficient for a later
 * deterministic admission gate. It never invokes a reviewer or performs promotion.
 */
function evaluateCapturedReviewYield(input: unknown, requireVerified: boolean): ReviewYieldDecision {
  const passes = capturePasses(input, requireVerified);
  if (!passes) return { status: "held", countedPasses: 0, reason: "invalid-review-lineage" };
  if (passes.length === 0) return { status: "continue", countedPasses: 0, reason: "minimum-passes-not-met" };
  if (passes.length > MAX_MEANINGFUL_CROSS_FAMILY_PASSES) return { status: "held", countedPasses: passes.length, reason: "invalid-review-lineage" };

  const campaignId = passes[0]!.campaignId;
  let priorPass = 0;
  let priorOperationId: StableOperationId | null = null;
  let currentOperationId: StableOperationId | null = null;
  let currentOperationPredecessorId: StableOperationId | null = null;
  const seenOperationIds = new Set<StableOperationId>();
  let priorAdverse = new Set<Sha256Digest>();
  for (const review of passes) {
    const operationContinues = currentOperationId === review.operationId && currentOperationPredecessorId === review.operationPredecessorId;
    const operationDescends = currentOperationId !== null && currentOperationId !== review.operationId && !seenOperationIds.has(review.operationId) && review.operationPredecessorId === currentOperationId;
    const operationGenesis = currentOperationId === null && review.operationPredecessorId === null;
    if (review.campaignId !== campaignId || (!operationGenesis && !operationContinues && !operationDescends) || review.pass !== priorPass + 1 || review.independence !== "cross-family-external-technical" || [...priorAdverse].some((digest) => !review.adverseObservationDigests.includes(digest)) || !review.transaction.exactSubjectCoverage || !review.transaction.allChildResultsPresent || !review.transaction.compositionVerified || review.transaction.unresolvedCrossPartCriticalCount !== 0) {
      return { status: "held", countedPasses: passes.length, reason: "invalid-review-lineage" };
    }
    if (operationDescends) { priorOperationId = currentOperationId; currentOperationId = review.operationId; currentOperationPredecessorId = review.operationPredecessorId; seenOperationIds.add(review.operationId); }
    else if (operationGenesis) { currentOperationId = review.operationId; currentOperationPredecessorId = null; seenOperationIds.add(review.operationId); }
    if (currentOperationPredecessorId !== priorOperationId) return { status: "held", countedPasses: passes.length, reason: "invalid-review-lineage" };
    priorPass = review.pass;
    priorAdverse = new Set(review.adverseObservationDigests);
  }

  const latest = passes.at(-1)!;
  const latestCritical = hasOpenCritical(latest) || latest.disposition !== "go" || latest.authoritySurfaceChanged;
  if (latestCritical) {
    return passes.length === MAX_MEANINGFUL_CROSS_FAMILY_PASSES
      ? { status: "held", countedPasses: passes.length, reason: "maximum-passes-reached-unresolved" }
      : { status: "continue", countedPasses: passes.length, reason: "material-findings-require-repair" };
  }
  if (passes.length < MIN_MEANINGFUL_CROSS_FAMILY_PASSES) return { status: "continue", countedPasses: passes.length, reason: "minimum-passes-not-met" };

  const confirmation = passes.at(-2)!;
  const sameCandidate = confirmation.candidateDigest === latest.candidateDigest
    && confirmation.adverseHistoryDigest === latest.adverseHistoryDigest;
  const confirmationClean = confirmation.disposition === "go" && !hasOpenCritical(confirmation) && !confirmation.authoritySurfaceChanged;
  if (sameCandidate && confirmationClean) return { status: "eligible", countedPasses: passes.length, reason: "exact-candidate-confirmed-clean" };

  return passes.length === MAX_MEANINGFUL_CROSS_FAMILY_PASSES
    ? { status: "held", countedPasses: passes.length, reason: "maximum-passes-reached-unresolved" }
    : { status: "continue", countedPasses: passes.length, reason: "candidate-needs-confirmation" };
}

export function evaluateReviewYield(input: unknown): ReviewYieldDecision {
  return evaluateCapturedReviewYield(input, true);
}

/** Structural-only diagnostic. Plan admission never consumes this result. */
export function evaluateReviewYieldStructure(input: unknown): ReviewYieldDecision {
  return evaluateCapturedReviewYield(input, false);
}
