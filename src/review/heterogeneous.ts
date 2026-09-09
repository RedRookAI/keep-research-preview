/**
 * Heterogeneous review (Phase 3, #13/#14) — the anti-self-review guardrail.
 *
 * The circular-review risk: a model reviewing its own output shares its own blind
 * spots, so "self-review" that just re-asks the author is theater. Keep enforces:
 *   1. HETEROGENEITY — the reviewer must be a different agent/model-family than the
 *      author (Claude writes, Gemini audits — not one model checking itself).
 *   2. OBJECTIVE ANCHORING — review is anchored to external signal (test outcomes,
 *      the human-approved spec, captured regressions) rather than the reviewer's
 *      unaided judgment.
 *
 * #13 intent-anchored: does the change actually satisfy the approved spec's intent,
 * not just "look plausible"?
 */

import type { Finding } from "./finding.js";

export interface Authorship {
  readonly agentId: string;
  readonly modelFamily: string;
}

export interface ObjectiveAnchor {
  /** Did the change's tests pass? (external objective signal) */
  readonly testsPass: boolean;
  /** The human-approved spec intent this change must satisfy (#13). */
  readonly approvedSpecIntent: string;
  /** Captured regression fingerprints this change must not reintroduce (from memory). */
  readonly knownRegressions: readonly string[];
}

export interface ReviewRequest {
  readonly author: Authorship;
  readonly reviewer: Authorship;
  readonly changeSummary: string;
  readonly anchor: ObjectiveAnchor;
  /** Findings already produced by scanners/detectors. */
  readonly detectorFindings: readonly Finding[];
}

export interface ReviewOutcome {
  readonly findings: readonly Finding[];
  /** True if the change satisfies the approved spec intent (#13). */
  readonly intentSatisfied: boolean;
  readonly reviewerModelFamily: string;
}

/**
 * Enforce heterogeneity: throws if the reviewer is the same agent OR same model
 * family as the author. This is the guardrail, enforced structurally.
 */
export function assertHeterogeneous(author: Authorship, reviewer: Authorship): void {
  if (author.agentId === reviewer.agentId) {
    throw new Error("self-review forbidden: reviewer is the author (same agent)");
  }
  if (author.modelFamily === reviewer.modelFamily) {
    throw new Error(
      `heterogeneity violated: reviewer and author share model family "${author.modelFamily}" ` +
        `(a model reviewing its own family shares its blind spots)`,
    );
  }
}

/** Result of a non-throwing heterogeneity check (for single-model-aware callers). */
export interface HeterogeneityStatus {
  /** True if reviewer is genuinely independent of the author (different agent AND family). */
  readonly independent: boolean;
  /** True when author and reviewer are the same model (single-model mode). */
  readonly singleModel: boolean;
  readonly reason: string;
}

/**
 * Single-model-aware heterogeneity check (LogicVet §9.1 failsafe). Unlike assertHeterogeneous,
 * this NEVER throws — it reports whether the reviewer is independent so callers can degrade
 * gracefully: an independent critic's judgement may gate; a single-model self-review can only
 * FLAG concerns for the human, never bless its own plan. This is the fix for the one-key operator,
 * who has no second model and must not hit a hard error.
 */
export function checkHeterogeneous(author: Authorship, reviewer: Authorship): HeterogeneityStatus {
  if (author.agentId === reviewer.agentId && author.modelFamily === reviewer.modelFamily) {
    return { independent: false, singleModel: true, reason: "reviewer is the author (single-model mode): may flag, not bless" };
  }
  if (author.modelFamily === reviewer.modelFamily) {
    return { independent: false, singleModel: false, reason: `same model family "${author.modelFamily}": shares blind spots; treat as weak signal` };
  }
  return { independent: true, singleModel: false, reason: "reviewer is independent of the author" };
}

export interface CrossFamilyVerifyInput {
  /** The AUTHORITATIVE deterministic oracle result (hard verification: tests/sound floor). */
  readonly deterministicPass: boolean;
  /** Who produced the fix (its model family). */
  readonly author: Authorship;
  /** Optional independent verifier's verdict — its identity + whether it approved. Absent ⇒ deterministic-only (n=1). */
  readonly verifier?: { readonly identity: Authorship; readonly approved: boolean };
}

export interface CrossFamilyVerdict {
  readonly accepted: boolean;
  readonly deterministicPass: boolean;
  readonly usedVerifier: boolean;
  /** Was the verifier genuinely cross-family (different lineage)? */
  readonly independent: boolean;
  readonly authorFamily: string;
  readonly verifierFamily?: string;
  /** Did the verifier agree (only meaningful when a verifier was used)? */
  readonly agreement?: boolean;
  readonly reason: string;
}

/**
 * XVERIFY — cross-family heterogeneous verification gate. Composes the DETERMINISTIC oracle (hard, AUTHORITATIVE) with
 * an OPTIONAL independent verifier drawn from a DIFFERENT model family. The soft (LLM) verifier has a blind-spot ceiling
 * (arXiv 2607.13918; "three models agreed, it was still wrong") so it is ADDITIVE ONLY: it can raise the bar (decline a
 * deterministically-passing fix) but can NEVER override a deterministic FAIL into a pass, and it is never required for the
 * n=1 deterministic-only path. A SAME-family verifier is rejected as non-independent — within-family correlation is high
 * (ρ=0.77 vs 0.54 cross-family; OpenReview ICLR-2026) so it shares the author's blind spots and cannot corroborate
 * (towardsai 2026: "actual diversity requires actually different models"). The decision reports both families + agreement.
 */
export function crossFamilyVerify(input: CrossFamilyVerifyInput): CrossFamilyVerdict {
  const authorFamily = input.author.modelFamily;
  // DETERMINISTIC IS AUTHORITATIVE: a hard fail is never rubber-stamped into a pass by any verifier.
  if (!input.deterministicPass) {
    return { accepted: false, deterministicPass: false, usedVerifier: false, independent: false, authorFamily, reason: "deterministic oracle FAILED — authoritative; not accepted (no soft verifier can override a hard fail)" };
  }
  // No verifier ⇒ the deterministic floor alone governs (n=1 / free-tier default).
  if (!input.verifier) {
    return { accepted: true, deterministicPass: true, usedVerifier: false, independent: false, authorFamily, reason: "deterministic oracle passed; no independent verifier configured — deterministic floor governs (n=1)" };
  }
  const verifierFamily = input.verifier.identity.modelFamily;
  const status = checkHeterogeneous(input.author, input.verifier.identity);
  // SAME-family verifier is NOT independent — it shares the author's blind spots; it cannot bless (no rubber-stamp).
  if (!status.independent) {
    return { accepted: false, deterministicPass: true, usedVerifier: true, independent: false, authorFamily, verifierFamily, agreement: input.verifier.approved, reason: `verifier is NOT independent (${status.reason}) — a same-family verifier cannot corroborate under a cross-family policy` };
  }
  // Independent (cross-family) verifier: ADDITIVE — accept iff it also approves the already-passing deterministic result.
  const accepted = input.verifier.approved === true;
  return { accepted, deterministicPass: true, usedVerifier: true, independent: true, authorFamily, verifierFamily, agreement: input.verifier.approved, reason: accepted ? `deterministic passed + independent ${verifierFamily} verifier approved (cross-family agreement: ${authorFamily} ⟷ ${verifierFamily})` : `deterministic passed but independent ${verifierFamily} verifier DECLINED — the additional cross-family gate was not cleared` };
}

/**
 * Run heterogeneous, objectively-anchored review. Produces the reviewer's findings
 * plus intent-satisfaction, anchored to test outcomes + the approved spec +
 * known regressions. `reviewerFn` is the (injected) reviewer agent.
 */
export async function heterogeneousReview(
  req: ReviewRequest,
  reviewerFn: (req: ReviewRequest) => Promise<{ findings: Finding[]; intentSatisfied: boolean }>,
): Promise<ReviewOutcome> {
  assertHeterogeneous(req.author, req.reviewer);
  const result = await reviewerFn(req);
  return {
    findings: result.findings,
    intentSatisfied: result.intentSatisfied,
    reviewerModelFamily: req.reviewer.modelFamily,
  };
}

/**
 * Objective self-review gate (#14): the change is only "self-review clean" when the
 * external anchors agree — tests pass AND no known regression fingerprint is present
 * in the change summary. This never depends on the reviewer "feeling" confident.
 */
export function objectiveSelfReviewClean(anchor: ObjectiveAnchor, changeText: string): { clean: boolean; reason: string } {
  if (!anchor.testsPass) return { clean: false, reason: "tests do not pass (objective anchor)" };
  for (const reg of anchor.knownRegressions) {
    if (changeText.includes(reg)) {
      return { clean: false, reason: `reintroduces known regression: ${reg}` };
    }
  }
  return { clean: true, reason: "objective anchors satisfied (tests pass, no known regression)" };
}
