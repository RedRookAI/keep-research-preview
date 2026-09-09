/**
 * VERIFY-CONFIDENCE — a bounded, transparent verification-confidence signal that MODULATES escalation.
 *
 * The confidence is NOT a self-reported/verbalized model score (those are "systematically overconfident… raw softmax
 * scores are not calibrated probabilities", Zylos 2026). It is a transparent function of OBJECTIVE signals already
 * computed elsewhere in the pipeline:
 *   - the DETERMINISTIC oracle result (hard, AUTHORITATIVE — a fail can never be lifted by soft signals),
 *   - rerun STABILITY (not flaky — from `judgeResolutionStable`),
 *   - cross-family AGREEMENT (an independent verifier from a different model family agreed — from `crossFamilyVerify`;
 *     this is the ensemble-disagreement signal Zylos names as a calibration input).
 *
 * It answers "how sure are we?" — but the MORE important question is "how bad is it if we're wrong?" (digitalapplied
 * 2026). So confidence never governs alone: it MODULATES escalation WITHIN the consequence gate (see composeGate). Low
 * confidence can only ADD scrutiny (escalate) on a consequential action; it can never override the deterministic floor
 * nor auto-accept a high-consequence action. Every contribution is reported (auditable), never fabricated. ZERO-DEP.
 */

export interface VerificationSignals {
  /** The hard, AUTHORITATIVE deterministic oracle result (tests / sound floor). */
  readonly deterministicPass: boolean;
  /** Rerun-stable (NOT flaky) — from the flakiness-aware oracle. */
  readonly stable: boolean;
  /** An independent cross-family verifier AGREED — from the cross-family gate. */
  readonly crossFamilyAgreement: boolean;
  /** Was an independent verifier even consulted? (n=1 / free-tier ⇒ false — deterministic-only, not a penalty-to-hide). */
  readonly hadIndependentVerifier: boolean;
}

export interface ConfidenceConfig {
  /** score ≥ this ⇒ "high". Default 0.85. */
  readonly highThreshold?: number;
  /** score ≥ this ⇒ "medium"; below ⇒ "low". Default 0.6. */
  readonly lowThreshold?: number;
}

export interface VerificationConfidence {
  readonly score: number; // 0..1
  readonly band: "high" | "medium" | "low";
  /** The transparent per-signal contributions (auditable — never a fabricated number). */
  readonly reasons: readonly string[];
}

/**
 * Compute the transparent confidence. A deterministic FAIL is confidence 0 — the soft signals can NEVER lift it (the
 * deterministic floor is authoritative). Otherwise: deterministic pass is the base, rerun-stability and cross-family
 * agreement each add a bounded increment.
 */
export function verificationConfidence(s: VerificationSignals, cfg: ConfidenceConfig = {}): VerificationConfidence {
  const hi = cfg.highThreshold ?? 0.85;
  const lo = cfg.lowThreshold ?? 0.6;

  // DETERMINISTIC FLOOR: a hard fail is confidence 0, regardless of any soft signal.
  if (!s.deterministicPass) {
    return { score: 0, band: "low", reasons: ["deterministic oracle FAILED (authoritative) — confidence 0; soft signals cannot lift a hard fail"] };
  }

  const reasons: string[] = [];
  let score = 0.5;
  reasons.push("deterministic pass (+0.50)");

  if (s.stable) { score += 0.25; reasons.push("rerun-stable, not flaky (+0.25)"); }
  else reasons.push("flaky-adjacent: not rerun-stable (+0.00)");

  if (s.hadIndependentVerifier && s.crossFamilyAgreement) { score += 0.25; reasons.push("cross-family verifier agreed (+0.25)"); }
  else if (s.hadIndependentVerifier) reasons.push("cross-family verifier did NOT agree (+0.00)");
  else reasons.push("no independent verifier consulted — deterministic-only (n=1) (+0.00)");

  const bounded = Math.min(1, score);
  const band = bounded >= hi ? "high" : bounded >= lo ? "medium" : "low";
  return { score: bounded, band, reasons };
}
