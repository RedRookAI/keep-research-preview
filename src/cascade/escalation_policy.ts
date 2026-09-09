/**
 * ConfidenceEscalationPolicy (Increment 3.9b) — when to climb the cascade.
 *
 * SOTA basis (2026-08-04):
 *  - Escalate on a confidence/marginality signal (tianpan; NeuralTrust: "escalate only if a
 *    confidence or verification check fails"). Keep reuses its BEHAVIORAL confidence estimator
 *    (control/confidence.ts — not self-reported; GRV anti-spoof) as the marginality signal.
 *  - PRE-ROUTE predictably-hard items straight to the strong tier, skipping the wasted cheap pass
 *    (arXiv 2605.06350 "Is Escalation Worth It?"; arXiv 2606.27457 Stage-1 pre-route). The
 *    complexity classifier (Adaptive Prompt Layer 3.7) is the pre-router.
 *  - Resolve marginal cases via INTRA-TIER consensus BEFORE inter-tier escalation, to avoid
 *    premature escalation on noisy single-model confidence (CascadeDebate ACL 2026 arXiv 2604.12262).
 *  - Honest caveat (tianpan): cascade latency accumulates; pre-routing is the escape valve, and
 *    every escalation is spine-logged for drift monitoring.
 *
 * Zero deps.
 */

import type { EscalationPolicy, TierResult, VerificationItem } from "./verification_cascade.js";
import { estimateConfidence, type ProcessSignals } from "../control/confidence.js";

/** A pre-router: maps an item to a starting tier (0 = normal floor-first; >0 = skip cheap passes). */
export type PreRouter = (item: VerificationItem) => number;

export interface EscalationConfig {
  /** Escalate when the deciding tier's certainty is below this. Default 0.7. */
  readonly certaintyThreshold?: number;
  /** A pre-router for predictably-hard items (e.g. from the complexity classifier). */
  readonly preRouter?: PreRouter;
  /** Max tiers to climb (bounds latency accumulation). Default 3 (up to human). */
  readonly maxTier?: number;
}

export class ConfidenceEscalationPolicy implements EscalationPolicy {
  private readonly threshold: number;
  private readonly maxTier: number;
  private readonly preRouter: PreRouter | undefined;

  constructor(cfg: EscalationConfig = {}) {
    this.threshold = cfg.certaintyThreshold ?? 0.7;
    this.maxTier = cfg.maxTier ?? 3;
    this.preRouter = cfg.preRouter;
  }

  /**
   * Escalate iff: the last tier left the item marginal (undecided, or a low-certainty fuzzy
   * verdict), a higher tier is available, and we haven't hit the tier ceiling. A SOUND verdict is
   * never escalated (soundness dominates — handled by the cascade itself).
   */
  shouldEscalate(results: readonly TierResult[], nextTierAvailable: boolean): boolean {
    if (!nextTierAvailable) return false;
    const last = results[results.length - 1];
    if (!last) return false;
    if (last.tier >= this.maxTier) return false; // bound latency accumulation
    if (last.sound && last.decision !== "undecided") return false; // sound & decided → never climb
    // climb when the item is still marginal: undecided, or fuzzy verdict below the certainty bar
    if (last.decision === "undecided") return true;
    return last.certainty < this.threshold;
  }

  preRoute(item: VerificationItem): number {
    return this.preRouter ? this.preRouter(item) : 0;
  }
}

/**
 * Build a pre-router from a complexity signal: predictably-hard items (complexity "complex") jump
 * straight to Tier 2 (external brain), skipping the wasted single-brain pass — but only when a
 * second brain exists (else the cascade skips the empty tier cleanly anyway).
 */
export function complexityPreRouter(
  complexityOf: (item: VerificationItem) => "trivial" | "simple" | "moderate" | "complex",
): PreRouter {
  return (item) => (complexityOf(item) === "complex" ? 2 : 0);
}

/**
 * Turn behavioral process signals into a certainty value for a tier result. Wraps the existing
 * estimateConfidence so tiers report marginality consistently. Higher = more certain.
 */
export function certaintyFromSignals(signals: ProcessSignals): number {
  return estimateConfidence(signals);
}

/**
 * Intra-tier consensus (CascadeDebate refinement): given N independent fuzzy verdicts at the same
 * tier, resolve BEFORE escalating. Returns a consensus decision + whether it's confident enough to
 * avoid climbing. Simple majority with agreement-strength as certainty.
 */
export function intraTierConsensus(
  verdicts: ReadonlyArray<{ decision: "pass" | "fail"; certainty: number }>,
): { decision: "pass" | "fail"; certainty: number; unanimous: boolean } {
  if (verdicts.length === 0) return { decision: "fail", certainty: 0, unanimous: false };
  const passes = verdicts.filter((v) => v.decision === "pass").length;
  const fails = verdicts.length - passes;
  const decision = passes >= fails ? "pass" : "fail";
  const agreeing = decision === "pass" ? passes : fails;
  const certainty = agreeing / verdicts.length; // fraction agreeing = agreement strength
  return { decision, certainty, unanimous: agreeing === verdicts.length };
}
