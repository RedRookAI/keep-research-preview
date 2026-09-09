/**
 * VerificationHarness (Increment 16.8c) — the model-harness seam that assembles a VerificationCascade
 * tuned to the operator's brain capability, serving BOTH the front of the room (a frontier model) and the
 * back (a free-tier model, or no model at all).
 *
 * The deterministic Tier-0 floor ALWAYS runs and is IDENTICAL for every operator — that's the non-
 * negotiable safety property. Only the MODEL tiers and their delivery adapt:
 *   - rich brain (front of room): Tier-1 single-brain + Tier-2 heterogeneous second-brain.
 *   - lean / free-tier brain (back of room): Tier-1 with lean (decomposed) delivery; Tier-2 only if a
 *     heterogeneous second model is actually wired; cost-adaptive (a decisive floor spends no model call).
 *   - no brain: floor + human only (still safe — the floor always runs).
 *
 * SOTA basis (2026-08-05): adaptive, regime-aware verification tuned to verifier capability, escalating
 * only marginal cases (emergentmind 2026; CascadeDebate ACL 2026). VERIFICATION ASYMMETRY — even a weak/
 * free-tier model can verify usefully, verification is a distinct capability (arXiv 2509.17995). BLIND-SPOT
 * CEILING — a verifier cascade has a failure floor that verifier scaling alone can't overcome and
 * correlated verifiers don't help → the deterministic floor must always run (non-correlated failure mode)
 * and the second brain must be heterogeneous (arXiv 2607.13918). COST-ADAPTIVE — skip the model tier when
 * the strong floor already answers (arXiv 2606.30919), which protects the free-tier budget.
 *
 * Zero deps. Assembles the existing cascade + tier adapters; enforces heterogeneity on Tier-2.
 */

import { VerificationCascade, type VerificationTier, type EscalationPolicy } from "./verification_cascade.js";
import { ConfidenceEscalationPolicy } from "./escalation_policy.js";
import { SingleBrainTier, ExternalBrainTier, HumanTier, type SingleBrainVerifier, type ExternalBrainReviewer } from "./tier_adapters.js";
import { assertHeterogeneous, type Authorship } from "../review/heterogeneous.js";
import type { CapabilityTier } from "../frontdoor/capability_adaptive.js";

export type BrainCapability = "rich" | "lean" | "none";

/** Map a model's CapabilityTier to a coarse harness capability. */
export function capabilityOf(tier: CapabilityTier | undefined): BrainCapability {
  if (tier === undefined || tier === "minimal") return "none";
  // "rich" → rich (front of room); "standard"/"lean" → lean (back of room, but still verifies usefully).
  return tier === "rich" ? "rich" : "lean";
}

export interface HarnessConfig<T> {
  /** The ALWAYS-ON deterministic floor tier (Tier 0). Required — the safety property. */
  readonly floor: VerificationTier<T>;
  /** The operator's brain capability (front vs back of room). */
  readonly capability: BrainCapability;
  /** Tier-1 single-brain verifier (the operator's own model), if any. */
  readonly singleBrain?: SingleBrainVerifier<T>;
  /** Tier-2 heterogeneous second brain, if a DIFFERENT-family model is wired. */
  readonly secondBrain?: { reviewer: ExternalBrainReviewer<T>; identity: Authorship };
  /** The single brain's authorship, to enforce Tier-2 heterogeneity. */
  readonly singleBrainAuthorship?: Authorship;
  /** Escalation strategy. Default: ConfidenceEscalationPolicy (threshold-based, latency-bounded, pre-routing). */
  readonly policy?: EscalationPolicy;
  readonly logger?: (tierResult: unknown, itemId: string) => void;
}

/**
 * Assemble the cascade for this operator. The floor is always present; model tiers are added per
 * capability. Tier-2 is included ONLY when a heterogeneous second brain is wired (enforced here).
 */
export function buildHarness<T>(config: HarnessConfig<T>): VerificationCascade<T> {
  const tiers: VerificationTier<T>[] = [config.floor];

  // Tier-1 single-brain: added when the operator has ANY brain (rich or lean). Even a lean/free-tier model
  // verifies usefully (verification asymmetry). "none" → no model tier, floor + human only.
  if (config.capability !== "none" && config.singleBrain) {
    tiers.push(new SingleBrainTier<T>(config.singleBrain));
  }

  // Tier-2 heterogeneous second brain: only if a genuinely DIFFERENT-family model is wired. Enforce
  // heterogeneity at assembly (a same-family second brain shares the blind spot — refused).
  if (config.secondBrain) {
    if (config.singleBrainAuthorship) {
      assertHeterogeneous(config.singleBrainAuthorship, config.secondBrain.identity);
    }
    tiers.push(new ExternalBrainTier<T>(config.secondBrain.reviewer));
  } else {
    // No second brain wired → Tier-2 present but unavailable (cascade skips it cleanly).
    tiers.push(new ExternalBrainTier<T>(undefined));
  }

  // Tier-3 human — the final fallback for unresolved AND consequential items (always present).
  tiers.push(new HumanTier<T>());

  const logger = config.logger as ((r: import("./verification_cascade.js").TierResult, itemId: string) => void) | undefined;
  return new VerificationCascade<T>(tiers, config.policy ?? new ConfidenceEscalationPolicy(), logger);
}

/**
 * A cost-adaptive escalation policy for the back-of-the-room operator: if the deterministic floor is
 * DECISIVE (a sound pass or fail), do NOT climb to a model tier (spends no scarce free-tier call). Only
 * climb when the floor left the item marginal. Soundness still dominates in the cascade itself.
 */
export function costAdaptivePolicy(): EscalationPolicy {
  return {
    shouldEscalate(results, nextTierAvailable) {
      if (!nextTierAvailable) return false;
      const last = results[results.length - 1];
      if (!last) return true;
      // A SOUND decisive verdict (pass or fail) does not need a model tier — protect the budget.
      if (last.sound && last.decision !== "undecided") return false;
      // Otherwise climb only if the item is still marginal (certainty below 1).
      return (last.certainty ?? 1) < 1 || last.decision === "undecided";
    },
  };
}
