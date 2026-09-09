/**
 * UnifiedVettingGate (Increment 16.8c) — the single cascade-based path that BOTH plan vetting and patch
 * vetting route through. Completes the vetting arc: instead of two separate gate implementations, each
 * gate supplies its own DETERMINISTIC Tier-0 floor adapter, and everything above (single-brain → hetero-
 * geneous second-brain → human) is the SHARED, capability-adaptive VerificationHarness.
 *
 * This is what makes the vetting uniform AND reach both ends of the room: the deterministic floor is
 * identical and always-on for every operator; only the model tiers adapt to the brain (rich up front,
 * lean/none at the back). Soundness dominates — a sound floor verdict is authoritative.
 *
 * Zero deps. Assembles the VerificationHarness; the floor adapters wrap the existing analyzeConsequences
 * (plans) and verifyPatch (patches) so there is ONE cascade and ONE audit shape for both gates.
 */

import { buildHarness, type BrainCapability } from "./verification_harness.js";
import type { EscalationPolicy } from "./verification_cascade.js";
import type { VerificationTier, VerificationItem, TierResult, CascadeOutcome } from "./verification_cascade.js";
import type { SingleBrainVerifier, ExternalBrainReviewer } from "./tier_adapters.js";
import type { Authorship } from "../review/heterogeneous.js";

/** What a caller provides for one gate: a deterministic floor that yields a sound verdict.
 *  `undecided` is sound too — the floor can soundly say "I can't decide this; climb it" (e.g. a heuristic concern that
 *  a model tier or human should weigh), which is NOT the same as a clean pass. */
export interface FloorAdapter<T> {
  readonly name: string;
  /** Run the deterministic floor; return a sound verdict. */
  evaluate(payload: T): { decision: "pass" | "fail" | "undecided"; reason: string };
}

/** Wrap a FloorAdapter as a sound Tier-0 VerificationTier. */
function floorTier<T>(adapter: FloorAdapter<T>): VerificationTier<T> {
  return {
    tier: 0, name: adapter.name, sound: true, available: () => true,
    verify: (item: VerificationItem<T>): TierResult => {
      const v = adapter.evaluate(item.payload);
      // pass/fail are decisive (certainty 1); undecided climbs (certainty 0.5) — a sound "can't decide", never a silent pass.
      return { tier: 0, name: adapter.name, decision: v.decision, reason: v.reason, sound: true, certainty: v.decision === "undecided" ? 0.5 : 1 };
    },
  };
}

export interface UnifiedGateConfig<T> {
  /** Escalation strategy override. Default: ConfidenceEscalationPolicy (via buildHarness). */
  readonly policy?: EscalationPolicy;
  readonly capability: BrainCapability;
  readonly singleBrain?: SingleBrainVerifier<T>;
  readonly singleBrainAuthorship?: Authorship;
  readonly secondBrain?: { reviewer: ExternalBrainReviewer<T>; identity: Authorship };
  /** Spine logger for the audit trail (each tier result). */
  readonly logger?: (tierResult: TierResult, itemId: string) => void;
}

/**
 * Build a gate function for one artifact kind (plan or patch). The floor is that gate's deterministic
 * check; the model tiers + human are the shared harness, adapted to the operator's brain capability.
 */
export function buildUnifiedGate<T>(
  floor: FloorAdapter<T>,
  config: UnifiedGateConfig<T>,
): (item: VerificationItem<T>) => Promise<CascadeOutcome> {
  const cascade = buildHarness<T>({
    floor: floorTier(floor),
    capability: config.capability,
    ...(config.singleBrain ? { singleBrain: config.singleBrain } : {}),
    ...(config.singleBrainAuthorship ? { singleBrainAuthorship: config.singleBrainAuthorship } : {}),
    ...(config.secondBrain ? { secondBrain: config.secondBrain } : {}),
    ...(config.policy ? { policy: config.policy } : {}),
    ...(config.logger ? { logger: config.logger as (r: unknown, itemId: string) => void } : {}),
  });
  return (item: VerificationItem<T>) => cascade.run(item);
}
