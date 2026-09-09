/**
 * VerificationCascade — tier abstraction + generic ladder (Increment 3.9a).
 *
 * SOTA basis (re-verified 2026-08-04): the winning production pattern is the eval-pyramid CASCADE —
 * "floor on every request, classifier on the residual, judge on the survivor sample; every layer
 * runs only on what the cheaper layer below could not decide" (futureagi; tianpan; NeuralTrust).
 * The deterministic floor is cheaper AND more reliable on what it covers (the $40K judge-missed-an-
 * order-of-magnitude-bug war story). Cascades cut cost 45-85% while keeping 95-99% of quality.
 *
 * This is the operator's insight generalized: run the cheap, sound, single-/no-brain checks FIRST
 * every round, escalate only the residual to an external brain when one exists. It unifies the
 * single-brain floor and the multi-brain ceiling into ONE architecture:
 *   Tier 0 — DETERMINISTIC FLOOR (no brain): sound executable checks; runs on EVERY item.
 *   Tier 1 — SINGLE-BRAIN: resolves the floor's residual via selective self-verification (flag-only).
 *   Tier 2 — EXTERNAL / SECOND-BRAIN: independent review on the still-marginal residual (if available).
 *   Tier 3 — HUMAN: final fallback for still-unresolved AND consequential items.
 *
 * Invariant (soundness dominates): a fuzzy tier can NEVER un-block a sound Tier-0 block.
 *
 * Zero deps; all tiers behind ports.
 */

/** The thing being verified (a plan, an artifact, a claim, a memory write, ...). */
export interface VerificationItem<T = unknown> {
  readonly id: string;
  readonly kind: string; // "plan" | "artifact" | "research-claim" | "memory-write" | ...
  readonly payload: T;
}

/** A tier's decision on an item. `undecided` means "climb to the next tier". */
export type TierDecision = "pass" | "fail" | "undecided";

export interface TierResult {
  readonly tier: number;
  readonly name: string;
  readonly decision: TierDecision;
  readonly reason: string;
  /** True if this tier is SOUND (deterministic). A sound `fail` cannot be overturned above. */
  readonly sound: boolean;
  /** Confidence/marginality in [0,1] the tier attaches (drives escalation). 1 = certain. */
  readonly certainty: number;
}

/** A verification tier — a check that can pass/fail/defer an item. Behind a port. */
export interface VerificationTier<T = unknown> {
  readonly tier: number;
  readonly name: string;
  /** True if this tier's verdicts are sound (deterministic). */
  readonly sound: boolean;
  /** Whether this tier is currently available (e.g. Tier 2 only if a 2nd brain is registered). */
  available(): boolean;
  /** Verify an item. Return `undecided` to let the cascade climb. */
  verify(item: VerificationItem<T>): TierResult | Promise<TierResult>;
}

/** The full outcome of running the cascade on one item. */
export interface CascadeOutcome {
  readonly itemId: string;
  readonly finalDecision: "pass" | "fail" | "escalate-human";
  /** The tier that produced the final decision. */
  readonly decidedAtTier: number;
  /** Every tier result, in order (the audit trail — spine-loggable). */
  readonly trail: readonly TierResult[];
  readonly reason: string;
}

/** How escalation decisions are made (injected — see 3.9b). */
export interface EscalationPolicy {
  /**
   * Given the results so far, should the cascade climb to `nextTier`? Also used for pre-routing:
   * `preRoute(item)` may return a tier to jump straight to, skipping cheaper passes.
   */
  shouldEscalate(results: readonly TierResult[], nextTierAvailable: boolean): boolean;
  /** Optional pre-route: return a starting tier > 0 for predictably-hard items (skip cheap pass). */
  preRoute?(item: VerificationItem): number;
}

export class VerificationCascade<T = unknown> {
  private readonly tiers: VerificationTier<T>[];
  constructor(
    tiers: readonly VerificationTier<T>[],
    private readonly policy: EscalationPolicy,
    private readonly logger?: (r: TierResult, itemId: string) => void,
  ) {
    // sort ascending by tier so the floor runs first
    this.tiers = [...tiers].sort((a, b) => a.tier - b.tier);
  }

  /**
   * Run the cascade on an item. The floor (lowest tier) runs first; each higher tier runs ONLY on
   * the residual the tier below couldn't decide. A SOUND fail short-circuits (soundness dominates —
   * no higher fuzzy tier can un-block it). Returns the outcome + full audit trail.
   */
  async run(item: VerificationItem<T>): Promise<CascadeOutcome> {
    const trail: TierResult[] = [];
    const startTier = this.policy.preRoute?.(item) ?? 0;

    for (const tier of this.tiers) {
      // Pre-routing may skip cheap FUZZY tiers, but never a SOUND one: the deterministic floor is cheap AND
      // authoritative, so it always runs — a policy can't pre-route past a sound gate (a sound fail must block).
      if (tier.tier < startTier && !tier.sound) continue;
      if (!tier.available()) continue; // e.g. Tier 2 with no second brain — skip cleanly

      const result = await tier.verify(item);
      trail.push(result);
      this.logger?.(result, item.id);

      if (result.decision === "pass" || result.decision === "fail") {
        // A sound decision is final. A fuzzy decision is final too UNLESS the policy wants to
        // escalate for a second opinion on a marginal fuzzy verdict.
        if (result.sound) {
          return this.finalize(item.id, result, trail);
        }
        // fuzzy decided: escalate only if the policy says the verdict is too marginal AND a higher
        // tier is available; otherwise accept the fuzzy decision.
        const higher = this.tiers.find((t) => t.tier > result.tier && t.available());
        if (higher && this.policy.shouldEscalate(trail, true)) {
          continue; // climb for a second opinion on the marginal fuzzy verdict
        }
        return this.finalize(item.id, result, trail);
      }

      // undecided → climb if a higher available tier exists AND the policy permits
      const higher = this.tiers.find((t) => t.tier > tier.tier && t.available());
      if (!higher || !this.policy.shouldEscalate(trail, !!higher)) {
        // nothing above (or policy declines) → unresolved → human
        return {
          itemId: item.id,
          finalDecision: "escalate-human",
          decidedAtTier: 3,
          trail,
          reason: higher ? "policy declined further escalation; unresolved → human" : "no higher tier available; unresolved → human",
        };
      }
      // else loop continues to the next available tier
    }

    // Ran out of tiers without a pass/fail → human.
    return {
      itemId: item.id,
      finalDecision: "escalate-human",
      decidedAtTier: 3,
      trail,
      reason: "cascade exhausted without a decision → human",
    };
  }

  private finalize(itemId: string, result: TierResult, trail: readonly TierResult[]): CascadeOutcome {
    return {
      itemId,
      finalDecision: result.decision === "pass" ? "pass" : "fail",
      decidedAtTier: result.tier,
      trail,
      reason: `${result.name} (tier ${result.tier}) ${result.decision}: ${result.reason}`,
    };
  }
}
