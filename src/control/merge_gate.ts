/**
 * Boot-level merge-gate invariant (Phase 2, Round 19).
 *
 * The human merge/approval gate on destructive/irreversible tiers is enforced at
 * the orchestration BOOT level, beyond RBAC's reach. No role — including superadmin
 * — can enable zero-click autonomous merge on those tiers. If the environment or CI
 * claims auto-merge for a gated tier, Keep REFUSES to operate on that tier rather
 * than honoring it. The invariant is set once at boot and frozen.
 */

import type { ActionTier } from "./action_tier.js";

/** Tiers on which autonomous (zero-click) merge is permanently forbidden. */
const GATED_TIERS: ReadonlySet<ActionTier> = new Set<ActionTier>(["irreversible"]);

export class MergeGateInvariant {
  /** Frozen at construction; cannot be mutated by any later RBAC/config change. */
  private readonly gatedTiers: ReadonlySet<ActionTier>;

  constructor(gatedTiers: ReadonlySet<ActionTier> = GATED_TIERS) {
    // Copy + freeze so no external reference can widen or narrow it later.
    this.gatedTiers = Object.freeze(new Set(gatedTiers));
  }

  /** True if human merge approval is mandatory for this tier (never overridable). */
  requiresHumanMerge(tier: ActionTier): boolean {
    return this.gatedTiers.has(tier);
  }

  /**
   * Decide whether an autonomous merge may proceed. If the tier is gated, the answer
   * is ALWAYS false regardless of what `envClaimsAutoMerge` says — and if the
   * environment claims auto-merge on a gated tier, that's a misconfiguration Keep
   * refuses rather than honors.
   */
  evaluateAutonomousMerge(
    tier: ActionTier,
    envClaimsAutoMerge: boolean,
  ): { allowed: boolean; refuseOperation: boolean; reason: string } {
    if (this.gatedTiers.has(tier)) {
      if (envClaimsAutoMerge) {
        return {
          allowed: false,
          refuseOperation: true,
          reason: `environment claims auto-merge on gated tier "${tier}" — refusing to operate on this tier`,
        };
      }
      return { allowed: false, refuseOperation: false, reason: `tier "${tier}" requires human merge (boot invariant)` };
    }
    // Non-gated tiers may follow policy.
    return { allowed: envClaimsAutoMerge, refuseOperation: false, reason: `tier "${tier}" not gated` };
  }
}
