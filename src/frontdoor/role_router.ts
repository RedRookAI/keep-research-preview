/**
 * F1.8 — Role-based routing ("best model for planning, cheap for execution").
 *
 * This is the moat. "Gets better as you use it" only compounds toward EXCELLENCE if
 * the high-stakes reasoning — planning, and the learning loop's own distillation and
 * reflection — is done by the best available brain. Cheap reasoning at those steps
 * poisons the flywheel: shallower plans -> worse outcomes -> thinner lessons ->
 * a library that compounds toward confident mediocrity. So planning ALWAYS routes to
 * the best available brain; only mechanical work economizes.
 *
 * SOTA basis (Aug 2026): role-based (structural) routing is the recommended pattern —
 * "the planner uses a frontier model; tool-call steps use a cheap fast model." It is
 * preferred over per-query classification because role profiles are stable, add zero
 * latency, have ZERO adversarial surface (no classifier to manipulate), are
 * deterministic, and leave a full audit trail. Picking one model for everything is
 * now called "architectural negligence." What would change it: adding a difficulty
 * signal WITHIN the mechanical tier — but planning stays quality-first regardless.
 *
 * CRITICAL (Mindra 2026): "silent degradation to a mismatched model is worse than an
 * explicit failure." So when no strong brain is available, planning runs on the best
 * we have AND records degraded=true — an explicit, audited fact, never silent.
 */

import type { BrainDescriptor } from "./brain_port.js";
import { classifyCapability, type CapabilityTier } from "./capability_adaptive.js";

/** The role a given LLM call plays. Planning-class routes to the best brain. */
export type TaskRole =
  // --- planning-class (high-stakes reasoning: best available brain, always) ---
  | "plan_decompose" // break a goal/ticket into subtasks
  | "sequence_work" // order the steps
  | "architecture_decision" // design/trade-off calls
  | "distill_lesson" // turn an outcome into a durable lesson (LEARNING LOOP)
  | "reflect_curate" // periodic reflection over the library (LEARNING LOOP)
  // --- mechanical-class (bounded work: may economize) ---
  | "converse" // drive the onboarding/chat turn
  | "extract" // pull structured fields from text
  | "classify" // label/route
  | "format" // shape output
  | "summarize_routine"; // routine summarization

const PLANNING_ROLES: ReadonlySet<TaskRole> = new Set<TaskRole>([
  "plan_decompose",
  "sequence_work",
  "architecture_decision",
  "distill_lesson",
  "reflect_curate",
]);

/** True if a role is planning-class (must use the best available brain). */
export function isPlanningRole(role: TaskRole): boolean {
  return PLANNING_ROLES.has(role);
}

/** A brain plus the capability tier we've assessed for it. */
export interface RankedBrain {
  readonly brain: BrainDescriptor;
  readonly tier: CapabilityTier;
  /** A comparable capability score (higher = more capable). */
  readonly score: number;
}

/** Operator preference — overridable from the chat box at any time. */
export interface RoutingPreference {
  /**
   * "quality" (default): planning always uses the best brain.
   * "balanced": planning uses best; mechanical uses cheapest.
   * "cost": operator explicitly accepts cheaper planning to save money.
   */
  readonly costPreference: "quality" | "balanced" | "cost";
}

export const DEFAULT_PREFERENCE: RoutingPreference = { costPreference: "quality" };

const TIER_SCORE: Record<CapabilityTier, number> = { rich: 3, standard: 2, lean: 1, minimal: 0 };

export interface RoutingRecord {
  readonly role: TaskRole;
  readonly chosenBrain: string; // providerLabel
  readonly chosenTier: CapabilityTier;
  /** True if this is planning-class work forced onto a less-than-'rich' brain. */
  readonly degraded: boolean;
  /** Plain-language reason (for the audit trail + optional dashboard). */
  readonly reason: string;
}

export interface RoutingResult {
  readonly brain: BrainDescriptor;
  readonly record: RoutingRecord;
}

/**
 * Routes a task to a brain by its ROLE. Planning-class -> best available brain;
 * mechanical-class -> cheapest capable brain (unless the operator prefers quality
 * everywhere). Rank brains once (via capability signals) and pass them in.
 */
export class RoleRouter {
  constructor(
    private readonly ranked: readonly RankedBrain[],
    private readonly preference: RoutingPreference = DEFAULT_PREFERENCE,
  ) {
    if (ranked.length === 0) throw new Error("RoleRouter needs at least one brain");
  }

  /** Build a router from raw brains + their capability signals. */
  static fromBrains(
    brains: readonly { brain: BrainDescriptor; signals?: Parameters<typeof classifyCapability>[1] }[],
    preference: RoutingPreference = DEFAULT_PREFERENCE,
  ): RoleRouter {
    const ranked = brains.map(({ brain, signals }) => {
      const tier = classifyCapability(brain, signals ?? {});
      return { brain, tier, score: TIER_SCORE[tier] };
    });
    return new RoleRouter(ranked, preference);
  }

  private best(): RankedBrain {
    return this.ranked.reduce((a, b) => (b.score > a.score ? b : a));
  }
  private cheapest(): RankedBrain {
    // Lowest-capability brain = cheapest proxy (cost tracks capability here).
    return this.ranked.reduce((a, b) => (b.score < a.score ? b : a));
  }

  route(role: TaskRole): RoutingResult {
    const planning = isPlanningRole(role);

    // Planning always uses the best available brain — UNLESS the operator explicitly
    // opted into cheaper planning ("cost").
    if (planning && this.preference.costPreference !== "cost") {
      const best = this.best();
      const degraded = best.tier !== "rich"; // planning on a less-than-frontier brain
      return {
        brain: best.brain,
        record: {
          role,
          chosenBrain: best.brain.providerLabel,
          chosenTier: best.tier,
          degraded,
          reason: degraded
            ? `Planning needs the strongest brain; the best available here is ${best.brain.providerLabel} (${best.tier}). Doing our best, and flagging that plan quality is capped by the available model.`
            : `Planning routed to the best available brain (${best.brain.providerLabel}).`,
        },
      };
    }

    // Mechanical work (or operator chose "cost" planning): pick the brain per
    // preference. "quality" => best everywhere; "balanced"/"cost" => cheapest for
    // mechanical work. Using a cheap brain for mechanical work is CORRECT, not degraded.
    const chosen = this.preference.costPreference === "quality" ? this.best() : this.cheapest();
    return {
      brain: chosen.brain,
      record: {
        role,
        chosenBrain: chosen.brain.providerLabel,
        chosenTier: chosen.tier,
        degraded: false,
        reason: `Routine work routed to ${chosen.brain.providerLabel} (${chosen.tier}).`,
      },
    };
  }
}
