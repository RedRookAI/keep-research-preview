/**
 * Budget-difficulty coupling (#40) + static routing/arbitrage (#44, v1 scope).
 *
 * v1 scope (Round 11): STATIC task-based routing — route each task to the cheapest
 * model that clears its difficulty class's MEASURED quality bar, within policy.
 * (Dynamic per-node arbitrage is deferred; FrugalGPT shows diminishing returns.)
 *
 * CRITICAL guardrail: arbitrage NEVER bypasses the quality judge. A cheaper model is
 * eligible only if it has met the quality bar for that difficulty class on measured
 * history; if it drops below bar it is demoted from the cheap tier. Savings are
 * MEASURED on your workload, never guaranteed.
 */

import { eligibleByPolicy } from "../routing/uncertainty_router.js";

export type DifficultyClass = "trivial" | "easy" | "moderate" | "hard";

export interface ModelQualityRecord {
  readonly model: string;
  /** Measured clean-resolved rate for this model at this difficulty class, 0..1. */
  readonly qualityByClass: Partial<Record<DifficultyClass, number>>;
  /** Blended price signal (USD per typical task) for ranking cheapest-first. */
  readonly typicalTaskUsd: number;
}

export interface RoutingPolicy {
  /** Models the operator permits at all (provider-agnostic; sovereignty/IP gated upstream). */
  readonly allowedModels: readonly string[];
  /** The minimum measured quality bar per difficulty class to be eligible. */
  readonly qualityBar: Record<DifficultyClass, number>;
}

export interface RoutingDecision {
  readonly model: string;
  readonly reason: string;
  /** Measured quality of the chosen model at this class. */
  readonly measuredQuality: number;
  readonly typicalTaskUsd: number;
}

/**
 * Choose the cheapest allowed model whose MEASURED quality at this difficulty class
 * meets the bar. Falls back to the highest-quality allowed model if none clears the
 * bar (never routes below quality to save money). Returns undefined only if no model
 * is allowed at all.
 */
export function routeTask(
  difficulty: DifficultyClass,
  models: readonly ModelQualityRecord[],
  policy: RoutingPolicy,
): RoutingDecision | undefined {
  const allowed = models.filter((m) => policy.allowedModels.includes(m.model));
  if (allowed.length === 0) return undefined;
  const bar = policy.qualityBar[difficulty];

  // Eligibility delegates to the single authoritative core gate: a quality BAR is the reversible-class,
  // zero-uncertainty consequence floor, and quality is the degenerate-posterior mean. Quality-bar routing has
  // no operator ceiling, so ceilingTier = +∞. Selection (cheapest clearing the bar; highest-quality fallback)
  // stays here — that is routeTask's distinct policy, not duplicated eligibility logic.
  const eligibleModels = new Set(
    eligibleByPolicy(
      allowed.map((m) => ({ model: m.model, tier: 0, estimate: m.qualityByClass[difficulty] ?? 0 })),
      bar,
      Number.POSITIVE_INFINITY,
      policy.allowedModels,
    ).map((i) => i.model),
  );
  const eligible = allowed.filter((m) => eligibleModels.has(m.model));

  if (eligible.length > 0) {
    // Cheapest eligible wins (arbitrage), quality already guaranteed by the filter.
    const chosen = [...eligible].sort((a, b) => a.typicalTaskUsd - b.typicalTaskUsd)[0]!;
    return {
      model: chosen.model,
      reason: `cheapest model clearing the ${difficulty} quality bar (${bar})`,
      measuredQuality: chosen.qualityByClass[difficulty] ?? 0,
      typicalTaskUsd: chosen.typicalTaskUsd,
    };
  }

  // Nobody clears the bar -> never trade quality for price; pick highest quality.
  const best = [...allowed].sort(
    (a, b) => (b.qualityByClass[difficulty] ?? 0) - (a.qualityByClass[difficulty] ?? 0),
  )[0]!;
  return {
    model: best.model,
    reason: `no model clears the ${difficulty} bar; routing to highest measured quality (quality over price)`,
    measuredQuality: best.qualityByClass[difficulty] ?? 0,
    typicalTaskUsd: best.typicalTaskUsd,
  };
}

/**
 * Measured savings vs a baseline model, on THIS workload. Positive = the routed
 * choice was cheaper. Presented as measured, never promised.
 */
export function measuredSavings(baselineUsd: number, routedUsd: number): { savedUsd: number; pct: number } {
  const savedUsd = baselineUsd - routedUsd;
  const pct = baselineUsd > 0 ? (savedUsd / baselineUsd) * 100 : 0;
  return { savedUsd, pct };
}
