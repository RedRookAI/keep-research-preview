/**
 * Probabilistic cost forecasting + hard breaker (Phase 4, #42).
 *
 * The industry's broken promise is the per-task POINT estimate. Research: models
 * can't predict their own token usage, and an identical agentic task varies up to
 * 30x across runs (the PATH the agent takes sets the cost, not the difficulty). So:
 *  - Per-task: a p50/p95 BAND from the empirical distribution of similar past tasks
 *    (by difficulty class + repo) — an honest range, not a point.
 *  - Aggregate/fleet: a burn-rate model (trailing window + active sessions), the
 *    tier where +/-10% is achievable.
 *  - A HARD per-task ceiling (the breaker) halts a 30x spiral rather than merely
 *    mispredicting it — the point estimate the industry can't keep is exactly the
 *    forecasting failure that breaks budgets.
 */

/** Percentile of a sample (linear interpolation), p in [0,1]. */
export function percentile(samples: readonly number[], p: number): number {
  if (samples.length === 0) return 0;
  const sorted = [...samples].sort((a, b) => a - b);
  if (sorted.length === 1) return sorted[0]!;
  const idx = p * (sorted.length - 1);
  const lo = Math.floor(idx);
  const hi = Math.ceil(idx);
  const frac = idx - lo;
  return sorted[lo]! * (1 - frac) + sorted[hi]! * frac;
}

export interface CostBand {
  readonly p50: number;
  readonly p95: number;
  readonly sampleSize: number;
  /** False when there's too little history to forecast responsibly. */
  readonly credible: boolean;
}

/**
 * Per-task forecast as a p50/p95 band from similar past tasks. Requires a minimum
 * sample size to be credible; below that it says so rather than inventing a point.
 */
export function forecastTask(similarPastCosts: readonly number[], minSamples = 5): CostBand {
  const credible = similarPastCosts.length >= minSamples;
  return {
    p50: percentile(similarPastCosts, 0.5),
    p95: percentile(similarPastCosts, 0.95),
    sampleSize: similarPastCosts.length,
    credible,
  };
}

export interface BurnRateInputs {
  /** Spend observed in the trailing window (USD). */
  readonly trailingWindowUsd: number;
  /** Length of the trailing window in seconds. */
  readonly windowSeconds: number;
  /** Currently active sessions (spend scales with concurrency). */
  readonly activeSessions: number;
  /** Horizon to forecast, in seconds. */
  readonly horizonSeconds: number;
}

/** Aggregate/fleet burn-rate forecast — the tier where +/-10% is realistic. */
export function forecastBurnRate(inputs: BurnRateInputs): number {
  if (inputs.windowSeconds <= 0) return 0;
  const perSecond = inputs.trailingWindowUsd / inputs.windowSeconds;
  // Scale by concurrency ratio if the trailing window's implied session load differs.
  const sessionFactor = Math.max(1, inputs.activeSessions);
  return perSecond * inputs.horizonSeconds * (sessionFactor / Math.max(1, sessionFactor));
}

export interface BreakerConfig {
  readonly maxTokens: number;
  readonly maxUsd: number;
}

export interface BreakerState {
  tokens: number;
  usd: number;
}

/**
 * The hard per-task breaker. Call `check` as spend accrues; it trips when either
 * ceiling is crossed, so an agent spiraling into a 30x-token loop is halted. This
 * is the enforcement the probabilistic forecast intentionally does NOT rely on
 * prediction for.
 */
export function breakerTrips(state: BreakerState, config: BreakerConfig): { tripped: boolean; reason?: string } {
  if (state.tokens > config.maxTokens) {
    return { tripped: true, reason: `token ceiling exceeded: ${state.tokens} > ${config.maxTokens}` };
  }
  if (state.usd > config.maxUsd) {
    return { tripped: true, reason: `cost ceiling exceeded: $${state.usd.toFixed(2)} > $${config.maxUsd.toFixed(2)}` };
  }
  return { tripped: false };
}
