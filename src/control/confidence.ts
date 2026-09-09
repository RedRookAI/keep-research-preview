/**
 * Behavioral confidence estimator (Phase 2, #21/#25).
 *
 * DECISIVE research caveat: do NOT use the model's self-reported ("verbalized")
 * confidence — RLHF systematically degrades its calibration, rewarding
 * confident-sounding answers. Escalate on a CALIBRATED value derived from
 * observable PROCESS signals, not on how sure the agent "feels".
 *
 * Signals (all things Keep already observes): no-progress across iterations,
 * repeated failure fingerprints, best-of-N none-pass, inter-agent divergence,
 * trace/iteration length, prior human-override frequency for similar work.
 *
 * Also surfaces the "I'm stuck / selectively quit" honesty signal (#25) —
 * deferring when stuck is a safety win, not a failure.
 */

export interface ProcessSignals {
  /** Iterations with no measurable progress (higher = less confident). */
  readonly noProgressIterations: number;
  /** Distinct repeated failure fingerprints seen (loops). */
  readonly repeatedFailureFingerprints: number;
  /** Best-of-N attempts where none passed verification (0..1 fraction). */
  readonly bestOfNNonePassRate: number;
  /** Inter-agent divergence, 0 (agree) .. 1 (fully disagree). */
  readonly interAgentDivergence: number;
  /** Trace length relative to the typical successful trace (1.0 = normal, >1 worse). */
  readonly traceLengthRatio: number;
  /** Historical human-override rate for similar tasks, 0..1. */
  readonly priorOverrideRate: number;
}

/** Weights for each signal's contribution to the penalty (sum used for normalization). */
const WEIGHTS = {
  noProgress: 0.22,
  repeatedFailures: 0.18,
  bestOfN: 0.22,
  divergence: 0.15,
  traceLength: 0.10,
  priorOverride: 0.13,
} as const;

function clamp01(x: number): number {
  return x < 0 ? 0 : x > 1 ? 1 : x;
}

/**
 * Estimate calibrated confidence in [0,1] from process signals. Purely behavioral.
 * 1.0 = strong process evidence of success; low = escalate.
 */
export function estimateConfidence(s: ProcessSignals): number {
  // Each signal maps to a 0..1 "trouble" score, combined into a penalty.
  const noProgress = clamp01(s.noProgressIterations / 5); // 5+ no-progress iters = max trouble
  const repeated = clamp01(s.repeatedFailureFingerprints / 3);
  const bestOfN = clamp01(s.bestOfNNonePassRate);
  const divergence = clamp01(s.interAgentDivergence);
  const traceLen = clamp01((s.traceLengthRatio - 1) / 2); // 3x normal = max trouble
  const override = clamp01(s.priorOverrideRate);

  const penalty =
    noProgress * WEIGHTS.noProgress +
    repeated * WEIGHTS.repeatedFailures +
    bestOfN * WEIGHTS.bestOfN +
    divergence * WEIGHTS.divergence +
    traceLen * WEIGHTS.traceLength +
    override * WEIGHTS.priorOverride;

  return clamp01(1 - penalty);
}

/**
 * The "#25 selectively quit" honesty signal: is the agent stuck enough that
 * deferring to a human is the safe move, independent of the confidence number?
 * True on hard loop/no-progress evidence — a safety win.
 */
export function shouldSelfQuit(s: ProcessSignals): boolean {
  return (
    s.noProgressIterations >= 4 ||
    s.repeatedFailureFingerprints >= 3 ||
    (s.bestOfNNonePassRate >= 0.99 && s.traceLengthRatio >= 2)
  );
}
