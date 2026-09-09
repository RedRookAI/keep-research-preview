/**
 * Baseline metric + aggregate-drift detector (Phase 3.5, Round 12/16).
 *
 * "The learning loop helps" must be MEASURED, not assumed. The improvement metric is
 * the Clean-Resolved rate on a FROZEN held-out eval set, reported as the DELTA vs a
 * learning-DISABLED baseline — an A/B against Keep's own past self.
 *
 * Aggregate-drift (Simpson's paradox, a named 2026 concern): per-lesson checks
 * (shadow-mode, negative-flip) can all pass while the WHOLE system trends worse.
 * A periodic whole-system re-eval against the frozen set alerts on an aggregate
 * decline and triggers memory-state rollback.
 *
 * Goodhart mitigations: the held-out set is rotated, and metrics are corroborated
 * (resolved-rate up WITH regression-rate up is flagged, not celebrated).
 */

import type { Spine } from "../spine/spine.js";

export interface EvalResult {
  /** Fraction of held-out tasks Keep clean-resolved, 0..1. */
  readonly cleanResolvedRate: number;
  /** Fraction of held-out tasks that introduced a regression, 0..1. */
  readonly regressionRate: number;
}

/** The A/B improvement report: learning-enabled vs the frozen learning-disabled baseline. */
export interface ImprovementReport {
  readonly baseline: EvalResult;
  readonly current: EvalResult;
  /** current.cleanResolved - baseline.cleanResolved. Positive = learning helps. */
  readonly cleanResolvedDelta: number;
  /** True if resolved-rate rose but regression-rate ALSO rose (Goodhart red flag). */
  readonly corroborationConflict: boolean;
}

export function computeImprovement(baseline: EvalResult, current: EvalResult): ImprovementReport {
  const cleanResolvedDelta = current.cleanResolvedRate - baseline.cleanResolvedRate;
  const corroborationConflict =
    current.cleanResolvedRate > baseline.cleanResolvedRate &&
    current.regressionRate > baseline.regressionRate;
  return { baseline, current, cleanResolvedDelta, corroborationConflict };
}

export interface DriftCheck {
  readonly declined: boolean;
  readonly magnitude: number; // how far below the reference (0 if not declined)
  readonly shouldRollback: boolean;
}

export class AggregateDriftDetector {
  constructor(
    private readonly spine: Spine,
    /** Alert threshold: an aggregate decline beyond this triggers rollback. */
    private readonly declineThreshold: number = 0.05,
    private readonly clock: () => number = () => Date.now(),
  ) {}

  /**
   * Compare the latest whole-system eval against a reference (e.g. the best prior
   * or the rolling mean). Alerts + recommends rollback on a material aggregate
   * decline — even if every individual lesson passed its own checks.
   */
  check(reference: EvalResult, latest: EvalResult): DriftCheck {
    const drop = reference.cleanResolvedRate - latest.cleanResolvedRate;
    const declined = drop > 0;
    const shouldRollback = drop > this.declineThreshold;
    this.spine.stage({
      type: "identity.action",
      actor: "drift-detector",
      payload: {
        event: "aggregate_drift_check",
        referenceRate: reference.cleanResolvedRate,
        latestRate: latest.cleanResolvedRate,
        drop,
        shouldRollback,
        ts: this.clock(),
      },
    });
    return { declined, magnitude: declined ? drop : 0, shouldRollback };
  }
}
