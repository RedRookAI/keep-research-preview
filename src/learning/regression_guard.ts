/**
 * Auto-Learning: the RegressionGuard (Increment 6b) — self-regression + reward-hacking guard.
 *
 * SOTA basis (2026-08-04): the rise-then-collapse failure mode — a metric peaks then collapses,
 * from within-task over-optimization; KL/EWC constraints do NOT prevent it (arXiv 2606.21090). The
 * recoveries that work are memory-level: track the PEAK and roll forward the peak checkpoint (that
 * paper's CARE/ES). Early-warning signals precede the reward collapse — reward std / output entropy
 * destabilize BEFORE the mean degrades (RAGEN arXiv 2504.20073), so a diversity-collapse signal is a
 * LEADING indicator. Reward hacking shows as the metric rising while a corroborating quality signal
 * degrades (RLIF arXiv 2605.22620) — reused here as the Goodhart conflict flag. On any trip: freeze,
 * roll back to the last-good peak, flag the human (ICLR 2026 RSI workshop: fallback to safe baseline
 * + layered approval).
 *
 * This guard is gradient-free-appropriate: it watches the LEARNING loop's metric trajectory (lesson
 * promotion quality), not gradients. It reuses RollbackLedger + the spine — it does not reinvent
 * rollback. Zero deps.
 */

import type { Spine } from "../spine/spine.js";
import type { RollbackLedger } from "../control/rollback.js";
import type { LearningStepReport } from "./learning_loop.js";

export type RegressionTripKind =
  | "drop-from-peak" // primary metric fell from its peak beyond the tolerance (rise-then-collapse)
  | "diversity-collapse" // early-warning: behavior collapsed toward repetition before the metric fell
  | "goodhart-conflict"; // metric rose while a corroborating signal degraded (reward hacking)

export interface RegressionTrip {
  readonly kind: RegressionTripKind;
  readonly reason: string;
  readonly peak: number;
  readonly current: number;
  readonly step: number;
}

export interface RegressionGuardOptions {
  /**
   * How far the primary metric may fall below its running peak before it's a collapse. Default 0.15
   * (15 points). Configurable — tuned against deployment telemetry.
   */
  readonly dropTolerance?: number;
  /**
   * Diversity floor: below this, behavior has collapsed toward repetition (leading indicator).
   * Default 0.25.
   */
  readonly diversityFloor?: number;
  /** Minimum steps observed before drop-from-peak can trip (let the peak establish). Default 2. */
  readonly warmupSteps?: number;
}

export interface RegressionGuardDeps {
  readonly spine: Spine;
  readonly rollback: RollbackLedger;
  readonly options?: RegressionGuardOptions;
}

export interface GuardObservation {
  readonly tripped: boolean;
  readonly trip?: RegressionTrip;
  readonly frozen: boolean;
  readonly peak: number;
}

export class RegressionGuard {
  private peak = -Infinity;
  private peakStep = -1;
  private step = 0;
  private frozen = false;
  private readonly opts: Required<RegressionGuardOptions>;

  constructor(private readonly deps: RegressionGuardDeps) {
    this.opts = {
      dropTolerance: deps.options?.dropTolerance ?? 0.15,
      diversityFloor: deps.options?.diversityFloor ?? 0.25,
      warmupSteps: deps.options?.warmupSteps ?? 2,
    };
  }

  get isFrozen(): boolean {
    return this.frozen;
  }

  /** The last-good (peak) step index — what a rollback rolls forward to. */
  get lastGoodStep(): number {
    return this.peakStep;
  }

  /**
   * Observe one learning step. Updates the running peak, checks the three trip conditions (Goodhart
   * first — it can fire even while the metric rises; then early-warning diversity; then drop-from-
   * peak), and on any trip freezes the loop + rolls back to the last-good peak + flags the human.
   * Returns whether it tripped. Once frozen, stays frozen until reset() (human-gated).
   */
  async observe(report: LearningStepReport): Promise<GuardObservation> {
    if (this.frozen) {
      return { tripped: false, frozen: true, peak: this.peak };
    }
    this.step++;
    const metric = report.primaryMetric;

    this.spine.stage({ type: "identity.action", actor: "learning", payload: { event: "learning_step", step: this.step, metric, diversity: report.diversitySignal } });

    // 1. Goodhart / reward-hacking: metric up but corroborating quality down.
    if (report.improvement?.corroborationConflict) {
      return this.trip("goodhart-conflict", `clean-resolved rose but regression-rate ALSO rose (Goodhart): the promotion metric is being gamed`, metric);
    }

    // 2. Early-warning: diversity collapse BEFORE the metric falls (leading indicator).
    if (report.diversitySignal < this.opts.diversityFloor && this.step > this.opts.warmupSteps) {
      return this.trip("diversity-collapse", `behavior diversity ${report.diversitySignal.toFixed(2)} below floor ${this.opts.diversityFloor} — repetition/echo-trap collapse forming before metric drop`, metric);
    }

    // Track the peak.
    if (metric > this.peak) {
      this.peak = metric;
      this.peakStep = this.step;
    }

    // 3. Confirming: drop-from-peak beyond tolerance (rise-then-collapse).
    if (this.step > this.opts.warmupSteps && this.peak - metric > this.opts.dropTolerance) {
      return this.trip("drop-from-peak", `primary metric fell from peak ${this.peak.toFixed(2)} to ${metric.toFixed(2)} (> ${this.opts.dropTolerance} tolerance) — rise-then-collapse`, metric);
    }

    return { tripped: false, frozen: false, peak: this.peak };
  }

  /** Freeze + roll back to the last-good peak + flag the human. Never silently continues. */
  private async trip(kind: RegressionTripKind, reason: string, current: number): Promise<GuardObservation> {
    this.frozen = true;
    const trip: RegressionTrip = { kind, reason, peak: this.peak === -Infinity ? current : this.peak, current, step: this.step };
    this.spine.stage({ type: "identity.action", actor: "learning", payload: { event: "regression_tripped", ...trip } });
    // Roll back learning actions taken since the peak (LIFO inverses) — restore last-good state.
    const stepsToUndo = Math.max(0, this.step - this.peakStep);
    await this.deps.rollback.rollback(stepsToUndo, `regression-guard ${kind}: restore last-good peak`);
    this.spine.stage({ type: "identity.action", actor: "learning", payload: { event: "frozen_pending_human", kind, reason, rolledBackSteps: stepsToUndo } });
    return { tripped: true, trip, frozen: true, peak: trip.peak };
  }

  /** Human-gated resume after review (the merge/approval owner stays in control). */
  reset(justification: string): void {
    this.spine.stage({ type: "identity.action", actor: "learning", payload: { event: "guard_reset", justification, atStep: this.step } });
    this.frozen = false;
    // keep the peak — we roll forward from the last-good state, we don't forget it.
  }

  private get spine(): Spine {
    return this.deps.spine;
  }
}
