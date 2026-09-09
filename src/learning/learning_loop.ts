/**
 * Auto-Learning: the LearningLoop (Increment 6a) — closes observe→distill→promote/retire.
 *
 * SOTA basis (2026-08-04): gradient-free continual learning is the safe tier — improve by
 * manipulating memory/context, not weights (JitRL Jan 2026; Letta learning-sdk Feb 2026). The
 * weight-level "rise-then-collapse" collapse (arXiv 2606.21090) is a GRADIENT pathology; by staying
 * gradient-free and promoting/retiring LESSONS, Keep structurally avoids it — but memory drift,
 * stale context, and reward-hacking on the promotion metric remain live risks (ICLR 2026 RSI
 * workshop), which the RegressionGuard (6b) covers.
 *
 * This loop does NOT reinvent tier transitions. The MemoryStore already implements the two-gate
 * graduation (candidate→probation→confirmed) and negative-flip demotion via recordOutcome(). The
 * LearningLoop's job is to CLOSE the loop: observe verified build outcomes → route them to the right
 * lessons as evidence (distill) → let graduation happen → and measure whether learning actually
 * helps (A/B vs a frozen baseline, via computeImprovement) so the guard can catch a regression.
 *
 * Zero deps.
 */

import type { MemoryStore } from "../memory/store.js";
import type { Lesson } from "../memory/model.js";
import { computeImprovement, type EvalResult, type ImprovementReport } from "./baseline_metric.js";

/** One observed build outcome to learn from. */
export interface LearningObservation {
  /** Lessons that were in-context / applied for this build (their evidence gets updated). */
  readonly appliedLessonIds: readonly string[];
  /** Did the build clean-resolve (the objective anchor)? */
  readonly cleanResolved: boolean;
  /** Free-text context (task shape / project) — kept for auditable evidence. */
  readonly context: string;
}

/** The report from one learning step (a batch of observations). */
export interface LearningStepReport {
  readonly observed: number;
  readonly outcomesRecorded: number;
  /** Lesson ids that graduated to confirmed during this step. */
  readonly graduated: readonly string[];
  /** Lesson ids that were demoted (negative-flip) during this step. */
  readonly demoted: readonly string[];
  /** The A/B improvement vs the frozen baseline, if an eval was supplied. */
  readonly improvement?: ImprovementReport;
  /** The primary metric value for this step (clean-resolved rate over the batch). */
  readonly primaryMetric: number;
  /** A diversity/variance signal over the batch — the collapse early-warning input (6b). */
  readonly diversitySignal: number;
}

export interface LearningLoopDeps {
  readonly memory: MemoryStore;
  /**
   * Optional frozen baseline (learning-disabled) eval, for the A/B improvement check. When present,
   * each step compares the current eval against it — the corroboration/Goodhart flag comes free.
   */
  readonly baseline?: EvalResult;
}

export class LearningLoop {
  constructor(private readonly deps: LearningLoopDeps) {}

  /**
   * Run one learning step over a batch of observations. Records each outcome against the applied
   * lessons (the MemoryStore runs graduation/demotion), then reports the metric trajectory + the
   * diversity signal for the RegressionGuard. `currentEval` (if given) is this step's held-out eval.
   */
  step(observations: readonly LearningObservation[], currentEval?: EvalResult): LearningStepReport {
    const tierBefore = this.snapshotTiers();

    let outcomesRecorded = 0;
    for (const obs of observations) {
      for (const lessonId of obs.appliedLessonIds) {
        this.deps.memory.recordOutcome(lessonId, obs.cleanResolved, obs.context);
        outcomesRecorded++;
      }
    }

    const tierAfter = this.snapshotTiers();
    const graduated: string[] = [];
    const demoted: string[] = [];
    for (const [id, after] of tierAfter) {
      const before = tierBefore.get(id);
      if (before === after) continue;
      if (after === "confirmed" && before !== "confirmed") graduated.push(id);
      if ((before === "confirmed") && (after === "probation" || after === "retired")) demoted.push(id);
    }

    const cleanCount = observations.filter((o) => o.cleanResolved).length;
    const primaryMetric = observations.length === 0 ? 0 : cleanCount / observations.length;
    const diversitySignal = this.diversity(observations);

    let improvement: ImprovementReport | undefined;
    if (this.deps.baseline && currentEval) {
      improvement = computeImprovement(this.deps.baseline, currentEval);
    }

    return {
      observed: observations.length,
      outcomesRecorded,
      graduated,
      demoted,
      ...(improvement !== undefined ? { improvement } : {}),
      primaryMetric,
      diversitySignal,
    };
  }

  /** Snapshot every lesson's current tier (for graduate/demote diffing). */
  private snapshotTiers(): Map<string, Lesson["tier"]> {
    const m = new Map<string, Lesson["tier"]>();
    for (const l of this.deps.memory.all()) m.set(l.id, l.tier);
    return m;
  }

  /**
   * Diversity signal over a batch: the fraction of DISTINCT contexts among observations. Collapse
   * shows up as this dropping toward near-constant behavior (the "Echo Trap" / std-collapse early
   * warning from RAGEN arXiv 2504.20073). 1 = all distinct; →0 = repetitive/collapsing.
   */
  private diversity(observations: readonly LearningObservation[]): number {
    if (observations.length === 0) return 1;
    const distinct = new Set(observations.map((o) => o.context)).size;
    return distinct / observations.length;
  }
}
