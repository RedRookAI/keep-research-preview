/**
 * SolveOutcomeWire (Increment 18.W) — the adapter that connects the SOLVE PIPELINE to the SELF-IMPROVEMENT
 * subsystem. Before 18.W, KeepPipeline.solveToPr produced a SolveToPrResult that nobody fed back: the bus
 * (18.1), drift monitor (C4), and reference monitor (C1) were wired into composeKeep but received no REAL
 * signals — only demo/test traffic. 18.W closes that: every real solve is mapped to an OutcomeSignal and
 * published, and irreversible actions are checked against the trace-level ReferenceMonitor first.
 *
 * Design: a standalone adapter behind a port, NOT a coupling inside the pipeline. The pipeline stays
 * swappable and knows nothing about learning; the wire translates its output. This is the "no islands"
 * fix done without creating a new coupling island. Zero runtime deps.
 *
 * SOTA basis (2026-08-05): the Adaptive Data Flywheel (arXiv 2510.27051) — the Monitor phase must be fed by
 * PRODUCTION outcomes, not synthetic ones, or the loop learns nothing real. The merge/reject verdict is
 * supplied LATER (the human reviews asynchronously); 18.W emits the solve-time signal immediately (with
 * mergeVerdict "pending") and exposes recordMergeVerdict() for the human decision when it arrives.
 */

import type { SelfImprovementBus, OutcomeSignal, MergeVerdict, LearningErrorSink, LearningFailure } from "./self_improvement_bus.js";
import type { ReferenceMonitor, TraceEvent, ClauseVerdict } from "../control/reference_monitor.js";
import type { NeedScopeBinding } from "../autonomy/need_scheduler.js";

/** The minimal shape of a solve result the wire needs (structurally compatible with SolveToPrResult). */
export interface SolveResultLike {
  readonly solveResult: { readonly issueId: string; readonly solved: boolean };
  readonly published?: unknown;
  readonly safety?: {
    readonly isolationTier?: string;
    readonly vettingCleared?: boolean;
    readonly vettingReason?: string;
  };
}

export interface WireOptions {
  /** The task shape (issue kind) for curriculum + skill relevance. Falls back to "build". */
  readonly taskShape?: string;
  /** Which artifacts (skills/prompts/lessons) were active on this solve (for reuse-reward credit). */
  readonly activeArtifacts?: readonly string[];
  readonly costUnits?: number;
}

/**
 * Maps a solve result → an OutcomeSignal. testsPassed is grounded in the REAL solve outcome (solved = the
 * produced patch passed validation). mergeVerdict starts "pending" — the human reviews the PR asynchronously;
 * recordMergeVerdict() publishes the follow-up signal when they decide.
 */
export class SolveOutcomeWire {
  private readonly bus: SelfImprovementBus;
  private readonly monitor: ReferenceMonitor | undefined;

  constructor(bus: SelfImprovementBus, monitor?: ReferenceMonitor, private readonly scope?: NeedScopeBinding,
    private readonly errorSink?: LearningErrorSink) {
    this.bus = bus;
    this.monitor = monitor;
  }

  /** Build the solve-time OutcomeSignal from a solve result (mergeVerdict pending). */
  toSignal(result: SolveResultLike, opts: WireOptions = {}): OutcomeSignal {
    return {
      solveId: result.solveResult.issueId,
      ...(this.scope === undefined ? {} : { scopeId: this.scope.scopeId, scopeToken: this.scope.token }),
      taskShape: opts.taskShape ?? "build",
      testsPassed: result.solveResult.solved,
      ...(result.safety?.vettingCleared !== undefined ? { vetVerdict: result.safety.vettingCleared ? "pass" : "escalate" } : {}),
      ...(result.safety?.isolationTier !== undefined ? { isolationTier: result.safety.isolationTier } : {}),
      mergeVerdict: "pending" as MergeVerdict,
      ...(opts.activeArtifacts ? { activeArtifacts: opts.activeArtifacts } : {}),
      ...(opts.costUnits !== undefined ? { costUnits: opts.costUnits } : {}),
      timestamp: Date.now(),
    };
  }

  /** Publish the solve-time outcome to the bus (records to spine + gates learning on readiness). */
  async publishSolve(result: SolveResultLike, opts: WireOptions = {}): Promise<{ recorded: boolean; dispatched: boolean }> {
    const signal = this.toSignal(result, opts);
    const r = await this.bus.publish(signal);
    return { recorded: r.recorded, dispatched: r.dispatched };
  }

  /**
   * The human's merge/reject decision arrives later. Publish the follow-up signal carrying the reuse verdict
   * (merge = positive, reject = negative, reason → counterexample). Zero extra human effort: this is the
   * decision they already make in review.
   */
  async recordMergeVerdict(
    result: SolveResultLike,
    verdict: "merged" | "rejected",
    opts: WireOptions & { rejectReason?: string } = {},
  ): Promise<{ recorded: boolean; dispatched: boolean }> {
    const base = this.toSignal(result, opts);
    const signal: OutcomeSignal = {
      ...base,
      mergeVerdict: verdict,
      ...(verdict === "rejected" && opts.rejectReason ? { rejectReason: opts.rejectReason } : {}),
      timestamp: Date.now(),
    };
    const r = await this.bus.publish(signal);
    return { recorded: r.recorded, dispatched: r.dispatched };
  }

  /**
   * Trace-level guard for an IRREVERSIBLE action (e.g. an autonomous merge on a gated tier). Consults the
   * ReferenceMonitor: returns the violations that would occur if this action committed. Empty = safe. The
   * caller MUST deny the action on any violation. If no monitor is wired, returns [] (no enforcement).
   */
  guardIrreversible(candidate: TraceEvent): ClauseVerdict[] {
    return this.monitor ? this.monitor.wouldViolate(candidate) : [];
  }

  /** Spine-independent failures visible through the composed app's existing wire surface. */
  learningFailures(): readonly LearningFailure[] { return this.errorSink?.snapshot?.() ?? []; }

  /**
   * The integration seam: wrap a pipeline's solve function so EVERY solve auto-publishes its outcome to the
   * loop — without coupling the pipeline to the learning subsystem. The caller keeps constructing the
   * pipeline with its own environment ports; they just call the wrapped solve instead of the raw one, and
   * outcomes flow to the bus automatically. Returns the original result unchanged.
   */
  wrapSolve<A extends unknown[], R extends SolveResultLike>(
    solve: (...args: A) => Promise<R>,
    opts: WireOptions = {},
  ): (...args: A) => Promise<R> {
    return async (...args: A): Promise<R> => {
      const result = await solve(...args);
      try {
        await this.publishSolve(result, opts);
      } catch (error) {
        try { this.errorSink?.report({ phase: "outcome-publish", componentId: "solve-outcome-wire",
          error: error instanceof Error ? `${error.name}: ${error.message}`.slice(0, 4096) : "unknown outcome publication failure",
          timestamp: Date.now() }); } catch { /* diagnostics cannot replace the successful solve result */ }
      }
      return result;
    };
  }
}
