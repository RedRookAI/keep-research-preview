/**
 * SelfImprovementBus (Increment 18.1) — the Monitor wire that CLOSES THE LOOP. Before this, every solve was
 * forgotten: LearningLoop/MemoryStore/MetaHarness were reachable only from demos/tests, and the heartbeat
 * tick defaulted to a no-op. 18.1 makes Keep "get better with use" AUTOMATIC: the pipeline emits a structured
 * OutcomeSignal after every solve; the bus fans it to registered learners, records it to the tamper-evident
 * spine, and coordinates the learners so competing adaptations never run concurrently.
 *
 * SOTA basis (2026-08-05):
 *  - MAPE-K (IBM autonomic computing; Adaptive Data Flywheel arXiv 2510.27051): the OutcomeSignal is the
 *    Monitor phase; the shared Knowledge (spine + memory + anchor) is what wires the loops together.
 *  - Sequenced multi-loop coordination (EUREMA): competing concerns (heal vs improve) must not run
 *    concurrently — a mutex over the shared K, one adaptation at a time, is the safest coordination.
 *  - Precedence heal > protect > improve (AdaptiFlow three criticality levels): a pending heal preempts an
 *    improvement; an improvement never interrupts a heal.
 *  - Shadow/observe-before-adapt → here reframed as an ANCHOR-READINESS gate: self-improvement stays DORMANT
 *    until a domain-specific anchor has accumulated enough real outcomes (an agent scores 10-20 pts lower on
 *    the operator's own processes than on generic data — service-desk shadow 2026). Before readiness, Keep
 *    just runs + logs. This is instant value (PRs) with no wait, not a shadow delay.
 *  - Human merge/reject as an implicit, zero-effort, RICHER-than-RLHF reuse signal ("Learning from
 *    Disagreement" arXiv 2604.28010) — a first-class field on the signal, combined with execution outcomes,
 *    never optimized as a standalone acceptance-rate target (Goodhart guard).
 *
 * Zero runtime deps. Everything behind ports. N=1 first-class (session-count cadence, no daemon assumed).
 */

import type { Spine } from "../spine/spine.js";

/** The precedence classes for sequenced coordination (higher wins when two learners contend). */
export type AdaptationClass = "heal" | "protect" | "improve";
const PRECEDENCE: Record<AdaptationClass, number> = { heal: 3, protect: 2, improve: 1 };

/** The human's verdict on the generated PR — the zero-effort reuse signal. */
export type MergeVerdict = "merged" | "rejected" | "pending";

/**
 * The structured signal emitted after EVERY solve. Provider-agnostic, execution-grounded. This is the
 * single Monitor input every learner reads. Fields map to Keep's real pipeline outputs.
 */
export interface OutcomeSignal {
  readonly solveId: string;
  /** Optional personal/tenant isolation key. Omitted retains the n=1 contract. */
  readonly scopeId?: string;
  /** Ephemeral unforgeable runtime binding. It is consumed by scoped learners and never persisted. */
  readonly scopeToken?: object;
  /** The originating issue/ticket shape (for curriculum + skill relevance). */
  readonly taskShape: string;
  /** Did the generated PR's tests pass? The un-gameable execution signal. */
  readonly testsPassed: boolean;
  /** The plan/patch vetting verdict, if any (e.g. "pass" | "escalate"). */
  readonly vetVerdict?: string;
  /** The isolation tier the work ran under (gates autonomy). */
  readonly isolationTier?: string;
  /** The human's merge/reject verdict — the richer-than-RLHF reuse signal (zero extra effort). */
  readonly mergeVerdict: MergeVerdict;
  /** If rejected, the reason if the human gave one — becomes a counterexample seed. */
  readonly rejectReason?: string;
  /** Which skills/prompts/lessons were active on this solve (for reuse-reward credit assignment). */
  readonly activeArtifacts?: readonly string[];
  /** Cost/latency for budget-aware learners. */
  readonly costUnits?: number;
  readonly timestamp: number;
}

/** A registered learner reacts to signals. It declares its class (for precedence) and a stable id. */
export interface Learner {
  readonly id: string;
  readonly loopClass: AdaptationClass;
  /** Narrow capability: only the tenant-bound scheduler needs the ephemeral authority token. */
  readonly acceptsScopeBinding?: boolean;
  /** React to one signal. MUST be side-effect-isolated: a throw here cannot break the bus (caught). */
  onOutcome(signal: OutcomeSignal): void | Promise<void>;
}

/** Gates whether self-improvement is active yet (observing → learning). */
export interface AnchorReadiness {
  /** How many real outcomes have accumulated. */
  count: number;
  /** The threshold (default 30) after which learning activates. */
  readonly threshold: number;
  /** True once count >= threshold. */
  readonly ready: boolean;
}

export interface BusConfig {
  readonly spine?: Spine;
  /** Outcomes needed before self-improvement activates (observing phase). Default 30 (SOTA 30-50 bootstrap). */
  readonly anchorThreshold?: number;
  /** Called if a learner throws, so one bad learner can't break the loop. */
  readonly onLearnerError?: (learnerId: string, err: unknown) => void;
  /** Spine-independent last-resort diagnostics: reporting must never throw into the solve path. */
  readonly errorSink?: LearningErrorSink;
  /**
   * C4 safe-mode gate: consulted BEFORE dispatching each "improve"-class learner. Returning false pauses
   * self-improvement (e.g. the DriftMonitor is in drift safe-mode) while heal/protect learners still run.
   * Evaluated per-signal AFTER heal/protect learners have observed it, so a monitor can latch drift first.
   */
  readonly improveGate?: () => boolean;
}

export interface LearningFailure {
  readonly phase: "learner" | "outcome-publish";
  readonly componentId: string;
  readonly error: string;
  readonly timestamp: number;
}
export interface LearningErrorSink { report(failure: LearningFailure): void; snapshot?(): readonly LearningFailure[]; }
export class CollectingLearningErrorSink implements LearningErrorSink {
  readonly failures: LearningFailure[] = [];
  report(failure: LearningFailure): void { this.failures.push(Object.freeze({ ...failure })); }
  snapshot(): readonly LearningFailure[] { return this.failures.map((failure) => Object.freeze({ ...failure })); }
}

/**
 * The bus: register learners, publish signals. Sequences learners (one at a time, precedence-ordered), records
 * every signal to the spine, and enforces the observing→learning gate. A mutex ensures no two adaptations run
 * concurrently (EUREMA sequencing) — even though learners are invoked in-process, the gate + ordering make the
 * coordination explicit and testable, and ready for async learners.
 */
export class SelfImprovementBus {
  private readonly learners: Learner[] = [];
  private readonly spine: Spine | undefined;
  private readonly threshold: number;
  private readonly onLearnerError: ((id: string, err: unknown) => void) | undefined;
  private readonly improveGate: (() => boolean) | undefined;
  private readonly errorSink: LearningErrorSink | undefined;
  private outcomeCount = 0;
  private busy = false; // the sequencing mutex over the shared K
  private readonly queue: OutcomeSignal[] = [];

  constructor(config: BusConfig = {}) {
    this.spine = config.spine;
    this.threshold = config.anchorThreshold ?? 30;
    this.onLearnerError = config.onLearnerError;
    this.improveGate = config.improveGate;
    this.errorSink = config.errorSink;
  }

  /** Register a learner. Idempotent by id. Learners fire in precedence order (heal → protect → improve). */
  register(learner: Learner): void {
    if (this.learners.some((l) => l.id === learner.id)) return;
    this.learners.push(learner);
    this.learners.sort((a, b) => PRECEDENCE[b.loopClass] - PRECEDENCE[a.loopClass]);
  }

  /** Current observing→learning readiness. */
  readiness(): AnchorReadiness {
    return { count: this.outcomeCount, threshold: this.threshold, ready: this.outcomeCount >= this.threshold };
  }

  /**
   * Publish one solve outcome. ALWAYS records to the spine (observing) + increments the count. Fans to
   * learners ONLY once anchor-ready (learning). Sequenced: if a publish is already in flight, the signal is
   * queued and drained in order (no concurrent adaptations). Returns whether learners were dispatched.
   */
  async publish(signal: OutcomeSignal): Promise<{ recorded: boolean; dispatched: boolean; readiness: AnchorReadiness }> {
    // Monitor: record to the shared Knowledge (spine) ALWAYS — even in the observing phase.
    this.recordToSpine(signal);
    this.outcomeCount++;
    const readiness = this.readiness();

    // MONITORS (heal/protect) must observe EVERY signal, including the observing phase — a drift baseline has
    // to be built from the same early traffic the anchor sees, and monitoring must be live before adaptation
    // (NIST AI RMF / EU AI Act "test while in operation"). Only IMPROVE-class learning waits for readiness.
    // Sequenced dispatch (mutex over shared K): a publish in flight queues the next signal.
    if (this.busy) {
      this.queue.push(signal);
      return { recorded: true, dispatched: false, readiness };
    }
    this.busy = true;
    try {
      await this.dispatch(signal, readiness.ready);
      // Bounded drain: a learner that re-publishes on every dispatch could otherwise loop the queue forever
      // (runaway). This cap can't trip in normal operation (no learner re-publishes today); it's a hard safety
      // net that stops + records rather than spinning. SOTA: bounded iteration is mandatory for any self-loop.
      let drained = 0;
      const maxDrain = 100_000;
      while (this.queue.length > 0) {
        if (++drained > maxDrain) {
          this.spine?.stage({ type: "identity.action", actor: "self-improvement-bus", payload: { event: "self_improvement.drain_guard_tripped", drained, queued: this.queue.length, note: "runaway drain guard — dispatch loop bounded" } });
          this.queue.length = 0;
          break;
        }
        const next = this.queue.shift();
        if (next) await this.dispatch(next, this.readiness().ready);
      }
    } finally {
      this.busy = false;
    }
    // "dispatched" reports whether IMPROVE-class learning ran (the observing→learning distinction the API
    // consumers care about); monitors always ran.
    return { recorded: true, dispatched: readiness.ready, readiness };
  }

  /**
   * Fan a signal to learners in precedence order (heal → protect → improve). Monitors (heal/protect) run
   * ALWAYS; improve-class learners run only when `learningActive` (anchor-ready) AND the safe-mode gate is
   * open. A throw in one learner cannot break the others or the bus.
   */
  private async dispatch(signal: OutcomeSignal, learningActive: boolean): Promise<void> {
    for (const learner of this.learners) {
      if (learner.loopClass === "improve") {
        // Gate improvement on BOTH observing→learning readiness AND C4 drift safe-mode. Because learners fire
        // in precedence order, any "protect" monitor has already observed THIS signal and may have latched
        // drift, so the gate reflects the current signal before any improvement runs.
        if (!learningActive) continue;
        if (this.improveGate && !this.improveGate()) continue;
      }
      try {
        const delivered = learner.acceptsScopeBinding === true ? signal : withoutScopeToken(signal);
        await learner.onOutcome(delivered);
      } catch (err) {
        this.onLearnerError?.(learner.id, err);
        try { this.errorSink?.report({ phase: "learner", componentId: learner.id, error: errorText(err), timestamp: Date.now() }); } catch { /* diagnostics cannot break isolation */ }
        // Isolated: continue to the next learner. One bad learner never breaks the loop.
      }
    }
  }

  private recordToSpine(signal: OutcomeSignal): void {
    const { scopeToken: _ephemeralScopeToken, ...durableSignal } = signal;
    this.spine?.stage({
      type: "identity.action",
      actor: "keep-self-improvement-bus",
      payload: { event: "outcome_signal", ...durableSignal },
    });
  }

  /** For diagnostics/tests. */
  get learnerIds(): readonly string[] {
    return this.learners.map((l) => l.id);
  }
}

function errorText(error: unknown): string {
  if (error instanceof Error) return `${error.name}: ${error.message}`.slice(0, 4096);
  try { return String(error).slice(0, 4096); } catch { return "unprintable learner failure"; }
}
function withoutScopeToken(signal: OutcomeSignal): OutcomeSignal {
  if (signal.scopeToken === undefined) return signal;
  const { scopeToken: _scopeToken, ...safe } = signal;
  return safe;
}

/**
 * Derive the reuse-reward contribution of a signal (execution + human, combined). Merge is POSITIVE evidence,
 * reject is NEGATIVE, but ONLY in combination with the execution outcome — never acceptance-rate alone
 * (Goodhart guard). A reject-with-reason yields a counterexample seed.
 */
export function reuseSignal(signal: OutcomeSignal): { reward: number; counterexample?: string } {
  // Execution is the primary, un-gameable component.
  let reward = signal.testsPassed ? 1 : -1;
  // Human verdict corroborates (does not dominate): merged reinforces, rejected penalizes.
  if (signal.mergeVerdict === "merged") reward += 1;
  else if (signal.mergeVerdict === "rejected") reward -= 1;
  const counterexample = signal.mergeVerdict === "rejected" && signal.rejectReason ? signal.rejectReason : undefined;
  return counterexample !== undefined ? { reward, counterexample } : { reward };
}
