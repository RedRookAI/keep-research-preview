/**
 * ReferenceMonitor (Increment C1) — the SINGLE, un-bypassable trace-level enforcement point. Keep's safety
 * checks were scattered across modules (merge-gate, consequence-floor, isolation, meta-harness), each firing
 * at its own action boundary. Two problems that C1 fixes:
 *   1. ACTION-BOUNDARY CHECKS MISS ~50% OF VIOLATIONS (VIGIL arXiv 2606.26524): a per-action check sees one
 *      event in isolation and cannot catch TEMPORAL properties ("a gated merge with no prior approval",
 *      "an accepted self-improvement with no preceding triad"). C1 checks the TRACE — the ordered event
 *      history — so temporal invariants are enforceable.
 *   2. SCATTERED = un-auditable + island-prone. C1 is the ONE plug-in point every safety module registers its
 *      invariant into as a CONTRACT CLAUSE. One place enforces all of them; nothing can route around it.
 *
 * SOTA basis (2026-08-05): VeriGuard's TWO-STAGE design (verify offline once → cheap runtime check) — here,
 * invariants are registered once and each runtime step is a single DFA transition (O(1) per invariant per
 * event). Runtime monitoring of PAST-TIME LTL compiles to FINITE-STATE monitors with bounded memory (Havelund
 * & Roșu; Bauer et al. runtime verification) — implemented as zero-dep DFAs, NO SMT/solver dependency. This is
 * an ARCHITECTURAL gate (a state machine over the trace), never a prompt-level ask.
 *
 * Enforcement: `wouldViolate(candidate)` steps a COPY of every invariant's state with the candidate event and
 * reports any that would go to a violated state — so a caller can DENY the action before it commits.
 * `commit(event)` advances the real state. Zero runtime deps.
 */

/** The minimal event shape C1 needs (structurally compatible with the spine's StagedEvent). */
export interface TraceEvent {
  readonly type: string;
  readonly actor: string;
  readonly payload: Readonly<Record<string, unknown>>;
}

/** The verdict of a single invariant against the current trace state. */
export interface ClauseVerdict {
  readonly clauseId: string;
  readonly violated: boolean;
  readonly reason: string;
}

/**
 * A contract clause = a finite-state monitor over the trace. `S` is the clause's private DFA state. `step`
 * folds one event into the next state (pure). `verdict` reads the state → violated?/reason. Because `step`
 * is pure and `S` is cloneable (structured value), the monitor can speculatively step a candidate.
 */
export interface TraceClause<S = unknown> {
  readonly id: string;
  readonly description: string;
  readonly initial: S;
  step(state: S, event: TraceEvent): S;
  verdict(state: S): { violated: boolean; reason: string };
  /** Clone the state for speculative `wouldViolate` checks (default: structuredClone). */
  clone?(state: S): S;
}

interface Registered {
  readonly clause: TraceClause<unknown>;
  state: unknown;
}

export class ReferenceMonitor {
  private readonly clauses: Registered[] = [];
  private eventCount = 0;

  /** Register a safety module's invariant as a contract clause. Idempotent by id. Returns this (chainable). */
  register<S>(clause: TraceClause<S>): this {
    if (this.clauses.some((c) => c.clause.id === clause.id)) return this;
    this.clauses.push({ clause: clause as TraceClause<unknown>, state: clause.initial });
    return this;
  }

  /** The registered clause ids (for audit/diagnostics). */
  get clauseIds(): readonly string[] {
    return this.clauses.map((c) => c.clause.id);
  }

  get eventsObserved(): number {
    return this.eventCount;
  }

  /**
   * Would committing `candidate` violate any clause? Steps a CLONE of each clause's state (no mutation) and
   * collects the clauses that would enter a violated state. Empty array = safe to commit. This is the
   * enforcement primitive: a caller checks this BEFORE performing an irreversible action, and denies on any
   * violation.
   */
  wouldViolate(candidate: TraceEvent): ClauseVerdict[] {
    const violations: ClauseVerdict[] = [];
    for (const reg of this.clauses) {
      const cloned = this.cloneState(reg);
      const next = reg.clause.step(cloned, candidate);
      const v = reg.clause.verdict(next);
      if (v.violated) violations.push({ clauseId: reg.clause.id, violated: true, reason: v.reason });
    }
    return violations;
  }

  /** Advance the real trace state by one event. Returns any clauses now in a violated state (post-hoc audit). */
  commit(event: TraceEvent): ClauseVerdict[] {
    this.eventCount++;
    const violations: ClauseVerdict[] = [];
    for (const reg of this.clauses) {
      reg.state = reg.clause.step(reg.state, event);
      const v = reg.clause.verdict(reg.state);
      if (v.violated) violations.push({ clauseId: reg.clause.id, violated: true, reason: v.reason });
    }
    return violations;
  }

  /** Replay an entire trace from genesis, returning every violation encountered (offline audit). */
  audit(trace: readonly TraceEvent[]): ClauseVerdict[] {
    for (const reg of this.clauses) reg.state = reg.clause.initial;
    this.eventCount = 0;
    const all: ClauseVerdict[] = [];
    for (const e of trace) all.push(...this.commit(e));
    return all;
  }

  private cloneState(reg: Registered): unknown {
    if (reg.clause.clone) return reg.clause.clone(reg.state);
    return structuredClone(reg.state);
  }
}

// ─── Zero-dep past-time-LTL clause builders (each compiles a temporal property to a small DFA) ───

/** H ¬p — "historically never": violated the moment any event matches `forbidden`. (frozen-floor mutation) */
export function neverEvent(id: string, description: string, forbidden: (e: TraceEvent) => boolean): TraceClause<{ hit: string | null }> {
  return {
    id, description,
    initial: { hit: null },
    step: (s, e) => (s.hit ? s : (forbidden(e) ? { hit: describe(e) } : s)),
    verdict: (s) => ({ violated: s.hit !== null, reason: s.hit ? `forbidden event occurred: ${s.hit}` : "" }),
  };
}

/**
 * trigger → O(required correlated by key) — "every trigger must be PRECEDED by a matching required event".
 * The correlation `key` ties a trigger to its required predecessor (e.g. same target/tier). A trigger with no
 * prior required event of the same key is a violation. This is the temporal property a per-action check
 * CANNOT see. (gated merge requires prior approval; accepted self-improvement requires prior triad-pass)
 */
export function precededBy(
  id: string,
  description: string,
  isRequired: (e: TraceEvent) => boolean,
  isTrigger: (e: TraceEvent) => boolean,
  key: (e: TraceEvent) => string,
): TraceClause<{ seen: string[]; badKey: string | null }> {
  return {
    id, description,
    initial: { seen: [], badKey: null },
    step: (s, e) => {
      if (s.badKey) return s; // already violated — latch
      if (isRequired(e)) return { seen: [...s.seen, key(e)], badKey: null };
      if (isTrigger(e) && !s.seen.includes(key(e))) return { seen: s.seen, badKey: key(e) };
      return s;
    },
    verdict: (s) => ({ violated: s.badKey !== null, reason: s.badKey ? `trigger for "${s.badKey}" had no preceding required event` : "" }),
  };
}

/**
 * "forbidden UNLESS a guard held earlier" — an action of class `action` is forbidden while the guard has not
 * been established. (e.g. an external-effect action forbidden unless the isolation tier permits egress). A
 * one-shot guard-then-permit past-time property.
 */
export function forbidWithout(
  id: string,
  description: string,
  establishesGuard: (e: TraceEvent) => boolean,
  guardedAction: (e: TraceEvent) => boolean,
): TraceClause<{ guarded: boolean; violated: boolean }> {
  return {
    id, description,
    initial: { guarded: false, violated: false },
    step: (s, e) => {
      if (s.violated) return s;
      if (establishesGuard(e)) return { guarded: true, violated: false };
      if (guardedAction(e) && !s.guarded) return { guarded: s.guarded, violated: true };
      return s;
    },
    verdict: (s) => ({ violated: s.violated, reason: s.violated ? `${description}: guarded action taken without an established guard` : "" }),
  };
}

function describe(e: TraceEvent): string {
  const ev = (e.payload as { event?: string }).event;
  return ev ? `${e.type}/${ev}` : e.type;
}
