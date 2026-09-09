/**
 * Scheduler + Envelope: saga sequencer + non-persistable regions + OTel gen_ai emission (7d).
 *
 * These are the four orchestration table-stakes gaps the 2026 SOTA gap-analysis flagged, slotted to
 * land with the Scheduler:
 *  1. multi-step SAGA sequencer — Keep had single-action compensation (rollback); this chains
 *     forward+compensating actions and unwinds completed steps on partial failure.
 *  2. non-persistable regions — don't checkpoint mid-side-effect (never resume into a half-applied
 *     external mutation).
 *  3. OTel gen_ai.* span emission — interop over the existing tracing.ts + cost_model's gen_ai attrs.
 *  4. (dead-letter queue lives in scheduler.ts alongside the run loop.)
 *
 * Reuses ReversibleAction (rollback.ts), TraceRecorder/CostModel (observability). Zero deps.
 */

import type { Spine } from "../spine/spine.js";
import type { ReversibleAction } from "../control/rollback.js";
import type { CostModel, TokenUsage } from "../observability/cost_model.js";

// ── 1. Saga sequencer ────────────────────────────────────────────────────────

/** A saga step: a forward action that produces an artifact + its compensating inverse. */
export interface SagaStep {
  readonly name: string;
  /** Run the forward action; returns the reversible record (with its concrete undo). */
  readonly forward: () => Promise<ReversibleAction>;
}

export interface SagaOutcome {
  readonly committed: boolean;
  /** Names of steps that completed forward. */
  readonly completed: readonly string[];
  /** If it failed: the step that failed + whether compensation fully unwound. */
  readonly failedAt?: string;
  readonly compensated?: readonly string[];
  readonly compensationErrors?: readonly string[];
}

/**
 * Runs a chain of steps as a saga: forward through all steps; on any failure, unwind the completed
 * steps in LIFO by running their compensating inverses. Extends single-action rollback to multi-step.
 * The whole sequence + any unwind is recorded to the spine (auditable).
 */
export class SagaSequencer {
  constructor(private readonly spine: Spine) {}

  async run(sagaId: string, steps: readonly SagaStep[]): Promise<SagaOutcome> {
    const done: Array<{ name: string; action: ReversibleAction }> = [];
    this.spine.stage({ type: "identity.action", actor: "saga", payload: { event: "saga_begin", sagaId, steps: steps.length } });

    for (const step of steps) {
      try {
        const action = await step.forward();
        done.push({ name: step.name, action });
        this.spine.stage({ type: "identity.action", actor: "saga", payload: { event: "saga_step_ok", sagaId, step: step.name, artifact: action.artifact } });
      } catch (err) {
        // Partial failure → unwind completed steps LIFO.
        this.spine.stage({ type: "identity.action", actor: "saga", payload: { event: "saga_step_failed", sagaId, step: step.name, error: String(err) } });
        const compensated: string[] = [];
        const compensationErrors: string[] = [];
        for (let i = done.length - 1; i >= 0; i--) {
          const { name, action } = done[i]!;
          try {
            await action.undo();
            compensated.push(name);
            this.spine.stage({ type: "identity.action", actor: "saga", payload: { event: "saga_compensated", sagaId, step: name } });
          } catch (undoErr) {
            compensationErrors.push(`${name}: ${String(undoErr)}`);
            this.spine.stage({ type: "identity.action", actor: "saga", payload: { event: "saga_compensation_failed", sagaId, step: name, error: String(undoErr) } });
          }
        }
        return {
          committed: false,
          completed: done.map((d) => d.name),
          failedAt: step.name,
          compensated,
          ...(compensationErrors.length > 0 ? { compensationErrors } : {}),
        };
      }
    }

    this.spine.stage({ type: "identity.action", actor: "saga", payload: { event: "saga_commit", sagaId, steps: done.length } });
    return { committed: true, completed: done.map((d) => d.name) };
  }
}

// ── 2. Non-persistable regions ───────────────────────────────────────────────

/**
 * Marks a critical section that must NOT be checkpointed mid-execution — so a crash+resume never
 * re-enters a half-applied external side effect. While a region is open, checkpointing is refused;
 * on close the section is durable-again. A registry-of-open-regions is consulted by the checkpointer.
 */
export class NonPersistableRegistry {
  private readonly open = new Map<string, Map<string, number>>();
  constructor(private readonly spine: Spine) {}

  enter(regionId: string, scopeId = "global"): void {
    const scope = this.open.get(scopeId) ?? new Map<string, number>();
    scope.set(regionId, (scope.get(regionId) ?? 0) + 1);
    this.open.set(scopeId, scope);
    this.spine.stage({ type: "identity.action", actor: "scheduler", payload: { event: "nonpersistable_enter", regionId, scopeId } });
  }

  exit(regionId: string, scopeId = "global"): void {
    const scope = this.open.get(scopeId);
    const count = scope?.get(regionId) ?? 0;
    if (count <= 1) scope?.delete(regionId); else scope!.set(regionId, count - 1);
    if (scope?.size === 0) this.open.delete(scopeId);
    this.spine.stage({ type: "identity.action", actor: "scheduler", payload: { event: "nonpersistable_exit", regionId, scopeId } });
  }

  /** The checkpointer calls this — true means a checkpoint is safe right now. */
  canCheckpoint(scopeId?: string): boolean {
    return scopeId === undefined ? this.open.size === 0 : !this.open.has("global") && !this.open.has(scopeId);
  }

  get openRegions(): readonly string[] {
    return [...this.open.entries()].flatMap(([scopeId, regions]) => [...regions.keys()].map((regionId) => `${scopeId}:${regionId}`));
  }

  openRegionsFor(scopeId: string): readonly string[] {
    return [
      ...(this.open.get("global")?.keys() ?? []),
      ...(scopeId === "global" ? [] : (this.open.get(scopeId)?.keys() ?? [])),
    ];
  }

  /** Run a function inside a non-persistable region, guaranteeing exit even on throw. */
  async within<T>(regionId: string, fn: () => Promise<T>, scopeId = "global"): Promise<T> {
    this.enter(regionId, scopeId);
    try {
      return await fn();
    } finally {
      this.exit(regionId, scopeId);
    }
  }
}

// ── 3. OTel gen_ai.* span emission ───────────────────────────────────────────

/** A minimal OTel-shaped span (the subset needed for gen_ai interop). */
export interface OtelSpan {
  readonly name: string;
  readonly traceId: string;
  readonly spanId: string;
  readonly parentSpanId?: string;
  readonly startUnixNano: number;
  readonly endUnixNano: number;
  readonly attributes: Readonly<Record<string, string | number>>;
  readonly status: "OK" | "ERROR";
}

/**
 * Emits OTel gen_ai.* semantic-convention spans over the existing cost model's gen_ai attributes.
 * This is interop glue — it does not replace tracing.ts; it maps a model call to the OTel shape an
 * external collector expects. The emit sink is injected (default: record to spine).
 */
export class OtelGenAiEmitter {
  constructor(
    private readonly costModel: CostModel,
    private readonly spine: Spine,
    private readonly sink?: (span: OtelSpan) => void,
  ) {}

  emitModelCall(input: {
    name: string;
    traceId: string;
    spanId: string;
    parentSpanId?: string;
    system: string;
    model: string;
    usage: TokenUsage;
    startMs: number;
    endMs: number;
    ok?: boolean;
  }): OtelSpan {
    const attrs = this.costModel.toOtelAttributes(input.system, input.model, input.usage);
    const span: OtelSpan = {
      name: input.name,
      traceId: input.traceId,
      spanId: input.spanId,
      ...(input.parentSpanId !== undefined ? { parentSpanId: input.parentSpanId } : {}),
      startUnixNano: Math.round(input.startMs * 1e6),
      endUnixNano: Math.round(input.endMs * 1e6),
      attributes: { ...attrs, "gen_ai.operation.name": "generate" },
      status: input.ok === false ? "ERROR" : "OK",
    };
    this.spine.stage({ type: "generic", actor: "otel", payload: { event: "gen_ai_span", name: span.name, traceId: span.traceId, model: input.model } });
    this.sink?.(span);
    return span;
  }
}
