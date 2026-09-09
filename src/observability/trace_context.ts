/**
 * Trace-context propagation (zero-dep, Node built-in AsyncLocalStorage).
 *
 * A model call deep in a solve is context-free — it doesn't know which run/task/parent-span it belongs to. Threading a
 * context object through every function signature fragments traces (MLflow 2026: manual passing breaks deeply nested
 * async chains). The SOTA fix is an ambient context propagated across await boundaries. Node's AsyncLocalStorage does
 * exactly this with no external dependency, so the TracingModelProvider can associate each model-call span with the
 * current run + parent span, producing the parent-child hierarchy that lets cost/latency be attributed to pipeline steps.
 */

import { AsyncLocalStorage } from "node:async_hooks";

export interface TraceCtx {
  /** The run's trace id — all spans of one run share it (one trace per run). */
  readonly traceId: string;
  /** The task/run id, for per-task cost attribution. */
  readonly taskId: string;
  /** Exact shared-deployment owner. Omitted is the private n=1 namespace only. */
  readonly tenant?: string;
  /** The current parent span id (a child span nests under it), if any. */
  readonly parentSpanId?: string;
  /** The agent/node label to tag spans with, if known. */
  readonly agent?: string;
  /** Skill/lesson ids deemed relevant to this work — model-call spans carry these so spend attributes per lesson
   *  (the "cost of the work a lesson influenced" grain). Provenance is retrieval-relevance, not per-token injection. */
  readonly lessonIds?: readonly string[];
}

const storage = new AsyncLocalStorage<TraceCtx>();

/** Run `fn` with `ctx` as the ambient trace context (propagates across awaits inside fn). */
export function runWithinTrace<T>(ctx: TraceCtx, fn: () => T): T {
  return storage.run(ctx, fn);
}

/** Run `fn` with `lessonIds` attached to the current context (merged), for per-lesson cost attribution of its calls. */
export function withLessons<T>(lessonIds: readonly string[], fn: () => T): T {
  const cur = storage.getStore();
  const base: TraceCtx = cur ?? { traceId: "adhoc", taskId: "adhoc" };
  const merged = [...new Set([...(base.lessonIds ?? []), ...lessonIds])];
  return storage.run({ ...base, lessonIds: merged }, fn);
}

/** The current ambient trace context, or undefined if not inside a run. */
export function currentTrace(): TraceCtx | undefined {
  return storage.getStore();
}
