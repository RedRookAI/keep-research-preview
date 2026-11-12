/**
 * TracingModelProvider — model-gateway instrumentation, behind the ModelProvider port.
 *
 * Wraps any ModelProvider so every generate() records a span: name gen_ai:<model>, tagged with the ambient trace context
 * (so it nests as a CHILD of the current run/stage span), carrying a cost breakdown computed from token usage × provider
 * pricing, and status llm-error if the call throws (the error is re-thrown after the span is recorded). Missing prices
 * or usage remain explicitly unknown. Embeddings pass through without token-price telemetry. The application/gateway
 * starts the span and captures timing + tokens; the provider itself doesn't extend it.
 *
 * SOTA basis (2026-08-07): OTel GenAI conventions — each LLM call is a child span; cost = usage attributes × provider
 * pricing, stored per span and summed at the root; context propagated across awaits (AsyncLocalStorage), not threaded by
 * hand. A small custom span schema captures ~80% of the value without the full OTel SDK. What would change it: exporting
 * these spans over OTLP to an external collector is a deployment seam; the in-process TraceRecorder is the source of truth.
 */

import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "./gateway.js";
import type { BoundedEmbeddingOptions, BoundedEmbeddingResult } from "./http_provider.js";
import type { TraceRecorder, SpanCostStatus } from "../observability/tracing.js";
import type { CostBreakdown } from "../observability/cost_model.js";
import { currentTrace } from "../observability/trace_context.js";

/** Per-model pricing (USD per MILLION tokens). Absence leaves the call unpriced. */
export type PriceFor = (model: string) => { inputPerM: number; outputPerM: number } | undefined;

function breakdown(tokensIn: number, tokensOut: number, p: ReturnType<PriceFor>): CostBreakdown {
  const inputUsd = p ? (tokensIn / 1_000_000) * p.inputPerM : 0;
  const outputUsd = p ? (tokensOut / 1_000_000) * p.outputPerM : 0;
  return {
    inputUsd,
    cachedInputUsd: 0,
    outputUsd,
    tokenUsd: inputUsd + outputUsd,
    humanUsd: 0,
    infraUsd: 0,
    toolApiUsd: 0,
    totalUsd: inputUsd + outputUsd,
  };
}

export class TracingModelProvider implements ModelProvider {
  readonly name: string;
  readonly isLocal: boolean;

  /** Preserve explicit reservation/dispatch counts; no missing embedding price is
   * fabricated as a zero-cost span. Token-price telemetry remains separate work. */
  embedBounded(texts: readonly string[], options: BoundedEmbeddingOptions): Promise<BoundedEmbeddingResult> {
    if (!this.inner.embedBounded) throw new Error("bounded embedding is unavailable; no unmetered fallback");
    return this.inner.embedBounded(texts, options);
  }

  constructor(
    private readonly inner: ModelProvider,
    private readonly recorder: TraceRecorder,
    private readonly priceFor: PriceFor,
    private readonly clock: () => number = () => Date.now(),
  ) {
    this.name = inner.name;
    this.isLocal = inner.isLocal;
  }

  async generate(req: GenerateRequest): Promise<GenerateResult> {
    const ctx = currentTrace();
    const startTs = this.clock();
    try {
      const result = await this.inner.generate(req);
      const usageKnown = result.usageComplete !== false && [result.tokensIn, result.tokensOut].every(n => Number.isSafeInteger(n) && n >= 0);
      this.record(result.model, usageKnown ? { input: result.tokensIn, output: result.tokensOut } : undefined, startTs, "ok", ctx);
      return result;
    } catch (e) {
      // Record the failed call as an llm-error span (root-cause material for failure localization), then re-throw.
      this.record(this.inner.name, undefined, startTs, "llm-error", ctx);
      throw e;
    }
  }

  embed(texts: readonly string[]): Promise<Embedding[]> {
    return this.inner.embed(texts);
  }

  private record(
    model: string,
    tokens: { readonly input: number; readonly output: number } | undefined,
    startTs: number,
    status: "ok" | "llm-error",
    ctx: ReturnType<typeof currentTrace>,
  ): void {
    const candidate = this.priceFor(model);
    const price = candidate && [candidate.inputPerM, candidate.outputPerM].every(n => Number.isFinite(n) && n >= 0) ? candidate : undefined;
    const costStatus: SpanCostStatus = tokens === undefined ? "usage-unknown" : price === undefined ? "unpriced" : "known";
    this.recorder.record({
      name: `gen_ai:${model}`,
      taskId: ctx?.taskId ?? "adhoc",
      ...(ctx?.tenant ? { tenant: ctx.tenant } : {}),
      ...(ctx?.traceId ? { traceId: ctx.traceId } : {}),
      ...(ctx?.parentSpanId ? { parentId: ctx.parentSpanId } : {}),
      ...(ctx?.lessonIds && ctx.lessonIds.length ? { lessonIds: ctx.lessonIds } : {}),
      provider: this.inner.name,
      agent: ctx?.agent ?? model,
      // Zero is a compatibility placeholder for unknown cost, excluded from any claim of complete coverage.
      cost: breakdown(tokens?.input ?? 0, tokens?.output ?? 0, tokens === undefined ? undefined : price),
      costStatus,
      ...(tokens === undefined ? {} : { tokens }),
      startTs,
      endTs: this.clock(),
      status,
    });
  }
}
