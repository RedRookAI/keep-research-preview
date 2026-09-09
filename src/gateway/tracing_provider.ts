/**
 * TracingModelProvider — model-gateway instrumentation, behind the ModelProvider port.
 *
 * Wraps any ModelProvider so every generate() records a span: name gen_ai:<model>, tagged with the ambient trace context
 * (so it nests as a CHILD of the current run/stage span), carrying a cost breakdown computed from token usage × provider
 * pricing, and status llm-error if the call throws (the error is re-thrown after the span is recorded). Embeddings pass
 * through untraced (cost-negligible for now). This is the gateway span the SOTA guides describe: the application/gateway
 * starts the span and captures timing + tokens; the provider itself doesn't extend it.
 *
 * SOTA basis (2026-08-07): OTel GenAI conventions — each LLM call is a child span; cost = usage attributes × provider
 * pricing, stored per span and summed at the root; context propagated across awaits (AsyncLocalStorage), not threaded by
 * hand. A small custom span schema captures ~80% of the value without the full OTel SDK. What would change it: exporting
 * these spans over OTLP to an external collector is a deployment seam; the in-process TraceRecorder is the source of truth.
 */

import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "./gateway.js";
import type { BoundedEmbeddingOptions, BoundedEmbeddingResult } from "./http_provider.js";
import type { TraceRecorder } from "../observability/tracing.js";
import type { CostBreakdown } from "../observability/cost_model.js";
import { currentTrace } from "../observability/trace_context.js";

/** Per-model pricing (USD per MILLION tokens). Absent for a model → cost is recorded as zero (honest, never fabricated). */
export type PriceFor = (model: string) => { inputPerM: number; outputPerM: number } | undefined;

function breakdown(model: string, tokensIn: number, tokensOut: number, priceFor: PriceFor): CostBreakdown {
  const p = priceFor(model);
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
      this.record(result.model, result.tokensIn, result.tokensOut, startTs, "ok", ctx);
      return result;
    } catch (e) {
      // Record the failed call as an llm-error span (root-cause material for failure localization), then re-throw.
      this.record(this.inner.name, 0, 0, startTs, "llm-error", ctx);
      throw e;
    }
  }

  embed(texts: readonly string[]): Promise<Embedding[]> {
    return this.inner.embed(texts);
  }

  private record(
    model: string,
    tokensIn: number,
    tokensOut: number,
    startTs: number,
    status: "ok" | "llm-error",
    ctx: ReturnType<typeof currentTrace>,
  ): void {
    this.recorder.record({
      name: `gen_ai:${model}`,
      taskId: ctx?.taskId ?? "adhoc",
      ...(ctx?.tenant ? { tenant: ctx.tenant } : {}),
      ...(ctx?.traceId ? { traceId: ctx.traceId } : {}),
      ...(ctx?.parentSpanId ? { parentId: ctx.parentSpanId } : {}),
      ...(ctx?.lessonIds && ctx.lessonIds.length ? { lessonIds: ctx.lessonIds } : {}),
      provider: this.inner.name,
      agent: ctx?.agent ?? model,
      cost: breakdown(model, tokensIn, tokensOut, this.priceFor),
      tokens: { input: tokensIn, output: tokensOut },
      startTs,
      endTs: this.clock(),
      status,
    });
  }
}
