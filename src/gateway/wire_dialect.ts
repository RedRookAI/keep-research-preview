/**
 * HTTP provider wire dialects (Increment 12a).
 *
 * SOTA basis (2026-08-05): the LLM API wire format has CONVERGED — all major providers use SSE for
 * streaming with delta events, standard HTTP status codes (429 rate-limit, 400 malformed, 500/503
 * server), and Retry-After headers (MyEngineeringPath/Requesty 2026). The two dominant dialects are
 * OpenAI-compatible (choices[].message.content, [DONE] sentinel, choices[].delta) and
 * Anthropic-compatible (content[].text, message_stop sentinel, content_block_delta). The lesson that
 * matters (MLflow 2026): "build the normalization layer early, not after the third provider breaks" —
 * so a WireDialect normalizes each provider's shape INTO Keep's ModelProvider port, and nothing
 * downstream ever sees provider quirks.
 *
 * Usage fields map onto the existing CostModel TokenUsage {freshInputTokens, cachedInputTokens,
 * outputTokens} — Anthropic reports cache_read_input_tokens (10x cheaper), which is the cached split.
 * Zero deps.
 */

import type { TokenUsage } from "../observability/cost_model.js";

export interface WireRequest {
  readonly method: "POST";
  readonly path: string;
  readonly body: Record<string, unknown>;
}

export interface WireParsed {
  readonly text: string;
  readonly model: string;
  readonly usage: TokenUsage;
  readonly usageComplete?: boolean;
  readonly providerRoute?: string;
}

/** Optional metadata keeps trusted custom dialects returning TokenUsage compatible.
 * Built-in dialects explicitly distinguish observed counters from missing evidence. */
export interface StreamUsage extends TokenUsage {
  readonly usageComplete?: boolean;
  readonly providerRoute?: string;
}

export interface ExternalRoutingPolicy {
  readonly zeroDataRetention: true;
  readonly dataCollection: "deny";
  readonly allowFallbacks: false;
  readonly providers: readonly string[];
}

export interface EmbedWireParsed {
  readonly vectors: readonly (readonly number[])[];
  readonly model: string;
  readonly usage: TokenUsage;
}

/**
 * A provider dialect: builds the HTTP request body/path for a generate/embed call and parses the
 * response back into Keep's normalized shapes. Also knows its streaming sentinel + how to pull a text
 * delta out of one SSE data line (so the transport layer stays dialect-agnostic).
 */
export interface WireDialect {
  readonly name: string;
  /** Auth header name (e.g. "authorization" | "x-api-key"). */
  readonly authHeader: string;
  /** Format the auth header value from a key (e.g. `Bearer ${k}` vs the bare key). */
  authValue(apiKey: string): string;
  /** Extra static headers (e.g. anthropic-version). */
  readonly extraHeaders?: Readonly<Record<string, string>>;

  buildGenerate(model: string, prompt: string, maxTokens: number, stream: boolean, options?: { readonly structuredOutput?: boolean }): WireRequest;
  parseGenerate(json: unknown): WireParsed;

  buildEmbed(model: string, texts: readonly string[]): WireRequest;
  parseEmbed(json: unknown): EmbedWireParsed;

  /** Hard terminal line. An object stop may also finish a stream; see streamStopIsFinal. */
  readonly streamDoneSentinel: string;
  /** Extract a text delta from one parsed SSE "data:" payload (or "" if this event carries none). */
  streamDelta(dataJson: unknown): string;
  /** Detect the terminal event object form (Anthropic message_stop) in addition to the raw sentinel. */
  isStreamStop(dataJson: unknown): boolean;
  /** Defaults to true. False allows usage-only events after an object stop until sentinel/EOF. */
  readonly streamStopIsFinal?: boolean;
  /** Pull final usage from a stream's terminal/aggregated events, if present. */
  streamUsage(events: readonly unknown[]): StreamUsage | undefined;
}

function num(x: unknown, d = 0): number {
  return typeof x === "number" && Number.isFinite(x) ? x : d;
}
function asObj(x: unknown): Record<string, unknown> {
  return x && typeof x === "object" ? (x as Record<string, unknown>) : {};
}
function tokenCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

// ── OpenAI-compatible dialect (also OpenRouter, vLLM, llama.cpp server, Mistral) ──

export const openAiDialect: WireDialect = {
  name: "openai-compatible",
  authHeader: "authorization",
  authValue: (k) => `Bearer ${k}`,
  buildGenerate(model, prompt, maxTokens, stream, options) {
    return {
      method: "POST",
      path: "/v1/chat/completions",
      body: { model, messages: [{ role: "user", content: prompt }], max_tokens: maxTokens, stream, ...(options?.structuredOutput === true ? { response_format: { type: "json_object" } } : {}) },
    };
  },
  parseGenerate(json) {
    const o = asObj(json);
    const choices = Array.isArray(o["choices"]) ? (o["choices"] as unknown[]) : [];
    const first = asObj(choices[0]);
    const msg = asObj(first["message"]);
    const usage = asObj(o["usage"]);
    const promptTokens = num(usage["prompt_tokens"]);
    const cached = num(asObj(usage["prompt_tokens_details"])["cached_tokens"]);
    return {
      text: typeof msg["content"] === "string" ? (msg["content"] as string) : "",
      model: typeof o["model"] === "string" ? (o["model"] as string) : "unknown",
      usage: { freshInputTokens: Math.max(0, promptTokens - cached), cachedInputTokens: cached, outputTokens: num(usage["completion_tokens"]) },
      usageComplete: [usage["prompt_tokens"], usage["completion_tokens"], asObj(usage["prompt_tokens_details"])["cached_tokens"] ?? 0].every(n => Number.isSafeInteger(n) && (n as number) >= 0) && cached <= promptTokens,
      ...(typeof o["provider"] === "string" ? { providerRoute: o["provider"] } : {}),
    };
  },
  buildEmbed(model, texts) {
    return { method: "POST", path: "/v1/embeddings", body: { model, input: texts } };
  },
  parseEmbed(json) {
    const o = asObj(json);
    const data = Array.isArray(o["data"]) ? (o["data"] as unknown[]) : [];
    // Providers may return indexed rows out of order. Never silently associate a
    // vector with the wrong source, or coerce malformed coordinates into zeros.
    const indexed = data.some(d => asObj(d)["index"] !== undefined);
    const ordered = indexed ? [...data].sort((a, b) => Number(asObj(a)["index"]) - Number(asObj(b)["index"])) : data;
    if (indexed && !ordered.every((d, i) => asObj(d)["index"] === i)) throw new Error("invalid embedding response indices");
    const vectors = ordered.map((d) => {
      const emb = asObj(d)["embedding"];
      if (!Array.isArray(emb) || !emb.every(n => typeof n === "number" && Number.isFinite(n))) throw new Error("invalid embedding coordinates");
      return [...emb] as number[];
    });
    const usage = asObj(o["usage"]);
    return {
      vectors,
      model: typeof o["model"] === "string" ? (o["model"] as string) : "unknown",
      usage: { freshInputTokens: num(usage["prompt_tokens"]), cachedInputTokens: 0, outputTokens: 0 },
    };
  },
  streamDoneSentinel: "[DONE]",
  streamStopIsFinal: false,
  streamDelta(dataJson) {
    const o = asObj(dataJson);
    const choices = Array.isArray(o["choices"]) ? (o["choices"] as unknown[]) : [];
    const delta = asObj(asObj(choices[0])["delta"]);
    return typeof delta["content"] === "string" ? (delta["content"] as string) : "";
  },
  isStreamStop(dataJson) {
    const o = asObj(dataJson);
    const choices = Array.isArray(o["choices"]) ? (o["choices"] as unknown[]) : [];
    return asObj(choices[0])["finish_reason"] != null;
  },
  streamUsage(events) {
    for (let i = events.length - 1; i >= 0; i--) {
      const event = asObj(events[i]);
      // Null is normal on text chunks. A malformed non-null final report must
      // not be replaced by older counters that happened to look complete.
      if (event["usage"] != null) {
        const u = asObj(event["usage"]);
        const promptTokens = num(u["prompt_tokens"]);
        const rawCached = asObj(u["prompt_tokens_details"])["cached_tokens"] ?? 0;
        const cached = num(rawCached);
        return { freshInputTokens: Math.max(0, promptTokens - cached), cachedInputTokens: cached, outputTokens: num(u["completion_tokens"]),
          usageComplete: tokenCount(u["prompt_tokens"]) && tokenCount(u["completion_tokens"]) && tokenCount(rawCached) && cached <= promptTokens,
          ...(typeof event["provider"] === "string" ? { providerRoute: event["provider"] } : {}) };
      }
    }
    return undefined;
  },
};

/** Bind explicit aggregator privacy/routing preferences without a provider SDK. */
export function openAiDialectWithRouting(policy: ExternalRoutingPolicy): WireDialect {
  const providers = [...policy.providers];
  if (providers.length === 0 || providers.length > 32 || providers.some((value) => !/^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$/u.test(value))) throw new Error("external routing providers are malformed");
  const provider = Object.freeze({ zdr: true, data_collection: "deny", allow_fallbacks: false, only: Object.freeze(providers) });
  return Object.freeze({
    ...openAiDialect,
    buildGenerate(model: string, prompt: string, maxTokens: number, stream: boolean, options?: { readonly structuredOutput?: boolean }) {
      const request = openAiDialect.buildGenerate(model, prompt, maxTokens, stream, options);
      return { ...request, body: { ...request.body, provider } };
    },
    buildEmbed(model: string, texts: readonly string[]) {
      const request = openAiDialect.buildEmbed(model, texts);
      return { ...request, body: { ...request.body, provider } };
    },
  });
}

// ── Anthropic-compatible dialect ──

export const anthropicDialect: WireDialect = {
  name: "anthropic-compatible",
  authHeader: "x-api-key",
  authValue: (k) => k,
  extraHeaders: { "anthropic-version": "2023-06-01" },
  buildGenerate(model, prompt, maxTokens, stream) {
    return {
      method: "POST",
      path: "/v1/messages",
      body: { model, messages: [{ role: "user", content: prompt }], max_tokens: maxTokens, stream },
    };
  },
  parseGenerate(json) {
    const o = asObj(json);
    const content = Array.isArray(o["content"]) ? (o["content"] as unknown[]) : [];
    const text = content.map((c) => (typeof asObj(c)["text"] === "string" ? (asObj(c)["text"] as string) : "")).join("");
    const usage = asObj(o["usage"]);
    const cached = num(usage["cache_read_input_tokens"]);
    return {
      text,
      model: typeof o["model"] === "string" ? (o["model"] as string) : "unknown",
      usage: { freshInputTokens: num(usage["input_tokens"]), cachedInputTokens: cached, outputTokens: num(usage["output_tokens"]) },
      usageComplete: [usage["input_tokens"], usage["output_tokens"], usage["cache_read_input_tokens"] ?? 0].every(n => Number.isSafeInteger(n) && (n as number) >= 0),
    };
  },
  buildEmbed() {
    // Anthropic has no first-party embeddings endpoint; callers should use an embeddings-capable
    // dialect. Throwing here is correct: it fails closed rather than silently returning garbage.
    throw new Error("anthropic-compatible dialect does not provide embeddings; use an embeddings provider");
  },
  parseEmbed() {
    throw new Error("anthropic-compatible dialect does not provide embeddings");
  },
  streamDoneSentinel: "[DONE]",
  streamDelta(dataJson) {
    const o = asObj(dataJson);
    if (o["type"] === "content_block_delta") {
      const delta = asObj(o["delta"]);
      return typeof delta["text"] === "string" ? (delta["text"] as string) : "";
    }
    return "";
  },
  isStreamStop(dataJson) {
    return asObj(dataJson)["type"] === "message_stop";
  },
  streamUsage(events) {
    let inTok = 0, outTok = 0, cached = 0, sawInput = false, sawOutputDelta = false, valid = true;
    for (const e of events) {
      const o = asObj(e);
      if (o["type"] === "message_start") {
        const u = asObj(asObj(o["message"])["usage"]);
        const rawCached = u["cache_read_input_tokens"] ?? 0;
        valid &&= !sawInput && tokenCount(u["input_tokens"]) && tokenCount(rawCached);
        inTok = num(u["input_tokens"]); cached = num(rawCached); sawInput = true;
        // The start snapshot's output count is preliminary, not final usage.
        if (u["output_tokens"] !== undefined) {
          valid &&= tokenCount(u["output_tokens"]);
          outTok = num(u["output_tokens"]);
        }
      } else if (o["type"] === "message_delta") {
        const u = asObj(o["usage"]);
        valid &&= sawInput && tokenCount(u["output_tokens"]) && num(u["output_tokens"]) >= outTok;
        outTok = num(u["output_tokens"]); sawOutputDelta = true;
      }
    }
    return sawInput || sawOutputDelta ? { freshInputTokens: inTok, cachedInputTokens: cached, outputTokens: outTok,
      usageComplete: valid && sawInput && sawOutputDelta && tokenCount(inTok + cached) } : undefined;
  },
};

/** Built-in dialects by name. */
export const WIRE_DIALECTS: Readonly<Record<string, WireDialect>> = {
  "openai-compatible": openAiDialect,
  "anthropic-compatible": anthropicDialect,
};
