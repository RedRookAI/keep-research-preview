/**
 * HttpProvider (Increment 12a) — a real ModelProvider over HTTP via a WireDialect.
 *
 * SOTA basis (2026-08-05): retry semantics are load-bearing (Requesty 2026) — failed requests still
 * count toward the rate limit, so blindly retrying fast makes it WORSE; always honor Retry-After, else
 * exponential backoff, cap attempts, and NEVER retry a 400 (malformed = permanent). Standard status
 * codes: 429 rate-limit, 400 bad request, 500/503 server (MyEngineeringPath 2026). Timeout via
 * AbortController. Usage parses into the existing CostModel TokenUsage shape. Streaming is added in 12b
 * (this is the non-streaming core). Zero deps — fetch/AbortController are Node built-ins here.
 */

import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "./gateway.js";
import type { TokenUsage } from "../observability/cost_model.js";
import type { WireDialect } from "./wire_dialect.js";
import { SseDecoder } from "./sse.js";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import type { CapabilityAdapter } from "../ecosystem/capability_port.js";
import type { EmbeddingWork, EmbeddingWorkControl } from "../solve/recovery_budget.js";

export interface BoundedEmbeddingOptions {
  /** Processing-policy role, not a declaration of a model's query/document encoding. */
  readonly role?: "query" | "document";
  /** Trusted wrapper hook, checked after backoff immediately before each HTTP dispatch. */
  readonly assertAuthority?: () => void;
  /** Trusted host supplies its existing durable recovery reservation. Not egress admission. */
  readonly reserve: (work: EmbeddingWork) => Promise<EmbeddingWorkControl>;
  readonly maxBatchWindows?: number;
  readonly maxBatchBytes?: number;
  readonly maxResponseBytes?: number;
  readonly signal?: AbortSignal;
}
export interface BoundedEmbeddingResult {
  readonly vectors: readonly Embedding[];
  /** Worst-case reserved exposure, including retries; unused slots are not refunded. */
  readonly reserved: EmbeddingWork;
  /** Actual HTTP dispatches, not estimated money or complete provider usage. */
  readonly dispatched: EmbeddingWork;
}

export interface RetryPolicy {
  /** Max attempts total (including the first). Default 4. */
  readonly maxAttempts?: number;
  /** Base backoff ms for exponential backoff when no Retry-After is given. Default 500. */
  readonly baseBackoffMs?: number;
  /** Cap on any single backoff wait, ms. Default 20_000. */
  readonly maxBackoffMs?: number;
}

export interface HttpProviderOptions {
  readonly baseUrl: string;
  readonly apiKey: string;
  readonly model: string;
  readonly dialect: WireDialect;
  /** True if this endpoint is local (llama.cpp/vLLM on-box) — air-gap / sovereignty safe. */
  readonly isLocal?: boolean;
  readonly defaultMaxTokens?: number;
  readonly requestTimeoutMs?: number;
  readonly retry?: RetryPolicy;
  /** Injectable sleep (tests pass a no-op to avoid real waits). */
  readonly sleep?: (ms: number) => Promise<void>;
  /** Injectable fetch (tests point at a local server; defaults to global fetch). */
  readonly fetchImpl?: typeof fetch;
}

/** Error thrown when the provider gives up after exhausting retries or hits a permanent error. */
export class ProviderError extends Error {
  constructor(message: string, readonly status: number, readonly permanent: boolean) {
    super(message);
    this.name = "ProviderError";
  }
}

export interface PrivateOtlpCapabilityConfig {
  readonly id: string;
  readonly tenant?: string;
  readonly collectorUrl: string;
  readonly authorization?: string;
  readonly timeoutMs?: number;
  readonly maxBodyBytes?: number;
  readonly fetchImpl?: typeof fetch;
}

export interface PrivateOtlpCapability {
  readonly adapter: CapabilityAdapter;
  readonly authorityToken: string;
  readonly destinationDigest: string;
}

function privateLiteralEndpoint(value: string): URL {
  const endpoint = new URL(value);
  const host = endpoint.hostname.replace(/^\[|\]$/gu, "").toLowerCase(), family = isIP(host);
  const privateV4 = family === 4 && (() => { const [a = -1, b = -1] = host.split(".").map(Number); return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168); })();
  const privateV6 = family === 6 && (host === "::1" || /^(?:fc|fd)/u.test(host));
  if ((endpoint.protocol !== "http:" && endpoint.protocol !== "https:") || endpoint.username !== "" || endpoint.password !== ""
    || endpoint.hash !== "" || endpoint.search !== "" || (!privateV4 && !privateV6)) throw new Error("OTLP collector must be an exact private literal HTTP(S) endpoint without credentials, query, or fragment");
  return endpoint;
}

/** Raw OTLP HTTP transport remains in the existing net owner and is reachable only behind CapabilityHub. */
export function buildPrivateOtlpCapability(config: PrivateOtlpCapabilityConfig): PrivateOtlpCapability {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(config.id) || (config.tenant !== undefined && !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(config.tenant))) throw new Error("invalid OTLP capability identity");
  const endpoint = privateLiteralEndpoint(config.collectorUrl), timeoutMs = config.timeoutMs ?? 2_000, maxBodyBytes = config.maxBodyBytes ?? 1_048_576;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000 || !Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1_024 || maxBodyBytes > 8_388_608) throw new Error("invalid OTLP transport bound");
  if (config.authorization !== undefined && (config.authorization.length === 0 || Buffer.byteLength(config.authorization, "utf8") > 8_192 || /[\r\n]/u.test(config.authorization))) throw new Error("invalid OTLP authorization header");
  const fetchImpl = config.fetchImpl ?? fetch, authorityToken = randomBytes(32).toString("hex");
  const destinationDigest = createHash("sha256").update("keep.private-otlp-destination/v1\0").update(endpoint.href).digest("hex");
  const adapter: CapabilityAdapter = {
    descriptor: {
      id: config.id, kind: "connector", name: "private OTLP collector", credentialId: destinationDigest, trust: "verified",
      ...(config.tenant === undefined ? {} : { tenant: config.tenant }),
      fleet: { admissionUnits: 1, resourceDomain: "telemetry", targetArgument: "destinationDigest" },
    },
    async invoke(invocation) {
      const supplied = invocation.args["authorityToken"];
      const expectedBytes = Buffer.from(authorityToken), suppliedBytes = Buffer.from(typeof supplied === "string" ? supplied : "");
      if (invocation.operation !== "telemetry.export" || suppliedBytes.length !== expectedBytes.length || !timingSafeEqual(suppliedBytes, expectedBytes)) return { ok: false, error: "telemetry export authority mismatch" };
      if (invocation.args["destinationDigest"] !== destinationDigest || typeof invocation.args["exportId"] !== "string" || typeof invocation.args["purpose"] !== "string") return { ok: false, error: "telemetry export destination identity mismatch" };
      const payload = invocation.args["payload"], body = JSON.stringify(payload);
      if (payload === null || typeof payload !== "object" || Array.isArray(payload) || Buffer.byteLength(body, "utf8") > maxBodyBytes) return { ok: false, error: "telemetry export payload exceeds its admitted bound" };
      const controller = new AbortController(), signal = invocation.signal === undefined ? controller.signal : AbortSignal.any([controller.signal, invocation.signal]);
      const timer = setTimeout(() => controller.abort(new Error("OTLP collector timed out")), timeoutMs);
      try {
        const response = await fetchImpl(endpoint, { method: "POST", redirect: "error", signal, headers: {
          "content-type": "application/json", "x-keep-export-id": invocation.args["exportId"],
          ...(config.authorization === undefined ? {} : { authorization: config.authorization }),
        }, body });
        if (!response.ok) return { ok: false, error: `OTLP collector returned HTTP ${response.status}`, output: { definitiveFailure: true, status: response.status } };
        return { ok: true, output: { accepted: true, status: response.status, destinationDigest } };
      } catch { return { ok: false, error: "OTLP transport outcome is indeterminate", output: { indeterminate: true } }; }
      finally { clearTimeout(timer); }
    },
  };
  return Object.freeze({ adapter, authorityToken, destinationDigest });
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export class HttpProvider implements ModelProvider {
  readonly name: string;
  readonly isLocal: boolean;
  readonly lastUsage: { value?: TokenUsage } = {};

  private readonly maxAttempts: number;
  private readonly baseBackoffMs: number;
  private readonly maxBackoffMs: number;
  private readonly timeoutMs: number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly opts: HttpProviderOptions) {
    this.name = `http:${opts.dialect.name}:${opts.model}`;
    this.isLocal = opts.isLocal ?? false;
    this.maxAttempts = opts.retry?.maxAttempts ?? 4;
    this.baseBackoffMs = opts.retry?.baseBackoffMs ?? 500;
    this.maxBackoffMs = opts.retry?.maxBackoffMs ?? 20_000;
    this.timeoutMs = opts.requestTimeoutMs ?? 60_000;
    this.sleep = opts.sleep ?? defaultSleep;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  async generate(req: GenerateRequest): Promise<GenerateResult> {
    const maxTokens = req.maxTokens ?? this.opts.defaultMaxTokens ?? 1024;
    const wire = this.opts.dialect.buildGenerate(this.opts.model, req.prompt, maxTokens, false, { structuredOutput: req.hints?.["structuredOutput"] === true });
    const json = await this.send(wire, req.signal);
    const parsed = this.opts.dialect.parseGenerate(json);
    this.lastUsage.value = parsed.usage;
    return { text: parsed.text, model: parsed.model, tokensIn: parsed.usage.freshInputTokens + parsed.usage.cachedInputTokens, tokensOut: parsed.usage.outputTokens, ...(parsed.providerRoute === undefined ? {} : { providerRoute: parsed.providerRoute }) };
  }

  async embed(texts: readonly string[]): Promise<Embedding[]> {
    if (texts.length === 0) return [];
    const wire = this.opts.dialect.buildEmbed(this.opts.model, texts);
    const json = await this.send(wire);
    const parsed = this.opts.dialect.parseEmbed(json);
    this.lastUsage.value = parsed.usage;
    return parsed.vectors.map((v) => v as Embedding);
  }

  /** Optional batched transport for an explicitly admitted embedding route. Ordinary
   * memory remains lexical until model/role/transform and document-egress admission
   * are wired by the host. This primitive never grants that authority itself. */
  async embedBounded(texts: readonly string[], options: BoundedEmbeddingOptions): Promise<BoundedEmbeddingResult> {
    const batchWindows = options.maxBatchWindows ?? 64, batchBytes = options.maxBatchBytes ?? 65_536;
    const responseBytes = options.maxResponseBytes ?? 4_194_304;
    if (!Number.isSafeInteger(batchWindows) || batchWindows < 1 || batchWindows > 256 ||
        !Number.isSafeInteger(batchBytes) || batchBytes < 1 || batchBytes > 1_048_576 ||
        !Number.isSafeInteger(responseBytes) || responseBytes < 1 || responseBytes > 8_388_608 ||
        !Number.isSafeInteger(this.maxAttempts) || this.maxAttempts < 1 || this.maxAttempts > 16 ||
        !Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1 || this.timeoutMs > 86_400_000 ||
        !Number.isSafeInteger(this.baseBackoffMs) || this.baseBackoffMs < 0 ||
        !Number.isSafeInteger(this.maxBackoffMs) || this.maxBackoffMs < 0 || this.maxBackoffMs > 60_000) throw new Error("invalid finite embedding transport bounds");
    if (!Array.isArray(texts) || texts.length > 65_536) throw new Error("invalid bounded embedding inputs");
    let rawBytes = 0;
    for (const text of texts) {
      if (typeof text !== "string" || text.length === 0) throw new Error("embedding windows must be nonempty strings");
      rawBytes += Buffer.byteLength(text, "utf8");
      if (rawBytes > 4_194_304) throw new Error("embedding input exceeds operation byte bound");
    }
    options.signal?.throwIfAborted();
    // Freeze exact serialized bodies before reservation. A caller or dialect cannot
    // mutate a previously counted body during asynchronous admission or dispatch.
    const batches: { path: string; body: string; bytes: number; windows: number }[] = [];
    const addBatch = (items: readonly string[]): void => {
      const wire = this.opts.dialect.buildEmbed(this.opts.model, items), body = JSON.stringify(wire.body), bytes = Buffer.byteLength(body, "utf8");
      if (bytes > batchBytes) {
        if (items.length === 1) throw new Error("embedding window exceeds serialized batch bound");
        const middle = Math.floor(items.length / 2);
        addBatch(items.slice(0, middle)); addBatch(items.slice(middle));
      } else batches.push({ path: wire.path, body, bytes, windows: items.length });
    };
    for (let start = 0; start < texts.length; start += batchWindows) addBatch(texts.slice(start, start + batchWindows));
    const reserved = Object.freeze({ requests: batches.length * this.maxAttempts,
      inputBytes: batches.reduce((n, b) => n + b.bytes, 0) * this.maxAttempts, windows: texts.length * this.maxAttempts });
    const dispatched = { requests: 0, inputBytes: 0, windows: 0 };
    if (!batches.length) return { vectors: [], reserved, dispatched };
    const control = await options.reserve(reserved), vectors: Embedding[] = [];
    let dimension: number | undefined, observedHttpFailure = false;
    try {
      for (const batch of batches) {
        let delay = 0;
        for (let attempt = 1; attempt <= this.maxAttempts; attempt++) {
          const result = await control.runRequest(batch.bytes, batch.windows, async budgetSignal => {
            const signal = options.signal === undefined ? budgetSignal : AbortSignal.any([budgetSignal, options.signal]);
            signal.throwIfAborted();
            if (delay) await this.sleep(delay);
            signal.throwIfAborted();
            options.assertAuthority?.();
            const requestSignal = AbortSignal.any([signal, AbortSignal.timeout(this.timeoutMs)]);
            dispatched.requests++; dispatched.inputBytes += batch.bytes; dispatched.windows += batch.windows;
            const res = await this.fetchImpl(this.opts.baseUrl.replace(/\/+$/, "") + batch.path, {
              method: "POST", redirect: "error", signal: requestSignal, body: batch.body,
              headers: { "content-type": "application/json", [this.opts.dialect.authHeader]: this.opts.dialect.authValue(this.opts.apiKey), ...(this.opts.dialect.extraHeaders ?? {}) },
            });
            if (!res.ok) {
              await res.body?.cancel();
              if (res.status < 400 || res.status > 599) throw new Error("indeterminate embedding HTTP response");
              return { status: res.status, retryAfter: parseRetryAfter(res.headers.get("retry-after")), vectors: undefined };
            }
            const parsed = this.opts.dialect.parseEmbed(await boundedJson(res, responseBytes, requestSignal));
            if (parsed.vectors.length !== batch.windows) throw new Error("embedding response count mismatch");
            for (const vector of parsed.vectors) {
              const norm = vector.reduce((n, value) => n + value * value, 0);
              dimension ??= vector.length;
              if (!dimension || vector.length !== dimension || !vector.every(value => typeof value === "number" && Number.isFinite(value)) ||
                  !Number.isFinite(norm) || norm <= 0) throw new Error("invalid embedding vector dimension or values");
            }
            return { status: res.status, retryAfter: undefined, vectors: parsed.vectors };
          });
          if (result.vectors) { vectors.push(...result.vectors); break; }
          const permanent = result.status !== 429 && result.status < 500;
          if (permanent || attempt === this.maxAttempts) {
            observedHttpFailure = true;
            throw new ProviderError(`embedding HTTP ${result.status}`, result.status, permanent);
          }
          delay = this.backoff(attempt, result.retryAfter);
        }
      }
      await control.complete();
      return { vectors, reserved, dispatched: Object.freeze({ ...dispatched }) };
    } catch (error) {
      // Known HTTP refusal can close observed work. Unknown/late/invalid responses
      // are held by runRequest; complete must not clear that durable hold.
      if (observedHttpFailure) {
        try { await control.complete(); } catch { /* retain original failure and pending work */ }
      }
      throw error;
    }
  }

  /**
   * Streaming generate. Yields text deltas as they arrive, then returns the aggregated result. FAILS
   * CLOSED on truncation: if the stream ends without the dialect's terminal sentinel / stop event, it
   * throws — a partial stream is an error, never a silent partial success (SOTA: detect mid-stream
   * failure by the missing [DONE]/message_stop). Streaming responses are NOT retried mid-flight
   * (can't cleanly resume), but a pre-first-token connection failure surfaces as a throw the caller
   * may fall back on.
   */
  async generateStream(req: GenerateRequest, onDelta?: (text: string) => void): Promise<GenerateResult> {
    const maxTokens = req.maxTokens ?? this.opts.defaultMaxTokens ?? 1024;
    const dialect = this.opts.dialect;
    const wire = dialect.buildGenerate(this.opts.model, req.prompt, maxTokens, true, { structuredOutput: req.hints?.["structuredOutput"] === true });
    const url = this.opts.baseUrl.replace(/\/+$/, "") + wire.path;
    const headers: Record<string, string> = {
      "content-type": "application/json",
      accept: "text/event-stream",
      [dialect.authHeader]: dialect.authValue(this.opts.apiKey),
      ...(dialect.extraHeaders ?? {}),
    };

    const ac = new AbortController();
    const signal = req.signal === undefined ? ac.signal : AbortSignal.any([ac.signal, req.signal]);
    const timer = setTimeout(() => ac.abort(), this.timeoutMs);
    let res: Response;
    try {
      res = await this.fetchImpl(url, { method: "POST", headers, body: JSON.stringify(wire.body), signal });
    } catch (err) {
      clearTimeout(timer);
      throw new ProviderError(`stream connect failed: ${String(err)}`, 0, false);
    }
    if (!res.ok) {
      clearTimeout(timer);
      const permanent = res.status !== 429 && res.status >= 400 && res.status < 500;
      throw new ProviderError(`stream ${res.status}`, res.status, permanent);
    }
    if (!res.body) {
      clearTimeout(timer);
      throw new ProviderError("stream had no body", 0, false);
    }

    const decoder = new SseDecoder();
    const textDecoder = new TextDecoder();
    const events: unknown[] = [];
    let text = "";
    let sawStop = false;
    const reader = res.body.getReader();

    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        const sseEvents = decoder.feed(textDecoder.decode(value, { stream: true }));
        for (const ev of sseEvents) {
          if (ev.data === dialect.streamDoneSentinel) { sawStop = true; continue; }
          let parsed: unknown;
          try { parsed = JSON.parse(ev.data); } catch { continue; } // ignore unparseable heartbeat lines
          events.push(parsed);
          if (dialect.isStreamStop(parsed)) sawStop = true;
          const delta = dialect.streamDelta(parsed);
          if (delta) { text += delta; onDelta?.(delta); }
        }
      }
      for (const ev of decoder.finish()) {
        if (ev.data === dialect.streamDoneSentinel) { sawStop = true; continue; }
        try {
          const parsed = JSON.parse(ev.data);
          events.push(parsed);
          if (dialect.isStreamStop(parsed)) sawStop = true;
          const delta = dialect.streamDelta(parsed);
          if (delta) { text += delta; onDelta?.(delta); }
        } catch { /* ignore */ }
      }
    } finally {
      clearTimeout(timer);
    }

    // FAIL CLOSED: no terminal sentinel/stop means the stream was cut off mid-generation.
    if (!sawStop) {
      throw new ProviderError("stream ended without terminal sentinel (truncated) — treating as failure, not partial success", 0, false);
    }

    const usage: TokenUsage = dialect.streamUsage(events) ?? { freshInputTokens: 0, cachedInputTokens: 0, outputTokens: 0 };
    this.lastUsage.value = usage;
    return { text, model: this.opts.model, tokensIn: usage.freshInputTokens + usage.cachedInputTokens, tokensOut: usage.outputTokens };
  }

  /** Send with retry. Honors Retry-After; else exponential backoff; never retries permanent (4xx≠429). */
  private async send(wire: { path: string; body: Record<string, unknown> }, externalSignal?: AbortSignal): Promise<unknown> {
    const url = this.opts.baseUrl.replace(/\/+$/, "") + wire.path;
    const dialect = this.opts.dialect;
    const headers: Record<string, string> = {
      "content-type": "application/json",
      [dialect.authHeader]: dialect.authValue(this.opts.apiKey),
      ...(dialect.extraHeaders ?? {}),
    };

    let lastErr: ProviderError | undefined;
    for (let attempt = 1; attempt <= this.maxAttempts; attempt++) {
      const ac = new AbortController();
      const signal = externalSignal === undefined ? ac.signal : AbortSignal.any([ac.signal, externalSignal]);
      const timer = setTimeout(() => ac.abort(), this.timeoutMs);
      let res: Response;
      try {
        res = await this.fetchImpl(url, { method: "POST", headers, body: JSON.stringify(wire.body), signal });
      } catch (err) {
        clearTimeout(timer);
        if (externalSignal?.aborted) throw new ProviderError("request cancelled", 0, true);
        // Network error / abort → transient; retry with backoff.
        lastErr = new ProviderError(`network error: ${String(err)}`, 0, false);
        if (attempt < this.maxAttempts) { await this.sleep(this.backoff(attempt, undefined)); continue; }
        throw lastErr;
      }
      clearTimeout(timer);

      if (res.ok) {
        return await res.json();
      }

      // Permanent client errors (400/401/403/404/422) must NOT be retried.
      if (res.status !== 429 && res.status >= 400 && res.status < 500) {
        const bodyText = await safeText(res);
        throw new ProviderError(`permanent ${res.status}: ${bodyText.slice(0, 200)}`, res.status, true);
      }

      // Transient (429 / 5xx): honor Retry-After, else backoff, then retry.
      lastErr = new ProviderError(`transient ${res.status}`, res.status, false);
      if (attempt < this.maxAttempts) {
        const retryAfterMs = parseRetryAfter(res.headers.get("retry-after"));
        await this.sleep(this.backoff(attempt, retryAfterMs));
        continue;
      }
      throw lastErr;
    }
    throw lastErr ?? new ProviderError("exhausted retries", 0, false);
  }

  private backoff(attempt: number, retryAfterMs: number | undefined): number {
    if (retryAfterMs !== undefined) return Math.min(retryAfterMs, this.maxBackoffMs);
    // exponential: base * 2^(attempt-1), capped.
    return Math.min(this.baseBackoffMs * 2 ** (attempt - 1), this.maxBackoffMs);
  }
}

/** Parse a Retry-After header (seconds or HTTP-date) into ms, or undefined. */
export function parseRetryAfter(value: string | null): number | undefined {
  if (!value) return undefined;
  const secs = Number(value);
  if (Number.isFinite(secs)) return Math.max(0, secs * 1000);
  const date = Date.parse(value);
  if (Number.isFinite(date)) return Math.max(0, date - Date.now());
  return undefined;
}

async function safeText(res: Response): Promise<string> {
  try { return await res.text(); } catch { return ""; }
}

async function boundedJson(res: Response, maxBytes: number, signal: AbortSignal): Promise<unknown> {
  if (!res.body) throw new Error("embedding response has no body");
  const reader = res.body.getReader(), chunks: Uint8Array[] = [];
  let bytes = 0, complete = false;
  try {
    for (;;) {
      signal.throwIfAborted();
      const item = await reader.read();
      signal.throwIfAborted();
      if (item.done) { complete = true; break; }
      bytes += item.value.byteLength;
      if (bytes > maxBytes) throw new Error("embedding response exceeds byte bound");
      chunks.push(item.value);
    }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)));
  } finally {
    if (!complete) void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}
