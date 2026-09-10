import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import { AddressInfo } from "node:net";

import { HttpProvider, ProviderError, parseRetryAfter } from "../src/gateway/http_provider.js";
import { openAiDialect, anthropicDialect, openAiDialectWithRouting } from "../src/gateway/wire_dialect.js";

/** Spin up a real local HTTP server with a handler; returns base URL + close fn. */
async function serve(handler: (req: IncomingMessage, res: ServerResponse, body: string) => void): Promise<{ url: string; close: () => Promise<void>; server: Server }> {
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => handler(req, res, body));
  });
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}`,
    server,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

const noSleep = async () => {};

// ── OpenAI dialect ──────────────────────────────────────────────────────────

test("INVARIANT: OpenAI dialect generate round-trips text + usage (real HTTP)", async () => {
  const s = await serve((req, res, _body) => {
    assert.equal(req.url, "/v1/chat/completions");
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({
      model: "gpt-x",
      choices: [{ message: { content: "hello world" }, finish_reason: "stop" }],
      usage: { prompt_tokens: 12, completion_tokens: 5, prompt_tokens_details: { cached_tokens: 4 } },
    }));
  });
  try {
    const p = new HttpProvider({ baseUrl: s.url, apiKey: "k", model: "gpt-x", dialect: openAiDialect, sleep: noSleep });
    const r = await p.generate({ prompt: "hi" });
    assert.equal(r.text, "hello world");
    assert.equal(r.tokensOut, 5);
    assert.equal(r.tokensIn, 12, "fresh+cached input tokens");
    assert.equal(p.lastUsage.value!.cachedInputTokens, 4);
    assert.equal(p.lastUsage.value!.freshInputTokens, 8, "prompt_tokens - cached");
  } finally { await s.close(); }
});

test("structured-output hints request JSON mode without changing ordinary calls", async () => {
  const bodies: Record<string, unknown>[] = [];
  const s = await serve((_req, res, body) => {
    bodies.push(JSON.parse(body));
    res.end(JSON.stringify({ model: "m", choices: [{ message: { content: "{}" } }], usage: { prompt_tokens: 1, completion_tokens: 1 } }));
  });
  try {
    const provider = new HttpProvider({ baseUrl: s.url, apiKey: "k", model: "m", dialect: openAiDialect, sleep: noSleep });
    await provider.generate({ prompt: "ordinary" });
    await provider.generate({ prompt: "structured", hints: { structuredOutput: true } });
    assert.equal(bodies[0]?.["response_format"], undefined);
    assert.deepEqual(bodies[1]?.["response_format"], { type: "json_object" });
  } finally { await s.close(); }
});

test("external routing policy is emitted exactly and returned route identity is preserved", async () => {
  const s = await serve((_req, res, body) => {
    const sent = JSON.parse(body) as { provider: unknown };
    assert.deepEqual(sent.provider, { zdr: true, data_collection: "deny", allow_fallbacks: false, only: ["Example Route"] });
    res.end(JSON.stringify({ model: "m", provider: "Example Route", choices: [{ message: { content: "ok" } }], usage: { prompt_tokens: 1, completion_tokens: 1 } }));
  });
  try {
    const dialect = openAiDialectWithRouting({ zeroDataRetention: true, dataCollection: "deny", allowFallbacks: false, providers: ["Example Route"] });
    const result = await new HttpProvider({ baseUrl: s.url, apiKey: "k", model: "m", dialect, sleep: noSleep }).generate({ prompt: "private repository context" });
    assert.equal(result.providerRoute, "Example Route");
  } finally { await s.close(); }
});

test("OpenAI dialect embed round-trips vectors", async () => {
  const s = await serve((_req, res) => {
    res.end(JSON.stringify({ model: "emb", data: [{ embedding: [0.1, 0.2, 0.3] }, { embedding: [0.4, 0.5, 0.6] }], usage: { prompt_tokens: 6 } }));
  });
  try {
    const p = new HttpProvider({ baseUrl: s.url, apiKey: "k", model: "emb", dialect: openAiDialect, sleep: noSleep });
    const v = await p.embed(["a", "b"]);
    assert.equal(v.length, 2);
    assert.deepEqual(v[0], [0.1, 0.2, 0.3]);
  } finally { await s.close(); }
});

// ── Anthropic dialect ───────────────────────────────────────────────────────

test("INVARIANT: Anthropic dialect generate parses content[].text + input/output/cache tokens", async () => {
  const s = await serve((req, res, _body) => {
    assert.equal(req.url, "/v1/messages");
    assert.equal(req.headers["anthropic-version"], "2023-06-01", "version header sent");
    assert.equal(req.headers["x-api-key"], "secret", "x-api-key auth (bare key)");
    res.end(JSON.stringify({
      model: "claude-x",
      content: [{ type: "text", text: "part1 " }, { type: "text", text: "part2" }],
      usage: { input_tokens: 20, output_tokens: 7, cache_read_input_tokens: 5 },
    }));
  });
  try {
    const p = new HttpProvider({ baseUrl: s.url, apiKey: "secret", model: "claude-x", dialect: anthropicDialect, sleep: noSleep });
    const r = await p.generate({ prompt: "hi" });
    assert.equal(r.text, "part1 part2", "content blocks concatenated");
    assert.equal(p.lastUsage.value!.freshInputTokens, 20);
    assert.equal(p.lastUsage.value!.cachedInputTokens, 5);
    assert.equal(p.lastUsage.value!.outputTokens, 7);
  } finally { await s.close(); }
});

test("INVARIANT: Anthropic dialect embed fails closed (no first-party embeddings)", async () => {
  const p = new HttpProvider({ baseUrl: "http://127.0.0.1:1", apiKey: "k", model: "claude-x", dialect: anthropicDialect, sleep: noSleep });
  await assert.rejects(() => p.embed(["a"]), /does not provide embeddings/);
});

// ── Retry / error semantics (the load-bearing SOTA) ─────────────────────────

test("INVARIANT: honors Retry-After then succeeds", async () => {
  let hits = 0;
  const s = await serve((_req, res) => {
    hits++;
    if (hits === 1) { res.statusCode = 429; res.setHeader("retry-after", "1"); res.end("slow down"); return; }
    res.end(JSON.stringify({ model: "m", choices: [{ message: { content: "ok" } }], usage: { prompt_tokens: 1, completion_tokens: 1 } }));
  });
  try {
    const waits: number[] = [];
    const p = new HttpProvider({ baseUrl: s.url, apiKey: "k", model: "m", dialect: openAiDialect, sleep: async (ms) => { waits.push(ms); } });
    const r = await p.generate({ prompt: "hi" });
    assert.equal(r.text, "ok");
    assert.equal(hits, 2, "retried once");
    assert.equal(waits[0], 1000, "honored Retry-After: 1s = 1000ms");
  } finally { await s.close(); }
});

test("INVARIANT: 5xx triggers exponential backoff retry then succeeds", async () => {
  let hits = 0;
  const s = await serve((_req, res) => {
    hits++;
    if (hits < 3) { res.statusCode = 503; res.end("unavailable"); return; }
    res.end(JSON.stringify({ model: "m", choices: [{ message: { content: "recovered" } }], usage: { prompt_tokens: 1, completion_tokens: 1 } }));
  });
  try {
    const waits: number[] = [];
    const p = new HttpProvider({ baseUrl: s.url, apiKey: "k", model: "m", dialect: openAiDialect, sleep: async (ms) => { waits.push(ms); }, retry: { baseBackoffMs: 100 } });
    const r = await p.generate({ prompt: "hi" });
    assert.equal(r.text, "recovered");
    assert.equal(hits, 3);
    assert.deepEqual(waits, [100, 200], "exponential: 100, then 200");
  } finally { await s.close(); }
});

test("INVARIANT: 400 is PERMANENT — never retried, throws immediately", async () => {
  let hits = 0;
  const s = await serve((_req, res) => { hits++; res.statusCode = 400; res.end("bad request"); });
  try {
    const p = new HttpProvider({ baseUrl: s.url, apiKey: "k", model: "m", dialect: openAiDialect, sleep: noSleep });
    await assert.rejects(() => p.generate({ prompt: "hi" }), (e: unknown) => e instanceof ProviderError && e.permanent && e.status === 400);
    assert.equal(hits, 1, "a 400 must NOT be retried (would just burn rate limit)");
  } finally { await s.close(); }
});

test("INVARIANT: exhausts retries on persistent 5xx then throws transient", async () => {
  let hits = 0;
  const s = await serve((_req, res) => { hits++; res.statusCode = 500; res.end("boom"); });
  try {
    const p = new HttpProvider({ baseUrl: s.url, apiKey: "k", model: "m", dialect: openAiDialect, sleep: noSleep, retry: { maxAttempts: 3, baseBackoffMs: 1 } });
    await assert.rejects(() => p.generate({ prompt: "hi" }), (e: unknown) => e instanceof ProviderError && !e.permanent);
    assert.equal(hits, 3, "tried exactly maxAttempts times");
  } finally { await s.close(); }
});

test("INVARIANT: request timeout aborts and is treated as transient", async () => {
  const s = await serve((_req, _res) => { /* never respond → force timeout */ });
  try {
    const p = new HttpProvider({ baseUrl: s.url, apiKey: "k", model: "m", dialect: openAiDialect, sleep: noSleep, requestTimeoutMs: 50, retry: { maxAttempts: 2, baseBackoffMs: 1 } });
    await assert.rejects(() => p.generate({ prompt: "hi" }), /network error|transient/);
  } finally { await s.close(); }
});

test("INVARIANT: caller cancellation aborts immediately and is never retried", async () => {
  let hits = 0;
  let markArrived!: () => void;
  const arrived = new Promise<void>((resolve) => { markArrived = resolve; });
  const s = await serve((_req, _res) => { hits += 1; markArrived(); });
  try {
    const controller = new AbortController();
    let attempts = 0;
    const fetchImpl: typeof fetch = (input, init) => { attempts += 1; return fetch(input, init); };
    const p = new HttpProvider({ baseUrl: s.url, apiKey: "k", model: "m", dialect: openAiDialect, sleep: noSleep, requestTimeoutMs: 10_000, fetchImpl });
    const pending = p.generate({ prompt: "cancel me", signal: controller.signal });
    await Promise.race([arrived, new Promise<never>((_resolve, reject) => setTimeout(() => reject(new Error("request never reached the server")), 5_000))]);
    controller.abort();
    await assert.rejects(() => pending, (error: unknown) => error instanceof ProviderError && error.permanent && /cancelled/u.test(error.message));
    assert.equal(hits, 1);
    assert.equal(attempts, 1, "caller cancellation is never retried");
  } finally { s.server.closeAllConnections(); await s.close(); }
});

test("INVARIANT: pre-dispatch caller cancellation reaches no server and is never retried", async () => {
  let hits = 0, attempts = 0;
  const s = await serve((_req, _res) => { hits += 1; });
  try {
    const controller = new AbortController(); controller.abort();
    const fetchImpl: typeof fetch = (input, init) => { attempts += 1; return fetch(input, init); };
    const p = new HttpProvider({ baseUrl: s.url, apiKey: "k", model: "m", dialect: openAiDialect, sleep: noSleep, requestTimeoutMs: 10_000, fetchImpl });
    await assert.rejects(() => p.generate({ prompt: "already cancelled", signal: controller.signal }), (error: unknown) => error instanceof ProviderError && error.permanent && /cancelled/u.test(error.message));
    assert.equal(attempts, 0, "an already-cancelled request is refused before invoking even the injected transport");
    assert.equal(hits, 0, "an already-cancelled request never reaches the server");
  } finally { s.server.closeAllConnections(); await s.close(); }
});

// ── parseRetryAfter helper ──────────────────────────────────────────────────

test("parseRetryAfter handles seconds and HTTP-date and junk", () => {
  assert.equal(parseRetryAfter("2"), 2000);
  assert.equal(parseRetryAfter(null), undefined);
  assert.equal(parseRetryAfter("garbage"), undefined);
  const future = new Date(Date.now() + 5000).toUTCString();
  const ms = parseRetryAfter(future)!;
  assert.ok(ms > 3000 && ms <= 5000, "HTTP-date parsed to ~5s");
});
