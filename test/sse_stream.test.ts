import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, type ServerResponse, type IncomingMessage } from "node:http";
import { AddressInfo } from "node:net";

import { SseDecoder, parseSse } from "../src/gateway/sse.js";
import { HttpProvider, ProviderError } from "../src/gateway/http_provider.js";
import { openAiDialect, anthropicDialect } from "../src/gateway/wire_dialect.js";

// ── SSE parser invariants ───────────────────────────────────────────────────

test("INVARIANT: SSE events are split on the blank-line boundary", () => {
  const events = parseSse("data: a\n\ndata: b\n\n");
  assert.equal(events.length, 2);
  assert.equal(events[0]!.data, "a");
  assert.equal(events[1]!.data, "b");
});

test("INVARIANT: a data payload split across chunk boundaries reassembles correctly", () => {
  const d = new SseDecoder();
  // JSON object split mid-way across two feeds (the real network-chunk hazard).
  let evs = d.feed('data: {"content":"hel');
  assert.equal(evs.length, 0, "incomplete event is buffered, not emitted");
  evs = d.feed('lo"}\n\n');
  assert.equal(evs.length, 1);
  assert.equal(evs[0]!.data, '{"content":"hello"}');
});

test("INVARIANT: multi-line data fields are joined with newlines", () => {
  const events = parseSse("data: line1\ndata: line2\n\n");
  assert.equal(events[0]!.data, "line1\nline2");
});

test("INVARIANT: comments/heartbeats (: lines) are ignored", () => {
  const events = parseSse(": heartbeat\ndata: real\n\n");
  assert.equal(events.length, 1);
  assert.equal(events[0]!.data, "real");
});

test("INVARIANT: SSE buffer overflow fails closed (malformed/unterminated stream)", () => {
  const d = new SseDecoder({ maxBufferBytes: 32 });
  assert.throws(() => d.feed("data: " + "x".repeat(100)), /overflow/);
});

test("event: and id: fields are parsed", () => {
  const events = parseSse("event: message\nid: 7\ndata: hi\n\n");
  assert.equal(events[0]!.event, "message");
  assert.equal(events[0]!.id, "7");
});

// ── Streaming provider against a real local SSE server ──────────────────────

async function sseServe(lines: string[], opts: { status?: number } = {}): Promise<{ url: string; close: () => Promise<void>; server: Server }> {
  const server = createServer((_req: IncomingMessage, res: ServerResponse) => {
    if (opts.status && opts.status >= 400) { res.statusCode = opts.status; res.end("err"); return; }
    res.setHeader("content-type", "text/event-stream");
    res.write(lines.join(""));
    res.end();
  });
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as AddressInfo).port;
  return { url: `http://127.0.0.1:${port}`, server, close: () => new Promise<void>((r) => server.close(() => r())) };
}

test("INVARIANT: OpenAI streaming accumulates deltas into full text + fires onDelta + parses usage", async () => {
  const s = await sseServe([
    `data: ${JSON.stringify({ choices: [{ delta: { content: "Hello" } }] })}\n\n`,
    `data: ${JSON.stringify({ choices: [{ delta: { content: ", world" } }] })}\n\n`,
    `data: ${JSON.stringify({ choices: [{ delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 3, completion_tokens: 2 } })}\n\n`,
    `data: [DONE]\n\n`,
  ]);
  try {
    const p = new HttpProvider({ baseUrl: s.url, apiKey: "k", model: "m", dialect: openAiDialect, sleep: async () => {} });
    const deltas: string[] = [];
    const r = await p.generateStream({ prompt: "hi" }, (d) => deltas.push(d));
    assert.equal(r.text, "Hello, world");
    assert.deepEqual(deltas, ["Hello", ", world"]);
    assert.equal(r.tokensOut, 2);
    assert.equal(r.tokensIn, 3);
  } finally { await s.close(); }
});

test("INVARIANT: Anthropic streaming (content_block_delta + message_stop) works", async () => {
  const s = await sseServe([
    `event: message_start\ndata: ${JSON.stringify({ type: "message_start", message: { usage: { input_tokens: 10 } } })}\n\n`,
    `event: content_block_delta\ndata: ${JSON.stringify({ type: "content_block_delta", delta: { text: "Hi" } })}\n\n`,
    `event: content_block_delta\ndata: ${JSON.stringify({ type: "content_block_delta", delta: { text: " there" } })}\n\n`,
    `event: message_delta\ndata: ${JSON.stringify({ type: "message_delta", usage: { output_tokens: 4 } })}\n\n`,
    `event: message_stop\ndata: ${JSON.stringify({ type: "message_stop" })}\n\n`,
  ]);
  try {
    const p = new HttpProvider({ baseUrl: s.url, apiKey: "k", model: "claude", dialect: anthropicDialect, sleep: async () => {} });
    const r = await p.generateStream({ prompt: "hi" });
    assert.equal(r.text, "Hi there");
    assert.equal(r.tokensOut, 4);
    assert.equal(r.tokensIn, 10, "input tokens from message_start");
  } finally { await s.close(); }
});

test("INVARIANT: a stream ending WITHOUT its terminal sentinel FAILS CLOSED (truncation ≠ partial success)", async () => {
  // No [DONE], no finish_reason, no message_stop — the connection just ends.
  const s = await sseServe([
    `data: ${JSON.stringify({ choices: [{ delta: { content: "partial" } }] })}\n\n`,
  ]);
  try {
    const p = new HttpProvider({ baseUrl: s.url, apiKey: "k", model: "m", dialect: openAiDialect, sleep: async () => {} });
    await assert.rejects(() => p.generateStream({ prompt: "hi" }), /truncated|terminal sentinel/);
  } finally { await s.close(); }
});

test("INVARIANT: a 5xx on stream connect throws (transient)", async () => {
  const s = await sseServe([], { status: 503 });
  try {
    const p = new HttpProvider({ baseUrl: s.url, apiKey: "k", model: "m", dialect: openAiDialect, sleep: async () => {} });
    await assert.rejects(() => p.generateStream({ prompt: "hi" }), (e: unknown) => e instanceof ProviderError && !e.permanent);
  } finally { await s.close(); }
});
