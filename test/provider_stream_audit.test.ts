import { test } from "node:test";
import assert from "node:assert/strict";
import { HttpProvider, ProviderError } from "../src/gateway/http_provider.js";
import { openAiDialect, anthropicDialect, type WireDialect } from "../src/gateway/wire_dialect.js";
import { SseDecoder } from "../src/gateway/sse.js";

const frame = (data: unknown, event?: string) => `${event ? `event: ${event}\n` : ""}data: ${JSON.stringify(data)}\n\n`;
const delta = (dialect: WireDialect, text: string) => dialect === anthropicDialect
  ? frame({ type: "content_block_delta", delta: { text } }) : frame({ choices: [{ delta: { content: text } }] });
const end = (dialect: WireDialect) => dialect === anthropicDialect ? frame({ type: "message_stop" }, "message_stop") : "data: [DONE]\n\n";

// Instrumented response ports supplement the separate real-HTTP audit tests.
// No inference, organization admission, or independent administration is claimed.
function fixture(chunks: readonly (string | Uint8Array)[], dialect = openAiDialect, close = true) {
  let reads = 0, cancelled = 0, calls = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (reads < chunks.length) {
        const chunk = chunks[reads++]!;
        controller.enqueue(typeof chunk === "string" ? new TextEncoder().encode(chunk) : chunk);
      } else if (close) controller.close();
    },
    cancel() { cancelled++; },
  }, { highWaterMark: 0 });
  const response = new Response(body);
  const provider = new HttpProvider({ baseUrl: "http://127.0.0.1:1", model: "synthetic", apiKey: "SYNTHETIC_ONLY", dialect,
    requestTimeoutMs: 1000, fetchImpl: async () => { calls++; return response; } });
  return { provider, body, counts: () => ({ reads, cancelled, calls }) };
}

for (const dialect of [openAiDialect, anthropicDialect]) {
  for (const errorFrame of [frame({ error: { message: "synthetic failure" } }), frame({ type: "error", error: {} }), "event: error\ndata: not-json\n\n"]) {
    test(`KEEP-12A-003 ${dialect.name}: explicit error cannot become successful partial output (${errorFrame.slice(0, 35)})`, async () => {
      const f = fixture([delta(dialect, "partial"), errorFrame + end(dialect)], dialect);
      const callbacks: string[] = [];
      await assert.rejects(f.provider.generateStream({ prompt: "synthetic" }, t => callbacks.push(t)),
        (e: unknown) => e instanceof ProviderError && e.permanent && /stream.*error/u.test(e.message));
      assert.deepEqual(callbacks, ["partial"]);
      assert.equal(f.provider.lastUsage.value, undefined);
      assert.equal(f.counts().calls, 1); assert.equal(f.counts().cancelled, 1); assert.equal(f.body.locked, false);
    });
  }
  for (const sameChunk of [true, false]) {
    test(`KEEP-12A-004 ${dialect.name}: hard terminal closes content (${sameChunk ? "same" : "later"} chunk)`, async () => {
      const first = delta(dialect, "useful") + end(dialect), tail = delta(dialect, " forbidden tail");
      const f = fixture(sameChunk ? [first + tail] : [first, tail], dialect, false);
      const callbacks: string[] = [];
      // This port stays open: terminal handling must not depend on socket EOF.
      const result = await f.provider.generateStream({ prompt: "synthetic" }, t => callbacks.push(t));
      assert.equal(result.text, "useful"); assert.deepEqual(callbacks, ["useful"]);
      assert.deepEqual(f.counts(), { reads: 1, cancelled: 1, calls: 1 }); assert.equal(f.body.locked, false);
    });
  }
}

test("OpenAI finish reason preserves its delta and trailing usage before hard completion", async () => {
  const f = fixture([frame({ choices: [{ delta: { content: "last" }, finish_reason: "stop" }] }),
    frame({ choices: [], usage: { prompt_tokens: 7, completion_tokens: 2 } }), end(openAiDialect)]);
  const r = await f.provider.generateStream({ prompt: "synthetic" });
  assert.equal(r.text, "last"); assert.equal(r.tokensIn, 7); assert.equal(r.tokensOut, 2);
  assert.equal(f.body.locked, false);
});

test("OpenAI soft completion does not reopen text and cannot hide a later error", async () => {
  for (const tail of [delta(openAiDialect, "unexpected"), frame({ error: { message: "synthetic" } })]) {
    const f = fixture([delta(openAiDialect, "useful"), frame({ choices: [{ delta: {}, finish_reason: "stop" }] }), tail + end(openAiDialect)]);
    const callbacks: string[] = [];
    await assert.rejects(f.provider.generateStream({ prompt: "synthetic" }, t => callbacks.push(t)));
    assert.deepEqual(callbacks, ["useful"]); assert.equal(f.provider.lastUsage.value, undefined);
    assert.equal(f.body.locked, false);
  }
});

test("existing EOF-after-finish compatibility remains explicit, with reader released", async () => {
  const f = fixture([delta(openAiDialect, "useful"), frame({ choices: [{ delta: {}, finish_reason: "stop" }] })]);
  assert.equal((await f.provider.generateStream({ prompt: "synthetic" })).text, "useful");
  assert.equal(f.body.locked, false);
});

for (const eofFlush of [true, false]) {
  test(`callback failure propagates outside JSON parsing (${eofFlush ? "EOF compatibility" : "framed"})`, async () => {
    const payload = frame({ choices: [{ delta: { content: "useful" }, finish_reason: "stop" }] });
    const f = fixture([eofFlush ? payload.trimEnd() : payload]);
    const failure = new Error("synthetic consumer failure");
    await assert.rejects(f.provider.generateStream({ prompt: "synthetic" }, () => { throw failure; }), e => e === failure);
    assert.equal(f.body.locked, false); assert.equal(f.provider.lastUsage.value, undefined);
  });
}

test("stream UTF8 decoding preserves a multibyte character split on every byte", async () => {
  const bytes = new TextEncoder().encode(delta(openAiDialect, "界😀") + end(openAiDialect));
  const f = fixture([...bytes].map(byte => new Uint8Array([byte])));
  assert.equal((await f.provider.generateStream({ prompt: "synthetic" })).text, "界😀");
  assert.equal(f.body.locked, false);
});

test("KEEP-12A-005 cap counts UTF8 bytes, including frame prefix, not JS string units", () => {
  const input = "data: " + "界".repeat(4); //18 bytes,10 UTF16 units
  assert.equal(Buffer.byteLength(input), 18);
  assert.throws(() => new SseDecoder({ maxBufferBytes: 16 }).feed(input), /overflow/u);
  const exact = new SseDecoder({ maxBufferBytes: 18 });
  assert.deepEqual(exact.feed(input), []);
  assert.equal(exact.finish()[0]!.data, "界".repeat(4));
});

test("KEEP-12A-005 incremental multibyte and surrogate boundaries retain the configured byte ceiling", () => {
  const d = new SseDecoder({ maxBufferBytes: 18 });
  assert.deepEqual(d.feed("data: 界界"), []); assert.deepEqual(d.feed("界界"), []);
  assert.throws(() => d.feed("x"), /overflow/u);
  const surrogate = new SseDecoder({ maxBufferBytes: 10 });
  assert.deepEqual(surrogate.feed("data: \ud83d"), []); assert.deepEqual(surrogate.feed("\ude00"), []);
  assert.equal(surrogate.finish()[0]!.data, "😀");
});

test("CRLF split across chunks cannot synthesize an extra blank line", () => {
  const input = "data: first\r\ndata: second\r\n\r\n";
  for (let i = 0; i <= input.length; i++) {
    const d = new SseDecoder();
    const events = [...d.feed(input.slice(0, i)), ...d.feed(input.slice(i)), ...d.finish()];
    assert.deepEqual(events, [{ data: "first\nsecond" }], `split ${i}`);
  }
});

test("buffer limit configuration cannot silently disable its bound", () => {
  for (const maxBufferBytes of [NaN, Infinity, -1, 0, 1.2]) assert.throws(() => new SseDecoder({ maxBufferBytes }));
});

test("KEEP-12A-005 default byte overflow cancels the stream and cannot produce usage success", async () => {
  const f = fixture(["data: " + "界".repeat(Math.ceil(8 * 1024 * 1024 / 3))], openAiDialect, false);
  await assert.rejects(f.provider.generateStream({ prompt: "synthetic" }),
    (e: unknown) => e instanceof ProviderError && e.permanent && /framing error/u.test(e.message));
  assert.equal(f.counts().cancelled, 1); assert.equal(f.counts().calls, 1);
  assert.equal(f.body.locked, false); assert.equal(f.provider.lastUsage.value, undefined);
});

test("cancellation requested by the final delta cannot return a successful completion", async () => {
  const controller = new AbortController();
  const f = fixture([delta(openAiDialect, "last") + end(openAiDialect)]);
  await assert.rejects(f.provider.generateStream({ prompt: "synthetic", signal: controller.signal }, () => controller.abort()));
  assert.equal(f.body.locked, false); assert.equal(f.provider.lastUsage.value, undefined);
});
