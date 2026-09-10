import { test } from "node:test";
import assert from "node:assert/strict";
import { HttpProvider } from "../src/gateway/http_provider.js";
import { openAiDialect, anthropicDialect, type WireDialect } from "../src/gateway/wire_dialect.js";

const frame = (value: unknown) => `data: ${JSON.stringify(value)}\n\n`;
const start = (usage: unknown) => ({ type: "message_start", message: { usage } });
const update = (usage: unknown) => ({ type: "message_delta", usage });

// Instrumented transport, real parser. No external model or billing evidence.
async function stream(dialect: WireDialect, events: readonly unknown[]) {
  let calls = 0;
  const anthropic = dialect.name === anthropicDialect.name;
  const text = anthropic ? { type: "content_block_delta", delta: { text: "useful" } }
    : { choices: [{ delta: { content: "useful" } }] };
  const body = [text, ...events].map(frame).join("") + (anthropic ? frame({ type: "message_stop" }) : "data: [DONE]\n\n");
  const provider = new HttpProvider({ baseUrl: "http://127.0.0.1:1", model: "synthetic", apiKey: "SYNTHETIC_ONLY", dialect,
    fetchImpl: async () => { calls++; return new Response(body); } });
  const result = await provider.generateStream({ prompt: "synthetic" });
  assert.equal(result.text, "useful"); assert.equal(calls, 1);
  return result;
}

for (const dialect of [openAiDialect, anthropicDialect]) {
  test(`${dialect.name}: absent streamed usage is unknown, not observed zero`, async () => {
    assert.equal((await stream(dialect, [])).usageComplete, false);
  });
  test(`${dialect.name}: explicitly reported zero is complete`, async () => {
    const events = dialect === openAiDialect ? [{ usage: { prompt_tokens: 0, completion_tokens: 0 } }]
      : [start({ input_tokens: 0 }), update({ output_tokens: 0 })];
    const r = await stream(dialect, events);
    assert.equal(r.usageComplete, true); assert.equal(r.tokensIn, 0); assert.equal(r.tokensOut, 0);
  });
}

test("OpenAI trailing usage preserves cached split, actual route and complete status", async () => {
  const r = await stream(openAiDialect, [{ choices: [{ delta: {}, finish_reason: "stop" }], usage: null },
    { choices: [], provider: "synthetic-route", usage: { prompt_tokens: 7, completion_tokens: 2, prompt_tokens_details: { cached_tokens: 3 } } }]);
  assert.equal(r.usageComplete, true); assert.equal(r.tokensIn, 7); assert.equal(r.tokensOut, 2);
  assert.equal(r.providerRoute, "synthetic-route");
});

for (const usage of [{}, { prompt_tokens: 2 }, { completion_tokens: 2 },
  { prompt_tokens: -1, completion_tokens: 2 }, { prompt_tokens: 2, completion_tokens: 0.5 },
  { prompt_tokens: "2", completion_tokens: 2 }, { prompt_tokens: 2, completion_tokens: Number.MAX_SAFE_INTEGER + 1 },
  { prompt_tokens: 2, completion_tokens: 2, prompt_tokens_details: { cached_tokens: 3 } }]) {
  test(`OpenAI malformed final usage cannot borrow previous complete counters: ${JSON.stringify(usage)}`, async () => {
    const r = await stream(openAiDialect, [{ usage: { prompt_tokens: 2, completion_tokens: 2 } }, { usage }]);
    assert.equal(r.usageComplete, false);
  });
}

test("Anthropic output snapshots are cumulative, not additive", async () => {
  const r = await stream(anthropicDialect, [start({ input_tokens: 10, cache_read_input_tokens: 4, output_tokens: 1 }),
    update({ output_tokens: 3 }), update({ output_tokens: 7 })]);
  assert.equal(r.usageComplete, true); assert.equal(r.tokensIn, 14); assert.equal(r.tokensOut, 7);
});

for (const events of [[start({ input_tokens: 2, output_tokens: 1 })], [update({ output_tokens: 3 })],
  [start({ input_tokens: 2 }), update({})], [start({ input_tokens: -1 }), update({ output_tokens: 3 })],
  [start({ input_tokens: 2, cache_read_input_tokens: "1" }), update({ output_tokens: 3 })],
  [start({ input_tokens: 2 }), update({ output_tokens: 0.5 })],
  [start({ input_tokens: 2 }), update({ output_tokens: 3 }), update({ output_tokens: 2 })],
  [start({ input_tokens: Number.MAX_SAFE_INTEGER, cache_read_input_tokens: 1 }), update({ output_tokens: 1 })]]) {
  test(`Anthropic incomplete or invalid usage: ${JSON.stringify(events)}`, async () => {
    assert.equal((await stream(anthropicDialect, events)).usageComplete, false);
  });
}

test("trusted custom dialect returning the existing complete TokenUsage shape remains usable", async () => {
  const dialect: WireDialect = { ...openAiDialect, streamUsage: () => ({ freshInputTokens: 2, cachedInputTokens: 1, outputTokens: 3 }) };
  const r = await stream(dialect, []);
  assert.equal(r.usageComplete, true); assert.equal(r.tokensIn, 3); assert.equal(r.tokensOut, 3);
  assert.equal(r.providerRoute, undefined);
});
