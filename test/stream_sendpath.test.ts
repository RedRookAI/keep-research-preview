import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ProviderRouter, type EgressFn } from "../src/gateway/provider_router.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import { interceptEgress } from "../src/privacy/egress_interceptor.js";
import { RedactionGateway } from "../src/privacy/redaction_gateway.js";
import { DataClassifier } from "../src/ingest/data_classifier.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";

const spine = () => new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-ss-"))), new InProcessLock(), new SchemaRegistry());
const classifier = new DataClassifier();
const egressFn = (): EgressFn => (prompt, provider) => interceptEgress(prompt, provider, { classifier, session: () => new RedactionGateway() });
const reg = (p: ModelProvider) => ({ id: "p1", tier: "standard" as const, costWeight: 1, provider: p });

// a streaming provider that emits the received prompt back in fixed-size chunks (echoing surrogates) and assembles the full text
class ChunkEchoProvider implements ModelProvider {
  readonly name = "echo";
  lastPrompt = "";
  constructor(readonly isLocal: boolean, private readonly chunkSize = 3) {}
  async generate(req: GenerateRequest): Promise<GenerateResult> { this.lastPrompt = req.prompt; return { text: req.prompt, model: "echo", tokensIn: 1, tokensOut: 1 }; }
  async generateStream(req: GenerateRequest, onDelta?: (t: string) => void): Promise<GenerateResult> {
    this.lastPrompt = req.prompt;
    // "the model answers with the surrogate it received" — emit the prompt back, chunked mid-surrogate
    const reply = req.prompt;
    for (let i = 0; i < reply.length; i += this.chunkSize) onDelta?.(reply.slice(i, i + this.chunkSize));
    return { text: reply, model: "echo", tokensIn: 1, tokensOut: 1 };
  }
  async embed(): Promise<Embedding[]> { return []; }
}
// a non-streaming provider (no generateStream) for the opt-in fallback
class PlainProvider implements ModelProvider {
  readonly name = "plain";
  constructor(readonly isLocal: boolean) {}
  async generate(req: GenerateRequest): Promise<GenerateResult> { return { text: `answer to ${req.prompt}`, model: "plain", tokensIn: 1, tokensOut: 1 }; }
  async embed(): Promise<Embedding[]> { return []; }
}

test("STREAM-SENDPATH (a): a remote streamed response is rehydrated across chunk boundaries", async () => {
  const prov = new ChunkEchoProvider(false, 3); // tiny chunks split the surrogate
  const r = new ProviderRouter(spine(), () => 1, { egress: egressFn() }); r.register(reg(prov));
  let streamed = "";
  await r.runStream({ prompt: "email alice@corp.com now" }, (d) => { streamed += d; });
  assert.ok(streamed.includes("alice@corp.com"), "the surrogate (split across chunks) was rehydrated in the stream");
  assert.ok(!streamed.includes("\u27E6"), "no surrogate token leaked across the boundary");
  assert.ok(!prov.lastPrompt.includes("alice@corp.com"), "the provider received a redacted prompt");
});

test("STREAM-SENDPATH (b): streamed concatenation is byte-exact with the non-streamed rehydrate", async () => {
  const prov = new ChunkEchoProvider(false, 2);
  const r = new ProviderRouter(spine(), () => 1, { egress: egressFn() }); r.register(reg(prov));
  let streamed = "";
  const result = await r.runStream({ prompt: "reach a@x.com and b@y.com" }, (d) => { streamed += d; });
  assert.equal(streamed, result.text, "the streamed pieces concatenate to the full rehydrated result");
  assert.ok(streamed.includes("a@x.com") && streamed.includes("b@y.com"), "both values rehydrated");
});

test("STREAM-SENDPATH (c): a LOCAL provider streams unchanged (no redaction)", async () => {
  const prov = new ChunkEchoProvider(true, 3);
  const r = new ProviderRouter(spine(), () => 1, { egress: egressFn() }); r.register(reg(prov));
  let streamed = "";
  await r.runStream({ prompt: "email alice@corp.com" }, (d) => { streamed += d; });
  assert.equal(prov.lastPrompt, "email alice@corp.com", "local provider receives the prompt byte-identical");
  assert.equal(streamed, "email alice@corp.com", "local stream is unchanged");
});

test("STREAM-SENDPATH (d): a provider WITHOUT generateStream falls back to the non-streaming path (opt-in)", async () => {
  const prov = new PlainProvider(false);
  const r = new ProviderRouter(spine(), () => 1, { egress: egressFn() }); r.register(reg(prov));
  let streamed = "";
  const result = await r.runStream({ prompt: "hello" }, (d) => { streamed += d; });
  assert.match(result.text, /answer to/, "non-streaming provider still answers via run()");
  assert.equal(streamed, result.text, "the full text is delivered once via onDelta");
});

test("STREAM-SENDPATH default: no injected egress fn still applies the remote privacy floor", async () => {
  const prov = new ChunkEchoProvider(false, 3);
  const r = new ProviderRouter(spine(), () => 1, {}); r.register(reg(prov)); // no egress
  let streamed = "";
  await r.runStream({ prompt: "email alice@corp.com" }, (d) => { streamed += d; });
  assert.doesNotMatch(prov.lastPrompt, /alice@corp\.com/, "the provider receives only the per-call surrogate");
  assert.equal(streamed, "email alice@corp.com", "safe complete output is rehydrated before caller delivery");
});
