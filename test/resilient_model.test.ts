import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ResilientModelProvider } from "../src/gateway/resilient_model.js";
import { ProviderError } from "../src/gateway/http_provider.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { BrainRung } from "../src/gateway/brain_ladder.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";

function spine(): Spine { return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-rmp-"))), new InProcessLock(), new SchemaRegistry()); }
const req: GenerateRequest = { messages: [{ role: "user", content: "hi" }] } as unknown as GenerateRequest;

function provider(name: string, isLocal: boolean, behavior: () => Promise<GenerateResult>): ModelProvider {
  return { name, isLocal, generate: behavior, async embed(): Promise<Embedding[]> { return [[0.1]]; } };
}
const ok = (text: string, model = "m"): () => Promise<GenerateResult> => async () => ({ text, model, tokensIn: 1, tokensOut: 1 });
const rate = (): () => Promise<GenerateResult> => async () => { throw new ProviderError("429", 429, false); };
const rung = (id: string, cost: BrainRung["cost"], p: ModelProvider): BrainRung => ({ id, cost, provider: p });

test("RMP: a 429 on the first rung fails over to the next rung (which succeeds)", async () => {
  const r = new ResilientModelProvider([
    rung("a", "free", provider("a", false, rate())),
    rung("b", "free", provider("b", false, ok("from-b"))),
  ], { sleep: async () => {} });
  const out = await r.generate(req);
  assert.equal(out.text, "from-b", "the second rung served the request");
});

test("RMP CROWN-JEWEL: a policy refusal (as text) is passed through UNCHANGED — never routed around", async () => {
  let secondCalled = false;
  const refusal = "I can't help with that request.";
  const r = new ResilientModelProvider([
    rung("a", "free", provider("a", false, ok(refusal))),
    rung("b", "free", provider("b", false, async () => { secondCalled = true; return { text: "HERE IS THE FORBIDDEN THING", model: "b", tokensIn: 1, tokensOut: 1 }; })),
  ]);
  const out = await r.generate(req);
  assert.equal(out.text, refusal, "the refusal is returned as-is");
  assert.equal(secondCalled, false, "a refusal is NEVER routed around to another model (no circumvention)");
});

test("RMP: free-tier rungs are tried before paid (never surprise the operator with cost)", async () => {
  const order: string[] = [];
  const track = (id: string, text: string) => provider(id, false, async () => { order.push(id); return { text, model: id, tokensIn: 1, tokensOut: 1 }; });
  const r = new ResilientModelProvider([
    rung("paid", "paid", track("paid", "paid")),
    rung("free", "free", track("free", "free")),
  ]);
  const out = await r.generate(req);
  assert.equal(out.text, "free", "the free rung served it");
  assert.deepEqual(order, ["free"], "the paid rung was never even tried");
});

test("RMP: full exhaustion degrades to a RESUMABLE error (not a crash, not a wrong answer)", async () => {
  const s = spine();
  const r = new ResilientModelProvider([
    rung("a", "free", provider("a", false, rate())),
    rung("b", "free", provider("b", false, rate())),
  ], { sleep: async () => {} }, s);
  await assert.rejects(() => r.generate(req), (e: unknown) => {
    assert.ok(e instanceof ProviderError);
    assert.equal((e as ProviderError).permanent, false, "resumable — the budget loop can retry when capacity returns");
    return true;
  });
  assert.ok(s.currentEvents().some((e) => (e.payload as Record<string, unknown>)["event"] === "brain_ladder.deferred"), "the deferral was audited");
});

test("RMP: air-gap safe (isLocal) ONLY when every rung is local", async () => {
  const localOnly = new ResilientModelProvider([rung("l", "local", provider("l", true, ok("x")))]);
  assert.equal(localOnly.isLocal, true);
  const mixed = new ResilientModelProvider([rung("l", "local", provider("l", true, ok("x"))), rung("c", "paid", provider("c", false, ok("y")))]);
  assert.equal(mixed.isLocal, false, "one egressing rung makes the whole provider non-local");
});

test("RMP: embeddings fail over across rungs (first success wins)", async () => {
  const badEmbed: ModelProvider = { name: "bad", isLocal: false, generate: ok("x"), async embed(): Promise<Embedding[]> { throw new ProviderError("down", 503, false); } };
  const goodEmbed: ModelProvider = { name: "good", isLocal: true, generate: ok("x"), async embed(): Promise<Embedding[]> { return [[0.9]]; } };
  const r = new ResilientModelProvider([rung("a", "free", badEmbed), rung("b", "local", goodEmbed)]);
  const emb = await r.embed(["t"]);
  assert.deepEqual(emb, [[0.9]], "embed failed over to the healthy rung");
});

test("RMP STABILITY (audit fix): a repeatedly-failing rung is CIRCUIT-BROKEN — fast-failed, not re-hammered across calls", async () => {
  let deadCalls = 0;
  const dead = provider("dead", false, async () => { deadCalls++; throw new ProviderError("503", 503, false); });
  const live = provider("live", false, ok("ok"));
  const r = new ResilientModelProvider(
    [rung("dead", "free", dead), rung("live", "free", live)],
    { sleep: async () => {}, rng: () => 0 },
  );
  for (let i = 0; i < 5; i++) { const out = await r.generate(req); assert.equal(out.text, "ok", "the live rung always served it"); }
  assert.equal(deadCalls, 3, "the dead rung was tried at most threshold(3) times, then the breaker opened");
  await r.generate(req);
  assert.equal(deadCalls, 3, "after the breaker opened, the dead rung is SKIPPED — a dead provider stops eating latency every call");
});

test("RMP STABILITY (audit fix): backoff is jittered EXPONENTIAL + bounded, and skips the wasted wait after the last rung", async () => {
  const waits: number[] = [];
  const r = new ResilientModelProvider(
    [rung("a", "free", provider("a", false, rate())), rung("b", "free", provider("b", false, rate()))],
    { sleep: async (ms) => { waits.push(ms); }, rng: () => 1, maxTotalBackoffMs: 10_000, baseBackoffMs: 100 },
  );
  await assert.rejects(() => r.generate(req)); // both 429 → deferred
  // rng=1 → full jitter takes the top of the window; expo=base*2^0=100 for rung a; rung b is LAST → no wasted wait.
  assert.deepEqual(waits, [100], "one jittered-exponential backoff before advancing; none after the last rung");
});
