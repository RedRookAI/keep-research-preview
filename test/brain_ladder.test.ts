import { test } from "node:test";
import assert from "node:assert/strict";
import { BrainLadder, type BrainRung, type CircuitCheck } from "../src/gateway/brain_ladder.js";
import type { ModelProvider, GenerateRequest, GenerateResult } from "../src/gateway/gateway.js";

const REQ: GenerateRequest = { model: "x", messages: [{ role: "user", content: "hi" }] } as unknown as GenerateRequest;
const okResult = (name: string): GenerateResult => ({ text: `ok from ${name}`, usage: { freshInputTokens: 1, cachedInputTokens: 0, outputTokens: 1 } } as unknown as GenerateResult);

class ProviderErr extends Error { constructor(public status: number, public permanent: boolean, public retryAfterMs?: number) { super(`status ${status}`); } }

function provider(name: string, behavior: () => Promise<GenerateResult>): ModelProvider {
  return { name, isLocal: name === "local", async generate() { return behavior(); }, async embed() { return []; } };
}
const rung = (id: string, cost: BrainRung["cost"], p: ModelProvider): BrainRung => ({ id, provider: p, cost });
const noSleep = async () => {};

test("INVARIANT: a 429 on rung 1 is NOT a crash — back off + advance to rung 2 (which succeeds)", async () => {
  const r1 = rung("free-a", "free", provider("free-a", async () => { throw new ProviderErr(429, false, 100); }));
  const r2 = rung("free-b", "free", provider("free-b", async () => okResult("free-b")));
  const ladder = new BrainLadder([r1, r2], { sleep: noSleep });
  const res = await ladder.generate(REQ);
  assert.equal(res.status, "ok");
  assert.equal(res.status === "ok" && res.rungId, "free-b");
  assert.ok(res.attempts.some((a) => a.rungId === "free-a" && a.outcome === "rate-limited"));
});

test("INVARIANT: full exhaustion → graceful DEFER (never throws for capacity)", async () => {
  const r1 = rung("free-a", "free", provider("free-a", async () => { throw new ProviderErr(429, false, 50); }));
  const r2 = rung("free-b", "free", provider("free-b", async () => { throw new ProviderErr(429, false, 50); }));
  const ladder = new BrainLadder([r1, r2], { sleep: noSleep });
  const res = await ladder.generate(REQ);
  assert.equal(res.status, "deferred", "graceful defer, not a crash");
  assert.ok(res.status === "deferred" && /resume/.test(res.reason));
});

test("INVARIANT: a circuit-open rung is skipped", async () => {
  const calls: string[] = [];
  const r1 = rung("free-a", "free", provider("free-a", async () => { calls.push("free-a"); return okResult("free-a"); }));
  const r2 = rung("free-b", "free", provider("free-b", async () => { calls.push("free-b"); return okResult("free-b"); }));
  const circuit: CircuitCheck = { isOpen: (id) => id === "free-a", recordFailure() {}, recordSuccess() {} };
  const ladder = new BrainLadder([r1, r2], { sleep: noSleep, circuit });
  const res = await ladder.generate(REQ);
  assert.equal(res.status === "ok" && res.rungId, "free-b");
  assert.ok(!calls.includes("free-a"), "the open-circuit rung was never called");
});

test("INVARIANT: free rungs are tried before paid (never surprise the operator with cost)", async () => {
  const order: string[] = [];
  const paid = rung("paid", "paid", provider("paid", async () => { order.push("paid"); return okResult("paid"); }));
  const free = rung("free", "free", provider("free", async () => { order.push("free"); return okResult("free"); }));
  const ladder = new BrainLadder([paid, free], { sleep: noSleep }); // registered paid-first
  const res = await ladder.generate(REQ);
  assert.equal(res.status === "ok" && res.rungId, "free", "free rung tried first regardless of registration order");
  assert.deepEqual(order, ["free"]);
});

test("INVARIANT: a permanent error (400) on a rung advances to the next, not retried", async () => {
  let freeCalls = 0;
  const r1 = rung("free-a", "free", provider("free-a", async () => { freeCalls++; throw new ProviderErr(400, true); }));
  const r2 = rung("local", "local", provider("local", async () => okResult("local")));
  const ladder = new BrainLadder([r1, r2], { sleep: noSleep });
  const res = await ladder.generate(REQ);
  assert.equal(res.status === "ok" && res.rungId, "local");
  assert.equal(freeCalls, 1, "the permanent-error rung was tried once, not retried");
});

test("INVARIANT: local rung is the last-resort before paid (free → local → paid)", async () => {
  const order: string[] = [];
  const local = rung("local", "local", provider("local", async () => { order.push("local"); throw new ProviderErr(500, false); }));
  const paid = rung("paid", "paid", provider("paid", async () => { order.push("paid"); return okResult("paid"); }));
  const free = rung("free", "free", provider("free", async () => { order.push("free"); throw new ProviderErr(429, false, 10); }));
  const ladder = new BrainLadder([local, paid, free], { sleep: noSleep });
  await ladder.generate(REQ);
  assert.deepEqual(order, ["free", "local", "paid"], "ordering is free → local → paid");
});

test("SAFETY ENVELOPE INVARIANT: the ladder only picks WHICH brain — it carries no vetting/floor logic that could be relaxed", () => {
  // Structural proof: the BrainLadder module exposes ONLY generate() (brain selection). It has no method
  // that vets, approves, or bypasses a floor — so a cheaper rung cannot get a laxer gate. The floors live
  // in the pipeline and run on whatever result the ladder returns, identically for every rung.
  const inst = new BrainLadder([rung("free", "free", provider("free", async () => okResult("free")))], { sleep: noSleep });
  const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(inst));
  assert.ok(methods.includes("generate"), "exposes generate");
  for (const m of methods) {
    assert.ok(!/vet|approve|bypass|floor|gate|merge/i.test(m), `ladder must not carry safety-relaxing method: ${m}`);
  }
});
