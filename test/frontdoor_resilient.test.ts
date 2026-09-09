import { test } from "node:test";
import assert from "node:assert/strict";

import { brainFromKey, localBrain, type BrainDescriptor } from "../src/frontdoor/brain_port.js";
import { CapabilityRegistry, type CapabilityRecord } from "../src/frontdoor/capability_registry.js";
import {
  buildChain,
  walkChain,
  CircuitBreaker,
  isFailoverEligible,
  type CandidateBrain,
  type HopAttempt,
} from "../src/frontdoor/fallback_chain.js";

const frontier: BrainDescriptor = brainFromKey("sk-ant-frontier1234567890", { baseURL: "https://frontier/v1", model: "opus" });
const cheap: BrainDescriptor = brainFromKey("sk-cheap1234567890", { baseURL: "https://cheap/v1", model: "mini" });

// --- Registry: self-updating precedence ---

test("measured quality overrides snapshot overrides inferred", () => {
  const reg = new CapabilityRegistry("2026-08-01", [
    { key: `${frontier.providerLabel}::opus`, tier: "standard", score: 0.65, source: "snapshot", asOf: "2026-08-01" },
  ]);
  // snapshot says 'standard'
  assert.equal(reg.capabilityOf(frontier).source, "snapshot");
  assert.equal(reg.capabilityOf(frontier).tier, "standard");
  // a measured run overrides it
  reg.recordMeasuredQuality(frontier, 0.95);
  const after = reg.capabilityOf(frontier);
  assert.equal(after.source, "measured");
  assert.equal(after.tier, "rich");
});

test("an unknown brain falls back to structural inference", () => {
  const reg = new CapabilityRegistry("2026-08-01", []);
  const rec = reg.capabilityOf(localBrain(), {});
  assert.equal(rec.source, "inferred");
});

test("recordMeasuredQuality blends via EMA (recent runs move it, don't overwrite)", () => {
  const reg = new CapabilityRegistry();
  reg.recordMeasuredQuality(cheap, 1.0);
  reg.recordMeasuredQuality(cheap, 0.0);
  const s = reg.capabilityOf(cheap).score;
  assert.ok(s > 0 && s < 1, `EMA should be between the two observations, got ${s}`);
});

test("registry knows when it is stale and says so plainly", () => {
  const fresh = new CapabilityRegistry("2026-08-01");
  assert.equal(fresh.isStale(new Date("2026-08-04")), false);
  const stale = new CapabilityRegistry("2026-01-01");
  assert.equal(stale.isStale(new Date("2026-08-04")), true);
  assert.ok(/out of date/i.test(stale.stalenessNote(new Date("2026-08-04"))));
});

test("refreshSnapshot updates records and the as-of date", () => {
  const reg = new CapabilityRegistry("2026-01-01");
  const rec: CapabilityRecord = { key: `${cheap.providerLabel}::mini`, tier: "lean", score: 0.4, source: "snapshot", asOf: "2026-08-04" };
  reg.refreshSnapshot([rec], "2026-08-04");
  assert.equal(reg.isStale(new Date("2026-08-04")), false);
  assert.equal(reg.capabilityOf(cheap).source, "snapshot");
});

// --- Chain construction ---

function cand(brain: BrainDescriptor, reg: CapabilityRegistry): CandidateBrain {
  return { brain, capability: reg.capabilityOf(brain) };
}

function richCheapRegistry(): CapabilityRegistry {
  return new CapabilityRegistry("2026-08-04", [
    { key: `${frontier.providerLabel}::opus`, tier: "rich", score: 0.9, source: "snapshot", asOf: "2026-08-04" },
    { key: `${cheap.providerLabel}::mini`, tier: "lean", score: 0.4, source: "snapshot", asOf: "2026-08-04" },
  ]);
}

test("planning orders best-first; mechanical orders cheap-first; terminal always appended", () => {
  const reg = richCheapRegistry();
  const cands = [cand(cheap, reg), cand(frontier, reg)]; // deliberately cheap-first input
  const breaker = new CircuitBreaker();

  const plan = buildChain("plan_decompose", cands, breaker);
  assert.equal(plan[0]!.brain!.providerLabel, frontier.providerLabel); // best first
  assert.equal(plan[plan.length - 1]!.kind, "deterministic"); // terminal

  const mech = buildChain("converse", cands, breaker);
  assert.equal(mech[0]!.brain!.providerLabel, cheap.providerLabel); // cheap first
  assert.equal(mech[mech.length - 1]!.kind, "deterministic");
});

test("an unhealthy brain (open breaker) is skipped in the chain", () => {
  const reg = richCheapRegistry();
  const breaker = new CircuitBreaker(1, 60_000); // opens after 1 failure
  breaker.recordFailure(frontier.providerLabel + "opus");
  const chain = buildChain("plan_decompose", [cand(frontier, reg), cand(cheap, reg)], breaker);
  const llmHops = chain.filter((h) => h.kind === "llm");
  assert.ok(!llmHops.some((h) => h.brain!.providerLabel === frontier.providerLabel)); // skipped
  assert.equal(llmHops[0]!.brain!.providerLabel, cheap.providerLabel); // fell to cheap
});

// --- Single-model contingency (the back of the room) ---

test("single weak brain: planning still runs, flagged degraded, terminal still present", () => {
  const reg = new CapabilityRegistry("2026-08-04");
  const only = localBrain(); // inferred lean
  const chain = buildChain("plan_decompose", [cand(only, reg)], new CircuitBreaker());
  const first = chain[0]!;
  assert.equal(first.kind, "llm");
  assert.equal(first.degraded, true); // honest about the ceiling
  assert.equal(chain[chain.length - 1]!.kind, "deterministic"); // never stuck
});

// --- Failure taxonomy ---

test("a policy refusal is NOT failover-eligible; other failures are", () => {
  assert.equal(isFailoverEligible("policy-refusal"), false);
  for (const k of ["rate-limit", "server-error", "timeout", "access-revoked", "quality-fail"] as const) {
    assert.equal(isFailoverEligible(k), true);
  }
});

// --- Walk: failover, stop-on-policy, never-hard-fail ---

test("a rate-limit on the primary fails over to the next hop", async () => {
  const reg = richCheapRegistry();
  const breaker = new CircuitBreaker();
  const chain = buildChain("plan_decompose", [cand(frontier, reg), cand(cheap, reg)], breaker);
  const attempt: HopAttempt = async (hop) =>
    hop.brain?.providerLabel === frontier.providerLabel ? { ok: false, failure: "rate-limit" } : { ok: true, output: "planned" };
  const res = await walkChain(chain, attempt, breaker);
  assert.equal(res.output, "planned");
  assert.equal(res.succeededAt!.brain!.providerLabel, cheap.providerLabel); // failed over
});

test("a policy refusal STOPS the chain (no circumvention)", async () => {
  const reg = richCheapRegistry();
  const breaker = new CircuitBreaker();
  const chain = buildChain("converse", [cand(frontier, reg), cand(cheap, reg)], breaker);
  const attempt: HopAttempt = async () => ({ ok: false, failure: "policy-refusal" });
  const res = await walkChain(chain, attempt, breaker);
  assert.equal(res.succeededAt, undefined); // did NOT route around the refusal
  assert.ok(res.trail.some((t) => t.outcome === "stopped-policy"));
});

test("total brain failure lands on the deterministic terminal (never hard-fails)", async () => {
  const reg = richCheapRegistry();
  const breaker = new CircuitBreaker();
  const chain = buildChain("plan_decompose", [cand(frontier, reg), cand(cheap, reg)], breaker);
  const attempt: HopAttempt = async () => ({ ok: false, failure: "server-error" }); // everything down
  const res = await walkChain(chain, attempt, breaker);
  assert.equal(res.succeededAt!.kind, "deterministic"); // survived on the built-in flow
});

test("the circuit breaker opens after the threshold and recovers after cooldown", () => {
  const b = new CircuitBreaker(2, 1000);
  assert.equal(b.isOpen("x", 0), false);
  b.recordFailure("x", 0);
  b.recordFailure("x", 0);
  assert.equal(b.isOpen("x", 500), true); // open
  assert.equal(b.isOpen("x", 2000), false); // half-open after cooldown
  b.recordSuccess("x");
  assert.equal(b.isOpen("x", 2001), false); // closed after success
});
