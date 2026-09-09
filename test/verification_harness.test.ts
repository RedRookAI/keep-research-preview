import { test } from "node:test";
import assert from "node:assert/strict";
import { buildHarness, costAdaptivePolicy, capabilityOf, type BrainCapability } from "../src/cascade/verification_harness.js";
import type { VerificationTier, VerificationItem, TierResult } from "../src/cascade/verification_cascade.js";
import type { Authorship } from "../src/review/heterogeneous.js";

// A sound Tier-0 floor for tests: passes unless the item id says "bad" (then a sound fail).
function floor<T>(): VerificationTier<T> {
  return {
    tier: 0, name: "test-floor", sound: true, available: () => true,
    verify: (item: VerificationItem<T>): TierResult => item.id.includes("bad")
      ? { tier: 0, name: "test-floor", decision: "fail", reason: "sound fail", sound: true, certainty: 1 }
      : { tier: 0, name: "test-floor", decision: "pass", reason: "sound pass", sound: true, certainty: 1 },
  };
}
// A marginal floor that leaves the item undecided (forces climb to model tiers).
function marginalFloor<T>(): VerificationTier<T> {
  return {
    tier: 0, name: "marginal-floor", sound: true, available: () => true,
    verify: (): TierResult => ({ tier: 0, name: "marginal-floor", decision: "undecided", reason: "marginal", sound: true, certainty: 0.5 }),
  };
}
const item = (id: string): VerificationItem<string> => ({ id, kind: "artifact", payload: id });
const policy = costAdaptivePolicy();

test("INVARIANT: the Tier-0 deterministic floor is present for EVERY capability (rich/lean/none)", async () => {
  for (const cap of ["rich", "lean", "none"] as BrainCapability[]) {
    const cascade = buildHarness<string>({ floor: floor(), capability: cap, policy });
    const out = await cascade.run(item("ok-1"));
    assert.ok(out.trail.some((t) => t.tier === 0), `floor ran for capability=${cap}`);
    assert.equal(out.finalDecision, "pass");
  }
});

test("INVARIANT: a sound Tier-0 FAIL is the final decision (soundness dominates, no model tier overturns)", async () => {
  const cascade = buildHarness<string>({
    floor: floor(), capability: "rich", policy,
    singleBrain: () => ({ decision: "pass", reason: "model likes it", certainty: 1 }), // would pass, but...
    singleBrainAuthorship: { agentId: "a", modelFamily: "fam-A" },
  });
  const out = await cascade.run(item("bad-1"));
  assert.equal(out.finalDecision, "fail", "sound fail cannot be overturned by a fuzzy pass tier");
  assert.equal(out.decidedAtTier, 0);
});

test("INVARIANT: back-of-room lean brain — a DECISIVE sound floor spends NO model call (cost-adaptive)", async () => {
  let modelCalled = false;
  const cascade = buildHarness<string>({
    floor: floor(), capability: "lean", policy,
    singleBrain: () => { modelCalled = true; return { decision: "pass", reason: "x", certainty: 1 }; },
    singleBrainAuthorship: { agentId: "a", modelFamily: "fam-A" },
  });
  await cascade.run(item("ok-2"));
  assert.equal(modelCalled, false, "decisive floor → no scarce free-tier model call");
});

test("INVARIANT: a MARGINAL floor DOES climb to the single-brain tier (verification asymmetry — lean still verifies)", async () => {
  let modelCalled = false;
  const cascade = buildHarness<string>({
    floor: marginalFloor(), capability: "lean", policy,
    singleBrain: () => { modelCalled = true; return { decision: "pass", reason: "verified", certainty: 1 }; },
    singleBrainAuthorship: { agentId: "a", modelFamily: "fam-A" },
  });
  await cascade.run(item("marginal-1"));
  assert.equal(modelCalled, true, "marginal item climbs to the lean model tier");
});

test("INVARIANT: Tier-2 second brain heterogeneity is ENFORCED (same-family reviewer refused)", () => {
  const same: Authorship = { agentId: "b", modelFamily: "fam-A" };
  assert.throws(() => buildHarness<string>({
    floor: floor(), capability: "rich", policy,
    singleBrain: () => ({ decision: "undecided", reason: "x", certainty: 0.5 }),
    singleBrainAuthorship: { agentId: "a", modelFamily: "fam-A" },
    secondBrain: { reviewer: () => ({ decision: "pass", reason: "y", certainty: 1 }), identity: same },
  }), /heterogeneity|self-review/);
});

test("INVARIANT: a heterogeneous Tier-2 second brain is ACCEPTED", () => {
  const diff: Authorship = { agentId: "b", modelFamily: "fam-B" };
  assert.doesNotThrow(() => buildHarness<string>({
    floor: floor(), capability: "rich", policy,
    singleBrain: () => ({ decision: "undecided", reason: "x", certainty: 0.5 }),
    singleBrainAuthorship: { agentId: "a", modelFamily: "fam-A" },
    secondBrain: { reviewer: () => ({ decision: "pass", reason: "y", certainty: 1 }), identity: diff },
  }));
});

test("INVARIANT: no-brain profile → floor + human only, still safe (no model tier)", async () => {
  const cascade = buildHarness<string>({ floor: floor(), capability: "none", policy });
  const out = await cascade.run(item("ok-3"));
  assert.ok(out.trail.some((t) => t.tier === 0));
  assert.ok(!out.trail.some((t) => t.tier === 1), "no single-brain tier when capability is none");
  assert.equal(out.finalDecision, "pass");
});

test("capabilityOf maps CapabilityTier → harness capability", () => {
  assert.equal(capabilityOf("rich"), "rich");
  assert.equal(capabilityOf("standard"), "lean");
  assert.equal(capabilityOf("lean"), "lean");
  assert.equal(capabilityOf("minimal"), "none");
  assert.equal(capabilityOf(undefined), "none");
});
