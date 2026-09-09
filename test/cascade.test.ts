import { test } from "node:test";
import assert from "node:assert/strict";

import {
  VerificationCascade,
  type VerificationTier,
  type VerificationItem,
  type TierResult,
} from "../src/cascade/verification_cascade.js";
import {
  ConfidenceEscalationPolicy,
  complexityPreRouter,
  intraTierConsensus,
} from "../src/cascade/escalation_policy.js";
import {
  LogicVetFloorTier,
  SingleBrainTier,
  ExternalBrainTier,
  HumanTier,
  logicVettingTiers,
  type PlanVetPayload,
} from "../src/cascade/tier_adapters.js";
import type { Plan } from "../src/logicvet/deterministic_critics.js";

// Simple tiers for the generic tests
function tier(n: number, name: string, sound: boolean, decision: TierResult["decision"], certainty = 1): VerificationTier {
  return {
    tier: n,
    name,
    sound,
    available: () => true,
    verify: (): TierResult => ({ tier: n, name, decision, reason: `${name}:${decision}`, sound, certainty }),
  };
}

const alwaysEscalate = new ConfidenceEscalationPolicy({ certaintyThreshold: 1.1 }); // always marginal
const neverEscalate = new ConfidenceEscalationPolicy({ certaintyThreshold: 0 });

function item(id = "i1"): VerificationItem {
  return { id, kind: "test", payload: {} };
}

// ── The cascade rule ────────────────────────────────────────────────────────

test("INVARIANT: the floor decides cheap items; higher tiers do NOT run", async () => {
  let tier1Ran = false;
  const t0 = tier(0, "floor", true, "pass");
  const t1: VerificationTier = { tier: 1, name: "brain", sound: false, available: () => true, verify: () => { tier1Ran = true; return { tier: 1, name: "brain", decision: "pass", reason: "", sound: false, certainty: 1 }; } };
  const cascade = new VerificationCascade([t0, t1], neverEscalate);
  const out = await cascade.run(item());
  assert.equal(out.finalDecision, "pass");
  assert.equal(out.decidedAtTier, 0, "decided at the floor");
  assert.equal(tier1Ran, false, "tier 1 never ran — cascade rule holds");
  assert.equal(out.trail.length, 1);
});

// ── Soundness dominates ─────────────────────────────────────────────────────

test("INVARIANT: a SOUND floor fail short-circuits and is never overturned", async () => {
  let higherRan = false;
  const t0 = tier(0, "floor", true, "fail");
  const t1: VerificationTier = { tier: 1, name: "brain", sound: false, available: () => true, verify: () => { higherRan = true; return { tier: 1, name: "brain", decision: "pass", reason: "brain says fine", sound: false, certainty: 1 }; } };
  const cascade = new VerificationCascade([t0, t1], alwaysEscalate);
  const out = await cascade.run(item());
  assert.equal(out.finalDecision, "fail", "sound fail stands");
  assert.equal(higherRan, false, "no higher tier can un-block a sound fail");
});

// ── Single-model graceful degradation ───────────────────────────────────────

test("INVARIANT: with no external brain, the cascade skips Tier 2 cleanly (single-model)", async () => {
  const t0 = tier(0, "floor", true, "undecided", 0.5); // floor can't decide
  const t1 = tier(1, "single-brain", false, "pass", 0.9); // single brain resolves
  const t2 = new ExternalBrainTier(undefined); // NOT available
  const cascade = new VerificationCascade([t0, t1, t2, new HumanTier()], neverEscalate);
  const out = await cascade.run(item());
  assert.equal(out.finalDecision, "pass", "single brain resolved it");
  assert.equal(out.decidedAtTier, 1);
  assert.ok(!out.trail.some((r) => r.tier === 2), "Tier 2 skipped cleanly (not available)");
});

test("with an external brain, a marginal residual escalates to Tier 2", async () => {
  const t0 = tier(0, "floor", true, "undecided", 0.5);
  const t1 = tier(1, "single-brain", false, "pass", 0.3); // low certainty → marginal, climbs
  const t2 = new ExternalBrainTier<unknown>(() => ({ decision: "fail", reason: "independent brain caught it", certainty: 0.95 }));
  // threshold 0.7: 0.3 (Tier 1) climbs, 0.95 (Tier 2) is accepted (not over-escalated to human)
  const policy = new ConfidenceEscalationPolicy({ certaintyThreshold: 0.7 });
  const cascade = new VerificationCascade([t0, t1, t2, new HumanTier()], policy);
  const out = await cascade.run(item());
  assert.equal(out.decidedAtTier, 2, "escalated to the external brain");
  assert.equal(out.finalDecision, "fail");
});

// ── Pre-routing ─────────────────────────────────────────────────────────────

test("INVARIANT: pre-route skips cheap FUZZY tiers but NEVER the sound floor (a sound gate can't be routed past)", async () => {
  let floorRan = false, brainRan = false;
  const t0: VerificationTier = { tier: 0, name: "floor", sound: true, available: () => true, verify: () => { floorRan = true; return { tier: 0, name: "floor", decision: "undecided", reason: "", sound: true, certainty: 0.5 }; } };
  const t1: VerificationTier = { tier: 1, name: "brain", sound: false, available: () => true, verify: () => { brainRan = true; return { tier: 1, name: "brain", decision: "pass", reason: "", sound: false, certainty: 1 }; } };
  const t2 = new ExternalBrainTier<unknown>(() => ({ decision: "pass", reason: "strong brain", certainty: 0.95 }));
  const policy = new ConfidenceEscalationPolicy({ preRouter: complexityPreRouter(() => "complex") });
  const cascade = new VerificationCascade([t0, t1, t2, new HumanTier()], policy);
  const out = await cascade.run(item());
  assert.equal(floorRan, true, "the SOUND floor ALWAYS runs — a policy cannot pre-route past a sound gate");
  assert.equal(brainRan, false, "the cheap fuzzy single-brain IS skipped (pre-routed)");
  assert.equal(out.decidedAtTier, 2, "the floor was undecided, then it went straight to Tier 2 (skipping the cheap brain)");
});

// ── Confidence-driven escalation ────────────────────────────────────────────

test("low-certainty fuzzy verdict escalates; high-certainty does not", async () => {
  const policy = new ConfidenceEscalationPolicy({ certaintyThreshold: 0.7 });
  const mk = (certainty: number) => {
    const t1 = tier(1, "brain", false, "pass", certainty);
    const t2 = new ExternalBrainTier<unknown>(() => ({ decision: "fail", reason: "2nd brain", certainty: 0.9 }));
    return new VerificationCascade([t1, t2, new HumanTier()], policy);
  };
  const lowConf = await mk(0.4).run(item());
  assert.equal(lowConf.decidedAtTier, 2, "low certainty climbed for a second opinion");
  const highConf = await mk(0.95).run(item());
  assert.equal(highConf.decidedAtTier, 1, "high certainty accepted without climbing");
});

// ── Intra-tier consensus (CascadeDebate refinement) ─────────────────────────

test("intra-tier consensus resolves a majority before escalating", () => {
  const c = intraTierConsensus([
    { decision: "pass", certainty: 0.8 },
    { decision: "pass", certainty: 0.7 },
    { decision: "fail", certainty: 0.6 },
  ]);
  assert.equal(c.decision, "pass");
  assert.equal(c.unanimous, false);
  assert.ok(Math.abs(c.certainty - 2 / 3) < 1e-9, "certainty = fraction agreeing");
});

// ── Unresolved → human ──────────────────────────────────────────────────────

test("INVARIANT: an item no tier can decide escalates to the human", async () => {
  const t0 = tier(0, "floor", true, "undecided", 0.5);
  const t1 = tier(1, "brain", false, "undecided", 0.5);
  const cascade = new VerificationCascade([t0, t1, new HumanTier()], alwaysEscalate);
  const out = await cascade.run(item());
  assert.equal(out.finalDecision, "escalate-human");
  assert.equal(out.decidedAtTier, 3);
});

// ── LogicVet floor integration ──────────────────────────────────────────────

test("INVARIANT: LogicVet floor tier FAILS a plan with a dependency cycle (sound, short-circuits)", async () => {
  const cyclePlan: Plan = {
    goal: "g",
    steps: [
      { id: "a", description: "a", dependsOn: ["b"] },
      { id: "b", description: "b", dependsOn: ["a"] },
    ],
  };
  const payload: PlanVetPayload = { plan: cyclePlan, constraints: {}, posture: "strict" };
  const tiers = logicVettingTiers(
    () => ({ decision: "pass", reason: "brain would pass it", certainty: 1 }), // brain says fine...
    undefined,
  );
  const cascade = new VerificationCascade<PlanVetPayload>(tiers, new ConfidenceEscalationPolicy());
  const out = await cascade.run({ id: "p1", kind: "plan", payload });
  assert.equal(out.finalDecision, "fail", "sound floor caught the cycle");
  assert.equal(out.decidedAtTier, 0, "...and the brain never got to overturn it");
});

test("LogicVet floor PASSES a clean plan straight through (no brain needed)", async () => {
  const cleanPlan: Plan = {
    goal: "g",
    steps: [
      { id: "a", description: "a", dependsOn: [] },
      { id: "b", description: "b", dependsOn: ["a"] },
    ],
  };
  const payload: PlanVetPayload = { plan: cleanPlan, constraints: { maxSteps: 5 }, posture: "strict" };
  let brainRan = false;
  const tiers = logicVettingTiers(() => { brainRan = true; return { decision: "pass", reason: "", certainty: 1 }; });
  const cascade = new VerificationCascade<PlanVetPayload>(tiers, new ConfidenceEscalationPolicy());
  const out = await cascade.run({ id: "p2", kind: "plan", payload });
  assert.equal(out.finalDecision, "pass");
  assert.equal(out.decidedAtTier, 0);
  assert.equal(brainRan, false, "clean plan decided by the sound floor — no brain spend");
});
