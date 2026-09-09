import { test } from "node:test";
import assert from "node:assert/strict";

import { ConfidenceEscalationPolicy, complexityPreRouter, intraTierConsensus } from "../src/cascade/escalation_policy.js";
import type { TierResult, VerificationItem } from "../src/cascade/verification_cascade.js";

function tier(over: Partial<TierResult> = {}): TierResult {
  return { tier: 1, name: "t1", decision: "pass", reason: "", sound: false, certainty: 1, ...over };
}

test("ESCALATION (budget win): a HIGH-but-imperfect certainty does NOT escalate — the SOTA threshold, not 'any imperfection'", () => {
  const p = new ConfidenceEscalationPolicy({ certaintyThreshold: 0.7 });
  // certainty 0.85 is imperfect but above the bar → the old climb-on-<1 policy would waste a tier here; this one won't.
  assert.equal(p.shouldEscalate([tier({ certainty: 0.85 })], true), false, "did not burn a stronger tier on a confident-enough verdict");
});

test("ESCALATION: a genuinely MARGINAL verdict (below the bar) still climbs", () => {
  const p = new ConfidenceEscalationPolicy({ certaintyThreshold: 0.7 });
  assert.equal(p.shouldEscalate([tier({ certainty: 0.5 })], true), true, "climbed on real marginality");
});

test("ESCALATION: an UNDECIDED verdict climbs (regardless of certainty)", () => {
  const p = new ConfidenceEscalationPolicy();
  assert.equal(p.shouldEscalate([tier({ decision: "undecided", certainty: 0.99 })], true), true);
});

test("ESCALATION (soundness dominates): a SOUND decided verdict is NEVER escalated", () => {
  const p = new ConfidenceEscalationPolicy();
  assert.equal(p.shouldEscalate([tier({ sound: true, decision: "fail", certainty: 0.1 })], true), false, "a deterministic fail is final, never climbed");
});

test("ESCALATION (latency bound): does not climb past the tier ceiling even when marginal", () => {
  const p = new ConfidenceEscalationPolicy({ maxTier: 2 });
  assert.equal(p.shouldEscalate([tier({ tier: 2, certainty: 0.1 })], true), false, "stopped at the ceiling to bound latency");
});

test("ESCALATION: never climbs when no higher tier is available", () => {
  const p = new ConfidenceEscalationPolicy();
  assert.equal(p.shouldEscalate([tier({ certainty: 0 })], false), false);
});

test("PRE-ROUTE: predictably-hard items jump straight to the strong tier, skipping the wasted cheap pass", () => {
  const preRouter = complexityPreRouter((it) => ((it as { c?: string }).c === "complex" ? "complex" : "simple"));
  const p = new ConfidenceEscalationPolicy({ preRouter });
  assert.equal(p.preRoute({ c: "complex" } as unknown as VerificationItem), 2, "hard item pre-routed to Tier 2");
  assert.equal(p.preRoute({ c: "simple" } as unknown as VerificationItem), 0, "easy item starts at the floor");
});

test("INTRA-TIER CONSENSUS: N fuzzy verdicts resolve BEFORE escalating (majority + agreement strength)", () => {
  const c = intraTierConsensus([{ decision: "pass", certainty: 1 }, { decision: "pass", certainty: 1 }, { decision: "fail", certainty: 1 }]);
  assert.equal(c.decision, "pass");
  assert.equal(c.unanimous, false);
  assert.ok(Math.abs(c.certainty - 2 / 3) < 1e-9, "agreement strength = fraction agreeing");
});

test("WIRE: buildHarness defaults to ConfidenceEscalationPolicy when no policy is given", async () => {
  const { buildHarness } = await import("../src/cascade/verification_harness.js");
  // A floor-only harness with no policy must construct (proving the default kicked in, not a required-field throw).
  const cascade = buildHarness({
    floor: { tier: 0, name: "floor", sound: true, available: () => true, verify() { return { tier: 0, name: "floor", decision: "undecided" as const, reason: "", sound: true, certainty: 1 }; } },
    capability: "none",
  });
  assert.ok(cascade, "harness built with the default ConfidenceEscalationPolicy");
});
