import { test } from "node:test";
import assert from "node:assert/strict";
import { VerificationCascade, type VerificationTier, type EscalationPolicy, type TierResult, type TierDecision } from "../src/cascade/verification_cascade.js";

function tierOf(tier: number, sound: boolean, decision: TierDecision, name = `t${tier}`): VerificationTier {
  return {
    tier, name, sound,
    available: () => true,
    verify: (): TierResult => ({ tier, name, decision, reason: `${name}:${decision}`, sound, certainty: sound ? 1 : 0.9 }),
  };
}
const preRouteTo = (t: number): EscalationPolicy => ({ shouldEscalate: () => true, preRoute: () => t });
const item = { id: "x", kind: "artifact", payload: {} };

// ── THE SAFETY HOLE: pre-routing past the sound floor would let a fuzzy tier clear a sound-failing patch ──
test("CASCADE ADVERSARIAL: pre-routing can NOT skip the SOUND floor — a sound fail still blocks", async () => {
  // Floor (tier 0, sound) FAILS; a fuzzy tier-1 PASSES. A policy pre-routes straight to tier 1.
  const cascade = new VerificationCascade(
    [tierOf(0, true, "fail", "sound-floor"), tierOf(1, false, "pass", "fuzzy-brain")],
    preRouteTo(1),
  );
  const out = await cascade.run(item);
  assert.equal(out.finalDecision, "fail", "the sound floor must run and block even when a policy pre-routes past it");
  assert.equal(out.decidedAtTier, 0, "the floor decided");
});

test("CASCADE ADVERSARIAL: a sound PASS at the floor is authoritative even under pre-route (no fuzzy override needed)", async () => {
  const cascade = new VerificationCascade(
    [tierOf(0, true, "pass", "sound-floor"), tierOf(1, false, "fail", "fuzzy-brain")],
    preRouteTo(1),
  );
  const out = await cascade.run(item);
  assert.equal(out.finalDecision, "pass", "a sound floor pass is not overturned by a fuzzy tier reached via pre-route");
});

// ── Pre-routing STILL works for its real purpose: skipping cheap FUZZY tiers when the floor is undecided ──
test("CASCADE: pre-route still skips fuzzy tiers below the target when the floor is UNDECIDED", async () => {
  // Floor undecided → climb. Pre-route target = tier 2, so the fuzzy tier-1 should be skipped, landing on tier 2.
  const cascade = new VerificationCascade(
    [tierOf(0, true, "undecided", "sound-floor"), tierOf(1, false, "pass", "cheap-brain"), tierOf(2, false, "fail", "strong-brain")],
    preRouteTo(2),
  );
  const out = await cascade.run(item);
  assert.equal(out.finalDecision, "fail", "landed on the pre-routed strong brain, skipping the cheap one");
  assert.equal(out.decidedAtTier, 2);
  assert.ok(!out.trail.some((t) => t.tier === 1), "the cheap fuzzy tier was skipped by pre-route");
  assert.ok(out.trail.some((t) => t.tier === 0), "but the sound floor still ran first");
});
