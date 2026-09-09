import { test } from "node:test";
import assert from "node:assert/strict";

import { verificationConfidence, type VerificationSignals } from "../src/routing/verification_confidence.js";
import { composeGate, defaultGatePolicy, type GateInputs } from "../src/gate/composed_gate.js";

// a baseline gate input that would otherwise auto-proceed (reversible, all clear)
const clearBase: GateInputs = {
  floor: "reversible-execute",
  budget: "within-budget",
  actionTier: "reversible-internal",
  ownerPresent: true,
};
const sig = (over: Partial<VerificationSignals> = {}): VerificationSignals => ({
  deterministicPass: true, stable: true, crossFamilyAgreement: true, hadIndependentVerifier: true, ...over,
});

test("VERIFY-CONFIDENCE (a): a high-confidence passing result flows through without escalation", () => {
  const vc = verificationConfidence(sig());
  assert.equal(vc.band, "high");
  // even on an irreversible action, a high-confidence result adds no confidence veto (other rules still apply)
  const r = composeGate({ ...clearBase, verification: { signals: sig(), consequence: "irreversible" } }, defaultGatePolicy());
  assert.ok(!r.reasons.some((x) => x.includes("low-verification-confidence")), "high confidence → no confidence veto");
});

test("VERIFY-CONFIDENCE (b): a passing-but-flaky-adjacent result on a high-consequence change is escalated", () => {
  const flaky = sig({ stable: false, hadIndependentVerifier: false, crossFamilyAgreement: false }); // 0.5 → low
  assert.equal(verificationConfidence(flaky).band, "low");
  const r = composeGate({ ...clearBase, verification: { signals: flaky, consequence: "irreversible" } }, defaultGatePolicy());
  assert.equal(r.route, "human-hold", "low confidence on a consequential change escalates");
  assert.ok(r.reasons.some((x) => x.includes("low-verification-confidence-on-consequential-action")));
});

test("VERIFY-CONFIDENCE (c): confidence never overrides the deterministic floor (a fail is confidence 0)", () => {
  const failed = sig({ deterministicPass: false }); // stable + agreement true, but deterministic FAILED
  const vc = verificationConfidence(failed);
  assert.equal(vc.score, 0, "soft signals cannot lift a hard deterministic fail");
  assert.equal(vc.band, "low");
  const r = composeGate({ ...clearBase, verification: { signals: failed, consequence: "irreversible" } }, defaultGatePolicy());
  assert.ok(r.reasons.some((x) => x.includes("low-verification-confidence")), "a deterministic fail escalates regardless of soft signals");
});

test("VERIFY-CONFIDENCE (d): confidence is a transparent function of the named signals (reported, not fabricated)", () => {
  const vc = verificationConfidence(sig({ crossFamilyAgreement: false }));
  assert.ok(vc.reasons.some((r) => r.includes("deterministic pass")), "deterministic contribution named");
  assert.ok(vc.reasons.some((r) => r.includes("rerun-stable")), "stability contribution named");
  assert.ok(vc.reasons.some((r) => r.includes("did NOT agree")), "cross-family disagreement named");
  assert.equal(vc.score, 0.75, "0.5 + 0.25 stable + 0 (no agreement) = 0.75 — a transparent sum");
});

test("VERIFY-CONFIDENCE (e): the n=1 default (no independent verifier) accepts a clean pass without over-escalating", () => {
  const n1 = sig({ hadIndependentVerifier: false, crossFamilyAgreement: false }); // 0.5+0.25 = 0.75 → medium
  const vc = verificationConfidence(n1);
  assert.equal(vc.band, "medium", "a clean deterministic-only pass is medium, not low");
  const r = composeGate({ ...clearBase, verification: { signals: n1, consequence: "reversible" } }, defaultGatePolicy());
  assert.equal(r.route, "auto-proceed", "n=1 clean pass on a reversible action flows through — no over-escalation");
  assert.ok(!r.reasons.some((x) => x.includes("low-verification-confidence")));
});

test("VERIFY-CONFIDENCE (additive): low confidence on a REVERSIBLE action does not add a confidence veto", () => {
  const flaky = sig({ stable: false, hadIndependentVerifier: false, crossFamilyAgreement: false });
  const r = composeGate({ ...clearBase, verification: { signals: flaky, consequence: "reversible" } }, defaultGatePolicy());
  assert.ok(!r.reasons.some((x) => x.includes("low-verification-confidence")), "confidence veto only fires on consequential actions");
});

test("VERIFY-CONFIDENCE (no-op): absent verification input is a no-op (behavior preserved)", () => {
  const r = composeGate({ ...clearBase }, defaultGatePolicy());
  assert.equal(r.route, "auto-proceed", "no verification input → unchanged behavior");
});
