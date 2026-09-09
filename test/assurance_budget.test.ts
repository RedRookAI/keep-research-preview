import { test } from "node:test";
import assert from "node:assert/strict";

import { trustReport, assuranceBudgetAdvice, type TrustEvidence, type AssuranceBudgetInput } from "../src/audit/decision_audit.js";

// evidence that yields a given assurance level
const atL2: TrustEvidence = { deterministicPass: true, sealValid: true };                       // L2
const atL4: TrustEvidence = { deterministicPass: true, sealValid: true, attesterLive: true, signatureValid: true, signatureGuarantee: "keyed-integrity" }; // L4
const mk = (current: TrustEvidence, ifEsc: TrustEvidence, cost: number, consequence: AssuranceBudgetInput["consequence"]): AssuranceBudgetInput =>
  ({ current: trustReport(current), ifEscalated: trustReport(ifEsc), escalationCost: cost, consequence });

test("ASSURANCE-BUDGET (a): escalation that raises assurance (or resolves the gap) is advised worthwhile", () => {
  const r = assuranceBudgetAdvice(mk(atL2, atL4, 0.05, "reversible")); // L2 → L4
  assert.equal(r.advice, "escalate-worthwhile");
  assert.equal(r.assuranceGain, 2);
  assert.equal(r.resolvesCappingGap, true, "escalation lifts past the L2 cap");
});

test("ASSURANCE-BUDGET (b): paying more for the same-or-lower assurance is flagged low-value", () => {
  const r = assuranceBudgetAdvice(mk(atL4, atL4, 0.10, "reversible")); // L4 → L4, no gain, costs money
  assert.equal(r.advice, "escalate-low-value");
  assert.equal(r.assuranceGain, 0);
});

test("ASSURANCE-BUDGET (c): a consequence-gated escalation is never suppressed to save cost", () => {
  // irreversible action, NO assurance gain, high cost — must STILL be required (cost cannot veto it)
  const r = assuranceBudgetAdvice(mk(atL4, atL4, 999, "irreversible"));
  assert.equal(r.advice, "escalate-required-by-consequence");
  assert.notEqual(r.advice, "escalate-low-value", "cost/low-value never suppresses a needed escalation");
});

test("ASSURANCE-BUDGET (d): advice reflects only REAL assurance signals — never fabricated; assurance ≠ correctness", () => {
  const r = assuranceBudgetAdvice(mk(atL4, atL4, 0.10, "reversible")); // no real gain
  assert.equal(r.assuranceGain, 0, "the gain is the real levelIndex delta, not a fabricated positive");
  assert.equal(r.basis, "assurance-not-correctness", "explicitly weighs assurance, not correctness");
  assert.match(r.reason, /assurance, not correctness/);
  // a real gain is reported as its true magnitude
  assert.equal(assuranceBudgetAdvice(mk(atL2, atL4, 0.05, "reversible")).assuranceGain, 2);
});

test("ASSURANCE-BUDGET (e): advice-only + deterministic — overrides no gate, same inputs → same advice", () => {
  const input = mk(atL2, atL4, 0.05, "reversible");
  const a = assuranceBudgetAdvice(input);
  const b = assuranceBudgetAdvice(input);
  assert.equal(a.overridesGate, false, "never overrides a gate/verdict");
  assert.deepEqual(a, b, "deterministic");
  assert.deepEqual(JSON.parse(JSON.stringify(a)), a, "serializable");
});

test("ASSURANCE-BUDGET (both-tracks): n=1 spend-lean sees low-value; the escalation cost is surfaced for an org ceiling", () => {
  const r = assuranceBudgetAdvice(mk(atL4, atL4, 0.42, "reversible"));
  assert.equal(r.advice, "escalate-low-value", "solo operator: don't pay for no assurance");
  assert.equal(r.escalationCost, 0.42, "the cost is surfaced so an org cost-ceiling policy can stack on top");
});
