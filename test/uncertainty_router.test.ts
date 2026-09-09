import { test } from "node:test";
import assert from "node:assert/strict";

import {
  priorPosterior,
  posteriorMean,
  successLCB,
  successUCB,
  decisionSuccess,
  updatePosterior,
  expectedCascadeCost,
  chooseCascade,
  type SuccessPosterior,
  type CascadeCandidate,
  type CascadePolicy,
} from "../src/routing/uncertainty_router.js";

// Red-team hardening: uncertainty-aware (Beta posterior), consequence-scaled (LCB pessimism on irreversible),
// cascade-cost (FrugalGPT objective) routing. Deterministic + auditable. Verify by disproof.

const confident = (succ: number, fail: number): SuccessPosterior => ({ alpha: 1 + succ, beta: 1 + fail });

test("posterior: mean matches Beta expectation; cold-start prior is uniform 0.5 (not an arbitrary magic 0.5 point)", () => {
  assert.equal(posteriorMean(priorPosterior()), 0.5); // Beta(1,1) mean, principled
  assert.ok(Math.abs(posteriorMean(confident(9, 1)) - 10 / 12) < 1e-9);
});

test("posterior: update + decay move the estimate and retain sample count (Beta, not EWMA)", () => {
  const after = updatePosterior(confident(5, 5), false); // one more failure
  assert.ok(posteriorMean(after) < posteriorMean(confident(5, 5)), "a failure lowers the mean");
  const decayed = updatePosterior(confident(50, 50), true, 0.5); // decay down-weights old counts
  assert.ok(decayed.alpha < 50 + 1, "decay shrinks the retained count (non-stationarity)");
});

test("LCB: uncertainty cuts the decision estimate DOWN — few samples ⇒ much lower bound than many", () => {
  const fewSamples = confident(3, 0); // Beta(4,1), mean 0.8 but wide
  const manySamples = confident(399, 99); // Beta(400,100), mean 0.8 but tight
  assert.ok(Math.abs(posteriorMean(fewSamples) - posteriorMean(manySamples)) < 1e-6, "same mean");
  assert.ok(successLCB(fewSamples) < successLCB(manySamples), "the uncertain one has a lower confidence bound");
  // optimism (UCB) is the mirror of pessimism (LCB): UCB >= mean >= LCB, and wider for the uncertain one.
  assert.ok(successUCB(fewSamples) > posteriorMean(fewSamples) && posteriorMean(fewSamples) > successLCB(fewSamples));
  assert.ok(successUCB(fewSamples) - successLCB(fewSamples) > successUCB(manySamples) - successLCB(manySamples), "the uncertain interval is wider");
});

test("consequence: irreversible uses the pessimistic LCB; reversible uses the mean (safety-aligned)", () => {
  const p = confident(3, 1); // wide
  assert.equal(decisionSuccess(p, "reversible"), posteriorMean(p), "reversible ⇒ mean (exploration is safe)");
  assert.ok(decisionSuccess(p, "irreversible") < posteriorMean(p), "irreversible ⇒ LCB (pessimism)");
  assert.equal(decisionSuccess(p, "irreversible"), successLCB(p));
});

test("consequence floor: an uncertain model is ELIGIBLE on a reversible task but REJECTED on an irreversible one", () => {
  const uncertain: CascadeCandidate = { model: "cheap", usdPerTask: 1, tier: 1, posterior: confident(3, 1) }; // mean .8, LCB low
  const solid: CascadeCandidate = { model: "ceiling", usdPerTask: 5, tier: 3, posterior: confident(90, 10) };
  const policy: CascadePolicy = {
    allowedModels: ["cheap", "ceiling"], operatorCeilingModel: "ceiling",
    floorByConsequence: { reversible: 0.6, irreversible: 0.75, unknown: 0.75 }, humanEscalationPenalty: 100, k: 2,
  };
  const rev = chooseCascade([uncertain, solid], "reversible", policy);
  assert.equal(rev.kind, "cascade");
  if (rev.kind === "cascade") assert.ok(rev.order.includes("cheap"), "reversible: the uncertain cheap model is eligible");

  const irr = chooseCascade([uncertain, solid], "irreversible", policy);
  assert.equal(irr.kind, "cascade");
  if (irr.kind === "cascade") assert.ok(!irr.order.includes("cheap"), "irreversible: the uncertain cheap model is rejected by the LCB floor");
});

test("cascade cost (F1): the escalation term is PROBABILITY-WEIGHTED — a reliable first model escalates less, so costs less", () => {
  const rest: CascadeCandidate = { model: "rest", usdPerTask: 10, tier: 3, posterior: confident(90, 10) };
  const reliableFirst: CascadeCandidate = { model: "relf", usdPerTask: 1, tier: 1, posterior: confident(95, 5) }; // p≈.95
  const flakyFirst: CascadeCandidate = { model: "flakyf", usdPerTask: 1, tier: 1, posterior: confident(20, 80) }; // p≈.2
  const costReliableFirst = expectedCascadeCost([reliableFirst, rest], "reversible", 100);
  const costFlakyFirst = expectedCascadeCost([flakyFirst, rest], "reversible", 100);
  // both pay the same $1 first; the flaky one escalates ~0.8 of the time vs ~0.05 → strictly more expensive.
  assert.ok(costFlakyFirst > costReliableFirst, "the (1-p)·escalation term makes the flaky first model cost more");
  // and the reliable-first cost is well below the always-escalate sum (1 + 10 + 100), proving the weighting.
  assert.ok(costReliableFirst < 1 + 10 + 100, "escalation is discounted by the first model's success probability");
});

test("cascade: chooseCascade never exceeds the operator ceiling tier (raise-only)", () => {
  const frontier: CascadeCandidate = { model: "frontier", usdPerTask: 0.5, tier: 9, posterior: confident(99, 1) };
  const ceiling: CascadeCandidate = { model: "ceiling", usdPerTask: 3, tier: 3, posterior: confident(90, 10) };
  const policy: CascadePolicy = {
    allowedModels: ["frontier", "ceiling"], operatorCeilingModel: "ceiling",
    floorByConsequence: { reversible: 0.5, irreversible: 0.7, unknown: 0.7 }, humanEscalationPenalty: 100, k: 2,
  };
  const c = chooseCascade([frontier, ceiling], "reversible", policy);
  assert.equal(c.kind, "cascade");
  if (c.kind === "cascade") assert.ok(!c.order.includes("frontier"), "never route above the operator ceiling even if cheaper");
});

test("cascade: unknown operator ceiling ⇒ escalate-human (fail-safe); no eligible model ⇒ escalate-human", () => {
  const only: CascadeCandidate = { model: "m", usdPerTask: 1, tier: 1, posterior: confident(1, 9) }; // mean .18
  const policy: CascadePolicy = {
    allowedModels: ["m"], operatorCeilingModel: "ghost",
    floorByConsequence: { reversible: 0.5, irreversible: 0.9, unknown: 0.9 }, humanEscalationPenalty: 100, k: 2,
  };
  assert.equal(chooseCascade([only], "reversible", policy).kind, "escalate-human"); // unknown ceiling
  const policy2: CascadePolicy = { ...policy, operatorCeilingModel: "m" };
  assert.equal(chooseCascade([only], "irreversible", policy2).kind, "escalate-human"); // .18 < 0.9 floor
});
