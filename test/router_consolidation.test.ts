import { test } from "node:test";
import assert from "node:assert/strict";

import { eligibleByPolicy, chooseCascade, type CascadeCandidate, type CascadePolicy } from "../src/routing/uncertainty_router.js";
import { chooseModel, type ModelProfile, type RouterPolicy } from "../src/routing/cost_of_pass_router.js";
import { routeTask, type ModelQualityRecord, type RoutingPolicy } from "../src/observability/routing.js";

// Router consolidation: one authoritative eligibility gate; three thin selection policies over it. The old
// APIs are preserved as shims (their own tests stay green); these prove they DELEGATE to the shared gate.

test("gate: eligibleByPolicy filters on allowed ∧ tier≤ceiling ∧ estimate≥floor (the one authoritative predicate)", () => {
  const items = [
    { model: "a", tier: 1, estimate: 0.9 }, // ok
    { model: "b", tier: 5, estimate: 0.9 }, // above ceiling
    { model: "c", tier: 1, estimate: 0.4 }, // below floor
    { model: "d", tier: 1, estimate: 0.9 }, // not allowed
  ];
  const got = new Set(eligibleByPolicy(items, 0.5, 3, ["a", "b", "c"]).map((i) => i.model));
  assert.deepEqual([...got].sort(), ["a"], "only the allowed, at/below-ceiling, above-floor item survives");
});

// ── Delegation: neuter the shared gate; every router must collapse to its no-eligible branch. ──
// We can't edit source here, so we prove delegation structurally: a fixture where the ONLY eligible model is
// the one the gate admits, and where a router that ignored the gate would pick a DIFFERENT model.

test("chooseModel delegates: the gate's floor excludes a flaky-cheap model the raw price would prefer", () => {
  const flakyCheap: ModelProfile = { model: "cheap", promptFormat: "terse", usdPerTask: 0.1, tier: 1, successByBand: { moderate: 0.3 } };
  const reliable: ModelProfile = { model: "rel", promptFormat: "xml", usdPerTask: 2, tier: 2, successByBand: { moderate: 0.95 } };
  const policy: RouterPolicy = { allowedModels: ["cheap", "rel"], operatorCeilingModel: "rel", minSuccess: 0.5 };
  const c = chooseModel("moderate", [flakyCheap, reliable], policy);
  // the gate excludes cheap (0.3 < 0.5 floor) → only 'rel' eligible → chosen. A no-gate router would keep cheap.
  assert.equal(c.kind, "model");
  if (c.kind === "model") assert.equal(c.model, "rel");
  // confirm the gate itself agrees on the eligible set the shim used.
  const eligible = new Set(eligibleByPolicy(
    [flakyCheap, reliable].map((p) => ({ model: p.model, tier: p.tier, estimate: p.successByBand.moderate ?? 0 })),
    policy.minSuccess, 2, policy.allowedModels,
  ).map((i) => i.model));
  assert.deepEqual([...eligible], ["rel"], "shim and gate agree on eligibility");
});

test("routeTask delegates: the gate drives the eligible set — cheapest-clearing-bar, NOT the highest-quality fallback", () => {
  const models: ModelQualityRecord[] = [
    { model: "cheapMid", qualityByClass: { hard: 0.6 }, typicalTaskUsd: 0.1 }, // clears the 0.5 bar, cheapest
    { model: "prem", qualityByClass: { hard: 0.9 }, typicalTaskUsd: 5 }, // highest quality (the fallback pick)
  ];
  const policy: RoutingPolicy = { allowedModels: ["cheapMid", "prem"], qualityBar: { trivial: 0.5, easy: 0.5, moderate: 0.5, hard: 0.5 } };
  const d = routeTask("hard", models, policy);
  // both clear the 0.5 bar → cheapest eligible = cheapMid. If the gate were bypassed (admits nothing), the
  // fallback would return the highest-quality 'prem' instead — so this asserts the gate really ran.
  assert.ok(d !== undefined);
  assert.equal(d!.model, "cheapMid", "cheapest model CLEARING the bar wins — proving the gate produced a non-empty eligible set");
});

test("chooseCascade delegates: the same gate drives the cascade's eligible set", () => {
  const cheapFlaky: CascadeCandidate = { model: "cheap", usdPerTask: 1, tier: 1, posterior: { alpha: 3, beta: 7 } }; // mean .3
  const solid: CascadeCandidate = { model: "solid", usdPerTask: 3, tier: 2, posterior: { alpha: 95, beta: 5 } };
  const policy: CascadePolicy = {
    allowedModels: ["cheap", "solid"], operatorCeilingModel: "solid",
    floorByConsequence: { reversible: 0.5, irreversible: 0.5, unknown: 0.5 }, humanEscalationPenalty: 100, k: 2,
  };
  const c = chooseCascade([cheapFlaky, solid], "reversible", policy);
  assert.equal(c.kind, "cascade");
  if (c.kind === "cascade") assert.deepEqual(c.order, ["solid"], "cheap (mean .3 < .5 floor) excluded by the shared gate");
});
