import { test } from "node:test";
import assert from "node:assert/strict";

import { composeGate, defaultGatePolicy, type GateInputs } from "../src/gate/composed_gate.js";

// Build Step 2 — the composed gate (deny-overrides two-path routing). These prove any single
// cautious input forces human-hold, nothing overrides a veto, and owner-absent holds the
// irreversible class. Verify by disproof.

const policy = defaultGatePolicy();

// The one all-green combination that auto-proceeds.
const allGreen: GateInputs = {
  floor: "reversible-execute",
  budget: "within-budget",
  actionTier: "reversible-internal",
  ownerPresent: true,
};

test("GATE: reversible-execute + within-budget + reversible tier + owner present → auto-proceed", () => {
  assert.equal(composeGate(allGreen, policy).route, "auto-proceed");
});

test("GATE: a floor GATE verdict forces human-hold", () => {
  const r = composeGate({ ...allGreen, floor: "gate" }, policy);
  assert.equal(r.route, "human-hold");
  assert.ok(r.reasons.includes("floor-gate"));
});

test("GATE: a budget EXCEEDED verdict forces human-hold", () => {
  const r = composeGate({ ...allGreen, budget: "exceeded" }, policy);
  assert.equal(r.route, "human-hold");
  assert.ok(r.reasons.includes("budget-exceeded"));
});

test("GATE: an irreversible action holds even with everything else green", () => {
  const r = composeGate({ ...allGreen, actionTier: "irreversible" }, policy);
  assert.equal(r.route, "human-hold");
  assert.ok(r.reasons.some((x) => x.startsWith("non-auto-tier") || x === "owner-absent-irreversible-hold"));
});

test("GATE: external-touching is not auto (holds)", () => {
  const r = composeGate({ ...allGreen, actionTier: "external-touching" }, policy);
  assert.equal(r.route, "human-hold");
  assert.ok(r.reasons.includes("non-auto-tier:external-touching"));
});

test("GATE: owner-absent + irreversible → HOLD (positive authorization required)", () => {
  const r = composeGate({ ...allGreen, actionTier: "irreversible", ownerPresent: false }, policy);
  assert.equal(r.route, "human-hold");
  assert.ok(r.reasons.includes("owner-absent-irreversible-hold"));
});

test("GATE: a veto is ABSOLUTE — a single gate cannot be overridden by other green inputs", () => {
  // Even with budget within, tier reversible, owner present, a floor gate alone holds.
  const r = composeGate({ floor: "gate", budget: "within-budget", actionTier: "reversible-internal", ownerPresent: true }, policy);
  assert.equal(r.route, "human-hold", "no combination of green inputs overrides a single veto");
});

test("GATE: unknown/missing inputs fail safe → human-hold (deny-unless-permit)", () => {
  const cases: GateInputs[] = [
    { floor: undefined, budget: "within-budget", actionTier: "reversible-internal", ownerPresent: true },
    { floor: "reversible-execute", budget: undefined, actionTier: "reversible-internal", ownerPresent: true },
    { floor: "reversible-execute", budget: "within-budget", actionTier: undefined, ownerPresent: true },
  ];
  for (const c of cases) {
    assert.equal(composeGate(c, policy).route, "human-hold", `unknown input must hold: ${JSON.stringify(c)}`);
  }
});

test("GATE: is pure — deterministic on frozen input", () => {
  const frozen = Object.freeze({ ...allGreen });
  assert.deepEqual(composeGate(frozen, policy), composeGate(frozen, policy));
});
