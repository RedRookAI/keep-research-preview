import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { composeKeep } from "../src/compose.js";
import type { ModelProfile, RouterPolicy, TaskSignal } from "../src/routing/cost_of_pass_router.js";
import type { CalibrationConfig } from "../src/routing/floor_calibration.js";

// WIRING PROOF (P0-A #2): the budget/routing lever is reachable from the running system + genuinely consulted.

function sb() {
  return composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-br-")) }).secondBrain;
}

// a cheap weaker model + an expensive stronger one, both reliable at easy bands
const CHEAP: ModelProfile = { model: "cheap", promptFormat: "terse", usdPerTask: 0.001, tier: 1, successByBand: { trivial: 0.95, easy: 0.9, moderate: 0.8, hard: 0.6 } };
const STRONG: ModelProfile = { model: "strong", promptFormat: "xml", usdPerTask: 0.05, tier: 3, successByBand: { trivial: 0.99, easy: 0.98, moderate: 0.97, hard: 0.96 } };
const POLICY: RouterPolicy = { allowedModels: ["cheap", "strong"], operatorCeilingModel: "strong", minSuccess: 0.5 };
const trivial: TaskSignal = { inputSize: 100, subGoalCount: 1, reversibilityClass: "reversible", priorFailures: 0 };
const risky: TaskSignal = { inputSize: 100, subGoalCount: 1, reversibilityClass: "irreversible", priorFailures: 0 };
const CAL: { records: []; config: CalibrationConfig } = {
  records: [],
  config: { targetAlphaByConsequence: { reversible: 0.2, irreversible: 0.02, unknown: 0.1 }, fallbackFloorByConsequence: { reversible: 0.5, irreversible: 0.95, unknown: 0.8 } },
};

test("composeKeep exposes the budget/routing lever", () => {
  const s = sb();
  assert.equal(typeof s.route, "function");
  assert.equal(typeof s.routingSavings, "function");
});

test("simple task routes DOWN to the cheaper model (min cost-of-pass)", () => {
  const choice = sb().route(trivial, [CHEAP, STRONG], POLICY);
  assert.equal(choice.kind, "model");
  if (choice.kind === "model") assert.equal(choice.model, "cheap", "a trivial task takes the cheaper eligible model");
});

test("consequential task under the calibrated floor routes UP", () => {
  // irreversible ⇒ calibrated fallback floor 0.95; cheap's easy-band success (0.9) is now BELOW the floor ⇒ ineligible.
  const choice = sb().route(risky, [CHEAP, STRONG], POLICY, CAL);
  assert.equal(choice.kind, "model");
  if (choice.kind === "model") assert.equal(choice.model, "strong", "the calibrated floor forces the higher-reliability model");
});

test("n=1 graceful degradation: a single available model still yields a valid choice", () => {
  const solo: RouterPolicy = { allowedModels: ["cheap"], operatorCeilingModel: "cheap", minSuccess: 0.5 };
  const choice = sb().route(trivial, [CHEAP], solo);
  assert.equal(choice.kind, "model");
  if (choice.kind === "model") assert.equal(choice.model, "cheap", "the solo/free-tier operator still gets a routed choice");
});

test("routingSavings computes measured savings vs a baseline", () => {
  const s = sb().routingSavings(1.0, 0.25);
  assert.equal(s.savedUsd, 0.75);
  assert.equal(s.pct, 75);
});

test("deterministic: same task + profiles + policy ⇒ same choice", () => {
  assert.deepEqual(sb().route(trivial, [CHEAP, STRONG], POLICY), sb().route(trivial, [CHEAP, STRONG], POLICY));
});
