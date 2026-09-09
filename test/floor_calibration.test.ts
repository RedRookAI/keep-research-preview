import { test } from "node:test";
import assert from "node:assert/strict";

import {
  calibrateFloor,
  calibratedFloorByConsequence,
  chooseCascadeCalibrated,
  type CalibrationRecord,
  type CalibrationConfig,
} from "../src/routing/floor_calibration.js";
import type { CascadeCandidate } from "../src/routing/uncertainty_router.js";

// Conformal calibration of the consequence floor (closes F3). The calibration DATA is the SEAM; the procedure
// is BUILT. Verify by disproof.

// A miscalibrated fixture: an optimistic band (p̂≈0.8) that actually FAILS, and a solid band (p̂≈0.95) that
// succeeds. A constant floor of 0.75 admits the failing band; a calibrated floor must raise the bar past it.
function miscalibrated(consequence: "reversible" | "irreversible" | "unknown"): CalibrationRecord[] {
  const recs: CalibrationRecord[] = [];
  for (let i = 0; i < 100; i++) recs.push({ pHat: 0.8, consequence, success: false }); // optimistic failures
  for (let i = 0; i < 400; i++) recs.push({ pHat: 0.95, consequence, success: true }); // solid successes
  return recs;
}

function admittedFailureRate(records: readonly CalibrationRecord[], floor: number): number {
  const admitted = records.filter((r) => r.pHat >= floor);
  if (admitted.length === 0) return 0;
  return admitted.filter((r) => !r.success).length / admitted.length;
}

test("coverage: the calibrated floor holds the admitted failure rate ≤ α where the constant floor does NOT", () => {
  const recs = miscalibrated("irreversible");
  const alpha = 0.1;
  const constantFloor = 0.75;
  const calibrated = calibrateFloor(recs, alpha, "irreversible", constantFloor);

  const constViolation = admittedFailureRate(recs, constantFloor); // admits the 0.8 failing band
  const calCoverage = admittedFailureRate(recs, calibrated); // must exclude it

  assert.ok(constViolation > alpha, "the constant floor admits enough failures to violate α (sanity)");
  assert.ok(calCoverage <= alpha, "the calibrated floor holds admitted failure rate within α");
  assert.ok(calibrated > constantFloor, "calibration raised the bar past the miscalibrated band");
});

test("monotone: a tighter α ⇒ a higher (or equal) calibrated floor", () => {
  const recs = miscalibrated("reversible");
  const strict = calibrateFloor(recs, 0.05, "reversible", 0.5);
  const loose = calibrateFloor(recs, 0.5, "reversible", 0.5);
  assert.ok(strict >= loose, "less tolerated failure ⇒ a higher floor");
  assert.ok(strict > loose, "on this fixture the tighter α is strictly higher");
});

test("fail-safe: empty calibration data ⇒ the conservative constant fallback (degenerate zero-data case)", () => {
  assert.equal(calibrateFloor([], 0.1, "irreversible", 0.9), 0.9);
  // records only for a different class ⇒ still fallback for the queried class.
  const other: CalibrationRecord[] = [{ pHat: 0.99, consequence: "reversible", success: true }];
  assert.equal(calibrateFloor(other, 0.1, "irreversible", 0.85), 0.85);
});

test("consequence: a stricter irreversible α flows through to a floor ≥ the reversible floor", () => {
  const recs = [...miscalibrated("reversible"), ...miscalibrated("irreversible")];
  const config: CalibrationConfig = {
    targetAlphaByConsequence: { reversible: 0.3, irreversible: 0.05, unknown: 0.05 },
    fallbackFloorByConsequence: { reversible: 0.5, irreversible: 0.7, unknown: 0.7 },
  };
  const floors = calibratedFloorByConsequence(recs, config);
  assert.ok(floors.irreversible >= floors.reversible, "the stricter class gets the higher bar");
});

test("consume: chooseCascadeCalibrated derives the floor from records and excludes a model below it", () => {
  const recs = miscalibrated("irreversible");
  const config: CalibrationConfig = {
    targetAlphaByConsequence: { reversible: 0.3, irreversible: 0.1, unknown: 0.1 },
    fallbackFloorByConsequence: { reversible: 0.5, irreversible: 0.75, unknown: 0.75 },
  };
  // a cheap model whose decision-success sits in the miscalibrated band (0.8) must be excluded on irreversible;
  // the ceiling model (high, solid) remains.
  const cheap: CascadeCandidate = { model: "cheap", usdPerTask: 1, tier: 1, posterior: { alpha: 81, beta: 20 } }; // mean ≈0.80
  const ceiling: CascadeCandidate = { model: "ceiling", usdPerTask: 5, tier: 3, posterior: { alpha: 990, beta: 10 } }; // ≈0.99, LCB clears 0.95
  const choice = chooseCascadeCalibrated([cheap, ceiling], "irreversible", recs, config, {
    allowedModels: ["cheap", "ceiling"], operatorCeilingModel: "ceiling", humanEscalationPenalty: 100, k: 2,
  });
  assert.equal(choice.kind, "cascade");
  if (choice.kind === "cascade") assert.ok(!choice.order.includes("cheap"), "the calibrated floor excludes the miscalibrated-band model");
});

test("finite-sample: on THIN evidence the conformal (k+1)/(n+1) correction refuses to certify a low floor", () => {
  // 3 successes at 0.85 and 3 at 0.95 — zero observed failures, but only 6 samples. The RAW empirical rate
  // (0/6 = 0) would happily certify the 0.85 floor at α=0.1; the conformal correction ((0+1)/(6+1)=0.143 > 0.1)
  // will not — it demands more evidence and falls back to the most conservative candidate (0.95).
  const thin: CalibrationRecord[] = [];
  for (let i = 0; i < 3; i++) thin.push({ pHat: 0.85, consequence: "irreversible", success: true });
  for (let i = 0; i < 3; i++) thin.push({ pHat: 0.95, consequence: "irreversible", success: true });
  const floor = calibrateFloor(thin, 0.1, "irreversible", 0.5);
  assert.equal(floor, 0.95, "the conformal correction won't certify 0.85 on 6 samples — it requires the stricter bar");
});
