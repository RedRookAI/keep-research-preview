import { test } from "node:test";
import assert from "node:assert/strict";

import {
  criticalityScore,
  autonomyProfileFor,
  shouldProceedInReversibleBand,
  AutonomyCalibration,
  atLeastAsAutonomous,
  type AutonomyLevel,
} from "../src/frontdoor/autonomy_profile.js";

// --- AUTONOMY PRESERVED: level genuinely reduces asking in the reversible band ---

test("higher autonomy level lowers the confidence bar (asks less) in the reversible band", () => {
  const observer = autonomyProfileFor("observer", "bind_channel");
  const delegator = autonomyProfileFor("delegator", "bind_channel");
  assert.ok(delegator.reversibleConfidenceThreshold < observer.reversibleConfidenceThreshold);
});

test("a delegator proceeds where an observer asks, for the same low-risk action", () => {
  const lowCrit = 0.2;
  const midConfidence = 0.6;
  const observer = shouldProceedInReversibleBand(autonomyProfileFor("observer", "bind_channel"), lowCrit, midConfidence);
  const delegator = shouldProceedInReversibleBand(autonomyProfileFor("delegator", "bind_channel"), lowCrit, midConfidence);
  assert.equal(observer.proceed, false); // observer wants to be asked
  assert.equal(delegator.proceed, true); // delegator lets it flow
});

test("calibration learns: repeated approvals of a class make Keep ask less over time", () => {
  const cal = new AutonomyCalibration();
  const before = autonomyProfileFor("collaborator", "bind_channel", cal).reversibleConfidenceThreshold;
  for (let i = 0; i < 8; i++) cal.record("bind_channel", true); // operator keeps approving
  const after = autonomyProfileFor("collaborator", "bind_channel", cal).reversibleConfidenceThreshold;
  assert.ok(after < before); // lower bar => asks less
});

test("calibration also learns the other way: a pushed-back class makes Keep ask MORE", () => {
  const cal = new AutonomyCalibration();
  const before = autonomyProfileFor("collaborator", "request_file_access", cal).reversibleConfidenceThreshold;
  for (let i = 0; i < 6; i++) cal.record("request_file_access", false); // operator keeps denying
  const after = autonomyProfileFor("collaborator", "request_file_access", cal).reversibleConfidenceThreshold;
  assert.ok(after > before); // higher bar => asks more
});

test("calibration needs a minimum sample before nudging (no over-fitting one click)", () => {
  const cal = new AutonomyCalibration();
  cal.record("bind_channel", true);
  cal.record("bind_channel", true); // only 2 — below threshold
  assert.equal(cal.adjustmentFor("bind_channel"), 0);
});

// --- SAFETY PRESERVED: the ceiling no level can cross ---

test("high criticality ALWAYS asks, even for a delegator (the safety ceiling)", () => {
  const highCrit = 0.8;
  const fullConfidence = 1.0;
  const delegator = shouldProceedInReversibleBand(autonomyProfileFor("delegator", "bind_channel"), highCrit, fullConfidence);
  assert.equal(delegator.proceed, false); // even max autonomy + full confidence asks when consequential
  assert.ok(/consequential|check with you/i.test(delegator.reason));
});

test("the criticality score weights irreversibility highest", () => {
  const irreversible = criticalityScore({ irreversibility: 1, rollbackCost: 0, scope: 0, novelty: 0 });
  const novel = criticalityScore({ irreversibility: 0, rollbackCost: 0, scope: 0, novelty: 1 });
  assert.ok(irreversible > novel); // 0.4 vs 0.1
});

test("calibration adjustment is bounded (can't run away and erase the floor)", () => {
  const cal = new AutonomyCalibration();
  for (let i = 0; i < 1000; i++) cal.record("bind_channel", true);
  assert.ok(cal.adjustmentFor("bind_channel") <= 0.2); // hard cap
});

test("even with max calibration + max level, the threshold never goes to zero", () => {
  const cal = new AutonomyCalibration();
  for (let i = 0; i < 1000; i++) cal.record("bind_channel", true);
  const profile = autonomyProfileFor("delegator", "bind_channel", cal);
  assert.ok(profile.reversibleConfidenceThreshold > 0); // a floor remains
});

// --- Basics ---

test("criticality score composes and clamps to [0,1]", () => {
  const mid = criticalityScore({ irreversibility: 0.5, rollbackCost: 0.5, scope: 0.5, novelty: 0.5 });
  assert.ok(mid > 0 && mid <= 1);
});

test("level ordering is monotonic", () => {
  assert.ok(atLeastAsAutonomous("delegator", "observer"));
  assert.ok(!atLeastAsAutonomous("observer", "delegator"));
  assert.ok(atLeastAsAutonomous("collaborator", "collaborator"));
});
