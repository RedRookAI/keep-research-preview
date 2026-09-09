import { test } from "node:test";
import assert from "node:assert/strict";

import { runSelfImprovementCycle, type SelfImprovementDeps } from "../src/learning/self_improvement_loop.js";
import type { TrainingSignals } from "../src/autotrain/training_decision.js";
import { ShadowModeGate, type RegressionCase } from "../src/learning/shadow_mode.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function spine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-sil-"))), new InProcessLock(), new SchemaRegistry());
}

// A held-out corpus: a candidate "passes" only if it does NOT advocate skipping the security review.
const corpus: RegressionCase[] = [
  { id: "no-skip-security", passesUnder: (c) => !/skip.*security/i.test(c) },
];

// A gap that gradient-free can fix (narrow but training NOT warranted → gradient-free / skill).
const gapSignals: TrainingSignals = {
  recurringFailureMode: true, occurrences: 12, gradientFreeTried: false, residualFailureRate: 0.4,
  verifiedExampleCount: 20, verifiableRewardAvailable: true, estimatedTargetGain: 0.05, narrowStableTask: true,
};

// A gap where training IS warranted (all disqualifiers cleared).
const trainSignals: TrainingSignals = {
  recurringFailureMode: true, occurrences: 200, gradientFreeTried: true, residualFailureRate: 0.4,
  verifiedExampleCount: 5000, verifiableRewardAvailable: true, estimatedTargetGain: 0.3, narrowStableTask: true,
};

function deps(over: Partial<SelfImprovementDeps> = {}): SelfImprovementDeps {
  return { enabled: true, shadow: new ShadowModeGate(spine(), corpus), ...over };
}

test("M6 RECOGNIZE→PROMOTE: a recognized gap + a clean candidate is implemented and promoted", () => {
  const out = runSelfImprovementCycle(gapSignals, deps({ candidate: { id: "s1", content: "always run the security review before merge" } }));
  assert.equal(out.recognizedGap, true, "the gap is recognized");
  assert.ok(out.plannedAction, "a fix is planned");
  assert.equal(out.implemented, true, "it is implemented (shadow-tested)");
  assert.equal(out.promoted, true, "a clean candidate is promoted");
});

test("M6 SHADOW GUARD: a bad improvement is caught and reverted, never promoted", () => {
  const out = runSelfImprovementCycle(gapSignals, deps({ candidate: { id: "bad", content: "skip the security review to merge faster" } }));
  assert.equal(out.implemented, true, "it reached the shadow gate");
  assert.equal(out.reverted, true, "the bad improvement is reverted");
  assert.equal(out.promoted, false, "it is NOT promoted (system uncorrupted)");
});

test("M6 OFF BY DEFAULT: the loop does not run unless explicitly enabled (n=1 never forced on)", () => {
  const out = runSelfImprovementCycle(gapSignals, { shadow: new ShadowModeGate(spine(), corpus), candidate: { id: "s", content: "x" } });
  assert.equal(out.ran, false, "disabled by default");
  assert.equal(out.promoted, false, "nothing promoted while disabled");
});

test("M6 TRAINING IS STAGED, NEVER SILENT: a train-warranted case stages for the operator, does not promote", () => {
  const out = runSelfImprovementCycle(trainSignals, deps({ candidate: { id: "s", content: "x" } }));
  assert.equal(out.plannedAction, "stage-training", "training is the planned action");
  assert.equal(out.stagedTrainingOnly, true, "it is STAGED for operator-authorized compute (seam S-10)");
  assert.equal(out.promoted, false, "the loop does not silently train + promote");
});
