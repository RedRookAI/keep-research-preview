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
import { composeKeep } from "../src/compose.js";

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
  return { enabled: true, shadow: new ShadowModeGate(spine(), corpus), safety: new ShadowModeGate(spine(), corpus), ...over };
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

test("candidate promotion requires both configured nonempty evaluations", () => {
  const candidate = { id: "held", content: "run security review" };
  const { safety: _safety, ...withoutSafety } = deps({ candidate });
  const variants: Array<{ config: SelfImprovementDeps; gate: "safety" | "capability"; reason: string }> = [
    { config: withoutSafety, gate: "safety", reason: "missing-gate" },
    { config: deps({ candidate, safety: new ShadowModeGate(spine(), []) }), gate: "safety", reason: "empty-corpus" },
    { config: deps({ candidate, shadow: new ShadowModeGate(spine(), []) }), gate: "capability", reason: "empty-corpus" },
  ];
  for (const { config, gate, reason } of variants) {
    const out = runSelfImprovementCycle(gapSignals, config);
    assert.equal(out.promoted, false);
    assert.equal(out.reverted, false, "missing evidence is not a measured regression");
    assert.equal(out.safetyRegressed, false);
    assert.deepEqual(out.evaluationHold, { gate, reason, evaluatedCases: 0 });
  }
});

test("a completed failing capability check remains a measured regression", () => {
  let safetyCalls = 0, capabilityCalls = 0;
  const out = runSelfImprovementCycle(gapSignals, deps({
    safety: new ShadowModeGate(spine(), [{ id: "safe", passesUnder: () => { safetyCalls++; return true; } }]),
    shadow: new ShadowModeGate(spine(), [{ id: "regression", passesUnder: () => { capabilityCalls++; return false; } }]),
    candidate: { id: "failed-capability", content: "candidate" },
  }));
  assert.equal(out.promoted, false);
  assert.equal(out.reverted, true);
  assert.equal(out.safetyRegressed, false);
  assert.equal(out.evaluationHold, undefined);
  assert.equal(safetyCalls, 1);
  assert.equal(capabilityCalls, 1);
});

test("shadow evidence distinguishes empty, failed, throwing and nonboolean checks", () => {
  const sp = spine();
  const empty = new ShadowModeGate(sp, []).evaluate("empty", "candidate");
  assert.equal(empty.passed, false);
  assert.equal(empty.evaluatedCases, 0);
  assert.equal(empty.unavailableReason, "empty-corpus");
  let revoked = false;
  assert.equal(new ShadowModeGate(sp, []).gate("empty", "candidate", () => { revoked = true; }), false);
  assert.equal(revoked, true, "empty evaluation cannot clear a lesson for use");
  const failed = new ShadowModeGate(sp, [{ id: "fails", passesUnder: () => false }]).evaluate("failed", "candidate");
  assert.equal(failed.evaluatedCases, 1);
  assert.deepEqual(failed.failedCases, ["fails"]);
  assert.equal(failed.unavailableReason, undefined);
  for (const [reason, check] of [
    ["evaluator-error", () => { throw new Error("private diagnostic"); }],
    ["invalid-result", () => "truthy" as unknown as boolean],
  ] as const) {
    const out = runSelfImprovementCycle(gapSignals, deps({
      safety: new ShadowModeGate(sp, [{ id: "check", passesUnder: check }]), candidate: { id: reason, content: "candidate" },
    }));
    assert.equal(out.promoted, false);
    assert.equal(out.evaluationHold?.reason, reason);
    assert.equal(out.safetyRegressed, false);
    assert.doesNotMatch(JSON.stringify(out), /private diagnostic/);
  }
  assert.ok(sp.currentEvents().some(e => e.payload["unavailableReason"] === "empty-corpus" && e.payload["evaluatedCases"] === 0));
});

test("composed self-improvement holds omitted corpora and executes configured controls", () => {
  const candidate = { id: "composed", content: "run security review" };
  const unconfigured = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-empty-eval-")), selfImprovement: { enabled: true } });
  const held = unconfigured.selfImprovement!.runCycle(gapSignals, candidate);
  assert.equal(held.promoted, false);
  assert.deepEqual(held.evaluationHold, { gate: "safety", reason: "empty-corpus", evaluatedCases: 0 });
  let capabilityCases = 0, safetyCases = 0;
  const configured = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-present-eval-")), selfImprovement: {
    enabled: true,
    corpus: [{ id: "capability", passesUnder: () => { capabilityCases++; return true; } }],
    safetyCorpus: [{ id: "safety", passesUnder: () => { safetyCases++; return true; } }],
  } });
  assert.equal(configured.selfImprovement!.runCycle(gapSignals, candidate).promoted, true);
  assert.equal(capabilityCases, 1);
  assert.equal(safetyCases, 1);
  assert.equal(unconfigured.selfImprovement!.runCycle(trainSignals, candidate).stagedTrainingOnly, true);
});
