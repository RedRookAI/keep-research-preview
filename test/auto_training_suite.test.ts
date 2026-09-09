import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { buildAutoTrainingSuite, type TrainingComputeAuthorization } from "../src/autotrain/auto_training_suite.js";
import type { AutoTrainRequest } from "../src/autotrain/auto_trainer.js";
import type { TrainingSignals } from "../src/autotrain/training_decision.js";
import type { PermissionContext } from "../src/autotrain/permission.js";
import type { TrainerBackend } from "../src/autotrain/training_loop.js";
import type { EvalHarness } from "../src/lora/eval_gate.js";
import type { SessionAuthorization } from "../src/lora/adapter_tier.js";

function newSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-at-"))), new InProcessLock(), new SchemaRegistry());
}

const WEAK: TrainingSignals = {
  recurringFailureMode: false, occurrences: 0, gradientFreeTried: false, residualFailureRate: 0,
  verifiedExampleCount: 0, verifiableRewardAvailable: false, estimatedTargetGain: 0, narrowStableTask: false,
};
const STRONG: TrainingSignals = {
  recurringFailureMode: true, occurrences: 12, gradientFreeTried: true, residualFailureRate: 0.5,
  verifiedExampleCount: 600, verifiableRewardAvailable: true, estimatedTargetGain: 0.4, narrowStableTask: true,
};
const ASK_CTX: PermissionContext = { standingAuthorization: false, firstOfItsKind: true, estimatedCostUsd: 0, wouldAutoPromote: false };
const AUTON_CTX: PermissionContext = { standingAuthorization: true, firstOfItsKind: false, estimatedCostUsd: 0, wouldAutoPromote: false };
function privateCompute(now = Date.now()): TrainingComputeAuthorization { return { computeId: "gpu-local-1", visibility: "local", authorizedBy: "operator", grantedTs: now - 1_000, expiresTs: now + 60_000 }; }

function req(signals: TrainingSignals, ctx: PermissionContext, over: Partial<AutoTrainRequest> = {}): AutoTrainRequest {
  return {
    capability: "sql-generation", baseModel: "base-7b", signals, verifierKind: "unit-tests",
    trainingData: [{ input: "a", reference: "b" }], permissionCtx: ctx, auth: undefined,
    estimatedCostUsd: 0, ...over,
  };
}

test("SAFETY (decision usually says no): weak signals → the decision policy declines to train", async () => {
  const suite = buildAutoTrainingSuite(newSpine());
  const out = await suite.run(req(WEAK, AUTON_CTX));
  assert.equal(out.decision.shouldTrain, false, "no measured, gradient-free-resistant failure → don't train weights");
  assert.notEqual(out.stage, "done");
  assert.notEqual(out.stage, "training");
});

test("SAFETY (permission gate): a genuine train case that is first-of-its-kind ASKS the human, does not proceed", async () => {
  const suite = buildAutoTrainingSuite(newSpine());
  const out = await suite.run(req(STRONG, ASK_CTX, { permissionGranted: false }));
  assert.equal(out.stage, "awaiting-permission", "it paused to ask before training");
  assert.ok(out.permissionRequest, "a plain-language permission request is surfaced to the operator");
  assert.equal(out.training, undefined, "nothing was trained while awaiting permission");
});

test("SAFETY (no fake training): with no GPU backend wired, an authorized run aborts HONESTLY — nothing deployed", async () => {
  const suite = buildAutoTrainingSuite(newSpine()); // default backend = unavailable (train → null)
  const out = await suite.run(req(STRONG, AUTON_CTX));
  assert.notEqual(out.stage, "done", "no deploy happened");
  assert.ok(out.training && out.training.completed === false, "training reported not-completed rather than a fabricated success");
});

test("SAFETY (deploy needs a fresh session authorization): even a COMPLETED run is not deployed without auth + a passing gauntlet", async () => {
  // A backend that reports a clean, completed run — but no eval harness and no session auth are supplied.
  const completingBackend: TrainerBackend = {
    name: "test-backend",
    async train(_config, _data, onStep) {
      onStep({ step: 1, reward: 0.9, heldOutSignal: 0.9 });
      return { adapterRef: "weights://trained", steps: 1, final: { step: 1, reward: 0.9, heldOutSignal: 0.9 } };
    },
  };
  const suite = buildAutoTrainingSuite(newSpine(), { backend: completingBackend, compute: privateCompute() });
  const out = await suite.run(req(STRONG, AUTON_CTX, { auth: undefined }));
  assert.notEqual(out.stage, "done", "training completed but deploy did NOT clear without auth + eval");
  assert.ok(out.deploy ? out.deploy.deployed === false : true, "the adapter was not deployed");
});

test("explicit opt-in trains, probes, evaluates, composes, and deploys a reversible sandbox canary", async () => {
  const backend: TrainerBackend = { name: "private-local-test-backend", async train(_config, _data, onStep) { onStep({ step: 1, reward: 0.9, heldOutSignal: 0.95 }); return { adapterRef: "sandbox://trained", steps: 1, final: { step: 1, reward: 0.9, heldOutSignal: 0.95 } }; } };
  const harness: EvalHarness = { evaluate: (ids) => ids.length === 0 ? { capability: 0.8, safety: 0.96 } : { capability: 0.86, safety: 0.97 }, redTeamComposed: () => ({ attackSuccessRate: 0, probesRun: 50 }) };
  const now = Date.now(); const adapterId = "authorized-local-adapter"; let deployed = 0;
  const auth: SessionAuthorization = { sessionId: "session-1", operator: "operator", authorizedAdapterId: adapterId, grantedTs: now, expiresTs: now + 60_000 };
  const suite = buildAutoTrainingSuite(newSpine(), { backend, compute: privateCompute(now), evalHarness: harness, backdoorProbe: (ref) => ref === "sandbox://trained", canaryDeploy: async (adapter) => { assert.equal(adapter.id, adapterId); deployed++; return { undo: async () => {} }; } });
  const out = await suite.run(req(STRONG, AUTON_CTX, { auth }));
  assert.equal(out.stage, "done", out.summary);
  assert.equal(out.deploy?.stageReached, "canary");
  assert.equal(deployed, 1);
  assert.ok(out.deploy?.canaryRollbackId);
});

test("missing, public, and expired compute authority never invokes the trainer backend", async () => {
  let calls = 0; const backend: TrainerBackend = { name: "must-not-run", async train() { calls++; return { adapterRef: "forbidden", steps: 1, final: { step: 1, reward: 1, heldOutSignal: 1 } }; } };
  const now = Date.now(); const authorities: Array<TrainingComputeAuthorization | undefined> = [undefined, { ...privateCompute(now), visibility: "public" }, { ...privateCompute(now), grantedTs: now - 2_000, expiresTs: now - 1_000 }];
  for (const compute of authorities) {
    const out = await buildAutoTrainingSuite(newSpine(), { backend, ...(compute ? { compute } : {}), clock: () => now }).run(req(STRONG, AUTON_CTX));
    assert.equal(out.stage, "training-aborted");
  }
  assert.equal(calls, 0);
});

test("WIRE: auto-training is OFF by default and present only when opted in", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const off = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-at-off-")) });
  assert.equal(off.autoTraining, undefined, "no auto-training capability unless explicitly enabled (safety default)");
  const on = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-at-on-")), autoTraining: {} });
  assert.ok(on.autoTraining, "opting in composes the suite");
  assert.ok(on.autoTraining!.dataEngine && on.autoTraining!.trainer, "data engine + trainer both present");
});
