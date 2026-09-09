import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { RollbackLedger } from "../src/control/rollback.js";

import { decideTraining, type TrainingSignals } from "../src/autotrain/training_decision.js";
import {
  TrainingLoop,
  generateConfig,
  usesVerifiableReward,
  type TrainerBackend,
  type TrainingStepSnapshot,
} from "../src/autotrain/training_loop.js";
import {
  permissionFor,
  buildPermissionRequest,
  explainTrainingDecision,
  type PermissionContext,
} from "../src/autotrain/permission.js";
import { AutoTrainer, type AutoTrainRequest } from "../src/autotrain/auto_trainer.js";
import { AdapterRegistry, type LoraAdapter, type SessionAuthorization } from "../src/lora/adapter_tier.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-at-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

const NOW = 1_000_000;

// Fully-qualified signals (a case where training SHOULD happen).
function goodSignals(over: Partial<TrainingSignals> = {}): TrainingSignals {
  return {
    recurringFailureMode: true, occurrences: 12, gradientFreeTried: true, residualFailureRate: 0.3,
    verifiedExampleCount: 800, verifiableRewardAvailable: true, estimatedTargetGain: 0.2, narrowStableTask: true,
    ...over,
  };
}

// ── Decision policy: usually says no ────────────────────────────────────────

test("INVARIANT: no recurring failure mode → gradient-free (nothing to train)", () => {
  const d = decideTraining(goodSignals({ recurringFailureMode: false }));
  assert.equal(d.shouldTrain, false);
  assert.equal(d.recommendation, "gradient-free");
});

test("INVARIANT: broad/general task → gradient-free (training is the wrong tool)", () => {
  const d = decideTraining(goodSignals({ narrowStableTask: false }));
  assert.equal(d.recommendation, "gradient-free");
});

test("INVARIANT: cheaper fixes not tried yet → gradient-free first (~90% solved there)", () => {
  const d = decideTraining(goodSignals({ gradientFreeTried: false }));
  assert.equal(d.recommendation, "gradient-free");
  assert.match(d.rationale, /cheaper|prompt|retrieval/i);
});

test("INVARIANT: gradient-free already good enough (low residual) → don't train", () => {
  const d = decideTraining(goodSignals({ residualFailureRate: 0.05 }));
  assert.equal(d.shouldTrain, false);
});

test("INVARIANT: no verifiable reward → refuse to train (can't train safely)", () => {
  const d = decideTraining(goodSignals({ verifiableRewardAvailable: false }));
  assert.equal(d.recommendation, "no-verifiable-reward");
  assert.equal(d.shouldTrain, false);
});

test("INVARIANT: insufficient verified data → don't train yet", () => {
  const d = decideTraining(goodSignals({ verifiedExampleCount: 100 }));
  assert.equal(d.recommendation, "insufficient-data");
});

test("INVARIANT: gain below the lifecycle-cost bar → not worth it", () => {
  const d = decideTraining(goodSignals({ estimatedTargetGain: 0.03 }));
  assert.equal(d.recommendation, "not-worth-it");
});

test("INVARIANT: a fully-qualified case → TRAIN, with a plain-language rationale", () => {
  const d = decideTraining(goodSignals());
  assert.equal(d.shouldTrain, true);
  assert.equal(d.recommendation, "train");
  assert.ok(d.rationale.length > 40, "rationale is explanatory, not a code");
});

// ── Training loop: actually trains, aborts on reward-hacking ─────────────────

function backend(steps: TrainingStepSnapshot[]): TrainerBackend {
  return {
    name: "fake-unsloth",
    async train(_config, _data, onStep) {
      let last = steps[0]!;
      for (const s of steps) {
        last = s;
        if (onStep(s) === "abort") return { adapterRef: "sb://ad", steps: s.step, final: s };
      }
      return { adapterRef: "sb://ad", steps: last.step, final: last };
    },
  };
}

test("usesVerifiableReward: only GRPO", () => {
  assert.equal(usesVerifiableReward("grpo"), true);
  assert.equal(usesVerifiableReward("sft"), false);
});

test("INVARIANT: training loop refuses a non-verifiable method", async () => {
  const loop = new TrainingLoop(backend([{ step: 1, reward: 0.5, heldOutSignal: 0.9 }]));
  const cfg = { ...generateConfig("llama-8b", "unit-tests"), method: "sft" as const };
  const r = await loop.run(cfg, []);
  assert.equal(r.completed, false);
  assert.match(r.abortedReason ?? "", /not verifiable/);
});

test("INVARIANT: training loop ABORTS on reward-hacking (held-out collapses while reward climbs)", async () => {
  // reward rises 0.5→0.9, but held-out collapses 0.95→0.80 (>0.10 drop)
  const steps: TrainingStepSnapshot[] = [
    { step: 1, reward: 0.5, heldOutSignal: 0.95 },
    { step: 2, reward: 0.7, heldOutSignal: 0.92 },
    { step: 3, reward: 0.9, heldOutSignal: 0.80 },
  ];
  const loop = new TrainingLoop(backend(steps));
  const r = await loop.run(generateConfig("llama-8b", "unit-tests"), []);
  assert.equal(r.completed, false);
  assert.match(r.abortedReason ?? "", /reward-hacking|over-optimization/);
});

test("INVARIANT: training loop reports honestly when the backend is offline", async () => {
  const offline: TrainerBackend = { name: "offline", async train() { return null; } };
  const loop = new TrainingLoop(offline);
  const r = await loop.run(generateConfig("llama-8b", "unit-tests"), []);
  assert.equal(r.completed, false);
  assert.match(r.abortedReason ?? "", /unavailable|offline/);
});

test("training loop completes a healthy run", async () => {
  const steps: TrainingStepSnapshot[] = [
    { step: 1, reward: 0.5, heldOutSignal: 0.95 },
    { step: 2, reward: 0.7, heldOutSignal: 0.95 },
    { step: 3, reward: 0.85, heldOutSignal: 0.96 },
  ];
  const loop = new TrainingLoop(backend(steps));
  const r = await loop.run(generateConfig("llama-8b", "unit-tests"), []);
  assert.equal(r.completed, true);
  assert.ok(r.adapterRef);
});

test("generateConfig always produces a safe config (GRPO, QLoRA, safety-preserving, replay, sandboxed)", () => {
  const c = generateConfig("llama-8b", "unit-tests");
  assert.equal(c.method, "grpo");
  assert.equal(c.peft, "qlora");
  assert.equal(c.safetyPreserving, true);
  assert.ok(c.replayFraction >= 0.1);
  assert.equal(c.sandboxed, true);
});

// ── Permission layer ────────────────────────────────────────────────────────

function ctx(over: Partial<PermissionContext> = {}): PermissionContext {
  return { standingAuthorization: true, firstOfItsKind: false, estimatedCostUsd: 0.5, wouldAutoPromote: false, ...over };
}

test("INVARIANT: a covered, low-cost, routine run proceeds AUTONOMOUSLY (don't over-ask)", () => {
  const d = decideTraining(goodSignals());
  const p = permissionFor(d, ctx());
  assert.equal(p.mode, "autonomous");
});

test("INVARIANT: first-of-its-kind training ASKS permission", () => {
  const d = decideTraining(goodSignals());
  assert.equal(permissionFor(d, ctx({ firstOfItsKind: true })).mode, "ask-permission");
});

test("INVARIANT: no standing authorization ASKS permission", () => {
  const d = decideTraining(goodSignals());
  assert.equal(permissionFor(d, ctx({ standingAuthorization: false })).mode, "ask-permission");
});

test("INVARIANT: cost over the autonomous ceiling ASKS permission", () => {
  const d = decideTraining(goodSignals());
  assert.equal(permissionFor(d, ctx({ estimatedCostUsd: 50 })).mode, "ask-permission");
});

test("INVARIANT: promotion past canary ALWAYS asks (never autonomous)", () => {
  const d = decideTraining(goodSignals());
  assert.equal(permissionFor(d, ctx({ wouldAutoPromote: true })).mode, "ask-permission");
});

test("buildPermissionRequest produces a plain-language ask a non-engineer can read", () => {
  const d = decideTraining(goodSignals());
  const req = buildPermissionRequest(d, { capability: "handling async errors", baseModel: "llama-8b", exampleCount: 800, estimatedCostUsd: 1.2, estimatedGainPct: 20 });
  assert.match(req.what, /I'd like to train/);
  assert.match(req.involves, /sandboxed|won't touch the base model/);
  assert.match(req.risksAndSafeguards, /safety|canary|undo/i);
  assert.match(req.ask, /permission|yes|no/i);
});

test("explainTrainingDecision renders a non-training decision in plain language", () => {
  const d = decideTraining(goodSignals({ recurringFailureMode: false }));
  const e = explainTrainingDecision(d);
  assert.match(e, /don't train/);
});

// ── AutoTrainer orchestrator: full pipeline ─────────────────────────────────

function autoTrainerDeps(spine: Spine, trainSteps: TrainingStepSnapshot[]) {
  const registry = new AdapterRegistry(spine);
  registry.enableTier("lisa", "opt-in");
  const rollback = new RollbackLedger(spine);
  const harness = {
    evaluate: (ids: readonly string[]) => ids.length === 0 ? { capability: 0.8, safety: 0.95 } : { capability: 0.85, safety: 0.96 },
    redTeamComposed: () => ({ attackSuccessRate: 0, probesRun: 50 }),
  };
  const buildAdapter = (_run: any, req: AutoTrainRequest): LoraAdapter => ({
    id: "trained-1", version: 1, targetSignature: req.capability, rewardKind: "unit-tests",
    provenance: { exampleCount: req.signals.verifiedExampleCount, untrustedFraction: 0, allScreened: true, backdoorProbed: true },
    weightsRef: "sb://trained-1", status: "candidate", createdTs: NOW,
  });
  return {
    spine,
    trainingLoop: new TrainingLoop(backend(trainSteps)),
    deployDeps: { registry, harness, rollback, spine, canaryDeploy: async (_a: LoraAdapter) => ({ undo: async () => {} }), clock: () => NOW },
    buildAdapter,
    clock: () => NOW,
  };
}

function autoReq(over: Partial<AutoTrainRequest> = {}): AutoTrainRequest {
  const auth: SessionAuthorization = { sessionId: "s", operator: "lisa", authorizedAdapterId: "trained-1", grantedTs: NOW, expiresTs: NOW + 600_000 };
  return {
    capability: "handling async errors", baseModel: "llama-8b", signals: goodSignals(),
    verifierKind: "unit-tests", trainingData: [{ input: "x", reference: "y" }],
    permissionCtx: ctx(), auth, estimatedCostUsd: 0.5, ...over,
  };
}

test("INVARIANT: AutoTrainer does NOT train when the decision says gradient-free", async () => {
  const spine = newSpine();
  const at = new AutoTrainer(autoTrainerDeps(spine, [{ step: 1, reward: 0.9, heldOutSignal: 0.95 }]));
  const out = await at.run(autoReq({ signals: goodSignals({ recurringFailureMode: false }) }));
  assert.equal(out.stage, "decision");
  assert.equal(out.decision.shouldTrain, false);
  assert.match(out.summary, /Not training/);
});

test("INVARIANT: AutoTrainer ASKS permission (and does not train) for a first-of-its-kind run", async () => {
  const spine = newSpine();
  const at = new AutoTrainer(autoTrainerDeps(spine, [{ step: 1, reward: 0.9, heldOutSignal: 0.95 }]));
  const out = await at.run(autoReq({ permissionCtx: ctx({ firstOfItsKind: true }) }));
  assert.equal(out.stage, "awaiting-permission");
  assert.ok(out.permissionRequest, "a plain-language permission request is produced");
  assert.match(out.permissionRequest!.what, /I'd like to train/);
});

test("INVARIANT: AutoTrainer runs the FULL pipeline to a canary when authorized + healthy", async () => {
  const spine = newSpine();
  const at = new AutoTrainer(autoTrainerDeps(spine, [
    { step: 1, reward: 0.5, heldOutSignal: 0.95 },
    { step: 2, reward: 0.85, heldOutSignal: 0.96 },
  ]));
  const out = await at.run(autoReq());
  assert.equal(out.stage, "done", out.summary);
  assert.equal(out.deploy!.deployed, true);
  assert.equal(out.deploy!.stageReached, "canary");
  assert.match(out.summary, /canary|trial/i);
});

test("INVARIANT: AutoTrainer aborts safely (no deploy) if training reward-hacks", async () => {
  const spine = newSpine();
  const at = new AutoTrainer(autoTrainerDeps(spine, [
    { step: 1, reward: 0.5, heldOutSignal: 0.95 },
    { step: 2, reward: 0.9, heldOutSignal: 0.78 }, // held-out collapse
  ]));
  const out = await at.run(autoReq());
  assert.equal(out.stage, "training-aborted");
  assert.equal(out.deploy, undefined, "nothing deployed after an aborted training run");
});
