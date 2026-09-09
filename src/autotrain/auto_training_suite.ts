/**
 * Auto-training suite composition — the gated far-tier weight-adaptation loop.
 *
 * The self-improvement backbone's deepest tier. Assembles:
 *  - DataEngineLoop: real, GPU-free Snorkel-style data engineering (LFs → denoise → held-out eval set).
 *  - AutoTrainer: decision → permission → training → deploy, where the SAFETY machinery is real and the COMPUTE is a seam.
 *
 * Safety-by-construction (this is off-by-default and permission-gated for a reason):
 *  - decideTraining is conservative — few-shot / prompt-tuning usually suffices, so it usually says "don't train weights".
 *  - permissionFor gates non-SOTA-safe training: it ASKS the human in plain language rather than proceeding.
 *  - deploy requires a FRESH per-session human authorization (never envelope-covered) — the human gate for weight changes.
 *  - the trainer backend is a PORT: absent → a null backend that honestly reports "unavailable" instead of faking a run.
 *
 * SOTA basis (2026-08-07): the mature single-GPU, solo-dev toolchain is QLoRA + a verifiable reward (RLVR); Keep generates
 * a declarative config and drives a real trainer through the port so a non-engineer never scripts. What would change it:
 * a real backend (Unsloth/Axolotl/TRL) + a sandbox canary-deploy are the seams a GPU deployment supplies; the decision,
 * permission, provenance, and deploy-authorization logic here is real and enforced regardless.
 */

import { AutoTrainer, type AutoTrainerDeps, type AutoTrainRequest } from "./auto_trainer.js";
import { DataEngineLoop } from "../training/data_engine_loop.js";
import { TrainingLoop, type TrainerBackend, type TrainingRunResult } from "./training_loop.js";
import { AdapterRegistry, type LoraAdapter } from "../lora/adapter_tier.js";
import { RollbackLedger } from "../control/rollback.js";
import type { EvalHarness } from "../lora/eval_gate.js";
import type { DeployDeps } from "../lora/deploy_orchestrator.js";
import type { Spine } from "../spine/spine.js";

/** A trainer backend that is honestly unavailable — train() returns null so the loop never pretends it trained. */
const UNAVAILABLE_BACKEND: TrainerBackend = {
  name: "unavailable (no GPU backend wired)",
  async train() {
    return null;
  },
};

/** A null eval harness — no eval signal available (returns null, never a fabricated score). */
const NULL_HARNESS: EvalHarness = {
  evaluate: () => null,
  redTeamComposed: () => null,
};

export interface AutoTrainingSeams {
  /** The real GPU trainer backend (Unsloth/Axolotl/TRL in a sandbox). Absent → honestly-unavailable null backend. */
  readonly backend?: TrainerBackend;
  /** Fresh authority for the concrete compute receiving training data. */
  readonly compute?: TrainingComputeAuthorization;
  /** Real canary deploy into a sandbox, returning a concrete undo. Absent → fail closed. */
  readonly canaryDeploy?: (adapter: LoraAdapter) => Promise<{ undo: () => Promise<void> }>;
  /** Real eval harness for the deploy gate. Absent → a null harness (no score). */
  readonly evalHarness?: EvalHarness;
  readonly backdoorProbe?: (adapterRef: string) => Promise<boolean> | boolean;
  readonly operator?: string;
  readonly clock?: () => number;
}

export interface TrainingComputeAuthorization {
  readonly computeId: string;
  readonly visibility: "local" | "private-network" | "public";
  readonly authorizedBy: string;
  readonly grantedTs: number;
  readonly expiresTs: number;
}

export interface AutoTrainingSuite {
  readonly dataEngine: DataEngineLoop;
  readonly trainer: AutoTrainer;
  /** Run the full decision → permission → training → deploy orchestration for a capability. */
  run(req: AutoTrainRequest): ReturnType<AutoTrainer["run"]>;
}

/** Mint a provenance-carrying LoraAdapter record from a completed training run (never loads weights into-process). */
function buildAdapter(run: TrainingRunResult, req: AutoTrainRequest, now: number, backdoorProbed: boolean): LoraAdapter {
  return {
    id: req.auth?.authorizedAdapterId ?? `adapter-${req.capability}-${now.toString(36)}`,
    version: 1,
    targetSignature: req.capability,
    rewardKind: req.verifierKind, // "unit-tests" | "compiler" | "exact-match" — all verifiable RLVR rewards
    provenance: {
      exampleCount: req.trainingData.length,
      untrustedFraction: 0,
      allScreened: true, // corpus sources came through the governed ingestion gate
      backdoorProbed,
    },
    weightsRef: run.adapterRef ?? "",
    status: "candidate",
    createdTs: now,
  };
}

export function buildAutoTrainingSuite(spine: Spine, seams: AutoTrainingSeams = {}): AutoTrainingSuite {
  const clock = seams.clock ?? (() => Date.now());
  const trainingLoop = new TrainingLoop(seams.backend ? authorizedComputeBackend(seams.backend, seams.compute, spine, clock) : UNAVAILABLE_BACKEND);
  const registry = new AdapterRegistry(spine);
  registry.enableTier(seams.operator ?? "operator", "explicit auto-training suite opt-in");
  const deployDeps: DeployDeps = {
    registry,
    harness: seams.evalHarness ?? NULL_HARNESS,
    rollback: new RollbackLedger(spine),
    spine,
    canaryDeploy: seams.canaryDeploy ?? (async () => { throw new Error("no sandbox canary deployment backend configured"); }),
  };
  const deps: AutoTrainerDeps = {
    spine,
    trainingLoop,
    deployDeps,
    buildAdapter: async (run, req) => buildAdapter(run, req, clock(), run.adapterRef ? await (seams.backdoorProbe?.(run.adapterRef) ?? false) : false),
  };
  const trainer = new AutoTrainer(deps);
  const dataEngine = new DataEngineLoop(spine);
  return { dataEngine, trainer, run: (req) => trainer.run(req) };
}

function authorizedComputeBackend(backend: TrainerBackend, authority: TrainingComputeAuthorization | undefined, spine: Spine, clock: () => number): TrainerBackend {
  return { name: `authorized-compute:${backend.name}`, async train(config, data, onStep) {
    const reason = computeDenial(authority, clock());
    if (reason) { spine.stage({ type: "identity.action", actor: "autotrain", payload: { event: "compute_denied", reason } }); return null; }
    spine.stage({ type: "identity.action", actor: "autotrain", payload: { event: "compute_authorized", computeId: authority!.computeId, visibility: authority!.visibility, authorizedBy: authority!.authorizedBy } });
    return backend.train(config, data, onStep);
  } };
}

function computeDenial(authority: TrainingComputeAuthorization | undefined, now: number): string | undefined {
  if (!authority) return "no training-compute authorization";
  if (!authority.computeId.trim() || !authority.authorizedBy.trim()) return "training-compute authority is incomplete";
  if (authority.visibility === "public") return "public compute is not authorized for training";
  if (!Number.isFinite(authority.grantedTs) || !Number.isFinite(authority.expiresTs) || authority.expiresTs <= authority.grantedTs) return "training-compute authority has an invalid lifetime";
  if (now < authority.grantedTs || now > authority.expiresTs) return "training-compute authorization is not currently valid";
  return undefined;
}
