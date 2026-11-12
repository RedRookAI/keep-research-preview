/**
 * Experimental training composition: data preparation, decision, permission and an external port.
 * The default backend reports unavailable. An injected backend also needs current private-compute
 * authority. Its completed result is retained, but this automatic route cannot construct or deploy
 * a candidate because the port supplies no verified screening, sandbox or replay evidence.
 */

import { AutoTrainer, type AutoTrainerDeps, type AutoTrainRequest } from "./auto_trainer.js";
import { DataEngineLoop } from "../training/data_engine_loop.js";
import { TrainingLoop, type TrainerBackend } from "./training_loop.js";
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
  /** External trainer supplied by the operator; its configuration does not establish isolation. Absent → unavailable. */
  readonly backend?: TrainerBackend;
  /** Fresh authority for the concrete compute receiving training data. */
  readonly compute?: TrainingComputeAuthorization;
  /** Reserved deployment seam; the current automatic route refuses before candidate construction. */
  readonly canaryDeploy?: (adapter: LoraAdapter) => Promise<{ undo: () => Promise<void> }>;
  /** Real eval harness for the deploy gate. Absent → a null harness (no score). */
  readonly evalHarness?: EvalHarness;
  /** Reserved probe seam; currently unused because automatic candidate construction is refused. */
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
  /** Run decision/permission/backend orchestration; missing evidence prevents automatic deployment. */
  run(req: AutoTrainRequest): ReturnType<AutoTrainer["run"]>;
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
