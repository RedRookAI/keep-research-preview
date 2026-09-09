/**
 * Auto-Training system: the AutoTrainer orchestrator (Increment 11d).
 *
 * This is the corrected capability: Keep ACTUALLY auto-trains when training genuinely helps, safely
 * and scalably, and explains itself to a non-engineer. It ties the whole pipeline together:
 *
 *   decideTraining (when it helps — usually says no)
 *     → permissionFor (proceed autonomously when SOTA-safe, else ask the human in plain language)
 *       → TrainingLoop (actually trains: GRPO on a verifiable reward, QLoRA, safety-preserving,
 *          reward-hacking-monitored, in a sandbox)
 *         → deployAdapter (the existing safety gauntlet: entry gates → before/after eval →
 *            colluding-LoRA composition check → canary + one-tap rollback)
 *
 * Every stage is auditable (spine) and explainable. The human merge gate stays the owner's: a canary
 * is the most an autonomous run produces; full activation is always a human step. Fail-closed
 * throughout. This REPLACES the earlier refuse-to-train stub. Zero deps.
 */

import type { Spine } from "../spine/spine.js";
import { decideTraining, type TrainingSignals, type TrainingDecisionOptions, type TrainingDecision } from "./training_decision.js";
import { permissionFor, buildPermissionRequest, type PermissionContext, type PermissionOptions, type PermissionDecision, type PermissionRequest } from "./permission.js";
import { TrainingLoop, generateConfig, type TrainingRunResult } from "./training_loop.js";
import { deployAdapter, type DeployRequest, type DeployDecision, type DeployDeps } from "../lora/deploy_orchestrator.js";
import type { LoraAdapter, SessionAuthorization } from "../lora/adapter_tier.js";

export type AutoTrainStage = "decision" | "permission" | "awaiting-permission" | "training" | "training-aborted" | "deploy" | "done";

export interface AutoTrainOutcome {
  readonly stage: AutoTrainStage;
  readonly decision: TrainingDecision;
  readonly permission?: PermissionDecision;
  /** When permission is required, the plain-language request to show the operator. */
  readonly permissionRequest?: PermissionRequest;
  readonly training?: TrainingRunResult;
  readonly deploy?: DeployDecision;
  /** A plain-language summary of what happened + why, for a non-engineer. */
  readonly summary: string;
}

export interface AutoTrainRequest {
  readonly capability: string;
  readonly baseModel: string;
  readonly signals: TrainingSignals;
  readonly verifierKind: "unit-tests" | "compiler" | "exact-match";
  readonly trainingData: readonly { input: string; reference: string }[];
  readonly permissionCtx: PermissionContext;
  /** Fresh per-session human authorization (required to actually deploy — never envelope-covered). */
  readonly auth: SessionAuthorization | undefined;
  /** If the operator has already granted permission this turn (the "yes" to a prior ask). */
  readonly permissionGranted?: boolean;
  readonly estimatedCostUsd: number;
  readonly decisionOpts?: TrainingDecisionOptions;
  readonly permissionOpts?: PermissionOptions;
}

export interface AutoTrainerDeps {
  readonly spine: Spine;
  readonly trainingLoop: TrainingLoop;
  readonly deployDeps: DeployDeps;
  /** Mints the LoraAdapter record from a completed training run (provenance carried from item 8). */
  readonly buildAdapter: (run: TrainingRunResult, req: AutoTrainRequest) => LoraAdapter | Promise<LoraAdapter>;
  readonly clock?: () => number;
}

export class AutoTrainer {
  constructor(private readonly deps: AutoTrainerDeps) {}

  /**
   * Run the auto-train pipeline for one capability gap. Returns an outcome at whatever stage it
   * reaches: a "don't train" decision, an awaiting-permission ask, a training abort, or a deployed
   * canary. Nothing is forced; the human gate holds.
   */
  async run(req: AutoTrainRequest): Promise<AutoTrainOutcome> {
    const { spine } = this.deps;

    // 1. Decision: does training genuinely help? (usually no)
    const decision = decideTraining(req.signals, req.decisionOpts);
    spine.stage({ type: "identity.action", actor: "autotrain", payload: { event: "training_decision", capability: req.capability, recommendation: decision.recommendation } });
    if (!decision.shouldTrain) {
      return { stage: "decision", decision, summary: `Not training for "${req.capability}". ${decision.rationale}` };
    }

    // 2. Permission: autonomous, or ask the human?
    const permission = permissionFor(decision, req.permissionCtx, req.permissionOpts);
    spine.stage({ type: "identity.action", actor: "autotrain", payload: { event: "permission_mode", capability: req.capability, mode: permission.mode } });
    if (permission.mode === "blocked") {
      return { stage: "permission", decision, permission, summary: `Blocked: ${permission.reason}` };
    }
    if (permission.mode === "ask-permission" && !req.permissionGranted) {
      const permissionRequest = buildPermissionRequest(decision, {
        capability: req.capability, baseModel: req.baseModel,
        exampleCount: req.signals.verifiedExampleCount, estimatedCostUsd: req.estimatedCostUsd,
        estimatedGainPct: Math.round(req.signals.estimatedTargetGain * 100),
      });
      spine.stage({ type: "identity.action", actor: "autotrain", payload: { event: "permission_requested", capability: req.capability } });
      return { stage: "awaiting-permission", decision, permission, permissionRequest, summary: `Asking permission before training "${req.capability}": ${permission.reason}` };
    }

    // 3. Train (autonomous, or permission granted). GRPO + QLoRA + safety-preserving, reward-hack-monitored.
    const config = generateConfig(req.baseModel, req.verifierKind);
    spine.stage({ type: "identity.action", actor: "autotrain", payload: { event: "training_started", capability: req.capability, method: config.method, sandboxed: config.sandboxed } });
    const training = await this.deps.trainingLoop.run(config, req.trainingData);
    if (!training.completed) {
      spine.stage({ type: "identity.action", actor: "autotrain", payload: { event: "training_aborted", capability: req.capability, reason: training.abortedReason } });
      return { stage: "training-aborted", decision, permission, training, summary: `Training stopped safely before finishing: ${training.abortedReason}. Nothing was deployed; Keep keeps its current approach.` };
    }

    // 4. Deploy through the FULL safety gauntlet (entry gates → eval → composition → canary).
    const adapter = await this.deps.buildAdapter(training, req);
    const deployReq: DeployRequest = {
      adapter,
      auth: req.auth,
      sandboxed: true,
      replay: { replayFraction: config.replayFraction, attested: true },
    };
    const deploy = await deployAdapter(deployReq, this.deps.deployDeps);
    spine.stage({ type: "identity.action", actor: "autotrain", payload: { event: "deploy_result", capability: req.capability, deployed: deploy.deployed, stage: deploy.stageReached } });

    if (!deploy.deployed) {
      return { stage: "deploy", decision, permission, training, deploy, summary: `Trained successfully, but the safety checks did not clear it: ${deploy.reason}. It was NOT deployed — Keep keeps its current approach.` };
    }
    return {
      stage: "done", decision, permission, training, deploy,
      summary: `Trained and deployed a trial ("canary") adapter for "${req.capability}". It passed the safety and capability checks and the combined-safety check. It's running on a trial basis with one-tap undo; I'll leave full activation to you.`,
    };
  }
}
