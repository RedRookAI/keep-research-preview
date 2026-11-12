/**
 * Experimental training orchestration: decision, permission and an external backend call.
 *
 * The backend reports progress and completion; a requested configuration does not prove that it
 * screened the supplied examples, used a sandbox or mixed replay data. Its current result contract
 * carries no evidence for those properties. Consequently this automatic route preserves the run
 * result but refuses candidate construction and deployment. The separate adapter deploy gates
 * remain available to callers with their own admitted evidence and human authorization.
 */

import type { Spine } from "../spine/spine.js";
import { decideTraining, type TrainingSignals, type TrainingDecisionOptions, type TrainingDecision } from "./training_decision.js";
import { permissionFor, buildPermissionRequest, type PermissionContext, type PermissionOptions, type PermissionDecision, type PermissionRequest } from "./permission.js";
import { TrainingLoop, generateConfig, type TrainingRunResult } from "./training_loop.js";
import type { DeployDecision, DeployDeps } from "../lora/deploy_orchestrator.js";
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
  /** Legacy candidate factory; not invoked while this route lacks training evidence. */
  readonly buildAdapter?: (run: TrainingRunResult, req: AutoTrainRequest) => LoraAdapter | Promise<LoraAdapter>;
  readonly clock?: () => number;
}

export class AutoTrainer {
  constructor(private readonly deps: AutoTrainerDeps) {}

  /**
   * Run the auto-train pipeline for one capability gap. Returns an outcome at whatever stage it
   * reaches: a declined decision, a permission wait, an aborted backend run or an explicit
   * missing-evidence deployment refusal. Backend completion alone cannot admit an adapter.
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

    // 3. Request training and monitor backend-supplied progress. Configuration is not attestation.
    const config = generateConfig(req.baseModel, req.verifierKind);
    spine.stage({ type: "identity.action", actor: "autotrain", payload: { event: "training_started", capability: req.capability, method: config.method, sandboxRequested: config.sandboxed } });
    const training = await this.deps.trainingLoop.run(config, req.trainingData);
    if (!training.completed) {
      spine.stage({ type: "identity.action", actor: "autotrain", payload: { event: "training_aborted", capability: req.capability, reason: training.abortedReason } });
      return { stage: "training-aborted", decision, permission, training, summary: `The training run was not accepted as completed: ${training.abortedReason}. Nothing was deployed.` };
    }

    // The current port returns a weights handle and metrics, without data/sandbox/replay evidence.
    // Refuse before invoking any candidate factory or registering trusted provenance.
    const deploy: DeployDecision = {
      deployed: false,
      stageReached: "rejected",
      reason: "automatic deployment unavailable: the backend contract supplies no verified training-data screening/trust, sandbox or replay evidence",
    };
    spine.stage({ type: "identity.action", actor: "autotrain", payload: { event: "training_evidence_missing", capability: req.capability, reason: deploy.reason } });
    return {
      stage: "deploy", decision, permission, training, deploy,
      summary: `The backend reported a completed training run for "${req.capability}". No adapter was registered or deployed: ${deploy.reason}.`,
    };
  }
}
