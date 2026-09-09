/**
 * LoRA tier (Increment 10c) — the deploy orchestrator: full gate chain + canary + rollback.
 *
 * This ties the tier together. A deploy runs an ORDERED, FAIL-CLOSED gate chain — entry gates →
 * before/after eval gate → composition check → canary — and ANY failure rejects the deploy and keeps
 * the current (gradient-free) floor. Nothing is ever force-through. Canary adapters are registered as
 * reversible actions in the existing RollbackLedger, so a bad canary is one-tap rolled back.
 *
 * SOTA basis (2026-08-04): the locked strict spec (master plan §9.A) — sandboxed only, mandatory
 * before/after eval gate, composition check (colluding-LoRA), replay buffer, versioned adapters +
 * canary + rollback, per-session human auth, verifiable rewards only. The orchestrator enforces the
 * ORDER and the fail-closed default. Zero deps.
 */

import type { Spine } from "../spine/spine.js";
import type { RollbackLedger } from "../control/rollback.js";
import {
  AdapterRegistry,
  checkEntryGates,
  type LoraAdapter,
  type SessionAuthorization,
  type EntryGateOptions,
  type EntryGateResult,
} from "./adapter_tier.js";
import {
  evalGate,
  compositionCheck,
  type EvalHarness,
  type EvalGateOptions,
  type CompositionCheckOptions,
  type EvalGateResult,
  type CompositionCheckResult,
} from "./eval_gate.js";

/** A replay-buffer attestation: was general data mixed in to resist over-specialization? */
export interface ReplayBufferAttestation {
  /** Fraction of training that was general replay data (10-20% recommended). */
  readonly replayFraction: number;
  readonly attested: boolean;
}

export interface DeployRequest {
  readonly adapter: LoraAdapter;
  readonly auth: SessionAuthorization | undefined;
  readonly sandboxed: boolean;
  readonly replay: ReplayBufferAttestation;
  readonly entryOpts?: EntryGateOptions;
  readonly evalOpts?: EvalGateOptions;
  readonly compositionOpts?: CompositionCheckOptions;
}

export type DeployStage = "entry" | "replay-buffer" | "eval" | "composition" | "canary" | "deployed" | "rejected";

export interface DeployDecision {
  readonly deployed: boolean;
  readonly stageReached: DeployStage;
  readonly reason: string;
  readonly entry?: EntryGateResult;
  readonly eval?: EvalGateResult;
  readonly composition?: CompositionCheckResult;
  /** If a canary was deployed, the rollback id to one-tap revert it. */
  readonly canaryRollbackId?: string;
}

export interface DeployDeps {
  readonly registry: AdapterRegistry;
  readonly harness: EvalHarness;
  readonly rollback: RollbackLedger;
  readonly spine: Spine;
  /** Deploys the canary in the sandbox; returns a concrete undo. Injected (real sandbox plugs in). */
  readonly canaryDeploy: (adapter: LoraAdapter) => Promise<{ undo: () => Promise<void> }>;
  readonly clock?: () => number;
}

/** Recommended replay fraction floor (10% of the 10-20% band). */
const REPLAY_FLOOR = 0.1;

/**
 * Run the full deploy gate chain for one adapter. Ordered + fail-closed: any stage that fails returns
 * immediately with the reason, nothing deployed, gradient-free floor preserved. Only a full pass
 * registers a CANARY (not a full rollout) with a one-tap rollback.
 */
export async function deployAdapter(req: DeployRequest, deps: DeployDeps): Promise<DeployDecision> {
  const now = (deps.clock ?? (() => Date.now()))();
  const { registry, harness, spine } = deps;
  // Ensure the candidate is tracked by the registry so status transitions + composition tracking are
  // consistent (an adapter being deployed must be in the registry).
  if (!registry.get(req.adapter.id)) registry.register(req.adapter);
  const activeIds = registry.activeAdapters().map((a) => a.id);

  spine.stage({ type: "identity.action", actor: "lora", payload: { event: "deploy_begin", id: req.adapter.id, activeAdapters: activeIds.length } });

  // 1. Entry gates (tier-on, auth, sandbox, verifiable reward, data provenance/poison, backdoor probe).
  const entry = checkEntryGates(registry, req.adapter, req.auth, req.sandboxed, now, req.entryOpts);
  if (!entry.passed) {
    return reject(spine, req.adapter.id, "entry", `entry gate '${entry.gate}': ${entry.reason}`, { entry });
  }

  // 2. Replay-buffer attestation (resist over-specialization / catastrophic forgetting).
  if (!req.replay.attested || req.replay.replayFraction < REPLAY_FLOOR) {
    return reject(spine, req.adapter.id, "replay-buffer", `replay buffer insufficient (${(req.replay.replayFraction * 100).toFixed(0)}% < ${REPLAY_FLOOR * 100}% general data attested)`, { entry });
  }

  // 3. Before/after eval gate (capability + safety, >5% either → reject).
  const ev = await evalGate(harness, activeIds, req.adapter, req.evalOpts);
  if (!ev.passed) {
    return reject(spine, req.adapter.id, "eval", ev.reason, { entry, eval: ev });
  }

  // 4. Composition check (colluding-LoRA defense; fail-closed).
  const comp = await compositionCheck(harness, spine, activeIds, req.adapter, req.compositionOpts);
  if (!comp.passed) {
    return reject(spine, req.adapter.id, "composition", comp.reason, { entry, eval: ev, composition: comp });
  }

  // 5. Canary deploy (NOT a full rollout) — reversible via the RollbackLedger.
  let canary: { undo: () => Promise<void> };
  try {
    canary = await deps.canaryDeploy(req.adapter);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    registry.setStatus(req.adapter.id, "rejected");
    return reject(spine, req.adapter.id, "canary", `canary deployment failed: ${reason}`, { entry, eval: ev, composition: comp });
  }
  const rollbackId = `canary_${req.adapter.id}_v${req.adapter.version}`;
  deps.rollback.record({ id: rollbackId, artifact: `lora-adapter:${req.adapter.id}`, undo: canary.undo });
  registry.setStatus(req.adapter.id, "canary");
  spine.stage({ type: "identity.action", actor: "lora", payload: { event: "canary_deployed", id: req.adapter.id, rollbackId } });

  return {
    deployed: true,
    stageReached: "canary",
    reason: `all gates passed; deployed as CANARY (one-tap rollback available). Full activation requires a further human promotion.`,
    entry,
    eval: ev,
    composition: comp,
    canaryRollbackId: rollbackId,
  };
}

/** One-tap rollback of a canary adapter via the RollbackLedger's real inverse. */
export async function rollbackCanary(deps: { rollback: RollbackLedger; registry: AdapterRegistry; spine: Spine }, adapterId: string): Promise<void> {
  const adapter = deps.registry.get(adapterId);
  if (!adapter || adapter.status !== "canary") throw new Error(`adapter ${adapterId} is not an active canary`);
  const result = await deps.rollback.rollbackAction(`canary_${adapter.id}_v${adapter.version}`, `lora canary rollback: ${adapterId}`);
  if (!result.rolledBack) throw new Error(`no rollback inverse recorded for canary ${adapterId}`);
  deps.registry.setStatus(adapterId, "rejected");
  deps.spine.stage({ type: "identity.action", actor: "lora", payload: { event: "canary_rolled_back", id: adapterId } });
}

function reject(spine: Spine, id: string, stage: DeployStage, reason: string, extra: Partial<DeployDecision>): DeployDecision {
  spine.stage({ type: "identity.action", actor: "lora", payload: { event: "deploy_rejected", id, stage, reason } });
  return { deployed: false, stageReached: "rejected", reason: `rejected at ${stage}: ${reason}`, ...extra };
}
