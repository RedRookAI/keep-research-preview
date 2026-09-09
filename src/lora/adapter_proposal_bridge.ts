/**
 * AdapterProposalBridge (Increment 18.8) — connects the self-improvement loop's model-adapter axis to the
 * existing LoRA tier (10a entry gates / 10b eval+composition / 10c deploy). Those modules were built and tested
 * but were ISLANDS: nothing wired a "model-adapter" proposal to checkEntryGates + compositionCheck + deploy,
 * and none of it reached composeKeep. This bridge makes weight-level adaptation a REAL, gated axis.
 *
 * The most-gated axis, and the ONLY gradient-based one. OPT-IN and RICH-TIER-ONLY: absent an opt-in config the
 * bridge is not constructed, so N=1 / free-tier / no-GPU is COMPLETELY unaffected — gradient-free learning
 * (prompts/memory/skills) stays the default and the floor.
 *
 * SOTA basis (2026-08-05, re-verified — one finding CHANGED the emphasis):
 *  - Colluding LoRA (ICLR 2026, arXiv 2603.12681): adapters each benign IN ISOLATION can dismantle safety WHEN
 *    COMPOSED; "multi-adapter collusion bypasses review that evaluates adapters in isolation." The CSA fix:
 *    behavioral red-team of the FULLY ASSEMBLED (all adapters merged) model before any new combination ships,
 *    incl. refuse-then-comply probes (prefix-only scoring insufficient). → the bridge routes through
 *    compositionCheck (merged-set eval), NOT per-adapter eval, as a HARD gate.
 *  - LoRA efficiently undoes safety training (Shadow Alignment; Lermen) and even BENIGN data degrades safety
 *    (Qi et al.) → preserved capability is NOT evidence of safety; the eval gate checks a safety DELTA + floor.
 *  - LoRA backdoors persist + are training-data-induced at ~4.2% poison (arXiv 2605.30189/2602.15195) → data
 *    provenance + poison-screen (entry gate) is mandatory; capability eval alone cannot catch a backdoor.
 *  - RLVR only safety-preserving with genuinely verifiable rewards (unit-tests/compiler/exact-match) → the
 *    entry gate rejects soft-reward adapters (isVerifiableReward).
 *
 * Zero runtime deps. All heavy lifting delegates to the existing LoRA functions + injected harness/registry.
 */

import type { Spine } from "../spine/spine.js";
import {
  AdapterRegistry,
  checkEntryGates,
  isVerifiableReward,
  type LoraAdapter,
  type SessionAuthorization,
  type EntryGateOptions,
} from "../lora/adapter_tier.js";
import type { EvalHarness, EvalGateOptions, CompositionCheckOptions } from "../lora/eval_gate.js";
import { deployAdapter, rollbackCanary, type ReplayBufferAttestation } from "../lora/deploy_orchestrator.js";
import type { RollbackLedger } from "../control/rollback.js";

export interface AdapterBridgeDeps {
  readonly registry: AdapterRegistry;
  /** The eval harness (rich-tier: a real sandbox that can evaluate + red-team the merged adapter set). */
  readonly harness: EvalHarness;
  readonly spine: Spine;
  readonly rollback: RollbackLedger;
  readonly canaryDeploy: (adapter: LoraAdapter) => Promise<{ undo: () => Promise<void> }>;
  readonly clock?: () => number;
}

export interface AdapterGateInput {
  readonly adapter: LoraAdapter;
  readonly auth: SessionAuthorization | undefined;
  readonly sandboxed: boolean;
  readonly replay: ReplayBufferAttestation;
}

export type AdapterOutcome =
  | "deployed-canary"      // cleared entry + composition → live as an instant-rollback canary
  | "rejected-entry"       // failed authorization / sandbox / provenance / poison / verifiable-reward
  | "rejected-replay"
  | "rejected-eval"
  | "rejected-composition" // failed the merged-set (Colluding-LoRA) eval or refuse-then-comply red-team
  | "rejected-canary"
  | "rejected-not-verifiable";

export interface AdapterDecision {
  readonly outcome: AdapterOutcome;
  readonly reason: string;
  readonly adapterId: string;
  readonly canaryRollbackId?: string;
}

export class AdapterProposalBridge {
  private readonly registry: AdapterRegistry;
  private readonly harness: EvalHarness;
  private readonly spine: Spine;
  private readonly rollbackLedger: RollbackLedger;
  private readonly canaryDeploy: AdapterBridgeDeps["canaryDeploy"];
  private readonly clock: () => number;

  constructor(deps: AdapterBridgeDeps) {
    this.registry = deps.registry;
    this.harness = deps.harness;
    this.spine = deps.spine;
    this.rollbackLedger = deps.rollback;
    this.canaryDeploy = deps.canaryDeploy;
    this.clock = deps.clock ?? (() => Date.now());
  }

  /**
   * The MetaHarness extraGate delegate for a model-adapter proposal: it must clear the LoRA ENTRY gates
   * (authorization + sandbox + data provenance/poison-screen + verifiable-reward-only) BEFORE the proposal can
   * even be scored against the anchor. Returns the shape MetaHarness.extraGate expects.
   */
  entryGateDelegate(input: AdapterGateInput, opts: EntryGateOptions = {}): () => { passed: boolean; reason: string } {
    return () => {
      // Verifiable-reward-only is a hard precondition (RLVR safety-preservation).
      if (!isVerifiableReward(input.adapter.rewardKind)) {
        return { passed: false, reason: `reward kind "${input.adapter.rewardKind}" is not verifiable (RLVR requires unit-tests/compiler/exact-match/cited-facts)` };
      }
      const g = checkEntryGates(this.registry, input.adapter, input.auth, input.sandboxed, this.clock(), opts);
      return { passed: g.passed, reason: g.reason };
    };
  }

  /**
   * The full gated pipeline for an APPROVED-at-entry adapter: composition eval (the Colluding-LoRA defense —
   * evaluates the candidate MERGED with every active adapter + refuse-then-comply, NOT in isolation) → deploy
   * as a canary. Fails closed. Never merges past the human gate; the deploy is an instant-rollback canary.
   */
  async admit(input: AdapterGateInput, opts: { entry?: EntryGateOptions; eval?: EvalGateOptions; composition?: CompositionCheckOptions } = {}): Promise<AdapterDecision> {
    const id = input.adapter.id;

    // 1. Entry gate (verifiable-reward + authorization + sandbox + provenance/poison).
    if (!isVerifiableReward(input.adapter.rewardKind)) {
      return { outcome: "rejected-not-verifiable", adapterId: id, reason: `non-verifiable reward "${input.adapter.rewardKind}" — rejected before entry` };
    }
    const decision = await deployAdapter({ adapter: input.adapter, auth: input.auth, sandboxed: input.sandboxed, replay: input.replay, ...(opts.entry ? { entryOpts: opts.entry } : {}), ...(opts.eval ? { evalOpts: opts.eval } : {}), ...(opts.composition ? { compositionOpts: opts.composition } : {}) }, { registry: this.registry, harness: this.harness, rollback: this.rollbackLedger, spine: this.spine, canaryDeploy: this.canaryDeploy, clock: this.clock });
    if (decision.deployed) return { outcome: "deployed-canary", adapterId: id, reason: decision.reason, ...(decision.canaryRollbackId ? { canaryRollbackId: decision.canaryRollbackId } : {}) };
    if (decision.entry && !decision.entry.passed) return { outcome: "rejected-entry", adapterId: id, reason: decision.reason };
    if (decision.eval && !decision.eval.passed) return { outcome: "rejected-eval", adapterId: id, reason: decision.reason };
    if (decision.composition && !decision.composition.passed) return { outcome: "rejected-composition", adapterId: id, reason: decision.reason };
    if (decision.reason.includes("replay buffer")) return { outcome: "rejected-replay", adapterId: id, reason: decision.reason };
    return { outcome: "rejected-canary", adapterId: id, reason: decision.reason };
  }

  async rollback(adapterId: string): Promise<void> {
    await rollbackCanary({ rollback: this.rollbackLedger, registry: this.registry, spine: this.spine }, adapterId);
  }
}
