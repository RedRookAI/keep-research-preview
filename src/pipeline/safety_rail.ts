/**
 * SafetyRail (Increment 16.6a) — default-on, fail-closed governance guardrails.
 *
 * Composes the built-but-previously-orphaned safety subsystems (killswitch, authorization envelope +
 * budget ledger, governance ledger, vetting) into ONE ordered interface the KeepPipeline calls. Every
 * decision is recorded to the tamper-evident spine via the GovernanceLedger. SOTA-settled design
 * (GOVERNANCE_INTEGRATION_SPEC, 2026-08-05):
 *  - Fork A: break-glass is a separate audited grant, never a config flag; it can relax the vetting
 *    VERDICT but never the human merge gate.
 *  - Fork B: two-tier budget — soft cap PAUSES + routes to operator approval (resumable); hard ceiling
 *    PAUSES + requires explicit re-authorization. Never a dead-end kill, never silent auto-proceed.
 *  - Fork C: no envelope → synthesize a conservative DEFAULT RESTRICTIVE envelope (secure-by-default),
 *    not an open one and not a hard refusal. N=1 / free-tier safe out of the box.
 *  - Fail-closed everywhere: a guardrail that errors or can't run gates to the human / pauses.
 * Zero deps.
 */

import type { Spine } from "../spine/spine.js";
import type { GovernanceLedger } from "../governance/decision_record.js";
import type { PolicyDecision, Effect } from "../governance/policy_engine.js";
import type { KillSwitch } from "../control/killswitch.js";
import { BudgetLedger, type AuthorizationEnvelope, type LoopClass, type ModelTier } from "../scheduler/authorization_envelope.js";
import { CostModel, type TokenUsage } from "../observability/cost_model.js";

// ── grants (Fork A break-glass, Fork B resume) — separate audited objects, NOT config flags ──

/** A break-glass grant that can relax the vetting VERDICT only. Never touches the merge gate. */
export interface BreakGlassGrant {
  readonly operatorId: string;
  readonly reason: string;
  readonly expiresAt: number;
}

/** A budget re-authorization: the operator raising the ceiling to resume a paused run. */
export interface RunResumeGrant {
  readonly operatorId: string;
  readonly reason: string;
  /** The new per-run ceiling (USD) the operator authorizes. */
  readonly raisedPerRunCapUsd: number;
  readonly expiresAt: number;
}

// ── decisions ──

export type RailOutcome = "allow" | "pause-soft" | "pause-hard" | "deny" | "block-killed";

export interface RailDecision {
  readonly outcome: RailOutcome;
  readonly reason: string;
  /** For a soft/hard budget pause: what the operator needs to approve to resume. */
  readonly approvalRequest?: BudgetApprovalRequest;
}

export interface BudgetApprovalRequest {
  readonly runId: string;
  readonly currentPerRunCapUsd: number;
  readonly projectedSpendUsd: number;
  readonly kind: "soft-cap" | "hard-ceiling";
  readonly message: string;
}

export interface VetDecision {
  /** True = the patch cleared vetting (or a valid break-glass relaxed it). */
  readonly cleared: boolean;
  /** True if clearance came from break-glass rather than passing vetting. */
  readonly viaBreakGlass: boolean;
  readonly reason: string;
}

export interface SafetyRailConfig {
  readonly spine: Spine;
  readonly governance: GovernanceLedger;
  readonly killSwitch?: KillSwitch;
  /** The vetting function on the produced patch. Fail-closed if it throws or is absent. */
  readonly vetPatchFn?: (repoRef: string) => Promise<boolean>;
  /** Soft-cap fraction of the per-run ceiling (default 0.8 — SOTA ~80% warn level). */
  readonly softCapFraction?: number;
  /** The default restrictive envelope's per-run cap (USD) when none supplied (Fork C). */
  readonly defaultPerRunCapUsd?: number;
  readonly defaultDailyCapUsd?: number;
  /** Cost model with registered pricing. Omit → a fresh one; unknown-model calls then fail-closed. */
  readonly costModel?: CostModel;
  readonly clock?: () => number;
}

const DEFAULTS = {
  softCapFraction: 0.8,
  // Conservative shipped defaults (SOTA anchor: ~$10/day catches 95% of runaways). Tunable up.
  defaultPerRunCapUsd: 2.0,
  defaultDailyCapUsd: 10.0,
  perCallTokenCeiling: 8000,
};

export class SafetyRail {
  private readonly budget: BudgetLedger;
  private readonly costModel: CostModel;
  private readonly softCapFraction: number;
  private readonly clock: () => number;
  private currentEnvelope?: AuthorizationEnvelope;

  constructor(private readonly config: SafetyRailConfig) {
    this.clock = config.clock ?? (() => Date.now());
    this.softCapFraction = config.softCapFraction ?? DEFAULTS.softCapFraction;
    this.costModel = config.costModel ?? new CostModel();
    this.budget = new BudgetLedger(config.spine, this.costModel, this.clock);
  }

  /** Stage 0: refuse to run if the killswitch is tripped for this agent. */
  checkKillswitch(agentId: string): RailDecision {
    if (this.config.killSwitch?.isTerminated(agentId)) {
      this.record("killswitch.check", "deny", { effect: "deny", ruleId: "killswitch", reason: "agent terminated", matchedRuleIds: ["killswitch"], policyVersion: "1" }, "blocked");
      return { outcome: "block-killed", reason: `killswitch tripped for ${agentId} — pipeline refuses to run` };
    }
    return { outcome: "allow", reason: "killswitch clear" };
  }

  /**
   * Stage 1: authorize the run. If no envelope is supplied, synthesize a conservative DEFAULT
   * RESTRICTIVE envelope (Fork C, secure-by-default). Deny (not crash) only if a supplied envelope is
   * expired/invalid. Opens a budget run for subsequent guardModelCall checks.
   */
  authorize(runId: string, envelope: AuthorizationEnvelope | undefined, projectId: string): RailDecision {
    let env = envelope;
    if (!env) {
      env = this.synthesizeDefaultEnvelope(projectId);
      this.record("authorize", "allow", { effect: "allow", ruleId: "default-restrictive-envelope", reason: "no envelope supplied — secure-by-default restrictive envelope synthesized", matchedRuleIds: ["default-restrictive-envelope"], policyVersion: "1" }, "proceeded");
    } else if (this.clock() > env.expiresAt) {
      this.record("authorize", "deny", { effect: "deny", ruleId: "envelope-expired", reason: `envelope ${env.id} expired`, matchedRuleIds: ["envelope-expired"], policyVersion: "1" }, "blocked");
      return { outcome: "deny", reason: `authorization denied: envelope ${env.id} expired` };
    } else {
      this.record("authorize", "allow", { effect: "allow", ruleId: env.id, reason: env.grantedReason, matchedRuleIds: [env.id], policyVersion: "1" }, "proceeded");
    }
    this.currentEnvelope = env;
    this.budget.grant(env);
    this.budget.beginRun(runId, env.id);
    return { outcome: "allow", reason: `authorized under envelope ${env.id}` };
  }

  /**
   * Stage 2 (per model call): two-tier budget guard (Fork B). A projected call that would cross the
   * HARD ceiling → pause-hard (needs a RunResumeGrant to continue). A call that would cross the SOFT
   * cap (default 80% of per-run) → pause-soft (routes to operator approval, resumable). A valid
   * resume grant that raises the ceiling lets the call proceed. Never a dead-end kill.
   */
  guardModelCall(runId: string, cls: LoopClass, tier: ModelTier, model: string, projected: TokenUsage, resume?: RunResumeGrant): RailDecision {
    const env = this.currentEnvelope;
    if (!env) return { outcome: "deny", reason: "no active envelope — call authorize() first" };

    // Apply a valid resume grant by raising the run's effective ceiling (audited).
    if (resume && this.clock() <= resume.expiresAt) {
      const raised: AuthorizationEnvelope = { ...env, perRunCapUsd: resume.raisedPerRunCapUsd };
      this.currentEnvelope = raised;
      this.budget.grant(raised);
      this.record("budget.resume", "allow", { effect: "allow", ruleId: "run-resume-grant", reason: `operator ${resume.operatorId} raised per-run cap to ${resume.raisedPerRunCapUsd}: ${resume.reason}`, matchedRuleIds: ["run-resume-grant"], policyVersion: "1" }, "warned-and-proceeded");
    }

    const eff = this.currentEnvelope!;

    // Fail-closed: if we cannot price the model, we cannot verify the call is within budget →
    // pause for operator approval rather than throwing or silently allowing.
    if (!this.costModel.hasPricing(model)) {
      const req: BudgetApprovalRequest = {
        runId, currentPerRunCapUsd: eff.perRunCapUsd, projectedSpendUsd: NaN,
        kind: "soft-cap", message: `cannot price model "${model}" — run paused for operator approval (fail-closed); register pricing or approve to resume`,
      };
      this.record("budget.unpriceable", "warn", { effect: "warn", ruleId: "unpriceable-model-fail-closed", reason: req.message, matchedRuleIds: ["unpriceable-model-fail-closed"], policyVersion: "1" }, "escalated-to-human");
      return { outcome: "pause-soft", reason: req.message, approvalRequest: req };
    }

    const hard = this.budget.willBreach(runId, cls, tier, model, projected);
    if (hard.wouldBreach) {
      const req: BudgetApprovalRequest = {
        runId, currentPerRunCapUsd: eff.perRunCapUsd, projectedSpendUsd: this.projectedSpend(runId, model, projected),
        kind: "hard-ceiling", message: `hard ceiling reached (${hard.kind}: ${hard.reason}) — run paused; an explicit re-authorization with a raised cap is required to continue`,
      };
      this.record("budget.hard", "deny", { effect: "deny", ruleId: "hard-ceiling", reason: hard.reason ?? "hard ceiling", matchedRuleIds: ["hard-ceiling"], policyVersion: "1" }, "escalated-to-human");
      return { outcome: "pause-hard", reason: req.message, approvalRequest: req };
    }

    // Soft cap: projected run spend crosses softCapFraction * per-run ceiling → pause for approval.
    const projectedSpend = this.projectedSpend(runId, model, projected);
    const softCap = eff.perRunCapUsd * this.softCapFraction;
    if (projectedSpend >= softCap) {
      const req: BudgetApprovalRequest = {
        runId, currentPerRunCapUsd: eff.perRunCapUsd, projectedSpendUsd: projectedSpend,
        kind: "soft-cap", message: `soft cap reached (projected ${projectedSpend.toFixed(4)} >= ${softCap.toFixed(4)}) — run paused for operator approval; approve/raise to resume`,
      };
      this.record("budget.soft", "warn", { effect: "warn", ruleId: "soft-cap", reason: req.message, matchedRuleIds: ["soft-cap"], policyVersion: "1" }, "escalated-to-human");
      return { outcome: "pause-soft", reason: req.message, approvalRequest: req };
    }

    return { outcome: "allow", reason: "within budget" };
  }

  /** Record actual spend after a call (keeps the ledger honest for the next guard check). */
  recordSpend(runId: string, model: string, usage: TokenUsage): void {
    this.budget.recordSpend(runId, model, usage);
  }

  /**
   * Stage 3 (after solve, before PR): vet the produced patch. FAIL-CLOSED — if the vet function throws
   * or is absent, the patch is treated as NOT cleared (forced to the human gate). A valid BreakGlassGrant
   * (Fork A) can relax the VERDICT (with a high-priority audit record) but NEVER the merge gate.
   */
  async vetPatch(repoRef: string, breakGlass?: BreakGlassGrant): Promise<VetDecision> {
    // Break-glass path: relax the verdict, loudly audited. Still cannot merge (that's structural).
    if (breakGlass && this.clock() <= breakGlass.expiresAt) {
      this.record("vet.breakglass", "warn", { effect: "warn", ruleId: "break-glass", reason: `BREAK-GLASS by ${breakGlass.operatorId}: ${breakGlass.reason} — vetting verdict relaxed (merge gate still human)`, matchedRuleIds: ["break-glass"], policyVersion: "1" }, "warned-and-proceeded");
      return { cleared: true, viaBreakGlass: true, reason: `vetting relaxed via break-glass (${breakGlass.operatorId})` };
    }

    if (!this.config.vetPatchFn) {
      this.record("vet.patch", "deny", { effect: "deny", ruleId: "vet-absent-fail-closed", reason: "no vetting function configured — fail-closed to human", matchedRuleIds: ["vet-absent-fail-closed"], policyVersion: "1" }, "escalated-to-human");
      return { cleared: false, viaBreakGlass: false, reason: "no vetting configured — fail-closed (human review required)" };
    }

    let cleared: boolean;
    try {
      cleared = await this.config.vetPatchFn(repoRef);
    } catch (e) {
      this.record("vet.patch", "deny", { effect: "deny", ruleId: "vet-error-fail-closed", reason: `vetting threw: ${(e as Error).message} — fail-closed`, matchedRuleIds: ["vet-error-fail-closed"], policyVersion: "1" }, "escalated-to-human");
      return { cleared: false, viaBreakGlass: false, reason: "vetting errored — fail-closed (human review required)" };
    }

    this.record("vet.patch", cleared ? "allow" : "deny", { effect: cleared ? "allow" : "deny", ruleId: "vetting-cascade", reason: cleared ? "vetting cleared" : "vetting did not clear", matchedRuleIds: ["vetting-cascade"], policyVersion: "1" }, cleared ? "proceeded" : "escalated-to-human");
    return { cleared, viaBreakGlass: false, reason: cleared ? "vetting cleared" : "vetting did not clear — human review required" };
  }

  /** The default restrictive envelope (Fork C) — conservative caps, short expiry, all classes local. */
  private synthesizeDefaultEnvelope(projectId: string): AuthorizationEnvelope {
    return {
      id: `default-restrictive-${projectId}`,
      projectId,
      allowedClasses: ["auto-research", "auto-rag", "auto-learning", "auto-training"],
      allowedTiers: [], // empty = any tier; caps do the real constraining
      dailyCapUsd: this.config.defaultDailyCapUsd ?? DEFAULTS.defaultDailyCapUsd,
      perRunCapUsd: this.config.defaultPerRunCapUsd ?? DEFAULTS.defaultPerRunCapUsd,
      perCallTokenCeiling: DEFAULTS.perCallTokenCeiling,
      expiresAt: this.clock() + 24 * 60 * 60 * 1000, // 24h default, re-granted per session
      grantedReason: "secure-by-default restrictive envelope (no operator envelope supplied)",
    };
  }

  private projectedSpend(runId: string, model: string, projected: TokenUsage): number {
    const run = this.budget.runSpend(runId);
    const spent = run?.spentUsd ?? 0;
    const callCost = this.costModel.cost(model, projected).totalUsd;
    return spent + callCost;
  }

  private record(action: string, _effect: Effect | "warn", policy: PolicyDecision, outcome: Parameters<GovernanceLedger["record"]>[0]["outcome"]): void {
    this.config.governance.record({ action, actor: "safety-rail", policy, outcome });
  }
}
