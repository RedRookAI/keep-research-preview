/**
 * Oversight routing (Increment 15.5b).
 *
 * Maps a PR's risk band + the operator's autonomy level to one of the THREE existing dispositions
 * (auto-approved / human-approval-required / blocked). SOTA three-tier model (Hitchhiker's Guide 2026):
 * Tier 1 auto-approve (low risk, reversible — logged, no interrupt), Tier 2 notify (medium — async,
 * cancellable), Tier 3 require-approval (high — blocking). Key safety rules honored:
 *  - rule-forced gate always wins (auth/crypto/migrations → human review regardless of confidence),
 *  - deny-by-default on timeout: an unanswered high-risk gate resolves to BLOCKED, never proceeds
 *    (Arthur 2026: "an approval that times out into execution is a gate that does not exist"),
 *  - graduated autonomy only widens the auto-approve band for LOW-risk reversible PRs; it NEVER
 *    removes the merge gate (that stays the human's, permanently — increment 15 invariant).
 *
 * "Auto-approved" means "the human need not look at this one right now" — NOT merged. Keep still never
 * merges. Zero deps.
 */

import type { AutonomyLevel } from "../frontdoor/autonomy_profile.js";
import type { GateDisposition } from "../frontdoor/plan_execute_gate.js";
import type { PrRiskScore, RiskBand } from "./pr_risk.js";

/** Non-blocking vs blocking distinction on top of the disposition (the "notify" tier). */
export type OversightMode = "silent-auto" | "notify-async" | "block-until-approved";

export interface OversightDecision {
  readonly disposition: GateDisposition;
  readonly mode: OversightMode;
  readonly band: RiskBand;
  readonly reasons: readonly string[];
  /** True if this PR should interrupt the human now (Tier 3) vs batch/notify (Tier 1/2). */
  readonly requiresImmediateAttention: boolean;
}

export interface OversightConfig {
  readonly autonomyLevel: AutonomyLevel;
  /** If a blocking gate isn't answered within this many ms, resolve to `blocked` (deny by default). */
  readonly approvalTimeoutMs?: number;
  /**
   * Classes with a HUMAN-AUTHORIZED, revocable reduced-escalation policy (from CalibrationWire, F2). A PR
   * whose classKey is in this set auto-approves in the low/medium reversible band — NEVER high, NEVER a
   * forced-gate path. Empty by default → N=1 safe-by-default behavior is unchanged until the operator
   * explicitly authorizes a proven-clean class.
   */
  readonly reducedEscalationClasses?: ReadonlySet<string>;
}

/**
 * The band that each autonomy level is willing to AUTO-APPROVE up to (within the reversible band only).
 * Higher autonomy → auto-approves more of the low/medium band. NOTE: "high" risk is NEVER auto-approved
 * at any level — the dangerous few always get human eyes. And rule-forced gates always block.
 */
const AUTO_APPROVE_CEILING: Record<AutonomyLevel, RiskBand | "none"> = {
  observer: "none", // ask about everything
  approver: "none", // ask about everything (default-safe)
  collaborator: "low", // auto-approve only low risk
  operator: "medium", // auto-approve low + medium (still gate high)
  delegator: "medium", // hands-off within reversible band; high still gated
};

const BAND_RANK: Record<RiskBand, number> = { low: 0, medium: 1, high: 2 };

export class OversightRouter {
  constructor(private readonly config: OversightConfig) {}

  /** Route a risk score to an oversight decision. Pure + deterministic. `classKey` (optional) lets a
   *  human-authorized calibration policy reduce escalation for a proven-clean reversible class. */
  route(risk: PrRiskScore, opts: { classKey?: string } = {}): OversightDecision {
    const reasons: string[] = [];
    const level = this.config.autonomyLevel;

    // Rule-forced gate wins outright — an authorized calibration policy can NEVER override it.
    if (risk.forcedGate) {
      reasons.push("sensitive path forces human review (rule-based, overrides autonomy + confidence + any calibration policy)");
      return { disposition: "human-approval-required", mode: "block-until-approved", band: "high", reasons, requiresImmediateAttention: true };
    }

    // High risk is never auto-approved — a calibration policy can NEVER reduce a high-risk PR.
    if (risk.band === "high") {
      reasons.push("high risk — requires explicit human approval before merge");
      return { disposition: "human-approval-required", mode: "block-until-approved", band: risk.band, reasons, requiresImmediateAttention: true };
    }

    // Human-authorized, revocable calibration policy: a proven-clean reversible class the operator chose to
    // stop being asked about. Only reachable for low/medium here (high + forced-gate already returned). Governed
    // + auto-tightening (CalibrationWire revokes on a rising revert rate). The class key defaults to the risk
    // BAND (a coarse, honest class — "low"/"medium"); a finer change-class taxonomy is a labeled future seam.
    const classKey = opts.classKey ?? risk.band;
    if (this.config.reducedEscalationClasses?.has(classKey) ?? false) {
      reasons.push(`auto-approved via human-authorized calibration policy for class '${classKey}' (governed, revocable, low/medium reversible only)`);
      return { disposition: "auto-approved", mode: risk.band === "low" ? "silent-auto" : "notify-async", band: risk.band, reasons, requiresImmediateAttention: false };
    }

    // Within low/medium: does the operator's autonomy level auto-approve this band?
    const ceiling = AUTO_APPROVE_CEILING[level];
    const autoApproves = ceiling !== "none" && BAND_RANK[risk.band] <= BAND_RANK[ceiling];

    if (autoApproves) {
      if (risk.band === "low") {
        reasons.push(`low risk + '${level}' autonomy — auto-approved for batch review (no interrupt)`);
        return { disposition: "auto-approved", mode: "silent-auto", band: risk.band, reasons, requiresImmediateAttention: false };
      }
      // medium, auto-approvable at this level → notify async (cancellable), don't block.
      reasons.push(`medium risk + '${level}' autonomy — auto-approved with async notification (cancellable)`);
      return { disposition: "auto-approved", mode: "notify-async", band: risk.band, reasons, requiresImmediateAttention: false };
    }

    // Not auto-approved at this level → human approval, but medium risk can notify rather than hard-block.
    if (risk.band === "medium") {
      reasons.push(`medium risk at '${level}' autonomy — human approval requested (async)`);
      return { disposition: "human-approval-required", mode: "notify-async", band: risk.band, reasons, requiresImmediateAttention: false };
    }
    reasons.push(`'${level}' autonomy asks about all changes`);
    return { disposition: "human-approval-required", mode: "notify-async", band: risk.band, reasons, requiresImmediateAttention: false };
  }

  /**
   * Resolve a blocking gate that was not answered in time. DENY BY DEFAULT: a timed-out approval
   * resolves to `blocked`, never to auto-proceed (Arthur 2026). Reversible low-risk items may be
   * configured to expire to their safe default elsewhere; a blocking gate never silently proceeds.
   */
  resolveTimeout(decision: OversightDecision): GateDisposition {
    if (decision.mode === "block-until-approved") return "blocked";
    // non-blocking notify items were never holding execution; they remain as-is.
    return decision.disposition;
  }
}
