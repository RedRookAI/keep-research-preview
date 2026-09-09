/**
 * OversightCalibration (Increment 16.9b, CORRECTED) — calibrates human escalation to RISK and OUTCOMES,
 * minimizing low-value approvals for the (especially solo) operator.
 *
 * SUPERSEDES the earlier RubberStampMonitor "high approve-rate -> tighten -> route more to human" logic,
 * which was faulty: it (a) can't tell a well-calibrated system from a rubber-stamping one, and (b) responds
 * to reviewer overload by ADDING low-value load — "a liability generator" producing "false assurance"
 * (waxell 2026). Burdening a solo user with MORE rubber-stamps is the failure mode, not the fix.
 *
 * Corrected principles (SOTA 2026-08-05):
 *  - ESCALATE BY RISK, NOT APPROVE-RATE: irreversibility, magnitude/blast, low confidence, and ANOMALY
 *    (is this change unlike the established safe pattern?). The reversible/low-magnitude long tail rarely
 *    escalates (waxell: "map by reversibility first; reversible low-magnitude rarely needs to escalate").
 *  - HIGH APPROVE-RATE -> OUTCOME REVIEW, NOT MORE ROUTING: track post-approval REVERT/REWORK. Clean
 *    outcomes on a reversible class -> CANDIDATE FOR REDUCED escalation, applied ONLY via a governed policy
 *    change (ping-os 2026: "candidates for a narrower preapproved rule, but only after outcome data
 *    supports the change... controlled governance process, never because the queue is inconvenient").
 *  - SAFETY PRESERVED: auto-approval is driven by deterministic confidence + reversibility + clean outcome
 *    history; IRREVERSIBLE / high-risk NEVER auto-promotes regardless of approve-rate. No ungoverned widen.
 *
 * Deterministic, zero deps. Every recommendation is audited; policy changes stay governed + human-authorized.
 */

import type { GovernanceLedger } from "../governance/decision_record.js";

/** A recorded human decision + its later outcome (for outcome-based calibration). */
export interface DecisionRecord {
  readonly gate: string;
  /** The risk class of the item (drives whether it was a low-value escalation). */
  readonly reversible: boolean;
  readonly approved: boolean;
  /** Post-approval outcome, filled in later: was the change reverted / reworked / caused a failure? */
  outcome?: "clean" | "reverted" | "failed";
  readonly ts: number;
}

export interface EscalationSignals {
  readonly reversible: boolean;
  /** blast magnitude: does a mistake here matter a lot? */
  readonly highMagnitude: boolean;
  /** deterministic confidence in [0,1] that the change is safe (from the vetting floor). */
  readonly confidence: number;
  /** anomaly: is this change unlike the established safe pattern for this gate/user? */
  readonly anomalous: boolean;
}

export interface EscalationDecision {
  readonly escalate: boolean;
  readonly reasons: readonly string[];
}

export interface CalibrationConfig {
  readonly windowSize?: number;
  /** Confidence at/below which we escalate regardless of reversibility. Default 0.6. */
  readonly lowConfidenceThreshold?: number;
  /** Min clean-outcome sample before recommending REDUCED escalation for a reversible class. Default 10. */
  readonly minCleanSample?: number;
  /** Max tolerated revert/fail rate to still consider a class "clean". Default 0.05. */
  readonly maxRevertRate?: number;
  readonly governance?: GovernanceLedger;
}

export interface CalibrationAssessment {
  readonly gate: string;
  readonly sample: number;
  readonly revertRate: number;
  /** Recommendation about ESCALATION VOLUME for this gate — the safe direction is usually LESS. */
  readonly recommendation: "reduce-escalation-candidate" | "increase-scrutiny" | "hold";
  readonly reason: string;
}

export class OversightCalibration {
  private readonly history = new Map<string, DecisionRecord[]>();
  private readonly windowSize: number;
  private readonly lowConfidence: number;
  private readonly minCleanSample: number;
  private readonly maxRevertRate: number;
  private readonly governance: GovernanceLedger | undefined;

  constructor(config: CalibrationConfig = {}) {
    this.windowSize = config.windowSize ?? 50;
    this.lowConfidence = config.lowConfidenceThreshold ?? 0.6;
    this.minCleanSample = config.minCleanSample ?? 10;
    this.maxRevertRate = config.maxRevertRate ?? 0.05;
    this.governance = config.governance;
  }

  /**
   * RISK-BASED escalation decision. Escalate iff: irreversible, OR high-magnitude, OR low confidence, OR
   * anomalous. The reversible + low-magnitude + confident + normal long tail does NOT escalate — the solo
   * operator is not asked to rubber-stamp it. (This is the whole point: escalate risk, not routine.)
   */
  shouldEscalate(signals: EscalationSignals): EscalationDecision {
    const reasons: string[] = [];
    if (!signals.reversible) reasons.push("change is not reversible");
    if (signals.highMagnitude) reasons.push("high-magnitude change");
    if (signals.confidence <= this.lowConfidence) reasons.push(`low deterministic confidence (${signals.confidence.toFixed(2)})`);
    if (signals.anomalous) reasons.push("anomalous vs the established safe pattern");
    return { escalate: reasons.length > 0, reasons: reasons.length > 0 ? reasons : ["reversible, low-magnitude, confident, and normal — no escalation needed"] };
  }

  /** Record a human decision (outcome filled in later via recordOutcome). */
  record(gate: string, reversible: boolean, approved: boolean, now = Date.now()): void {
    const h = this.history.get(gate) ?? [];
    h.push({ gate, reversible, approved, ts: now });
    while (h.length > this.windowSize) h.shift();
    this.history.set(gate, h);
  }

  /** Fill in the post-approval outcome for the most recent matching decision (outcome-based calibration). */
  recordOutcome(gate: string, outcome: "clean" | "reverted" | "failed"): void {
    const h = this.history.get(gate) ?? [];
    for (let i = h.length - 1; i >= 0; i--) {
      if (h[i]!.outcome === undefined) { h[i]!.outcome = outcome; return; }
    }
  }

  /**
   * Assess a gate by OUTCOMES (not approve totals). A reversible class with a clean outcome history is a
   * CANDIDATE FOR REDUCED escalation (fewer rubber-stamps for the operator) — recorded as a governed
   * recommendation, NOT auto-applied. A rising revert/fail rate -> increase scrutiny on that class.
   */
  assess(gate: string): CalibrationAssessment {
    const h = (this.history.get(gate) ?? []).filter((d) => d.outcome !== undefined);
    const sample = h.length;
    const bad = h.filter((d) => d.outcome === "reverted" || d.outcome === "failed").length;
    const revertRate = sample === 0 ? 0 : bad / sample;

    if (sample >= this.minCleanSample && revertRate > this.maxRevertRate) {
      const reason = `revert/fail rate ${(revertRate * 100).toFixed(0)}% over ${sample} outcomes — increase scrutiny on this class`;
      return { gate, sample, revertRate, recommendation: "increase-scrutiny", reason };
    }
    if (sample >= this.minCleanSample && revertRate <= this.maxRevertRate && h.every((d) => d.reversible)) {
      const reason = `clean outcomes (${(revertRate * 100).toFixed(0)}% revert) over ${sample} REVERSIBLE decisions — candidate to REDUCE escalation for this class (fewer low-value approvals); apply only via governed policy change`;
      return { gate, sample, revertRate, recommendation: "reduce-escalation-candidate", reason };
    }
    return { gate, sample, revertRate, recommendation: "hold", reason: `insufficient outcome data or mixed reversibility (${sample} outcomes) — hold` };
  }

  /**
   * Emit a governed recommendation to REDUCE escalation for a consistently-clean reversible class. This is
   * a RECOMMENDATION recorded for human authorization — never an auto-applied loosening. Returns the
   * assessment; records to governance if it's a reduce/increase recommendation.
   */
  recommend(gate: string): CalibrationAssessment {
    const a = this.assess(gate);
    if (a.recommendation !== "hold") {
      this.governance?.record({
        action: a.recommendation === "reduce-escalation-candidate" ? "oversight.recommend-reduce" : "oversight.recommend-scrutiny",
        actor: "oversight-calibration",
        policy: { effect: "warn", ruleId: "oversight-calibration", reason: a.reason, matchedRuleIds: ["oversight-calibration"], policyVersion: "1" },
        outcome: "warned-and-proceeded",
      });
    }
    return a;
  }
}
