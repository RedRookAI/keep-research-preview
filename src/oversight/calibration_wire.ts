/**
 * Connects review decisions and post-approval outcomes to oversight calibration.
 *
 * Reduced escalation requires human authorization and remains revocable. Increased scrutiny can
 * revoke a reduction automatically. Only consistently clean, reversible histories can be candidates;
 * the router separately retains high-risk and forced-approval gates.
 * GitRevertSignalSource supplies local git outcomes; other tracker signals require configured adapters.
 */

import { OversightCalibration, type CalibrationAssessment } from "../pipeline/oversight_calibration.js";
import type { GovernanceLedger } from "../governance/decision_record.js";

/** An active, human-authorized, revocable reduced-escalation policy for one class. */
export interface CalibrationPolicy {
  readonly gate: string;
  readonly authorizedBy: string;
  readonly at: number;
}

export interface CalibrationWireConfig {
  readonly calibration?: OversightCalibration;
  readonly governance?: GovernanceLedger;
}

export class CalibrationWire {
  private readonly calibration: OversightCalibration;
  private readonly governance?: GovernanceLedger;
  private readonly policies = new Map<string, CalibrationPolicy>(); // active AUTHORIZED reductions
  private readonly pendingReduce = new Set<string>(); // classes with a reduce-candidate awaiting authorization

  constructor(cfg: CalibrationWireConfig = {}) {
    if (cfg.governance) this.governance = cfg.governance;
    this.calibration = cfg.calibration ?? new OversightCalibration(cfg.governance ? { governance: cfg.governance } : {});
  }

  /** Feed a human review decision (live, from the review flow). `gate` is the change's class key. */
  recordDecision(gate: string, reversible: boolean, approved: boolean): void {
    this.calibration.record(gate, reversible, approved);
  }

  /**
   * Feed a post-approval outcome (clean / reverted / failed). Drives the governed recommendation AND the
   * automatic tightening. NOT operator-invoked — called by the outcome seam. Returns the assessment.
   */
  observeOutcome(gate: string, outcome: "clean" | "reverted" | "failed"): CalibrationAssessment {
    this.calibration.recordOutcome(gate, outcome);
    const a = this.calibration.recommend(gate); // records the governed recommendation to the ledger
    if (a.recommendation === "increase-scrutiny") {
      // TIGHTEN automatically — revoke any active reduced-escalation policy for this class (safe direction).
      this.revoke(gate, `auto-revoked: revert/fail rate rose to ${(a.revertRate * 100).toFixed(0)}% — tightening (automatic, safe direction)`);
      this.pendingReduce.delete(gate);
    } else if (a.recommendation === "reduce-escalation-candidate") {
      this.pendingReduce.add(gate); // awaits HUMAN authorization — never auto-applied
    }
    return a;
  }

  /** Classes with a governed reduce-escalation proposal awaiting human authorization. */
  pendingReductions(): readonly string[] {
    return [...this.pendingReduce];
  }

  /**
   * HUMAN action: authorize a pending reduce-escalation proposal for a class → an active, revocable, audited
   * policy. Loosening is ALWAYS human-authorized + governed. No-op (returns null) unless a candidate is
   * actually pending for that class (a human cannot loosen a class the outcomes don't support).
   */
  authorizeReduction(gate: string, actor: string, now = Date.now()): CalibrationPolicy | null {
    if (!this.pendingReduce.has(gate)) return null;
    const policy: CalibrationPolicy = { gate, authorizedBy: actor, at: now };
    this.policies.set(gate, policy);
    this.pendingReduce.delete(gate);
    this.governance?.record({
      action: "oversight.authorize-reduce",
      actor,
      policy: { effect: "allow", ruleId: "oversight-calibration-authorized", reason: `human-authorized reduced escalation for reversible class '${gate}' (governed, revocable)`, matchedRuleIds: ["oversight-calibration-authorized"], policyVersion: "1" },
      outcome: "proceeded",
    });
    return policy;
  }

  /** Revoke an active policy (human OR automatic tightening). Audited. Returns whether one was active. */
  revoke(gate: string, reason: string, actor = "oversight-calibration"): boolean {
    if (!this.policies.has(gate)) return false;
    this.policies.delete(gate);
    this.governance?.record({
      action: "oversight.revoke-reduce",
      actor,
      policy: { effect: "deny", ruleId: "oversight-calibration-revoke", reason, matchedRuleIds: ["oversight-calibration-revoke"], policyVersion: "1" },
      outcome: "proceeded",
    });
    return true;
  }

  /** The classes with an ACTIVE authorized reduced-escalation policy — consumed by the OversightRouter. */
  activePolicyGates(): ReadonlySet<string> {
    return new Set(this.policies.keys());
  }
}
