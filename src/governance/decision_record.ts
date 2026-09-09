/**
 * Governance decision record (Phase 5) — THE foundational artifact.
 *
 * Every framework (EU AI Act, NIST AI RMF, ISO 42001) demands the SAME artifact,
 * confirmed verbatim in 2026 guidance: "a continuous, machine-generated record that
 * links each AI decision to the governance policy applied and the enforcement
 * outcome, retained inside the organization's trust boundary."
 *
 * Keep is that control plane: each gated decision produces one record bound to a
 * spine event (hash-chained, tamper-evident, self-hosted), replayable on demand —
 * the continuous structured trail most orgs cannot produce when an auditor asks.
 */

import type { Spine } from "../spine/spine.js";
import type { PolicyDecision } from "./policy_engine.js";

export type EnforcementOutcome = "proceeded" | "blocked" | "escalated-to-human" | "warned-and-proceeded";

export interface GovernanceRecord {
  readonly decisionId: string;
  /** What the AI decision/action was. */
  readonly action: string;
  /** Who/what initiated it. */
  readonly actor: string;
  /** The policy decision applied (effect + rule + version). */
  readonly policy: PolicyDecision;
  /** What actually happened as a result — the enforcement outcome. */
  readonly outcome: EnforcementOutcome;
  /** The spine event id this record is bound to (provenance, tamper-evidence). */
  readonly spineEventId: string;
  readonly ts: number;
}

export class GovernanceLedger {
  constructor(
    private readonly spine: Spine,
    private readonly clock: () => number = () => Date.now(),
  ) {}

  /**
   * Record a governance decision: link the action -> the policy applied -> the
   * enforcement outcome, bound to a spine event. Returns the record.
   */
  record(params: {
    action: string;
    actor: string;
    policy: PolicyDecision;
    outcome: EnforcementOutcome;
  }): GovernanceRecord {
    const ts = this.clock();
    const spineEventId = this.spine.stage({
      type: "identity.action",
      actor: "governance",
      payload: {
        event: "governance.decision",
        action: params.action,
        initiator: params.actor,
        effect: params.policy.effect,
        ruleId: params.policy.ruleId,
        policyVersion: params.policy.policyVersion,
        matchedRuleIds: params.policy.matchedRuleIds,
        outcome: params.outcome,
        ts,
      },
    });
    return {
      decisionId: spineEventId,
      action: params.action,
      actor: params.actor,
      policy: params.policy,
      outcome: params.outcome,
      spineEventId,
      ts,
    };
  }

  /**
   * Read the full continuous governance trail back from the spine (deterministic
   * replay). This is what gets produced on demand for an auditor.
   */
  readTrail(): GovernanceRecord[] {
    const out: GovernanceRecord[] = [];
    for (const e of this.spine.currentEvents()) {
      const p = e.payload as Record<string, unknown>;
      if (p["event"] !== "governance.decision") continue;
      out.push({
        decisionId: e.id,
        action: String(p["action"]),
        actor: String(p["initiator"]),
        policy: {
          effect: p["effect"] as PolicyDecision["effect"],
          ruleId: String(p["ruleId"]),
          reason: "",
          matchedRuleIds: (p["matchedRuleIds"] as string[]) ?? [],
          policyVersion: String(p["policyVersion"]),
        },
        outcome: p["outcome"] as EnforcementOutcome,
        spineEventId: e.id,
        ts: Number(p["ts"] ?? e.ts),
      });
    }
    return out;
  }
}
