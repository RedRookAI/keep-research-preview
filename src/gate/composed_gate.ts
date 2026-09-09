/**
 * Composed gate (Build Step 2, layer 7) — the two-path routing decision.
 *
 * A pure, total function that fuses the three Step-2 verdicts + owner-presence into ONE
 * route: `auto-proceed` (through the REE) or `human-hold`. The composition rule is
 * DENY-OVERRIDES (XACML): if any single input is cautious, the result is human-hold,
 * regardless of the others — a veto is absolute and nothing can override it. The default
 * is DENY-UNLESS-PERMIT: human-hold unless every input positively clears, so an unknown or
 * missing input routes to human-hold, and the irreversible class requires POSITIVE
 * authorization (owner present) rather than a default-proceed.
 *
 * GROUNDING (research, 2026-08-08):
 *  - XACML deny-overrides / deny-unless-permit (OASIS): a single Deny wins over any Permit;
 *    the combined result is Deny unless something positively permits. This is the monotone
 *    meet-semilattice — combining can only move toward caution, never away.
 *  - Two-person rule / positive authorization for irreversible action (nuclear two-man
 *    rule, launch authorization): an irreversible step needs an affirmative authorization,
 *    not merely the absence of an objection.
 *  - Dead-man / owner-absent default: fail to a safe HOLD, not to proceed. Owner-absent on
 *    an irreversible action holds the action; it never auto-executes without authorization.
 *
 * SCOPE: this selects the PATH. The mechanisms named on the human-hold path — the timelock
 * queue, dual-control (two-key) authorization, and audited break-glass — are SEAMs here,
 * not built in this round. The existing oversight `decideMergeAuthority` is the in-env
 * consumer of the human-hold path.
 *
 * WHAT WOULD CHANGE IT: adding a new deny-capable input (e.g. a provenance check) extends
 * the veto set; it never adds a permit-override. Widening `autoProceedTiers` is an owner
 * policy choice, bounded to reversible classes. The composition rule itself does not change.
 */

import type { FloorVerdict } from "../floor/structural_floor.js";
import type { BudgetVerdict } from "../budget/budget_ledger.js";
import type { ActionTier } from "../control/action_tier.js";
import type { ConsequenceClass } from "../routing/uncertainty_router.js";
import { verificationConfidence, type VerificationSignals } from "../routing/verification_confidence.js";

export interface GateInputs {
  /** Floor verdict value; undefined ⇒ unknown ⇒ fail-safe veto. */
  readonly floor: FloorVerdict["verdict"] | undefined;
  /** Budget verdict value; undefined ⇒ unknown ⇒ fail-safe veto. */
  readonly budget: BudgetVerdict["verdict"] | undefined;
  /** Action reversibility class; undefined ⇒ unknown ⇒ fail-safe veto. */
  readonly actionTier: ActionTier | undefined;
  /** Is the owner present to give positive authorization? undefined ⇒ treated as absent. */
  readonly ownerPresent: boolean | undefined;
  /**
   * Effect provenance (Finding 2.6). "untrusted-derived" ⇒ deny-capable veto (force human-hold).
   * undefined ⇒ not assessed for this op (no veto) — ensuring it is ALWAYS assessed when untrusted
   * content is involved is the taint-tracer SEAM. "trusted" ⇒ no veto.
   */
  readonly provenance?: "trusted" | "untrusted-derived" | undefined;
  /**
   * Digital-twin verdict (layer 6). "mismatch" (the op's actual effect exceeds its declaration) ⇒
   * deny-capable veto (force human-hold). undefined ⇒ not previewed (no veto). "match" ⇒ no veto.
   */
  readonly twin?: "match" | "mismatch" | undefined;
  /**
   * AI-BOM verification (Core Addition B). `false` ⇒ the manifest of what produced this effect could
   * not be verified (missing or tampered) ⇒ deny-capable veto. undefined ⇒ not assessed (no veto).
   * `true` ⇒ verified, no veto.
   */
  readonly bomVerified?: boolean | undefined;
  /**
   * Acting agent identity liveness (Core Addition C). `false` ⇒ the effect's agent identity is
   * killed, unknown, or forged ⇒ deny-capable veto. undefined ⇒ not assessed (no veto). `true` ⇒ live.
   */
  readonly identityLive?: boolean | undefined;
  /**
   * Trusted-computing-base integrity (Core Addition A). `false` ⇒ the TCB drifted (a trusted module
   * changed / was added / removed, or gained a dependency) ⇒ deny-capable veto. undefined ⇒ not
   * assessed (no veto). `true` ⇒ intact.
   */
  readonly tcbIntact?: boolean | undefined;
  /**
   * VERIFY-CONFIDENCE (additive): a passing-but-LOW-confidence result on a CONSEQUENTIAL (non-reversible) action is a
   * deny-capable veto — it ADDS scrutiny (forces human-hold) but never lifts an existing veto and never overrides the
   * deterministic floor (a deterministic fail is already confidence 0). undefined ⇒ not assessed (no veto). Confidence
   * is a transparent function of {deterministic pass, rerun stability, cross-family agreement}, not a fabricated score.
   */
  readonly verification?: { readonly signals: VerificationSignals; readonly consequence: ConsequenceClass } | undefined;
}

export interface GatePolicy {
  /** Reversibility classes eligible for auto-proceed. Bounded to reversible classes. */
  readonly autoProceedTiers: readonly ActionTier[];
}

export type GateRoute = {
  readonly route: "auto-proceed" | "human-hold";
  readonly reasons: readonly string[];
};

/**
 * Compose. Deny-overrides: collect every cautious input as a veto reason; auto-proceed only
 * if there are none. Monotone — an added cautious input can only add reasons, never clear
 * them. Total — every field has a defined (fail-safe) treatment when unknown.
 */
export function composeGate(i: GateInputs, policy: GatePolicy): GateRoute {
  const reasons: string[] = [];

  // Floor: must positively say reversible-execute.
  if (i.floor === undefined) reasons.push("floor-unknown");
  else if (i.floor !== "reversible-execute") reasons.push(`floor-${i.floor}`);

  // Budget: must positively say within-budget.
  if (i.budget === undefined) reasons.push("budget-unknown");
  else if (i.budget !== "within-budget") reasons.push(`budget-${i.budget}`);

  // Reversibility class: must be on the auto-proceed (reversible) whitelist.
  if (i.actionTier === undefined) reasons.push("action-tier-unknown");
  else if (!policy.autoProceedTiers.includes(i.actionTier)) reasons.push(`non-auto-tier:${i.actionTier}`);

  // Positive-authorization rule: an irreversible action with the owner absent HOLDS.
  if (i.actionTier === "irreversible" && i.ownerPresent !== true) {
    reasons.push("owner-absent-irreversible-hold");
  }

  // Provenance (Finding 2.6): an untrusted-content-derived effect can never auto-proceed.
  if (i.provenance === "untrusted-derived") {
    reasons.push("untrusted-derived-provenance");
  }

  // Digital twin (layer 6): the op's actual effect exceeded its declaration → surprise → hold.
  if (i.twin === "mismatch") {
    reasons.push("digital-twin-mismatch");
  }

  // AI-BOM (Core Addition B): if the manifest of what produced this effect can't be verified, hold.
  if (i.bomVerified === false) {
    reasons.push("unverifiable-ai-bom");
  }

  // Per-agent identity (Core Addition C): an effect from a killed/unknown/forged identity is refused.
  if (i.identityLive === false) {
    reasons.push("killed-or-unknown-identity");
  }

  // Minimal-TCB integrity (Core Addition A): if the trusted core drifted, hold everything.
  if (i.tcbIntact === false) {
    reasons.push("tcb-drift");
  }

  // VERIFY-CONFIDENCE (additive scrutiny): low verification-confidence on a CONSEQUENTIAL (non-reversible) action holds
  // for extra scrutiny. Modulates escalation WITHIN the consequence gate — it can only ADD a veto, never remove one, and
  // a deterministic fail is already confidence 0 (soft signals never override the floor).
  if (i.verification !== undefined) {
    const vc = verificationConfidence(i.verification.signals);
    if (vc.band === "low" && i.verification.consequence !== "reversible") {
      reasons.push(`low-verification-confidence-on-consequential-action (score ${vc.score.toFixed(2)}; ${i.verification.consequence})`);
    }
  }

  if (reasons.length === 0) return { route: "auto-proceed", reasons: ["all-checks-permit"] };
  return { route: "human-hold", reasons };
}

/** Default policy: only the reversible classes auto-proceed; external-touching + irreversible hold. */
export function defaultGatePolicy(): GatePolicy {
  return { autoProceedTiers: ["read-only", "reversible-internal"] };
}
