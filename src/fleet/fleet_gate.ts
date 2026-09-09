/**
 * Fleet composition point — the smallest hardening fix from the fleet-composition close-out review.
 *
 * The three fleet barriers (2.2 shared-resource, 2.3 joint-reversibility, 2.4 cross-agent taint) each
 * shipped a `*Admit(gateAutoProceed, check)` helper that pairs the gate with ONE fleet check. But there
 * was no single point requiring ALL THREE — so an integration could call one and structurally bypass the
 * other two (a fleet bypass), and separate helpers could mask each other's reasons. This is the fleet
 * analog of `composeGate`: ONE combinator that ANDs the per-decision gate + all three fleet checks under
 * deny-overrides, collecting ALL failing reasons (no masking).
 *
 * PROPERTIES (verified by the review tests):
 *  - deny-overrides: any single hold (gate OR any fleet barrier) ⇒ hold.
 *  - no masking: every failing reason is reported, not just the first.
 *  - never overrides the gate: a gate hold is always a hold, regardless of the fleet checks.
 *  - monotone toward caution: proceed ⟹ the gate auto-proceeds (a pure AND — the fleet layer can only
 *    ADD holds, never remove one).
 *  - fail-safe: each fleet check already fails closed on unknown state; the AND preserves that (any
 *    fail-closed ⇒ hold), so the three fail-safes compose to a fleet fail-closed.
 *
 * This introduces NO new barrier — it composes the three EXISTING fleet barriers, exactly as composeGate
 * composes the nine per-decision barriers. It does not modify the gate, the floor, or any barrier's logic.
 */

import type { ReserveResult } from "./shared_resource.js";
import type { JointCheck } from "./joint_reversibility.js";
import type { FlowCheck } from "./cross_agent_taint.js";
import type { CorrelationCheck } from "./fleet_correlation.js";

export interface FleetChecks {
  readonly reserve: ReserveResult;
  readonly jointReversibility: JointCheck;
  readonly crossAgent: FlowCheck;
  readonly correlation: CorrelationCheck;
}

export interface FleetAdmission {
  readonly proceed: boolean;
  /** Every reason the effect is held (empty iff it proceeds). No reason is masked. */
  readonly reasons: readonly string[];
}

/**
 * Compose the per-decision gate with all three fleet barriers. Proceeds iff the gate auto-proceeds AND
 * every fleet check clears; otherwise holds, reporting ALL failing reasons (deny-overrides, no masking).
 */
export function fleetAdmit(gateAutoProceed: boolean, checks: FleetChecks): FleetAdmission {
  const reasons: string[] = [];
  if (!gateAutoProceed) reasons.push("per-decision-gate-hold");
  if (!checks.reserve.granted) reasons.push(`fleet-2.2-${checks.reserve.reason}`);
  if (!checks.jointReversibility.ok) reasons.push(`fleet-2.3-${checks.jointReversibility.reason}`);
  if (!checks.crossAgent.clean) reasons.push(`fleet-2.4-${checks.crossAgent.reason}`);
  if (!checks.correlation.ok) reasons.push(`fleet-2.5-${checks.correlation.reason}`);
  return { proceed: reasons.length === 0, reasons };
}
