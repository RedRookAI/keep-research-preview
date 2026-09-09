/**
 * Action-tier gate (Phase 2) — the unifying principle.
 *
 * Gate by reversibility x blast-radius, NEVER uniformly (uniform gating manufactures
 * confirmation fatigue). Every action falls into one of four tiers, and the required
 * control follows from the tier — not from the agent's confidence:
 *
 *   1. read-only            -> run freely (no side effects)
 *   2. reversible-internal  -> act, but log enough to undo + audit
 *   3. external-touching     -> staging queue / confidence-gate
 *   4. irreversible          -> HUMAN APPROVAL, non-negotiable, regardless of confidence
 *
 * "High-confidence does not buy an agent the right to take an irreversible action
 * unsupervised." Keep's primary output is a PR — a stageable, rejectable tier-2/3
 * artifact — so Keep is reversible-by-default at the core.
 */

export type ActionTier = "read-only" | "reversible-internal" | "external-touching" | "irreversible";

/** The control an action requires before it may proceed. */
export type RequiredControl =
  | "run-freely"
  | "act-and-log"
  | "confidence-gate-or-stage"
  | "human-approval-required";

export interface ActionDescriptor {
  readonly name: string;
  readonly tier: ActionTier;
  /** True if a known inverse/compensating action exists (affects tier-3 handling). */
  readonly hasCompensatingAction?: boolean;
  /** True if the external action is idempotency-keyable (Round 8). */
  readonly idempotencyKeyable?: boolean;
}

/** The control required for an action, from its tier. Confidence never downgrades tier 4. */
export function requiredControl(action: ActionDescriptor): RequiredControl {
  switch (action.tier) {
    case "read-only":
      return "run-freely";
    case "reversible-internal":
      return "act-and-log";
    case "external-touching":
      return "confidence-gate-or-stage";
    case "irreversible":
      return "human-approval-required";
  }
}

/**
 * Whether an action may proceed autonomously given a (behavioral, calibrated)
 * confidence in [0,1] and the escalation threshold. Tier 4 NEVER proceeds
 * autonomously, regardless of confidence.
 */
export function mayProceedAutonomously(
  action: ActionDescriptor,
  calibratedConfidence: number,
  threshold: number,
): { proceed: boolean; reason: string } {
  switch (action.tier) {
    case "read-only":
      return { proceed: true, reason: "read-only: no side effects" };
    case "reversible-internal":
      return { proceed: true, reason: "reversible-internal: act and log to undo" };
    case "external-touching":
      if (calibratedConfidence >= threshold) {
        return { proceed: true, reason: `external: calibrated confidence ${calibratedConfidence.toFixed(2)} >= ${threshold}` };
      }
      return { proceed: false, reason: `external: confidence ${calibratedConfidence.toFixed(2)} < ${threshold} -> escalate` };
    case "irreversible":
      // The invariant: confidence is irrelevant here.
      return { proceed: false, reason: "irreversible: human approval required regardless of confidence" };
  }
}
