/**
 * Security-critical gate (SoD composition). The single enforcement point for privileged actions that reduce Keep's
 * safety margin — reducing escalation, lowering an isolation floor, promoting memory to global, disabling review.
 *
 * Two layers, both required (NIST AC-3(2) Dual Authorization, mapped in the SL5 AI Security Standard 2026):
 *  1. RBAC — does this principal even hold the permission for this action? (X0)
 *  2. Separation of Duties — dual control: N distinct approvers with author ≠ sole approver in multi-operator mode;
 *     in single-operator (N=1) mode a hardware-key STEP-UP substitutes for the absent second party. (Round 19)
 * Both the grant (via SoD's onApproval → spine) and every denial are audited, so the regulator-required "HITL
 * checkpoint technically enforced through authn/authz/audit" (EU AI Act Art. 14; China agent rules 2026) is met.
 *
 * What would change it: rotating approver duties (anti-collusion) and time-bounded approvals are refinements that
 * layer on without changing this gate's shape. Zero deps.
 */

import type { AuthorizationPort, Principal, Permission } from "./rbac.js";
import type { SeparationOfDuties, SecurityCriticalAction, ApprovalRecord } from "./identity.js";
import type { Spine } from "../spine/spine.js";

/** Which RBAC permission a principal must hold to even attempt each security-critical action. */
const PERMISSION_FOR: Partial<Record<SecurityCriticalAction, Permission>> = {
  "calibration.reduce_escalation": "calibration.authorize",
  "control.disable_review_or_killswitch_or_mergegate": "rbac.admin",
  "audit.config_change": "config.write",
  "policy.change_invariant": "config.write",
  "memory.promote_global": "config.write",
  "isolation.lower_floor": "config.write",
  "skill.approve_distribution": "config.write",
};

export interface SecurityGateDeps {
  readonly authorization: AuthorizationPort;
  readonly separationOfDuties: SeparationOfDuties;
  readonly spine: Spine;
}

export interface SecurityGateRequest {
  readonly action: SecurityCriticalAction;
  readonly author: Principal;
  /** The set of approvers (defaults to just the author — valid only in N=1 with step-up). */
  readonly approvers?: readonly string[];
  /** True when the author proved presence via a hardware key / re-auth (stands in for the second party in N=1). */
  readonly stepUpVerified: boolean;
  readonly now: number;
}

export interface SecurityGateOutcome {
  readonly ok: boolean;
  readonly reason?: string;
  readonly record?: ApprovalRecord;
}

/** Enforce RBAC then dual-control for a security-critical action. Never merges; only authorizes the action. */
export function authorizeSecurityCritical(deps: SecurityGateDeps, req: SecurityGateRequest): SecurityGateOutcome {
  // Layer 1 — RBAC.
  const perm = PERMISSION_FOR[req.action];
  if (perm && !deps.authorization.authorize(req.author, perm).allow) {
    deps.spine.stage({ type: "identity.action", actor: "security-gate", payload: { event: "authz.denied", who: req.author.id, role: req.author.role, action: req.action, layer: "rbac", reason: `role '${req.author.role}' lacks '${perm}'`, ts: req.now } });
    return { ok: false, reason: `your role (${req.author.role}) may not perform ${req.action}` };
  }
  // Layer 2 — Separation of Duties (dual control / step-up). SoD records the grant via its onApproval hook.
  try {
    const record = deps.separationOfDuties.authorize({
      action: req.action,
      author: req.author.id,
      approvers: req.approvers ?? [req.author.id],
      stepUpVerified: req.stepUpVerified,
      now: req.now,
    });
    return { ok: true, record };
  } catch (e) {
    deps.spine.stage({ type: "identity.action", actor: "security-gate", payload: { event: "sod.denied", who: req.author.id, action: req.action, layer: "sod", reason: (e as Error).message, ts: req.now } });
    return { ok: false, reason: (e as Error).message };
  }
}
