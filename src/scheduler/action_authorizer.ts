/**
 * AUTONOMY-POSTURE GUARD — external-action taxonomy + autonomous-spend cap.
 *
 * Keep's posture is autonomous-by-default, human-by-exception. That is only safe if there is a hard backstop on
 * what "autonomous" is allowed to touch. Two things bound it:
 *   1. EXTERNAL-EFFECT TAXONOMY — an action that reaches the outside world (send / publish / pay / deploy / delete)
 *      is categorically different from a local, in-workspace one. External effects can't be unsent, so they are
 *      NEVER done autonomously — they route to the human veto/gate regardless of confidence or cost.
 *   2. AUTONOMOUS-SPEND CAP — even a local action that SPENDS is blocked if it would exceed the run/period cap. A
 *      daily cap alone is insufficient ("$500/month still allows burning $500 in 20 minutes"), so the cap is a hard
 *      per-decision predicate backed by the real BudgetLedger — it BLOCKS, it never warns-and-proceeds.
 *
 * This composes machinery that already exists (it invents no new spend ledger and no new consequence model):
 *   - the external vocabulary is the `estimateConsequence` externality axis, partitioned by effect type;
 *   - the cap is the `BudgetLedger`-backed `canAfford` predicate (the same shape the resolution cascade uses);
 *   - the consequence comes from `estimateConsequence` / `ConsequenceClass`.
 *
 * Four hard properties (each disproof-backed):
 *   - TAXONOMIC: every action maps to exactly one external-effect class.
 *   - ENVELOPE-CONSISTENT: an external OR irreversible action is never autonomous, regardless of spend → veto.
 *   - CAP-BOUNDED: a local action whose spend would breach the cap is BLOCKED, never executed over budget.
 *   - COMPOSED: reuses the budget predicate + the consequence class; nothing reinvented.
 *
 * BUILT + proven in-env: the taxonomy + the authorize decision. SEAM: the `canAfford` predicate is backed by
 * `BudgetLedger.willBreach` at deploy (injected here for testability); the live wiring at the action-dispatch point
 * is the next increment. Zero deps.
 */

import type { ConsequenceClass } from "../routing/uncertainty_router.js";

/** The external-effect class of an action. `none` = local / in-workspace (no outside-world effect). */
export type ExternalClass = "none" | "send" | "publish" | "pay" | "deploy" | "delete";

export interface ActionDescriptor {
  readonly description: string;
  /** The consequence of the action (from estimateConsequence) — an irreversible action is never autonomous. */
  readonly consequence: ConsequenceClass;
  /** Projected USD cost of the action, if it spends. Absent/0 = no spend. */
  readonly costUsd?: number;
}

/** A hard spend predicate, backed by BudgetLedger.willBreach at deploy (injected in tests). BLOCKS, never warns. */
export interface SpendCap {
  canAfford(costUsd: number): boolean;
}

export type AutonomyVerdict = "autonomous" | "veto" | "blocked-over-cap";

export interface AuthorizeResult {
  readonly verdict: AutonomyVerdict;
  readonly externalClass: ExternalClass;
  readonly rationale: string;
}

// Effect patterns (the estimateConsequence external vocabulary, partitioned). Highest-stakes class wins.
const PAY_RX = /\b(pay|charge|purchase|buy|invoice|bill|transfer|wire|refund|checkout|subscribe)\b/i;
const DELETE_RX = /\b(delete|remove|drop|wipe|erase|destroy|purge|revoke|terminate)\b/i;
const DEPLOY_RX = /\b(deploy|rollout|roll out|provision|go live|production|prod)\b/i;
const PUBLISH_RX = /\b(publish|post|tweet|release|ship|launch|broadcast)\b/i;
const SEND_RX = /\b(send|email|e-mail|message|\bdm\b|submit|notify|reply to)\b/i;

/**
 * Classify an action's external-effect class. Exactly one class (precedence: pay > delete > deploy > publish >
 * send > none) so the taxonomy is total and unambiguous.
 */
export function classifyExternalAction(description: string): ExternalClass {
  if (PAY_RX.test(description)) return "pay";
  if (DELETE_RX.test(description)) return "delete";
  if (DEPLOY_RX.test(description)) return "deploy";
  if (PUBLISH_RX.test(description)) return "publish";
  if (SEND_RX.test(description)) return "send";
  return "none";
}

/** Any real external effect is never autonomous — only `none` (local) actions can be. */
function isExternal(cls: ExternalClass): boolean {
  return cls !== "none";
}

/**
 * Authorize (or refuse) an action for AUTONOMOUS execution. External or irreversible → veto (human decides);
 * local over the cap → blocked; local, reversible, within cap → autonomous.
 */
export function authorizeAutonomousAction(action: ActionDescriptor, cap: SpendCap): AuthorizeResult {
  const externalClass = classifyExternalAction(action.description);

  // ENVELOPE-CONSISTENT: a real external effect, or any irreversible action, is NEVER autonomous — route to veto.
  if (isExternal(externalClass) || action.consequence === "irreversible") {
    return {
      verdict: "veto",
      externalClass,
      rationale: isExternal(externalClass)
        ? `${externalClass} reaches the outside world — never autonomous, routed to the veto/gate`
        : "irreversible action — never autonomous, routed to the veto/gate",
    };
  }

  // CAP-BOUNDED: a local action that would breach the spend cap is BLOCKED (never executed over budget).
  const cost = action.costUsd ?? 0;
  if (cost > 0 && !cap.canAfford(cost)) {
    return { verdict: "blocked-over-cap", externalClass, rationale: `projected spend $${cost} would breach the autonomous cap — blocked` };
  }

  // Local, reversible, within cap → autonomous (the default).
  return { verdict: "autonomous", externalClass, rationale: "local, reversible, within the spend cap — proceed autonomously" };
}
