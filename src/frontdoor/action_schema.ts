/**
 * F1.5 — Action schema (what the LLM is allowed to PROPOSE).
 *
 * The LLM never emits free-form commands; it proposes a typed ProposedAction from a
 * fixed menu. Each action's ActionTier (reversibility x blast-radius, from Phase 2)
 * is assigned DETERMINISTICALLY by classifyProposedAction — NOT by asking the model.
 *
 * This encodes the hard 2026 lesson (arXiv 2605.11360, and the Cursor/Antigravity/
 * Kiro/OpenClaw production-deletion incidents): system-prompt rules are NOT a safety
 * boundary. An agent told "never delete the database" still did. So "is this
 * destructive?" is decided by the action's KIND, structurally, and destructive kinds
 * are pinned to irreversible -> human-approval-required with no path for the model to
 * downgrade them.
 */

import type { ActionTier, ActionDescriptor } from "../control/action_tier.js";

/** The kinds of action the onboarding/runtime LLM may propose. Extend deliberately. */
export type ActionKind =
  // --- reversible-internal: auto-approve after vetting ---
  | "capture_goal" // record a goal/context as a probation directive
  | "set_preference" // e.g. tone, check-in frequency
  | "note_project" // record project metadata
  | "start_background_research" // kick off self-learning on a topic (internal, revocable)
  | "index_uploaded_file" // RAG-index a file the human already gave us
  // --- external-touching: confidence-gated ---
  | "bind_channel" // connect Slack/Telegram/web (external creds involved)
  | "request_file_access" // ask to read a path/drive (scope-limited)
  | "suggest_runtime" // propose OpenClaw/Hermes (a suggestion, not an action)
  // --- irreversible / destructive: ALWAYS human-approval-required ---
  | "delete_data"
  | "drop_database"
  | "revoke_access"
  | "spend_money"
  | "send_external_comms"
  | "deploy_production"
  | "grant_broad_scope"; // widening the agent's own permissions

export interface ProposedAction {
  readonly kind: ActionKind;
  /** Structured, validated args (never a raw command string). */
  readonly args: Readonly<Record<string, unknown>>;
  /** The LLM's plain-language description of what it wants to do + why. */
  readonly rationale: string;
}

/** Destructive/irreversible kinds — pinned, non-downgradable. */
const IRREVERSIBLE_KINDS: ReadonlySet<ActionKind> = new Set<ActionKind>([
  "delete_data",
  "drop_database",
  "revoke_access",
  "spend_money",
  "send_external_comms",
  "deploy_production",
  "grant_broad_scope",
]);

const EXTERNAL_KINDS: ReadonlySet<ActionKind> = new Set<ActionKind>([
  "bind_channel",
  "request_file_access",
]);

const TIER_BY_KIND: Record<ActionKind, ActionTier> = {
  capture_goal: "reversible-internal",
  set_preference: "reversible-internal",
  note_project: "reversible-internal",
  start_background_research: "reversible-internal",
  index_uploaded_file: "reversible-internal",
  bind_channel: "external-touching",
  request_file_access: "external-touching",
  suggest_runtime: "read-only", // a suggestion has no side effect until accepted
  delete_data: "irreversible",
  drop_database: "irreversible",
  revoke_access: "irreversible",
  spend_money: "irreversible",
  send_external_comms: "irreversible",
  deploy_production: "irreversible",
  grant_broad_scope: "irreversible",
};

/**
 * Deterministically classify a proposed action into an ActionDescriptor. The tier
 * comes from the action's KIND, never from the model's say-so. Unknown kinds are
 * treated as irreversible (fail-safe: the safest assumption for something we can't
 * classify).
 */
export function classifyProposedAction(action: ProposedAction): ActionDescriptor {
  const tier = TIER_BY_KIND[action.kind] ?? "irreversible";
  return {
    name: action.kind,
    tier,
    // Reversible-internal actions have a compensating action by construction.
    hasCompensatingAction: tier === "reversible-internal",
    // External bindings are idempotency-keyable.
    idempotencyKeyable: EXTERNAL_KINDS.has(action.kind),
  };
}

/** True if this kind is a hard-pinned irreversible/destructive action. */
export function isDestructiveKind(kind: ActionKind): boolean {
  return IRREVERSIBLE_KINDS.has(kind);
}

/** True if the kind is a known, allowed action (schema validation for LLM output). */
export function isKnownActionKind(kind: string): kind is ActionKind {
  return kind in TIER_BY_KIND;
}
