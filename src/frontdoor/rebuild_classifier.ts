/**
 * F3b — Rebuild classifier (the additive/destructive line, enforced structurally).
 *
 * Operator's locked rule: revisions are ADDITIVE by default (supersede, old version
 * retained + restorable), but anything that would DELETE or OVERWRITE real work —
 * files, code, prior build output, deployed state — is DESTRUCTIVE and needs a human
 * tap. Per the Cursor-deleted-the-prod-DB lesson, the destructive line is decided by
 * DETERMINISTIC classification of the request's target, never by trusting the model.
 *
 * This maps a "change/rebuild" request to a ProposedAction the F1.5 gate then judges:
 *   - pure belief/directive/plan/understanding revision -> reversible action
 *     (the RevisionStore does the non-destructive supersede)
 *   - delete/overwrite of real work -> a destructive ActionKind -> human tap
 */

import type { ProposedAction, ActionKind } from "./action_schema.js";

export interface RebuildRequest {
  /** The human's phrasing of what they want changed/rebuilt. */
  readonly text: string;
  /** What the change targets, if known: a directive/plan (soft) or real work (hard). */
  readonly target?: "directive" | "plan" | "understanding" | "preference" | "files" | "code" | "build-output" | "deployment";
}

export interface RebuildClassification {
  /** True if this is a pure, reversible revision (revision store handles it). */
  readonly isPureRevision: boolean;
  /** The action to feed the gate (reversible for revisions, destructive for real-work deletion). */
  readonly action: ProposedAction;
  /** Plain-language description of what will happen. */
  readonly summary: string;
}

/** Targets that represent REAL WORK — deleting/overwriting them is destructive. */
const REAL_WORK_TARGETS = new Set(["files", "code", "build-output", "deployment"]);

/** Verbs that imply destruction/overwrite rather than additive revision. */
const DESTRUCTIVE_VERBS = /\b(delete|remove|wipe|erase|drop|destroy|overwrite|replace the (files|code)|throw away|start over from scratch and delete|reset|revert the (files|code))\b/i;

/** Verbs that imply an additive change of mind (revise, not destroy). */
const REVISION_VERBS = /\b(change|revise|update|adjust|rethink|redo|rebuild|different|instead|actually|new plan|change my mind)\b/i;

/**
 * Classify a rebuild request. Deterministic: if the target is real work OR the phrasing
 * is destructive toward real work, it's a destructive action (human tap). Otherwise a
 * pure revision (reversible, handled additively).
 */
export function classifyRebuild(req: RebuildRequest): RebuildClassification {
  const target = req.target;
  const mentionsDestruction = DESTRUCTIVE_VERBS.test(req.text);
  const targetsRealWork = target !== undefined && REAL_WORK_TARGETS.has(target);

  // Destructive path: deleting/overwriting real work.
  if (targetsRealWork && (mentionsDestruction || target === "deployment")) {
    const kind = destructiveKindFor(target);
    return {
      isPureRevision: false,
      action: { kind, args: { target, request: req.text }, rationale: `Human asked to change work that can't be auto-undone (${target}).` },
      summary: `This would change or remove real work (${target}), which can't be undone automatically — I'll ask you to confirm first.`,
    };
  }

  // If the phrasing is destructive but the target is unknown, fail safe to destructive.
  if (mentionsDestruction && target === undefined) {
    return {
      isPureRevision: false,
      action: { kind: "delete_data", args: { request: req.text }, rationale: "Destructive phrasing with an unclear target — treating as destructive to be safe." },
      summary: "That sounds like it might remove something that can't be undone, so I'll check with you before doing anything.",
    };
  }

  // Pure, additive revision.
  return {
    isPureRevision: true,
    action: { kind: revisionKindFor(target), args: { target: target ?? "directive", request: req.text }, rationale: "An additive revision — the previous version is kept and can be restored." },
    summary: "I'll update this and keep the previous version so you can go back any time.",
  };
}

function destructiveKindFor(target: string): ActionKind {
  switch (target) {
    case "deployment":
      return "deploy_production";
    case "files":
    case "code":
    case "build-output":
    default:
      return "delete_data";
  }
}

function revisionKindFor(target?: string): ActionKind {
  // A revision of a directive/preference is captured as a reversible internal action.
  return target === "preference" ? "set_preference" : "capture_goal";
}
