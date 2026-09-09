/**
 * Trajectory-drift checkpoint (Increment 16.8b).
 *
 * Second/third-order effects are a TRAJECTORY property, not only a pre-flight one: ~12% of long agent
 * runs carry a propagated error single-step evals never flag, and "each step looked locally reasonable"
 * (FutureAGI 2026; Latitude 2026). A one-shot pre-solve plan gate is necessary but NOT sufficient — the
 * produced patch can quietly do MORE than the plan approved. This checkpoint compares the patch's ACTUAL
 * effects against the effect classes the plan gate approved; if the patch introduces a higher-risk class
 * the plan did not approve (drift), it escalates to human EVEN IF the patch's own tests pass.
 *
 * This catches the canonical cascade chain: planner approves a small change → executor does more →
 * summariser reports success. Deterministic, model-free; reuses the one consequence taxonomy. Zero deps.
 */

import { deriveEffectsFromEdits, type EffectClass, type IntendedEffect } from "./plan_consequences.js";
import type { SearchReplaceEdit } from "../solve/issue_model.js";

/** Risk rank of an effect class (higher = more consequential). pure-code is the floor. */
const RISK_RANK: Record<EffectClass, number> = {
  "audit-tamper": 7,
  "filesystem-destructive": 6,
  "db-schema": 5,
  "network-egress": 4,
  "secret-credential": 4,
  "auth-access-control": 3,
  "dependency-config": 2,
  "pure-code": 0,
};

export interface TrajectoryDrift {
  readonly drifted: boolean;
  readonly decision: "pass" | "escalate";
  /** Effect classes the patch introduced that the plan did not approve (above pure-code). */
  readonly newClasses: readonly EffectClass[];
  readonly patchEffects: readonly IntendedEffect[];
  readonly reason: string;
}

/**
 * Compare a produced patch's effects against the plan-approved effect classes. Any NEW effect class in
 * the patch that (a) the plan did not approve and (b) is above the pure-code floor → drift → escalate.
 */
export function checkTrajectoryDrift(
  planApprovedClasses: readonly EffectClass[],
  edits: readonly SearchReplaceEdit[],
): TrajectoryDrift {
  const patchEffects = deriveEffectsFromEdits(edits.map((e) => ({ file: e.file, replace: e.replace })));
  const approved = new Set(planApprovedClasses);
  const newClasses: EffectClass[] = [];
  for (const eff of patchEffects) {
    if (eff.cls === "pure-code") continue;
    if (!approved.has(eff.cls) && !newClasses.includes(eff.cls)) newClasses.push(eff.cls);
  }
  // Sort worst-first for a readable reason.
  newClasses.sort((a, b) => RISK_RANK[b] - RISK_RANK[a]);
  if (newClasses.length > 0) {
    return {
      drifted: true,
      decision: "escalate",
      newClasses,
      patchEffects,
      reason: `patch introduces effect(s) the plan did not approve: ${newClasses.join(", ")} — trajectory drift, human review required even though tests pass`,
    };
  }
  return { drifted: false, decision: "pass", newClasses: [], patchEffects, reason: "patch effects stay within the plan-approved envelope" };
}
