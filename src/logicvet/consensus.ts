/**
 * Consensus + posture switch (Increment 3.8c) — the verdict function, done soundly.
 *
 * SOTA basis (2026-08-04):
 *  - "A menagerie of partial critics where consensus is verification" (arXiv 2402.08115) — BUT
 *    consensus is only trustworthy among INDEPENDENT critics; correlated LLM critics share blind
 *    spots (SAVeR arXiv 2604.08401). So the consensus rule here privileges SOUND (deterministic)
 *    critics: a plan is BLOCKED iff a sound critic blocks; fuzzy critics can only raise concerns.
 *  - Precision/recall is DOMAIN-TUNED (arXiv 2510.03469): STRICT (high-precision) for builds —
 *    reject on any unsound step; PERMISSIVE (high-recall) for brainstorming — only kill on internal
 *    contradiction or gross infeasibility, so divergent creative ideas aren't strangled.
 *
 * Zero deps.
 */

import type { CriticVerdict } from "./deterministic_critics.js";

/** The vetting posture — set from the ProjectLoop's task shape. */
export type VetPosture = "strict" | "permissive";

/** The overall verdict + why. */
export interface VetVerdict {
  readonly decision: "pass" | "rework" | "block";
  readonly posture: VetPosture;
  readonly reason: string;
  /** Which critics blocked/concerned (for audit + targeted rework). */
  readonly blocking: readonly CriticVerdict[];
  readonly concerns: readonly CriticVerdict[];
  /** Step ids to rework (rethink), deduped — never a global recheck. */
  readonly reworkTargets: readonly string[];
}

/**
 * Reduce a panel of critic verdicts to a decision.
 *
 * STRICT (build): any SOUND block → block. Any concern (sound or fuzzy) → rework. Else pass.
 * PERMISSIVE (brainstorm): only a SOUND block from the contradiction OR feasibility/constraint
 *   critic blocks (gross infeasibility / internal contradiction). Order/proportionality drop to
 *   concerns (divergent structure is allowed while exploring). Fuzzy concerns are informational.
 *
 * In BOTH postures: a fuzzy (non-sound) critic can NEVER block on its own — soundness gates.
 */
export function consensus(verdicts: readonly CriticVerdict[], posture: VetPosture): VetVerdict {
  const soundBlocks = verdicts.filter((v) => v.sound && v.status === "block");
  const allConcerns = verdicts.filter((v) => v.status === "concern");
  const fuzzyBlocks = verdicts.filter((v) => !v.sound && v.status === "block");
  // A fuzzy "block" is demoted to a concern (it cannot gate alone).
  const concerns = [...allConcerns, ...fuzzyBlocks.map((v) => ({ ...v, status: "concern" as const }))];

  if (posture === "strict") {
    if (soundBlocks.length > 0) {
      return {
        decision: "block",
        posture,
        reason: `sound critic(s) blocked: ${soundBlocks.map((v) => v.critic).join(", ")}`,
        blocking: soundBlocks,
        concerns,
        reworkTargets: dedupe(soundBlocks.flatMap((v) => v.implicated)),
      };
    }
    if (concerns.length > 0) {
      return {
        decision: "rework",
        posture,
        reason: `concern(s) from: ${concerns.map((v) => v.critic).join(", ")}`,
        blocking: [],
        concerns,
        reworkTargets: dedupe(concerns.flatMap((v) => v.implicated)),
      };
    }
    return { decision: "pass", posture, reason: "all critics pass (strict)", blocking: [], concerns: [], reworkTargets: [] };
  }

  // PERMISSIVE: only contradiction / constraint (gross infeasibility) sound-blocks actually block.
  const permissiveBlockers = soundBlocks.filter(
    (v) => v.critic === "contradiction" || v.critic === "constraint-satisfaction",
  );
  const demotedToConcern = soundBlocks.filter((v) => !permissiveBlockers.includes(v));
  const permissiveConcerns = [...concerns, ...demotedToConcern.map((v) => ({ ...v, status: "concern" as const }))];

  if (permissiveBlockers.length > 0) {
    return {
      decision: "block",
      posture,
      reason: `brainstorm blocked only on ${permissiveBlockers.map((v) => v.critic).join(", ")} (contradiction/gross-infeasibility)`,
      blocking: permissiveBlockers,
      concerns: permissiveConcerns,
      reworkTargets: dedupe(permissiveBlockers.flatMap((v) => v.implicated)),
    };
  }
  // In permissive mode, concerns are informational — do NOT force rework on divergent ideas.
  return {
    decision: "pass",
    posture,
    reason: permissiveConcerns.length > 0
      ? `passed (permissive): ${permissiveConcerns.length} informational concern(s), divergent ideas preserved`
      : "all critics pass (permissive)",
    blocking: [],
    concerns: permissiveConcerns,
    reworkTargets: [],
  };
}

function dedupe(a: readonly string[]): string[] {
  return [...new Set(a)];
}

/** Choose posture from the task shape (creative work → permissive; concrete build → strict). */
export function postureForTaskShape(taskShape: string): VetPosture {
  const creative = /\b(brainstorm|ideate|novel|story|creative|explore|research angle|premise|draft ideas)\b/i;
  return creative.test(taskShape) ? "permissive" : "strict";
}
