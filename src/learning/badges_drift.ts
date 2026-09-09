/**
 * Lesson confidence badges (#8) + spec-drift detection (#9) — Phase 3.5 -> Phase 3.
 *
 * #8: surface which CONFIRMED lessons a change relied on, as a PR badge that feeds
 *     merge-readiness (#19). Only confirmed lessons earn a badge (probation lessons
 *     inform but don't claim authority).
 * #9: detect when a change has drifted from the approved spec intent — anchored to
 *     OBJECTIVE signal (the approved spec + test outcomes), NEVER agent-vs-agent
 *     (the anti-circular guardrail from vetting).
 */

import type { Lesson } from "../memory/model.js";

export interface LessonBadge {
  readonly confirmedCount: number;
  readonly lessonIds: readonly string[];
  readonly text: string;
}

/** Build a PR confidence badge from the lessons a change relied on (#8). */
export function buildLessonBadge(reliedOn: readonly Lesson[]): LessonBadge {
  const confirmed = reliedOn.filter((l) => l.tier === "confirmed");
  const lessonIds = confirmed.map((l) => l.id);
  const text =
    confirmed.length === 0
      ? "No confirmed lessons applied to this change."
      : `This change follows ${confirmed.length} confirmed lesson${confirmed.length === 1 ? "" : "s"}.`;
  return { confirmedCount: confirmed.length, lessonIds, text };
}

export interface SpecDriftInput {
  /** The human-approved spec intent (objective anchor). */
  readonly approvedIntent: string;
  /** Key requirement phrases the change MUST still satisfy. */
  readonly requiredCapabilities: readonly string[];
  /** The change summary / what was actually built. */
  readonly changeSummary: string;
  /** Did the change's tests (that encode the spec) pass? Objective signal. */
  readonly testsPass: boolean;
}

export interface SpecDriftResult {
  readonly drifted: boolean;
  /** Required capabilities not evidenced in the change (potential drift). */
  readonly missingCapabilities: readonly string[];
  readonly reason: string;
}

/**
 * Detect spec-drift by objective anchoring: a change has drifted if a required
 * capability from the approved spec is not evidenced OR the spec-encoding tests
 * fail. This never asks one agent to judge another — it checks against the
 * approved spec and test outcomes.
 */
export function detectSpecDrift(input: SpecDriftInput): SpecDriftResult {
  if (!input.testsPass) {
    return { drifted: true, missingCapabilities: [], reason: "spec-encoding tests fail (objective drift signal)" };
  }
  const summary = input.changeSummary.toLowerCase();
  const missing = input.requiredCapabilities.filter((cap) => !summary.includes(cap.toLowerCase()));
  if (missing.length > 0) {
    return {
      drifted: true,
      missingCapabilities: missing,
      reason: `required capabilities not evidenced in the change: ${missing.join(", ")}`,
    };
  }
  return { drifted: false, missingCapabilities: [], reason: "change satisfies approved intent + tests pass" };
}
