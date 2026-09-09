/**
 * Shadow-mode gate (Phase 3.5, Round 16) — proactive pre-live safety.
 *
 * The negative-flip demotion (Phase 1) is REACTIVE — it catches a bad lesson only
 * after it has already hurt live PRs. Shadow-mode is PROACTIVE: a newly-graduated
 * lesson runs first against a held-out regression corpus, and is AUTO-REVOKED
 * (demoted back to probation) if applying it would reintroduce any held-out
 * regression — before it can influence a single live PR.
 */

import type { Spine } from "../spine/spine.js";

/** A held-out regression case: applying a bad lesson should NOT break it. */
export interface RegressionCase {
  readonly id: string;
  /** The check: given the lesson content, returns true if the case still passes. */
  readonly passesUnder: (lessonContent: string) => boolean;
}

export interface ShadowResult {
  readonly lessonId: string;
  readonly passed: boolean;
  readonly failedCases: readonly string[];
}

export class ShadowModeGate {
  constructor(
    private readonly spine: Spine,
    private readonly corpus: readonly RegressionCase[],
    private readonly clock: () => number = () => Date.now(),
  ) {}

  /**
   * Evaluate a lesson in shadow against the held-out corpus. Returns pass/fail and
   * the failing case ids. Records the shadow run to the spine.
   */
  evaluate(lessonId: string, lessonContent: string): ShadowResult {
    const failedCases: string[] = [];
    for (const c of this.corpus) {
      if (!c.passesUnder(lessonContent)) failedCases.push(c.id);
    }
    const passed = failedCases.length === 0;
    this.spine.stage({
      type: "identity.action",
      actor: "shadow-mode",
      payload: { event: "shadow_eval", lessonId, passed, failedCases, ts: this.clock() },
    });
    return { lessonId, passed, failedCases };
  }

  /**
   * Gate: a lesson is live-eligible only if it passes shadow evaluation. On failure,
   * `onRevoke` is called (e.g. demote the lesson back to probation). Returns whether
   * the lesson is cleared for live use.
   */
  gate(lessonId: string, lessonContent: string, onRevoke: (lessonId: string) => void): boolean {
    const result = this.evaluate(lessonId, lessonContent);
    if (!result.passed) {
      onRevoke(lessonId);
      this.spine.stage({
        type: "identity.action",
        actor: "shadow-mode",
        payload: { event: "lesson_auto_revoked", lessonId, failedCases: result.failedCases },
      });
      return false;
    }
    return true;
  }
}
