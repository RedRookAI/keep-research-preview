/**
 * Shadow-mode gate — proactive pre-live safety.
 *
 * The negative-flip demotion  is REACTIVE — it catches a bad lesson only
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
  readonly evaluatedCases: number;
  readonly unavailableReason?: "empty-corpus" | "evaluator-error" | "invalid-result";
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
    const cases = [...this.corpus];
    const failedCases: string[] = [];
    let evaluatedCases = 0;
    let unavailableReason: ShadowResult["unavailableReason"] = cases.length === 0 ? "empty-corpus" : undefined;
    for (const c of cases) {
      let result: unknown;
      try { result = c.passesUnder(lessonContent); }
      catch { unavailableReason = "evaluator-error"; break; }
      if (typeof result !== "boolean") { unavailableReason = "invalid-result"; break; }
      evaluatedCases++;
      if (!result) failedCases.push(c.id);
    }
    const passed = unavailableReason === undefined && evaluatedCases > 0 && failedCases.length === 0;
    const result: ShadowResult = { lessonId, passed, failedCases, evaluatedCases,
      ...(unavailableReason === undefined ? {} : { unavailableReason }) };
    this.spine.stage({
      type: "identity.action",
      actor: "shadow-mode",
      payload: { event: "shadow_eval", ...result, ts: this.clock() },
    });
    return result;
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
