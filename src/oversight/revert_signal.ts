/**
 * GitRevertSignalSource (Increment 3.1) — retires the calibration "revert/reopened SIGNAL SOURCE" seam.
 *
 * The oversight calibration loop learns from post-approval outcomes: a merge that later gets reverted is evidence the
 * gate that cleared it was too loose. Until now the outcome signal (clean / reverted) was a VERIFIED-SEAM supplied at
 * deployment. This sources it FOR REAL from local git history: `git revert` writes a commit whose body contains
 * "This reverts commit <full-sha>", so scanning the log maps each merged change to reverted-or-clean with zero deps.
 *
 * This closes a genuine loop: Keep's own GitMergePort (autonomous-merge) produces the merge commits, and its auto-revert
 * (or a human's `git revert`) produces the revert commits — this source reads them back and feeds calibration, which
 * AUTO-TIGHTENS scrutiny on a class whose revert rate rose (the safe direction).
 *
 * SOTA basis (2026-08-08): revert (not reset) is Keep's rollback primitive, so a reverted merge always leaves a durable,
 * greppable "This reverts commit <sha>" trailer in history — a reliable, tamper-evident signal. What would change it: a
 * hosted forge's merge/revert webhooks could feed the same observeOutcome() at deployment (the prod swap), but the local
 * git history is the authoritative source and needs no external service.
 */

import type { GitAdapter } from "../infra/git_adapter.js";
import type { CalibrationWire } from "./calibration_wire.js";
import type { CalibrationAssessment } from "../pipeline/oversight_calibration.js";
import type { Spine } from "../spine/spine.js";

/** A merge Keep made, tagged with the gate/class that cleared it (so a later revert attributes to that gate). */
export interface TrackedMerge {
  /** The merge commit SHA (GitMergePort's mergeId). */
  readonly mergeSha: string;
  /** The oversight gate/class that approved the change (calibration attributes the outcome here). */
  readonly gate: string;
}

export interface RevertScanResult {
  readonly gate: string;
  readonly mergeSha: string;
  readonly outcome: "clean" | "reverted";
  readonly assessment: CalibrationAssessment;
}

export class GitRevertSignalSource {
  constructor(
    private readonly git: GitAdapter,
    private readonly wire: CalibrationWire,
    private readonly spine?: Spine,
  ) {}

  /** All full SHAs referenced by "This reverts commit <sha>" trailers in the current history. */
  private async revertedShas(): Promise<Set<string>> {
    const out = new Set<string>();
    // %H starts each commit; %B is the raw body. A generous window; zero-dep single call.
    const res = await this.git.git(["log", "--format=%B%x00", "-n", "2000"]);
    for (const m of res.stdout.matchAll(/This reverts commit ([0-9a-f]{7,40})/g)) {
      out.add(m[1]!);
    }
    return out;
  }

  /**
   * Reconcile tracked merges against real history: each merge whose SHA appears in a revert trailer is a "reverted"
   * outcome; the rest are "clean". Feeds calibration.observeOutcome for each and returns the per-merge assessments.
   * Matching is prefix-aware (a revert may reference an abbreviated SHA).
   */
  async reconcile(merges: readonly TrackedMerge[]): Promise<readonly RevertScanResult[]> {
    const reverted = await this.revertedShas();
    const isReverted = (sha: string): boolean => {
      for (const r of reverted) {
        if (sha === r || sha.startsWith(r) || r.startsWith(sha)) return true;
      }
      return false;
    };

    const results: RevertScanResult[] = [];
    for (const m of merges) {
      const outcome: "clean" | "reverted" = isReverted(m.mergeSha) ? "reverted" : "clean";
      const assessment = this.wire.observeOutcome(m.gate, outcome);
      this.spine?.stage({
        type: "identity.action", actor: "revert-signal",
        payload: { event: "post_approval_outcome", gate: m.gate, mergeSha: m.mergeSha, outcome, revertRate: assessment.revertRate, recommendation: assessment.recommendation },
      });
      results.push({ gate: m.gate, mergeSha: m.mergeSha, outcome, assessment });
    }
    return results;
  }
}
