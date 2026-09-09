/**
 * Decontamination (Increment 4.1) — the contamination controls that make a SWE-bench-style resolved-rate TRUSTWORTHY.
 *
 * The 2026 literature is blunt that a raw number is inflated by three leakage sources, so a credible eval must EXCLUDE
 * contaminated instances before scoring, and report how many it excluded and why:
 *   1. Temporal leakage — >94% of SWE-bench Verified issues predate leading models' training cutoffs, so the model may
 *      have memorised the fix. Fix (SWE-rebench / SWE-bench-Live): keep only tasks created AFTER the model's cutoff.
 *   2. Solution leakage — ~1/3 of Verified issues contain the fix's code verbatim in the problem statement, letting a
 *      model copy rather than synthesize. Fix: reject tasks whose gold-patch added lines appear in the problem text.
 *   3. Known-eval reuse — a task that appears in a public benchmark split a model may have trained on. Fix: exclude ids
 *      on a known-eval denylist.
 *
 * SOTA basis (2026-08-08): temporal decontamination (SWE-rebench arXiv 2505.20411, SWE-bench-Live), the solution/oracle
 * leakage findings on Verified, and Scale's "non-contamination by design". What would change it: a maintained public
 * denylist / a dataset that ships per-instance created-at dates would tighten these gates further.
 *
 * Zero deps. This does NOT weaken the resolved-rate oracle — it decides which instances are ELIGIBLE to be scored.
 */

import type { EvalTask } from "./swebench_task.js";

export interface DecontaminationPolicy {
  /** ISO date of the solver model's training cutoff. Tasks created ON/BEFORE it are rejected (temporal leakage). */
  readonly modelCutoff?: string;
  /** Instance ids known to appear in public eval splits a model may have trained on. */
  readonly knownEvalIds?: ReadonlySet<string>;
  /** Reject if this fraction (0..1) of the gold patch's added lines appear in the problem statement. Default 0.5. */
  readonly maxLeakageOverlap?: number;
}

export interface RejectedTask {
  readonly task: EvalTask;
  readonly reasons: readonly string[];
}
export interface DecontaminationResult {
  readonly admitted: readonly EvalTask[];
  readonly rejected: readonly RejectedTask[];
  /** Human-readable counts by reason (for the honest report). */
  readonly excludedByReason: Readonly<Record<string, number>>;
}

/** Added ("+") non-trivial code lines from a unified-diff gold patch, normalized for comparison. */
function goldAddedLines(goldPatch: string): string[] {
  return goldPatch
    .split(/\r?\n/)
    .filter((l) => l.startsWith("+") && !l.startsWith("+++"))
    .map((l) => l.slice(1).trim())
    .filter((l) => l.length >= 8 && !/^[)}\]{(;,]+$/.test(l)); // skip trivial punctuation-only lines
}

/** Fraction of the gold patch's added lines that appear (normalized substring) in the problem statement. */
export function solutionLeakageOverlap(task: EvalTask): number {
  if (!task.goldPatch) return 0;
  const added = goldAddedLines(task.goldPatch);
  if (added.length === 0) return 0;
  const problem = task.problemStatement.replace(/\s+/g, " ").toLowerCase();
  const leaked = added.filter((line) => problem.includes(line.replace(/\s+/g, " ").toLowerCase()));
  return leaked.length / added.length;
}

/**
 * Partition tasks into those ELIGIBLE to be scored and those excluded (with reasons). A task is admitted only if it
 * passes every configured gate; the report should surface the exclusions so the resolved-rate is over a decontaminated
 * denominator, not a contaminated one.
 */
export function decontaminate(tasks: readonly EvalTask[], policy: DecontaminationPolicy = {}): DecontaminationResult {
  const maxOverlap = policy.maxLeakageOverlap ?? 0.5;
  const admitted: EvalTask[] = [];
  const rejected: RejectedTask[] = [];
  const excludedByReason: Record<string, number> = {};
  const bump = (r: string): void => { excludedByReason[r] = (excludedByReason[r] ?? 0) + 1; };

  for (const task of tasks) {
    const reasons: string[] = [];

    // 1) Temporal: reject tasks created on/before the model cutoff (possible memorisation).
    if (policy.modelCutoff && task.createdAt && task.createdAt <= policy.modelCutoff) {
      reasons.push("temporal-leakage: created on/before the model cutoff");
    }
    // 2) Known-eval reuse.
    if (policy.knownEvalIds?.has(task.instanceId)) {
      reasons.push("known-eval: instance appears in a public eval split");
    }
    // 3) Solution leakage: the fix's code appears in the problem statement.
    if (task.goldPatch && solutionLeakageOverlap(task) > maxOverlap) {
      reasons.push("solution-leakage: gold-patch code present in the problem statement");
    }

    if (reasons.length === 0) admitted.push(task);
    else { rejected.push({ task, reasons }); for (const r of reasons) bump(r.split(":")[0]!); }
  }

  return { admitted, rejected, excludedByReason };
}
