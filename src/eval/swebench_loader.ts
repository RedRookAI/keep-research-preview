/**
 * Z2 — SWE-BENCH DATASET LOADER (the operator-run seam to a real number).
 *
 * The eval instrument (harness/report/two-part oracle/decontamination) already exists and self-validates. What was
 * missing is the adapter that turns REAL SWE-bench records into the existing `EvalTask` contract. This is that
 * adapter — and nothing more: it PARSES + MAPS + DECONTAMINATES; it does not score (that is `judgeResolution`) and
 * it does not run (that needs a real provider + sandbox — the operator's step, carried forward as a caveat).
 *
 * Four hard properties (each disproof-backed):
 *   - COMPOSED: produces the existing `EvalTask`; reuses `decontaminate` (and, downstream, `judgeResolution`). No new oracle.
 *   - FORMAT-FAITHFUL: the real SWE-bench fields map to the two-part oracle's fields; a malformed record is REJECTED,
 *     never silently coerced into a half-valid task.
 *   - DECONTAMINATED: loaded tasks pass through the existing decontamination policy; a leakage-failing task is excluded.
 *   - HONEST: loading tasks is not running them. `LoadResult.caveats` carries the "a real run needs a real provider" note.
 */

import type { EvalTask } from "./swebench_task.js";
import { decontaminate, type DecontaminationPolicy, type DecontaminationResult } from "./decontamination.js";

/** The real SWE-bench record shape (as published on HF / in the JSONL). FAIL_TO_PASS/PASS_TO_PASS may be a JSON string OR an array. */
export interface SwebenchRecord {
  readonly instance_id?: unknown;
  readonly repo?: unknown;
  readonly base_commit?: unknown;
  readonly problem_statement?: unknown;
  readonly patch?: unknown; // the gold patch
  readonly test_patch?: unknown;
  readonly FAIL_TO_PASS?: unknown;
  readonly PASS_TO_PASS?: unknown;
  readonly created_at?: unknown;
  readonly version?: unknown;
}

export interface RejectedRecord {
  readonly record: SwebenchRecord;
  readonly reason: string;
}

export interface LoadResult {
  readonly tasks: readonly EvalTask[]; // decontaminated + admitted
  readonly malformed: readonly RejectedRecord[];
  readonly decontamination: DecontaminationResult;
  readonly caveats: readonly string[];
}

const LOAD_CAVEAT =
  "Loaded tasks are NOT a benchmark result — a resolved-rate requires running Keep's real solver (a real ModelProvider) " +
  "against each task's repo@base_commit in a sandbox, then scoring with judgeResolution.";

/** A required string field: present, a string, non-empty. Otherwise the record is malformed (rejected, not coerced). */
function reqStr(v: unknown): string | null {
  return typeof v === "string" && v.trim().length > 0 ? v : null;
}

/** SWE-bench encodes FAIL_TO_PASS/PASS_TO_PASS as either a JSON-string array or a real array of test-name strings. */
function parseTestList(v: unknown): readonly string[] | null {
  let arr: unknown = v;
  if (typeof v === "string") {
    try { arr = JSON.parse(v); } catch { return null; }
  }
  if (!Array.isArray(arr)) return null;
  if (!arr.every((x) => typeof x === "string" && x.length > 0)) return null;
  return arr as string[];
}

/** Parse one real SWE-bench record into an EvalTask, or return why it is malformed. */
export function parseRecord(record: SwebenchRecord): { task: EvalTask } | { reason: string } {
  const instanceId = reqStr(record.instance_id);
  if (instanceId === null) return { reason: "missing/invalid instance_id" };
  const repo = reqStr(record.repo);
  if (repo === null) return { reason: `${instanceId}: missing/invalid repo` };
  const baseCommit = reqStr(record.base_commit);
  if (baseCommit === null) return { reason: `${instanceId}: missing/invalid base_commit` };
  const problemStatement = reqStr(record.problem_statement);
  if (problemStatement === null) return { reason: `${instanceId}: missing/invalid problem_statement` };
  const failToPass = parseTestList(record.FAIL_TO_PASS);
  if (failToPass === null || failToPass.length === 0) return { reason: `${instanceId}: FAIL_TO_PASS missing/malformed (a task with no fail-to-pass test cannot be scored)` };
  const passToPass = parseTestList(record.PASS_TO_PASS);
  if (passToPass === null) return { reason: `${instanceId}: PASS_TO_PASS malformed` };

  const goldPatch = typeof record.patch === "string" ? record.patch : undefined;
  const testPatch = typeof record.test_patch === "string" && record.test_patch.length > 0 ? record.test_patch : undefined;
  const createdAt = typeof record.created_at === "string" ? record.created_at : undefined;
  const notes: string[] = [`repo=${repo}@${baseCommit}`];
  if (typeof record.test_patch === "string" && record.test_patch.length > 0) notes.push("has test_patch (applied before scoring)");
  if (typeof record.version === "string") notes.push(`version=${record.version}`);

  const task: EvalTask = {
    instanceId, repo, baseCommit, problemStatement, failToPass, passToPass,
    ...(goldPatch !== undefined ? { goldPatch } : {}),
    ...(testPatch !== undefined ? { testPatch } : {}),
    ...(createdAt !== undefined ? { createdAt } : {}),
    notes,
  };
  return { task };
}

/**
 * Load a batch of real SWE-bench records into decontaminated `EvalTask[]`. Malformed records are rejected (not
 * coerced); well-formed tasks pass through the EXISTING decontamination policy before admission.
 */
export function loadSwebenchTasks(records: readonly SwebenchRecord[], policy: DecontaminationPolicy = {}): LoadResult {
  const parsed: EvalTask[] = [];
  const malformed: RejectedRecord[] = [];
  for (const record of records) {
    const r = parseRecord(record);
    if ("task" in r) parsed.push(r.task);
    else malformed.push({ record, reason: r.reason });
  }
  const decontamination = decontaminate(parsed, policy);
  return { tasks: decontamination.admitted, malformed, decontamination, caveats: [LOAD_CAVEAT] };
}
