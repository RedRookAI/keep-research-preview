/**
 * R2 (BA-2) — EVAL RUN DRIVER. The one thing standing between the built-and-proven instrument (loader + two-part
 * oracle + report) and a run is a driver that SEQUENCES them. This is that driver — and nothing more: it parses +
 * decontaminates real SWE-bench records into the existing `EvalTask` contract, runs the ADMITTED tasks through an
 * INJECTED `InstanceRunner`, aggregates with `computeReport`, and surfaces the honest denominator (malformed +
 * decontamination ledger). It composes `loadSwebenchTasks` + `runSuite` + `computeReport`; it invents no loader,
 * oracle, or aggregator.
 *
 * HONEST SCOPE: the runner is INJECTED. A synthetic/local runner gives a self-test today (n=1); an official
 * SWE-bench Verified number needs the real repo-materializing runner (seam S-1: clone repo@base_commit, apply
 * test_patch, sandbox), which this driver deliberately does NOT fabricate. The injected-runner caveat is carried
 * into the report so no number produced here is mistaken for an official score.
 */

import { loadSwebenchTasks, type SwebenchRecord, type RejectedRecord } from "./swebench_loader.js";
import { runSuite, type InstanceRunner } from "./harness.js";
import { computeReport, type EvalReport } from "./report.js";
import type { DecontaminationPolicy, DecontaminationResult } from "./decontamination.js";
import type { Spine } from "../spine/spine.js";

const INJECTED_RUNNER_CAVEAT =
  "Run through an INJECTED InstanceRunner — an official SWE-bench Verified number requires the real repo-materializing " +
  "runner (seam S-1: clone repo@base_commit, apply test_patch, sandbox). This report reflects the injected runner's " +
  "verdicts, NOT an official score.";

export interface LoadedEvalResult {
  readonly report: EvalReport;
  /** Records rejected at load for bad shape (never run, never scored). */
  readonly malformed: readonly RejectedRecord[];
  /** The decontamination ledger — the resolved-rate is over the ADMITTED (decontaminated) denominator. */
  readonly decontamination: DecontaminationResult;
}

/**
 * Load a batch of real SWE-bench records, run the admitted+decontaminated tasks through the injected runner, and
 * aggregate into a report. The denominator is the admitted set (malformed + leaked are excluded before running).
 */
export async function runLoadedEvalSuite(
  records: readonly SwebenchRecord[],
  runner: InstanceRunner,
  policy: DecontaminationPolicy,
  spine: Spine,
  suiteName = "swebench-loaded",
): Promise<LoadedEvalResult> {
  // (1) parse + decontaminate real-format records into the existing EvalTask contract.
  const loaded = loadSwebenchTasks(records, policy);
  // (2) run ONLY the admitted (decontaminated) tasks through the injected runner — the real-repo runner is seam S-1.
  const runs = await runSuite(loaded.tasks, runner, spine);
  // (3) aggregate; carry the loader's "loading ≠ a number" caveat AND the injected-runner caveat forward.
  const report = computeReport(suiteName, runs, [...loaded.caveats, INJECTED_RUNNER_CAVEAT]);
  // (4) surface the malformed records + the decontamination ledger so the denominator is honest.
  return { report, malformed: loaded.malformed, decontamination: loaded.decontamination };
}
