/**
 * Eval harness (Increment 16b) — run one instance end-to-end.
 *
 * Pipeline per instance: build an instance-scoped SolvePipeline (real solve: localize→plan→apply→
 * validate→repair→PR proposal), then execute the fail-to-pass + pass-to-pass tests against the patched
 * tree and judge via the two-part oracle (16a). Records cost + trajectory to the spine (tamper-evident,
 * auditable — Keep's differentiator vs a leaderboard boast). Benchmark-agnostic: the synthetic suite
 * runs it here under the replay model; real SWE-bench Verified/Pro adapters run it on Hetzner behind the
 * same TaskSource port. Latency-to-first-patch + failure class are recorded (variance/cost signals the
 * 2026 SOTA says matter more than peak score). Zero deps.
 */

import type { Spine } from "../spine/spine.js";
import type { SolveResult } from "../solve/issue_model.js";
import { judgeResolution, type EvalTask, type TestExecution, type ResolutionVerdict } from "./swebench_task.js";

/** How the harness runs an instance's solve + tests. Provided by the suite (synthetic) or Hetzner adapter. */
export interface InstanceRunner {
  /**
   * Solve the task (run the SolvePipeline against an instance-scoped tree/runner/model) and return the
   * SolveResult. The tree passed to the pipeline must already be at baseCommit.
   */
  solve(task: EvalTask): Promise<SolveResult>;
  /**
   * After solve, execute the named tests against the (patched) tree and report pass/fail per test.
   * Must run BOTH the fail-to-pass and pass-to-pass sets. A test that cannot run is reported false.
   */
  runTests(task: EvalTask, testNames: readonly string[]): Promise<TestExecution>;
  /** Estimated USD cost of the solve (tokens + infra). Optional; 0 if unknown. */
  costUsd?(task: EvalTask, result: SolveResult): number;
}

export type FailureClass =
  | "resolved"
  | "gave-up" // pipeline never produced a patch
  | "fix-incomplete" // patch produced, fail-to-pass still failing
  | "regression" // patch produced, pass-to-pass broke
  | "fix-incomplete+regression";

export interface InstanceRun {
  readonly instanceId: string;
  readonly verdict: ResolutionVerdict;
  readonly solveResult: SolveResult;
  readonly failureClass: FailureClass;
  readonly costUsd: number;
  readonly latencyMs: number;
  /** The stages the solver actually ran (trajectory). */
  readonly stagesRun: readonly string[];
  readonly repairRounds: number;
}

/** Run a single instance end-to-end and record it to the spine. */
export async function runInstance(task: EvalTask, runner: InstanceRunner, spine: Spine, now: () => number = () => Date.now()): Promise<InstanceRun> {
  const started = now();

  const solveResult = await runner.solve(task);

  // If the solver gave up, there is no patch to test — unresolved by definition.
  let verdict: ResolutionVerdict;
  if (!solveResult.solved) {
    verdict = {
      instanceId: task.instanceId,
      resolved: false,
      failToPassCleared: [],
      failToPassMissed: [...task.failToPass],
      passToPassRegressed: [],
      reason: `solver gave up: ${solveResult.gaveUpReason ?? "no patch produced"}`,
    };
  } else {
    // Execute BOTH test sets against the patched tree, then judge.
    const allTests = [...task.failToPass, ...task.passToPass];
    const execution = await runner.runTests(task, allTests);
    verdict = judgeResolution(task, execution);
  }

  const latencyMs = now() - started;
  const costUsd = runner.costUsd?.(task, solveResult) ?? 0;
  const failureClass = classify(verdict, solveResult.solved);

  // Record the trajectory to the tamper-evident spine.
  spine.stage({
    type: "identity.action",
    actor: "eval-harness",
    payload: {
      event: "instance_run",
      instanceId: task.instanceId,
      repo: task.repo,
      resolved: verdict.resolved,
      failureClass,
      costUsd,
      latencyMs,
      stagesRun: solveResult.stagesRun,
      repairRounds: solveResult.repairRounds,
      failToPassMissed: verdict.failToPassMissed.length,
      passToPassRegressed: verdict.passToPassRegressed.length,
    },
  });

  return {
    instanceId: task.instanceId,
    verdict,
    solveResult,
    failureClass,
    costUsd,
    latencyMs,
    stagesRun: solveResult.stagesRun,
    repairRounds: solveResult.repairRounds,
  };
}

function classify(verdict: ResolutionVerdict, solved: boolean): FailureClass {
  if (verdict.resolved) return "resolved";
  if (!solved) return "gave-up";
  const incomplete = verdict.failToPassMissed.length > 0;
  const regressed = verdict.passToPassRegressed.length > 0;
  if (incomplete && regressed) return "fix-incomplete+regression";
  if (regressed) return "regression";
  return "fix-incomplete";
}

/** Run a whole suite of instances (sequentially — deterministic, auditable). */
export async function runSuite(tasks: readonly EvalTask[], runner: InstanceRunner, spine: Spine, now: () => number = () => Date.now()): Promise<InstanceRun[]> {
  const runs: InstanceRun[] = [];
  for (const task of tasks) runs.push(await runInstance(task, runner, spine, now));
  return runs;
}
