/**
 * SWE-bench task contract + two-part resolution oracle (Increment 16a).
 *
 * SOTA basis (2026-08-05): the resolution oracle is a TWO-PART contract (Scale SWE-bench Pro; survey
 * arXiv 2606.20683): a task is resolved ONLY IF every fail-to-pass test flips red→green (the fix works)
 * AND every pass-to-pass test stays green (no regression). SWE-bench Verified is saturating and
 * contamination-compromised (OpenAI recommended discontinuing it; ~30% of Pro's public split found
 * broken — arXiv 2603.21454), so the harness is benchmark-agnostic behind a task port and surfaces a
 * contamination/flaky note as a first-class field. A credible 2026 eval reports variance + cost +
 * failure classes, not a single peak number (appliedtechnologyindex 2026). Zero deps.
 *
 * What would change it: the field's benchmark of record shifts → add a TaskSource adapter (the port is
 * generic — Verified, Pro, Multilingual, Terminal-Bench 2.0 all fit).
 */

/** A single evaluation task in the SWE-bench contract (benchmark-agnostic). */
export interface EvalTask {
  readonly instanceId: string;
  readonly repo: string;
  readonly baseCommit: string;
  readonly problemStatement: string;
  /** Tests that FAIL on the base commit and must PASS after a correct patch (the bug's tests). */
  readonly failToPass: readonly string[];
  /** Tests that PASS on the base commit and must STILL pass after the patch (no regression). */
  readonly passToPass: readonly string[];
  /** The reference solution, if the dataset ships one (for analysis; never given to the solver). */
  readonly goldPatch?: string;
  /** Dataset-supplied hidden tests, materialized only after the solver returns. */
  readonly testPatch?: string;
  /** ISO date the issue/PR was created — enables temporal decontamination (reject tasks predating a model's cutoff). */
  readonly createdAt?: string;
  /** Provenance/flags — e.g. flagged as possibly-contaminated or flaky by dataset maintainers. */
  readonly notes?: readonly string[];
}

/** The result of running a test set: which tests passed. */
export interface TestExecution {
  /** Map test name → passed. A test absent from the map is treated as not-run (a failure to execute). */
  readonly passed: Readonly<Record<string, boolean>>;
}

/** The oracle's verdict for one task. */
export interface ResolutionVerdict {
  readonly instanceId: string;
  readonly resolved: boolean;
  /** fail-to-pass tests that correctly flipped to passing. */
  readonly failToPassCleared: readonly string[];
  /** fail-to-pass tests that did NOT pass (fix incomplete). */
  readonly failToPassMissed: readonly string[];
  /** pass-to-pass tests that REGRESSED (broke) — any of these means unresolved. */
  readonly passToPassRegressed: readonly string[];
  /** Human-readable reason. */
  readonly reason: string;
}

/**
 * The two-part resolution oracle. Deterministic, dataset-independent. `afterPatch` is the test
 * execution AFTER the candidate patch is applied. Resolved iff every fail-to-pass test passes AND no
 * pass-to-pass test regressed. Tests not present in the execution map count as failures (a test that
 * didn't run is not a pass — mirrors validate.ts's "0 tests is not a pass" rule).
 */
export function judgeResolution(task: EvalTask, afterPatch: TestExecution): ResolutionVerdict {
  const passed = afterPatch.passed;

  const failToPassCleared: string[] = [];
  const failToPassMissed: string[] = [];
  for (const t of task.failToPass) {
    if (passed[t] === true) failToPassCleared.push(t);
    else failToPassMissed.push(t);
  }

  const passToPassRegressed: string[] = [];
  for (const t of task.passToPass) {
    if (passed[t] !== true) passToPassRegressed.push(t);
  }

  const resolved = failToPassMissed.length === 0 && passToPassRegressed.length === 0;
  let reason: string;
  if (resolved) {
    reason = `resolved: all ${task.failToPass.length} fail-to-pass cleared, no regression in ${task.passToPass.length} pass-to-pass`;
  } else if (failToPassMissed.length > 0 && passToPassRegressed.length > 0) {
    reason = `unresolved: ${failToPassMissed.length} fail-to-pass still failing AND ${passToPassRegressed.length} pass-to-pass regressed`;
  } else if (failToPassMissed.length > 0) {
    reason = `unresolved: ${failToPassMissed.length} of ${task.failToPass.length} fail-to-pass still failing (fix incomplete)`;
  } else {
    reason = `unresolved: ${passToPassRegressed.length} pass-to-pass regressed (fix caused a regression)`;
  }

  return { instanceId: task.instanceId, resolved, failToPassCleared, failToPassMissed, passToPassRegressed, reason };
}

/** Config for the flakiness-aware oracle. Rerun budget is bounded + operator-controlled (Mergify 2026). */
export interface StableOracleConfig {
  /** Require at least this many identical reruns before a "resolved" verdict. Default 1 (n=1 fast single-run path). */
  readonly minRuns?: number;
}

export interface StableResolutionVerdict {
  readonly instanceId: string;
  /** STABLY resolved: enough reruns, every rerun resolved, and no relevant test flaky. */
  readonly resolved: boolean;
  /** A relevant test's pass/fail VARIED across identical reruns — the "lucky pass problem" (AgentLens 2026). */
  readonly flaky: boolean;
  /** The tests that varied across reruns (empty unless flaky). */
  readonly flakyTests: readonly string[];
  /** How many reruns were judged. */
  readonly runs: number;
  /** Per-rerun single-run resolved verdicts (in order). */
  readonly perRunResolved: readonly boolean[];
  readonly reason: string;
}

/**
 * FLAKE-ORACLE — flakiness-aware resolution oracle. Wraps the two-part `judgeResolution` over MULTIPLE identical reruns
 * (the caller supplies the executions — NO new test runner). A genuine fix is STABLE: every rerun resolves AND no
 * relevant test's pass/fail varies across the reruns. A target that flips red→green once but not on rerun — or a
 * pass-to-pass test that regresses on some rerun — is FLAKY and does NOT count as resolved (fail-safe: flaky ≠ resolved;
 * a flaky green is not a fix — the "lucky pass problem", AgentLens 2026). Flakiness is REPORTED, never hidden. HONEST:
 * determinism is assumed only within the bounded rerun budget; more reruns → higher confidence.
 */
export function judgeResolutionStable(task: EvalTask, runs: readonly TestExecution[], cfg: StableOracleConfig = {}): StableResolutionVerdict {
  const minRuns = cfg.minRuns ?? 1;
  const perRunResolved = runs.map((r) => judgeResolution(task, r).resolved);

  // A relevant test is FLAKY if its passed-value is not identical across every rerun.
  const relevant = [...task.failToPass, ...task.passToPass];
  const flakyTests: string[] = [];
  for (const t of relevant) {
    const vals = runs.map((r) => r.passed[t] === true);
    if (vals.length > 1 && !vals.every((v) => v === vals[0])) flakyTests.push(t);
  }
  const flaky = flakyTests.length > 0;

  const enoughRuns = runs.length >= minRuns && runs.length >= 1;
  const allResolved = perRunResolved.length > 0 && perRunResolved.every((x) => x);
  const resolved = enoughRuns && allResolved && !flaky;

  let reason: string;
  if (resolved) {
    reason = `stably resolved across ${runs.length} rerun(s) — no flaky test`;
  } else if (flaky) {
    reason = `FLAKY: test(s) [${flakyTests.join(", ")}] varied across ${runs.length} identical reruns — NOT resolved (a flaky green is not a fix; the lucky-pass problem)`;
  } else if (!enoughRuns) {
    reason = `insufficient reruns: ${runs.length} provided, ${minRuns} required — not resolved`;
  } else {
    // consistently unresolved — defer to the single-run reason of the first run.
    reason = `unresolved (stable across ${runs.length} reruns): ${runs.length > 0 ? judgeResolution(task, runs[0]!).reason : "no runs"}`;
  }

  return { instanceId: task.instanceId, resolved, flaky, flakyTests, runs: runs.length, perRunResolved, reason };
}

/**
 * A source of eval tasks — the generic port. The synthetic suite implements it here; real SWE-bench
 * Verified / Pro / Terminal-Bench 2.0 adapters implement it on Hetzner (load dataset + Docker/env-free
 * runner). Keeps the harness benchmark-agnostic.
 */
export interface TaskSource {
  readonly name: string;
  /** Load the tasks in this suite. */
  load(): Promise<readonly EvalTask[]>;
  /** Any dataset-level contamination/reliability caveats to surface in the report. */
  caveats(): readonly string[];
}
