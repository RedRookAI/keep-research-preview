/**
 * SolvePipeline: validate (Increment 13c).
 *
 * SOTA basis (2026-08-05): the acceptance gate must be EXTERNAL — only a real test run (or gate)
 * accepts a candidate; a model's self-assessment never can (VeriHarness 2026). Running the repo's
 * existing tests as the oracle gives early, actionable feedback and materially cuts cost/steps
 * ("Old Tests New Tricks" 2026: -23% cost, statistically significant). And the feedback must be
 * STRUCTURED — which tests failed and why — because a repair interface that exposes the observed
 * failure helps far more than a raw "tests failed" (VeriHarness). So ValidationOutcome carries the
 * specific failures, and validation is decided by the TestRunner port, not the model.
 *
 * The TestRunner is a port: an in-memory scripted runner here (deterministic), a real process-
 * spawning runner on Hetzner behind the same interface. Zero deps.
 */

import type { ValidationOutcome } from "./issue_model.js";
import { executionStopReason, type ExecutionContext } from "../infra/execution_lifetime.js";
import { copyProcessIsolationObservation, type ProcessIsolationObservation } from "../infra/isolation_backend.js";
export type TestExecutionContext = ExecutionContext;

/** One test's result. */
export interface TestCaseResult {
  readonly name: string;
  readonly passed: boolean;
  /** Failure output (assertion message, stack) — the structured signal the repair loop conditions on. */
  readonly output?: string;
}

/** The result of running a test suite. */
export interface TestRunResult {
  readonly results: readonly TestCaseResult[];
  /** Any runner-level error (compile failure, crash) that prevented tests from running at all. */
  readonly runnerError?: string;
  readonly failureKind?: ValidationOutcome["failureKind"];
  readonly processCompletion?: "not-started" | "direct-child-closed" | "unconfirmed";
  readonly processIsolation?: ProcessIsolationObservation;
}

/** The test-runner port: run the repo's tests and report per-case results. */
export interface TestRunner {
  run(repoRef: string, options?: TestExecutionContext): Promise<TestRunResult>;
}

/** Optional extra gates layered on top of the test oracle. */
export interface ValidateGates {
  /** A vetting hook (verification cascade / logic vetting) → true if it clears. */
  vet?: (repoRef: string) => Promise<boolean>;
}

/**
 * Validate the current working tree: run the tests (the external oracle), optionally run the vetting
 * gate, and return a structured outcome. testsPassed is true ONLY if the runner ran cleanly AND every
 * test passed — never inferred from anything the model said.
 */
export async function validate(repoRef: string, runner: TestRunner, gates: ValidateGates = {}, execution?: TestExecutionContext): Promise<ValidationOutcome> {
  let processIsolation: ProcessIsolationObservation | undefined;
  const stopped = () => ({ testsPassed: false, passedCount: 0, passedTests: [], failureKind: "harness" as const, failures: ["<runner-error>"], vettingCleared: false, detail: executionStopReason(execution) ?? "execution stopped", ...(processIsolation ? { processIsolation } : {}) });
  if (executionStopReason(execution)) return stopped();
  const run = await runner.run(repoRef, execution);
  processIsolation = run.processIsolation ? copyProcessIsolationObservation(run.processIsolation) : undefined;
  if (executionStopReason(execution)) return stopped();

  if (run.runnerError) {
    return { testsPassed: false, passedCount: 0, passedTests: [], failureKind: run.failureKind ?? "unknown", failures: ["<runner-error>"], vettingCleared: false, detail: `runner error: ${run.runnerError}`, ...(processIsolation ? { processIsolation } : {}) };
  }

  const failures = run.results.filter((r) => !r.passed);
  const testsPassed = failures.length === 0 && run.results.length > 0;

  // Vetting only runs if tests passed (no point vetting a broken patch); default cleared when absent.
  let vettingCleared = testsPassed;
  if (testsPassed && gates.vet) {
    vettingCleared = await gates.vet(repoRef);
    if (executionStopReason(execution)) return stopped();
  }

  const failureDetail = failures.map((f) => `${f.name}: ${f.output ?? "failed"}`).join("\n");
  const detail = run.results.length === 0
    ? "no tests were discovered (a green run with 0 tests is NOT a pass)"
    : testsPassed
      ? (vettingCleared ? "all tests passed; vetting cleared" : "all tests passed but vetting did not clear")
      : `${failures.length}/${run.results.length} tests failing:\n${failureDetail}`;

  return {
    ...(processIsolation ? { processIsolation } : {}),
    testsPassed,
    passedCount: run.results.filter((result) => result.passed).length,
    passedTests: run.results.filter((result) => result.passed).map(result => result.name),
    ...(!testsPassed ? { failureKind: run.failureKind ?? (run.results.length === 0 ? "unknown" as const : "product" as const) } : !vettingCleared ? { failureKind: "authority" as const } : {}),
    failures: failures.map((f) => f.name),
    vettingCleared,
    detail,
  };
}
