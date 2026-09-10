import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";

import { computeMicrovmProjectSourceManifestSha256, consumeVerifiedMicrovmRunReceiptDigest, verifiedMicrovmRunReceipt, verifiedMicrovmRunReceiptDigest, verifiedMicrovmTestRunResultDigest } from "../infra/microvm_boundary.js";
import { consumeVerifiedIsolatedRunOutcome, IsolatedTestRunner } from "../isolation/isolated_executor.js";
import { TIER_STRENGTH, type IsolationTier } from "../isolation/isolation_tier.js";
import type { Issue } from "../solve/issue_model.js";
import type { RepoFile } from "../solve/localize.js";
import type { TestRunner } from "../solve/validate.js";
import type { ProjectImplementationArtifact } from "../solve/project_loop_wiring.js";
import { projectRepositoryTreeSha256 } from "./project_localization.js";
import type { ProjectState } from "./project_state.js";
import { RedactionGateway } from "../privacy/redaction_gateway.js";
import { canonicalize } from "../spine/event.js";
import { copyProcessIsolationObservation, type ProcessIsolationObservation } from "../infra/isolation_backend.js";
import { executionStopReason, type ExecutionContext } from "../infra/execution_lifetime.js";

const MAX_FAILURE_OUTPUT = 16 * 1024;
const MAX_RESULT_CASES = 10_000;
const MAX_PERSISTED_FAILURES = 1_000;
const MAX_RESULT_INPUT_BYTES = 16 * 1024 * 1024;

function digest(domain: string, value: unknown): string {
  return createHash("sha256").update(`${domain}\0${JSON.stringify(value)}\n`).digest("hex");
}
/** Checkpoint persistence canonicalizes object keys; identity must survive restart. */
export function projectImplementationDigest(value: unknown): string {
  return createHash("sha256").update(`keep.project-implementation/v2\0${canonicalize(value)}\n`).digest("hex");
}

function boundedTail(value: string): string {
  return value.length <= MAX_FAILURE_OUTPUT ? value : value.slice(-MAX_FAILURE_OUTPUT);
}

export interface ProjectTestArtifact {
  readonly schemaVersion: 1;
  readonly issueId: string;
  readonly taskId: string;
  readonly planStepId: string;
  readonly implementationSha256: string;
  readonly repositoryTreeSha256: string;
  readonly repositoryExecutionManifestSha256: string;
  readonly testRunResultSha256?: string;
  readonly command: { readonly executable: string; readonly args: readonly string[] };
  readonly verdict: "passed" | "failed" | "unavailable" | "stale";
  /** Compatibility-independent success signal consumed by repair/learning joins. */
  readonly passed: boolean;
  readonly isolation: {
    readonly selectedTier: IsolationTier;
    readonly requiredTier: IsolationTier;
    /** Actual local process observation; selected-tier admission is not project-jail proof. */
    readonly processIsolation?: ProcessIsolationObservation;
    readonly requirementMet: boolean;
    readonly attempted: boolean;
    readonly executed: boolean;
    readonly refusalReason?: string;
    readonly microvmReceipt?: {
      readonly digest: string;
      readonly runtimeKind: string;
      readonly attemptNonce: string;
      readonly durationMs: number;
      readonly guestExitCode: number;
      readonly executionSpecSha256: string;
      readonly guestExecutionRequestSha256: string;
      readonly projectSourceManifestSha256: string;
      readonly testRunResultSha256: string;
      readonly measurementPolicyCanonicalSha256: string;
      readonly measuredCgroupMemoryMax: string;
      readonly measuredCgroupPidsMax: string;
      readonly teardownClean: true;
    };
  };
  readonly testsExecuted: boolean;
  readonly testsPassed: boolean;
  readonly discovered: number;
  readonly passedCount: number;
  readonly failures: readonly { readonly name: string; readonly output: string }[];
  readonly failureOutput: string;
  readonly runnerError?: string;
  readonly reasons: readonly string[];
  readonly failuresOmitted?: number;
}

export interface ProjectTester {
  run(issue: Issue, state: ProjectState): Promise<ProjectTestArtifact>;
}

export interface ProjectTestConfig {
  readonly runnerFor: (repoRef: string) => TestRunner;
  readonly snapshotFiles: (repoRef: string) => Promise<readonly RepoFile[]>;
  /** Canonical source root. Non-microVM verification must execute from a different disposable root. */
  readonly canonicalProjectDirFor: (repoRef: string) => string;
  /** Exact source root used by the isolated runner. */
  readonly executionProjectDirFor: (repoRef: string) => string;
  /** Enumerate the disposable execution root independently of the canonical snapshot. */
  readonly executionSnapshotFiles: (repoRef: string) => Promise<readonly RepoFile[]>;
  /** Release the disposable execution root after every terminal verification outcome. */
  readonly disposeExecution?: (repoRef: string) => void | Promise<void>;
  readonly selectedTier: IsolationTier;
  readonly requiredTier: IsolationTier;
  readonly command: string;
  readonly args: readonly string[];
  /** Independently derived guest request identity required when the selected tier is a microVM. */
  readonly expectedMicrovmGuestExecutionRequestSha256?: string;
}

function boundedResultRefusal(result: import("../solve/validate.js").TestRunResult): string | undefined {
  if (!Array.isArray(result.results) || result.results.length > MAX_RESULT_CASES) return `test result exceeds ${MAX_RESULT_CASES} cases`;
  let bytes = typeof result.runnerError === "string" ? Buffer.byteLength(result.runnerError, "utf8") : 0;
  for (const row of result.results) {
    if (!row || typeof row.name !== "string" || typeof row.passed !== "boolean" || (row.output !== undefined && typeof row.output !== "string")) return "test result contains malformed rows";
    bytes += Buffer.byteLength(row.name, "utf8") + (row.output === undefined ? 0 : Buffer.byteLength(row.output, "utf8"));
    if (!Number.isSafeInteger(bytes) || bytes > MAX_RESULT_INPUT_BYTES) return `test result exceeds ${MAX_RESULT_INPUT_BYTES} input bytes`;
  }
  return undefined;
}

function implementationOf(issue: Issue, state: ProjectState): ProjectImplementationArtifact & { readonly repositoryTreeAfterSha256: string; readonly repositoryExecutionManifestSha256: string } {
  const implementation = state.artifacts["implement"] as Partial<ProjectImplementationArtifact> | undefined;
  if (implementation?.schemaVersion !== 1 || !implementation.issue || !implementation.solve || !implementation.task ||
      implementation.issue.id !== issue.id || implementation.solve.issueId !== issue.id ||
      implementation.task.id !== implementation.issue.hints?.["projectTaskId"] ||
      implementation.task.planStepId !== implementation.issue.hints?.["planStepId"] ||
      typeof implementation.repositoryTreeAfterSha256 !== "string" || typeof implementation.repositoryExecutionManifestSha256 !== "string") {
    throw new Error("configured project tests require a content-bound persisted implementation artifact");
  }
  if (implementation.solve.projectEditReceipt && implementation.solve.projectEditReceipt.repositoryTreeAfterSha256 !== implementation.repositoryTreeAfterSha256) {
    throw new Error("project test implementation and canonical edit receipt disagree on final repository bytes");
  }
  return implementation as ProjectImplementationArtifact & { readonly repositoryTreeAfterSha256: string; readonly repositoryExecutionManifestSha256: string };
}

type ProjectTestExecutionEvidence = Omit<ProjectTestArtifact, "issueId" | "taskId" | "planStepId" | "implementationSha256">;

/** One enforcing execution boundary, shared by repair feedback and durable verification. */
export function buildProjectTester(config: ProjectTestConfig): ProjectTester & { feedbackRunner(repoRef: string): TestRunner } {
  const command = Object.freeze({ executable: config.command, args: Object.freeze([...config.args]) });
  async function execute(repoRef: string, expectedTree: string, expectedExecutionManifest: string,
    onResult?: (result: import("../solve/validate.js").TestRunResult) => void, execution?: ExecutionContext): Promise<ProjectTestExecutionEvidence> {
    const redactor = new RedactionGateway();
    const safe = (value: string): string => boundedTail(redactor.redact(value).redacted);
    const base = { schemaVersion: 1 as const, repositoryTreeSha256: expectedTree,
      repositoryExecutionManifestSha256: expectedExecutionManifest, command };
    const unavailable = (reason: string, selectedTier = config.selectedTier, attempted = false, processIsolation?: ProcessIsolationObservation): ProjectTestExecutionEvidence => Object.freeze({
      ...base, verdict: "unavailable" as const, passed: false,
      isolation: Object.freeze({ selectedTier, requiredTier: config.requiredTier, requirementMet: false, attempted, executed: false, refusalReason: safe(reason),
        ...(processIsolation ? { processIsolation: copyProcessIsolationObservation(processIsolation) } : {}) }),
      testsExecuted: false, testsPassed: false, discovered: 0, passedCount: 0,
      failures: Object.freeze([]), failureOutput: "", runnerError: safe(reason), reasons: Object.freeze([`test verification unavailable: ${safe(reason)}`]),
    });
    const finish = async (artifact: ProjectTestExecutionEvidence): Promise<ProjectTestExecutionEvidence> => {
      try { await config.disposeExecution?.(repoRef); }
      catch (error) { return unavailable(`disposable verification cleanup failed: ${error instanceof Error ? error.message : String(error)}`,
        artifact.isolation.selectedTier, artifact.isolation.attempted, artifact.isolation.processIsolation); }
      return artifact;
    };
    let beforeTree: string;
    let canonicalProjectDir: string;
    let executionProjectDir: string;
    try {
      beforeTree = projectRepositoryTreeSha256(await config.snapshotFiles(repoRef));
      canonicalProjectDir = config.canonicalProjectDirFor(repoRef);
      executionProjectDir = config.executionProjectDirFor(repoRef);
    } catch (error) { return finish(unavailable(error instanceof Error ? error.message : String(error))); }
    if (beforeTree !== expectedTree) {
      const reason = "repository changed after implementation and before independent verification";
      return finish(Object.freeze({ ...base, verdict: "stale" as const, passed: false,
        isolation: Object.freeze({ selectedTier: config.selectedTier, requiredTier: config.requiredTier, requirementMet: false, attempted: false, executed: false, refusalReason: reason }),
        testsExecuted: false, testsPassed: false, discovered: 0, passedCount: 0,
        failures: Object.freeze([]), failureOutput: "", runnerError: reason, reasons: Object.freeze([reason]),
      }));
    }
    let canonicalExecutionManifest: string;
    try { canonicalExecutionManifest = await computeMicrovmProjectSourceManifestSha256(canonicalProjectDir); }
    catch (error) { return finish(unavailable(error instanceof Error ? error.message : String(error))); }
    if (canonicalExecutionManifest !== expectedExecutionManifest) {
      const reason = "repository execution inputs changed after implementation and before independent verification";
      return finish(Object.freeze({ ...base, verdict: "stale" as const, passed: false,
        isolation: Object.freeze({ selectedTier: config.selectedTier, requiredTier: config.requiredTier, requirementMet: false, attempted: false, executed: false, refusalReason: reason }),
        testsExecuted: false, testsPassed: false, discovered: 0, passedCount: 0,
        failures: Object.freeze([]), failureOutput: "", runnerError: reason, reasons: Object.freeze([reason]),
      }));
    }
    let executionTree: string;
    try { executionTree = projectRepositoryTreeSha256(await config.executionSnapshotFiles(repoRef)); }
    catch (error) { return finish(unavailable(error instanceof Error ? error.message : String(error))); }
    if (executionTree !== expectedTree) {
      let currentCanonical: string;
      try { currentCanonical = projectRepositoryTreeSha256(await config.snapshotFiles(repoRef)); }
      catch (error) { return finish(unavailable(error instanceof Error ? error.message : String(error))); }
      if (currentCanonical !== expectedTree) {
        const reason = "repository changed while preparing the independent verification source";
        return finish(Object.freeze({ ...base, verdict: "stale" as const, passed: false,
          isolation: Object.freeze({ selectedTier: config.selectedTier, requiredTier: config.requiredTier, requirementMet: false, attempted: false, executed: false, refusalReason: reason }),
          testsExecuted: false, testsPassed: false, discovered: 0, passedCount: 0,
          failures: Object.freeze([]), failureOutput: "", runnerError: reason, reasons: Object.freeze([reason]),
        }));
      }
      return finish(unavailable("disposable verification source does not match the implemented repository bytes"));
    }
    let executionManifest: string;
    try { executionManifest = await computeMicrovmProjectSourceManifestSha256(executionProjectDir); }
    catch (error) { return finish(unavailable(error instanceof Error ? error.message : String(error))); }
    if (executionManifest !== expectedExecutionManifest) return finish(unavailable("disposable verification execution inputs do not match the implemented repository bytes"));
    if (config.selectedTier !== "microvm") {
      try {
        if (realpathSync(canonicalProjectDir) === realpathSync(executionProjectDir)) {
          return finish(unavailable("non-microVM verification requires a disposable source root distinct from canonical"));
        }
      } catch (error) { return finish(unavailable(error instanceof Error ? error.message : String(error))); }
    }

    let runner: TestRunner;
    try { runner = config.runnerFor(repoRef); }
    catch (error) { return finish(unavailable(error instanceof Error ? error.message : String(error))); }
    if (!(runner instanceof IsolatedTestRunner)) return finish(unavailable("configured project tests require the selected enforcing isolation runner"));
    const actualCommand = runner.verifiedCommandConfig();
    if (!actualCommand || actualCommand.command !== command.executable || JSON.stringify(actualCommand.args) !== JSON.stringify(command.args)) {
      return finish(unavailable("configured project-test command does not match the verifier-owned runner argv"));
    }
    try {
      if (realpathSync(actualCommand.projectDir) !== realpathSync(executionProjectDir)) return finish(unavailable("configured project-test runner cwd does not match the disposable source root"));
    } catch (error) { return finish(unavailable(error instanceof Error ? error.message : String(error))); }
    let outcome: Awaited<ReturnType<IsolatedTestRunner["runWithEvidence"]>>;
    try { outcome = await runner.runWithEvidence(repoRef, true, execution); }
    catch (error) { return finish(unavailable(error instanceof Error ? error.message : String(error))); }
    const result = outcome.result;
    const receipt = result ? verifiedMicrovmRunReceipt(result) : undefined;
    const outcomeMet = consumeVerifiedIsolatedRunOutcome(outcome, executionProjectDir);
    const tierMet = outcome.tier === config.selectedTier && TIER_STRENGTH[outcome.tier] >= TIER_STRENGTH[config.requiredTier];
    const receiptMet = outcome.tier !== "microvm" || (receipt !== undefined && result !== undefined && executionManifest === receipt.projectSourceManifestSha256 &&
      config.expectedMicrovmGuestExecutionRequestSha256 === receipt.guestExecutionRequestSha256 &&
      consumeVerifiedMicrovmRunReceiptDigest(verifiedMicrovmRunReceiptDigest(receipt), executionProjectDir, receipt.executionSpecSha256,
        receipt.guestExecutionRequestSha256, receipt.projectSourceManifestSha256, verifiedMicrovmTestRunResultDigest(result)));
    const resultRefusal = result === undefined ? undefined : boundedResultRefusal(result);
    const verifiedExecution = outcome.executed && result !== undefined && outcomeMet && tierMet && receiptMet && resultRefusal === undefined;
    let afterTree: string;
    let afterExecutionManifest: string;
    try {
      afterTree = projectRepositoryTreeSha256(await config.snapshotFiles(repoRef));
      afterExecutionManifest = await computeMicrovmProjectSourceManifestSha256(canonicalProjectDir);
    }
    catch (error) { return finish(unavailable(error instanceof Error ? error.message : String(error), outcome.tier, outcome.executed, result?.processIsolation)); }
    const changedDuringRun = afterTree !== expectedTree || afterExecutionManifest !== expectedExecutionManifest;
    const allFailures = (resultRefusal === undefined ? result?.results ?? [] : []).filter((row) => !row.passed);
    const failures = Object.freeze(allFailures.slice(0, MAX_PERSISTED_FAILURES).map((row) => Object.freeze({
      name: safe(row.name).slice(0, 1_024), output: safe(row.output ?? "failed"),
    })));
    const guestOutput = receipt ? safe(`${receipt.guestResult.stdout}\n${receipt.guestResult.stderr}`.trim()) : "";
    const runnerError = executionStopReason(execution) ?? (changedDuringRun
      ? "repository changed during independent verification"
      : result?.runnerError ?? (!outcome.executed ? outcome.refusedReason ?? "isolated execution refused"
        : !outcomeMet ? "isolated execution outcome is not verifier-owned or was already consumed"
        : !tierMet ? `selected isolation tier ${outcome.tier} did not satisfy configured ${config.selectedTier}/${config.requiredTier}`
        : resultRefusal ?? (!receiptMet ? "microvm execution did not produce a fresh source-bound verified receipt" : undefined)));
    const discovered = resultRefusal === undefined ? result?.results.length ?? 0 : 0;
    const passedCount = resultRefusal === undefined ? result?.results.filter((row) => row.passed).length ?? 0 : 0;
    const testsPassed = verifiedExecution && !changedDuringRun && !runnerError && discovered > 0 && failures.length === 0;
    const verdict = changedDuringRun ? "stale" as const : testsPassed ? "passed" as const
      : verifiedExecution && !runnerError && discovered > 0 ? "failed" as const : "unavailable" as const;
    const reasons = Object.freeze(runnerError ? [`test verification unavailable: ${safe(runnerError)}`]
      : discovered === 0 ? ["configured test execution discovered no tests"]
      : failures.map((row) => `TEST FAILED: ${row.name}\n${row.output}`));
    if (verifiedExecution && !changedDuringRun && result) onResult?.(result);
    return finish(Object.freeze({
      ...base, verdict, passed: verdict === "passed",
      ...(result && resultRefusal === undefined ? { testRunResultSha256: digest("keep.project-test-result/v1", result) } : {}),
      isolation: Object.freeze({
        selectedTier: outcome.tier, requiredTier: config.requiredTier,
        ...(result?.processIsolation ? { processIsolation: copyProcessIsolationObservation(result.processIsolation) } : {}),
        requirementMet: outcomeMet && tierMet && receiptMet, attempted: outcome.executed, executed: verifiedExecution,
        ...(outcome.refusedReason ? { refusalReason: safe(outcome.refusedReason) } : {}),
        ...(receipt ? { microvmReceipt: Object.freeze({
          digest: verifiedMicrovmRunReceiptDigest(receipt), runtimeKind: receipt.runtimeKind,
          attemptNonce: receipt.attemptNonce, durationMs: receipt.durationMs,
          guestExitCode: receipt.guestResult.exitCode, executionSpecSha256: receipt.executionSpecSha256,
          guestExecutionRequestSha256: receipt.guestExecutionRequestSha256,
          projectSourceManifestSha256: receipt.projectSourceManifestSha256,
          testRunResultSha256: receipt.testRunResultSha256,
          measurementPolicyCanonicalSha256: receipt.measurementPolicyCanonicalSha256,
          measuredCgroupMemoryMax: receipt.measuredCgroupMemoryMax,
          measuredCgroupPidsMax: receipt.measuredCgroupPidsMax, teardownClean: receipt.teardownClean,
        }) } : {}),
      }),
      testsExecuted: verifiedExecution, testsPassed, discovered, passedCount, failures,
      failureOutput: guestOutput || failures.map((row) => `${row.name}: ${row.output}`).join("\n"),
      ...(runnerError ? { runnerError: safe(runnerError) } : {}), reasons,
      ...(allFailures.length > failures.length ? { failuresOmitted: allFailures.length - failures.length } : {}),
    }));
  }
  return {
    async run(issue, state): Promise<ProjectTestArtifact> {
      const implementation = implementationOf(issue, state);
      const binding = { issueId: issue.id, taskId: implementation.task.id,
        planStepId: implementation.task.planStepId, implementationSha256: projectImplementationDigest(implementation) };
      const evidence = await execute(issue.repoRef, implementation.repositoryTreeAfterSha256, implementation.repositoryExecutionManifestSha256);
      return Object.freeze({ ...evidence, ...binding });
    },
    feedbackRunner(repoRef): TestRunner {
      return {
        async run(ref, execution) {
          if (ref !== repoRef) return { results: [], runnerError: "feedback repository differs from the bound repository", failureKind: "authority" };
          if (execution?.signal?.aborted || (execution?.deadline !== undefined && Date.now() >= execution.deadline)) {
            return { results: [], runnerError: "recovery deadline exhausted before feedback dispatch", failureKind: "harness" };
          }
          let tree: string, manifest: string;
          try {
            tree = projectRepositoryTreeSha256(await config.snapshotFiles(repoRef));
            manifest = await computeMicrovmProjectSourceManifestSha256(config.canonicalProjectDirFor(repoRef));
          } catch { return { results: [], runnerError: "feedback source identity unavailable", failureKind: "harness" }; }
          let result: import("../solve/validate.js").TestRunResult | undefined;
          const evidence = await execute(repoRef, tree, manifest, value => { result = value; }, execution);
          // Preserve actual test names and failures for repair; cleanup or provenance
          // failure cannot turn raw subprocess output into an accepted feedback result.
          if ((evidence.verdict === "passed" || evidence.verdict === "failed") && result) return result;
          return { results: [], runnerError: evidence.runnerError ?? evidence.reasons.join("; "), failureKind: "harness",
            ...(evidence.isolation.processIsolation ? { processIsolation: copyProcessIsolationObservation(evidence.isolation.processIsolation) } : {}) };
        },
      };
    },
  };
}
