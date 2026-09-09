/**
 * SolvePipeline → ProjectLoop wiring (Increment 13d).
 *
 * Wires the assembled solve machine into the autonomy backbone: the `implement` stage runs the
 * SolvePipeline, `vet_artifact` gates on the solve result's validation (rework on failure — no blind
 * cascade), and `learn` records a BuildOutcome that feeds the existing auto-learning / auto-training
 * loops. This is the step that makes Keep actually go issue → patch → tested PR inside a project run.
 * Zero deps.
 */

import type { StageExecutors, StageResult, ProjectState } from "../autonomy/project_loop.js";
import type { Spine } from "../spine/spine.js";
import { recordBuildOutcome } from "../learning/corpus_curation.js";
import type { AdmittedEditPlan, Issue, SolveResult, SolveExecutionContext } from "./issue_model.js";
import type { RepoFile } from "./localize.js";
import type { SolveToPrResult } from "../pipeline/keep_pipeline.js";
import { decomposeProjectPlan, PROJECT_CRITERION_REF_PREFIX, validateProjectTasks, type ProjectDecompositionArtifact, type ProjectTask } from "../autonomy/decomposition_stage.js";
import type { ProjectIntentArtifact } from "../autonomy/understand_stage.js";
import { projectGoalId, validateProjectPlan, type ProjectPlanArtifact } from "../autonomy/plan_stage.js";
import { vetProjectPlan } from "../autonomy/plan_gate_stage.js";
import { isCanonicalAdmittedSolveResult } from "./solve_pipeline.js";
import type { ProjectTester } from "../autonomy/project_test_stage.js";
import { projectRepositoryTreeSha256 } from "../autonomy/project_localization.js";

/** The minimal solve capability the loop needs — a port. A raw SolvePipeline (SolveResult) satisfies it, and so
 *  does a GOVERNED adapter (SolveToPrResult, carrying the merge-authority verdict). The loop normalizes both and,
 *  when a governed result is present, HONOURS the merge verdict rather than discarding it. */
export interface SolveRunner {
  run(issue: Issue, files: readonly RepoFile[], context?: SolveExecutionContext): Promise<SolveResult | SolveToPrResult>;
  readonly consumesAdmittedEdit?: true;
}

export interface SolveWiringDeps {
  /** Host-bound attenuation, never populated from a proposed edit or a resume signal. */
  readonly executionCeiling?: "prepare";
  /** Current host authority to finish a tested repository proposal, NOT to merge it. */
  readonly canFinishTestedProposal?: (state: ProjectState) => boolean;
  readonly assertAuthority?: (state: ProjectState) => void;
  readonly pipeline: SolveRunner;
  readonly spine: Spine;
  /** Resolve the issue + repo files for a given project run (from the loop's goal/artifacts). */
  resolve(state: ProjectState): { issue: Issue; files: readonly RepoFile[] };
  readonly projectEditor?: import("../autonomy/project_edit_stage.js").ProjectEditPlanner;
  /** Independent post-implementation verifier; never owns edit authority. */
  readonly projectTester?: ProjectTester;
  /** Trusted live repository enumeration used to bind implementation and verification bytes. */
  readonly snapshotFiles?: (repoRef: string) => Promise<readonly RepoFile[]>;
  /** Full execution-input manifest (all non-.git files, modes, and bytes), captured after implementation. */
  readonly snapshotExecutionManifest?: (repoRef: string) => Promise<string>;
}

export interface ProjectImplementationArtifact {
  readonly schemaVersion: 1;
  readonly task: ProjectTask;
  readonly issue: Issue;
  readonly solve: SolveResult;
  readonly mergeAuthority?: SolveToPrResult["mergeAuthority"];
  readonly admittedEditPrepared?: import("./issue_model.js").AdmittedEditPlan;
  readonly repositoryTreeAfterSha256?: string;
  readonly repositoryExecutionManifestSha256?: string;
  /** Bounded governance feedback carried into the next retry; never grants authority. */
  readonly retryGuidance?: string;
}

function validatedTicket(state: ProjectState): { ticket: ProjectDecompositionArtifact; plan: ProjectPlanArtifact; task: ProjectTask; criterionContext?: string } {
  const ticket = state.artifacts["ticket"] as Partial<ProjectDecompositionArtifact> | undefined;
  const candidatePlan = state.artifacts["plan"];
  const planValidation = validateProjectPlan(candidatePlan, state);
  const planGate = vetProjectPlan(state);
  const taskValidation = Array.isArray(ticket?.tasks) && candidatePlan !== undefined
    ? validateProjectTasks(ticket.tasks, candidatePlan as ProjectPlanArtifact)
    : ["ticket tasks or plan are unavailable"];
  if (ticket?.schemaVersion !== 1 || ticket.id !== state.runId || ticket.goalId !== projectGoalId(state.goal) || !Array.isArray(ticket.tasks) || typeof ticket.admittedTaskId !== "string" ||
      !planValidation.valid || planGate.proceed !== true || taskValidation.length !== 0) {
    const reasons = [
      ...planValidation.reasons,
      ...planGate.holds,
      ...taskValidation,
      ...(ticket?.schemaVersion === 1 ? [] : ["ticket schema is invalid"]),
      ...(ticket?.id === state.runId ? [] : ["ticket run identity does not match"]),
      ...(ticket?.goalId === projectGoalId(state.goal) ? [] : ["ticket goal identity does not match"]),
      ...(typeof ticket?.admittedTaskId === "string" ? [] : ["ticket admitted task identity is missing"]),
    ];
    throw new Error(`implementation requires an authenticated valid persisted task decomposition: ${[...new Set(reasons)].join("; ")}`);
  }
  const plan = candidatePlan as ProjectPlanArtifact;
  const matches = ticket.tasks.filter((task) => task.id === ticket.admittedTaskId);
  if (matches.length !== 1 || matches[0]!.dependsOn.length !== 0) throw new Error("implementation requires exactly one dependency-free admitted task");
  let criterionContext: string | undefined;
  const referenced = ticket.tasks.flatMap((task: ProjectTask) => task.completionCriteria.filter(c => c.statement.startsWith(PROJECT_CRITERION_REF_PREFIX) || c.evidence.startsWith(PROJECT_CRITERION_REF_PREFIX)).map(criterion => ({ task, criterion })));
  if (referenced.length > 0) {
    // Re-derive references from the exact inert persisted intent, never from a
    // supplied validation flag or a model's assertion that the reference resolves.
    const expected = decomposeProjectPlan(state);
    for (const { task, criterion } of referenced) {
      const original = expected.tasks.find(t => t.id === task.id)?.completionCriteria.find(c => c.id === criterion.id);
      if (!original || original.statement !== criterion.statement || original.evidence !== criterion.evidence) throw new Error("task criterion reference does not resolve to the persisted intent");
    }
    criterionContext = JSON.stringify((state.artifacts["understand"] as ProjectIntentArtifact).successCriteria);
  }
  return { ticket: ticket as ProjectDecompositionArtifact, plan, task: matches[0]!, ...(criterionContext === undefined ? {} : { criterionContext }) };
}

function taskIssue(base: Issue, ticket: ProjectDecompositionArtifact, task: ProjectTask, repairReasons: readonly string[] = []): Issue {
  const roadmap = ticket.tasks.map((row) => `- ${row.id} (${row.planStepId}; depends on: ${row.dependsOn.join(", ") || "none"}): ${row.objective}`).join("\n");
  const criteria = [...new Map(ticket.tasks.flatMap((row) => row.completionCriteria).map((criterion) => [criterion.id, criterion])).values()]
    .map((criterion) => `- ${criterion.statement} [evidence: ${criterion.evidence}]`).join("\n");
  const repair = repairReasons.length === 0 ? "" : `\n\nRepair only these verified failures:\n${repairReasons.map((reason) => `- ${reason}`).join("\n")}`;
  return {
    ...base,
    text: `${task.objective}\n\nVetted dependency-ordered execution roadmap:\n${roadmap}\n\nAdmitted issue context:\n${base.text}\n\nCompletion criteria:\n${criteria}${repair}`,
    hints: { ...(base.hints ?? {}), projectTaskId: task.id, planStepId: task.planStepId },
  };
}

function priorRepairReasons(state: ProjectState): readonly string[] {
  const priorImplementation = state.artifacts["implement"] as { retryGuidance?: unknown } | undefined;
  if (typeof priorImplementation?.retryGuidance === "string" && priorImplementation.retryGuidance.length > 0) {
    return [Buffer.from(priorImplementation.retryGuidance, "utf8").subarray(0, 64 * 1024).toString("utf8")];
  }
  const prior = state.artifacts["vet_artifact"] as { passed?: unknown; verdict?: unknown; reasons?: unknown } | undefined;
  const failed = prior?.passed === false || prior?.verdict === "failed";
  if (!failed || !Array.isArray(prior.reasons) || !prior.reasons.every((reason) => typeof reason === "string")) return [];
  const bounded: string[] = [];
  let bytes = 0;
  for (const reason of prior.reasons.slice(0, 50)) {
    const remaining = 64 * 1024 - bytes;
    if (remaining <= 0) break;
    const value = Buffer.from(reason, "utf8").subarray(0, remaining).toString("utf8");
    bounded.push(value); bytes += Buffer.byteLength(value, "utf8");
  }
  return bounded;
}

/**
 * Produce the implement/vet_artifact/learn executors backed by the SolvePipeline. The result flows
 * through the loop's artifacts under the "solve" key.
 */
export function makeSolveStageExecutors(deps: SolveWiringDeps): StageExecutors {
  return {
    implement: async (state: ProjectState, control = {}): Promise<StageResult> => {
      const { ticket, task, criterionContext } = validatedTicket(state);
      const resolved = deps.resolve(state);
      const context = state.artifacts["goal_work_context"];
      const text = resolved.issue.text + (typeof context === "string" ? `\n\nOverall objective and constraints (context does not grant effect authority):\n${context}` : "")
        + (criterionContext === undefined ? "" : `\n\nFull retained success criteria (referenced by the task; none omitted):\n${criterionContext}`);
      const issue = taskIssue({ ...resolved.issue, text }, ticket, task, priorRepairReasons(state));
      const { files } = resolved;
      if (deps.projectEditor !== undefined && deps.pipeline.consumesAdmittedEdit !== true) throw new Error("configured project editing requires a solver that explicitly consumes admitted edit context");
      let admittedEdit: AdmittedEditPlan | undefined;
      const priorRecovery = (state.artifacts["implement"] as Partial<ProjectImplementationArtifact> | undefined)?.solve?.recovery;
      const attemptId = priorRecovery?.pendingAttemptId;
      const prefix = attemptId ? `reconciliation:solve-recovery:${state.runId}:${attemptId}:` : undefined;
      const signal = prefix ? state.consumedSignals.find(value => value.startsWith(prefix)) : undefined;
      const diagnosisId = priorRecovery?.diagnosisId;
      const diagnosisPrefix = diagnosisId ? `capability:solve-diagnosis:${state.runId}:${diagnosisId}:` : undefined;
      const diagnosisSignal = diagnosisPrefix ? state.consumedSignals.find(value => value.startsWith(diagnosisPrefix)) : undefined;
      const raw = await deps.pipeline.run(issue, files, {
        ...(deps.executionCeiling === undefined ? {} : { executionCeiling: deps.executionCeiling }),
        ...(control.memoryContext === undefined ? {} : { memoryContext: control.memoryContext }),
        ...(deps.assertAuthority === undefined ? {} : { assertAuthority: () => deps.assertAuthority!(state) }),
        ...(control.signal === undefined ? {} : { signal: control.signal }),
        ...(control.trackActivity === undefined ? {} : { trackActivity: control.trackActivity }),
        ...(deps.projectEditor === undefined ? {} : { prepareAdmittedEdit: async context => {
          admittedEdit = await deps.projectEditor!.prepare(issue, task, state, context);
          return admittedEdit;
        } } satisfies Pick<SolveExecutionContext, "prepareAdmittedEdit">),
        recoveryOperationId: state.runId,
        ...(attemptId && prefix && signal ? { recoveryReconciliation: { attemptId, evidenceId: signal.slice(prefix.length) } } : {}),
        ...(diagnosisId && diagnosisPrefix && diagnosisSignal ? { recoveryDiagnosis: { holdId: diagnosisId, evidenceId: diagnosisSignal.slice(diagnosisPrefix.length) } } : {}),
      });
      // normalize: a raw SolveResult, or a governed SolveToPrResult carrying the merge verdict
      let result: SolveResult;
      let gov;
      let retryGuidance: string | undefined;
      if ("solveResult" in raw) {
        result = raw.solveResult;
        gov = raw.mergeAuthority;
        retryGuidance = raw.abandoned?.reason;
      } else {
        result = raw;
      }
      try { deps.assertAuthority?.(state); }
      catch {
        return { output: { schemaVersion: 1, task, issue, solve: { issueId: issue.id, solved: false,
          stagesRun: result.stagesRun, repairRounds: result.repairRounds,
          ...(result.recovery === undefined ? {} : { recovery: result.recovery }),
          gaveUpReason: "native project command authority unavailable" } },
          control: "capability-unavailable", capability: "native-project-command-authority",
          headline: "The original command no longer has current work authority; no successful proposal is admitted." };
      }
      if (deps.projectEditor !== undefined && result.solved && (admittedEdit === undefined || !isCanonicalAdmittedSolveResult(result))) throw new Error("solver claimed a successful admitted edit without a canonical pipeline effect attestation");
      // Project artifacts are durable JSON. Solve implementations/tests may attach helper methods;
      // persist only the declared SolveResult data contract, never executable properties.
      const durableResult: SolveResult = {
        issueId: result.issueId, solved: result.solved,
        ...(result.preparedProposal === undefined ? {} : { preparedProposal: result.preparedProposal }),
        ...(result.inertControls === undefined ? {} : { inertControls: result.inertControls }),
        stagesRun: result.stagesRun, repairRounds: result.repairRounds,
        ...(result.validation === undefined ? {} : { validation: result.validation }),
        ...(result.recovery === undefined ? {} : { recovery: result.recovery }),
        ...(result.prProposal === undefined ? {} : { prProposal: result.prProposal }),
        ...(result.gaveUpReason === undefined ? {} : { gaveUpReason: result.gaveUpReason }),
        ...(result.admittedEdit === undefined ? {} : { admittedEdit: result.admittedEdit }),
        ...(result.projectEditReceipt === undefined ? {} : { projectEditReceipt: result.projectEditReceipt }),
        ...(result.localization === undefined ? {} : { localization: result.localization }),
        ...(result.authority === undefined ? {} : { authority: result.authority }),
        ...(result.proposalEvidence === undefined ? {} : { proposalEvidence: result.proposalEvidence }),
        ...(result.candidateFloorEvidence === undefined ? {} : { candidateFloorEvidence: result.candidateFloorEvidence }),
      };
      if (deps.executionCeiling === "prepare") {
        if (result.solved || result.projectEditReceipt || result.prProposal || result.validation) throw new Error("preparation port returned execution evidence");
        // Never persist the captured AdmittedEditPlan as replayable execution input.
        const { admittedEdit: _admission, ...inertResult } = durableResult;
        if (result.recovery?.status === "reconciliation" && result.recovery.pendingAttemptId) return {
          output: { schemaVersion: 1, task, issue, solve: inertResult }, control: "reconciliation-required",
          effectId: `solve-recovery:${state.runId}:${result.recovery.pendingAttemptId}`,
          headline: result.recovery.reason ?? "Preparation accounting requires reconciliation before another attempt.",
        };
        return { output: { schemaVersion: 1, task, issue, solve: inertResult }, control: "capability-unavailable",
          capability: "project-execution-admission", resumeAuthority: "approval",
          headline: result.preparedProposal ? "Code proposal prepared but not executed. The full goal and external effects remain unaddressed and unqueued."
            : result.gaveUpReason ?? "Preparation did not produce a proposal; execution remains unavailable." };
      }
      if (deps.projectTester !== undefined && deps.snapshotFiles === undefined) throw new Error("configured project tests require a trusted live repository snapshot capability");
      const repositoryTreeAfterSha256 = deps.snapshotFiles === undefined ? undefined : projectRepositoryTreeSha256(await deps.snapshotFiles(issue.repoRef));
      const repositoryExecutionManifestSha256 = deps.snapshotExecutionManifest === undefined ? undefined : await deps.snapshotExecutionManifest(issue.repoRef);
      if (deps.projectTester !== undefined && repositoryExecutionManifestSha256 === undefined) throw new Error("configured project tests require a trusted full execution-input manifest capability");
      if (result.projectEditReceipt && repositoryTreeAfterSha256 !== result.projectEditReceipt.repositoryTreeAfterSha256) {
        throw new Error("canonical edit receipt does not match the live post-implementation repository");
      }
      const base: ProjectImplementationArtifact = { schemaVersion: 1, task, issue, solve: durableResult, ...(gov ? { mergeAuthority: gov } : {}), ...(retryGuidance ? { retryGuidance } : {}), ...(admittedEdit ? { admittedEditPrepared: admittedEdit } : {}), ...(repositoryTreeAfterSha256 ? { repositoryTreeAfterSha256 } : {}), ...(repositoryExecutionManifestSha256 ? { repositoryExecutionManifestSha256 } : {}) };
      // Recovery is runtime-owned. Failed evidence cannot advance into vet/learn,
      // and a governance retry never overrides an unresolved effect or hard budget.
      if (!result.solved && result.recovery) {
        const reason = result.recovery.reason ?? result.gaveUpReason ?? "recovery requires diagnosis";
        if (result.recovery.status === "reconciliation" && result.recovery.pendingAttemptId) {
          return { output: base, control: "reconciliation-required", effectId: `solve-recovery:${state.runId}:${result.recovery.pendingAttemptId}`, headline: reason };
        }
        if (result.recovery.status === "authority") return { output: base, control: "capability-unavailable", capability: `solve-authority:${state.runId}`, resumeAuthority: "approval", headline: reason };
        if (result.recovery.status === "diagnosis" && result.recovery.diagnosisId) return { output: base, control: "capability-unavailable", capability: `solve-diagnosis:${state.runId}:${result.recovery.diagnosisId}`, headline: reason };
        return { output: base, control: "capability-unavailable", capability: `solve-recovery:${result.recovery.status}`, headline: reason };
      }
      // Finishing a host-admitted local repair is not merging it. Preserve the exact
      // human-merge verdict in the artifact: the independent merge consumer still
      // refuses it. Only a canonically consumed, measured native proposal can take
      // this route; custom success flags and generic approval cannot authorize it.
      const testedProposalOnly = result.solved && isCanonicalAdmittedSolveResult(result)
        && admittedEdit?.plan.goalCheck !== undefined && result.validation?.testsPassed === true
        && deps.canFinishTestedProposal?.(state) === true;
      if (gov && gov.verdict === "human-merge" && !testedProposalOnly) {
        // governance says a PERSON must own this merge → park the loop for a human, never auto-proceed.
        return { output: base, control: "approval-required", decisionId: `merge:${result.issueId}`, severity: "routine", headline: `human-merge interaction requested: ${gov.reason}`, detail: gov.reason };
      }
      if (gov && gov.verdict === "block") {
        return { output: base, control: "capability-unavailable", capability: "merge-policy-satisfying-alternative", headline: `merge blocked: ${gov.reason}`, detail: gov.reason };
      }
      if (gov && gov.verdict === "abandon-retry") {
        return { output: base, control: "retry", headline: `merge verification requires another bounded attempt: ${gov.reason}`, detail: gov.reason };
      }
      if (!result.solved && result.validation?.failures.includes("<runner-error>")) {
        const reason = result.validation.detail ?? result.gaveUpReason ?? "the configured test capability was unavailable";
        return {
          output: base,
          control: "capability-unavailable",
          capability: "project-test-isolation",
          headline: reason,
          detail: reason,
        };
      }
      // autonomous-merge, or an ungoverned solve (mergeAuthority absent) → proceed as before.
      return {
        output: base,
        control: "advance",
        headline: gov?.verdict === "human-merge" && testedProposalOnly ? "Tested repository repair is ready; its merge remains human-gated."
          : result.solved ? `Implemented a fix for ${issue.id}` : `Could not fix ${issue.id}`,
        detail: result.solved ? `${result.stagesRun.join(" → ")}` : (result.gaveUpReason ?? "unsolved"),
      };
    },

    vet_artifact: async (state: ProjectState): Promise<StageResult> => {
      const result = solveResultOf(state);
      if (!result) {
        return { output: {}, control: "fail", headline: "No solve result to vet" };
      }
      const implementation = state.artifacts["implement"] as Partial<ProjectImplementationArtifact> | undefined;
      const task = implementation?.task;
      const issue = implementation?.issue;
      let ticket: ProjectDecompositionArtifact | undefined;
      let ticketFailure: string | undefined;
      try { ticket = validatedTicket(state).ticket; } catch (error) { ticketFailure = error instanceof Error ? error.message : "durable task decomposition could not be safely inspected"; }
      const reasons = [
        ...(ticketFailure === undefined ? [] : [ticketFailure]),
        ...(task && ticket?.admittedTaskId === task.id && ticket.tasks.filter((row) => row.id === task.id).length === 1 ? [] : ["implementation is not bound to the one admitted task"]),
        ...(task && ticket && issue?.hints?.["projectTaskId"] === task.id && issue.hints?.["planStepId"] === task.planStepId && ticket.tasks.every((row) => issue.text.includes(row.objective) && row.completionCriteria.every((criterion) => issue.text.includes(criterion.statement))) ? [] : ["solver issue does not preserve every vetted task objective and completion criterion"]),
        ...(issue && result.issueId === issue.id ? [] : ["solve result is not bound to the task issue"]),
        ...(deps.projectEditor === undefined || (result.admittedEdit?.taskId === task?.id && result.admittedEdit?.planStepId === task?.planStepId && JSON.stringify(result.admittedEdit) === JSON.stringify(implementation?.admittedEditPrepared)) ? [] : ["configured project edit proposal was not consumed by the canonical solve path"]),
        ...(deps.projectEditor === undefined || (result.projectEditReceipt?.applied === true && result.projectEditReceipt.testsExecuted === true && result.projectEditReceipt.rollbackIds.length > 0) ? [] : ["canonical project edit effect receipt is missing actual rollback or test evidence"]),
        ...(result.solved ? [] : [result.gaveUpReason ?? "solver did not produce an artifact"]),
        // Some valid n=1 SolveFn adapters predate the optional inner logic-vet signal. The outer
        // vet_artifact stage remains mandatory; an explicit inner veto is never ignored.
        ...(result.validation?.testsPassed === true && result.validation.vettingCleared !== false ? [] : [result.validation?.detail ?? "configured verification did not pass"]),
      ];
      if (reasons.length === 0 && deps.projectTester !== undefined) {
        const artifact = await deps.projectTester.run(issue!, state);
        if (artifact.verdict === "passed") return { output: artifact, control: "advance", headline: `Independent isolated tests passed for ${artifact.taskId}` };
        if (artifact.verdict === "failed") return {
          output: artifact, control: "rework", reworkTo: "implement",
          headline: "Independent tests exposed a genuine failure; returning for bounded repair",
          detail: artifact.failureOutput || artifact.reasons.join("; "),
        };
        if (artifact.verdict === "stale") return {
          output: artifact, control: "reconciliation-required", effectId: `project-test:${artifact.implementationSha256}`,
          headline: "Repository changed across the independent test boundary; reconciliation is required",
          detail: artifact.reasons.join("; "),
        };
        return {
          output: artifact, control: "capability-unavailable", capability: `project-test-isolation:${artifact.isolation.requiredTier}`,
          headline: "Independent verification could not produce a trustworthy verdict",
          detail: artifact.reasons.join("; "),
        };
      }
      const verification = Object.freeze({ schemaVersion: 1 as const, taskId: task?.id ?? "", planStepId: task?.planStepId ?? "", passed: reasons.length === 0, repairAttempt: state.reworkCount, reasons: Object.freeze(reasons) });
      if (verification.passed) return { output: verification, control: "advance", headline: `Vetted artifact for ${verification.taskId}` };
      return {
        output: verification,
        control: "rework",
        reworkTo: "implement",
        headline: `Vetting failed for ${result.issueId} — sending back`,
        detail: reasons.join("; "),
      };
    },

    learn: async (state: ProjectState): Promise<StageResult> => {
      const result = solveResultOf(state);
      if (result) {
        const regSig = result.regressionSignature();
        recordBuildOutcome(deps.spine, {
          buildId: result.issueId,
          context: `project:${state.runId};task:${(state.artifacts["implement"] as Partial<ProjectImplementationArtifact> | undefined)?.task?.id ?? "missing"};solve:${result.stagesRun.join(">")}`,
          cleanResolved: result.solved && (result.validation?.testsPassed ?? false) && (() => {
            const vet = state.artifacts["vet_artifact"] as { passed?: unknown; verdict?: unknown; testsPassed?: unknown } | undefined;
            return vet?.passed === true || (vet?.verdict === "passed" && vet.testsPassed === true);
          })(),
          ...(regSig ? { regressionSignature: regSig } : {}),
        });
      }
      return { output: { learned: true }, control: "advance", headline: "Recorded build outcome for learning" };
    },
  };
}

function solveResultOf(state: ProjectState): (SolveResult & { regressionSignature(): string | undefined }) | undefined {
  const artifacts = state.artifacts as Record<string, unknown>;
  const implement = artifacts["implement"] as { solve?: SolveResult } | undefined;
  const result = implement?.solve;
  if (!result) return undefined;
  return {
    ...result,
    regressionSignature(): string | undefined {
      // A gave-up-with-regression run carries a signature the learning loop can cluster on.
      return result.gaveUpReason?.includes("regression") ? `repair-regression:${result.issueId}` : undefined;
    },
  };
}
