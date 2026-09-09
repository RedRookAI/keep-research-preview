/**
 * Autonomy Engine — ProjectLoop backbone (build item 2).
 *
 * The universal pipeline every project runs through, regardless of what it is (romance
 * novel, academic paper, app): research → plan → vet → ticket → implement → vet → done.
 *
 * SOTA-grounded (2026 orchestration consensus):
 *  - "The model never decides whether to keep going; the RUNTIME does." The runtime holds
 *    the hard limits (a quantum/step budget) and forces termination — the antidote to
 *    runaway loops. Stages are DETERMINISTIC control flow; the model only supplies the
 *    CONTENT within a stage via injected executors.
 *  - Converged primitives: typed state, checkpoint every transition, interrupt/resume,
 *    explicit gates before high-risk actions. The orchestration graph is a "policy
 *    enforcement boundary, not just control flow."
 *  - Failure mode designed against: "bad output in stage 1 cascades downstream with no
 *    backtracking" — so VET stages can route work BACK, not only forward.
 *
 * The stage executors are injected seams: this backbone SEQUENCES and GOVERNS; the actual
 * research/plan/implement work is pluggable (the auto-loops fill them in later). Every
 * transition narrates (ProgressNarrator) and checkpoints (spine). Zero deps.
 */

import type { Spine } from "../spine/spine.js";
import type { ProjectJobActivityTracker } from "../session/project_job_journal.js";
import { TaskMemoryUnavailableError, type TaskMemoryContext } from "../memory/task_context.js";
import type { ProgressNarrator } from "./progress_narrator.js";
import type { NonPersistableRegistry } from "../scheduler/saga_sequencer.js";
import type { TraceRecorder, Span } from "../observability/tracing.js";
import { currentTrace } from "../observability/trace_context.js";
import type { FeasibilityReport } from "./feasibility_check.js";
import { InMemoryProjectCheckpointStore, ProjectCheckpointConflictError, type ProjectCheckpointStore } from "./project_checkpoint_store.js";
import {
  PROJECT_STATE_SCHEMA_VERSION,
  PROJECT_STAGES,
  type AuthorityPosture,
  type ProjectState,
  type ProjectStatus,
  type Stage,
  type ProjectStrategy,
  type WaitState,
} from "./project_state.js";

export type { AuthorityPosture, ProjectState, ProjectStatus, Stage, WaitState } from "./project_state.js";

const ZERO_COST = { inputUsd: 0, cachedInputUsd: 0, outputUsd: 0, tokenUsd: 0, humanUsd: 0, infraUsd: 0, toolApiUsd: 0, totalUsd: 0 };

/** The fixed stages every project moves through. Order is deterministic. */
/** The canonical forward order. rag is optional (skipped unless a stage requests it). */
const FORWARD: readonly Stage[] = PROJECT_STAGES;

/** The outcome a stage executor returns. */
export interface StageResult {
  /** Content this stage produced (merged into artifacts under the stage name). */
  readonly output: unknown;
  /**
   * Control signal:
   *  - "advance": proceed to the next stage.
   *  - "rework": send work BACK to a named earlier stage (vet failure; no blind cascade).
   *  - "need-rag": (from research) request the optional rag stage next.
   * Compatibility controls are retained while callers migrate. The runtime normalizes them
   * into the durable transition vocabulary; no control can mutate state directly.
   */
  readonly control:
    | "advance" | "rework" | "need-rag" | "block-human" | "fail"
    | "retry" | "capability-unavailable" | "reconciliation-required" | "approval-required" | "policy-hold";
  /** For "rework": which stage to return to. */
  readonly reworkTo?: Stage;
  /** A one-or-two-sentence progress headline for the narrator. */
  readonly headline: string;
  /** Optional detail. */
  readonly detail?: string;
  /** How many steps this stage consumed (default 1). */
  readonly stepsUsed?: number;
  readonly capability?: string;
  /** Capability waits caused by denied consequential authority require approval authority to resume. */
  readonly resumeAuthority?: "work" | "approval";
  readonly effectId?: string;
  readonly decisionId?: string;
  readonly policyId?: string;
  readonly severity?: "routine" | "extreme";
  /** `fail` is terminal only when explicitly classified permanent. Legacy fail defaults to recoverable capability debt. */
  readonly permanent?: boolean;
}

/** A stage executor: the pluggable seam that does the actual work of one stage. */
export interface StageExecutor {
  (state: ProjectState, control?: { readonly signal?: AbortSignal; readonly trackActivity?: ProjectJobActivityTracker; readonly memoryContext?: TaskMemoryContext }): Promise<StageResult>;
}

/** Registry of executors. A missing required stage is durable capability debt, never pass-through. */
export type StageExecutors = Partial<Record<Stage, StageExecutor>>;

export interface ProjectLoopConfig {
  /** Total quantum/step budget for the whole run (runtime-enforced termination). */
  readonly stepBudget: number;
  /** Max times work may be routed back before we pause for human help (anti-thrash). */
  readonly maxRework: number;
  readonly retryRunLimit: number;
  readonly retryPerStageLimit: number;
  readonly retryBaseDelayMs: number;
  readonly retryMaxDelayMs: number;
}

const DEFAULT_CONFIG: ProjectLoopConfig = {
  stepBudget: 100, maxRework: 3, retryRunLimit: 8, retryPerStageLimit: 3,
  retryBaseDelayMs: 1_000, retryMaxDelayMs: 60_000,
};

/** The result of running (or advancing) the loop. */
export interface LoopRunResult {
  readonly state: ProjectState;
  /** The ordered stages actually visited this run (for inspection/tests). */
  readonly visited: readonly Stage[];
  /** The intake feasibility report (scope-of-competence). Present when the loop was invoked via the autonomy loop. */
  readonly feasibility?: FeasibilityReport;
}

export interface ResumeProjectInput {
  readonly addSteps?: number;
  readonly approval?: { readonly decisionId: string; readonly approved: boolean };
  readonly policy?: { readonly policyId: string; readonly proceed: boolean };
  readonly reconciliation?: { readonly effectId: string; readonly resolved: boolean; readonly evidenceId: string };
  readonly capability?: { readonly capability: string; readonly evidenceId: string };
}

export interface ProjectPermissionRequest {
  readonly runId: string;
  readonly stage: Stage;
  readonly reason: string;
  readonly severity: "routine" | "extreme";
}

export type ProjectPermissionDecision = "proceed" | "approval" | "deny";
export type ProjectPermissionPolicy = (request: ProjectPermissionRequest) => Promise<ProjectPermissionDecision>;

class ProjectStateSupersededError extends Error {
  constructor(readonly winner: ProjectState) { super(`project state superseded by revision ${winner.revision}`); }
}

export class ProjectLoop {
  private readonly config: ProjectLoopConfig;

  constructor(
    private readonly spine: Spine,
    private readonly narrator: ProgressNarrator,
    private readonly executors: StageExecutors,
    config: Partial<ProjectLoopConfig> = {},
    /** Optional: guards durable checkpoints so none is taken mid-side-effect (never resume into a half-applied mutation). */
    private readonly nonPersistable?: NonPersistableRegistry,
    /** Optional: records a span per stage for failure localization + cost attribution over real runs. */
    private readonly tracer?: TraceRecorder,
    /** Authoritative full-state recovery store. Installed composition supplies the filesystem adapter. */
    private readonly checkpoints: ProjectCheckpointStore = new InMemoryProjectCheckpointStore(),
    private readonly now: () => number = Date.now,
    private readonly permissionPolicy?: ProjectPermissionPolicy,
    private readonly signal?: AbortSignal,
    private readonly trackActivity?: ProjectJobActivityTracker,
    private readonly memoryContext?: TaskMemoryContext,
  ) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /** Create the initial state for a new project run. */
  init(runId: string, goal: string, posture: AuthorityPosture = "autonomous", strategy: ProjectStrategy = { kind: "software" }, projectId?: import("../session/project_id.js").ProjectId, goalContext?: string, preparationBinding?: string, operationBinding?: string): ProjectState {
    if (preparationBinding !== undefined && operationBinding !== undefined) throw new Error("preparation cannot acquire an execution disposition");
    const state: ProjectState = {
      schemaVersion: PROJECT_STATE_SCHEMA_VERSION, revision: 0, runId, ...(projectId ? { projectId } : {}), goal, stage: "understand", artifacts: {
        ...(goalContext === undefined ? {} : { goal_work_context: goalContext }),
        ...(preparationBinding === undefined ? {} : { software_preparation: { schemaVersion: 1, binding: preparationBinding } }),
        ...(operationBinding === undefined ? {} : { software_operation: { schemaVersion: 1, binding: operationBinding } }),
        ...(this.memoryContext === undefined ? {} : { memory_context_required: true, memory_copy_notice: this.memoryContext.copyNotice }),
      }, posture, strategy,
      stepsRemaining: this.config.stepBudget,
      reworkCount: 0,
      status: "running",
      retry: { attemptsByStage: {}, attemptsConsumed: 0, runLimit: this.config.retryRunLimit }, consumedSignals: [],
    };
    return this.createCheckpoint(state, "init");
  }

  restore(runId: string): ProjectState | undefined { return this.checkpoints.load(runId); }

  holdCapability(state: ProjectState, capability: string, reason: string, resumeAuthority: "work" | "approval" = "work"): ProjectState {
    return this.waitForCapability(state, state.stage, capability, reason, resumeAuthority);
  }

  pauseBudget(state: ProjectState, reason: string): ProjectState {
    return this.transitionCheckpoint({ ...state, status: "paused-budget", note: reason }, "paused-budget");
  }

  async holdForApproval(state: ProjectState, reason: string, severity: "routine" | "extreme" = "routine"): Promise<ProjectState> {
    const decisionId = `${state.runId}:preflight:${state.stage}:${state.revision + 1}`;
    const wait: WaitState = { kind: "approval", activity: state.stage, createdAt: this.now(), decisionId, severity, resumeMode: "rerun", reason };
    return this.transitionCheckpoint({ ...state, status: "waiting-approval", wait, note: reason }, "waiting-approval");
  }

  holdForPolicy(state: ProjectState, policyId: string, reason: string): ProjectState {
    const wait: WaitState = { kind: "policy", activity: state.stage, createdAt: this.now(), policyId, reason };
    return this.transitionCheckpoint({ ...state, status: "waiting-policy", wait, note: reason }, "waiting-policy");
  }

  /** Load the authoritative snapshot and apply one idempotent resume signal. */
  async resume(runId: string, input: ResumeProjectInput = {}, admitPreparedExecution?: (state: ProjectState) => string | undefined): Promise<LoopRunResult> {
    try { return await this.resumeInternal(runId, input, admitPreparedExecution); }
    catch (error) {
      if (error instanceof ProjectStateSupersededError) return { state: error.winner, visited: [] };
      throw error;
    }
  }

  private async resumeInternal(runId: string, input: ResumeProjectInput, admitPreparedExecution?: (state: ProjectState) => string | undefined): Promise<LoopRunResult> {
    let state = this.checkpoints.load(runId);
    if (state === undefined) throw new Error(`unknown project run ${runId}`);
    if (state.status === "completed" || state.status === "failed") return { state, visited: [] };
    // A resume signal cannot erase the original context requirement or supply authority.
    this.checkMemoryContext(state);
    // Only the trusted host can admit this separate phase. The ordinary request is
    // work intent, not authority; approval/capability signals cannot create it.
    const executionBinding = Object.keys(input).length === 0 && state.status === "waiting-capability"
      ? admitPreparedExecution?.(state) : undefined;
    if (executionBinding !== undefined) {
      state = this.transitionCheckpoint({ ...clearWait(state), status: "running", artifacts: {
        ...state.artifacts,
        software_prepared_implementation: state.artifacts["implement"],
        software_operation: { schemaVersion: 1, binding: executionBinding },
      } }, "native-prepared-execution-admitted");
      // Preserve run identity, step/retry counters, original recovery history and
      // the old preparation marker. The executor must obtain fresh edit admission.
      return this.run(state);
    }
    if (state.status === "paused-budget") {
      const add = input.addSteps ?? 0;
      if (!Number.isSafeInteger(add) || add <= 0) return { state, visited: [] };
      state = this.transitionCheckpoint({ ...clearWait(state), status: "running", stepsRemaining: state.stepsRemaining + add }, "budget-resume");
    } else if (state.status === "waiting-retry") {
      if (state.wait?.kind !== "retry" || this.now() < state.wait.resumeAt) return { state, visited: [] };
      state = this.transitionCheckpoint({ ...clearWait(state), status: "running" }, "retry-due");
    } else if (state.status === "waiting-capability") {
      if (state.wait?.kind !== "capability" || input.capability?.capability !== state.wait.capability || input.capability.evidenceId.length === 0) return { state, visited: [] };
      const attempt = state.retry.attemptsByStage[state.stage] ?? 0;
      if (state.wait.capability.startsWith("recovery:") && (state.retry.attemptsConsumed >= state.retry.runLimit || attempt >= this.config.retryPerStageLimit)) return { state, visited: [] };
      const signal = `capability:${state.wait.capability}:${input.capability.evidenceId}`;
      if (state.consumedSignals.includes(signal)) return { state, visited: [] };
      state = this.transitionCheckpoint({ ...clearWait(state), status: "running", consumedSignals: [...state.consumedSignals, signal] }, "capability-recheck");
    } else if (state.status === "waiting-approval") {
      if (state.wait?.kind !== "approval" || input.approval?.decisionId !== state.wait.decisionId) return { state, visited: [] };
      const decisionId = state.wait.decisionId;
      const signal = `approval:${decisionId}:${input.approval.approved ? "approved" : "declined"}`;
      if (state.consumedSignals.some((entry) => entry.startsWith(`approval:${decisionId}:`))) return { state, visited: [] };
      const decided = { ...clearWait(state), consumedSignals: [...state.consumedSignals, signal] };
      state = input.approval.approved
        ? state.wait.resumeMode === "advance"
          ? this.advanceStage({ ...decided, status: "running" }, state.stage)
          : this.transitionCheckpoint({ ...decided, status: "running" }, "approval-granted")
        : this.waitForCapability({ ...decided, status: "running" }, state.stage, `alternative:${state.stage}`, "Approval declined; preserving the run for a safe alternative.", "approval");
    } else if (state.status === "waiting-policy") {
      if (state.wait?.kind !== "policy" || input.policy?.policyId !== state.wait.policyId) return { state, visited: [] };
      const policyId = state.wait.policyId;
      const signal = `policy:${policyId}:${input.policy.proceed ? "proceed" : "deny"}`;
      if (state.consumedSignals.some((entry) => entry.startsWith(`policy:${policyId}:`))) return { state, visited: [] };
      const decided = { ...clearWait(state), consumedSignals: [...state.consumedSignals, signal] };
      state = input.policy.proceed
        ? this.advanceStage({ ...decided, status: "running" }, state.stage)
        : this.waitForCapability({ ...decided, status: "running" }, state.stage, `policy-alternative:${state.stage}`, "Policy declined this path; preserving the run for an alternative.", "approval");
    } else if (state.status === "waiting-reconciliation") {
      if (state.wait?.kind !== "reconciliation" || input.reconciliation?.effectId !== state.wait.effectId || !input.reconciliation.resolved || input.reconciliation.evidenceId.length === 0) return { state, visited: [] };
      const signal = `reconciliation:${state.wait.effectId}:${input.reconciliation.evidenceId}`;
      if (state.consumedSignals.includes(signal)) return { state, visited: [] };
      state = this.transitionCheckpoint({ ...clearWait(state), status: "running", consumedSignals: [...state.consumedSignals, signal] }, "reconciled");
    }
    return this.run(state);
  }

  /**
   * Run the loop from the given state until it completes, fails, or pauses (budget or
   * human). Resumable: pass a previously-paused state back in to continue. The RUNTIME
   * decides advancement — never an executor's free choice to "keep going."
   */
  async run(initial: ProjectState): Promise<LoopRunResult> {
    try { return await this.runInternal(initial); }
    catch (error) {
      if (error instanceof ProjectStateSupersededError) return { state: error.winner, visited: [] };
      throw error;
    }
  }

  private async runInternal(initial: ProjectState): Promise<LoopRunResult> {
    this.checkMemoryContext(initial);
    let state = initial;
    const visited: Stage[] = [];

    while (state.status === "running" && state.stage !== "done") {
      if (this.signal?.aborted) {
        state = this.waitForCapability(state, state.stage, "project-cancellation", "Operator cancelled before this stage started; no new stage was dispatched.");
        break;
      }
      // Runtime-held budget check: force a clean checkpoint pause when exhausted.
      if (state.stepsRemaining <= 0) {
        state = { ...state, status: "paused-budget", note: "Step budget exhausted — paused for review/top-up." };
        this.narrator.blocked(state.stage, "I've hit the work budget for this run, so I've paused here.", "You can review progress and resume with more budget.");
        state = this.transitionCheckpoint(state, "paused-budget");
        break;
      }

      const stage = state.stage;
      visited.push(stage);
      const executor = this.executors[stage];

      // Missing work is exact, resumable capability debt. It never fabricates a prerequisite artifact.
      if (!executor) {
        state = this.waitForCapability(state, stage, `project-stage:${stage}`, `No executor is installed for required stage "${stage}".`);
        this.narrator.blocked(stage, `Waiting for the ${stage} capability.`, state.note);
        break;
      }

      // Write-ahead activity intent: after this checkpoint, a crash can never make recovery
      // confuse "not started" with "possibly accepted by an external sink". Reconciliation
      // evidence must explicitly establish that retry is safe before the executor runs again.
      const effectId = `${state.runId}:${stage}:${state.revision + 1}`;
      const inFlight: WaitState = { kind: "reconciliation", activity: stage, createdAt: this.now(), effectId, reason: `Activity ${stage} may be in flight; reconcile before retry after process loss.` };
      state = this.transitionCheckpoint({ ...state, status: "waiting-reconciliation", wait: inFlight, note: inFlight.reason }, "activity-in-flight");
      if (this.nonPersistable && !this.nonPersistable.canCheckpoint(state.runId)) {
        this.narrator.blocked(stage, "An existing effect region must be reconciled before this activity can start.", inFlight.reason);
        break;
      }
      const executingState: ProjectState = { ...clearWait(state), status: "running" };

      this.narrator.start(stage, `Starting: ${stage}`);
      const stageStart = Date.now();
      let result: StageResult;
      const control = { ...(this.signal === undefined ? {} : { signal: this.signal }), ...(this.trackActivity === undefined ? {} : { trackActivity: this.trackActivity }), ...(this.memoryContext === undefined ? {} : { memoryContext: this.memoryContext }) };
      try {
        // The executor is where a stage's external side effects happen. Hold a non-persistable region across it so no
        // durable checkpoint is taken mid-mutation — a crash+resume must never re-enter a half-applied side effect.
        result = this.nonPersistable
          ? await this.nonPersistable.within(`${state.runId}:${stage}`, () => executor(executingState, control), state.runId)
          : await executor(executingState, control);
      } catch (e) {
        this.recordSpan(stage, state.runId, stageStart, "tool-error");
        const detail = e instanceof Error ? e.message : String(e);
        const charged = { ...executingState, stepsRemaining: Math.max(0, executingState.stepsRemaining - 1) };
        // An arbitrary throw does not establish that the effect failed before commit.
        // Preserve the already-written effect identity; only explicit reconciliation
        // can permit replay. Retryable failures must return a classified retry control.
        const reason = `Stage "${stage}" threw; reconcile its effect before retry: ${detail}`;
        state = this.transitionCheckpoint({ ...charged, status: "waiting-reconciliation", wait: { ...inFlight, reason }, note: reason }, "exception-reconciliation");
        this.narrator.blocked(stage, `The ${stage} activity requires reconciliation.`, detail);
        break;
      }
      if (this.signal?.aborted) {
        const reason = `Operator cancelled during ${stage}; reconcile its effects before retry. Late stage output was not accepted.`;
        state = this.transitionCheckpoint({ ...state, stepsRemaining: Math.max(0, executingState.stepsRemaining - 1), wait: { ...inFlight, reason }, note: reason }, "cancelled-in-flight");
        this.recordSpan(stage, state.runId, stageStart, "tool-error");
        break;
      }
      state = executingState;
      // A stage that returned a control signal executed; a "fail" control is a stage-level failure (tool-error), else ok.
      this.recordSpan(stage, state.runId, stageStart, result.control === "fail" ? "tool-error" : "ok");

      // Normalize executor data before it can enter durable state. Undefined fields are omitted;
      // functions, exotic prototypes, cycles, non-finite numbers, and unsupported values are invalid output.
      let output: unknown;
      try { output = normalizeDurableJson(result.output); }
      catch (error) {
        state = this.transitionCheckpoint({ ...state, status: "failed", note: `Invalid durable output from ${stage}: ${(error as Error).message}` }, "invalid-executor-output");
        this.narrator.failed(stage, `The ${stage} executor returned invalid durable data.`, (error as Error).message);
        break;
      }
      const reportedSteps = result.stepsUsed ?? 1;
      if (!Number.isSafeInteger(reportedSteps) || reportedSteps <= 0) {
        state = this.transitionCheckpoint({ ...state, status: "failed", note: `Invalid stepsUsed from ${stage}: ${String(reportedSteps)}` }, "invalid-executor-output");
        break;
      }
      const stepsUsed = Math.min(state.stepsRemaining, reportedSteps);
      const artifacts = { ...state.artifacts, [stage]: output };
      state = { ...state, artifacts, stepsRemaining: state.stepsRemaining - stepsUsed };

      // Apply the executor's control signal (but the RUNTIME owns the transition).
      switch (result.control) {
        case "advance":
          this.narrator.done(stage, result.headline, result.detail);
          state = this.advanceStage(state, stage);
          break;
        case "need-rag":
          this.narrator.done(stage, result.headline, result.detail);
          state = { ...state, stage: "rag" };
          state = this.transitionCheckpoint(state, "transition");
          break;
        case "rework": {
          const target = result.reworkTo ?? priorStage(stage);
          if (FORWARD.indexOf(target) < 0 || FORWARD.indexOf(target) >= FORWARD.indexOf(stage)) {
            state = this.transitionCheckpoint({ ...state, status: "failed", note: `Invalid rework target ${target} from ${stage}; target must be an earlier stage.` }, "invalid-executor-output");
            this.narrator.failed(stage, "The executor proposed an invalid rework transition.", String(target));
            break;
          }
          if (state.reworkCount >= this.config.maxRework) {
            state = this.waitForCapability(state, stage, `rework-strategy:${stage}`, `Rework limit reached at ${stage}; a different strategy or capability is required.`);
            this.narrator.blocked(stage, "This approach exhausted its rework budget; the run is preserved for another strategy.", result.detail);
          } else {
            state = { ...state, stage: target, reworkCount: state.reworkCount + 1 };
            this.narrator.narrate({ stage, phase: "update", headline: result.headline || `Sending work back to ${target} to fix an issue.`, ...(result.detail === undefined ? {} : { detail: result.detail }) });
            state = this.transitionCheckpoint(state, "rework");
          }
          break;
        }
        case "block-human":
        case "approval-required":
          state = await this.applyApprovalOutcome(state, stage, result);
          this.narrator.blocked(stage, state.note ?? result.headline, result.detail);
          break;
        case "fail":
          if (result.permanent === true) {
            state = this.transitionCheckpoint({ ...state, status: "failed", note: result.headline }, "permanent-impossibility");
            this.narrator.failed(stage, result.headline, result.detail);
          } else {
            state = this.waitForCapability(state, stage, `recovery:${stage}`, result.headline);
            this.narrator.blocked(stage, result.headline, result.detail);
          }
          break;
        case "retry":
          state = this.retryOrDefer(state, stage, result.headline);
          this.narrator.blocked(stage, result.headline, result.detail);
          break;
        case "capability-unavailable":
          state = this.waitForCapability(state, stage, result.capability ?? `project-stage:${stage}`, result.headline, result.resumeAuthority ?? "work");
          this.narrator.blocked(stage, result.headline, result.detail);
          break;
        case "reconciliation-required": {
          const wait: WaitState = { kind: "reconciliation", activity: stage, createdAt: this.now(), effectId: result.effectId ?? `${state.runId}:${stage}`, reason: result.headline };
          state = this.transitionCheckpoint({ ...state, status: "waiting-reconciliation", wait, note: result.headline }, "waiting-reconciliation");
          this.narrator.blocked(stage, result.headline, result.detail);
          break;
        }
        case "policy-hold": {
          const wait: WaitState = { kind: "policy", activity: stage, createdAt: this.now(), policyId: result.policyId ?? `policy:${stage}`, reason: result.headline };
          state = this.transitionCheckpoint({ ...state, status: "waiting-policy", wait, note: result.headline }, "waiting-policy");
          this.narrator.blocked(stage, result.headline, result.detail);
          break;
        }
        default: {
          const unknown = (result as { readonly control?: unknown }).control;
          state = this.transitionCheckpoint({ ...state, status: "failed", note: `Unknown executor control from ${stage}: ${String(unknown)}` }, "invalid-executor-output");
          this.narrator.failed(stage, "The executor returned an unknown control signal.", String(unknown));
          break;
        }
      }
    }

    // Reached "done" cleanly.
    if (state.stage === "done" && state.status === "running") {
      state = { ...state, status: "completed" };
      this.narrator.done("done", "All stages complete — ready for your review.");
      state = this.transitionCheckpoint(state, "completed");
    }

    return { state, visited };
  }

  /** Advance to the next forward stage, skipping optional rag unless requested. */
  private advanceStage(state: ProjectState, from: Stage): ProjectState {
    let idx = FORWARD.indexOf(from) + 1;
    // Skip the optional rag stage in the default forward path.
    if (FORWARD[idx] === "rag") idx += 1;
    const next = FORWARD[idx] ?? "done";
    const advanced = { ...state, stage: next };
    return this.transitionCheckpoint(advanced, "transition");
  }

  private checkMemoryContext(state: ProjectState): void {
    if (state.artifacts["memory_context_required"] === true && this.memoryContext === undefined) throw new TaskMemoryUnavailableError("authority");
    if (this.memoryContext) {
      if (!this.memoryContext.restore) throw new TaskMemoryUnavailableError("custody");
      this.memoryContext.restore(state.artifacts["memory_dependency"]);
    }
    this.memoryContext?.assertCurrent();
  }

  private withMemoryDependency(state: ProjectState): ProjectState {
    if (!this.memoryContext) return state;
    return { ...state, artifacts: { ...state.artifacts, memory_context_required: true,
      memory_dependency: this.memoryContext.checkpoint?.() ?? { schema: "keep.task-memory-snapshot/v1", status: "unavailable" } } };
  }

  /** Record a per-stage span (flat within the run's trace; earliest failing stage is the root for triage). */
  private recordSpan(stage: Stage, runId: string, startTs: number, status: Span["status"]): void {
    const tenant = currentTrace()?.tenant;
    this.tracer?.record({ name: stage, taskId: runId, traceId: runId, cost: ZERO_COST, startTs, endTs: Date.now(), status, ...(tenant === undefined ? {} : { tenant }) });
  }

  private createCheckpoint(state: ProjectState, reason: string): ProjectState {
    const saved = this.checkpoints.save(this.withMemoryDependency(state), undefined);
    this.auditCheckpoint(saved.state, saved.sha256, reason, undefined);
    return saved.state;
  }

  /** Persist full state first; the spine receives only digest + transition metadata. */
  private transitionCheckpoint(candidate: ProjectState, reason: string): ProjectState {
    // If a side-effect region is open, refuse the durable checkpoint — persisting now could resume into a half-applied
    // mutation. This is a programmer error: executors must return only after the region closes.
    if (this.nonPersistable && !this.nonPersistable.canCheckpoint(candidate.runId) && candidate.status !== "waiting-reconciliation") {
      this.spine.stage({
        type: "checkpoint",
        actor: "project_loop",
        payload: { event: "project.checkpoint_deferred", runId: candidate.runId, stage: candidate.stage, reason, openRegions: this.nonPersistable.openRegionsFor(candidate.runId) },
      });
      throw new Error(`refusing project transition while non-persistable regions remain open: ${this.nonPersistable.openRegionsFor(candidate.runId).join(",")}`);
    }
    const priorRevision = candidate.revision;
    const state = this.withMemoryDependency({ ...candidate, revision: priorRevision + 1 });
    let saved;
    try { saved = this.checkpoints.save(state, priorRevision); }
    catch (error) {
      if (error instanceof RangeError) {
        const prior = this.checkpoints.load(candidate.runId);
        if (prior === undefined) throw error;
        const failed = { ...clearWait(prior), revision: prior.revision + 1, status: "failed" as const, note: `Project output exceeded the durable checkpoint ceiling: ${error.message}` };
        const failedSaved = this.checkpoints.save(failed, prior.revision);
        this.auditCheckpoint(failedSaved.state, failedSaved.sha256, "checkpoint-ceiling", prior.revision);
        return failedSaved.state;
      }
      if (!(error instanceof ProjectCheckpointConflictError)) throw error;
      const winner = this.checkpoints.load(candidate.runId);
      if (winner === undefined) throw error;
      this.spine.stage({ type: "checkpoint", actor: "project_loop", payload: { event: "project.checkpoint_conflict", runId: candidate.runId, attemptedRevision: state.revision, winnerRevision: winner.revision } });
      throw new ProjectStateSupersededError(winner);
    }
    this.auditCheckpoint(saved.state, saved.sha256, reason, priorRevision);
    return saved.state;
  }

  private auditCheckpoint(state: ProjectState, sha256: string, reason: string, priorRevision: number | undefined): void {
    this.spine.stage({
      type: "checkpoint",
      actor: "project_loop",
      payload: {
        event: "project.checkpoint",
        runId: state.runId,
        stage: state.stage,
        status: state.status,
        revision: state.revision,
        priorRevision: priorRevision ?? null,
        snapshotSha256: sha256,
        stepsRemaining: state.stepsRemaining,
        reworkCount: state.reworkCount,
        reason,
      },
    });
  }

  private waitForCapability(state: ProjectState, stage: Stage, capability: string, reason: string, resumeAuthority: "work" | "approval" = "work"): ProjectState {
    const wait: WaitState = { kind: "capability", activity: stage, createdAt: this.now(), capability, resumeAuthority, reason };
    return this.transitionCheckpoint({ ...state, status: "waiting-capability", wait, note: reason }, "waiting-capability");
  }

  private retryOrDefer(state: ProjectState, stage: Stage, reason: string): ProjectState {
    const prior = state.retry.attemptsByStage[stage] ?? 0;
    if (prior >= this.config.retryPerStageLimit || state.retry.attemptsConsumed >= state.retry.runLimit) {
      return this.waitForCapability(state, stage, `recovery:${stage}`, `Retry budget exhausted. ${reason}`);
    }
    const attempt = prior + 1;
    const attemptsByStage = { ...state.retry.attemptsByStage, [stage]: attempt };
    const delay = deterministicRetryDelay(state.runId, stage, attempt, this.config.retryBaseDelayMs, this.config.retryMaxDelayMs);
    const wait: WaitState = { kind: "retry", activity: stage, createdAt: this.now(), resumeAt: this.now() + delay, attempt, reason };
    return this.transitionCheckpoint({
      ...state, status: "waiting-retry", wait, note: reason,
      retry: { ...state.retry, attemptsByStage, attemptsConsumed: state.retry.attemptsConsumed + 1 },
    }, "waiting-retry");
  }

  private async applyApprovalOutcome(state: ProjectState, stage: Stage, result: StageResult): Promise<ProjectState> {
    const severity = result.severity ?? "routine";
    if (state.posture === "autonomous" && severity !== "extreme") {
      return this.waitForCapability(state, stage, `safe-resolution:${stage}`, `Autonomous posture deferred the isolated action: ${result.headline}`, "approval");
    }
    if (state.posture === "policy-calibrated") {
      if (this.permissionPolicy === undefined) return this.waitForCapability(state, stage, "project-permission-policy", `No permission policy is installed for: ${result.headline}`);
      const decision = await this.permissionPolicy({ runId: state.runId, stage, reason: result.headline, severity });
      if (decision === "proceed") return this.advanceStage(state, stage);
      if (decision === "deny") return this.waitForCapability(state, stage, `policy-alternative:${stage}`, `Policy denied this path: ${result.headline}`, "approval");
    }
    const baseId = result.decisionId ?? `${state.runId}:${stage}`;
    const decisionId = `${baseId}:${state.revision + 1}`;
    const wait: WaitState = {
      kind: "approval", activity: stage, createdAt: this.now(),
      decisionId,
      severity, resumeMode: "advance", reason: result.headline,
    };
    return this.transitionCheckpoint({ ...state, status: "waiting-approval", wait, note: result.headline }, "waiting-approval");
  }
}

function deterministicRetryDelay(runId: string, stage: Stage, attempt: number, baseMs: number, maxMs: number): number {
  const exponent = Math.min(30, Math.max(0, attempt - 1));
  const ceiling = Math.min(maxMs, baseMs * 2 ** exponent);
  let hash = 2166136261;
  for (const char of `${runId}\0${stage}\0${attempt}`) hash = Math.imul(hash ^ char.charCodeAt(0), 16777619) >>> 0;
  const jitter = 0.75 + (hash / 0xffff_ffff) * 0.25;
  return Math.max(1, Math.floor(ceiling * jitter));
}

function clearWait(state: ProjectState): Omit<ProjectState, "wait" | "note"> {
  const { wait: _wait, note: _note, ...rest } = state;
  return rest;
}

function normalizeDurableJson(value: unknown, seen = new Set<object>()): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("non-finite number");
    return value;
  }
  if (typeof value === "undefined") return null;
  if (typeof value !== "object") throw new TypeError(`unsupported ${typeof value}`);
  if (seen.has(value)) throw new TypeError("cyclic value");
  seen.add(value);
  try {
    if (Array.isArray(value)) return value.map((entry) => normalizeDurableJson(entry, seen));
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError("non-plain object");
    const output: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      if (entry !== undefined) output[key] = normalizeDurableJson(entry, seen);
    }
    return output;
  } finally { seen.delete(value); }
}

/** The stage immediately before a given one (default rework target). */
function priorStage(stage: Stage): Stage {
  const idx = FORWARD.indexOf(stage);
  return idx > 0 ? FORWARD[idx - 1]! : stage;
}

/** Expose the canonical stage order (for interfaces/tests). */
export function stageOrder(): readonly Stage[] {
  return FORWARD;
}

/**
 * CONCURRENCY-GOVERNOR — a fair-share ADMISSION decision for concurrent project runs on one box. Per-project state is
 * already isolated; this bounds simultaneous RESOURCE contention. Given the currently-running set (each with a resource
 * weight), an aggregate ceiling, and a per-project fair share, it decides ADMITTED / QUEUED / DENIED. Admission control
 * belongs at the gate, BEFORE execution ("decisions before resources commit" — arXiv 2603.00356); the actual OS-level
 * resource cap (cgroups / memory+CPU limits) is a named [ENV] SEAM — this decides admission, it does not itself cap a
 * kernel resource.
 *
 * SAFE: the aggregate ceiling is HARD — the sum of admitted weights NEVER exceeds it (no silent over-admission; "aggregate
 * consumption respects the original constraint" — arXiv 2601.08815). FAIR-SHARE: no single project may exceed its bounded
 * share, so a greedy project cannot monopolize and others are not starved ("naive per-call caps still let one tenant
 * dominate by many concurrent calls" — systemshardening 2026). Over-budget-but-feasible requests are QUEUED (delayed, not
 * dropped — tinyagentos 2026); a request too large to EVER fit is DENIED. HONEST: admission-decision-only; reflects only
 * the real running-set + weights (never fabricates spare capacity); changes no unrelated gate. Deterministic. ZERO-DEP.
 */

export interface RunningEntry {
  readonly project: string;
  /** Resource weight (normalized concurrency/resource units). */
  readonly weight: number;
}

export interface AdmissionRequest {
  readonly project: string;
  readonly weight: number;
}

export interface ConcurrencyPolicy {
  /** Aggregate resource ceiling — the sum of admitted weights must NEVER exceed this (HARD). */
  readonly aggregateCeiling: number;
  /** Max fraction of the ceiling any single project may hold (0..1) — fair-share, prevents monopoly/starvation. */
  readonly perProjectShare: number;
}

export type AdmissionVerdict = "admitted" | "queued" | "denied";

export interface AdmissionDecision {
  readonly verdict: AdmissionVerdict;
  readonly reason: string;
  readonly aggregateUsed: number;
  readonly aggregateCeiling: number;
  readonly projectUsed: number;
  readonly projectCap: number;
  /** HONEST: an admission DECISION only — the OS-level resource enforcement is a named [ENV] seam. */
  readonly enforcement: "admission-decision-only";
  readonly changesGate: false;
}

/**
 * An input fuse: a resource weight / budget must be a finite, non-negative number. A `NaN` slips past every `x > ceiling`
 * comparison (`NaN > n` is always false — Stainless, arXiv 2601.14059: "a false comparison implies the input is valid…
 * a property that does not hold when the input is NaN"), so a bare `>` gate silently ADMITS a NaN weight past the ceiling.
 * Validating finiteness up front is what makes the hard-ceiling invariant hold under adversarial input. Reused across the
 * numeric gates. ZERO-DEP.
 */
export function finiteNonNegative(x: number): boolean {
  return Number.isFinite(x) && x >= 0;
}

export function concurrencyGovernor(running: readonly RunningEntry[], req: AdmissionRequest, policy: ConcurrencyPolicy): AdmissionDecision {
  const aggregateUsed = running.reduce((s, e) => s + e.weight, 0);
  const projectUsed = running.filter((e) => e.project === req.project).reduce((s, e) => s + e.weight, 0);
  const policyValid = finiteNonNegative(policy.aggregateCeiling) && Number.isFinite(policy.perProjectShare) && policy.perProjectShare >= 0 && policy.perProjectShare <= 1;
  const projectCap = policyValid ? policy.aggregateCeiling * policy.perProjectShare : NaN;
  const base = { aggregateUsed, aggregateCeiling: policy.aggregateCeiling, projectUsed, projectCap, enforcement: "admission-decision-only" as const, changesGate: false as const };

  // INPUT FUSES (fail-closed) — a malformed number must NEVER be admitted via a false `>` comparison. Checked BEFORE any
  // ceiling arithmetic, because `NaN`/`±Infinity`/negative weights either slip past `>` (fail-open) or poison the aggregate.
  if (!policyValid) {
    return { ...base, verdict: "denied", reason: `malformed policy (ceiling=${policy.aggregateCeiling}, share=${policy.perProjectShare}) — fail-closed, denied` };
  }
  if (!finiteNonNegative(req.weight)) {
    return { ...base, verdict: "denied", reason: `malformed request weight ${req.weight} (must be finite and >= 0) — fail-closed, denied` };
  }
  if (!running.every((e) => finiteNonNegative(e.weight))) {
    return { ...base, verdict: "denied", reason: `running-set carries a malformed weight — the aggregate is untrustworthy; fail-closed, denied` };
  }

  // DENIED: structurally infeasible — the request ALONE exceeds a hard bound; it can never be admitted.
  if (req.weight > policy.aggregateCeiling) {
    return { ...base, verdict: "denied", reason: `request weight ${req.weight} exceeds the entire aggregate ceiling ${policy.aggregateCeiling} — infeasible, denied` };
  }
  if (req.weight > projectCap) {
    return { ...base, verdict: "denied", reason: `request weight ${req.weight} exceeds project '${req.project}' fair-share cap ${projectCap} — infeasible, denied` };
  }
  // QUEUED: feasible but does not fit right now — delayed, not dropped.
  if (projectUsed + req.weight > projectCap) {
    return { ...base, verdict: "queued", reason: `project '${req.project}' at fair-share cap (${projectUsed}+${req.weight} > ${projectCap}) — queued so it cannot monopolize/starve others` };
  }
  if (aggregateUsed + req.weight > policy.aggregateCeiling) {
    return { ...base, verdict: "queued", reason: `aggregate ceiling reached (${aggregateUsed}+${req.weight} > ${policy.aggregateCeiling}) — queued, never over-admitted` };
  }
  // ADMITTED: within both the aggregate ceiling and the project's fair share.
  return { ...base, verdict: "admitted", reason: `admitted: ${aggregateUsed}+${req.weight} within ceiling ${policy.aggregateCeiling}; project within fair share ${projectCap}` };
}
