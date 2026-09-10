/**
 * Autonomy-loop composition — assembles the long-horizon project FSM into the app.
 *
 * The ProjectLoop runs a goal through understand → research → rag → plan → vet_plan → ticket → implement →
 * vet_artifact → learn → done as a durable, resumable state machine. The real-work stages (implement / vet_artifact /
 * learn) are backed by the app's SOLVE seam; the rest no-op-advance until their executors are wired. This factory is
 * what makes the subsystem reachable from composeKeep — and it threads the composed NonPersistableRegistry through, so
 * the checkpoint-isolation guard (no durable checkpoint mid-side-effect) is live end-to-end, not just correct-by-construction.
 *
 * The implement stage delegates to the app's SolveFn (issue → PR), reusing the one composed solve machine rather than
 * rebuilding it; the loop adds the resumable project envelope + sessions on top.
 */

import { ProjectLoop, ProjectFinalizationError, type AuthorityPosture, type ProjectState, type ProjectLoopConfig, type LoopRunResult, type ResumeProjectInput, type StageExecutors, type ProjectPermissionPolicy } from "./project_loop.js";
import type { DomainWorkflowKind, GoalLifecycleArtifactV1, GoalLifecycleRequestV1, ProjectStrategy } from "./project_state.js";
import { InMemoryProjectCheckpointStore, type ProjectCheckpointStore } from "./project_checkpoint_store.js";
import { ProgressNarrator } from "./progress_narrator.js";
import { runWithinTrace } from "../observability/trace_context.js";
import { checkFeasibility, type FeasibilityClassifier } from "./feasibility_check.js";
import { makeSolveStageExecutors } from "../solve/project_loop_wiring.js";
import type { ProjectJobActivityTracker } from "../session/project_job_journal.js";
import { TaskMemoryUnavailableError, type TaskMemoryContext } from "../memory/task_context.js";
import { ProjectSessionManager } from "../session/project_session_manager.js";
import type { ProjectId } from "../session/project_id.js";
import { ProjectRegistry } from "../session/project_registry.js";
import { CryptoShredKeyStore } from "../keystore/keystore.js";
import type { NonPersistableRegistry } from "../scheduler/saga_sequencer.js";
import type { TraceRecorder } from "../observability/tracing.js";
import type { Spine } from "../spine/spine.js";
import type { Issue } from "../solve/issue_model.js";
import type { SolveToPrResult } from "../pipeline/keep_pipeline.js";
import type { SolveFn } from "../loop/review_intake.js";
import type { RepoFile } from "../solve/localize.js";
import { computeMicrovmProjectSourceManifestSha256 } from "../infra/microvm_boundary.js";
import { authorizeAutonomousAction, type SpendCap } from "../scheduler/action_authorizer.js";
import type { VetoQueue } from "../scheduler/veto_queue.js";
import { estimateConsequence } from "../anticipate/consequence_estimator.js";
import { createHash, randomUUID } from "node:crypto";
import { TriResearchRuntime, supportsBoundedReversibleWork, type TriResearchRuntimeConfig } from "../research/tri_research_runtime.js";
import { buildUnderstandStageExecutor, type ProjectIntentRouter } from "./understand_stage.js";
import { decideProjectResearch } from "./research_decision_stage.js";
import { buildRetrievalStageExecutor, type ProjectRetriever } from "./retrieval_stage.js";
import { localizeProjectRepository } from "./project_localization.js";
import type { Workspace } from "../solve/workspace.js";
import type { Localizer } from "../solve/localize.js";
import { buildPlanStageExecutor, type ProjectPlanner } from "./plan_stage.js";
import { buildPlanGateStageExecutor } from "./plan_gate_stage.js";
import { buildDecompositionStageExecutor } from "./decomposition_stage.js";
import type { ProjectEditPlanner } from "./project_edit_stage.js";
import { createDomainWorkflow, domainWorkflowFeasibility, type DomainWorkflowConfig } from "./domain_workflows.js";
import type { ProjectSession } from "../session/project_session.js";
import { SecretSafeIntake } from "../frontdoor/secret_intake.js";
import { admitGoal, type AuthorityContextV1, type GoalScopeAuthorityV1 } from "../goal/goal_authority.js";
import { admitGoalResearch, researchProtocolDigest, stableResearchJson, type CurrentResearchIdentities, type GoalResearchRecordV1, type ResearchProtocolV1 } from "../research/goal_research.js";
import { evaluateGoalTransition, type GoalTransitionProposalV1, type GoalTransitionStateV1 } from "../goal/goal_transition.js";
import { nextGoalAuthorityEventV1, reconstructGoalAuthorityEventsV1, type GoalAuthorityEventPortV1 } from "../spine/goal_authority_events_v1.js";
import { reconstructDecompositionAuthorityV1, type DecompositionAuthorityEventPortV1, type DecompositionAuthorityReplayBundleV1, type DecompositionEventAuthorityContextV1 } from "../decomposition/decomposition_review_events_v1.js";
import { publishEngineeringStatusProjectionV1, rebuildEngineeringStatusProjectionV1, type EngineeringLifecycleSourceV1, type EngineeringStatusProjectionAuthorityV1, type EngineeringStatusProjectionStoreV1, type EngineeringStatusProjectionV1 } from "../spine/engineering_status_projection_v1.js";

function durableProjectTokens(spine: Spine, runId: string, tracer?: Pick<TraceRecorder, "trace">): number {
  if (tracer !== undefined) {
    let tracedTotal = 0;
    for (const span of tracer.trace(runId)) for (const value of [span.tokens?.input, span.tokens?.output]) {
      if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) tracedTotal = Math.min(Number.MAX_SAFE_INTEGER, tracedTotal + value);
    }
    return tracedTotal;
  }
  let total = 0;
  for (const event of spine.currentEvents()) {
    const payload = event.payload;
    if (event.actor !== "trace" || payload["event"] !== "span" || payload["traceId"] !== runId) continue;
    // keep.trace-span/v1 owns token usage as one nested pair. Reading the former
    // pre-schema flat names silently reset a reconstructed project's measured
    // budget watermark to zero after the durable trace representation landed.
    const tokens = payload["tokens"];
    if (tokens === null || typeof tokens !== "object" || Array.isArray(tokens)) continue;
    for (const field of ["input", "output"] as const) {
      const value = (tokens as Record<string, unknown>)[field];
      if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) total = Math.min(Number.MAX_SAFE_INTEGER, total + value);
    }
  }
  return total;
}

function reconcileProjectBudget(session: ProjectSession, spine: Spine, runId: string, tracer?: Pick<TraceRecorder, "trace">): void {
  session.reconcileMeteredTokens(durableProjectTokens(spine, runId, tracer));
}

export interface AutonomyLoopConfig {
  readonly spine: Spine;
  /** The app's solve seam (the full governed SolveFn — carries the merge-authority verdict the loop now honours;
   *  previously typed as just `{ solveResult }`, which hid the verdict and is why it was silently discarded). */
  readonly solve: SolveFn;
  /** Guards durable checkpoints against half-applied side effects (pass the composed registry to make it live). */
  readonly nonPersistable?: NonPersistableRegistry;
  /** Optional span recorder — instruments each project stage for failure localization + cost attribution. */
  readonly tracer?: TraceRecorder;
  /** Optional: return the lesson/skill ids Keep judges relevant to a goal. Their retrieval-relevance tags the run's
   *  model-call spans, so per-lesson cost attribution reflects "the work a lesson was deemed relevant to". */
  readonly lessonsForGoal?: (goal: string) => readonly string[];
  /** Optional LLM feasibility classifier (deterministic floor always runs; this only tightens honesty). */
  readonly feasibilityClassifier?: FeasibilityClassifier;
  /** Map a run's goal → the issue (+ optional files) to solve. Default: the goal becomes the issue text. */
  readonly resolve?: (state: ProjectState) => { issue: Issue; files: readonly RepoFile[] };
  /** The repo the default resolver targets. */
  readonly repoRef?: string;
  /** Shared crypto-shred keystore for per-project session keys. Default: fresh. */
  readonly keys?: CryptoShredKeyStore;
  /** Optional pre-composed lifecycle authority. Installed composition supplies the one durable manager. */
  readonly manager?: ProjectSessionManager;
  readonly loopConfig?: Partial<ProjectLoopConfig>;
  /** Autonomous-spend cap (backed by BudgetLedger at deploy). Default: permissive. n=1 personal / org policy cap. */
  readonly spendCap?: SpendCap;
  /** Optional projected USD cost of acting on the goal, for the spend cap. Default: 0 (no spend estimate). */
  readonly estimatedActionCostUsd?: number;
  /** Optional async veto queue — a vetoed external/irreversible goal is PARKED here for async veto/approve. */
  readonly vetoQueue?: VetoQueue;
  /** Durable full-state store. Installed composition binds a filesystem store; memory is explicit standalone behavior. */
  readonly checkpoints?: ProjectCheckpointStore;
  /** Default operator interaction posture. It never grants effect authority. */
  readonly posture?: AuthorityPosture;
  readonly research?: TriResearchRuntimeConfig;
  readonly permissionPolicy?: ProjectPermissionPolicy;
  /** Optional enterprise/personal intent classifier adapter; deterministic router remains the shared floor. */
  readonly intentRouter?: ProjectIntentRouter;
  /** Optional personal/enterprise corpus adapter; admitted tri-research sources provide the shared built-in floor. */
  readonly projectRetriever?: ProjectRetriever;
  readonly projectRetrievalLimit?: number;
  /** Optional canonical workspace enables durable read-only localization before planning. */
  readonly projectWorkspace?: Workspace;
  readonly projectLocalizer?: Localizer;
  readonly projectLocalizationTopK?: number;
  /** Optional bounded planner adapter. The deterministic grounded planner remains the zero-config floor. */
  readonly projectPlanner?: ProjectPlanner;
  /** Optional strict project edit planner; it proposes bytes but never owns write authority. */
  readonly projectEditor?: ProjectEditPlanner;
  /** Trusted host port for bounded native preparation; not a self-attested custom solve flag. */
  readonly softwarePreparation?: {
    readonly binding: string;
    readonly workspace: Workspace;
    readonly editor: ProjectEditPlanner;
    readonly solve: SolveFn;
  };
  /** Host-bound native repository operation, never a model's effect classification.
   * Admission does not authorize payment, deployment, or completion by assertion. */
  readonly softwareOperation?: {
    readonly binding: string;
    readonly authorize: (runId: string, projectId: ProjectId | undefined, goal: string) => boolean;
  };
  /** Optional independent isolated post-implementation verifier. */
  readonly projectTester?: import("./project_test_stage.js").ProjectTester;
  /** Full non-.git execution-input identity for custom/disk workspace verifier compositions. */
  readonly snapshotExecutionManifest?: (repoRef: string) => Promise<string>;
  readonly solveConsumesAdmittedEdit?: true;
  /** Optional typed production strategy; it enriches canonical prerequisites and never creates another loop. */
  readonly domainWorkflow?: DomainWorkflowConfig;
  /** Per-run production strategies. One installed loop can concurrently execute software and every domain kind. */
  readonly domainWorkflows?: Omit<DomainWorkflowConfig, "kind">;
  /** Whether the canonical software implement path has a real solver (never inferred from a throwing placeholder). */
  readonly softwareStrategyAvailable?: boolean;
  /** Composition-owned async context for project-scoped cross-stage consumers such as adaptation. */
  readonly runInProjectContext?: <T>(projectId: ProjectId, subjectId: string, run: () => Promise<T>) => Promise<T>;
  /** Earliest untrusted-text boundary. Raw credentials never enter checkpoints, traces, the spine, or a model prompt. */
  readonly secretIntake?: SecretSafeIntake;
  /** T010 witnessed goal-event authority. Required only for the structured goal lifecycle. */
  readonly goalAuthorityEvents?: GoalAuthorityEventPortV1;
  /** T011 event authority; T015/T016 install both fields into their track compositions. */
  readonly decompositionAuthorityEvents?: DecompositionAuthorityEventPortV1;
  readonly decompositionAuthorityContext?: (state: ProjectState) => DecompositionEventAuthorityContextV1;
  /** W10-W13 lifecycle cache. Its absence affects speed only, never lifecycle authority. */
  readonly engineeringStatusProjections?: EngineeringStatusProjectionStoreV1;
}

export interface AutonomyLoop {
  /** Session manager (switch/background/foreground of concurrent project sessions). */
  readonly manager: ProjectSessionManager;
  /** Run a project goal through the durable FSM to completion (or a checkpointed pause). */
  runProject(goal: string, opts?: { runId?: string; stepBudget?: number; posture?: AuthorityPosture; domainWorkflowKind?: DomainWorkflowKind; goalLifecycle?: GoalLifecycleRequestV1; goalContext?: string; signal?: AbortSignal; trackActivity?: ProjectJobActivityTracker; memoryContext?: TaskMemoryContext }): Promise<LoopRunResult>;
  /** Run through a named durable project session and bind its canonical checkpoint for restart/switch. */
  runManagedProject(projectId: ProjectId, goal: string, opts?: { runId?: string; stepBudget?: number; posture?: AuthorityPosture; domainWorkflowKind?: DomainWorkflowKind; goalLifecycle?: GoalLifecycleRequestV1; goalContext?: string; signal?: AbortSignal; trackActivity?: ProjectJobActivityTracker; memoryContext?: TaskMemoryContext }): Promise<LoopRunResult>;
  resumeProject(runId: string, input?: ResumeProjectInput, control?: ProjectResumeControl): Promise<LoopRunResult>;
  /** Resume a run only through the durable project session that owns its checkpoint reference. */
  resumeManagedProject(projectId: ProjectId, runId: string, input?: ResumeProjectInput, control?: ProjectResumeControl): Promise<LoopRunResult>;
  resumePermission(runId: string, input?: ResumeProjectInput): "change.solve" | "review.approve";
  supportsStrategy(domainWorkflowKind?: DomainWorkflowKind): boolean;
}

/** Ephemeral host authority, deliberately separate from caller-supplied resume signals. */
export interface ProjectResumeControl {
  readonly memoryContext?: TaskMemoryContext;
  readonly signal?: AbortSignal;
  readonly trackActivity?: ProjectJobActivityTracker;
}

interface GoalLifecycleDenialResult extends LoopRunResult {
  readonly goalLifecycle: { readonly code: string; readonly artifact: GoalLifecycleArtifactV1 };
}

export function buildAutonomyLoop(cfg: AutonomyLoopConfig): AutonomyLoop {
  if (cfg.domainWorkflow !== undefined && cfg.domainWorkflows !== undefined) {
    throw new Error("domainWorkflow and domainWorkflows are mutually exclusive");
  }
  const projectionAuthority=(source:EngineeringLifecycleSourceV1):EngineeringStatusProjectionAuthorityV1=>{const a=source.receipt.authority;return a.kind==="n1"?{kind:"n1",principal_id:a.actor_id,custody_id:a.custody_id,organization_services:"ABSENT"}:{kind:"enterprise",organization_id:a.organization_id,tenant_id:a.tenant_id,actor_id:a.actor_id,role_id:a.actor_role_id,custody_id:a.custody_id,isolation_id:a.isolation_id,local_owner_substitution:false};};
  async function refreshEngineeringProjection(state:ProjectState,decompositionBundle?:DecompositionAuthorityReplayBundleV1):Promise<EngineeringStatusProjectionV1|undefined>{
    const store=cfg.engineeringStatusProjections;if(store===undefined)return undefined;const sources:EngineeringLifecycleSourceV1[]=[];
    const raw=state.artifacts["goal_lifecycle"],request=plainObject(raw)?raw["request"]:undefined;
    if(cfg.goalAuthorityEvents!==undefined&&validLifecycleRequest(request)){const bundle=await cfg.goalAuthorityEvents.load(state.runId),reconstructed=reconstructGoalAuthorityEventsV1(state.runId,request,bundle);if(!reconstructed.ok)throw new Error(`goal lifecycle projection refused: ${reconstructed.code}`);if(bundle!==null&&bundle.replay.ok&&reconstructed.artifact!==null){const ts=reconstructed.artifact.transition_state as {phase?:unknown};sources.push({kind:"goal",receipt:bundle.replay.receipt,status:{code:reconstructed.artifact.code,phase:typeof ts.phase==="string"?ts.phase:null,next_transition_index:reconstructed.artifact.next_transition_index}});}}
    const db=decompositionBundle??(cfg.decompositionAuthorityEvents===undefined?null:await cfg.decompositionAuthorityEvents.load(state.runId));if(db!==null){const reconstructed=reconstructDecompositionAuthorityV1(state.runId,db);if(!reconstructed.ok)throw new Error(`decomposition lifecycle projection refused: ${reconstructed.code}`);if(db.replay.ok)sources.push({kind:"decomposition",receipt:db.replay.receipt,status:{transition_phase:reconstructed.projection.transition?.phase??null,review_phase:reconstructed.projection.review?.phase??null,review_disposition_digest:reconstructed.projection.review?.disposition?.disposition_digest??null,event_count:reconstructed.projection.event_count}});}
    if(sources.length===0)return undefined;const authority=projectionAuthority(sources[0]!),projectId=state.projectId??state.runId,input={schema_version:1 as const,project_id:projectId,run_id:state.runId,authority,sources},verified=rebuildEngineeringStatusProjectionV1(input);if(!verified.ok)throw new Error(`engineering status projection refused: ${verified.code}`);
    // Cache I/O is deliberately outside lifecycle authority. Corruption, deletion, or
    // unavailability costs acceleration only; the independently verified histories above stand.
    try{const current=store.load(projectId),published=publishEngineeringStatusProjectionV1(input,store,current?.projection_digest??null);if(published.ok)return published.projection;if(published.code==="STALE_PROJECTION")return store.load(projectId);return undefined;}catch{return undefined;}
  }
  async function refreshDecompositionProjection(state:ProjectState,bundle:DecompositionAuthorityReplayBundleV1):Promise<void>{await refreshEngineeringProjection(state,bundle);}
  async function finalizeManagedResult(projectId: ProjectId, result: LoopRunResult): Promise<LoopRunResult> {
    let phase: ProjectFinalizationError["phase"] = "projection";
    try {
      const projection = await refreshEngineeringProjection(result.state);
      // The task/projection may have awaited a sibling writer. Obtain a current
      // session, not a rebased stale object, and retain all normal write guards.
      phase = "session";
      const current = manager.runnableSession(projectId);
      if (current.boundRunId() !== result.state.runId) throw new Error("finalization run binding changed");
      phase = "budget"; reconcileProjectBudget(current, cfg.spine, result.state.runId, cfg.tracer);
      phase = "checkpoint"; current.checkpoint(result.state, projection);
      phase = "history";
      if (result.visited.length > 0) {
        // checkpoint() can accept a verified sibling winner while fencing current.
        // Append to a fresh guarded object, preserving the winner's other state.
        // This reports the returned result's revision, not necessarily today's latest.
        const history = manager.runnableSession(projectId);
        if (history.boundRunId() !== result.state.runId) throw new Error("finalization history run binding changed");
        history.append("event", `Project status: ${result.state.status}${result.state.note ? ` — ${result.state.note}` : ""} (run ${result.state.runId}, revision ${result.state.revision})`);
      }
      return result;
    } catch (cause) {
      // Never re-execute the task to repair a projection, accounting or write error.
      throw new ProjectFinalizationError(result, phase, { cause });
    }
  }
  const resolve =
    cfg.resolve ??
    ((state: ProjectState): { issue: Issue; files: readonly RepoFile[] } => ({
      issue: { id: state.runId, text: state.goal, repoRef: cfg.repoRef ?? ".", ...(state.projectId === undefined ? {} : { hints: { projectId: state.projectId } }) },
      files: [],
    }));

  // Adapt the app's SolveFn into the wiring's pipeline.run — passing the FULL governed result through (not just
  // .solveResult) so the implement stage can HONOUR the merge-authority verdict instead of discarding it.
  const solveExecutors = makeSolveStageExecutors({
    pipeline: { ...(cfg.solveConsumesAdmittedEdit ? { consumesAdmittedEdit: true as const } : {}), run: async (issue: Issue, _files, context): Promise<SolveToPrResult> => cfg.solve(issue, context) },
    spine: cfg.spine,
    resolve,
    ...(cfg.softwareOperation === undefined ? {} : { assertAuthority: (state: ProjectState) => {
      if (Object.hasOwn(state.artifacts, "software_operation")
        && cfg.softwareOperation!.authorize(state.runId, state.projectId, state.goal) !== true) {
        throw new Error("native project command authority unavailable");
      }
    } }),
    ...(cfg.softwareOperation === undefined ? {} : { canFinishTestedProposal: (state: ProjectState) => {
      const marker = state.artifacts["software_operation"] as { schemaVersion?: unknown; binding?: unknown } | undefined;
      return state.posture === "autonomous" && marker?.schemaVersion === 1 && marker.binding === cfg.softwareOperation!.binding
        && cfg.softwareOperation!.authorize(state.runId, state.projectId, state.goal);
    } }),
    ...(cfg.projectEditor ? { projectEditor: cfg.projectEditor } : {}),
    ...(cfg.projectTester ? { projectTester: cfg.projectTester } : {}),
    ...(cfg.projectWorkspace ? { snapshotFiles: (repoRef: string) => cfg.projectWorkspace!.files(repoRef) } : {}),
    ...(cfg.snapshotExecutionManifest ? { snapshotExecutionManifest: cfg.snapshotExecutionManifest }
      : cfg.projectWorkspace?.dir ? { snapshotExecutionManifest: (repoRef: string) => computeMicrovmProjectSourceManifestSha256(cfg.projectWorkspace!.dir!(repoRef)) } : {}),
  });
  const preparationExecutors = cfg.softwarePreparation === undefined ? undefined : makeSolveStageExecutors({
    spine: cfg.spine, resolve, executionCeiling: "prepare", projectEditor: cfg.softwarePreparation.editor,
    pipeline: { consumesAdmittedEdit: true, run: (issue, _files, context) => cfg.softwarePreparation!.solve(issue, { ...context, executionCeiling: "prepare" }) },
  });
  const triResearch = new TriResearchRuntime(cfg.research ?? {});
  const researchRetrievalAvailable = (cfg.research?.transports?.length ?? 0) > 0;
  const planStage = buildPlanStageExecutor(cfg.projectPlanner);
  const canonicalExecutors: StageExecutors = {
    understand: buildUnderstandStageExecutor(cfg.intentRouter),
    research: async (state) => {
      const decision = decideProjectResearch(state, researchRetrievalAvailable);
      if (!decision.required) return { output: { decision, disposition: "not-required" }, control: "advance", headline: decision.reason };
      const report = await triResearch.run(state.goal);
      const consequence = estimateConsequence({ message: state.goal }).consequence;
      const bounded = consequence === "reversible" && supportsBoundedReversibleWork(report);
      return report.complete || bounded
        ? { output: { decision, report, admission: report.complete ? "complete" : "bounded-reversible" }, control: "need-rag", headline: report.complete ? "Tri-research completed; preparing its admitted evidence for grounded use" : "Bounded reversible work admitted; preparing fresh current and labelled LKG evidence for grounded use" }
        : { output: { decision, report }, control: "capability-unavailable", capability: "tri-research-retrieval", headline: "Tri-research debt is recorded; dependent work is preserved until retrieval succeeds" };
    },
    rag: buildRetrievalStageExecutor(cfg.projectRetriever, cfg.projectRetrievalLimit),
    plan: async (state) => {
      let localization;
      const workspace = Object.hasOwn(state.artifacts, "software_preparation") && !Object.hasOwn(state.artifacts, "software_operation") ? cfg.softwarePreparation?.workspace : cfg.projectWorkspace;
      let localizationFallback: { readonly mechanism: "deterministic-without-localization"; readonly reason: string } | undefined;
      if (workspace !== undefined) {
        try {
          localization = await localizeProjectRepository(state, workspace, cfg.repoRef ?? ".", cfg.projectLocalizer, cfg.projectLocalizationTopK);
        } catch (error) {
          if (cfg.projectEditor !== undefined) throw error;
          localizationFallback = { mechanism: "deterministic-without-localization", reason: `optional localization failed with ${error instanceof Error ? error.name : "a non-Error exception"}` };
        }
      }
      const planningState = localization === undefined ? state : {
        ...state,
        artifacts: { ...state.artifacts, project_localization: localization },
      };
      const priorGate = state.artifacts["vet_plan"] as { proceed?: unknown } | undefined;
      const executor = state.reworkCount > 0 && priorGate?.proceed === false ? buildPlanStageExecutor() : planStage;
      const result = await executor(planningState);
      if (localizationFallback === undefined || result.output === null || typeof result.output !== "object" || Array.isArray(result.output)) return result;
      return { ...result, output: { ...(result.output as Record<string, unknown>), localizationFallback } };
    },
    vet_plan: buildPlanGateStageExecutor(),
    ticket: buildDecompositionStageExecutor(cfg.decompositionAuthorityEvents, cfg.decompositionAuthorityContext, refreshDecompositionProjection),
    ...solveExecutors,
  };
  const fixedDomainKind = cfg.domainWorkflow?.kind;

  const guardedSoftwareExecutors: StageExecutors = Object.fromEntries(Object.entries(canonicalExecutors).map(([stage, execute]) => [stage, async (state: ProjectState, control = {}) => {
    const marker = state.artifacts["software_preparation"];
    const previous = state.artifacts["implement"] as { solve?: SolveToPrResult["solveResult"] } | undefined;
    // A pre-dispatch refusal is not a replacement execution result. Keep the prior
    // attempt/receipt visible; the wait and headline already carry the new reason.
    const hold = (reason: string) => ({ output: Object.hasOwn(state.artifacts, stage) ? state.artifacts[stage] : { reason }, control: "capability-unavailable" as const,
      capability: "native-preparation-binding", resumeAuthority: "approval" as const, headline: reason });
    if (Object.hasOwn(state.artifacts, "software_preparation")) {
      if (!marker || typeof marker !== "object" || Array.isArray(marker)
        || Object.keys(marker).length !== 2 || (marker as { schemaVersion?: unknown }).schemaVersion !== 1
        || typeof (marker as { binding?: unknown }).binding !== "string"
        || (marker as { binding?: unknown }).binding !== cfg.softwarePreparation?.binding || preparationExecutors === undefined) {
        return hold("The native preparation binding is missing, malformed or changed; no phase was dispatched.");
      }
      if (!Object.hasOwn(state.artifacts, "software_operation") && !["understand", "research", "rag", "plan", "vet_plan", "ticket", "implement"].includes(stage)) {
        return hold("An unexecuted preparation cannot advance into verification, tests, learning or completion.");
      }
      if (stage === "implement" && !Object.hasOwn(state.artifacts, "software_operation")) {
        if (previous?.solve?.preparedProposal !== undefined) return { output: previous, control: "capability-unavailable" as const,
          capability: "project-execution-admission", resumeAuthority: "approval" as const,
          headline: "The earlier proposal remains unexecuted. Resume cannot grant execution authority or queue external effects." };
        return preparationExecutors.implement!(state, control);
      }
    }
    if (Object.hasOwn(state.artifacts, "software_operation")) {
      const operation = state.artifacts["software_operation"];
      const prepared = state.artifacts["software_prepared_implementation"] as { solve?: SolveToPrResult["solveResult"] } | undefined;
      if (!operation || typeof operation !== "object" || Array.isArray(operation)
        || Object.keys(operation).length !== 2 || (operation as { schemaVersion?: unknown }).schemaVersion !== 1
        || (operation as { binding?: unknown }).binding !== cfg.softwareOperation?.binding
        || cfg.softwareOperation?.authorize(state.runId, state.projectId, state.goal) !== true
        || (Object.hasOwn(state.artifacts, "software_preparation") && (prepared?.solve?.preparedProposal?.disposition !== "unexecuted" || prepared.solve.solved !== false))
        || (previous?.solve?.preparedProposal !== undefined && prepared === undefined)) {
        return hold("The native repository operation lost its original command or current authority; no phase was dispatched.");
      }
    } else if (!Object.hasOwn(state.artifacts, "software_preparation") && (previous?.solve?.preparedProposal !== undefined || (state.posture === "autonomous"
      && authorizeAutonomousAction({ description: state.goal, consequence: estimateConsequence({ message: state.goal }).consequence }, { canAfford: () => true }).verdict === "veto"))) {
      return hold("This held goal lacks its native preparation disposition; resume cannot grant execution authority.");
    }
    return execute(state, control);
  }]));

  function strategyFor(requested?: DomainWorkflowKind): ProjectStrategy {
    if (requested !== undefined) {
      if (cfg.domainWorkflows === undefined && fixedDomainKind !== requested) {
        throw new Error(`domain workflow ${requested} is not configured`);
      }
      return { kind: "domain", domainKind: requested };
    }
    return fixedDomainKind === undefined ? { kind: "software" } : { kind: "domain", domainKind: fixedDomainKind };
  }

  function restoredStrategy(state: ProjectState | undefined): ProjectStrategy {
    if (state?.strategy !== undefined) return state.strategy;
    // Checkpoints created by the former fixed-domain composition predate durable strategy identity.
    return fixedDomainKind === undefined ? { kind: "software" } : { kind: "domain", domainKind: fixedDomainKind };
  }

  function executorsFor(strategy: ProjectStrategy | undefined): StageExecutors {
    const resolved = strategy ?? { kind: "software" };
    if (resolved.kind === "software") return guardedSoftwareExecutors;
    const base = cfg.domainWorkflows ?? (cfg.domainWorkflow?.kind === resolved.domainKind ? cfg.domainWorkflow : undefined);
    if (base === undefined) throw new Error(`checkpoint requires unconfigured domain workflow ${resolved.domainKind}`);
    return createDomainWorkflow({ ...base, kind: resolved.domainKind }, canonicalExecutors);
  }

  const checkpoints = cfg.checkpoints ?? new InMemoryProjectCheckpointStore();
  const secretIntake = cfg.secretIntake ?? new SecretSafeIntake(cfg.keys ?? new CryptoShredKeyStore());
  const manager = cfg.manager ?? new ProjectSessionManager(
    new ProjectRegistry(cfg.keys ?? new CryptoShredKeyStore()),
    undefined,
    undefined,
    checkpoints,
  );
  const managedOwners = new Map<string, ProjectId>();

  function loopFor(strategy: ProjectStrategy | undefined, stepBudget?: number, control?: ProjectResumeControl): ProjectLoop {
    const loopConfig: Partial<ProjectLoopConfig> = {
      ...(cfg.loopConfig ?? {}),
      ...(stepBudget !== undefined ? { stepBudget } : {}),
    };
    return new ProjectLoop(cfg.spine, new ProgressNarrator("project", cfg.spine), executorsFor(strategy), loopConfig, cfg.nonPersistable, cfg.tracer, checkpoints, Date.now, cfg.permissionPolicy, control?.signal, control?.trackActivity, control?.memoryContext);
  }

  const lifecycleRequestKeys = [
    "schema_version", "goal_candidate", "authority_context", "scope_authority", "research_protocol",
    "research_record", "observed_at", "current_source_identities", "transition_state", "transitions", "executable",
  ].sort();
  const plainObject = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
  const exactObjectKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean =>
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
  const stableJson = (value: unknown): string => JSON.stringify(stableValue(value));
  function stableValue(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(stableValue);
    if (plainObject(value)) return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
    return value;
  }
  function validLifecycleRequest(value: unknown): value is GoalLifecycleRequestV1 {
    const scope = plainObject(value) ? value["scope_authority"] : undefined;
    const tracks = plainObject(scope) ? scope["required_track_obligations"] : undefined;
    return plainObject(value) && exactObjectKeys(value, lifecycleRequestKeys) && value["schema_version"] === 1
      && value["executable"] === false && typeof value["observed_at"] === "string"
      && plainObject(value["goal_candidate"]) && plainObject(scope)
      && ["known_scope_ids","required_scope_ids","required_track_obligations","dependency_closures","owner_reduction_decision"].every((key) => !Object.hasOwn(scope, key) || key === "owner_reduction_decision" || scope[key] !== undefined)
      && Object.keys(scope).every((key) => ["known_scope_ids","required_scope_ids","required_track_obligations","dependency_closures","owner_reduction_decision"].includes(key))
      && Array.isArray(scope["known_scope_ids"]) && Array.isArray(scope["required_scope_ids"]) && plainObject(tracks)
      && ["n1","enterprise","parity"].every((key) => Array.isArray(tracks[key]))
      && plainObject(scope["dependency_closures"]) && Object.values(scope["dependency_closures"]).every((digest) => typeof digest === "string")
      && plainObject(value["current_source_identities"]) && Object.values(value["current_source_identities"]).every((identity) => typeof identity === "string")
      && Array.isArray(value["transitions"]) && value["transitions"].length === 6
      && value["transitions"].every((proposal) => plainObject(proposal) && plainObject(proposal["authority_context"]));
  }
  function lifecycleArtifact(state: ProjectState): GoalLifecycleArtifactV1 | undefined {
    const value = state.artifacts["goal_lifecycle"];
    if (!plainObject(value) || !exactObjectKeys(value, ["schema_version","mode","request","code","admitted_goal","admitted_research","transition_state","next_transition_index","executable"])
      || value["schema_version"] !== 1 || value["mode"] !== "goal-to-architecture" || value["executable"] !== false
      || !validLifecycleRequest(value["request"]) || typeof value["code"] !== "string"
      || !Number.isSafeInteger(value["next_transition_index"]) || (value["next_transition_index"] as number) < 0) return undefined;
    return value as unknown as GoalLifecycleArtifactV1;
  }
  const hasLifecycleArtifact = (state: ProjectState): boolean => Object.hasOwn(state.artifacts, "goal_lifecycle");
  function saveLifecycle(state: ProjectState, artifact: GoalLifecycleArtifactV1, status: ProjectState["status"] = "running"): ProjectState {
    const candidate: ProjectState = {
      ...state,
      revision: state.revision + 1,
      stage: "understand",
      status,
      artifacts: { goal_lifecycle: artifact },
      note: artifact.code,
    };
    const saved = checkpoints.save(candidate, state.revision);
    cfg.spine.stage({
      type: "checkpoint", actor: "goal_lifecycle",
      payload: { event: "project.checkpoint", runId: saved.state.runId, stage: saved.state.stage, revision: saved.state.revision, sha256: saved.sha256, reason: artifact.code },
    });
    return saved.state;
  }
  function deniedLifecycle(state: ProjectState, request: GoalLifecycleRequestV1, code: string, artifact?: GoalLifecycleArtifactV1): GoalLifecycleDenialResult {
    const denied: GoalLifecycleArtifactV1 = artifact === undefined ? {
      schema_version: 1, mode: "goal-to-architecture", request, code,
      admitted_goal: null, admitted_research: null, transition_state: request.transition_state,
      next_transition_index: 0, executable: false,
    } : { ...artifact, code };
    // Rejection is observational output, not a transition: the durable checkpoint remains
    // byte-for-byte unchanged and a retry cannot consume authority or a revision.
    return { state, visited: [], goalLifecycle: { code, artifact: denied } };
  }
  async function runGoalLifecycle(initial: ProjectState, requestInput: unknown, boundaryBudget?: number): Promise<LoopRunResult> {
    if (!validLifecycleRequest(requestInput)) {
      const placeholder = {
        schema_version: 1, goal_candidate: null, authority_context: null, scope_authority: null,
        research_protocol: null, research_record: null, observed_at: "", current_source_identities: {},
        transition_state: null, transitions: [null], executable: false,
      } satisfies GoalLifecycleRequestV1;
      return deniedLifecycle(initial, placeholder, "MALFORMED_OR_UNKNOWN_FIELD");
    }
    const request = requestInput;
    if (cfg.goalAuthorityEvents === undefined) return deniedLifecycle(initial, request, "GOAL_EVENT_AUTHORITY_REQUIRED");
    const bundle = await cfg.goalAuthorityEvents.load(initial.runId);
    const reconstructed = reconstructGoalAuthorityEventsV1(initial.runId, request, bundle);
    if (!reconstructed.ok) return deniedLifecycle(initial, request, reconstructed.code);
    const persisted = reconstructed.artifact ?? undefined;
    const projected = lifecycleArtifact(initial);
    if (bundle === null && projected !== undefined) return deniedLifecycle(initial, request, "LEGACY_GOAL_MUTATION_REJECTED", projected);
    if (bundle === null && initial.revision > 0 && projected === undefined) return deniedLifecycle(initial, request, "LEGACY_GOAL_MUTATION_REJECTED");
    if (persisted !== undefined && projected !== undefined && stableJson(projected) !== stableJson(persisted)) {
      return deniedLifecycle(initial, request, "LEGACY_GOAL_MUTATION_REJECTED", persisted);
    }

    // Edge precedence is owned by T003. This is deliberately a pure probe: only malformed
    // inputs and illegal edges terminate here; all other guards run after T001 and T002.
    const probe = evaluateGoalTransition(request.transition_state, request.transitions[0]);
    if (probe.code === "MALFORMED_OR_UNKNOWN_FIELD" || probe.code === "ILLEGAL_PHASE_EDGE") {
      return deniedLifecycle(initial, request, probe.code, persisted);
    }

    const goalResult = admitGoal(
      null,
      request.goal_candidate,
      request.authority_context as AuthorityContextV1 | null,
      request.scope_authority as GoalScopeAuthorityV1,
    );
    if (!goalResult.admitted) return deniedLifecycle(initial, request, goalResult.denial, persisted);
    const researchResult = admitGoalResearch(
      goalResult.authority,
      request.research_protocol as ResearchProtocolV1,
      request.research_record as GoalResearchRecordV1,
      request.observed_at,
      request.current_source_identities as CurrentResearchIdentities,
    );
    if (!researchResult.admitted) return deniedLifecycle(initial, request, researchResult.denial, persisted);

    const protocolDigest = researchProtocolDigest(request.research_protocol as ResearchProtocolV1);
    const researchDigest = createHash("sha256").update(stableResearchJson(request.research_record)).digest("hex");
    const admittedGoalDigest = goalResult.authority.goal_digest;
    const transitionState = request.transition_state as GoalTransitionStateV1;
    if (transitionState.phase !== "GOAL_PROPOSED" || transitionState.active_head_digest !== admittedGoalDigest
      || transitionState.ancestor_digests.goal !== admittedGoalDigest
      || transitionState.ancestor_digests.protocol !== protocolDigest
      || transitionState.ancestor_digests.research !== researchDigest) {
      return deniedLifecycle(initial, request, "STALE_DERIVATION", persisted);
    }
    const goalTrack = goalResult.authority.authority_context;
    for (const raw of request.transitions) {
      const proposal = raw as GoalTransitionProposalV1;
      if (goalTrack.kind === "n1") {
        if (proposal.authority_context.kind !== "n1") return deniedLifecycle(initial, request, "N1_ENTERPRISE_CEREMONY_FORBIDDEN", persisted);
        if (proposal.authority_context.principal_id !== goalTrack.principal_id || proposal.authority_context.custody_id !== goalTrack.custody_id || proposal.authority_context.organization_services !== "ABSENT") {
          return deniedLifecycle(initial, request, "TRACK_AUTHORITY_SUBSTITUTION", persisted);
        }
      } else {
        if (proposal.authority_context.kind !== "enterprise") return deniedLifecycle(initial, request, "ENTERPRISE_AUTHORITY_REQUIRED", persisted);
        if (proposal.authority_context.organization_id !== goalTrack.organization_id || proposal.authority_context.actor_id !== goalTrack.principal_id
          || proposal.authority_context.role_id !== goalTrack.role_id || proposal.authority_context.separation_policy_id !== goalTrack.separation_policy_id
          || proposal.authority_context.local_owner_substitution !== false) {
          return deniedLifecycle(initial, request, "TRACK_AUTHORITY_SUBSTITUTION", persisted);
        }
      }
    }
    const semanticProposal = request.transitions.find((raw) => (raw as GoalTransitionProposalV1).to_phase === "RESEARCH_SEMANTIC_PASS") as GoalTransitionProposalV1 | undefined;
    const semanticDigest = createHash("sha256").update(stableJson(semanticProposal?.semantic_admission ?? null)).digest("hex");
    const expectedHead = (proposal: GoalTransitionProposalV1): string => {
      if (proposal.to_phase === "GOAL_ADMITTED") return admittedGoalDigest;
      if (proposal.to_phase === "RESEARCH_PROTOCOL_FROZEN") return protocolDigest;
      if (proposal.to_phase === "RESEARCH_CANDIDATE" || proposal.to_phase === "RESEARCH_STRUCTURAL_PASS") return researchDigest;
      if (proposal.to_phase === "RESEARCH_SEMANTIC_PASS") return semanticDigest;
      return createHash("sha256").update(stableJson({ goal_digest: admittedGoalDigest, protocol_digest: protocolDigest, research_digest: researchDigest, semantic_digest: semanticDigest, consequence_graph: proposal.consequence_graph })).digest("hex");
    };

    if (persisted !== undefined && persisted.admitted_goal !== null && stableJson(persisted.admitted_goal) !== stableJson(goalResult.authority)) {
      return deniedLifecycle(initial, request, "STALE_DERIVATION", persisted);
    }
    if (persisted !== undefined && persisted.admitted_research !== null && stableJson(persisted.admitted_research) !== stableJson(researchResult.authority)) {
      return deniedLifecycle(initial, request, "STALE_DERIVATION", persisted);
    }
    if (persisted !== undefined && persisted.code === "ARCHITECTURE_AUTHORIZED") {
      const terminalProbe = evaluateGoalTransition(persisted.transition_state, request.transitions.at(-1));
      if((persisted.transition_state as GoalTransitionStateV1).phase === "ARCHITECTURE_AUTHORIZED"&&persisted.next_transition_index===request.transitions.length&&terminalProbe.code==="ILLEGAL_PHASE_EDGE"){
        const terminal=projected!==undefined&&stableJson(projected)===stableJson(persisted)&&initial.status==="completed"?initial:saveLifecycle(initial,persisted,"completed");await refreshEngineeringProjection(terminal);return {state:terminal,visited:[]};
      }
      return deniedLifecycle(initial, request, "STALE_DERIVATION", persisted);
    }

    let state = initial;
    let artifact: GoalLifecycleArtifactV1 = persisted ?? {
      schema_version: 1, mode: "goal-to-architecture", request, code: "IN_PROGRESS",
      admitted_goal: null, admitted_research: null, transition_state: request.transition_state,
      next_transition_index: 0, executable: false,
    };
    let remaining = boundaryBudget ?? Number.MAX_SAFE_INTEGER;
    if (!Number.isSafeInteger(remaining) || remaining <= 0) remaining = 1;
    let eventCount = reconstructed.event_count;
    const commitBoundary = async (next: GoalLifecycleArtifactV1, status: ProjectState["status"] = "running"): Promise<boolean> => {
      if (remaining <= 0) return false;
      const event = nextGoalAuthorityEventV1(initial.runId,request,eventCount);
      if (event === null || stableJson(event.artifact) !== stableJson(next)) throw new Error("goal event boundary disagrees with deterministic lifecycle");
      const committed = await cfg.goalAuthorityEvents!.appendAndReplay(initial.runId,event);
      const verified = reconstructGoalAuthorityEventsV1(initial.runId,request,committed);
      if (!verified.ok || verified.artifact === null || verified.event_count !== eventCount + 1 || stableJson(verified.artifact) !== stableJson(next)) {
        throw new Error(`goal event authority failed after append: ${verified.ok ? "STATE_MISMATCH" : verified.code}`);
      }
      eventCount = verified.event_count;
      artifact = verified.artifact;
      state = saveLifecycle(state, artifact, status);
      await refreshEngineeringProjection(state);
      remaining -= 1;
      return true;
    };
    if (artifact.admitted_goal === null) {
      if (!await commitBoundary({ ...artifact, admitted_goal: goalResult.authority })) return { state, visited: [] };
    } else if (stableJson(artifact.admitted_goal) !== stableJson(goalResult.authority)) {
      return deniedLifecycle(state, request, "STALE_DERIVATION", artifact);
    }
    if (artifact.admitted_research === null) {
      if (!await commitBoundary({ ...artifact, admitted_research: researchResult.authority })) return { state, visited: [] };
    } else if (stableJson(artifact.admitted_research) !== stableJson(researchResult.authority)) {
      return deniedLifecycle(state, request, "STALE_DERIVATION", artifact);
    }
    while (artifact.next_transition_index < request.transitions.length && remaining > 0) {
      const proposal = request.transitions[artifact.next_transition_index] as GoalTransitionProposalV1;
      const transition = evaluateGoalTransition(artifact.transition_state, proposal);
      if (!transition.advanced) return deniedLifecycle(state, request, transition.code, artifact);
      if (proposal.next_head_digest !== expectedHead(proposal)) return deniedLifecycle(state, request, "STALE_DERIVATION", artifact);
      const terminal = transition.state.phase === "ARCHITECTURE_AUTHORIZED";
      const next: GoalLifecycleArtifactV1 = {
        ...artifact,
        code: terminal ? "ARCHITECTURE_AUTHORIZED" : "IN_PROGRESS",
        transition_state: transition.state,
        next_transition_index: artifact.next_transition_index + 1,
      };
      if (!await commitBoundary(next, terminal ? "completed" : "running")) break;
      if (terminal) return { state, visited: [] };
    }
    if (artifact.next_transition_index >= request.transitions.length) return deniedLifecycle(state, request, "ILLEGAL_PHASE_EDGE", artifact);
    return { state, visited: [] };
  }

  const api: AutonomyLoop = {
    manager,
    supportsStrategy(domainWorkflowKind) {
      if (domainWorkflowKind !== undefined) return cfg.domainWorkflows !== undefined || fixedDomainKind === domainWorkflowKind;
      return fixedDomainKind !== undefined || cfg.softwareStrategyAvailable !== false;
    },
    resumePermission(runId, input = {}) {
      const state = checkpoints.load(runId);
      if (state?.wait?.kind === "capability" && input.capability !== undefined) return state.wait.resumeAuthority === "approval" ? "review.approve" : "change.solve";
      if (input.approval !== undefined || input.policy !== undefined || input.reconciliation !== undefined) return "review.approve";
      return "change.solve";
    },
    async runProject(goal, opts = {}): Promise<LoopRunResult> {
      goal = secretIntake.process(goal).safeText;
      const goalContext = opts.goalContext === undefined ? undefined : secretIntake.process(opts.goalContext).safeText;
      const runId = opts.runId ?? `proj-${randomUUID()}`;
      const strategy = strategyFor(opts.domainWorkflowKind);
      const existing = checkpoints.load(runId);
      // The public local API predates explicit project handles. In an installed composition,
      // preserve that capability by acquiring (or recovering) a durable owner before the first
      // checkpoint. The authenticated state chooses an existing owner; callers never do.
      if (cfg.manager !== undefined && managedOwners.get(runId) === undefined) {
        const owner = existing?.projectId ?? manager.create({ name: "Keep project" }).id;
        return api.runManagedProject(owner, goal, { ...opts, runId });
      }
      if (existing !== undefined) {
        const owner = managedOwners.get(runId);
        if (existing.projectId !== undefined && owner !== existing.projectId) throw new Error(`run ${runId} requires its owning managed project`);
        if (existing.goal !== goal) throw new Error(`project runId ${runId} already belongs to a different goal`);
        if (existing.artifacts["goal_work_context"] !== goalContext) throw new Error(`project runId ${runId} already belongs to different goal context`);
        const existingStrategy = restoredStrategy(existing);
        if (JSON.stringify(existingStrategy) !== JSON.stringify(strategy)) throw new Error(`project runId ${runId} already belongs to a different strategy`);
        const pristineInitialization = existing.revision === 0 && existing.stage === "understand" && existing.status === "running" && Object.keys(existing.artifacts).length === 0;
        if (opts.goalLifecycle !== undefined && !hasLifecycleArtifact(existing) && !pristineInitialization) {
          if (cfg.goalAuthorityEvents === undefined || await cfg.goalAuthorityEvents.load(runId) === null) throw new Error(`project runId ${runId} already belongs to the legacy project mode`);
        }
        if (opts.goalLifecycle !== undefined || hasLifecycleArtifact(existing)) {
          const raw = existing.artifacts["goal_lifecycle"];
          const recoveredRequest = plainObject(raw) ? raw["request"] : undefined;
          return runGoalLifecycle(existing, opts.goalLifecycle ?? recoveredRequest, opts.stepBudget);
        }
        return { state: existing, visited: [] };
      }
      const narrator = new ProgressNarrator(runId, cfg.spine);
      const loopConfig: Partial<ProjectLoopConfig> = {
        ...(cfg.loopConfig ?? {}),
        ...(opts.stepBudget !== undefined ? { stepBudget: opts.stepBudget } : {}),
      };
      const loop = new ProjectLoop(cfg.spine, narrator, executorsFor(strategy), loopConfig, cfg.nonPersistable, cfg.tracer, checkpoints, Date.now, cfg.permissionPolicy, opts.signal, opts.trackActivity, opts.memoryContext);
      const posture = stricterPosture(cfg.posture ?? "autonomous", opts.posture);
      let initialized: ProjectState | undefined;
      let preparationBinding: string | undefined;
      let operationBinding: string | undefined;
      const initialState = (): ProjectState => initialized ??= loop.init(runId, goal, posture, strategy, managedOwners.get(runId), goalContext, preparationBinding, operationBinding);
      if (opts.signal?.aborted) return { state: loop.holdCapability(initialState(), "project-cancellation", "Operator cancelled before project dispatch."), visited: [] };

      if (opts.goalLifecycle !== undefined) return runGoalLifecycle(initialState(), opts.goalLifecycle, opts.stepBudget);

      // Feasibility pre-flight (deterministic floor; optional LLM refinement that only tightens honesty). This is the
      // "fully autonomous UNLESS out of competence" envelope: if Keep can't deliver the goal end-to-end (physical build,
      // external-account operation, out-of-scope), it does NOT charge ahead — it pauses for the human to accept an honest
      // reframe first. Overpromising is the #1 trust-killer; early honest scoping beats false continuation.
      const genericFeasibility = await checkFeasibility(goal, cfg.feasibilityClassifier);
      const feasibility = strategy.kind === "software" ? genericFeasibility : domainWorkflowFeasibility(goal, strategy.domainKind, genericFeasibility);
      if (!feasibility.proceed) {
        cfg.spine.stage({
          type: "identity.action",
          actor: "autonomy",
          payload: { event: "feasibility_pause", runId, deliverability: feasibility.deliverability, sensitivity: feasibility.sensitivity },
        });
        return { state: loop.holdCapability(initialState(), `goal-delivery:${feasibility.deliverability}`, feasibility.framing), visited: [], feasibility };
      }

      // Autonomy-posture guard: even a FEASIBLE goal is not run autonomously if it is an external/irreversible
      // action (route to the human veto) or would breach the spend cap (pause for top-up). Feasibility gates
      // deliverability; this gates the POSTURE — external/irreversible/over-cap are never autonomous.
      // Classify the operation supplied by the native host, not nouns in its goal.
      // The host owns the constrained editor/test ports and current command authority;
      // model proposals still pass the ordinary content-bound edit/effect gates.
      if (posture === "autonomous" && strategy.kind === "software"
        && cfg.softwareOperation?.authorize(runId, managedOwners.get(runId), goal) === true) {
        operationBinding = cfg.softwareOperation.binding;
      }
      const authz = authorizeAutonomousAction(
        {
          description: operationBinding === undefined ? goal : "bounded repository edit and isolated verification",
          consequence: operationBinding === undefined ? estimateConsequence({ message: goal }).consequence : "reversible",
          ...(cfg.estimatedActionCostUsd !== undefined ? { costUsd: cfg.estimatedActionCostUsd } : {}),
        },
        cfg.spendCap ?? { canAfford: () => true },
      );
      if (authz.verdict === "veto" && posture === "autonomous" && strategy.kind === "software" && cfg.softwarePreparation !== undefined) {
        const cost = cfg.estimatedActionCostUsd ?? 0;
        if (cost > 0 && cfg.spendCap?.canAfford(cost) === false) return { state: loop.pauseBudget(initialState(), "Preparation would breach the configured spend cap."), visited: [], feasibility };
        preparationBinding = cfg.softwarePreparation.binding;
      }
      if (authz.verdict !== "autonomous" && preparationBinding === undefined) {
        cfg.spine.stage({
          type: "identity.action",
          actor: "autonomy",
          payload: { event: "autonomy_guard_pause", runId, verdict: authz.verdict, externalClass: authz.externalClass },
        });
        // Async veto surface: a vetoed external/irreversible goal is PARKED for the human to veto or approve later
        // (NEVER auto-runs). The pause return below is preserved — the queue is the async surface behind it.
        if (authz.verdict === "blocked-over-cap") {
          return { state: loop.pauseBudget(initialState(), authz.rationale), visited: [], feasibility };
        }
        if (authz.verdict === "veto" && posture === "approval-required" && cfg.vetoQueue !== undefined) {
          const owner = managedOwners.get(runId);
          const tenant = owner === undefined ? undefined : cfg.manager?.list().find((record) => record.id === owner)?.tenant;
          cfg.vetoQueue.enqueue({ id: runId, description: goal, externalClass: authz.externalClass, ...(tenant === undefined ? {} : { tenant }) }, Date.now());
        }
        if (authz.verdict === "veto" && posture === "approval-required") {
          return { state: await loop.holdForApproval(initialState(), authz.rationale), visited: [], feasibility };
        }
        if (authz.verdict === "veto" && posture === "policy-calibrated") {
          if (cfg.permissionPolicy === undefined) return { state: loop.holdCapability(initialState(), "project-permission-policy", "Policy-calibrated posture requires an installed permission policy."), visited: [], feasibility };
          const decision = await cfg.permissionPolicy({ runId, stage: "understand", reason: authz.rationale, severity: "routine" });
          if (decision === "deny") return { state: loop.holdCapability(initialState(), "policy-approved-alternative", authz.rationale, "approval"), visited: [], feasibility };
          if (decision === "approval") return { state: await loop.holdForApproval(initialState(), authz.rationale), visited: [], feasibility };
        }
        if (authz.verdict === "veto" && posture === "autonomous") {
          return {
            state: loop.holdCapability(initialState(), `authorized-effect-executor:${authz.externalClass}`, `The external effect is isolated until an executor with fresh commit-time authority is installed. ${authz.rationale}`, "approval"),
            visited: [], feasibility,
          };
        }
      }

      // Establish the run's trace context so every model call inside a stage records a cost-tagged span in this run's
      // trace (per-task/per-model cost attribution + llm-error localization), propagated across awaits.
      const lessonIds = cfg.lessonsForGoal ? cfg.lessonsForGoal(goal) : [];
      const managedOwner = managedOwners.get(runId);
      const tenant = managedOwner === undefined ? undefined : cfg.manager?.list().find((record) => record.id === managedOwner)?.tenant;
      const res = await runWithinTrace(
        { traceId: runId, taskId: runId, ...(tenant === undefined ? {} : { tenant }), ...(lessonIds.length ? { lessonIds } : {}) },
        () => loop.run(initialState()),
      );
      return { ...res, feasibility };
    },
    async runManagedProject(projectId, goal, opts = {}): Promise<LoopRunResult> {
      goal = secretIntake.process(goal).safeText;
      const session = manager.runnableSession(projectId);
      const bound = session.lastCheckpoint();
      if (bound !== undefined && opts.runId !== undefined && opts.runId !== bound.runId) {
        throw new Error(`project ${projectId} is already bound to run ${bound.runId}`);
      }
      if (bound !== undefined && bound.goal !== goal) throw new Error(`project ${projectId} is already bound to a different goal`);
      const runId = opts.runId ?? session.boundRunId() ?? bound?.runId ?? `proj-${randomUUID()}`;
      session.bindRun(runId);
      managedOwners.set(runId, projectId);
      try {
        const execute = () => api.runProject(goal, { ...opts, runId });
        const result = cfg.runInProjectContext === undefined ? await execute() : await cfg.runInProjectContext(projectId, runId, execute);
        if (result.state.projectId !== projectId) throw new Error(`run ${runId} lost its project ownership binding`);
        return await finalizeManagedResult(projectId, result);
      } finally { managedOwners.delete(runId); }
    },
    async resumeProject(runId, input = {}, control = {}): Promise<LoopRunResult> {
      const state = checkpoints.load(runId);
      const owner = managedOwners.get(runId);
      if (cfg.manager !== undefined && owner === undefined && state?.projectId !== undefined) return api.resumeManagedProject(state.projectId, runId, input, control);
      if (state?.projectId !== undefined && owner !== state.projectId) throw new Error(`run ${runId} requires its owning managed project`);
      if (state?.artifacts["memory_context_required"] === true && control.memoryContext === undefined) throw new TaskMemoryUnavailableError("authority");
      control.memoryContext?.assertCurrent();
      if (state !== undefined && hasLifecycleArtifact(state)) {
        const raw = state.artifacts["goal_lifecycle"];
        return runGoalLifecycle(state, plainObject(raw) ? raw["request"] : undefined, input.addSteps);
      }
      const loop = loopFor(restoredStrategy(state), undefined, control);
      const projectId = state?.projectId;
      const tenant = projectId === undefined ? undefined : cfg.manager?.list().find((record) => record.id === projectId)?.tenant;
      return runWithinTrace({ traceId: runId, taskId: runId, ...(tenant === undefined ? {} : { tenant }) }, () => loop.resume(runId, input, candidate => {
        const marker = candidate.artifacts["software_preparation"] as { schemaVersion?: unknown; binding?: unknown } | undefined;
        const prior = candidate.artifacts["implement"] as { solve?: SolveToPrResult["solveResult"] } | undefined;
        const recovery = prior?.solve?.recovery;
        if (stricterPosture(cfg.posture ?? "autonomous", candidate.posture) !== "autonomous" || candidate.strategy?.kind !== "software" || candidate.stage !== "implement"
          || candidate.wait?.kind !== "capability" || candidate.wait.capability !== "project-execution-admission"
          || !marker || Object.keys(marker).length !== 2 || marker.schemaVersion !== 1 || marker.binding !== cfg.softwarePreparation?.binding
          || Object.hasOwn(candidate.artifacts, "software_operation") || Object.hasOwn(candidate.artifacts, "software_prepared_implementation")
          || prior?.solve?.solved !== false || prior.solve.preparedProposal?.disposition !== "unexecuted"
          || recovery?.status !== "ready" || recovery.pendingAttemptId !== undefined || Date.now() >= recovery.deadline
          || recovery.attempts >= recovery.maxAttempts || recovery.planningCalls >= recovery.maxPlanningCalls
          || control.signal?.aborted || cfg.softwareOperation?.authorize(candidate.runId, candidate.projectId, candidate.goal) !== true
          || ((cfg.estimatedActionCostUsd ?? 0) > 0 && cfg.spendCap?.canAfford(cfg.estimatedActionCostUsd!) === false)) return undefined;
        control.memoryContext?.assertCurrent();
        return cfg.softwareOperation.binding;
      }));
    },
    async resumeManagedProject(projectId, runId, input = {}, control = {}): Promise<LoopRunResult> {
      const session = manager.runnableSession(projectId);
      if (session.boundRunId() !== runId) throw new Error(`project ${projectId} does not own run ${runId}`);
      managedOwners.set(runId, projectId);
      try {
        const result = await api.resumeProject(runId, input, control);
        if (result.state.projectId !== projectId) throw new Error(`run ${runId} belongs to a different project`);
        return await finalizeManagedResult(projectId, result);
      } finally { managedOwners.delete(runId); }
    },
  };
  return api;
}

function stricterPosture(configured: AuthorityPosture, requested: AuthorityPosture | undefined): AuthorityPosture {
  if (requested === undefined) return configured;
  const rank: Readonly<Record<AuthorityPosture, number>> = { autonomous: 0, "policy-calibrated": 1, "approval-required": 2 };
  return rank[requested] > rank[configured] ? requested : configured;
}
