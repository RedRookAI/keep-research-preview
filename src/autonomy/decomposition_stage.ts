import { types } from "node:util";
import { createHash } from "node:crypto";
import { canonicalize } from "../spine/event.js";

import type { ProjectState, StageExecutor, StageResult } from "./project_loop.js";
import { projectGoalId, validateProjectPlan, type ProjectPlanArtifact } from "./plan_stage.js";
import { vetProjectPlan } from "./plan_gate_stage.js";
import type { ProjectIntentArtifact } from "./understand_stage.js";
import { candidateCreatedEventV1, reconstructDecompositionAuthorityV1, type DecompositionAuthorityEventPortV1, type DecompositionEventAuthorityContextV1 } from "../decomposition/decomposition_review_events_v1.js";

export interface TaskCompletionCriterion {
  readonly id: string;
  readonly statement: string;
  readonly evidence: string;
}

export interface ProjectTask {
  readonly id: string;
  readonly planStepId: string;
  readonly objective: string;
  readonly dependsOn: readonly string[];
  readonly completionCriteria: readonly TaskCompletionCriterion[];
}

/** Durable execution ticket: an authenticated, dependency-preserving projection of the vetted plan. */
export interface ProjectDecompositionArtifact {
  readonly schemaVersion: 1;
  readonly id: string;
  readonly goalId: string;
  /** Exactly one dependency-free task is admitted for this run's implementation stage. */
  readonly admittedTaskId: string;
  readonly tasks: readonly ProjectTask[];
  readonly validation: { readonly valid: boolean; readonly reasons: readonly string[] };
}

const EPIC_RX = /\b(entire|everything|all features|whole system|full (product|platform|application)|end-to-end platform)\b/i;
const MAX_TASKS = 20;
const MAX_TASK_CHARS = 512;
const MAX_CRITERIA = 5;
const MAX_CRITERION_CHARS = 1_024;
export const PROJECT_CRITERION_REF_PREFIX = "Retained success criterion SHA-256: ";

/** The full criterion remains in intent; bounded task projections reference it. */
function projectCriterion(criterion: TaskCompletionCriterion): TaskCompletionCriterion {
  const reference = PROJECT_CRITERION_REF_PREFIX + createHash("sha256").update(canonicalize(criterion)).digest("hex");
  return Object.freeze({ id: criterion.id,
    statement: criterion.statement.length <= MAX_CRITERION_CHARS ? criterion.statement : reference,
    evidence: criterion.evidence.length <= MAX_CRITERION_CHARS ? criterion.evidence : reference });
}

function inert(value: unknown, depth = 0, budget = { remaining: 10_000 }): boolean {
  if (budget.remaining-- <= 0 || depth > 32 || types.isProxy(value)) return false;
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value !== "object" || Object.getOwnPropertySymbols(value).length !== 0) return false;
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Object.keys(descriptors).length !== value.length + 1) return false;
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || descriptor.get || descriptor.set || !("value" in descriptor) || !inert(descriptor.value, depth + 1, budget)) return false;
    }
    return true;
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) return false;
  return Object.values(Object.getOwnPropertyDescriptors(value)).every((descriptor) =>
    !descriptor.get && !descriptor.set && "value" in descriptor && inert(descriptor.value, depth + 1, budget));
}

function prerequisites(state: ProjectState): { plan: ProjectPlanArtifact; intent: ProjectIntentArtifact } {
  const candidate = state.artifacts["plan"];
  const intent = state.artifacts["understand"];
  if (!inert(candidate) || !inert(intent) || validateProjectPlan(candidate, state).valid !== true || vetProjectPlan(state).proceed !== true) {
    throw new Error("decomposition requires the exact deterministically vetted plan");
  }
  const completeIntent = intent as unknown as ProjectIntentArtifact;
  if (completeIntent.schemaVersion !== 1 || completeIntent.input?.text !== state.goal || !Array.isArray(completeIntent.successCriteria)) {
    throw new Error("decomposition requires success criteria bound to the persisted goal");
  }
  return { plan: candidate as unknown as ProjectPlanArtifact, intent: completeIntent };
}

/** Total validator for untrusted durable task artifacts. */
export function validateProjectTasks(tasks: unknown, plan: ProjectPlanArtifact): readonly string[] {
  try { return validateProjectTasksInner(tasks, plan); }
  catch { return Object.freeze(["decomposition could not be safely inspected"]); }
}

function validateProjectTasksInner(tasks: unknown, plan: ProjectPlanArtifact): readonly string[] {
  const reasons: string[] = [];
  if (!inert(tasks) || !Array.isArray(tasks)) return Object.freeze(["decomposition is not inert bounded data"]);
  if (tasks.length === 0) reasons.push("decomposition produced no tasks");
  if (tasks.length > MAX_TASKS) reasons.push(`decomposition exceeds the ${MAX_TASKS}-task bound`);
  const planStepIds = new Set(plan.steps.map((step) => step.id));
  const taskByPlanStep = new Map<string, ProjectTask>();
  const seen = new Set<string>();
  for (const value of tasks) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) { reasons.push("decomposition contains a malformed task"); continue; }
    const task = value as ProjectTask;
    const id = typeof task.id === "string" ? task.id : "";
    const planStepId = typeof task.planStepId === "string" ? task.planStepId : "";
    if (!/^task-[0-9]{2}$/.test(id) || seen.has(id)) reasons.push(`invalid or duplicate task id: ${id || "<empty>"}`);
    if (!planStepIds.has(planStepId)) reasons.push(`task ${id || "<empty>"} is outside the vetted plan`);
    if (taskByPlanStep.has(planStepId)) reasons.push(`plan step ${planStepId || "<empty>"} has multiple tasks`);
    else taskByPlanStep.set(planStepId, task);
    if (typeof task.objective !== "string" || task.objective.trim().length === 0 || task.objective.length > MAX_TASK_CHARS) reasons.push(`task ${id || "<empty>"} objective is empty or exceeds ${MAX_TASK_CHARS} characters`);
    else if (EPIC_RX.test(task.objective)) reasons.push(`task ${id} is epic-shaped and must be split`);
    if (!Array.isArray(task.dependsOn) || task.dependsOn.some((dependency) => typeof dependency !== "string" || !seen.has(dependency))) reasons.push(`task ${id || "<empty>"} has a missing or forward dependency`);
    if (!Array.isArray(task.completionCriteria) || task.completionCriteria.length === 0 || task.completionCriteria.length > MAX_CRITERIA || task.completionCriteria.some((criterion) =>
      criterion === null || typeof criterion !== "object" || typeof criterion.id !== "string" || criterion.id.trim().length === 0 ||
      typeof criterion.statement !== "string" || criterion.statement.trim().length === 0 || criterion.statement.length > MAX_CRITERION_CHARS ||
      typeof criterion.evidence !== "string" || criterion.evidence.trim().length === 0 || criterion.evidence.length > MAX_CRITERION_CHARS)) {
      reasons.push(`task ${id || "<empty>"} lacks bounded observable completion criteria`);
    }
    seen.add(id);
  }
  for (const step of plan.steps) {
    const task = taskByPlanStep.get(step.id);
    if (!task) { reasons.push(`plan step ${step.id} has no task`); continue; }
    const expected = step.dependsOn.map((id) => taskByPlanStep.get(id)?.id).filter((id): id is string => id !== undefined);
    if (!Array.isArray(task.dependsOn) || task.dependsOn.length !== expected.length || task.dependsOn.some((id, index) => id !== expected[index])) reasons.push(`task ${task.id} does not preserve plan dependencies`);
    if (task.objective !== step.description) reasons.push(`task ${task.id} does not preserve its plan objective`);
  }
  return Object.freeze(reasons);
}

export function decomposeProjectPlan(state: ProjectState): ProjectDecompositionArtifact {
  const { plan, intent } = prerequisites(state);
  const taskIds = new Map(plan.steps.map((step, index) => [step.id, `task-${String(index + 1).padStart(2, "0")}`]));
  const tasks = plan.steps.map((step, index): ProjectTask => Object.freeze({
    id: taskIds.get(step.id)!,
    planStepId: step.id,
    objective: step.description,
    dependsOn: Object.freeze(step.dependsOn.map((id) => taskIds.get(id)!).filter((id): id is string => id !== undefined)),
    completionCriteria: Object.freeze((index === plan.steps.length - 1 ? intent.successCriteria : intent.successCriteria.slice(0, 1)).map(projectCriterion)),
  }));
  const reasons = validateProjectTasks(tasks, plan);
  return Object.freeze({
    schemaVersion: 1, id: state.runId, goalId: projectGoalId(state.goal), admittedTaskId: tasks.find((task) => task.dependsOn.length === 0)?.id ?? "",
    tasks: Object.freeze(tasks), validation: Object.freeze({ valid: reasons.length === 0, reasons }),
  });
}

export function buildDecompositionStageExecutor(events?: DecompositionAuthorityEventPortV1, authority?: (state: ProjectState) => DecompositionEventAuthorityContextV1, onProjection?: (state:ProjectState,bundle:NonNullable<Awaited<ReturnType<DecompositionAuthorityEventPortV1["load"]>>>)=>Promise<void>): StageExecutor {
  return async (state): Promise<StageResult> => {
    try {
      if ((events === undefined) !== (authority === undefined)) return { output: { schemaVersion: 1, valid: false, code: "DECOMPOSITION_EVENT_AUTHORITY_REQUIRED" }, control: "capability-unavailable", capability: "decomposition-event-authority", headline: "Decomposition event authority is required" };
      let artifact: ProjectDecompositionArtifact;
      if (events === undefined || authority === undefined) artifact = decomposeProjectPlan(state);
      else {
        const loaded = await events.load(state.runId);
        const replayed = reconstructDecompositionAuthorityV1(state.runId, loaded);
        if (!replayed.ok) return { output: { schemaVersion: 1, valid: false, code: replayed.code }, control: "fail", permanent: true, headline: "Decomposition event history was refused" };
        if (loaded === null && Object.hasOwn(state.artifacts, "ticket")) return { output: { schemaVersion: 1, valid: false, code: "LEGACY_DECOMPOSITION_MUTATION_REJECTED" }, control: "fail", permanent: true, headline: "Legacy decomposition mutation was refused" };
        artifact = replayed.projection.candidate ?? decomposeProjectPlan(state);
        if (replayed.projection.candidate === null) {
          const committed = await events.appendAndReplay(state.runId, candidateCreatedEventV1(state.runId, state, authority(state)));
          const verified = reconstructDecompositionAuthorityV1(state.runId, committed);
          if (!verified.ok || verified.projection.candidate === null || verified.projection.event_count !== 1) throw new Error("decomposition event failed replay verification");
          artifact = verified.projection.candidate;
        }
        const current=await events.load(state.runId);if(current!==null&&onProjection!==undefined)await onProjection(state,current);
      }
      if (!artifact.validation.valid) return { output: artifact, control: "rework", reworkTo: "plan", headline: "Task decomposition returned to bounded replanning", detail: artifact.validation.reasons.join("; ") };
      return { output: artifact, control: "advance", headline: `Admitted one root task from ${artifact.tasks.length} dependency-ordered tasks` };
    } catch (error) {
      return { output: { schemaVersion: 1, valid: false }, control: "rework", reworkTo: "plan", headline: "Task decomposition prerequisites changed; replanning from durable intent", detail: error instanceof Error ? error.message : "decomposition rejected a non-Error exception" };
    }
  };
}
