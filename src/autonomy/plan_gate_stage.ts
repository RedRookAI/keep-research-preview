import { vetPlan, type Plan, type PlanPolicy, type PlanVerdict } from "../logic/plan_gate.js";
import type { ProjectState, StageExecutor, StageResult } from "./project_loop.js";
import { validateProjectPlan, type ProjectPlanArtifact } from "./plan_stage.js";
import { types } from "node:util";

export interface ProjectPlanGateArtifact {
  readonly schemaVersion: 1;
  readonly proceed: boolean;
  readonly holds: readonly string[];
  readonly logic: PlanVerdict;
}

const POLICY: PlanPolicy = Object.freeze({
  maxCostValueRatio: 2,
  maxNoProgressRun: 1,
  // Research admission is already a required predecessor in this FSM. Requiring the separate
  // tri-research promotion package here would duplicate policy and reject ordinary project work.
  researchRequirement: "not-required",
  reviewRequirement: "not-required",
});

function logicPlan(plan: ProjectPlanArtifact): Plan {
  const last = plan.steps.at(-1);
  return {
    goals: [plan.goalId],
    committed: plan.committedStepIds,
    initialState: plan.committedStepIds.map((id) => `${id}:done`),
    goalFacts: last ? [`${last.id}:done`] : [],
    steps: plan.steps.map((step, index) => ({
      id: step.id,
      prerequisites: step.dependsOn,
      advancesGoal: step.advancesGoal,
      predictedCost: 1,
      subProblemValue: 1,
      undoes: step.undoes,
      progressAfter: index + 1,
      requires: step.dependsOn.map((id) => `${id}:done`),
      establishes: [`${step.id}:done`],
      deletes: step.undoes.map((id) => `${id}:done`),
    })),
  };
}

function researchHolds(state: ProjectState, plan: ProjectPlanArtifact): string[] {
  const research = state.artifacts["research"] as { decision?: { required?: unknown } } | undefined;
  const decision = research?.decision;
  if (decision?.required !== true) return [];
  const rag = state.artifacts["rag"] as { sufficiency?: { status?: unknown }; sourceIds?: readonly string[] } | undefined;
  if (rag?.sufficiency?.status !== "sufficient" || !Array.isArray(rag.sourceIds) || rag.sourceIds.length === 0) return ["research:retrieval-insufficient"];
  const cited = new Set(plan.evidence.map((row) => row.sourceId).filter((id): id is string => typeof id === "string"));
  return rag.sourceIds.filter((id) => !cited.has(id)).map((id) => `research:source-not-used:${id}`);
}

export function vetProjectPlan(state: ProjectState): ProjectPlanGateArtifact {
  const candidate = state.artifacts["plan"];
  const structure = validateProjectPlan(candidate, state);
  let logic = vetPlan(null as unknown as Plan, POLICY);
  let research: readonly string[] = [];
  if (isInertJson(candidate)) {
    try {
      const plan = candidate as unknown as ProjectPlanArtifact;
      logic = vetPlan(logicPlan(plan), POLICY);
      research = researchHolds(state, plan);
    } catch { /* malformed shapes retain the explicit invalid-plan hard hold */ }
  }
  const holds = Object.freeze([
    ...structure.reasons.map((reason) => `project:${reason}`),
    ...logic.hardHolds,
    ...research,
  ]);
  return Object.freeze({ schemaVersion: 1, proceed: holds.length === 0, holds, logic });
}

/** Admit only inert JSON-like data before adapting a durable artifact into the logic critic schema. */
function isInertJson(value: unknown, depth = 0, budget = { remaining: 10_000 }): boolean {
  if (budget.remaining-- <= 0 || depth > 32 || types.isProxy(value)) return false;
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value !== "object" || Object.getOwnPropertySymbols(value).length !== 0) return false;
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Object.keys(descriptors).length !== value.length + 1) return false;
    for (let index = 0; index < value.length; index++) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || descriptor.get || descriptor.set || !("value" in descriptor) || !isInertJson(descriptor.value, depth + 1, budget)) return false;
    }
    return true;
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) return false;
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if (descriptor.get || descriptor.set || !("value" in descriptor) || !isInertJson(descriptor.value, depth + 1, budget)) return false;
  }
  return true;
}

export function buildPlanGateStageExecutor(): StageExecutor {
  return async (state): Promise<StageResult> => {
    const verdict = vetProjectPlan(state);
    if (!verdict.proceed) {
      return { output: verdict, control: "rework", reworkTo: "plan", headline: "Deterministic plan vetting returned the project to bounded replanning", detail: verdict.holds.join("; ") };
    }
    const advisory = verdict.logic.softHolds.join("; ");
    return { output: verdict, control: "advance", headline: "Project plan cleared deterministic vetting", ...(advisory ? { detail: advisory } : {}) };
  };
}
