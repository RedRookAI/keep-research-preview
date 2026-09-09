import assert from "node:assert/strict";
import { test } from "node:test";

import { buildDecompositionStageExecutor, decomposeProjectPlan, PROJECT_CRITERION_REF_PREFIX, validateProjectTasks } from "../src/autonomy/decomposition_stage.js";
import { createProjectPlan, projectGoalId, type ProjectPlanArtifact } from "../src/autonomy/plan_stage.js";
import { vetProjectPlan } from "../src/autonomy/plan_gate_stage.js";
import { captureProjectIntent } from "../src/autonomy/understand_stage.js";
import { PROJECT_STATE_SCHEMA_VERSION, type ProjectState } from "../src/autonomy/project_state.js";

function state(goal = "implement deterministic parser recovery"): ProjectState {
  const base: ProjectState = { schemaVersion: PROJECT_STATE_SCHEMA_VERSION, revision: 0, runId: "tasks", goal, stage: "plan", stepsRemaining: 5, reworkCount: 0, status: "running", posture: "autonomous", retry: { attemptsByStage: {}, attemptsConsumed: 0, runLimit: 8 }, consumedSignals: [], artifacts: {
    understand: captureProjectIntent(goal, { shape: "concrete-task", confidence: 1, via: "rule", note: "test" }), research: { decision: { required: false } },
  } };
  const plan = createProjectPlan(base);
  const withPlan = { ...base, stage: "vet_plan" as const, artifacts: { ...base.artifacts, plan } };
  return { ...withPlan, stage: "ticket", artifacts: { ...withPlan.artifacts, vet_plan: vetProjectPlan(withPlan) } };
}

test("vetted plan becomes an authenticated dependency-ordered execution ticket", () => {
  const artifact = decomposeProjectPlan(state());
  assert.equal(artifact.validation.valid, true);
  assert.equal(artifact.id, "tasks");
  assert.equal(artifact.goalId, projectGoalId(state().goal));
  assert.equal(artifact.admittedTaskId, "task-01");
  assert.deepEqual(artifact.tasks.map((task) => task.id), ["task-01", "task-02"]);
  assert.deepEqual(artifact.tasks[1]?.dependsOn, ["task-01"]);
  assert.deepEqual(artifact.tasks[1]?.completionCriteria.map((criterion) => criterion.id), ["requested-outcome", "configured-verification", "artifact-vetting"]);
});

test("long admitted goals retain their complete criteria through bounded references without replanning", async () => {
  const goal = "Implement the parser correctly. " + "Preserve this required behavior. ".repeat(100) + "LAST_REQUIREMENT";
  const s = state(goal), intent = JSON.stringify(s.artifacts["understand"]);
  const artifact = decomposeProjectPlan(s);
  assert.equal(artifact.validation.valid, true, artifact.validation.reasons.join("; "));
  assert.ok(artifact.tasks[0]!.completionCriteria[0]!.statement.startsWith(PROJECT_CRITERION_REF_PREFIX));
  assert.ok(artifact.tasks.every(t => t.completionCriteria.every(c => c.statement.length <= 1024 && c.evidence.length <= 1024)));
  assert.equal(JSON.stringify(s.artifacts["understand"]), intent); assert.ok(intent.includes(goal));
  assert.equal((await buildDecompositionStageExecutor()(s)).control, "advance");
  const restored = JSON.parse(JSON.stringify(s));
  assert.deepEqual(decomposeProjectPlan(restored), artifact);
});

test("missing, extra, reordered, or widened tasks fail exact plan fidelity", () => {
  const s = state();
  const artifact = decomposeProjectPlan(s);
  const plan = s.artifacts["plan"] as ProjectPlanArtifact;
  const broken = [{ ...artifact.tasks[1]!, dependsOn: [], objective: "invent unrelated behavior" }, { ...artifact.tasks[0]!, planStepId: "invented" }];
  const reasons = validateProjectTasks(broken, plan);
  assert.ok(reasons.some((reason) => /no task/.test(reason)));
  assert.ok(reasons.some((reason) => /outside the vetted plan/.test(reason)));
  assert.ok(reasons.some((reason) => /does not preserve its plan objective/.test(reason)));
});

test("epic output returns to bounded planning under every interaction posture", async () => {
  for (const posture of ["autonomous", "policy-calibrated", "approval-required"] as const) {
    const s = { ...state(), posture };
    const plan = s.artifacts["plan"] as ProjectPlanArtifact;
    const epic = { ...plan, steps: [{ ...plan.steps[0]!, description: "Implement the entire platform and all features and every integration" }, plan.steps[1]!] };
    const withEpic = { ...s, artifacts: { ...s.artifacts, plan: epic } };
    const gate = vetProjectPlan(withEpic);
    const result = await buildDecompositionStageExecutor()({ ...withEpic, artifacts: { ...withEpic.artifacts, vet_plan: gate } });
    assert.equal(result.control, "rework");
    assert.equal(result.reworkTo, "plan");
  }
});

test("hostile and stale prerequisites totalize to replanning without executing traps", async () => {
  let executed = false;
  const hostile = new Proxy({}, { get() { executed = true; throw new Error("trap"); } });
  const result = await buildDecompositionStageExecutor()({ ...state(), artifacts: { ...state().artifacts, plan: hostile } });
  assert.equal(result.control, "rework");
  assert.equal(executed, false);
  assert.deepEqual(validateProjectTasks(hostile, createProjectPlan(state())), ["decomposition is not inert bounded data"]);
});

test("exact whitespace-bearing goal identity survives decomposition", () => {
  const goal = "  implement deterministic parser recovery  ";
  const artifact = decomposeProjectPlan(state(goal));
  assert.equal(artifact.goalId, projectGoalId(goal));
  assert.equal(artifact.validation.valid, true);
});
