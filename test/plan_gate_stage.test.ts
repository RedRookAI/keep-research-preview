import assert from "node:assert/strict";
import { test } from "node:test";

import { buildPlanGateStageExecutor, vetProjectPlan } from "../src/autonomy/plan_gate_stage.js";
import { createProjectPlan, type ProjectPlanArtifact } from "../src/autonomy/plan_stage.js";
import { captureProjectIntent } from "../src/autonomy/understand_stage.js";
import type { ProjectState } from "../src/autonomy/project_loop.js";

function state(researchRequired = false): ProjectState {
  const goal = "implement deterministic parser recovery";
  const base: ProjectState = {
    schemaVersion: 1, revision: 1, runId: "gate", goal, stage: "plan", posture: "autonomous", stepsRemaining: 5, reworkCount: 0, status: "running",
    retry: { attemptsByStage: {}, attemptsConsumed: 0, runLimit: 8 }, consumedSignals: [],
    artifacts: {
      understand: captureProjectIntent(goal, { shape: "concrete-task", confidence: 1, via: "rule", note: "test" }),
      research: { decision: { required: researchRequired } },
      ...(researchRequired ? { rag: { sufficiency: { status: "sufficient" }, sourceIds: ["source-a"], chunks: [{ text: "evidence", sourceId: "source-a", score: 1 }] } } : {}),
    },
  };
  return { ...base, stage: "vet_plan", artifacts: { ...base.artifacts, plan: createProjectPlan(base) } };
}

const planOf = (state: ProjectState): ProjectPlanArtifact => state.artifacts["plan"] as ProjectPlanArtifact;

test("LOOP-07: the installed project plan clears one deterministic gate pass", () => {
  const verdict = vetProjectPlan(state());
  assert.equal(verdict.proceed, true);
  assert.deepEqual(verdict.holds, []);
});

test("LOOP-07: invalid order, scope, and non-regression properties all hold before implementation", () => {
  const s = state();
  const plan = planOf(s);
  const broken: ProjectPlanArtifact = {
    ...plan,
    committedStepIds: ["prior"],
    steps: [
      { ...plan.steps[0]!, dependsOn: ["verify"], advancesGoal: "other-goal", undoes: ["prior"] },
      plan.steps[1]!,
    ],
  };
  const verdict = vetProjectPlan({ ...s, artifacts: { ...s.artifacts, plan: broken } });
  assert.equal(verdict.proceed, false);
  assert.ok(verdict.holds.some((hold) => hold.startsWith("order:")));
  assert.ok(verdict.holds.some((hold) => hold.startsWith("goal:")));
  assert.ok(verdict.holds.some((hold) => hold.startsWith("regression:")));
});

test("LOOP-07: research-required plans must use every retrieved source", () => {
  const s = state(true);
  const plan = planOf(s);
  const verdict = vetProjectPlan({ ...s, artifacts: { ...s.artifacts, plan: { ...plan, evidence: plan.evidence.filter((row) => row.sourceId !== "source-a") } } });
  assert.equal(verdict.proceed, false);
  assert.ok(verdict.holds.some((hold) => hold.includes("not grounded in admitted evidence")));
  assert.ok(verdict.holds.includes("research:source-not-used:source-a"));
});

test("LOOP-07: rejection returns to bounded replanning instead of creating a human gate", async () => {
  const s = state();
  const plan = planOf(s);
  const result = await buildPlanGateStageExecutor()({ ...s, artifacts: { ...s.artifacts, plan: { ...plan, steps: [] } } });
  assert.equal(result.control, "rework");
  assert.equal(result.reworkTo, "plan");
});

test("LOOP-07: missing and hostile durable plans are total deterministic rework outcomes", async () => {
  for (const candidate of [undefined, null, { schemaVersion: 1 }, new Proxy({}, { getPrototypeOf() { throw new Error("trap"); } })]) {
    const s = { ...state(), artifacts: { ...state().artifacts, plan: candidate } };
    assert.doesNotThrow(() => vetProjectPlan(s));
    const result = await buildPlanGateStageExecutor()(s);
    assert.equal(result.control, "rework");
  }
});

test("LOOP-07: Array subclasses cannot execute overridden methods through the exported gate", () => {
  class HostileSteps<T> extends Array<T> { override map(): never { throw new Error("hostile map executed"); } }
  const clean = state();
  const plan = planOf(clean);
  const hostile = { ...plan, steps: new HostileSteps(...plan.steps) };
  assert.doesNotThrow(() => vetProjectPlan({ ...clean, artifacts: { ...clean.artifacts, plan: hostile } }));
  assert.equal(vetProjectPlan({ ...clean, artifacts: { ...clean.artifacts, plan: hostile } }).proceed, false);
});

test("LOOP-07: deterministic internal vetting has the same no-human-gate contract in every posture", async () => {
  const clean = state();
  for (const posture of ["autonomous", "policy-calibrated", "approval-required"] as const) {
    assert.equal((await buildPlanGateStageExecutor()({ ...clean, posture })).control, "advance");
    const broken = { ...clean, posture, artifacts: { ...clean.artifacts, plan: { ...planOf(clean), steps: [] } } };
    assert.equal((await buildPlanGateStageExecutor()(broken)).control, "rework");
  }
});
