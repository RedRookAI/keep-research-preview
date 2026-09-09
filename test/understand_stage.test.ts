import assert from "node:assert/strict";
import { test } from "node:test";

import { buildUnderstandStageExecutor, captureProjectIntent, projectGoalByteLimit, type ProjectIntentRouter } from "../src/autonomy/understand_stage.js";
import type { AuthorityPosture, ProjectState } from "../src/autonomy/project_state.js";

const state = (goal: string, posture: AuthorityPosture = "autonomous"): ProjectState => ({
  schemaVersion: 1, revision: 0, runId: "understand-1", goal, stage: "understand", artifacts: {}, posture,
  stepsRemaining: 10, reworkCount: 0, status: "running", retry: { attemptsByStage: {}, attemptsConsumed: 0, runLimit: 8 }, consumedSignals: [],
});

test("concrete text becomes durable intent, constraints, and evidence-bearing success criteria", async () => {
  const result = await buildUnderstandStageExecutor()(state("implement and test a markdown parser"));
  assert.equal(result.control, "advance");
  const artifact = result.output as ReturnType<typeof captureProjectIntent>;
  assert.equal(artifact.input.text, "implement and test a markdown parser");
  assert.equal(artifact.intent.shape, "concrete-task");
  assert.equal(artifact.ambiguity.detected, false);
  assert.deepEqual(artifact.constraints.map((row) => row.id), ["requested-scope", "workspace-boundary", "consequential-effects"]);
  assert.deepEqual(artifact.successCriteria.map((row) => row.id), ["requested-outcome", "configured-verification", "artifact-vetting"]);
  assert.ok(artifact.successCriteria.every((row) => row.evidence.length > 0));
});

test("autonomous ambiguity preserves the question and advances only under a narrow reversible interpretation", async () => {
  const result = await buildUnderstandStageExecutor()(state("maybe something better", "autonomous"));
  assert.equal(result.control, "advance");
  const artifact = result.output as ReturnType<typeof captureProjectIntent>;
  assert.equal(artifact.intent.shape, "ambiguous");
  assert.equal(artifact.ambiguity.detected, true);
  assert.equal(artifact.ambiguity.safeAutonomousInterpretation, "narrow-reversible-discovery");
  assert.ok(artifact.ambiguity.clarificationQuestion);
});

for (const posture of ["policy-calibrated", "approval-required"] as const) {
  test(`${posture} ambiguity retains the hands-on decision path`, async () => {
    const result = await buildUnderstandStageExecutor()(state("maybe something better", posture));
    assert.equal(result.control, "approval-required");
    assert.match(result.detail ?? "", /do you want|different ways/i);
  });
}

test("attachment claims become exact capability debt instead of false ingestion or terminal failure", async () => {
  const router: ProjectIntentRouter = { route: async () => ({ shape: "artifact-drop", confidence: 1, via: "rule", note: "attachment" }) };
  const result = await buildUnderstandStageExecutor(router)(state("use the attached project"));
  assert.equal(result.control, "capability-unavailable");
  assert.equal(result.capability, "project-attachment-intake");
});

test("understanding preserves the canonical durable goal ceiling and rejects malformed input", () => {
  assert.equal(projectGoalByteLimit(), 1_000_000);
  assert.throws(() => captureProjectIntent("\0", { shape: "concrete-task", confidence: 1, via: "rule", note: "n" }), /non-empty bounded text/);
});
