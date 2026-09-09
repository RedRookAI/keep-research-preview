import assert from "node:assert/strict";
import { test } from "node:test";

import { decideProjectResearch } from "../src/autonomy/research_decision_stage.js";
import { captureProjectIntent } from "../src/autonomy/understand_stage.js";
import type { IntentShape } from "../src/frontdoor/intent_router.js";
import type { ProjectState } from "../src/autonomy/project_state.js";

const state = (goal: string, shape: IntentShape = "concrete-task"): ProjectState => ({
  schemaVersion: 1, revision: 1, runId: "research-decision", goal, stage: "research", posture: "autonomous",
  stepsRemaining: 10, reworkCount: 0, status: "running", retry: { attemptsByStage: {}, attemptsConsumed: 0, runLimit: 8 }, consumedSignals: [],
  artifacts: { understand: captureProjectIntent(goal, { shape, confidence: 0.9, via: "rule", note: "routed" }) },
});

test("bounded local work records why external research is unnecessary", () => {
  const decision = decideProjectResearch(state("implement and test a local parser in this repository"), false);
  assert.equal(decision.required, false);
  assert.equal(decision.coordinator, "built-in");
  assert.match(decision.reason, /not required/);
});

test("current external dependence records exact debt without claiming the coordinator is missing", () => {
  const decision = decideProjectResearch(state("research current parser standards and implement the repository changes"), false);
  assert.equal(decision.required, true);
  assert.equal(decision.available, false);
  assert.equal(decision.coordinator, "built-in");
  assert.match(decision.reason, /built-in coordinator.*retrieval debt/i);
  assert.ok(decision.signals.includes("research-trigger:recency-sensitive"));
  assert.ok(decision.signals.includes("research-trigger:explicit-research-goal"));
});

test("local wording cannot suppress an unstable external dependency", () => {
  const decision = decideProjectResearch(state("Update this repository for the latest regulations and vendor prices."), true);
  assert.equal(decision.required, true);
  assert.ok(decision.signals.includes("research-trigger:recency-sensitive"));
});

test("open-ended external goals require grounding while bounded local ones do not", () => {
  const external = decideProjectResearch(state("help me grow this business somehow", "open-ended-goal"), true);
  assert.equal(external.required, true);
  assert.ok(external.signals.includes("open-ended-goal-needs-external-grounding"));
  const local = decideProjectResearch(state("improve the architecture of this local repository", "open-ended-goal"), true);
  assert.equal(local.required, false);
});

test("research decision refuses to guess without durable understanding", () => {
  assert.throws(() => decideProjectResearch({ ...state("x"), artifacts: {} }, false), /persisted understand artifact/);
});

test("named source runtime state is not an external freshness request and full intent is retained", () => {
  const input = state("Add the retryStatus export in src/retry.mjs returning the current retry limit followed by attempts. Preserve all earlier exports.");
  const before = JSON.stringify(input);
  assert.equal(decideProjectResearch(input, false).required, false);
  assert.equal(JSON.stringify(input), before);
  assert.equal(decideProjectResearch(state("Read the current value from `lib/status.ts`."), false).required, false);
});

test("source paths and local state cannot erase other research obligations", () => {
  for (const goal of [
    "Update src/sdk.ts for the latest SDK version.",
    "Read the current value from src/status.ts and research latest parser standards.",
    "Read the current value from src/status.ts and compare competing approaches.",
    "Return the current vendor prices from src/pricing.ts.",
    "Read the current value from https://example.invalid/status.json.",
    "Implement the current API protocol in src/client.ts.",
  ]) assert.equal(decideProjectResearch(state(goal), false).required, true, goal);
});

const withTaskMemory = (goal: string): ProjectState => {
  const input = state(goal, "revision");
  return { ...input, artifacts: { ...input.artifacts, memory_context_required: true } };
};

test("selected retained history routes original and replacement settings to task evidence", () => {
  // Exact installed request that previously stopped both authority tracks before
  // any memory/model use. Values deliberately absent: routing is not an answer.
  const goal = "Restore migrationOriginalRetries and liveCurrentRetries in src/retry.mjs from retained launch history and the latest policy. Migration must preserve the original rollout setting, while live traffic must use its current replacement. Preserve schedulerVersion and the exported API. Change only src/retry.mjs; do not change tests.";
  const input = withTaskMemory(goal), before = JSON.stringify(input);
  const decision = decideProjectResearch(input, false);
  assert.equal(decision.required, false);
  assert.deepEqual(decision.signals, []);
  assert.equal(decision.available, false, "no research availability is fabricated");
  assert.equal(JSON.stringify(input), before, "no rewrite of request or authority");
  assert.equal(decideProjectResearch(state(goal, "revision"), false).required, true, "text alone cannot assert selected task memory");
  assert.equal(decideProjectResearch(withTaskMemory("Restore src/config.ts using retained project records and the newest setting."), false).required, false);
});

test("retained history and file scope cannot suppress external or additional research", () => {
  for (const goal of [
    "Restore settings from retained launch history and the latest policy.",
    "Restore src/retry.mjs from launch history and the latest policy.",
    "Restore src/retry.mjs from retained launch history and the latest SDK version.",
    "Restore src/retry.mjs from retained launch history and the latest policy; research competing approaches.",
    "Restore src/retry.mjs from retained launch history and the latest policy; compare alternatives.",
    "Restore src/retry.mjs from retained launch history and the latest policy; check if an alternative already exists.",
    "Restore src/retry.mjs from retained launch history and the latest policy for vendor pricing.",
    "Restore src/retry.mjs from retained launch history and the latest policy required by regulations.",
    "Restore src/retry.mjs from retained launch history and the latest security standards.",
    "Restore src/retry.mjs from retained launch history and the latest policy at https://example.invalid/policy.json.",
    "Restore src/retry.mjs from retained launch history and today's policy.",
  ]) assert.equal(decideProjectResearch(withTaskMemory(goal), false).required, true, goal);
});
