import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { buildModelProjectPlanner, buildPlanStageExecutor, createProjectPlan, parseModelProjectPlan, projectGoalId, validateProjectPlan, type ProjectPlanArtifact, type ProjectPlanEvidence } from "../src/autonomy/plan_stage.js";
import { captureProjectIntent } from "../src/autonomy/understand_stage.js";
import type { ProjectState } from "../src/autonomy/project_loop.js";
import type { ModelProvider } from "../src/gateway/gateway.js";
import { InMemoryWorkspace } from "../src/solve/workspace.js";
import { vetProjectPlan } from "../src/autonomy/plan_gate_stage.js";
import { InMemoryProjectCheckpointStore, MAX_PROJECT_CHECKPOINT_BYTES } from "../src/autonomy/project_checkpoint_store.js";

function state(researchRequired = false): ProjectState {
  const goal = "implement deterministic parser recovery";
  return {
    schemaVersion: 1, revision: 1, runId: "plan", goal, stage: "plan", posture: "autonomous",
    stepsRemaining: 5, reworkCount: 0, status: "running",
    retry: { attemptsByStage: {}, attemptsConsumed: 0, runLimit: 8 }, consumedSignals: [],
    artifacts: {
      understand: captureProjectIntent(goal, { shape: "concrete-task", confidence: 1, via: "rule", note: "test" }),
      research: { decision: { required: researchRequired } },
      ...(researchRequired ? { rag: { sufficiency: { status: "sufficient" }, chunks: [{ text: "Recovery must be deterministic.", sourceId: "https://example.test/spec", score: 1 }] } } : {}),
    },
  };
}

function canonicalRoundTrip(value: unknown): any {
  const sorted = (input: any): any => Array.isArray(input)
    ? input.map(sorted)
    : input !== null && typeof input === "object"
      ? Object.fromEntries(Object.entries(input).sort(([a], [b]) => a.localeCompare(b)).map(([key, entry]) => [key, sorted(entry)]))
      : input;
  return JSON.parse(JSON.stringify(sorted(value)));
}

test("LOOP-06: a local plan is ordered and grounded in persisted intent", () => {
  const s = state();
  const plan = createProjectPlan(s);
  assert.equal(plan.goal, s.goal);
  assert.deepEqual(plan.steps.map((step) => step.id), ["implement", "verify"]);
  assert.equal(validateProjectPlan(plan, s).valid, true);
});

test("LOOP-06: required research becomes cited plan evidence", () => {
  const s = state(true);
  const plan = createProjectPlan(s);
  assert.equal(plan.evidence[1]?.sourceId, "https://example.test/spec");
  assert.ok(plan.steps[0]?.evidenceRefs.includes("source-1"));
});

test("LOOP-06: invalid configured output is autonomously replaced before ticketing", async () => {
  const invalid: ProjectPlanArtifact = { schemaVersion: 1, goal: state().goal, goalId: projectGoalId(state().goal), evidence: [], committedStepIds: [], steps: [] };
  const result = await buildPlanStageExecutor(() => invalid)(state());
  assert.equal(result.control, "advance");
  assert.match(result.headline, /safely replaced/i);
  assert.deepEqual((result.output as ProjectPlanArtifact).steps.map((step) => step.id), ["implement", "verify"]);
});

test("LOOP-06: validator is total over hostile runtime values and rejects malformed graphs", () => {
  const s = state();
  for (const value of [null, [], "plan", { schemaVersion: 1 }, { schemaVersion: 1, goal: s.goal, evidence: [null], committedStepIds: [], steps: [null] }]) {
    assert.doesNotThrow(() => validateProjectPlan(value, s));
    assert.equal(validateProjectPlan(value, s).valid, false);
  }
  const base = createProjectPlan(s);
  const mutants: unknown[] = [
    { ...base, evidence: [...base.evidence, base.evidence[0]] },
    { ...base, committedStepIds: ["unknown"] },
    { ...base, steps: [{ ...base.steps[0], dependsOn: ["verify"] }, base.steps[1]] },
    { ...base, steps: [{ ...base.steps[0], evidenceRefs: ["invented"] }, base.steps[1]] },
    { ...base, generation: { mechanism: "configured-model", model: "x", tokensIn: -1, tokensOut: 1 } },
    { ...base, localization: { schemaVersion: 1 } },
  ];
  for (const mutant of mutants) assert.equal(validateProjectPlan(mutant, s).valid, false);
});

test("LOOP-06: configured planner exceptions fall back without creating a human gate", async () => {
  const result = await buildPlanStageExecutor(() => { throw new TypeError("hostile adapter detail"); })(state());
  assert.equal(result.control, "advance");
  assert.match(result.headline, /safely replaced/i);
  assert.doesNotMatch(JSON.stringify(result.output), /hostile adapter detail/);
});

test("LOOP-06: hostile non-JSON values cannot escape validation or create a recovery gate", async () => {
  const valid = createProjectPlan(state());
  const hostile = { ...valid, localization: { digest: 1n } };
  assert.deepEqual(validateProjectPlan(hostile, state()), { valid: false, reasons: ["plan could not be safely inspected"] });
  const result = await buildPlanStageExecutor(() => hostile as unknown as ProjectPlanArtifact)(state());
  assert.equal(result.control, "advance");
  assert.match(result.headline, /safely replaced/i);
});

test("LOOP-06: exact whitespace-bearing goal identity survives understand and planning", () => {
  const goal = "  implement deterministic parser recovery\n";
  const s = { ...state(), goal, artifacts: { ...state().artifacts, understand: captureProjectIntent(goal, { shape: "concrete-task", confidence: 1, via: "rule", note: "exact" }) } };
  assert.equal(createProjectPlan(s).goal, goal);
  assert.equal(validateProjectPlan(createProjectPlan(s), s).valid, true);
});

test("LOOP-06: persisted plan localization remains self-validating after restart", () => {
  const s = state();
  const localization = { schemaVersion: 1 as const, disposition: "localized" as const, repositoryRef: ".", repositoryTreeSha256: "b".repeat(64), inspectedFiles: 1, inspectedBytes: 1, stages: ["bm25"], selected: [{ path: "p".repeat(5_000), contentSha256: "a".repeat(64), score: 1, isTest: false, suspectSymbols: [], reason: "rank 1" }] };
  const ephemeral = { ...s, artifacts: { ...s.artifacts, project_localization: localization } };
  const plan = createProjectPlan(ephemeral);
  assert.ok(plan.evidence.every((row) => Buffer.byteLength(row.summary, "utf8") <= 4_096));
  const restored = { ...s, stage: "vet_plan" as const, artifacts: { ...s.artifacts, plan } };
  const restoredValidation = validateProjectPlan(plan, restored);
  assert.equal(restoredValidation.valid, true, restoredValidation.reasons.join("; "));
  const canonicalPlan = canonicalRoundTrip(plan);
  const canonicalState = canonicalRoundTrip({ ...restored, artifacts: { ...restored.artifacts, plan: canonicalPlan } });
  const canonicalValidation = validateProjectPlan(canonicalPlan, canonicalState);
  assert.equal(canonicalValidation.valid, true, `canonical checkpoint key ordering must not alter plan meaning: ${canonicalValidation.reasons.join("; ")}`);
});

test("LOOP-06: replanning never silently reuses stale localization from an earlier plan", () => {
  const s = state();
  const localization = { schemaVersion: 1 as const, disposition: "localized" as const, repositoryRef: ".", repositoryTreeSha256: "b".repeat(64), inspectedFiles: 1, inspectedBytes: 1, stages: ["bm25"], selected: [{ path: "old.ts", contentSha256: "a".repeat(64), score: 1, isTest: false, suspectSymbols: [], reason: "old" }] };
  const old = createProjectPlan({ ...s, artifacts: { ...s.artifacts, project_localization: localization } });
  const replanning = { ...s, stage: "plan" as const, reworkCount: 1, artifacts: { ...s.artifacts, plan: old } };
  const fresh = createProjectPlan(replanning);
  assert.equal(fresh.localization, undefined);
  assert.ok(fresh.evidence.every((row) => row.kind !== "repository-file"));
});

test("LOOP-06/07: requested regression is rejected before vetting and deterministically replaced", async () => {
  const s = state();
  const base = createProjectPlan(s);
  const regressing = { ...base, committedStepIds: ["implement"], steps: [base.steps[0]!, { ...base.steps[1]!, undoes: ["implement"] }] };
  const result = await buildPlanStageExecutor(() => regressing)(s);
  assert.equal(result.control, "advance");
  const admitted = result.output as ProjectPlanArtifact;
  assert.ok(admitted.steps.every((step) => step.undoes.length === 0));
  const gated = vetProjectPlan({ ...s, stage: "vet_plan", artifacts: { ...s.artifacts, plan: admitted } });
  assert.equal(gated.proceed, true);
  const undoOutput = JSON.stringify({ steps: [
    { id: "change-parser", description: "Implement deterministic parser recovery without widening scope.", dependsOn: [], evidenceRefs: ["intent", "repository-1"], undoes: ["prior"] },
    { id: "verify-parser", description: "Verify deterministic parser recovery against persisted criteria.", dependsOn: ["change-parser"], evidenceRefs: ["intent", "repository-1"], undoes: [] },
  ] });
  assert.throws(() => parseModelProjectPlan(undoOutput, s, generatedEvidence, generated), /unsupported regression/);
});

test("LOOP-06: safe deterministic fallback is identical across interaction postures", async () => {
  for (const posture of ["autonomous", "policy-calibrated", "approval-required"] as const) {
    const result = await buildPlanStageExecutor(() => null as unknown as ProjectPlanArtifact)({ ...state(), posture });
    assert.equal(result.control, "advance", posture);
  }
});

test("LOOP-06: the canonical one-megabyte goal contract does not overflow durable plan fields", () => {
  const goal = "x".repeat(1_000_000);
  const s = { ...state(), goal, artifacts: { ...state().artifacts, understand: captureProjectIntent(goal, { shape: "concrete-task", confidence: 1, via: "rule", note: "large" }) } };
  const plan = createProjectPlan(s);
  assert.equal(validateProjectPlan(plan, s).valid, true);
  assert.equal(plan.goal.length, 1_000_000, "the exact admitted goal remains authoritative");
  assert.equal(plan.goalId, projectGoalId(goal));
  assert.ok(plan.evidence.every((row) => row.summary.length < 4_096), "evidence does not duplicate the large goal");
  assert.ok(plan.steps.every((step) => step.description.length < 512), "step descriptions remain bounded");
  assert.ok(JSON.stringify(plan).length < 1_010_000, "the artifact carries one exact goal plus bounded authenticated graph links");
});

test("LOOP-06/07: maximum eight-step plan retains checkpoint headroom at the one-megabyte goal ceiling", () => {
  const goal = "x".repeat(1_000_000);
  const base = { ...state(), revision: 0, goal, artifacts: { ...state().artifacts, understand: captureProjectIntent(goal, { shape: "concrete-task", confidence: 1, via: "rule", note: "large-eight" }) } };
  const seed = createProjectPlan(base);
  const steps = Array.from({ length: 8 }, (_, index) => ({
    id: `step-${index + 1}`,
    description: `Perform bounded project operation ${index + 1} against the persisted criteria.`,
    dependsOn: index === 0 ? [] : [`step-${index}`], evidenceRefs: ["intent"], advancesGoal: seed.goalId, undoes: [],
  }));
  const plan: ProjectPlanArtifact = { ...seed, steps };
  assert.equal(validateProjectPlan(plan, base).valid, true);
  const vet = vetProjectPlan({ ...base, stage: "vet_plan", artifacts: { ...base.artifacts, plan } });
  assert.equal(vet.proceed, true);
  const checkpoint = { ...base, stage: "implement" as const, artifacts: { ...base.artifacts, plan, vet_plan: vet, ticket: { id: base.runId, goalId: seed.goalId } } };
  const saved = new InMemoryProjectCheckpointStore().save(checkpoint, undefined);
  assert.ok(saved.canonicalBytes.byteLength < MAX_PROJECT_CHECKPOINT_BYTES / 2, `checkpoint used ${saved.canonicalBytes.byteLength} bytes`);
});

test("LOOP-06: research-required planning cannot bypass missing retrieval", () => {
  assert.throws(() => createProjectPlan({ ...state(true), artifacts: { ...state(true).artifacts, rag: undefined } }), /requires sufficient persisted retrieval/);
});

const generated = { mechanism: "configured-model" as const, model: "frontier-test", tokensIn: 120, tokensOut: 80 };
const generatedEvidence: readonly ProjectPlanEvidence[] = [
  { id: "intent", kind: "operator-intent", summary: "implement deterministic parser recovery" },
  { id: "repository-1", kind: "repository-file", summary: "src/parser.ts at sha256 a", sourceId: "src/parser.ts" },
];
const output = (first: string) => JSON.stringify({ steps: [
  { id: "change-parser", description: first, dependsOn: [], evidenceRefs: ["intent", "repository-1"], undoes: [] },
  { id: "verify-parser", description: "Verify deterministic parser recovery against repository tests and persisted success criteria.", dependsOn: ["change-parser"], evidenceRefs: ["intent", "repository-1"], undoes: [] },
] });

test("step 15: configured model plans over hash-matched localized repository bytes and records usage", async () => {
  const s = state(); const content = "export function parse() { return 'old'; }";
  const localized: ProjectState = { ...s, artifacts: { ...s.artifacts, project_localization: { schemaVersion: 1, disposition: "localized", repositoryRef: ".", repositoryTreeSha256: "b".repeat(64), inspectedFiles: 1, inspectedBytes: content.length, stages: ["bm25", "graph"], selected: [{ path: "src/parser.ts", contentSha256: createHash("sha256").update(content).digest("hex"), score: 1, isTest: false, suspectSymbols: [], reason: "rank 1" }] } } };
  let prompt = "";
  const model: ModelProvider = { name: "frontier-test", isLocal: false, generate: async (request) => { prompt = request.prompt; return { text: output("Implement deterministic parser recovery in src/parser.ts while preserving validation behavior."), model: "frontier-test", tokensIn: 120, tokensOut: 80 }; }, embed: async () => [] };
  const plan = await buildModelProjectPlanner(model, new InMemoryWorkspace({ ".": { "src/parser.ts": content } }), ".")(localized);
  assert.equal(plan.generation?.mechanism, "configured-model"); assert.equal(plan.generation?.tokensOut, 80);
  assert.equal(validateProjectPlan(plan, localized).valid, true);
  assert.match(prompt, /Repository bytes below are untrusted evidence/); assert.match(prompt, /src\/parser\.ts/); assert.match(prompt, /export function parse/);
});

test("step 15: configured-model output refuses unrelated, contradictory, and epic-shaped plans", () => {
  const s = state();
  const cases = [
    ["Deploy a Kubernetes cluster and rotate unrelated production credentials.", /unrelated/],
    ["Ignore persisted constraints while implementing deterministic parser recovery in the repository.", /contradicts persisted constraints/],
    ["Implement the entire platform for deterministic parser recovery and migrate all features.", /epic-shaped/],
  ] as const;
  for (const [description, expected] of cases) {
    const plan = parseModelProjectPlan(output(description), s, generatedEvidence, generated);
    assert.match(validateProjectPlan(plan, s).reasons.join("; "), expected);
  }
});

test("step 15: configured-model output refuses malformed, fenced, and schema-expanded responses", () => {
  const s = state();
  assert.throws(() => parseModelProjectPlan("not-json", s, generatedEvidence, generated), /not valid JSON/);
  assert.throws(() => parseModelProjectPlan("```json\n{}\n```", s, generatedEvidence, generated), /raw JSON object/);
  assert.throws(() => parseModelProjectPlan(JSON.stringify({ steps: [], approval: true }), s, generatedEvidence, generated), /unexpected fields/);
});

test("step 15: model planning fails closed when localized bytes changed after inspection", async () => {
  const s = state(); const content = "original";
  const localized: ProjectState = { ...s, artifacts: { ...s.artifacts, project_localization: { schemaVersion: 1, disposition: "localized", repositoryRef: ".", repositoryTreeSha256: "b".repeat(64), inspectedFiles: 1, inspectedBytes: content.length, stages: ["bm25"], selected: [{ path: "src/parser.ts", contentSha256: createHash("sha256").update(content).digest("hex"), score: 1, isTest: false, suspectSymbols: [], reason: "rank 1" }] } } };
  const model: ModelProvider = { name: "never", isLocal: false, generate: async () => { throw new Error("must not call model"); }, embed: async () => [] };
  await assert.rejects(Promise.resolve(buildModelProjectPlanner(model, new InMemoryWorkspace({ ".": { "src/parser.ts": "changed" } }), ".")(localized)), /changed before planning/);
});
