import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { RollbackLedger } from "../src/control/rollback.js";

import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import { InMemoryFileTree } from "../src/solve/patch.js";
import { HierarchicalLocalizer, type RepoFile } from "../src/solve/localize.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";
import { SolvePipeline } from "../src/solve/solve_pipeline.js";
import { makeSolveStageExecutors } from "../src/solve/project_loop_wiring.js";
import { PROJECT_STATE_SCHEMA_VERSION, type ProjectState } from "../src/autonomy/project_state.js";
import type { Issue } from "../src/solve/issue_model.js";
import { captureProjectIntent } from "../src/autonomy/understand_stage.js";
import { createProjectPlan } from "../src/autonomy/plan_stage.js";
import { vetProjectPlan } from "../src/autonomy/plan_gate_stage.js";
import { decomposeProjectPlan } from "../src/autonomy/decomposition_stage.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-solve-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

/** A model that returns a canned edit plan JSON (stands in for the replay provider). */
class PlanModel implements ModelProvider {
  readonly name = "plan-model";
  readonly isLocal = true;
  constructor(private readonly planJson: string) {}
  async generate(_req: GenerateRequest): Promise<GenerateResult> { return { text: this.planJson, model: this.name, tokensIn: 1, tokensOut: 1 }; }
  async embed(_t: readonly string[]): Promise<Embedding[]> { return []; }
}

const issue: Issue = { id: "BUG-1", text: "add() returns the wrong value; it subtracts instead of adds in calc.ts", repoRef: "repo" };
const files: RepoFile[] = [
  { path: "src/calc.ts", content: "export function add(a, b) { return a - b; }" },
  { path: "src/util.ts", content: "export function noop() {}" },
];

function implementationState(goal = "fix BUG-1"): ProjectState {
  const base: ProjectState = { schemaVersion: PROJECT_STATE_SCHEMA_VERSION, revision: 0, runId: "r", goal, stage: "plan", artifacts: { understand: captureProjectIntent(goal, { shape: "concrete-task", confidence: 1, via: "rule", note: "test" }), research: { decision: { required: false } } }, posture: "autonomous", stepsRemaining: 10, reworkCount: 0, status: "running", retry: { attemptsByStage: {}, attemptsConsumed: 0, runLimit: 8 }, consumedSignals: [] };
  const plan = createProjectPlan(base);
  const planned = { ...base, stage: "vet_plan" as const, artifacts: { ...base.artifacts, plan } };
  const vetted = { ...planned, stage: "ticket" as const, artifacts: { ...planned.artifacts, vet_plan: vetProjectPlan(planned) } };
  return { ...vetted, stage: "implement", artifacts: { ...vetted.artifacts, ticket: decomposeProjectPlan(vetted) } };
}

test("project wiring retains recovery debt and forwards only matching consumed reconciliation", async () => {
  const spine = newSpine();
  const contexts: import("../src/solve/issue_model.js").SolveExecutionContext[] = [];
  const recovery = { status: "reconciliation" as const, attempts: 1, maxAttempts: 4, planningCalls: 1, maxPlanningCalls: 16, planningInputBytes: 100, maxPlanningInputBytes: 1_048_576, deadline: Date.now() + 60_000, pendingAttemptId: "pending-attempt", reason: "ambiguous test process" };
  const execs = makeSolveStageExecutors({ spine, resolve: () => ({ issue, files }), pipeline: { run: async (_issue, _files, context = {}) => {
    contexts.push(context);
    return { issueId: issue.id, solved: false, stagesRun: [], repairRounds: 0, recovery };
  } } });
  const base = implementationState();
  const first = await execs.implement!(base);
  assert.equal(first.control, "reconciliation-required");
  const persisted = { ...base, artifacts: { ...base.artifacts, implement: first.output } };
  await execs.implement!({ ...persisted, consumedSignals: ["reconciliation:wrong:observed"] });
  assert.equal(contexts[1]!.recoveryReconciliation, undefined);
  await execs.implement!({ ...persisted, consumedSignals: [`reconciliation:${first.effectId}:trusted-quiescent-observation`] });
  assert.equal(contexts[2]!.recoveryOperationId, base.runId);
  assert.deepEqual(contexts[2]!.recoveryReconciliation, { attemptId: "pending-attempt", evidenceId: "trusted-quiescent-observation" });
});

test("project wiring never advances exhausted evidence or converts a diagnosis into owner approval", async () => {
  for (const status of ["exhausted", "diagnosis", "authority"] as const) {
    const spine = newSpine();
    const execs = makeSolveStageExecutors({ spine, resolve: () => ({ issue, files }), pipeline: { run: async () => ({
      issueId: issue.id, solved: false, stagesRun: [], repairRounds: 0,
      recovery: { status, attempts: 4, maxAttempts: 4, planningCalls: 4, maxPlanningCalls: 16, planningInputBytes: 400, maxPlanningInputBytes: 1_048_576, deadline: 100, ...(status === "diagnosis" ? { diagnosisId: "diagnosed-hold" } : {}) },
    }) } });
    const result = await execs.implement!(implementationState());
    assert.equal(result.control, "capability-unavailable");
    assert.equal(result.resumeAuthority, status === "authority" ? "approval" : undefined);
    if (status === "diagnosis") assert.match(result.capability!, /diagnosed-hold/);
  }
});

/** A runner whose pass/fail depends on the current calc.ts content (so the patch actually changes it). */
function calcRunner(tree: InMemoryFileTree): TestRunner {
  return {
    async run(): Promise<TestRunResult> {
      const content = (await tree.read("src/calc.ts")) ?? "";
      const correct = content.includes("a + b");
      return { results: [{ name: "add(2,3)==5", passed: correct, ...(correct ? {} : { output: "expected 5, got -1" }) }] };
    },
  };
}

test("INVARIANT: the machine runs end-to-end — localize→plan→apply→validate→done, proposes a PR (never merges)", async () => {
  const spine = newSpine();
  const tree = new InMemoryFileTree(Object.fromEntries(files.map((f) => [f.path, f.content])));
  const model = new PlanModel(JSON.stringify({
    rationale: "the operator was inverted",
    edits: [{ file: "src/calc.ts", search: "return a - b;", replace: "return a + b;", intent: "use + not -" }],
  }));
  const pipeline = new SolvePipeline({
    spine, ledger: new RollbackLedger(spine), tree, runner: calcRunner(tree),
    localizer: new HierarchicalLocalizer(), model,
  });
  const result = await pipeline.run(issue, files);

  assert.equal(result.solved, true, "the planted bug was fixed");
  assert.deepEqual(result.stagesRun, ["localize", "plan", "apply", "validate", "done"]);
  assert.ok(result.prProposal, "a PR proposal was produced");
  assert.equal(result.prProposal!.testsPassed, true);
  assert.match(result.prProposal!.body, /awaiting human review and will not be merged automatically/i);
  assert.equal(await tree.read("src/calc.ts"), "export function add(a, b) { return a + b; }", "the fix is in the tree");
});

test("INVARIANT: the PR proposal is a human-review manifest (names issue + files)", async () => {
  const spine = newSpine();
  const tree = new InMemoryFileTree(Object.fromEntries(files.map((f) => [f.path, f.content])));
  const model = new PlanModel(JSON.stringify({ rationale: "fix", edits: [{ file: "src/calc.ts", search: "return a - b;", replace: "return a + b;", intent: "fix" }] }));
  const pipeline = new SolvePipeline({ spine, ledger: new RollbackLedger(spine), tree, runner: calcRunner(tree), localizer: new HierarchicalLocalizer(), model });
  const result = await pipeline.run(issue, files);
  assert.match(result.prProposal!.body, /BUG-1/);
  assert.match(result.prProposal!.body, /src\/calc\.ts/);
  assert.equal(result.prProposal!.branch, "keep/solve/BUG-1");
});

test("INVARIANT: gives up gracefully when localization finds nothing", async () => {
  const spine = newSpine();
  const tree = new InMemoryFileTree({});
  const model = new PlanModel("{}");
  const pipeline = new SolvePipeline({ spine, ledger: new RollbackLedger(spine), tree, runner: calcRunner(tree), localizer: new HierarchicalLocalizer(), model });
  const result = await pipeline.run({ id: "X", text: "zzz", repoRef: "r" }, []);
  assert.equal(result.solved, false);
  assert.ok(result.stagesRun.includes("gave-up"));
});

test("INVARIANT: gives up when the model produces no usable edit plan", async () => {
  const spine = newSpine();
  const tree = new InMemoryFileTree(Object.fromEntries(files.map((f) => [f.path, f.content])));
  const model = new PlanModel("no json here, model failed");
  const pipeline = new SolvePipeline({ spine, ledger: new RollbackLedger(spine), tree, runner: calcRunner(tree), localizer: new HierarchicalLocalizer(), model });
  const result = await pipeline.run(issue, files);
  assert.equal(result.solved, false);
  assert.match(result.gaveUpReason ?? "", /no edits/);
});

test("INVARIANT: a case needing repair goes through the repair stage and still proposes a PR", async () => {
  const spine = newSpine();
  const tree = new InMemoryFileTree(Object.fromEntries(files.map((f) => [f.path, f.content])));
  // First plan is a near-miss (applies but doesn't fix); repair re-plan (same model) gives the real fix.
  let call = 0;
  const model: ModelProvider = {
    name: "two-shot", isLocal: true,
    async generate(): Promise<GenerateResult> {
      call++;
      const json = call === 1
        ? JSON.stringify({ rationale: "attempt", edits: [{ file: "src/calc.ts", search: "return a - b;", replace: "return a * b;", intent: "wrong: multiply" }] })
        : JSON.stringify({ rationale: "real fix", edits: [{ file: "src/calc.ts", search: "return a * b;", replace: "return a + b;", intent: "use +" }] });
      return { text: json, model: "two-shot", tokensIn: 1, tokensOut: 1 };
    },
    async embed(): Promise<Embedding[]> { return []; },
  };
  const pipeline = new SolvePipeline({ spine, ledger: new RollbackLedger(spine), tree, runner: calcRunner(tree), localizer: new HierarchicalLocalizer(), model }, { maxRepairRounds: 2 });
  const result = await pipeline.run(issue, files);
  assert.ok(result.stagesRun.includes("repair"), "repair stage ran");
  assert.equal(result.solved, true, "repair produced a passing fix");
  assert.equal(result.repairRounds >= 1, true);
  assert.equal(result.prProposal?.edits.length, 2, "governance receives both the initial and retained repair effects");
  assert.ok(result.prProposal?.edits.some((edit) => edit.replace.includes("a + b")), "the repair bytes are present in the PR evidence");
});

// ── ProjectLoop wiring ───────────────────────────────────────────────────────

test("INVARIANT: ProjectLoop wiring — implement solves, vet_artifact advances, learn records outcome", async () => {
  const spine = newSpine();
  const tree = new InMemoryFileTree(Object.fromEntries(files.map((f) => [f.path, f.content])));
  const model = new PlanModel(JSON.stringify({ rationale: "fix", edits: [{ file: "src/calc.ts", search: "return a - b;", replace: "return a + b;", intent: "fix" }] }));
  const pipeline = new SolvePipeline({ spine, ledger: new RollbackLedger(spine), tree, runner: calcRunner(tree), localizer: new HierarchicalLocalizer(), model });
  const execs = makeSolveStageExecutors({ pipeline, spine, resolve: () => ({ issue, files }) });

  const base = implementationState();
  const impl = await execs.implement!(base);
  assert.equal(impl.control, "advance");
  const afterImpl = { ...base, artifacts: { ...base.artifacts, implement: impl.output } };

  const vet = await execs.vet_artifact!(afterImpl);
  assert.equal(vet.control, "advance", `passing solve advances: ${JSON.stringify(vet)}`);

  const learn = await execs.learn!(afterImpl);
  assert.equal(learn.control, "advance");
  await spine.seal();
  const events = spine.replay().map((e) => (e.payload as Record<string, unknown>)["event"]).filter(Boolean);
  assert.ok(events.includes("build_outcome_recorded") || spine.replay().some((e) => JSON.stringify(e.payload).includes("BUG-1")), "build outcome recorded to the spine");
});

test("project-loop independent verification distinguishes product failure from missing isolation capability", async () => {
  for (const scenario of ["failure", "unavailable"] as const) {
    const spine = newSpine();
    const tree = new InMemoryFileTree(Object.fromEntries(files.map((f) => [f.path, f.content])));
    const snapshotFiles = async (): Promise<readonly RepoFile[]> => Promise.all(files.map(async (file) => ({ path: file.path, content: (await tree.read(file.path))! })));
    const model = new PlanModel(JSON.stringify({ rationale: "fix", edits: [{ file: "src/calc.ts", search: "return a - b;", replace: "return a + b;", intent: "fix" }] }));
    const pipeline = new SolvePipeline({ spine, ledger: new RollbackLedger(spine), tree, runner: calcRunner(tree), localizer: new HierarchicalLocalizer(), model });
    let independentCalls = 0;
    const requiredTier = scenario === "unavailable" ? "microvm" as const : "process" as const;
    const projectTester = { async run() {
      independentCalls += scenario === "failure" ? 1 : 0;
      return {
        schemaVersion: 1 as const, issueId: issue.id, taskId: "task-1", planStepId: "step-1",
        implementationSha256: "a".repeat(64), repositoryTreeSha256: "b".repeat(64), repositoryExecutionManifestSha256: "c".repeat(64), command: { executable: "node", args: ["--test"] },
        verdict: scenario === "failure" ? "failed" as const : "unavailable" as const, passed: false, isolation: { selectedTier: "process" as const, requiredTier, requirementMet: scenario === "failure", attempted: scenario === "failure", executed: scenario === "failure" },
        testsExecuted: scenario === "failure", testsPassed: false, discovered: scenario === "failure" ? 1 : 0, passedCount: 0,
        failures: scenario === "failure" ? [{ name: "independent", output: "held-out regression" }] : [],
        failureOutput: scenario === "failure" ? "held-out regression" : "", ...(scenario === "unavailable" ? { runnerError: "microvm unavailable" } : {}),
        reasons: scenario === "failure" ? ["TEST FAILED: independent\nheld-out regression"] : ["test verification unavailable: microvm unavailable"],
      };
    } };
    const execs = makeSolveStageExecutors({ pipeline, spine, resolve: () => ({ issue, files }), projectTester, snapshotFiles: () => snapshotFiles(), snapshotExecutionManifest: async () => "c".repeat(64) });
    const base = implementationState();
    const impl = await execs.implement!(base);
    const vet = await execs.vet_artifact!({ ...base, artifacts: { ...base.artifacts, implement: impl.output } });
    if (scenario === "failure") {
      assert.equal(vet.control, "rework");
      assert.equal(vet.reworkTo, "implement");
      assert.equal(independentCalls, 1);
      assert.match(vet.detail ?? "", /held-out regression/);
    } else {
      assert.equal(vet.control, "capability-unavailable");
      assert.equal(vet.capability, "project-test-isolation:microvm");
      assert.equal(independentCalls, 0, "a missing required tier never executes weakly");
    }
  }
});

test("independent failure reasons reach the next bounded autonomous repair attempt", async () => {
  const spine = newSpine();
  const seen: Issue[] = [];
  const pipeline = { async run(nextIssue: Issue) {
    seen.push(nextIssue);
    return { issueId: nextIssue.id, solved: false, stagesRun: ["validate"] as const, repairRounds: 0,
      validation: { testsPassed: false, vettingCleared: true, failures: [], detail: "not repaired yet" }, gaveUpReason: "not repaired yet" };
  } };
  const execs = makeSolveStageExecutors({ pipeline, spine, resolve: () => ({ issue, files }) });
  const base = implementationState();
  const failedVet = { schemaVersion: 1, verdict: "failed", passed: false,
    reasons: ["TEST FAILED: independent\nheld-out regression"] };
  await execs.implement!({ ...base, artifacts: { ...base.artifacts, vet_artifact: failedVet } });
  assert.equal(seen.length, 1);
  assert.match(seen[0]!.text, /Repair only these verified failures/);
  assert.match(seen[0]!.text, /held-out regression/);
});

test("governance abandon guidance reaches the next bounded autonomous retry", async () => {
  const spine = newSpine();
  let received: Issue | undefined;
  const execs = makeSolveStageExecutors({
    pipeline: { async run(nextIssue) { received = nextIssue; return { issueId: nextIssue.id, solved: false, stagesRun: [], repairRounds: 0 }; } },
    spine,
    resolve: () => ({ issue, files }),
  });
  const base = implementationState();
  await execs.implement!({ ...base, artifacts: { ...base.artifacts, implement: { retryGuidance: "patch-verifier: added continue changes control flow" } } });
  assert.match(received?.text ?? "", /Repair only these verified failures/u);
  assert.match(received?.text ?? "", /added continue changes control flow/u);
});

test("learning records independently verified success as clean-resolved", async () => {
  const spine = newSpine();
  const execs = makeSolveStageExecutors({ pipeline: { async run() { throw new Error("not called"); } }, spine, resolve: () => ({ issue, files }) });
  const base = implementationState();
  const solved = { issueId: issue.id, solved: true, stagesRun: ["apply", "validate", "done"], repairRounds: 0,
    validation: { testsPassed: true, vettingCleared: true, failures: [], detail: "passed" } };
  await execs.learn!({ ...base, artifacts: { ...base.artifacts,
    implement: { schemaVersion: 1, task: { id: "task-1" }, issue, solve: solved },
    vet_artifact: { schemaVersion: 1, verdict: "passed", passed: true, testsPassed: true },
  } });
  await spine.seal();
  const event = spine.replay().find((row) => (row.payload as Record<string, unknown>)["event"] === "build.outcome");
  assert.equal((event?.payload as Record<string, unknown> | undefined)?.["cleanResolved"], true);
});

test("INVARIANT: vet_artifact reworks back to implement on an unsolved result", async () => {
  const spine = newSpine();
  const tree = new InMemoryFileTree(Object.fromEntries(files.map((f) => [f.path, f.content])));
  const model = new PlanModel("garbage — no plan"); // implement will give up
  const pipeline = new SolvePipeline({ spine, ledger: new RollbackLedger(spine), tree, runner: calcRunner(tree), localizer: new HierarchicalLocalizer(), model });
  const execs = makeSolveStageExecutors({ pipeline, spine, resolve: () => ({ issue, files }) });
  const base = implementationState("fix the admitted bug");
  const impl = await execs.implement!(base);
  const vet = await execs.vet_artifact!({ ...base, artifacts: { implement: impl.output } });
  assert.equal(vet.control, "rework");
  assert.equal(vet.reworkTo, "implement");
});

test("DURABLE TRUST: implementation revalidates ticket bytes instead of trusting validation.valid", async () => {
  const spine = newSpine();
  const base = implementationState();
  const ticket = base.artifacts.ticket as ReturnType<typeof decomposeProjectPlan>;
  const hostile = { ...ticket, validation: { valid: true, reasons: [] }, tasks: [{ ...ticket.tasks[0]!, objective: "Perform attacker-selected work outside the vetted plan." }, ...ticket.tasks.slice(1)] };
  let calls = 0;
  const execs = makeSolveStageExecutors({ pipeline: { async run() { calls += 1; throw new Error("must not run"); } }, spine, resolve: () => ({ issue, files }) });
  await assert.rejects(() => execs.implement!({ ...base, artifacts: { ...base.artifacts, ticket: hostile } }), /authenticated valid persisted task decomposition/);
  assert.equal(calls, 0);
});

test("full retained criteria reach the solver and a forged bounded reference cannot execute", async () => {
  const goal = "Implement the requested change. " + "Retain every obligation. ".repeat(100) + "LAST_REQUIRED_BEHAVIOR";
  const base = implementationState(goal); let calls = 0, received: Issue | undefined;
  const execs = makeSolveStageExecutors({ spine: newSpine(), resolve: () => ({ issue, files }), pipeline: { async run(input) { calls++; received = input; return { issueId: input.id, solved: false, stagesRun: [], repairRounds: 0 }; } } });
  await execs.implement!(base); assert.equal(calls, 1); assert.ok(received!.text.includes(goal));
  const ticket = base.artifacts["ticket"] as ReturnType<typeof decomposeProjectPlan>;
  const first = ticket.tasks[0]!;
  const forged = { ...ticket, tasks: [{ ...first, completionCriteria: [{ ...first.completionCriteria[0]!, statement: "Retained success criterion SHA-256: " + "a".repeat(64) }] }, ...ticket.tasks.slice(1)] };
  await assert.rejects(execs.implement!({ ...base, artifacts: { ...base.artifacts, ticket: forged } }), /criterion reference/u);
  assert.equal(calls, 1);
});

test("a custom solve cannot forge admission consumption by opting in and echoing the proposal", async () => {
  const spine = newSpine();
  const base = implementationState();
  const ticket = base.artifacts.ticket as ReturnType<typeof decomposeProjectPlan>;
  const task = ticket.tasks.find((row) => row.id === ticket.admittedTaskId)!;
  const admittedEdit = {
    schemaVersion: 1 as const, mechanism: "project-edit-stage" as const, repositoryRef: issue.repoRef,
    repositoryTreeSha256: "a".repeat(64), allowedFiles: ["src/calc.ts"], allowedFileSha256: { "src/calc.ts": "b".repeat(64) },
    taskId: task.id, planStepId: task.planStepId, generation: { model: "test", tokensIn: 1, tokensOut: 1 },
    plan: { rationale: "test", edits: [{ file: "src/calc.ts", search: "a", replace: "b", intent: "test" }] },
  };
  const execs = makeSolveStageExecutors({
    spine, resolve: () => ({ issue, files }),
    canFinishTestedProposal: () => true,
    projectEditor: { async prepare() { return admittedEdit; } },
    pipeline: { consumesAdmittedEdit: true, async run(input, _files, context) { return { issueId: input.id, solved: true, stagesRun: ["done"], repairRounds: 0, validation: { testsPassed: true, vettingCleared: true, failures: [], detail: "claimed" }, admittedEdit: context!.admittedEdit! }; } },
  });
  await assert.rejects(execs.implement!(base), /without a canonical pipeline effect attestation/);
});

test("proposal-only host permission does not waive human merge for an unproven custom solve", async () => {
  const execs = makeSolveStageExecutors({ spine: newSpine(), resolve: () => ({ issue, files }),
    canFinishTestedProposal: () => true,
    pipeline: { async run(input) { return {
      solveResult: { issueId: input.id, solved: true, stagesRun: ["done"], repairRounds: 0,
        validation: { testsPassed: true, vettingCleared: true, failures: [], detail: "claimed" } },
      mergeAuthority: { verdict: "human-merge", verified: true, consequential: true, reason: "sensitive path" },
    }; } },
  });
  const result = await execs.implement!(implementationState());
  assert.equal(result.control, "approval-required");
});

test("SCOPE FIDELITY: one atomic solve receives every objective in a configured multi-step DAG", async () => {
  const spine = newSpine();
  const seedState = implementationState("repair parser recovery behavior");
  const seed = seedState.artifacts.plan as ReturnType<typeof createProjectPlan>;
  const descriptions = [
    "Inspect parser recovery behavior and preserve the admitted issue constraints.",
    "Implement bounded parser recovery using the admitted repository evidence.",
    "Exercise hostile parser recovery cases without changing unrelated behavior.",
    "Verify parser recovery against every persisted completion criterion.",
  ];
  const steps = descriptions.map((description, index) => ({ id: `step-${index + 1}`, description, dependsOn: index === 0 ? [] : [`step-${index}`], evidenceRefs: ["intent"], advancesGoal: seed.goalId, undoes: [] }));
  const plan = { ...seed, steps };
  const planned = { ...seedState, stage: "vet_plan" as const, artifacts: { ...seedState.artifacts, plan } };
  const vetted = { ...planned, stage: "ticket" as const, artifacts: { ...planned.artifacts, vet_plan: vetProjectPlan(planned) } };
  const base = { ...vetted, stage: "implement" as const, artifacts: { ...vetted.artifacts, ticket: decomposeProjectPlan(vetted) } };
  let received: Issue | undefined;
  const execs = makeSolveStageExecutors({ pipeline: { async run(input) { received = input; return { issueId: input.id, solved: true, stagesRun: ["done"], repairRounds: 0, validation: { testsPassed: true, vettingCleared: true, failures: [], detail: "verified" } }; } }, spine, resolve: () => ({ issue, files }) });
  const result = await execs.implement!(base);
  assert.equal(result.control, "advance");
  for (const description of descriptions) assert.ok(received?.text.includes(description), description);
});

// ── LogicVet pre-apply gate (wired 2026-08-06) ───────────────────────────────

test("INVARIANT: logic-vet blocks a forbidden edit BEFORE it touches the tree (fail-closed pre-apply gate)", async () => {
  const spine = newSpine();
  const tree = new InMemoryFileTree(Object.fromEntries(files.map((f) => [f.path, f.content])));
  const original = await tree.read("src/calc.ts");
  const model = new PlanModel(JSON.stringify({
    rationale: "cleanup",
    edits: [{ file: "src/calc.ts", search: "return a - b;", replace: "DROP TABLE users; return a + b;", intent: "drop the users table" }],
  }));
  const pipeline = new SolvePipeline({
    spine, ledger: new RollbackLedger(spine), tree, runner: calcRunner(tree),
    localizer: new HierarchicalLocalizer(), model,
  }, { forbiddenActions: ["drop table"] });
  const result = await pipeline.run(issue, files);
  assert.equal(result.solved, false, "the forbidden plan was not solved");
  assert.match(result.gaveUpReason ?? "", /logic-vet blocked/i);
  assert.ok(!result.stagesRun.includes("apply"), "blocked BEFORE the apply stage");
  assert.equal(await tree.read("src/calc.ts"), original, "the tree was never touched — fail-closed");
});

test("the pre-apply logic-vet gate runs on every solve and is audited (not skipped)", async () => {
  const spine = newSpine();
  const tree = new InMemoryFileTree(Object.fromEntries(files.map((f) => [f.path, f.content])));
  const model = new PlanModel(JSON.stringify({
    rationale: "the operator was inverted",
    edits: [{ file: "src/calc.ts", search: "return a - b;", replace: "return a + b;", intent: "use + not -" }],
  }));
  const pipeline = new SolvePipeline({
    spine, ledger: new RollbackLedger(spine), tree, runner: calcRunner(tree),
    localizer: new HierarchicalLocalizer(), model,
  });
  const result = await pipeline.run(issue, files);
  assert.equal(result.solved, true, "a clean plan passes the gate and applies");
  const planEvt = spine.currentEvents().find((e) => {
    const p = e.payload as Record<string, unknown>;
    return p["stage"] === "plan" && "logicVet" in p;
  });
  assert.ok(planEvt, "a plan-stage logic-vet audit event was emitted (the gate ran)");
  assert.equal((planEvt!.payload as Record<string, unknown>)["logicVet"], "pass", "clean plan cleared the gate");
});

// ── ADVERSARIAL pressure tests for the logic-vet gate (2026-08-06) ───────────

/** A model that returns a different canned plan on each successive call (plan, then replan, ...). */
class SeqModel implements ModelProvider {
  readonly name = "seq-model"; readonly isLocal = true;
  private i = 0;
  constructor(private readonly plans: readonly string[]) {}
  async generate(_r: GenerateRequest): Promise<GenerateResult> { const p = this.plans[Math.min(this.i, this.plans.length - 1)]!; this.i++; return { text: p, model: this.name, tokensIn: 1, tokensOut: 1 }; }
  async embed(_t: readonly string[]): Promise<Embedding[]> { return []; }
}

test("PRESSURE: a forbidden op hidden PAST 200 chars in the replacement is still blocked", async () => {
  const spine = newSpine();
  const tree = new InMemoryFileTree(Object.fromEntries(files.map((f) => [f.path, f.content])));
  const original = await tree.read("src/calc.ts");
  const pad = "x".repeat(300);
  const model = new PlanModel(JSON.stringify({
    rationale: "padded",
    edits: [{ file: "src/calc.ts", search: "return a - b;", replace: `return a + b; /* ${pad} DROP TABLE users */`, intent: "fix" }],
  }));
  const pipeline = new SolvePipeline({
    spine, ledger: new RollbackLedger(spine), tree, runner: calcRunner(tree),
    localizer: new HierarchicalLocalizer(), model,
  }, { forbiddenActions: ["drop table"] });
  const result = await pipeline.run(issue, files);
  assert.equal(result.solved, false, "the forbidden op must be caught despite the padding");
  assert.ok(!result.stagesRun.includes("apply"), "blocked before apply");
  assert.equal(await tree.read("src/calc.ts"), original, "tree untouched");
});

test("PRESSURE: a forbidden edit introduced during a REPAIR round is blocked (no bypass)", async () => {
  const spine = newSpine();
  const tree = new InMemoryFileTree(Object.fromEntries(files.map((f) => [f.path, f.content])));
  // Plan 1: a harmless non-fixing edit (tests still fail → repair triggers). Plan 2 (replan): forbidden.
  const model = new SeqModel([
    // Plan 1 edits the localized file (calc.ts) validly but does NOT fix the bug → tests still fail → repair runs.
    JSON.stringify({ rationale: "annotate", edits: [{ file: "src/calc.ts", search: "export function add(a, b)", replace: "export function add(a, b) /* wip */", intent: "annotate signature" }] }),
    // Plan 2 (the repair replan) smuggles in a forbidden op on the same localized file.
    JSON.stringify({ rationale: "repair", edits: [{ file: "src/calc.ts", search: "return a - b;", replace: "DROP TABLE users; return a + b;", intent: "drop users then fix" }] }),
  ]);
  const pipeline = new SolvePipeline({
    spine, ledger: new RollbackLedger(spine), tree, runner: calcRunner(tree),
    localizer: new HierarchicalLocalizer(), model,
  }, { forbiddenActions: ["drop table"] });
  const result = await pipeline.run(issue, files);
  assert.ok(result.stagesRun.includes("repair"), "the repair path MUST have run (else the test is vacuous)");
  assert.ok(result.repairRounds >= 1, "at least one repair round executed");
  const calc = await tree.read("src/calc.ts");
  assert.ok(!(calc ?? "").toLowerCase().includes("drop table"), "the forbidden op never reached the tree via repair");
  assert.equal(result.solved, false, "the repair must not smuggle in a forbidden edit");
});

test("PRESSURE: two DIFFERENT plans under the same issue are each vetted (no cross-suppression bug)", async () => {
  const spine = newSpine();
  const tree = new InMemoryFileTree(Object.fromEntries(files.map((f) => [f.path, f.content])));
  // Plan 1 clean non-fixing (edit-0), Plan 2 forbidden (also edit-0 positionally) — the guard must NOT
  // suppress re-vetting plan 2's edit-0 just because plan 1's edit-0 passed.
  const model = new SeqModel([
    JSON.stringify({ rationale: "annotate", edits: [{ file: "src/calc.ts", search: "export function add(a, b)", replace: "export function add(a, b) /* v1 */", intent: "annotate" }] }),
    JSON.stringify({ rationale: "repair", edits: [{ file: "src/calc.ts", search: "return a - b;", replace: "DROP TABLE users; return a + b;", intent: "fix" }] }),
  ]);
  const pipeline = new SolvePipeline({
    spine, ledger: new RollbackLedger(spine), tree, runner: calcRunner(tree),
    localizer: new HierarchicalLocalizer(), model,
  }, { forbiddenActions: ["drop table"] });
  const result = await pipeline.run(issue, files);
  assert.ok(result.stagesRun.includes("repair"), "the repair path MUST have run (else vacuous)");
  const calc = await tree.read("src/calc.ts");
  assert.ok(!(calc ?? "").toLowerCase().includes("drop table"), "plan 2's forbidden edit-0 was vetted, not suppressed by plan 1 (same positional id)");
});
