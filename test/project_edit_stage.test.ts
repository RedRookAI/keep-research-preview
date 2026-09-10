import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { buildModelProjectEditPlanner, parseProjectEditPlan, ProjectEditAdmissionError } from "../src/autonomy/project_edit_stage.js";
import { localizeProjectRepository } from "../src/autonomy/project_localization.js";
import type { ProjectTask } from "../src/autonomy/decomposition_stage.js";
import type { ProjectState } from "../src/autonomy/project_state.js";
import type { Embedding, GenerateRequest, GenerateResult, ModelProvider } from "../src/gateway/gateway.js";
import { InProcessLock } from "../src/lock/lock.js";
import { IdentityRegistry } from "../src/identity/agent_identity.js";
import { RollbackLedger } from "../src/control/rollback.js";
import { HierarchicalLocalizer } from "../src/solve/localize.js";
import { SolvePipeline } from "../src/solve/solve_pipeline.js";
import { buildDefaultSolver } from "../src/solve/default_solver.js";
import { InMemoryWorkspace } from "../src/solve/workspace.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { TaskMemoryUnavailableError, type TaskMemoryContext } from "../src/memory/task_context.js";

const repositoryRef = "repo";
const original = "export const value = 1;\n";
const other = "export const other = 1;\n";
const issue = { id: "ISSUE-1", repoRef: repositoryRef, text: "Change the admitted value to two.", hints: { projectTaskId: "task-01", planStepId: "bounded-edit" } };
const task: ProjectTask = { id: "task-01", planStepId: "bounded-edit", objective: issue.text, dependsOn: [], completionCriteria: [{ id: "value", statement: "The admitted value is two.", evidence: "repository behavior" }] };
const allowedEdit = { file: "src/value.ts", search: "value = 1", replace: "value = 2", intent: "meet the admitted task" };

class ResponseModel implements ModelProvider {
  readonly name = "configured-test-model";
  readonly isLocal = false;
  calls = 0;
  constructor(private readonly response: string) {}
  async generate(_request: GenerateRequest): Promise<GenerateResult> { this.calls++; return { text: this.response, model: this.name, tokensIn: 101, tokensOut: 37 }; }
  async embed(): Promise<Embedding[]> { return []; }
}

function plan(edits: readonly Record<string, string>[]): string { return JSON.stringify({ rationale: "Make only the admitted behavioral change.", edits }); }
function spine(): Spine { return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-edit-stage-"))), new InProcessLock(), new SchemaRegistry()); }

async function state(workspace: InMemoryWorkspace): Promise<ProjectState> {
  const base = {
    schemaVersion: 1 as const, revision: 0, runId: "run-1", goal: issue.text, stage: "plan" as const, posture: "autonomous" as const,
    artifacts: {}, stepsRemaining: 10, reworkCount: 0, status: "running" as const,
    retry: { attemptsByStage: {}, attemptsConsumed: 0, runLimit: 8 }, consumedSignals: [],
  };
  const projectLocalization = await localizeProjectRepository(base, workspace, repositoryRef, {
    async localize() { return { suspects: [{ path: "src/value.ts", score: 1, isTest: false }], stages: ["bm25"] }; },
  });
  return {
    ...base, stage: "implement",
    artifacts: {
      plan: {
        schemaVersion: 1, goal: issue.text, committedStepIds: [],
        localization: projectLocalization,
        evidence: [{ id: "intent", kind: "operator-intent", summary: issue.text }, { id: "repository-1", kind: "repository-file", summary: "admitted", sourceId: "src/value.ts" }, { id: "repository-2", kind: "repository-file", summary: "not admitted", sourceId: "src/other.ts" }],
        steps: [{ id: "bounded-edit", description: task.objective, dependsOn: [], evidenceRefs: ["intent", "repository-1"], advancesGoal: issue.text, undoes: [] }],
      },
    },
  };
}

test("project edit planning is bounded, content-bound, and has no write authority", async () => {
  const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
  const model = new ResponseModel(plan([allowedEdit]));
  const proposal = await buildModelProjectEditPlanner(model, workspace, repositoryRef).prepare(issue, task, await state(workspace));
  assert.equal(await workspace.tree(repositoryRef).read("src/value.ts"), original);
  assert.deepEqual(proposal.allowedFiles, ["src/value.ts"]);
  assert.equal(proposal.taskId, task.id);
  assert.deepEqual(proposal.generation, { model: model.name, tokensIn: 101, tokensOut: 37 });
  assert.deepEqual(JSON.parse(JSON.stringify(proposal)), proposal);
});

test("native preparation returns only unexecuted data and never constructs effect ports", async () => {
  const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
  const model = new ResponseModel(plan([allowedEdit])), s = spine();
  const editor = buildModelProjectEditPlanner(model, workspace, repositoryRef), durable = await state(workspace);
  let forbidden = 0;
  const fail = (): never => { forbidden++; throw new Error("effect port called during preparation"); };
  const cfg = { spine: s, model, workspace: { files: (ref: string) => workspace.files(ref), tree: fail },
    runnerFor: fail, proposalEvidenceFor: fail, governance: { spine: s, vetPatch: fail }, options: { maxRepairRounds: 1 } };
  const context = { executionCeiling: "prepare" as const, recoveryOperationId: "same-logical-preparation",
    prepareAdmittedEdit: (control: import("../src/solve/issue_model.js").AdmittedEditPlanningContext) => editor.prepare(issue, task, durable, control) };
  const first = (await buildDefaultSolver(cfg)(issue, context)).solveResult;
  assert.equal(first.solved, false);
  assert.deepEqual(first.preparedProposal?.plan.edits, [allowedEdit]);
  assert.equal(first.preparedProposal?.goalFulfilled, false);
  assert.equal(first.preparedProposal?.disposition, "unexecuted");
  assert.equal(first.admittedEdit, undefined); assert.equal(first.validation, undefined);
  assert.equal(first.prProposal, undefined); assert.equal(first.projectEditReceipt, undefined);
  assert.equal(first.authority, undefined); assert.deepEqual(first.stagesRun, ["localize", "plan"]);
  assert.equal(first.recovery?.attempts, 1); assert.equal(first.recovery?.planningCalls, 1);
  const second = (await buildDefaultSolver(cfg)(issue, context)).solveResult;
  assert.equal(second.preparedProposal?.disposition, "unexecuted", "the last allowed attempt may return its proposal");
  assert.equal(second.recovery?.attempts, 2); assert.equal(second.recovery?.planningCalls, 2);
  const third = (await buildDefaultSolver(cfg)(issue, context)).solveResult;
  assert.equal(third.preparedProposal, undefined); assert.equal(third.recovery?.status, "exhausted");
  assert.equal(model.calls, 2); assert.equal(forbidden, 0);
  assert.equal(await workspace.tree(repositoryRef).read("src/value.ts"), original);
});

test("preparation refuses unknown ceilings, missing admission, cancellation and revoked identity", async () => {
  const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
  const model = new ResponseModel(plan([allowedEdit])), s = spine(), identities = new IdentityRegistry(s);
  const root = identities.mint("preparation-owner", ["."]);
  const editor = buildModelProjectEditPlanner(model, workspace, repositoryRef), durable = await state(workspace);
  const solve = buildDefaultSolver({ spine: s, model, workspace, identityRegistry: identities, rootIdentity: root,
    runnerFor: () => { throw new Error("runner factory must not run"); } });
  const unknown = await solve(issue, { executionCeiling: "execute" as never });
  assert.match(unknown.solveResult.gaveUpReason!, /unknown execution ceiling/);
  const missing = await solve(issue, { executionCeiling: "prepare" });
  assert.match(missing.solveResult.gaveUpReason!, /content-bound/);
  const context = { executionCeiling: "prepare" as const,
    prepareAdmittedEdit: (control: import("../src/solve/issue_model.js").AdmittedEditPlanningContext) => editor.prepare(issue, task, durable, control) };
  const cancelled = await solve(issue, { ...context, signal: AbortSignal.abort() });
  assert.equal(cancelled.solveResult.preparedProposal, undefined);
  identities.kill(root.id);
  await assert.rejects(solve(issue, context), /preparation identity refused/);
  assert.equal(model.calls, 0);
});

test("preparation checks memory currentness after durable budget settlement before releasing excerpts", async () => {
  const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
  const model = new ResponseModel(plan([allowedEdit])), s = spine();
  const editor = buildModelProjectEditPlanner(model, workspace, repositoryRef), durable = await state(workspace);
  let prepared = false, checksAfterPreparation = 0;
  const memoryContext: TaskMemoryContext = { copyNotice: "synthetic", select: () => ({ prompt: "", metrics: {} }),
    assertCurrent() { if (prepared && ++checksAfterPreparation >= 2) throw new TaskMemoryUnavailableError("authority"); } };
  const pipeline = new SolvePipeline({ spine: s, ledger: new RollbackLedger(s), tree: workspace.tree(repositoryRef),
    model, localizer: new HierarchicalLocalizer(), snapshotFiles: () => workspace.files(repositoryRef),
    runner: { async run() { throw new Error("preparation must not run tests"); } } });
  const result = await pipeline.run(issue, await workspace.files(repositoryRef), { executionCeiling: "prepare", memoryContext,
    prepareAdmittedEdit: async control => { const value = await editor.prepare(issue, task, durable, control); prepared = true; return value; } });
  assert.equal(result.preparedProposal, undefined); assert.equal(result.solved, false);
  assert.match(result.gaveUpReason!, /selected task memory unavailable/);
  assert.equal(await workspace.tree(repositoryRef).read("src/value.ts"), original);
});

test("an asynchronous caller cannot lift the native preparation ceiling", async () => {
  const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
  const model = new ResponseModel(plan([allowedEdit])), s = spine();
  const editor = buildModelProjectEditPlanner(model, workspace, repositoryRef), durable = await state(workspace);
  const context: { executionCeiling?: "prepare"; prepareAdmittedEdit: import("../src/solve/issue_model.js").SolveExecutionContext["prepareAdmittedEdit"] } = {
    executionCeiling: "prepare", prepareAdmittedEdit: control => editor.prepare(issue, task, durable, control),
  };
  const generate = model.generate.bind(model);
  model.generate = async request => { delete context.executionCeiling; return generate(request); };
  const pipeline = new SolvePipeline({ spine: s, ledger: new RollbackLedger(s), tree: workspace.tree(repositoryRef),
    model, localizer: new HierarchicalLocalizer(), snapshotFiles: () => workspace.files(repositoryRef),
    runner: { async run() { throw new Error("ceiling was removed"); } } });
  const result = await pipeline.run(issue, await workspace.files(repositoryRef), context as import("../src/solve/issue_model.js").SolveExecutionContext);
  assert.equal(result.preparedProposal?.disposition, "unexecuted");
  assert.equal(result.solved, false); assert.equal(await workspace.tree(repositoryRef).read("src/value.ts"), original);
});

test("an operator-named file narrows authority; large admitted files use bounded previews", async () => {
  const large = "x".repeat(24_001);
  const workspace = new InMemoryWorkspace({ repo: { "README.md": original, "src/value.ts": original, "src/other.ts": other, "src/large.ts": large } });
  const model = new ResponseModel(plan([{ file: "README.md", search: "value = 1", replace: "value = 2", intent: "document the requested behavior" }]));
  const durable = await state(workspace);
  const localization = await localizeProjectRepository({ ...durable, goal: "Update README.md only." }, workspace, repositoryRef, {
    async localize() { return { suspects: [{ path: "README.md", score: 1, isTest: false }, { path: "src/large.ts", score: 0.5, isTest: false }], stages: ["bm25"] }; },
  });
  const narrowedState = { ...durable, goal: "Update README.md only.", artifacts: { ...durable.artifacts, project_localization: localization, plan: { ...(durable.artifacts["plan"] as any), goal: "Update README.md only.", localization, evidence: [{ id: "intent", kind: "operator-intent", summary: "Update README.md only." }, { id: "repository-1", kind: "repository-file", summary: "README", sourceId: "README.md" }, { id: "repository-2", kind: "repository-file", summary: "large", sourceId: "src/large.ts" }], steps: [{ id: "bounded-edit", description: "Update README.md only.", dependsOn: [], evidenceRefs: ["intent", "repository-1", "repository-2"], advancesGoal: "Update README.md only.", undoes: [] }] } } } as ProjectState;
  const narrowed = await buildModelProjectEditPlanner(model, workspace, repositoryRef).prepare({ ...issue, text: "Update README.md only." }, { ...task, objective: "Update README.md only." }, narrowedState);
  assert.deepEqual(narrowed.allowedFiles, ["README.md"]);

  const unnamed = { ...narrowedState, goal: "Update the documentation and source.", artifacts: { ...narrowedState.artifacts, plan: { ...(narrowedState.artifacts["plan"] as any), goal: "Update the documentation and source.", steps: [{ id: "bounded-edit", description: "Update the documentation and source.", dependsOn: [], evidenceRefs: ["intent", "repository-1", "repository-2"], advancesGoal: "Update the documentation and source.", undoes: [] }] } } } as ProjectState;
  let promptBytes = 0;
  const boundedModel: ModelProvider = { name: model.name, isLocal: false, embed: async () => [], generate: async request => {
    promptBytes = Buffer.byteLength(request.prompt, "utf8");
    assert.equal(request.prompt.includes(large), false, "the entire large file is not forced into context");
    return model.generate(request);
  } };
  const expanded = await buildModelProjectEditPlanner(boundedModel, workspace, repositoryRef).prepare({ ...issue, text: "Update the documentation and source." }, { ...task, objective: "Update the documentation and source." }, unnamed);
  assert.deepEqual(expanded.allowedFiles, ["README.md", "src/large.ts"]);
  assert.ok(promptBytes < 65_536);
});

test("one unauthorized member rejects the entire proposal before any write", async () => {
  const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
  const model = new ResponseModel(plan([allowedEdit, { file: "src/other.ts", search: "other = 1", replace: "other = 2", intent: "unrelated" }]));
  await assert.rejects(buildModelProjectEditPlanner(model, workspace, repositoryRef).prepare(issue, task, await state(workspace)), /outside the admitted plan step/);
  assert.equal(await workspace.tree(repositoryRef).read("src/value.ts"), original);
  assert.equal(await workspace.tree(repositoryRef).read("src/other.ts"), other);
});

test("malformed output and stale localization refuse before effects; stale bytes avoid model spend", async () => {
  assert.throws(() => parseProjectEditPlan("```json\n{}\n```", new Set(["src/value.ts"])), /bounded raw JSON object/);
  assert.deepEqual(parseProjectEditPlan(`\n${plan([allowedEdit])}\n`, new Set(["src/value.ts"])).edits, [allowedEdit]);
  const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
  const durable = await state(workspace);
  await workspace.tree(repositoryRef).write("src/value.ts", "export const value = 9;\n");
  const model = new ResponseModel(plan([allowedEdit]));
  await assert.rejects(buildModelProjectEditPlanner(model, workspace, repositoryRef).prepare(issue, task, durable), /changed after localization/);
  assert.equal(model.calls, 0);
});

test("canonical pipeline is the sole writer and consumes the exact admitted proposal through validation", async () => {
  const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
  const model = new ResponseModel(plan([allowedEdit]));
  const proposal = await buildModelProjectEditPlanner(model, workspace, repositoryRef).prepare(issue, task, await state(workspace));
  const s = spine();
  const tree = workspace.tree(repositoryRef);
  const ledger = new RollbackLedger(s);
  const pipeline = new SolvePipeline({
    spine: s, ledger, tree,
    runner: { async run() { return { results: [{ name: "value-is-two", passed: (await tree.read("src/value.ts"))?.includes("value = 2") === true }] }; } },
    localizer: new HierarchicalLocalizer(), model, snapshotFiles: () => workspace.files(repositoryRef),
  });
  const files = await workspace.files(repositoryRef);
  const result = await pipeline.run(issue, files, { admittedEdit: proposal });
  assert.equal(result.solved, true);
  assert.equal(await tree.read("src/value.ts"), "export const value = 2;\n");
  assert.equal(await tree.read("src/other.ts"), other);
  assert.deepEqual(result.admittedEdit, proposal);
  assert.equal(result.projectEditReceipt?.applied, true);
  assert.equal(result.projectEditReceipt?.testsExecuted, true);
  assert.equal(result.projectEditReceipt?.rollbackIds.length, 1);
  assert.notEqual(result.projectEditReceipt?.touchedFiles[0]?.beforeSha256, result.projectEditReceipt?.touchedFiles[0]?.afterSha256);
  assert.equal(model.calls, 1, "the pipeline used the prepared plan instead of generating a second one");
  await ledger.rollback(1, "receipt rollback proof");
  assert.equal(await tree.read("src/value.ts"), original, "the receipt's registered rollback restores the exact pre-image");
});

test("goal checks are separately derived from original evidence within the shared call budget", async () => {
  for (const reserveSecond of [true, false]) {
    const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
    let calls = 0, reservations = 0;
    const model: ModelProvider = { name: "goal-check-fixture", isLocal: true, embed: async () => [], generate: async request => {
      calls++;
      if (calls === 1) return { text: plan([allowedEdit]), model: "fixture", tokensIn: 1, tokensOut: 1 };
      assert.equal(request.hints?.["taskRole"], "goal_test");
      assert.ok(request.prompt.includes(issue.text)); assert.ok(request.prompt.includes("value = 1"));
      assert.ok(!request.prompt.includes("value = 2"), "check author must not copy the proposed replacement");
      return { text: JSON.stringify({ body: "assert.equal((await import('./src/value.ts')).value, 2);" }), model: "fixture", tokensIn: 1, tokensOut: 1 };
    } };
    const prepare = () => buildModelProjectEditPlanner(model, workspace, repositoryRef, { prepareGoalCheck: true })
      .prepare(issue, task, stateValue, { signal: new AbortController().signal,
        reserveCall: async bytes => { assert.ok(bytes > 0); return ++reservations === 1 || reserveSecond; }, observe: () => {} });
    const stateValue = await state(workspace);
    if (reserveSecond) {
      const admission = await prepare(); assert.ok(admission.plan.goalCheck);
      assert.match(admission.plan.goalCheck.requestSha256, /^[a-f0-9]{64}$/u); assert.equal(calls, 2);
    } else { await assert.rejects(prepare(), /shared planning budget/); assert.equal(calls, 1); }
    assert.equal(reservations, 2); assert.equal(await workspace.tree(repositoryRef).read("src/value.ts"), original);
  }
});

test("memory-independent command authority fences model, goal check, tests and repair awaits", async () => {
  for (const phase of ["edit-model", "check-model", "baseline", "validation", "repair-model"] as const) {
    const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
    const s = spine(), durable = await state(workspace);
    let current = true, calls = 0, checkRuns = 0;
    const assertAuthority = () => { if (!current) throw new Error("revoked original command"); };
    const model: ModelProvider = { name: "authority-fixture", isLocal: true, embed: async () => [], generate: async request => {
      calls++;
      if ((phase === "edit-model" && calls === 1) || (phase === "check-model" && calls === 2)
        || (phase === "repair-model" && calls === 3)) current = false;
      return { text: request.hints?.["taskRole"] === "goal_test" ? JSON.stringify({ body: "assert.equal(1, 2);" }) : plan([allowedEdit]),
        model: "authority-fixture", tokensIn: 1, tokensOut: 1 };
    } };
    const editor = buildModelProjectEditPlanner(model, workspace, repositoryRef, { prepareGoalCheck: true });
    const solve = buildDefaultSolver({ spine: s, model, workspace, options: { maxRepairRounds: 1 },
      runnerFor: () => ({ run: async () => {
        if (phase === "validation") current = false;
        return { results: [{ name: "regression", passed: phase !== "repair-model" }] };
      } }),
      goalCheckRunnerFor: () => ({ run: async () => {
        checkRuns++;
        if (phase === "baseline" && checkRuns === 1) current = false;
        return { results: [{ name: "requested outcome", passed: (await workspace.tree(repositoryRef).read("src/value.ts"))?.includes("value = 2") === true }] };
      } }),
    });
    const result = await solve(issue, { assertAuthority, recoveryOperationId: "original-" + phase,
      prepareAdmittedEdit: context => editor.prepare(issue, task, durable, context) });
    assert.equal(current, false, phase); assert.equal(result.solveResult.solved, false, phase);
    assert.equal(result.solveResult.prProposal, undefined, phase); assert.equal(result.solveResult.projectEditReceipt, undefined, phase);
    assert.equal(result.solveResult.recovery?.status, "authority", phase);
    assert.equal(result.solveResult.recovery?.planningCalls, calls, phase);
    assert.equal(calls, phase === "edit-model" ? 1 : phase === "repair-model" ? 3 : 2, phase);
    assert.equal(await workspace.tree(repositoryRef).read("src/value.ts"), original, phase);
  }
});

test("revoked command authority constructs no workspace or runner capability", async () => {
  const fail = (): never => { throw new Error("effect factory was reached"); };
  const solve = buildDefaultSolver({ spine: spine(), model: new ResponseModel(plan([allowedEdit])), workspace: { files: fail, tree: fail }, runnerFor: fail });
  const result = await solve(issue, { assertAuthority: () => { throw new Error("revoked"); } });
  assert.equal(result.solveResult.solved, false); assert.match(result.solveResult.gaveUpReason!, /command authority unavailable/u);
});

test("frozen goal checks reject vacuous baselines and compensate wrong results despite passing regressions", async () => {
  for (const mode of ["correct", "wrong", "vacuous", "unavailable", "missing-runner"] as const) {
    const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
    const model = new ResponseModel(plan([allowedEdit]));
    const proposed = await buildModelProjectEditPlanner(model, workspace, repositoryRef).prepare(issue, task, await state(workspace));
    const check = Object.freeze({ body: "frozen-test-body", requestSha256: "a".repeat(64) });
    const admission = { ...proposed, plan: { ...proposed.plan, goalCheck: check } };
    const s = spine(), tree = workspace.tree(repositoryRef); let checkRuns = 0, regressionRuns = 0;
    const pipeline = new SolvePipeline({ spine: s, ledger: new RollbackLedger(s), tree,
      runner: { run: async () => { regressionRuns++; return { results: [{ name: "stale regression", passed: true }] }; } },
      ...(mode === "missing-runner" ? {} : { goalCheckRunnerFor: (_ref: string, actual: { readonly body: string; readonly requestSha256: string }) => {
        assert.deepEqual(actual, check);
        return { run: async () => { checkRuns++;
          if (mode === "unavailable") return { results: [], runnerError: "test syntax failure" };
          return { results: [{ name: "current requested value", passed: mode === "vacuous" ||
            (mode === "correct" && (await tree.read("src/value.ts")) === "export const value = 2;\n") }] };
        } };
      } }),
      localizer: new HierarchicalLocalizer(), model, snapshotFiles: () => workspace.files(repositoryRef),
    }, { maxRepairRounds: 0 });
    const result = await pipeline.run(issue, await workspace.files(repositoryRef), { admittedEdit: admission });
    assert.equal(result.solved, mode === "correct");
    assert.equal(await tree.read("src/value.ts"), mode === "correct" ? "export const value = 2;\n" : original);
    assert.equal(regressionRuns, mode === "correct" || mode === "wrong" ? 1 : 0);
    assert.equal(checkRuns, mode === "missing-runner" ? 0 : mode === "correct" || mode === "wrong" ? 2 : 1);
    if (mode === "wrong") { assert.ok(result.validation?.failures.includes("goal: current requested value")); assert.equal(result.prProposal, undefined); }
    await s.seal();
  }
});

test("pre-effect recheck refuses stale, forged-task, and incompletely hashed proposals without writing", async () => {
  for (const mutate of [
    (proposal: any) => ({ ...proposal, taskId: "task-forged" }),
    (proposal: any) => ({ ...proposal, allowedFileSha256: {} }),
    (proposal: any) => ({ ...proposal, repositoryTreeSha256: "0".repeat(64) }),
  ]) {
    const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
    const model = new ResponseModel(plan([allowedEdit]));
    const proposal = mutate(await buildModelProjectEditPlanner(model, workspace, repositoryRef).prepare(issue, task, await state(workspace)));
    const s = spine();
    const pipeline = new SolvePipeline({ spine: s, ledger: new RollbackLedger(s), tree: workspace.tree(repositoryRef), runner: { async run() { return { results: [] }; } }, localizer: new HierarchicalLocalizer(), model, snapshotFiles: () => workspace.files(repositoryRef) });
    const result = await pipeline.run(issue, await workspace.files(repositoryRef), { admittedEdit: proposal });
    assert.equal(result.solved, false);
    assert.match(result.gaveUpReason ?? "", /admitted project edit refused/);
    assert.equal(await workspace.tree(repositoryRef).read("src/value.ts"), original);
  }
});

test("repair remains attenuated to the admitted file set", async () => {
  const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
  let call = 0;
  const model: ModelProvider = {
    name: "repair-scope-model", isLocal: false,
    async generate() {
      call++;
      return { text: call === 1
        ? plan([{ ...allowedEdit, replace: "value = 3" }])
        : plan([{ file: "src/other.ts", search: "other = 1", replace: "other = 2", intent: "escape admitted scope" }]), model: this.name, tokensIn: 1, tokensOut: 1 };
    },
    async embed() { return []; },
  };
  const proposal = await buildModelProjectEditPlanner(model, workspace, repositoryRef).prepare(issue, task, await state(workspace));
  const s = spine();
  const tree = workspace.tree(repositoryRef);
  const pipeline = new SolvePipeline({
    spine: s, ledger: new RollbackLedger(s), tree,
    runner: { async run() { return { results: [{ name: "value-is-two", passed: (await tree.read("src/value.ts"))?.includes("value = 2") === true }] }; } },
    localizer: new HierarchicalLocalizer(), model, snapshotFiles: () => workspace.files(repositoryRef),
  }, { maxRepairRounds: 1 });
  const result = await pipeline.run(issue, await workspace.files(repositoryRef), { admittedEdit: proposal });
  assert.equal(result.solved, false);
  assert.equal(await tree.read("src/other.ts"), other);
  assert.match(result.gaveUpReason ?? "", /blocked|admitted project step|invalid whole edit proposal/i);
});

test("a stale non-applicable repair refuses normally without throwing or changing bytes", async () => {
  const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
  let modelCall = 0;
  const model: ModelProvider = {
    name: "stale-repair-model", isLocal: false,
    async generate() {
      modelCall++;
      return {
        text: modelCall === 1
          ? plan([{ ...allowedEdit, replace: "value = 3" }])
          : plan([{ ...allowedEdit, search: "value = 99", replace: "value = 2" }]),
        model: this.name, tokensIn: 1, tokensOut: 1,
      };
    },
    async embed() { return []; },
  };
  const proposal = await buildModelProjectEditPlanner(model, workspace, repositoryRef).prepare(issue, task, await state(workspace));
  const s = spine();
  const tree = workspace.tree(repositoryRef);
  const pipeline = new SolvePipeline({
    spine: s, ledger: new RollbackLedger(s), tree,
    runner: { async run() { return { results: [{ name: "value-is-two", passed: false }] }; } },
    localizer: new HierarchicalLocalizer(), model, snapshotFiles: () => workspace.files(repositoryRef),
  }, { maxRepairRounds: 1 });

  const result = await pipeline.run(issue, await workspace.files(repositoryRef), { admittedEdit: proposal });
  assert.equal(result.solved, false);
  assert.match(result.gaveUpReason ?? "", /repair patch did not apply|not found|not applicable/i);
  assert.equal(await tree.read("src/value.ts"), original, "an admitted attempt that never clears verification is fully rolled back");
});

test("whole-tree freshness rejects a change outside the admitted file even with a stale caller snapshot", async () => {
  const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
  const model = new ResponseModel(plan([allowedEdit]));
  const proposal = await buildModelProjectEditPlanner(model, workspace, repositoryRef).prepare(issue, task, await state(workspace));
  const staleFiles = await workspace.files(repositoryRef);
  await workspace.tree(repositoryRef).write("src/other.ts", "export const other = 9;\n");
  const s = spine();
  const pipeline = new SolvePipeline({ spine: s, ledger: new RollbackLedger(s), tree: workspace.tree(repositoryRef), runner: { async run() { return { results: [] }; } }, localizer: new HierarchicalLocalizer(), model, snapshotFiles: () => workspace.files(repositoryRef) });
  const result = await pipeline.run(issue, staleFiles, { admittedEdit: proposal });
  assert.equal(result.solved, false);
  assert.match(result.gaveUpReason ?? "", /live repository bytes changed/);
  assert.equal(await workspace.tree(repositoryRef).read("src/value.ts"), original);
});

test("admitted project edits cannot use the legacy direct-apply flag to bypass a killed identity", async () => {
  const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
  const model = new ResponseModel(plan([allowedEdit]));
  const proposal = await buildModelProjectEditPlanner(model, workspace, repositoryRef).prepare(issue, task, await state(workspace));
  const s = spine();
  const identities = new IdentityRegistry(s);
  const identity = identities.mint("project-editor", ["*"]);
  identities.kill(identity.id, "test revocation");
  const pipeline = new SolvePipeline({
    spine: s, ledger: new RollbackLedger(s), tree: workspace.tree(repositoryRef), runner: { async run() { return { results: [] }; } },
    localizer: new HierarchicalLocalizer(), model, snapshotFiles: () => workspace.files(repositoryRef), identity, identityRegistry: identities,
    reversibleEnvelope: false,
  });
  const result = await pipeline.run(issue, await workspace.files(repositoryRef), { admittedEdit: proposal });
  assert.equal(result.solved, false);
  assert.equal(await workspace.tree(repositoryRef).read("src/value.ts"), original);
  assert.match(result.gaveUpReason ?? "", /identity/i);
});

test("identity revocation between initial validation and repair prevents the repair write", async () => {
  const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
  let modelCall = 0;
  const model: ModelProvider = {
    name: "repair-after-kill", isLocal: false,
    async generate() { modelCall++; return { text: modelCall === 1 ? plan([{ ...allowedEdit, replace: "value = 3" }]) : plan([{ ...allowedEdit, search: "value = 3", replace: "value = 2" }]), model: this.name, tokensIn: 1, tokensOut: 1 }; },
    async embed() { return []; },
  };
  const proposal = await buildModelProjectEditPlanner(model, workspace, repositoryRef).prepare(issue, task, await state(workspace));
  const s = spine();
  const identities = new IdentityRegistry(s);
  const identity = identities.mint("repairing-project-editor", ["*"]);
  let runnerCalls = 0;
  const tree = workspace.tree(repositoryRef);
  const pipeline = new SolvePipeline({
    spine: s, ledger: new RollbackLedger(s), tree,
    runner: { async run() { runnerCalls++; if (runnerCalls === 1) identities.kill(identity.id, "revoked during validation"); return { results: [{ name: "value-is-two", passed: (await tree.read("src/value.ts"))?.includes("value = 2") === true }] }; } },
    localizer: new HierarchicalLocalizer(), model, snapshotFiles: () => workspace.files(repositoryRef), identity, identityRegistry: identities,
  }, { maxRepairRounds: 1 });
  const result = await pipeline.run(issue, await workspace.files(repositoryRef), { admittedEdit: proposal });
  assert.equal(result.solved, false);
  assert.equal(await tree.read("src/value.ts"), original, "revocation prevents repair and rolls back the unverified admitted attempt");
  assert.match(result.gaveUpReason ?? "", /identity/i);
});

test("commit-boundary freshness preserves a concurrent admitted-file change containing the same search text", async () => {
  const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
  const model = new ResponseModel(plan([allowedEdit]));
  const proposal = await buildModelProjectEditPlanner(model, workspace, repositoryRef).prepare(issue, task, await state(workspace));
  const underlying = workspace.tree(repositoryRef);
  const racingTree = {
    async read(path: string) { return underlying.read(path); },
    async write(path: string, content: string) { return underlying.write(path, content); },
    async commitBatchIfUnchanged(expected: Readonly<Record<string, string>>, writes: readonly { readonly path: string; readonly content: string }[]) {
      await underlying.write("src/value.ts", `// concurrent owner change\n${original}`);
      return underlying.commitBatchIfUnchanged!(expected, writes);
    },
  };
  const s = spine();
  const pipeline = new SolvePipeline({
    spine: s, ledger: new RollbackLedger(s), tree: racingTree,
    runner: { async run() { return { results: [] }; } }, localizer: new HierarchicalLocalizer(), model,
    snapshotFiles: () => workspace.files(repositoryRef),
  });
  const result = await pipeline.run(issue, await workspace.files(repositoryRef), { admittedEdit: proposal });
  assert.equal(result.solved, false);
  assert.match(result.gaveUpReason ?? "", /content-bound commit refused|repository bytes changed/i);
  assert.equal(await underlying.read("src/value.ts"), `// concurrent owner change\n${original}`);
});

test("rollback intent persistence failure prevents the admitted effect", async () => {
  const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
  const model = new ResponseModel(plan([allowedEdit]));
  const proposal = await buildModelProjectEditPlanner(model, workspace, repositoryRef).prepare(issue, task, await state(workspace));
  const s = spine();
  const refusingLedger = { record() { throw new Error("injected rollback persistence failure"); } };
  const pipeline = new SolvePipeline({
    spine: s, ledger: refusingLedger as never, tree: workspace.tree(repositoryRef),
    runner: { async run() { return { results: [] }; } }, localizer: new HierarchicalLocalizer(), model,
    snapshotFiles: () => workspace.files(repositoryRef),
  });
  await assert.rejects(pipeline.run(issue, await workspace.files(repositoryRef), { admittedEdit: proposal }), /rollback persistence failure/);
  assert.equal(await workspace.tree(repositoryRef).read("src/value.ts"), original);
});

test("initial preflight exceptions remain uncertain rather than becoming non-applicability", async () => {
  const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
  const model = new ResponseModel(plan([allowedEdit]));
  const proposal = await buildModelProjectEditPlanner(model, workspace, repositoryRef).prepare(issue, task, await state(workspace));
  const s = spine(), ledger = new RollbackLedger(s);
  // Trusted-host fault injection at the snapshot's map operation. Admission's
  // iterated digest remains valid; only the initial in-memory preflight throws.
  const files = new Proxy(await workspace.files(repositoryRef), {
    get(target, property, receiver) {
      if (property === "map") return () => { throw new Error("synthetic snapshot mapping failure"); };
      return Reflect.get(target, property, receiver);
    },
  });
  const pipeline = new SolvePipeline({ spine: s, ledger, tree: workspace.tree(repositoryRef), model,
    localizer: new HierarchicalLocalizer(), snapshotFiles: () => workspace.files(repositoryRef),
    runner: { async run() { throw new Error("test execution must not follow a preflight exception"); } } });
  await assert.rejects(pipeline.run(issue, files, { admittedEdit: proposal }), /synthetic snapshot mapping failure/);
  assert.equal(ledger.pending, 0); assert.equal(await workspace.tree(repositoryRef).read("src/value.ts"), original);
  assert.equal(s.currentEvents().some(event => event.payload["classification"] === "non-applicable"), false);
  assert.ok(JSON.stringify(s.currentEvents()).includes("solve threw; reconciliation required"));
});

test("task memory reaches deferred project editing and canonical repair without extra generation", async () => {
  const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
  const tree = workspace.tree(repositoryRef), s = spine();
  let calls = 0, selected = 0, guards = 0;
  const memoryContext: TaskMemoryContext = { copyNotice: "Synthetic outside-copy notice", assertCurrent() { guards++; },
    select() { selected++; return { prompt: "\nQUOTED MEMORY: amber orchard policy\n", metrics: { selected: 1 } }; } };
  const model: ModelProvider = { name: "memory-repair", isLocal: true, embed: async () => [[1]], generate: async request => {
    assert.match(request.prompt, /amber orchard policy/); calls++;
    return { text: plan([{ ...allowedEdit, search: calls === 1 ? "value = 1" : "value = 3", replace: calls === 1 ? "value = 3" : "value = 2" }]), model: "memory-repair", tokensIn: 1, tokensOut: 1 };
  } };
  const editor = buildModelProjectEditPlanner(model, workspace, repositoryRef), durable = await state(workspace);
  const pipeline = new SolvePipeline({ spine: s, ledger: new RollbackLedger(s), tree,
    runner: { async run() { return { results: [{ name: "value-is-two", passed: (await tree.read("src/value.ts"))?.includes("value = 2") === true }] }; } },
    localizer: new HierarchicalLocalizer(), model, snapshotFiles: () => workspace.files(repositoryRef),
  }, { maxRepairRounds: 1 });
  const result = await pipeline.run(issue, await workspace.files(repositoryRef), {
    memoryContext, prepareAdmittedEdit: context => { assert.equal(context.memoryContext, memoryContext); return editor.prepare(issue, task, durable, context); },
  });
  assert.equal(result.solved, true); assert.equal(result.repairRounds, 1); assert.equal(calls, 2); assert.equal(selected, 2);
  assert.ok(guards >= 8, "dispatch, response, proposal and initial/repair precommit guards consumed");
  assert.equal(await tree.read("src/value.ts"), "export const value = 2;\n");
  assert.equal(await tree.read("src/other.ts"), other);
});

test("task memory revoked while registering rollback refuses the initial commit without ambiguous effect debt", async () => {
  const workspace = new InMemoryWorkspace({ repo: { "src/value.ts": original, "src/other.ts": other } });
  const s = spine(), model = new ResponseModel(plan([allowedEdit])); let allowed = true;
  const memoryContext: TaskMemoryContext = { copyNotice: "Synthetic", select: () => ({ prompt: "", metrics: {} }),
    assertCurrent() { if (!allowed) throw new TaskMemoryUnavailableError("authority"); } };
  const proposal = await buildModelProjectEditPlanner(model, workspace, repositoryRef).prepare(issue, task, await state(workspace));
  const ledger = new RollbackLedger(s), record = ledger.record.bind(ledger);
  ledger.record = (...args) => { record(...args); allowed = false; };
  const pipeline = new SolvePipeline({ spine: s, ledger, tree: workspace.tree(repositoryRef),
    runner: { async run() { return { results: [] }; } }, localizer: new HierarchicalLocalizer(), model,
    snapshotFiles: () => workspace.files(repositoryRef),
  });
  const result = await pipeline.run(issue, await workspace.files(repositoryRef), { admittedEdit: proposal, memoryContext });
  assert.equal(result.solved, false); assert.match(result.gaveUpReason ?? "", /selected task memory unavailable: authority/);
  assert.equal(result.recovery?.pendingAttemptId, undefined);
  assert.equal(await workspace.tree(repositoryRef).read("src/value.ts"), original);
});
