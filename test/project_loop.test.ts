import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { ProgressNarrator } from "../src/autonomy/progress_narrator.js";
import { ProjectLoop, stageOrder, type StageExecutors, type StageResult, type ProjectState } from "../src/autonomy/project_loop.js";
import { FileProjectCheckpointStore, InMemoryProjectCheckpointStore, type ProjectCheckpointStore } from "../src/autonomy/project_checkpoint_store.js";
import type { TaskMemoryContext } from "../src/memory/task_context.js";
import { buildAutonomyLoop } from "../src/autonomy/autonomy_loop.js";
import { buildDefaultSolver, validatorRunner } from "../src/solve/default_solver.js";
import { buildModelProjectEditPlanner } from "../src/autonomy/project_edit_stage.js";
import { InMemoryWorkspace } from "../src/solve/workspace.js";

function newSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-loop-"))), new InProcessLock(), new SchemaRegistry());
}
function narrator(spine: Spine, runId = "run"): ProgressNarrator {
  return new ProgressNarrator(runId, spine);
}
/** An executor that just advances with a headline. */
const adv = (headline: string): StageResult => ({ output: headline, control: "advance", headline });
const allExecutors = (overrides: StageExecutors = {}): StageExecutors => ({
  understand: async () => adv("understood"), research: async () => adv("researched"), plan: async () => adv("planned"),
  vet_plan: async () => adv("plan vetted"), ticket: async () => adv("ticketed"), implement: async () => adv("implemented"),
  vet_artifact: async () => adv("artifact vetted"), learn: async () => adv("learned"), ...overrides,
});

function preparationFixture() {
  const spine = newSpine(), checkpoints = new InMemoryProjectCheckpointStore();
  const workspace = new InMemoryWorkspace({ repo: { "billing.ts": "export const retryLimit = 0;\n" } });
  let calls = 0, effects = 0;
  const forbidden = (): never => { effects++; throw new Error("effectful port reached"); };
  const model = { name: "preparation-fixture", isLocal: true, embed: async () => [], generate: async () => {
    calls++; return { text: JSON.stringify({ action: "plan", rationale: "prepare only", edits: [
      { file: "billing.ts", search: "retryLimit = 0", replace: "retryLimit = 7", intent: "bounded proposal" },
    ] }), model: "preparation-fixture", tokensIn: 1, tokensOut: 1 };
  } };
  const editor = buildModelProjectEditPlanner(model, workspace, "repo");
  const prepare = buildDefaultSolver({ spine, model, workspace, runnerFor: forbidden });
  const build = (binding = "a".repeat(64), cost = 0, executionAvailable = false) => buildAutonomyLoop({ spine, checkpoints,
    solve: forbidden, repoRef: "repo", projectWorkspace: { files: forbidden, tree: forbidden },
    softwarePreparation: { binding, workspace, editor, solve: prepare },
    ...(executionAvailable ? { softwareOperation: { binding: "c".repeat(64), authorize: () => true } } : {}),
    estimatedActionCostUsd: cost, spendCap: { canAfford: () => false },
  });
  return { build, spine, workspace, checkpoints, counts: () => ({ calls, effects }) };
}

test("ordinary held billing goal prepares without effects; resume cannot execute or repeat the model", async () => {
  const fixture = preparationFixture(), loop = fixture.build();
  const goal = "Correct the invoice retry limit in billing.ts according to the retained policy and pending task.";
  const result = await loop.runProject(goal, { runId: "billing", stepBudget: 50 });
  assert.equal(result.state.status, "waiting-capability"); assert.equal(result.state.stage, "implement");
  const output = result.state.artifacts["implement"] as { solve: import("../src/solve/issue_model.js").SolveResult; admittedEditPrepared?: unknown };
  assert.equal(output.solve.preparedProposal?.disposition, "unexecuted", JSON.stringify(result.state));
  assert.equal(output.solve.solved, false); assert.equal(output.admittedEditPrepared, undefined);
  assert.equal(output.solve.admittedEdit, undefined); assert.equal(output.solve.recovery?.planningCalls, 1);
  assert.equal(result.state.goal, goal);
  const resumed = await fixture.build(undefined, 0, true).resumeProject("billing", {
    capability: { capability: "project-execution-admission", evidenceId: "generic-owner-approval" },
  });
  assert.equal(resumed.state.status, "waiting-capability"); assert.equal(resumed.state.stage, "implement");
  assert.deepEqual(fixture.counts(), { calls: 1, effects: 0 });
  assert.equal(await fixture.workspace.tree("repo").read("billing.ts"), "export const retryLimit = 0;\n");
});

test("separately admitted execution replans under the original run budget and retains inert preparation", async () => {
  const fixture = preparationFixture();
  const first = await fixture.build().runProject("Correct the invoice retry limit in billing.ts.", { runId: "phase", stepBudget: 50 });
  const original = first.state.artifacts["implement"];
  let calls = 0;
  const model = { name: "execution-fixture", isLocal: true, embed: async () => [], generate: async () => {
    calls++; return { text: JSON.stringify({ action: "plan", rationale: "fresh execution plan", edits: [
      { file: "billing.ts", search: "retryLimit = 0", replace: "retryLimit = 9", intent: "fresh source admission" },
    ] }), model: "execution-fixture", tokensIn: 1, tokensOut: 1 };
  } };
  const editor = buildModelProjectEditPlanner(model, fixture.workspace, "repo");
  const loop = buildAutonomyLoop({ spine: fixture.spine, checkpoints: fixture.checkpoints, repoRef: "repo",
    projectWorkspace: fixture.workspace, projectEditor: editor, solveConsumesAdmittedEdit: true,
    softwarePreparation: { binding: "a".repeat(64), workspace: fixture.workspace, editor, solve: async () => { throw new Error("preparation replayed"); } },
    softwareOperation: { binding: "c".repeat(64), authorize: () => true },
    solve: buildDefaultSolver({ spine: fixture.spine, model, workspace: fixture.workspace,
      runnerFor: (_repo, tree) => validatorRunner(tree, async t => (await t.read("billing.ts"))?.includes("retryLimit = 9") === true) }),
  });
  const result = await loop.resumeProject("phase");
  const solve = (result.state.artifacts["implement"] as { solve: import("../src/solve/issue_model.js").SolveResult }).solve;
  assert.equal(solve.solved, true, JSON.stringify(result.state));
  assert.equal(await fixture.workspace.tree("repo").read("billing.ts"), "export const retryLimit = 9;\n", "old prepared seven is never applied");
  assert.equal(calls, 1); assert.equal(fixture.counts().calls, 1);
  assert.equal(solve.recovery?.attempts, 2); assert.equal(solve.recovery?.planningCalls, 2);
  assert.equal(solve.recovery?.deadline, (original as { solve: import("../src/solve/issue_model.js").SolveResult }).solve.recovery?.deadline);
  assert.deepEqual(result.state.artifacts["software_prepared_implementation"], original);
  assert.deepEqual(result.state.artifacts["software_preparation"], first.state.artifacts["software_preparation"]);
  assert.equal(result.state.runId, first.state.runId); assert.equal(result.state.goal, first.state.goal);
  assert.ok(result.state.stepsRemaining < first.state.stepsRemaining);
  await loop.resumeProject("phase"); assert.equal(calls, 1, "completed observation does not replan");
});

test("prepared execution admission cannot clear expired budgets, holds, changed bindings or lower posture", async () => {
  for (const defect of ["expired", "exhausted", "authority", "pending", "binding", "posture"] as const) {
    const fixture = preparationFixture();
    const first = await fixture.build().runProject("Correct the invoice retry limit in billing.ts.", { runId: defect, stepBudget: 50 });
    const previous = first.state.artifacts["implement"] as { solve: import("../src/solve/issue_model.js").SolveResult };
    const recovery = previous.solve.recovery!;
    const changed = defect === "expired" ? { deadline: 0 } : defect === "exhausted" ? { planningCalls: recovery.maxPlanningCalls }
      : defect === "authority" ? { status: "authority" as const } : defect === "pending" ? { pendingAttemptId: "unresolved" } : {};
    fixture.checkpoints.save({ ...first.state, revision: first.state.revision + 1,
      ...(defect === "posture" ? { posture: "approval-required" as const } : {}),
      artifacts: { ...first.state.artifacts, implement: { ...previous, solve: { ...previous.solve, recovery: { ...recovery, ...changed } } } },
    }, first.state.revision);
    const held = await fixture.build(defect === "binding" ? "b".repeat(64) : undefined, 0, true).resumeProject(defect);
    assert.equal(held.state.status, "waiting-capability");
    assert.equal(held.state.artifacts["software_operation"], undefined);
    assert.deepEqual(fixture.counts(), { calls: 1, effects: 0 });
  }
});

test("native repository operation keeps the exact goal and rechecks authority on resumed stages", async () => {
  const goal = "Correct the invoice retry limit in billing.ts according to the retained policy and pending task.";
  for (const defect of ["revoked", "missing", "changed", "malformed", "valid"] as const) {
    const spine = newSpine(), checkpoints = new InMemoryProjectCheckpointStore();
    let current = true, calls = 0;
    const build = (binding = "a".repeat(64)) => buildAutonomyLoop({ spine, checkpoints, loopConfig: { maxRework: 0 }, softwareOperation: {
      binding, authorize: (runId, _projectId, requested) => current && runId === defect && requested === goal,
    }, solve: async issue => { calls++; return { solveResult: { issueId: issue.id, solved: false, stagesRun: [], repairRounds: 0 } }; } });
    const first = await build().runProject(goal, { runId: defect, stepBudget: 2 });
    assert.equal(first.state.status, "paused-budget"); assert.equal(first.state.goal, goal);
    assert.deepEqual(first.state.artifacts["software_operation"], { schemaVersion: 1, binding: "a".repeat(64) });
    assert.equal(calls, 0);
    if (defect === "revoked") current = false;
    if (defect === "missing" || defect === "malformed") {
      const artifacts = { ...first.state.artifacts };
      if (defect === "missing") delete artifacts["software_operation"];
      else artifacts["software_operation"] = { schemaVersion: 2, binding: "a".repeat(64) };
      checkpoints.save({ ...first.state, revision: first.state.revision + 1, artifacts }, first.state.revision);
    }
    const resumed = await build(defect === "changed" ? "b".repeat(64) : undefined).resumeProject(defect, { addSteps: 30 });
    assert.equal(resumed.state.status, "waiting-capability");
    assert.equal(calls, defect === "valid" ? 1 : 0);
    assert.equal(resumed.state.runId, defect); assert.equal(resumed.state.goal, goal);
  }
});

test("native repository operation cannot bypass cost or lower-posture admission", async () => {
  for (const posture of ["autonomous", "approval-required"] as const) {
    let calls = 0;
    const loop = buildAutonomyLoop({ spine: newSpine(), posture,
      softwareOperation: { binding: "a".repeat(64), authorize: () => true },
      spendCap: { canAfford: () => false }, estimatedActionCostUsd: 5,
      solve: async () => { calls++; throw new Error("not authorized"); },
    });
    const result = await loop.runProject("Correct the invoice retry limit in billing.ts.");
    assert.equal(result.state.status, posture === "autonomous" ? "paused-budget" : "waiting-approval");
    assert.equal(calls, 0);
  }
});

test("a denied native resume preserves the earlier attempt instead of overwriting its accounting", async () => {
  const spine = newSpine(), checkpoints = new InMemoryProjectCheckpointStore();
  let current = true;
  const loop = buildAutonomyLoop({ spine, checkpoints,
    softwareOperation: { binding: "a".repeat(64), authorize: () => current },
    solve: async () => { throw new Error("denied operation dispatched"); },
  });
  const initial = await loop.runProject("Correct the invoice retry limit in billing.ts.", { runId: "retained", stepBudget: 1 });
  const previous = { solve: { solved: false, recovery: { planningCalls: 1, status: "authority" } } };
  checkpoints.save({ ...initial.state, stage: "implement", revision: initial.state.revision + 1,
    artifacts: { ...initial.state.artifacts, implement: previous } }, initial.state.revision);
  current = false;
  const held = await loop.resumeProject("retained", { addSteps: 10 });
  assert.equal(held.state.status, "waiting-capability");
  assert.deepEqual(held.state.artifacts["implement"], previous);
  assert.match(held.state.note!, /authority/u);
});

test("preparation survives a paused phase but rejects changed or missing persisted bindings", async () => {
  for (const defect of ["changed", "missing", "malformed"] as const) {
    const fixture = preparationFixture();
    const first = await fixture.build().runProject("Correct the invoice retry limit in billing.ts.", { runId: defect, stepBudget: 2 });
    assert.equal(first.state.status, "paused-budget"); assert.deepEqual(fixture.counts(), { calls: 0, effects: 0 });
    if (defect !== "changed") {
      const artifacts = { ...first.state.artifacts };
      if (defect === "missing") delete artifacts["software_preparation"];
      else artifacts["software_preparation"] = { schemaVersion: 2, binding: "a".repeat(64) };
      fixture.checkpoints.save({ ...first.state, revision: first.state.revision + 1, artifacts }, first.state.revision);
    }
    const next = await fixture.build(defect === "changed" ? "b".repeat(64) : undefined).resumeProject(defect, { addSteps: 20 });
    assert.equal(next.state.status, "waiting-capability");
    assert.deepEqual(fixture.counts(), { calls: 0, effects: 0 });
  }
});

test("preparation respects the spend cap and never completes payment or mixed-effect goals", async () => {
  const capped = preparationFixture();
  const blocked = await capped.build(undefined, 5).runProject("Correct the invoice retry limit in billing.ts.");
  assert.equal(blocked.state.status, "paused-budget"); assert.deepEqual(capped.counts(), { calls: 0, effects: 0 });
  for (const goal of ["Pay the invoice.", "Correct billing.ts and pay the invoice."]) {
    const fixture = preparationFixture();
    const result = await fixture.build().runProject(goal, { stepBudget: 50 });
    assert.notEqual(result.state.status, "completed"); assert.equal(fixture.counts().effects, 0);
    assert.equal(await fixture.workspace.tree("repo").read("billing.ts"), "export const retryLimit = 0;\n");
  }
});

test("task memory capability is per-run control, never persisted; missing capability cannot consume a resume signal", async () => {
  const spine = newSpine(), checkpoints = new InMemoryProjectCheckpointStore();
  const memory: TaskMemoryContext = { copyNotice: "outside-copy limitation", assertCurrent() {}, select: () => ({ prompt: "private memory text", metrics: {} }),
    checkpoint: () => ({ schema: "keep.task-memory-snapshot/v1", status: "current", revision: 1, erasureCount: 0, observedAt: 1, validUntil: null }), restore() {} };
  let calls = 0;
  const executors = allExecutors({ understand: async (_state, control) => { calls++; assert.equal(control?.memoryContext, memory); return adv("understood"); } });
  const first = new ProjectLoop(spine, narrator(spine), executors, { stepBudget: 0 }, undefined, undefined, checkpoints, Date.now, undefined, undefined, undefined, memory);
  const paused = await first.run(first.init("memory-resume", "goal"));
  assert.equal(paused.state.artifacts["memory_context_required"], true);
  assert.doesNotMatch(JSON.stringify(paused.state), /private memory text|assertCurrent|select/);
  const without = new ProjectLoop(spine, narrator(spine), executors, {}, undefined, undefined, checkpoints);
  await assert.rejects(without.resume("memory-resume", { addSteps: 1 }), /selected task memory unavailable/);
  assert.deepEqual(checkpoints.load("memory-resume"), paused.state, "failed reconstruction cannot consume budget/resume authority");
  assert.equal(calls, 0);
  const restored = new ProjectLoop(spine, narrator(spine), executors, {}, undefined, undefined, checkpoints, Date.now, undefined, undefined, undefined, memory);
  await restored.resume("memory-resume", { addSteps: 1 }); assert.equal(calls, 1);
});

test("operator cancellation before a stage dispatches nothing and remains a resumable non-success", async () => {
  const spine = newSpine(), controller = new AbortController(); controller.abort();
  let calls = 0;
  const loop = new ProjectLoop(spine, narrator(spine), allExecutors({ understand: async () => { calls++; return adv("must not run"); } }), {}, undefined, undefined, undefined, Date.now, undefined, controller.signal);
  const result = await loop.run(loop.init("cancel-before", "goal"));
  assert.equal(calls, 0); assert.equal(result.state.status, "waiting-capability");
  assert.equal(result.state.wait?.kind, "capability"); assert.deepEqual(result.visited, []);
});

test("operator cancellation inside a stage discards late output, charges the step and preserves its effect identity", async () => {
  const spine = newSpine(), controller = new AbortController(); let nextCalls = 0;
  const loop = new ProjectLoop(spine, narrator(spine), allExecutors({
    understand: async (_state, control) => { assert.equal(control?.signal, controller.signal); controller.abort(); return adv("late output must not be accepted"); },
    research: async () => { nextCalls++; return adv("must not run"); },
  }), { stepBudget: 10 }, undefined, undefined, undefined, Date.now, undefined, controller.signal);
  const result = await loop.run(loop.init("cancel-during", "goal"));
  assert.equal(nextCalls, 0); assert.equal(result.state.status, "waiting-reconciliation");
  assert.deepEqual(result.state.artifacts, {}); assert.equal(result.state.stepsRemaining, 9);
  assert.equal(result.state.wait?.kind, "reconciliation");
  assert.deepEqual(loop.restore("cancel-during"), result.state);
});

test("a project runs the full stage sequence in deterministic order to completion", async () => {
  const spine = newSpine();
  // Pass-through executors for every non-optional stage.
  const executors = allExecutors();
  const loop = new ProjectLoop(spine, narrator(spine), executors);
  const { state, visited } = await loop.run(loop.init("run", "write a romance novel"));
  assert.equal(state.status, "completed");
  assert.equal(state.stage, "done");
  // rag is optional and skipped in the default path.
  assert.deepEqual(visited, ["understand", "research", "plan", "vet_plan", "ticket", "implement", "vet_artifact", "learn"]);
});

test("the runtime controls advancement — one 'advance' moves exactly one stage", async () => {
  const spine = newSpine();
  const loop = new ProjectLoop(spine, narrator(spine), { understand: async () => adv("ok") });
  const s0 = loop.init("r", "goal");
  assert.equal(s0.stage, "understand");
  // Run with only 'understand' defined; the next missing prerequisite must not be fabricated.
  const { state } = await loop.run(s0);
  assert.equal(state.stage, "research");
  assert.equal(state.status, "waiting-capability");
});

test("a vet stage can route work BACK (no blind error cascade)", async () => {
  const spine = newSpine();
  let planCount = 0;
  const executors: StageExecutors = allExecutors({
    plan: async () => {
      planCount++;
      return adv(`plan attempt ${planCount}`);
    },
    vet_plan: async (): Promise<StageResult> =>
      planCount < 2
        ? { output: "rejected", control: "rework", reworkTo: "plan", headline: "Plan needs work — sending back" }
        : { output: "accepted", control: "advance", headline: "Plan looks good now" },
  });
  const loop = new ProjectLoop(spine, narrator(spine), executors);
  const { state } = await loop.run(loop.init("r", "goal"));
  assert.equal(state.status, "completed");
  assert.equal(planCount, 2); // plan ran twice: once, rejected, reworked, accepted
});

test("the runtime-held step budget forces a clean paused-budget checkpoint (runaway guard)", async () => {
  const spine = newSpine();
  // An executor that always reworks would loop forever WITHOUT the budget cap.
  const executors: StageExecutors = {
    understand: async () => adv("u"),
    research: async (): Promise<StageResult> => ({ output: "loop", control: "rework", reworkTo: "understand", headline: "again" }),
  };
  const loop = new ProjectLoop(spine, narrator(spine), executors, { stepBudget: 5, maxRework: 999 });
  const { state } = await loop.run(loop.init("r", "goal"));
  assert.equal(state.status, "paused-budget"); // runtime stopped it; the model could not spend past the cap
  assert.ok(state.stepsRemaining <= 0);
});

test("repeated rework beyond maxRework becomes resumable strategy debt (anti-thrash without rubber-stamping)", async () => {
  const spine = newSpine();
  const executors: StageExecutors = allExecutors({
    plan: async () => adv("plan"),
    vet_plan: async (): Promise<StageResult> => ({ output: "no", control: "rework", reworkTo: "plan", headline: "still not right" }),
  });
  const loop = new ProjectLoop(spine, narrator(spine), executors, { maxRework: 2, stepBudget: 100 });
  const { state } = await loop.run(loop.init("r", "goal"));
  assert.equal(state.status, "waiting-capability");
  assert.equal(state.wait?.kind, "capability");
});

test("a missing executor is exact capability debt and never silently advances", async () => {
  const spine = newSpine();
  const loop = new ProjectLoop(spine, narrator(spine), {}); // no executors at all
  const { state, visited } = await loop.run(loop.init("r", "goal"));
  assert.equal(state.status, "waiting-capability");
  assert.equal(state.stage, "understand");
  assert.deepEqual(visited, ["understand"]);
});

test("a missing executor resumes only after exact capability-change evidence", async () => {
  const spine = newSpine();
  const executors: StageExecutors = {};
  const loop = new ProjectLoop(spine, narrator(spine), executors);
  const first = await loop.run(loop.init("cap", "goal"));
  const unchanged = await loop.resume("cap");
  assert.equal(unchanged.state.revision, first.state.revision, "bare resume is idempotent and does not probe");
  executors.understand = async () => adv("installed");
  const resumed = await loop.resume("cap", { capability: { capability: "project-stage:understand", evidenceId: "executor-v1-installed" } });
  assert.equal(resumed.state.stage, "research");
  assert.equal(resumed.state.wait?.kind, "capability");
});

test("an unclassified throwing executor preserves its effect and requires matching reconciliation", async () => {
  const spine = newSpine();
  const executors: StageExecutors = {
    research: async () => {
      throw new Error("search backend down");
    },
  };
  const loop = new ProjectLoop(spine, narrator(spine), { understand: async () => adv("u"), ...executors });
  const { state } = await loop.run(loop.init("r", "goal"));
  assert.equal(state.status, "waiting-reconciliation");
  assert.ok(state.note!.includes("search backend down"));
  assert.equal((await loop.resume("r")).state.revision, state.revision);
  assert.equal((await loop.resume("r", { reconciliation: { effectId: "wrong", resolved: true, evidenceId: "observed" } })).state.revision, state.revision);
  const effectId = state.wait?.kind === "reconciliation" ? state.wait.effectId : "";
  const resumed = await loop.resume("r", { reconciliation: { effectId, resolved: true, evidenceId: "sink-observed-no-effect" } });
  assert.ok(resumed.state.consumedSignals.includes(`reconciliation:${effectId}:sink-observed-no-effect`));
  assert.equal(resumed.state.status, "waiting-reconciliation", "a second unknown throw needs its own evidence");
  assert.notEqual(resumed.state.wait?.kind === "reconciliation" ? resumed.state.wait.effectId : "", effectId);
});

test("retry is not invoked early and cannot exceed the run-wide budget through resume", async () => {
  const spine = newSpine();
  let now = 1_000;
  let calls = 0;
  const store = new InMemoryProjectCheckpointStore();
  const loop = new ProjectLoop(spine, narrator(spine), { understand: async () => { calls += 1; return { output: {}, control: "retry", headline: "read-only backend observed unavailable; safe to repeat" }; } }, { retryRunLimit: 2, retryPerStageLimit: 2, retryBaseDelayMs: 10, retryMaxDelayMs: 10 }, undefined, undefined, store, () => now);
  let result = await loop.run(loop.init("retry", "goal"));
  assert.equal(calls, 1);
  const early = await loop.resume("retry");
  assert.equal(early.state.revision, result.state.revision);
  assert.equal(calls, 1);
  now = (result.state.wait?.kind === "retry" ? result.state.wait.resumeAt : now);
  result = await loop.resume("retry");
  assert.equal(calls, 2);
  now = result.state.wait?.kind === "retry" ? result.state.wait.resumeAt : now;
  result = await loop.resume("retry");
  assert.equal(calls, 3);
  assert.equal(result.state.status, "waiting-capability");
  for (let i = 0; i < 5; i += 1) result = await loop.resume("retry", { capability: { capability: "recovery:understand", evidenceId: "same-recovery" } });
  assert.equal(calls, 3, "exhausted retry budget cannot be bypassed through capability resumes");
});

test("shipped per-stage retry limit cannot be bypassed when the larger run limit has not bound", async () => {
  const spine = newSpine();
  let now = 1_000;
  let calls = 0;
  const loop = new ProjectLoop(spine, narrator(spine), { understand: async () => { calls += 1; return { output: {}, control: "retry", headline: "read-only backend observed unavailable; safe to repeat" }; } }, { retryBaseDelayMs: 1, retryMaxDelayMs: 1 }, undefined, undefined, new InMemoryProjectCheckpointStore(), () => now);
  let result = await loop.run(loop.init("default-retry", "goal"));
  while (result.state.wait?.kind === "retry") { now = result.state.wait.resumeAt; result = await loop.resume("default-retry"); }
  assert.equal(calls, 4, "initial attempt plus three configured retries");
  assert.equal(result.state.status, "waiting-capability");
  assert.equal(result.state.stepsRemaining, 96, "classified retries still consume the hard step budget");
  for (let i = 0; i < 10; i += 1) result = await loop.resume("default-retry", { capability: { capability: "recovery:understand", evidenceId: `probe-${i}` } });
  assert.equal(calls, 4);
});

test("runtime CAS loser loads the winner and does not execute or overwrite it", async () => {
  const spine = newSpine();
  const inner = new InMemoryProjectCheckpointStore();
  let raced = false;
  const store: ProjectCheckpointStore = {
    load: (runId) => inner.load(runId),
    save: (next, expected) => {
      if (!raced && next.revision === 1) {
        raced = true;
        const wait = { kind: "capability" as const, activity: next.stage, createdAt: 1, capability: "winner-capability", resumeAuthority: "work" as const, reason: "competing winner" };
        inner.save({ ...next, status: "waiting-capability", wait, note: wait.reason }, expected);
      }
      return inner.save(next, expected);
    },
  };
  let calls = 0;
  const loop = new ProjectLoop(spine, narrator(spine), { understand: async () => { calls += 1; return adv("must not run"); } }, {}, undefined, undefined, store);
  const result = await loop.run(loop.init("race", "goal"));
  assert.equal(calls, 0);
  assert.equal(result.state.status, "waiting-capability");
  assert.equal(result.state.wait?.kind === "capability" ? result.state.wait.capability : "", "winner-capability");
  assert.deepEqual(store.load("race"), result.state);
});

test("invalid rework target and unknown control fail without false completion or repeated execution", async () => {
  const spine = newSpine();
  const jump = new ProjectLoop(spine, narrator(spine), { understand: async () => ({ output: {}, control: "rework", reworkTo: "done", headline: "skip" }) });
  const jumped = await jump.run(jump.init("jump", "goal"));
  assert.equal(jumped.state.status, "failed");
  assert.equal(jumped.state.stage, "understand");
  let calls = 0;
  const unknown = new ProjectLoop(spine, narrator(spine), { understand: async () => { calls += 1; return { output: {}, control: "unknown" as StageResult["control"], headline: "bad" }; } });
  const bad = await unknown.run(unknown.init("unknown", "goal"));
  assert.equal(bad.state.status, "failed");
  assert.equal(calls, 1);
});

test("oversized step charge clamps to a durable budget pause instead of corrupting state", async () => {
  const spine = newSpine();
  const loop = new ProjectLoop(spine, narrator(spine), { understand: async () => ({ ...adv("expensive"), stepsUsed: 50 }) }, { stepBudget: 3 });
  const result = await loop.run(loop.init("cost", "goal"));
  assert.equal(result.state.status, "paused-budget");
  assert.equal(result.state.stepsRemaining, 0);
});

test("checkpoint ceiling failure is durable and never re-executes an oversized stage", async () => {
  const spine = newSpine();
  let calls = 0;
  const loop = new ProjectLoop(spine, narrator(spine), {
    understand: async () => { calls += 1; return { output: { oversized: "x".repeat(17 * 1024 * 1024) }, control: "advance", headline: "large" }; },
  });
  const result = await loop.run(loop.init("checkpoint-ceiling", "produce a very large artifact"));
  assert.equal(result.state.status, "failed");
  assert.match(result.state.note ?? "", /durable checkpoint ceiling/u);
  assert.equal(calls, 1);
  const resumed = await loop.resume("checkpoint-ceiling");
  assert.equal(resumed.state.status, "failed");
  assert.equal(calls, 1);
});

test("installed file store persists normalized stage artifacts and restores them through a fresh loop", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-loop-file-"));
  const spine = newSpine();
  const store = new FileProjectCheckpointStore(dir);
  const executors: StageExecutors = { understand: async () => ({ output: { kept: true, omitted: undefined }, control: "advance", headline: "ok" }) };
  const firstLoop = new ProjectLoop(spine, narrator(spine), executors, {}, undefined, undefined, store);
  const first = await firstLoop.run(firstLoop.init("disk", "goal", "policy-calibrated"));
  assert.equal(first.state.status, "waiting-capability");
  const secondLoop = new ProjectLoop(spine, narrator(spine), executors, {}, undefined, undefined, new FileProjectCheckpointStore(dir));
  const restored = secondLoop.restore("disk")!;
  assert.equal(restored.posture, "policy-calibrated");
  assert.deepEqual(restored.artifacts["understand"], { kept: true });
  assert.deepEqual(restored.retry, first.state.retry);
  assert.deepEqual(restored.wait, first.state.wait);
});

test("every transition is checkpointed to the spine (resumable + auditable)", async () => {
  const spine = newSpine();
  const loop = new ProjectLoop(spine, narrator(spine), allExecutors());
  await loop.run(loop.init("r", "goal"));
  await spine.seal();
  const checkpoints = spine.replay().filter((e) => (e.payload as Record<string, unknown>)["event"] === "project.checkpoint");
  assert.ok(checkpoints.length >= 3); // init + several transitions + completed
});

test("a paused-budget run resumes from where it left off", async () => {
  const spine = newSpine();
  const executors: StageExecutors = {
    understand: async () => adv("u"),
    research: async () => adv("r"),
    plan: async () => adv("p"),
    vet_plan: async () => adv("v"),
    ticket: async () => adv("t"),
    implement: async () => adv("i"),
    vet_artifact: async () => adv("va"),
    learn: async () => adv("l"),
  };
  const loop = new ProjectLoop(spine, narrator(spine), executors, { stepBudget: 3, maxRework: 3 });
  const first = await loop.run(loop.init("r", "goal"));
  assert.equal(first.state.status, "paused-budget");
  // Resume from the authoritative store with a top-up, never from caller-mutated state.
  const resumed = await loop.resume("r", { addSteps: 50 });
  assert.equal(resumed.state.status, "completed");
});

test("need-rag routes into the optional rag stage", async () => {
  const spine = newSpine();
  let ragRan = false;
  const executors: StageExecutors = allExecutors({
    research: async (): Promise<StageResult> => ({ output: "need corpus", control: "need-rag", headline: "Building a knowledge base first" }),
    rag: async () => {
      ragRan = true;
      return adv("corpus built");
    },
  });
  const loop = new ProjectLoop(spine, narrator(spine), executors);
  await loop.run(loop.init("r", "goal"));
  assert.equal(ragRan, true);
});

test("stageOrder exposes the canonical sequence", () => {
  assert.equal(stageOrder()[0], "understand");
  assert.equal(stageOrder()[stageOrder().length - 1], "done");
});

import { NonPersistableRegistry } from "../src/scheduler/saga_sequencer.js";

test("NON-PERSISTABLE (isolation): the stage executor runs inside a region — no checkpoint can land mid-side-effect", async () => {
  const spine = newSpine();
  const registry = new NonPersistableRegistry(spine);
  let couldCheckpointDuringExecutor = true;
  const executors: StageExecutors = {
    understand: async () => {
      // We are mid-executor (a side effect could be in flight here) — a checkpoint must be refused right now.
      couldCheckpointDuringExecutor = registry.canCheckpoint();
      return adv("understood");
    },
  };
  const loop = new ProjectLoop(spine, narrator(spine), executors, {}, registry);
  await loop.run(loop.init("run", "goal"));
  assert.equal(couldCheckpointDuringExecutor, false, "a durable checkpoint is refused while the executor holds the region");
  assert.equal(registry.canCheckpoint(), true, "the region is released once the executor returns");
});

test("NON-PERSISTABLE (isolation): an already-open region durably becomes reconciliation, never execution", async () => {
  const spine = newSpine();
  const registry = new NonPersistableRegistry(spine);
  registry.enter("external-side-effect"); // simulate an outer side-effect region held across the run
  let invoked = false;
  const loop = new ProjectLoop(spine, narrator(spine), { understand: async () => { invoked = true; return adv("ok"); } }, {}, registry);
  const result = await loop.run(loop.init("run", "goal"));
  assert.equal(result.state.status, "waiting-reconciliation");
  assert.equal(invoked, false);
  const events = spine.currentEvents().map((e) => (e.payload as Record<string, unknown>)["event"]);
  assert.equal(events.filter((event) => event === "project.checkpoint").length, 2, "init plus durable reconciliation intent exist");
  const effectId = result.state.wait?.kind === "reconciliation" ? result.state.wait.effectId : "";
  registry.exit("external-side-effect");
  const resumed = await loop.resume("run", { reconciliation: { effectId, resolved: true, evidenceId: "sink-proved-not-committed" } });
  assert.equal(invoked, true);
  assert.ok(resumed.state.consumedSignals.includes(`reconciliation:${effectId}:sink-proved-not-committed`));
});

test("crash window: a fresh store sees reconciliation while an executor is in flight", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-loop-inflight-"));
  const spine = newSpine();
  let release!: () => void;
  const blocked = new Promise<void>((resolve) => { release = resolve; });
  const executors = allExecutors({ understand: async () => { await blocked; return adv("done"); } });
  const loop = new ProjectLoop(spine, narrator(spine), executors, {}, undefined, undefined, new FileProjectCheckpointStore(dir));
  const running = loop.run(loop.init("inflight", "goal"));
  await new Promise<void>((resolve) => setImmediate(resolve));
  const crashView = new FileProjectCheckpointStore(dir).load("inflight")!;
  assert.equal(crashView.status, "waiting-reconciliation");
  assert.equal(crashView.wait?.kind, "reconciliation");
  release();
  const completed = await running;
  assert.equal(completed.state.status, "completed");
});
