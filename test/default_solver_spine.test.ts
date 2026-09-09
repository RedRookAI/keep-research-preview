import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { InMemoryWorkspace, LocalFsWorkspace } from "../src/solve/workspace.js";
import { createProjectPlan } from "../src/autonomy/plan_stage.js";
import { buildDefaultSolver, validatorRunner, failClosedRunner } from "../src/solve/default_solver.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { FileTree } from "../src/solve/patch.js";

function newSpine() {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-solver-"))), new InProcessLock(), new SchemaRegistry());
}

// A scripted model: returns a strict-JSON edit plan that fixes the bug (deterministic stand-in for a frontier model).
function scriptedModel(planJson: string): ModelProvider {
  return {
    name: "scripted", isLocal: true,
    async generate(_req: GenerateRequest): Promise<GenerateResult> { return { text: planJson, model: "scripted", tokensIn: 0, tokensOut: 0 } as GenerateResult; },
    async embed(texts: readonly string[]): Promise<Embedding[]> { return texts.map(() => [0]); },
  };
}

const BUGGY = "export function add(a: number, b: number): number {\n  return a - b;\n}\n";
const FIXED = "export function add(a: number, b: number): number {\n  return a + b;\n}\n";
const planJson = JSON.stringify({
  rationale: "the operator should be + not -",
  edits: [{ file: "src/math.ts", search: "return a - b;", replace: "return a + b;", intent: "fix the operator" }],
});

test("SPINE (crown): a real ticket runs end-to-end through the composed default solver → a real PR proposal", async () => {
  const spine = newSpine();
  const ws = new InMemoryWorkspace({ "repo-1": { "src/math.ts": BUGGY } });
  const solve = buildDefaultSolver({
    spine, model: scriptedModel(planJson), workspace: ws,
    // the runner passes once the tree actually contains the fix — real validation over the patched tree
    runnerFor: (_ref, tree: FileTree) => validatorRunner(tree, async (t) => (await t.read("src/math.ts"))?.includes("a + b") ?? false),
  });

  const out = await solve({ id: "T-1", text: "add() returns a-b instead of a+b", repoRef: "repo-1" });

  assert.equal(out.solveResult.solved, true, "the ticket was solved end-to-end");
  assert.ok(out.solveResult.prProposal, "a PR proposal was produced (never auto-merged)");
  assert.equal(out.solveResult.validation?.testsPassed, true, "validation passed against the patched tree");
  // the fix actually landed in the workspace tree
  assert.equal((await ws.tree("repo-1").read("src/math.ts")), FIXED, "the workspace now holds the corrected code");
  // the trajectory is on the tamper-evident spine (localize + plan stages audited); seal to commit the block
  await spine.seal();
  const stages = spine.replay()
    .map((e: any) => e.payload as Record<string, unknown>)
    .filter((p) => p?.["issueId"] === "T-1")
    .map((p) => p?.["stage"]);
  assert.ok(stages.includes("localize") && stages.includes("plan"), "solve stages were audited to the tamper-evident spine");
});

test("FAIL-CLOSED: with the default runner, validation cannot pass on vacuous evidence", async () => {
  const spine = newSpine();
  const ws = new InMemoryWorkspace({ "repo-2": { "src/math.ts": BUGGY } });
  const solve = buildDefaultSolver({ spine, model: scriptedModel(planJson), workspace: ws }); // no runnerFor → fail-closed
  const out = await solve({ id: "T-2", text: "fix add()", repoRef: "repo-2" });
  assert.notEqual(out.solveResult.validation?.testsPassed, true, "no real runner ⇒ never reports verified");
});

test("WIRE: composeKeep with a workspace exposes an autonomy loop that BUILDS (no operator solver written)", async () => {
  const { composeKeep } = await import("../src/compose.js");
  let configuredTopK: number | undefined;
  let configuredPlannerCalls = 0;
  const workspace = new InMemoryWorkspace({ "r": { "src/math.ts": BUGGY } });
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-solver-wire-")),
    developmentProvider: scriptedModel(planJson),
    workspace,
    repoRef: "r",
    projectLocalizationTopK: 1,
    projectLocalizer: { async localize(_issue, _files, k) { configuredTopK = k; return { suspects: [{ path: "src/math.ts", score: 1, isTest: false }], stages: ["bm25"] }; } },
    projectPlanner: (state) => { configuredPlannerCalls += 1; return createProjectPlan(state); },
    solverRunnerFor: (_ref, tree) => validatorRunner(tree, async (t) => (await t.read("src/math.ts"))?.includes("a + b") ?? false),
  });
  assert.ok(app.autonomyLoop, "a workspace activates the built-in solver → autonomy loop present");
  const run = await app.autonomyLoop!.runProject("fix the add() operator bug", { runId: "rSolve", stepBudget: 50 });
  assert.ok(run.feasibility?.proceed, "a software fix is feasible");
  assert.equal(run.state.status, "completed");
  assert.equal(configuredTopK, 1, "composeKeep exposes the enterprise/personal localizer contract and bound");
  assert.equal(configuredPlannerCalls, 1, "composeKeep reaches the configured personal/enterprise planner seam");
  assert.equal((run.state.artifacts.plan as { localization?: { selected?: readonly { path?: string }[] } }).localization?.selected?.[0]?.path, "src/math.ts");
  assert.deepEqual((run.state.artifacts.plan as { steps?: readonly { id?: string }[] }).steps?.map((step) => step.id), ["implement", "verify"]);
  assert.equal((run.state.artifacts.vet_plan as { proceed?: boolean }).proceed, true, "installed composition consumes the plan through deterministic critics");
  assert.equal(await workspace.tree("r").read("src/math.ts"), FIXED, "the installed surface actually modifies the configured repository");
});

test("LocalFsWorkspace: reads + writes a real on-disk repo, project-jailed", async () => {
  const base = mkdtempSync(join(tmpdir(), "keep-fsws-"));
  mkdirSync(join(base, "repoA", "src"), { recursive: true });
  writeFileSync(join(base, "repoA", "src", "math.ts"), BUGGY);
  const ws = new LocalFsWorkspace(base);
  const files = await ws.files("repoA");
  assert.ok(files.some((f) => f.path.endsWith("math.ts")), "reads real files");
  await ws.tree("repoA").write("src/math.ts", FIXED);
  assert.equal(await ws.tree("repoA").read("src/math.ts"), FIXED, "writes real files");
  // path-jail: a traversal escape is rejected
  await assert.rejects(() => ws.tree("repoA").write("../escape.ts", "x"), /escape/i);
});

test("failClosedRunner reports a runner error (never a silent pass)", async () => {
  const r = await failClosedRunner("boom").run("ref");
  assert.equal(r.runnerError, "boom");
  assert.equal(r.results.length, 0);
});
