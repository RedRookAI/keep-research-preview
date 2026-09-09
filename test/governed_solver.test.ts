import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";

import { InMemoryWorkspace } from "../src/solve/workspace.js";
import { buildDefaultSolver, withGovernance, validatorRunner } from "../src/solve/default_solver.js";
import { buildVettingGates } from "../src/cascade/vetting_gates.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { FileTree } from "../src/solve/patch.js";
import type { Issue, SolveResult, SearchReplaceEdit } from "../src/solve/issue_model.js";
import type { SolveToPrResult } from "../src/pipeline/keep_pipeline.js";
import type { SolveFn } from "../src/loop/review_intake.js";
import { projectRepositoryTreeSha256 } from "../src/autonomy/project_localization.js";

function newSpine() {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-gov-"))), new InProcessLock(), new SchemaRegistry());
}
// A stub solver returning a controlled proposal — isolates the GOVERNANCE decision from localizer/planner mechanics.
function stubSolver(edits: readonly SearchReplaceEdit[] | null, testsPassed = true): SolveFn {
  return async (issue: Issue): Promise<SolveToPrResult> => {
    const solveResult: SolveResult = {
      issueId: issue.id, solved: edits !== null, stagesRun: [], repairRounds: 0,
      validation: { testsPassed, failures: [], vettingCleared: false, detail: "stub" } as never,
      ...(edits ? { prProposal: { title: "t", body: "b", branch: "keep/solve/x", edits, testsPassed } } : {}),
    };
    return { solveResult };
  };
}
function govern(solve: SolveFn, spine = newSpine()) {
  const gates = buildVettingGates({ capability: "none" });
  return withGovernance(solve, { vetPatch: gates.vetPatch, spine });
}
const ISSUE: Issue = { id: "G", text: "fix", repoRef: "repo" };
const cleanEdit: SearchReplaceEdit = { file: "src/math.ts", search: "a - b", replace: "a + b", intent: "fix" };

test("GOVERNED (crown): a clean, verified, reversible fix → AUTONOMOUS-MERGE (no human bothered)", async () => {
  const out = await govern(stubSolver([cleanEdit], true))(ISSUE);
  assert.ok(out.mergeAuthority, "the output carries a governed merge-authority decision");
  assert.equal(out.mergeAuthority!.verdict, "autonomous-merge", "verified + reversible + low-blast → merge without a human");
});

test("MISSION: a heuristic concern (scope-creep, 15 edits) on a REVERSIBLE change → ABANDON-RETRY, never a human", async () => {
  const edits = Array.from({ length: 15 }, (_, i) => ({ file: `src/m${i}.ts`, search: `a${i}`, replace: `b${i}`, intent: "bump" }));
  const out = await govern(stubSolver(edits, true))(ISSUE);
  assert.equal(out.mergeAuthority!.verdict, "abandon-retry", "unverified (scope-creep) + reversible → dropped autonomously, NOT a human");
  assert.ok(out.abandoned, "the abandon is recorded (auditable), not a human interrupt");
  assert.match(out.abandoned!.reason, /patch-verifier/u, "the bounded retry receives the concrete verification concern");
});

test("SOUND FAIL: a test-file edit is BLOCKED outright (never mergeable, never a human judgement call)", async () => {
  const edits = [cleanEdit, { file: "src/math.test.ts", search: "toBe(1)", replace: "toBe(2)", intent: "game" }];
  const out = await govern(stubSolver(edits, true))(ISSUE);
  assert.equal(out.mergeAuthority!.verdict, "block", "oracle-gaming (test-file edit) is a sound fail → blocked");
});

test("NO PROPOSAL: a gave-up solve is passed through ungoverned (nothing to decide)", async () => {
  const out = await govern(stubSolver(null))(ISSUE);
  assert.equal(out.mergeAuthority, undefined, "no proposal → no governed decision");
});

test("VERIFIED CONSEQUENTIAL → HUMAN-MERGE: a clean, passing, but irreversible change → the owner owns the merge", async () => {
  // A single large deletion is clean (no heuristic/sound flag) and tests pass → verified; but it's irreversible
  // (looksDestructive) → consequential → a person must own it. Consequence gates the human here, not confidence.
  const bigDelete: SearchReplaceEdit = { file: "src/core.ts", search: "x".repeat(60), replace: "", intent: "remove dead block" };
  const out = await govern(stubSolver([bigDelete], true))(ISSUE);
  assert.equal(out.mergeAuthority!.verdict, "human-merge", "verified + irreversible → a person decides (not auto, not abandoned)");
  assert.equal(out.mergeAuthority!.verified, true);
});

// ── real end-to-end through the composed pipeline ──
const BUGGY = "export function add(a: number, b: number): number {\n  return a - b;\n}\n";
function scriptedModel(planJson: string): ModelProvider {
  return { name: "s", isLocal: true,
    async generate(_r: GenerateRequest): Promise<GenerateResult> { return { text: planJson, model: "s", tokensIn: 0, tokensOut: 0 } as GenerateResult; },
    async embed(t: readonly string[]): Promise<Embedding[]> { return t.map(() => [0]); } };
}
const cleanPlan = JSON.stringify({ rationale: "fix", edits: [{ file: "src/math.ts", search: "return a - b;", replace: "return a + b;", intent: "fix" }] });
const passRunner = (_ref: string, tree: FileTree) => validatorRunner(tree, async (t) => (await t.read("src/math.ts"))?.includes("a + b") ?? false);

test("WIRE (end-to-end): composeKeep + runProject → a real solve → a governed merge decision on the spine", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-gov-wire-")),
    developmentProvider: scriptedModel(cleanPlan),
    workspace: new InMemoryWorkspace({ "app-repo": { "src/math.ts": BUGGY } }),
    repoRef: "app-repo",
    solverRunnerFor: passRunner,
  });
  const run = await app.autonomyLoop!.runProject("fix the add() operator so it returns a+b", { runId: "rGov", stepBudget: 50 });
  assert.ok(run.feasibility?.proceed, "feasible software fix");
  await app.spine.seal();
  const decision = app.spine.replay().map((e: any) => e.payload).find((p: any) => p?.event === "merge_authority");
  assert.ok(decision, "a governed merge-authority decision was audited during the run");
  assert.ok(["autonomous-merge", "human-merge", "abandon-retry", "block"].includes(decision.verdict), "it is a real governed verdict");
});

test("BUILT-IN COMPENSATION: an abandon-retry verdict restores the pre-edit workspace before returning", async () => {
  const spine = newSpine();
  const original = "export function values(xs: string[]) {\n  return xs;\n}\n";
  const replacement = "export function values(xs: string[]) {\n  const out = [];\n  for (const x of xs) {\n    if (!x) continue;\n    out.push(x);\n  }\n  return out;\n}\n";
  const workspace = new InMemoryWorkspace({ repo: { "src/values.ts": original } });
  const model = scriptedModel(JSON.stringify({ rationale: "filter empties", edits: [{ file: "src/values.ts", search: original, replace: replacement, intent: "filter empty values" }] }));
  const gates = buildVettingGates({ capability: "none" });
  const solve = buildDefaultSolver({
    spine, model, workspace, repository: "repo",
    runnerFor: (_ref, tree) => validatorRunner(tree, async (candidate) => (await candidate.read("src/values.ts")) === replacement),
    governance: { vetPatch: gates.vetPatch, spine },
  });

  const files = await workspace.files("repo");
  const admittedEdit = {
    schemaVersion: 1 as const,
    mechanism: "project-edit-stage" as const,
    repositoryRef: "repo",
    repositoryTreeSha256: projectRepositoryTreeSha256(files),
    allowedFiles: ["src/values.ts"],
    allowedFileSha256: { "src/values.ts": createHash("sha256").update(original).digest("hex") },
    taskId: "task-1",
    planStepId: "step-1",
    generation: { model: "s", tokensIn: 0, tokensOut: 0 },
    plan: JSON.parse(JSON.stringify({ rationale: "filter empties", edits: [{ file: "src/values.ts", search: original, replace: replacement, intent: "filter empty values" }] })),
  };
  const out = await solve({ id: "compensate", text: "filter empty values", repoRef: "repo", hints: { projectTaskId: "task-1", planStepId: "step-1" } }, { admittedEdit });
  assert.equal(out.mergeAuthority?.verdict, "abandon-retry");
  assert.equal(await workspace.tree("repo").read("src/values.ts"), original, "retry begins from the authenticated pre-edit tree");
  assert.equal(out.solveResult.projectEditReceipt, undefined, "a compensated effect is never represented as retained");
  assert.match(out.solveResult.gaveUpReason ?? "", /compensated/u);
});
