import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { buildAutonomyLoop } from "../src/autonomy/autonomy_loop.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import type { SolveFn } from "../src/loop/review_intake.js";
import type { SolveResult } from "../src/solve/issue_model.js";
import type { MergeAuthorityVerdict } from "../src/oversight/merge_authority.js";

/**
 * ROUND 6 (route the governed decision) — does the loop HONOUR the merge-authority verdict, or discard it?
 *
 * MEASURED FIRST: withGovernance computes decideMergeAuthority (autonomous-merge / human-merge / abandon-retry
 * / block) and audits it — but the autonomy adapter (autonomy_loop.ts) extracted only `.solveResult`, dropping
 * `mergeAuthority`. So a "human-merge" verdict (governance says a PERSON must own this irreversible/high-blast
 * change) had ZERO control effect: the loop proceeded autonomously anyway. This round routes it: human-merge ->
 * park for a human (block-human -> paused-human); block/abandon-retry -> stop honestly (fail); autonomous-merge
 * -> proceed.
 *
 * PROVEN-LIVE (harness A1). Disproof neuter: revert the implement-stage routing to always-advance -> HUMAN-MERGE-PARKS
 * goes RED (the verdict regains no control effect). AUTONOMOUS-MERGE-PROCEEDS guards against parking everything.
 */

function tmp(): string { return mkdtempSync(join(tmpdir(), "keep-gov-")); }
function newSpine(): Spine { return new Spine(new FileSpineStore(tmp()), new InProcessLock(), new SchemaRegistry()); }

function governedSolve(verdict: MergeAuthorityVerdict): SolveFn {
  return async (issue) => ({
    solveResult: {
      issueId: issue.id, solved: true, stagesRun: ["localize"], repairRounds: 0,
      validation: { testsPassed: true },
      regressionSignature: () => undefined,
    } as unknown as SolveResult,
    mergeAuthority: { verdict, reason: `test:${verdict}`, consequential: verdict !== "autonomous-merge", verified: true },
  });
}
const GOAL = "refactor the local helper to be clearer"; // benign, local, reversible → passes feasibility + autonomy authorize

test("HUMAN-MERGE posture matrix: interaction changes, authority never silently escalates", async () => {
  const autonomous = await buildAutonomyLoop({ spine: newSpine(), solve: governedSolve("human-merge"), posture: "autonomous" }).runProject(GOAL, { runId: "gov-hm-a", stepBudget: 30 });
  assert.equal(autonomous.state.status, "waiting-capability", "autonomous mode defers the isolated merge for a safe resolution, not routine approval");
  const policy = await buildAutonomyLoop({ spine: newSpine(), solve: governedSolve("human-merge"), posture: "policy-calibrated", permissionPolicy: async () => "approval" }).runProject(GOAL, { runId: "gov-hm-p", stepBudget: 30 });
  assert.equal(policy.state.status, "waiting-approval");
  const handsOn = await buildAutonomyLoop({ spine: newSpine(), solve: governedSolve("human-merge"), posture: "approval-required" }).runProject(GOAL, { runId: "gov-hm-h", stepBudget: 30 });
  assert.equal(handsOn.state.status, "waiting-approval");
});

test("configured posture is a floor: a request cannot relax approval-required to autonomous", async () => {
  const loop = buildAutonomyLoop({ spine: newSpine(), solve: governedSolve("human-merge"), posture: "approval-required" });
  const result = await loop.runProject(GOAL, { runId: "floor", posture: "autonomous", stepBudget: 30 });
  assert.equal(result.state.posture, "approval-required");
  assert.equal(result.state.status, "waiting-approval");
});

test("policy-calibrated posture consults policy and can proceed without an interruption", async () => {
  let consulted = 0;
  const loop = buildAutonomyLoop({ spine: newSpine(), solve: governedSolve("human-merge"), posture: "policy-calibrated", permissionPolicy: async () => { consulted += 1; return "proceed"; } });
  const result = await loop.runProject(GOAL, { runId: "policy-proceed", stepBudget: 30 });
  assert.equal(result.state.status, "completed");
  assert.equal(consulted, 1);
});

test("approval is single-use and advances the existing proposal without re-running implement", async () => {
  let calls = 0;
  const solve: SolveFn = async (issue) => {
    calls += 1;
    return governedSolve("human-merge")(issue);
  };
  const loop = buildAutonomyLoop({ spine: newSpine(), solve, posture: "approval-required" });
  const first = await loop.runProject(GOAL, { runId: "single-use", stepBudget: 30 });
  assert.equal(first.state.wait?.kind, "approval");
  const decisionId = first.state.wait?.kind === "approval" ? first.state.wait.decisionId : "";
  const resumed = await loop.resumeProject("single-use", { approval: { decisionId, approved: true } });
  assert.equal(resumed.state.status, "completed");
  assert.equal(calls, 1, "approved proposal is advanced, not re-executed");
  const replay = await loop.resumeProject("single-use", { approval: { decisionId, approved: true } });
  assert.equal(replay.state.revision, resumed.state.revision);
  assert.equal(calls, 1);
});

test("BLOCK-DEFERS: a sound safety block becomes exact alternative-capability debt, never auto-merges", async () => {
  const loop = buildAutonomyLoop({ spine: newSpine(), solve: governedSolve("block") });
  const res = await loop.runProject(GOAL, { runId: "gov-blk", stepBudget: 30 });
  assert.equal(res.state.status, "waiting-capability");
  assert.equal(res.state.wait?.kind, "capability");
});

test("AUTONOMOUS-MERGE-PROCEEDS: an autonomous-merge verdict is NOT parked — the loop proceeds", async () => {
  const loop = buildAutonomyLoop({ spine: newSpine(), solve: governedSolve("autonomous-merge") });
  const res = await loop.runProject(GOAL, { runId: "gov-am", stepBudget: 30 });
  assert.notEqual(res.state.status, "waiting-approval", "a reversible+verified change is not parked");
  assert.notEqual(res.state.status, "failed", "a clean autonomous-merge does not fail on the merge account");
});
