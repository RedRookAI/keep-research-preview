import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { checkFeasibility } from "../src/autonomy/feasibility_check.js";

test("FEASIBILITY (deterministic floor): a physical-build goal is assist-only and does NOT auto-proceed", async () => {
  const r = await checkFeasibility("build a drone that carries 10x its weight");
  assert.equal(r.deliverability, "assist-only");
  assert.equal(r.sensitivity, "dual-use", "the 10x-payload dual-use signal is caught");
  assert.equal(r.proceed, false, "it pauses for an honest reframe instead of charging ahead");
  assert.match(r.framing, /software, documents, and analysis/i);
});

test("FEASIBILITY: a pure software goal is fully-deliverable and proceeds", async () => {
  const r = await checkFeasibility("write a REST API in TypeScript with tests");
  assert.equal(r.deliverability, "fully-deliverable");
  assert.equal(r.proceed, true);
});

test("FEASIBILITY: an external-account operation is needs-account and pauses (gated action)", async () => {
  const r = await checkFeasibility("run my instagram account and post to it daily");
  assert.equal(r.deliverability, "needs-account");
  assert.equal(r.proceed, false);
});

test("ENVELOPE (crown): an infeasible goal PAUSES the autonomy loop for a reframe — no work committed", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const spy = { called: false };
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-feas-env-")),
    solve: async (issue: { id: string; text: string }) => { spy.called = true; return { solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, detail: "ok" } } } as never; },
  });
  const run = await app.autonomyLoop!.runProject("build a physical robot arm and assemble it", { runId: "rF", stepBudget: 50 });
  assert.equal(run.state.status, "waiting-capability", "the exact unavailable physical capability is durable debt");
  assert.ok(run.feasibility && run.feasibility.proceed === false, "the feasibility report explains the pause");
  assert.equal(spy.called, false, "the solve seam was NEVER invoked — no autonomous work committed on an infeasible goal");
  assert.equal(run.visited.length, 0, "no stages ran");
});

test("ENVELOPE: a feasible goal proceeds through the loop and carries its feasibility report", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const spy = { called: false };
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-feas-ok-")),
    solve: async (issue: { id: string; text: string }) => { spy.called = true; return { solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, detail: "ok" } } } as never; },
  });
  const run = await app.autonomyLoop!.runProject("write and test a markdown parser library", { runId: "rG", stepBudget: 50 });
  assert.ok(run.feasibility && run.feasibility.proceed === true, "feasible → proceed");
  assert.notEqual(run.state.status, "waiting-approval");
  assert.equal(spy.called, true, "the feasible goal actually ran the solve pipeline");
});

test("HONESTY: the deterministic verdict holds when no classifier is supplied (no forced model call at intake)", async () => {
  // No classifier passed → deterministic-only, zero-cost intake (sovereignty/N=1 default).
  const r = await checkFeasibility("assemble and solder a circuit board");
  assert.equal(r.deliverability, "assist-only");
  assert.equal(r.proceed, false);
});
