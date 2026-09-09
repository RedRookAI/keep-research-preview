import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { buildAutonomyLoop } from "../src/autonomy/autonomy_loop.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import type { SpendCap } from "../src/scheduler/action_authorizer.js";
import { VetoQueue, type ParkedAction } from "../src/scheduler/veto_queue.js";
import type { TriResearchLane, TriResearchSource, TriResearchTransport } from "../src/research/tri_research_runtime.js";

function mkSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-guard-"))), new InProcessLock(), new SchemaRegistry());
}

type Spy = { called: boolean };
function stubSolve(spy: Spy) {
  return async (issue: { id: string; text: string }) => {
    spy.called = true;
    return { solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, detail: "ok" } } } as never;
  };
}

test("GUARD LIVE: an autonomous local goal dispatches (solve is invoked)", async () => {
  const spy: Spy = { called: false };
  const loop = buildAutonomyLoop({ spine: mkSpine(), solve: stubSolve(spy) });
  const run = await loop.runProject("write and test a markdown parser library", { runId: "a1", stepBudget: 50 });
  assert.notEqual(run.state.status, "paused-human", "a local reversible goal is not vetoed");
  assert.notEqual(run.state.status, "paused-budget");
  assert.equal(spy.called, true, "the autonomous goal actually ran the solve pipeline");
  const research = run.state.artifacts.research as { decision?: { required?: boolean; coordinator?: string } };
  assert.equal(research.decision?.required, false);
  assert.equal(research.decision?.coordinator, "built-in");
});

test("GUARD LIVE: autonomous posture isolates an external goal until a commit-authorized executor exists", async () => {
  const spy: Spy = { called: false };
  const loop = buildAutonomyLoop({ spine: mkSpine(), solve: stubSolve(spy) });
  // 'email the report to the team' is fully-deliverable (feasibility proceeds) but external → the GUARD vetoes it.
  const run = await loop.runProject("email the report to the team", { runId: "a2", stepBudget: 50 });
  assert.equal(run.state.status, "waiting-capability");
  assert.ok(run.feasibility && run.feasibility.proceed === true);
  assert.equal(spy.called, false, "the code-solve seam is not misrepresented as an authorized external executor");
});

test("POLICY-CALIBRATED: a proceed decision initializes once and continues the authorized run", async () => {
  const spy: Spy = { called: false };
  let policyCalls = 0;
  const loop = buildAutonomyLoop({
    spine: mkSpine(), solve: stubSolve(spy), posture: "policy-calibrated",
    permissionPolicy: async () => { policyCalls += 1; return "proceed"; },
  });
  const run = await loop.runProject("email the report to the team", { runId: "policy-proceed", stepBudget: 50 });
  assert.equal(run.state.status, "completed");
  assert.equal(policyCalls, 1);
  assert.equal(spy.called, true);
});

test("GUARD LIVE: an over-cap goal is blocked at dispatch → paused-budget", async () => {
  const spy: Spy = { called: false };
  const brokeCap: SpendCap = { canAfford: () => false };
  const loop = buildAutonomyLoop({ spine: mkSpine(), solve: stubSolve(spy), spendCap: brokeCap, estimatedActionCostUsd: 5 });
  const run = await loop.runProject("write and test a markdown parser library", { runId: "a3", stepBudget: 50 });
  assert.equal(run.state.status, "paused-budget", "an over-cap spend is blocked, not executed");
  assert.equal(spy.called, false, "no work ran over budget");
});

test("GUARD LIVE: a within-cap costed local goal still dispatches", async () => {
  const spy: Spy = { called: false };
  const okCap: SpendCap = { canAfford: () => true };
  const loop = buildAutonomyLoop({ spine: mkSpine(), solve: stubSolve(spy), spendCap: okCap, estimatedActionCostUsd: 5 });
  const run = await loop.runProject("write and test a markdown parser library", { runId: "a4", stepBudget: 50 });
  assert.notEqual(run.state.status, "paused-budget");
  assert.equal(spy.called, true);
});

test("TRI-RESEARCH DEBT: one waiting research run does not block an independent local project", async () => {
  const spy: Spy = { called: false };
  const loop = buildAutonomyLoop({ spine: mkSpine(), solve: stubSolve(spy) });
  const research = await loop.runProject("research the latest 2026 state of the art for vector search", { runId: "research-debt", stepBudget: 50 });
  assert.equal(research.state.status, "waiting-capability");
  assert.equal(research.state.stage, "research");
  const local = await loop.runProject("write and test a markdown parser library", { runId: "independent-local", stepBudget: 50 });
  assert.equal(local.state.status, "completed");
  assert.equal(spy.called, true);
});

test("BOUNDED RESEARCH: fresh current plus labelled non-current LKG advances local reversible work", async () => {
  const spy: Spy = { called: false };
  const evidence = (lane: TriResearchLane): TriResearchSource => ({
    id: lane, title: lane, locator: `https://evidence.invalid/${lane}`,
    retrievedAt: "2026-08-28T10:00:00Z", asOf: "2026-08-01", summary: `${lane} evidence`,
  });
  const currentOnly: TriResearchTransport = { id: "current-only", search: async (lane) => lane === "current" ? [evidence(lane)] : null };
  const loop = buildAutonomyLoop({
    spine: mkSpine(), solve: stubSolve(spy),
    research: { transports: [currentOnly], asOf: () => "2026-08-28", lastKnownGood: { historical: [evidence("historical")], "cross-disciplinary": [evidence("cross-disciplinary")] } },
  });
  const run = await loop.runProject("locally draft and test a research review of vector search", { runId: "bounded-research", stepBudget: 50 });
  assert.equal(run.state.status, "completed");
  assert.equal(spy.called, true);
  assert.equal((run.state.artifacts.research as { admission?: string }).admission, "bounded-reversible");
  assert.ok(run.visited.includes("rag"), "admitted research is made reachable through the canonical retrieval stage");
  const rag = run.state.artifacts.rag as { providers?: readonly string[]; sufficiency?: { status?: string } };
  assert.deepEqual(rag.providers, ["tri-research"]);
  assert.equal(rag.sufficiency?.status, "sufficient");
});

test("BOUNDED RESEARCH: identical evidence cannot advance work that is not proven reversible", async () => {
  const spy: Spy = { called: false };
  const evidence = (lane: TriResearchLane): TriResearchSource => ({
    id: lane, title: lane, locator: `https://evidence.invalid/${lane}`,
    retrievedAt: "2026-08-28T10:00:00Z", asOf: "2026-08-01", summary: `${lane} evidence`,
  });
  const currentOnly: TriResearchTransport = { id: "current-only", search: async (lane) => lane === "current" ? [evidence(lane)] : null };
  const loop = buildAutonomyLoop({
    spine: mkSpine(), solve: stubSolve(spy),
    research: { transports: [currentOnly], asOf: () => "2026-08-28", lastKnownGood: { historical: [evidence("historical")], "cross-disciplinary": [evidence("cross-disciplinary")] } },
  });
  const run = await loop.runProject("research the latest vector search techniques", { runId: "unbounded-research", stepBudget: 50 });
  assert.equal(run.state.status, "waiting-capability");
  assert.equal(run.state.stage, "research", "the research admission—not the external-effect preflight—holds the run");
  assert.equal(spy.called, false);
});


// ─── veto verdict → veto queue (async veto surface) ───

function newVetoQueue(runSpy: { ran: string[] }): VetoQueue {
  return new VetoQueue({ spine: mkSpine(), run: (a: ParkedAction) => runSpy.ran.push(a.id) });
}

test("APPROVAL-REQUIRED→QUEUE: an external goal is parked only in the hands-on posture", async () => {
  const spy = { ran: [] as string[] };
  const q = newVetoQueue(spy);
  const loop = buildAutonomyLoop({ spine: mkSpine(), solve: stubSolve({ called: false }), vetoQueue: q, posture: "approval-required" });
  const run = await loop.runProject("email the whole team the report", { runId: "v1", stepBudget: 50 });
  assert.equal(run.state.status, "waiting-approval");
  const parked = q.parked();
  assert.equal(parked.length, 1, "the vetoed action is parked for async veto/approve");
  assert.equal(parked[0]!.id, "v1");
  assert.deepEqual(spy.ran, [], "parking never runs it");
});

test("VETO→QUEUE: non-veto pauses do NOT park (autonomous skips; blocked-over-cap is a budget pause, not a veto)", async () => {
  const spy = { ran: [] as string[] };
  // autonomous goal → not parked (never enters the pause block)
  const qA = newVetoQueue(spy);
  const loopA = buildAutonomyLoop({ spine: mkSpine(), solve: stubSolve({ called: false }), vetoQueue: qA });
  await loopA.runProject("write and test a markdown parser library", { runId: "v2a", stepBudget: 50 });
  assert.equal(qA.parked().length, 0, "an autonomous goal is not vetoed, so nothing is parked");
  // blocked-over-cap → paused-budget, NOT parked (only a veto of an external action parks)
  const qB = newVetoQueue(spy);
  const loopB = buildAutonomyLoop({ spine: mkSpine(), solve: stubSolve({ called: false }), vetoQueue: qB, spendCap: { canAfford: () => false }, estimatedActionCostUsd: 5 });
  const run = await loopB.runProject("write and test a markdown parser library", { runId: "v2b", stepBudget: 50 });
  assert.equal(run.state.status, "paused-budget");
  assert.equal(qB.parked().length, 0, "a budget pause is not an external-action veto — it does not park");
});

test("APPROVAL-REQUIRED→QUEUE: the parked item NEVER auto-runs (still needs explicit approve)", async () => {
  const spy = { ran: [] as string[] };
  const q = newVetoQueue(spy);
  const loop = buildAutonomyLoop({ spine: mkSpine(), solve: stubSolve({ called: false }), vetoQueue: q, posture: "approval-required" });
  await loop.runProject("email the report to the team", { runId: "v3", stepBudget: 50 });
  assert.equal(q.runnable("v3"), false, "parked, not runnable");
  assert.deepEqual(spy.ran, [], "the loop parks but never approves/runs it");
  // only an explicit approve runs it
  q.approve("v3");
  assert.deepEqual(spy.ran, ["v3"], "explicit approve is the only run path");
});
