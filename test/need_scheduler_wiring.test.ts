import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import type { NeedSignal } from "../src/autonomy/need_scheduler.js";
import type { OutcomeSignal } from "../src/loop/self_improvement_bus.js";
import { RbacAuthorizer, type Principal } from "../src/identity/rbac.js";
import { SolveOutcomeWire } from "../src/loop/solve_outcome_wire.js";

const measuredGap: NeedSignal = {
  id: "gap-1", subject: "typescript-api", goal: "repair repeated API failures",
  currentKnowledgeMissing: true, projectEvidenceMissing: true, repeatedSuccessfulProcedure: true,
  measuredFailureCount: 4, evaluationCoverage: 0.25, gradientFreeTried: true,
  residualFailureRate: 0.3, verifiedExampleCount: 700, verifiableRewardAvailable: true,
  narrowStableTask: true,
};
const failure = (solveId: string, scopeId?: string): OutcomeSignal => ({
  solveId, ...(scopeId === undefined ? {} : { scopeId }), taskShape: "typescript-api", testsPassed: false,
  mergeVerdict: "pending", timestamp: Date.now(),
});

test("IMPROVE-01: composeKeep preserves bounded operator-submitted proposals without an execution surface", () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-need-wire-")) });
  const first = app.needScheduler.schedule([measuredGap, { ...measuredGap, id: "duplicate-observation" }]);
  assert.deepEqual(first.scheduled.map((proposal) => proposal.kind), ["research", "rag", "skill"]);
  assert.equal(first.scheduled.some((proposal) => proposal.kind === "training"), false);
  assert.ok(first.scheduled.every((proposal) => proposal.signalId === "duplicate-observation"),
    "duplicate evidence provenance is input-order independent");
  const reordered = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-need-reordered-")) })
    .needScheduler.schedule([{ ...measuredGap, id: "duplicate-observation" }, measuredGap]);
  assert.deepEqual(reordered.scheduled.map((p) => p.signalId), first.scheduled.map((p) => p.signalId));
  assert.deepEqual(app.needScheduler.schedule([measuredGap]).scheduled.map((p) => p.kind), ["evaluation-data"]);
  assert.equal(typeof (app.needScheduler as unknown as { execute?: unknown }).execute, "undefined");
});

test("IMPROVE-01: real solve failures feed a durable proposal inbox and do not require human prompting", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "keep-need-outcome-"));
  let calls = 0;
  const app = composeKeep({ dataDir, anchorThreshold: 99, solve: async (issue) => ({ solveResult: {
    issueId: `${issue.id}-${++calls}`, solved: false, stagesRun: [], repairRounds: 0,
    validation: { testsPassed: false, detail: "measured failure" },
  } } as never) });
  await app.autonomyLoop!.runProject("add a dark-mode toggle", { runId: "need-real-1", stepBudget: 50 });
  await app.autonomyLoop!.runProject("add a dark-mode toggle", { runId: "need-real-2", stepBudget: 50 });
  assert.deepEqual(app.needScheduler.pending().map((p) => p.kind), ["evaluation-data"]);
  assert.equal(app.needScheduler.pending()[0]?.requiresOptIn, false);

  const restarted = composeKeep({ dataDir, anchorThreshold: 99 });
  assert.deepEqual(restarted.needScheduler.pending().map((p) => p.id), app.needScheduler.pending().map((p) => p.id));
  await restarted.selfImprovementBus.publish(failure("solve-2"));
  assert.equal(restarted.needScheduler.pending().length, 1, "replayed solve cannot inflate recurrence evidence");
});

test("IMPROVE-01: n=1 and enterprise scopes remain isolated under the same composition", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-need-scope-")), anchorThreshold: 99 });
  await app.selfImprovementBus.publish(failure("personal-1"));
  await app.selfImprovementBus.publish(failure("personal-2"));
  const owner: Principal = { id: "owner-a", kind: "human", role: "owner", tenant: "tenant-a" };
  const view = app.needScheduler.forPrincipal(owner, new RbacAuthorizer())!;
  const wire = new SolveOutcomeWire(app.selfImprovementBus, undefined, view.outcomeBinding);
  await wire.publishSolve({ solveResult: { issueId: "tenant-1", solved: false } }, { taskShape: "typescript-api" });
  await wire.publishSolve({ solveResult: { issueId: "tenant-2", solved: false } }, { taskShape: "typescript-api" });
  assert.equal(app.needScheduler.pending().length, 1);
  assert.equal(view.pending().length, 1);
  assert.notEqual(app.needScheduler.pending()[0]?.id, view.pending()[0]?.id);
});

test("IMPROVE-01: identical solve ids remain independent across tenant scopes", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-need-same-id-")), anchorThreshold: 99 });
  const owner: Principal = { id: "owner-a", kind: "human", role: "owner", tenant: "tenant-a" };
  const view = app.needScheduler.forPrincipal(owner, new RbacAuthorizer())!;
  const wire = new SolveOutcomeWire(app.selfImprovementBus, undefined, view.outcomeBinding);
  await app.selfImprovementBus.publish(failure("same-1"));
  await app.selfImprovementBus.publish(failure("same-2"));
  await wire.publishSolve({ solveResult: { issueId: "same-1", solved: false } }, { taskShape: "typescript-api" });
  await wire.publishSolve({ solveResult: { issueId: "same-2", solved: false } }, { taskShape: "typescript-api" });
  assert.equal(app.needScheduler.pending().length, 1);
  assert.equal(view.pending().length, 1);
  assert.match(app.needScheduler.pending()[0]!.reason, /distinct execution-grounded solve failures/);
  assert.doesNotMatch(app.needScheduler.pending()[0]!.reason, /coverage/i, "unknown coverage is never fabricated");
});

test("IMPROVE-01: caller-asserted tenant strings cannot forge an enterprise outcome", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-need-forged-scope-")), anchorThreshold: 99 });
  const owner: Principal = { id: "owner-a", kind: "human", role: "owner", tenant: "tenant-a" };
  const view = app.needScheduler.forPrincipal(owner, new RbacAuthorizer())!;
  await app.selfImprovementBus.publish(failure("forged-1", "tenant-a"));
  await app.selfImprovementBus.publish(failure("forged-2", "tenant-a"));
  assert.equal(view.pending().length, 0);
  assert.equal(app.needScheduler.pending().length, 0);
});

test("IMPROVE-01: training remains proposal-only after explicit opt-in", () => {
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-need-training-wire-")),
    needScheduling: { maxPerCycle: 5, maxPerKind: 1, trainingProposalsEnabled: true },
  });
  assert.equal(app.needScheduler.schedule([measuredGap]).scheduled.find((p) => p.kind === "training")?.requiresOptIn, true);
});

test("IMPROVE-01: bounded delta backlog and acknowledgement reconstruct exactly after restart", () => {
  const dataDir = mkdtempSync(join(tmpdir(), "keep-need-delta-restart-"));
  const options = { maxPerCycle: 1, maxPerKind: 1, maxPending: 1, maxDeferred: 2 };
  const app = composeKeep({ dataDir, needScheduling: options });
  app.needScheduler.schedule(Array.from({ length: 20 }, (_, i) => ({ ...measuredGap, id: `signal-${i}`, subject: `subject-${i}` })));
  const acknowledged = app.needScheduler.pending()[0]!.id;
  assert.equal(app.needScheduler.acknowledge(acknowledged), true);
  const expected = { pending: app.needScheduler.pending(), deferred: app.needScheduler.deferred() };
  assert.ok(expected.deferred.length <= 2);
  const restarted = composeKeep({ dataDir, needScheduling: options });
  assert.deepEqual(restarted.needScheduler.pending(), expected.pending);
  assert.deepEqual(restarted.needScheduler.deferred(), expected.deferred);
});
