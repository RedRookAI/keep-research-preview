import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveCascade, type ResolutionTier, type CascadeBudget } from "../src/resolve/budget_cascade.js";
import type { TestGenerator, TestExecutor } from "../src/resolve/novel_tests.js";
import type { CandidateSolver } from "../src/resolve/best_of_n.js";
import { composeKeep } from "../src/compose.js";
import type { Issue, SolveResult, SearchReplaceEdit } from "../src/solve/issue_model.js";

const issue: Issue = { id: "ENG-4", text: "fix it", repoRef: "repo" };
const edit = (file: string, i: number): SearchReplaceEdit => ({ file, search: `f_${i}`, replace: `r_${i}`, intent: "fix" });
const testEdit = (i: number): SearchReplaceEdit => ({ file: `tests/t${i}.test.ts`, search: `e_${i}`, replace: `e2_${i}`, intent: "game" });
function candidate(edits: readonly SearchReplaceEdit[]): SolveResult {
  return { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, failures: [], vettingCleared: true, detail: "" }, prProposal: { title: "t", body: "b", branch: "keep/x", edits, testsPassed: true } };
}
const cleanSampler: CandidateSolver = async (_i, idx) => candidate([edit("src/a.ts", idx)]);
const failSampler: CandidateSolver = async (_i, idx) => candidate([testEdit(idx)]); // fails the SOUND floor
const tier = (name: string, sample: CandidateSolver, estCostUsd: number, extra: Partial<ResolutionTier> = {}): ResolutionTier => ({ name, n: 2, sample, estCostUsd, ...extra });
function budgetOf(remaining: number): CascadeBudget {
  let bal = remaining;
  return { canAfford: (c) => bal >= c, record: (c) => { bal -= c; } };
}
const payloads = (app: ReturnType<typeof composeKeep>) => app.spine.currentEvents().map((e) => e.payload as Record<string, unknown>);

test("R4: an easy ticket is resolved by the CHEAP tier alone (no escalation)", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-r4-")) });
  const res = await resolveCascade({ tiers: [tier("cheap", cleanSampler, 1), tier("strong", cleanSampler, 10)], spine: app.spine }, issue);
  assert.deepEqual(res.tiersUsed, ["cheap"]);
  assert.equal(res.escalations, 0);
  assert.equal(res.stoppedReason, "verified");
  assert.equal(res.escalateToHuman, false);
});

test("R4: escalates on a PROVABLE verification failure (not confidence)", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-r4b-")) });
  const res = await resolveCascade({ tiers: [tier("cheap", failSampler, 1), tier("strong", cleanSampler, 10)], spine: app.spine }, issue);
  assert.deepEqual(res.tiersUsed, ["cheap", "strong"]);
  assert.equal(res.escalations, 1);
  assert.equal(res.stoppedReason, "verified");
  assert.ok(payloads(app).some((p) => p["event"] === "resolve.cascade.escalate" && p["reason"] === "no-verified-candidate"));
});

test("R4: escalates on an R3 behavioral fork", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-r4c-")) });
  const generator: TestGenerator = { generate: async () => [{ id: "d", description: "d" }] };
  const forkExec: TestExecutor = { run: async (_t, _c, idx) => (idx === 0 ? "pass" : "fail") }; // splits the pool
  const res = await resolveCascade({
    tiers: [tier("cheap", cleanSampler, 1, { useTests: true }), tier("strong", cleanSampler, 10)],
    generator, executor: forkExec, spine: app.spine,
  }, issue);
  assert.equal(res.tiersUsed[0], "cheap");
  assert.ok(res.tiersUsed.includes("strong"), "a fork at the cheap tier escalates");
  assert.ok(payloads(app).some((p) => p["event"] === "resolve.cascade.escalate" && p["reason"] === "behavioral-fork"));
});

test("R4 SOVEREIGNTY: never escalate past budget — cheap fails, strong is unaffordable → defer to human, strong never runs", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-r4d-")) });
  let strongRan = false;
  const strongSampler: CandidateSolver = async (_i, idx) => { strongRan = true; return candidate([edit("src/a.ts", idx)]); };
  const res = await resolveCascade({
    tiers: [tier("cheap", failSampler, 1), tier("strong", strongSampler, 10)],
    budget: budgetOf(1), // affords cheap only
    spine: app.spine,
  }, issue);
  assert.equal(strongRan, false, "the unaffordable strong tier never runs");
  assert.deepEqual(res.tiersUsed, ["cheap"]);
  assert.equal(res.stoppedReason, "budget");
  assert.equal(res.escalateToHuman, true);
  assert.ok(payloads(app).some((p) => p["event"] === "resolve.cascade.budget_stop"));
});

test("R4: human is the final fallback — all tiers fail → escalate to human (least-bad returned)", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-r4e-")) });
  const res = await resolveCascade({ tiers: [tier("cheap", failSampler, 1), tier("strong", failSampler, 10)], spine: app.spine }, issue);
  assert.equal(res.stoppedReason, "exhausted");
  assert.equal(res.escalateToHuman, true);
  assert.equal(res.winnerCleared, false);
});

test("R4: complexity pre-routing sends an obviously-hard ticket straight to the stronger tier", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-r4f-")) });
  const res = await resolveCascade({
    tiers: [tier("cheap", failSampler, 1), tier("strong", cleanSampler, 10)],
    complexity: () => "complex",
    spine: app.spine,
  }, issue);
  assert.deepEqual(res.tiersUsed, ["strong"], "the cheap tier was skipped for a complex ticket");
  assert.equal(res.escalations, 0);
});

test("R4: the cascade chooses HOW MUCH to spend + WHICH candidate — never WHETHER to approve", async () => {
  const res = await resolveCascade({ tiers: [tier("cheap", cleanSampler, 1)] }, issue);
  assert.equal("oversight" in res.winner, false);
  assert.equal("humanApprovalRequired" in res.winner, false);
});

test("R4 wiring: composeKeep exposes app.resolveCascade", async () => {
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-r4w-")),
    resolutionTiers: [tier("cheap", cleanSampler, 1), tier("strong", cleanSampler, 10)],
    cascadeBudget: budgetOf(100),
  });
  assert.ok(app.resolveCascade, "app.resolveCascade is wired");
  const res = await app.resolveCascade!(issue);
  assert.equal(res.stoppedReason, "verified");
});
