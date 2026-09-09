import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { computeResolutionEconomics, renderResolutionCurve } from "../src/resolve/resolution_curve.js";
import { resolveCascade, type ResolutionTier } from "../src/resolve/budget_cascade.js";
import { runCli } from "../src/cli/cli_core.js";
import { composeKeep, type KeepApp } from "../src/compose.js";
import type { Issue, SolveResult, SearchReplaceEdit } from "../src/solve/issue_model.js";
import type { CandidateSolver } from "../src/resolve/best_of_n.js";

function app(): KeepApp { return composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-r5-")) }); }
function stageResolution(a: KeepApp, o: { issueId: string; tiers: { name: string; cost: number }[]; winnerCleared: boolean; escalateToHuman: boolean; stoppedReason: string; escalations: number; behavioralFork?: boolean; tiersUsed: string[] }): void {
  for (const t of o.tiers) a.spine.stage({ type: "identity.action", actor: "cascade", payload: { event: "resolve.cascade.tier", issueId: o.issueId, tier: t.name, n: 2, estCostUsd: t.cost, ts: 1 } });
  a.spine.stage({ type: "identity.action", actor: "cascade", payload: { event: "resolve.cascade.done", issueId: o.issueId, tiersUsed: o.tiersUsed, escalations: o.escalations, stoppedReason: o.stoppedReason, escalateToHuman: o.escalateToHuman, winnerCleared: o.winnerCleared, behavioralFork: o.behavioralFork ?? false, ts: 2 } });
}
const econOf = (a: KeepApp) => computeResolutionEconomics(a.spine.currentEvents());

test("R5 CARDINAL RULE: a deferred-to-human outcome is NEVER counted as verified (containment ≠ resolution)", () => {
  const a = app();
  stageResolution(a, { issueId: "i1", tiers: [{ name: "cheap", cost: 1 }], winnerCleared: true, escalateToHuman: false, stoppedReason: "verified", escalations: 0, tiersUsed: ["cheap"] });
  stageResolution(a, { issueId: "i2", tiers: [{ name: "cheap", cost: 1 }, { name: "strong", cost: 9 }], winnerCleared: false, escalateToHuman: true, stoppedReason: "exhausted", escalations: 1, tiersUsed: ["cheap", "strong"] });
  const e = econOf(a);
  assert.equal(e.resolutions, 2);
  assert.equal(e.verified, 1, "only the genuinely-solved one counts");
  assert.equal(e.deferredToHuman, 1);
  assert.equal(e.verifiedRate, 0.5);
});

test("R5: cost per verified resolution includes spend on attempts that deferred (they still cost money)", () => {
  const a = app();
  stageResolution(a, { issueId: "i1", tiers: [{ name: "cheap", cost: 2 }], winnerCleared: true, escalateToHuman: false, stoppedReason: "verified", escalations: 0, tiersUsed: ["cheap"] });
  stageResolution(a, { issueId: "i2", tiers: [{ name: "cheap", cost: 2 }, { name: "strong", cost: 6 }], winnerCleared: false, escalateToHuman: true, stoppedReason: "exhausted", escalations: 1, tiersUsed: ["cheap", "strong"] });
  const e = econOf(a);
  assert.equal(e.groundedSpendUsd, 10); // 2 + (2+6)
  assert.equal(e.costPerVerifiedUsd, 10, "total spend ÷ 1 verified — deferred spend is not hidden");
  assert.equal(e.costPerResolutionUsd, 5);
});

test("R5: no verified resolutions → cost-per-verified is null (honest 'n/a'), not a divide-by-zero", () => {
  const a = app();
  stageResolution(a, { issueId: "i1", tiers: [{ name: "cheap", cost: 3 }], winnerCleared: false, escalateToHuman: true, stoppedReason: "budget", escalations: 0, tiersUsed: ["cheap"] });
  const e = econOf(a);
  assert.equal(e.verified, 0);
  assert.equal(e.costPerVerifiedUsd, null);
  assert.equal(e.budgetStopped, 1);
});

test("R5: escalation rate, terminal-tier rate, and fork rate are computed; >30% escalation warns", () => {
  const a = app();
  stageResolution(a, { issueId: "i1", tiers: [{ name: "cheap", cost: 1 }, { name: "strong", cost: 5 }], winnerCleared: true, escalateToHuman: false, stoppedReason: "verified", escalations: 1, behavioralFork: true, tiersUsed: ["cheap", "strong"] });
  stageResolution(a, { issueId: "i2", tiers: [{ name: "cheap", cost: 1 }], winnerCleared: true, escalateToHuman: false, stoppedReason: "verified", escalations: 0, tiersUsed: ["cheap"] });
  const e = econOf(a);
  assert.equal(e.escalationRate, 0.5);
  assert.equal(e.behavioralForkRate, 0.5);
  assert.equal(e.terminalTierRate["strong"], 0.5);
  assert.equal(e.terminalTierRate["cheap"], 0.5);
  assert.match(renderResolutionCurve(e), /escalation rate > 30%/);
});

test("R5: the render spells out containment≠resolution and the live-runs caveat", () => {
  const a = app();
  stageResolution(a, { issueId: "i1", tiers: [{ name: "cheap", cost: 1 }], winnerCleared: true, escalateToHuman: false, stoppedReason: "verified", escalations: 0, tiersUsed: ["cheap"] });
  const out = renderResolutionCurve(econOf(a));
  assert.match(out, /NOT counted as solved/);
  assert.match(out, /deferred cost, not a saving/);
  assert.match(out, /contamination-controlled runs on real infrastructure/);
});

test("R5: bare best-of-N runs (no cascade) are aggregated as resolutions", () => {
  const a = app();
  a.spine.stage({ type: "identity.action", actor: "best-of-n", payload: { event: "resolve.best_of_n", issueId: "i1", sampled: 2, requestedN: 3, selectedIndex: 0, winnerCleared: true, anyCleared: true, ts: 1 } });
  a.spine.stage({ type: "identity.action", actor: "best-of-n", payload: { event: "resolve.best_of_n", issueId: "i2", sampled: 3, requestedN: 3, selectedIndex: 0, winnerCleared: false, anyCleared: false, ts: 1 } });
  const e = econOf(a);
  assert.equal(e.resolutions, 2);
  assert.equal(e.verified, 1);
});

test("R5 end-to-end: reads the REAL cascade trail via `keep resolution`", async () => {
  const a = app();
  const edit = (f: string, i: number): SearchReplaceEdit => ({ file: f, search: `s_${i}`, replace: `r_${i}`, intent: "x" });
  const testEdit = (i: number): SearchReplaceEdit => ({ file: `tests/t${i}.test.ts`, search: `e_${i}`, replace: `e2_${i}`, intent: "game" });
  const cand = (edits: SearchReplaceEdit[]): SolveResult => ({ issueId: "x", solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, failures: [], vettingCleared: true, detail: "" }, prProposal: { title: "t", body: "b", branch: "keep/x", edits, testsPassed: true } });
  const cleanS: CandidateSolver = async (_i, idx) => cand([edit("src/a.ts", idx)]);
  const failS: CandidateSolver = async (_i, idx) => cand([testEdit(idx)]);
  const tiers: ResolutionTier[] = [{ name: "cheap", n: 2, sample: cleanS, estCostUsd: 1 }, { name: "strong", n: 2, sample: cleanS, estCostUsd: 5 }];
  // easy ticket → verified at cheap
  await resolveCascade({ tiers, spine: a.spine }, { id: "easy", text: "e", repoRef: "r" });
  // hard ticket → all fail → deferred to human
  await resolveCascade({ tiers: [{ name: "cheap", n: 2, sample: failS, estCostUsd: 1 }, { name: "strong", n: 2, sample: failS, estCostUsd: 5 }], spine: a.spine }, { id: "hard", text: "h", repoRef: "r" });

  const out: string[] = [];
  await runCli(["resolution"], { write: (s: string) => out.push(s), prompt: async () => "" }, { app: a });
  const text = out.join("\n");
  assert.match(text, /VERIFIED \(solved\):         1/);
  assert.match(text, /Deferred to a human:       1/);
  assert.match(text, /Cost \/ verified resolution/);
});
