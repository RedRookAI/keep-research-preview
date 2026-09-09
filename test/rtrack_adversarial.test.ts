import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveCascade, type ResolutionTier } from "../src/resolve/budget_cascade.js";
import type { TestGenerator, TestExecutor } from "../src/resolve/novel_tests.js";
import type { CandidateSolver } from "../src/resolve/best_of_n.js";
import { computeResolutionEconomics } from "../src/resolve/resolution_curve.js";
import { composeKeep, type KeepApp } from "../src/compose.js";
import type { Issue, SolveResult, SearchReplaceEdit } from "../src/solve/issue_model.js";
import type { StagedEvent } from "../src/spine/event.js";

const issue: Issue = { id: "ADV-1", text: "fix it", repoRef: "repo" };
const edit = (file: string, i: number): SearchReplaceEdit => ({ file, search: `f_${i}`, replace: `r_${i}`, intent: "fix" });
function candidate(edits: readonly SearchReplaceEdit[]): SolveResult {
  return { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, failures: [], vettingCleared: true, detail: "" }, prProposal: { title: "t", body: "b", branch: "keep/x", edits, testsPassed: true } };
}
const cleanSampler: CandidateSolver = async (_i, idx) => candidate([edit("src/a.ts", idx)]);
const tier = (name: string, sample: CandidateSolver, estCostUsd: number, extra: Partial<ResolutionTier> = {}): ResolutionTier => ({ name, n: 2, sample, estCostUsd, ...extra });
const generator: TestGenerator = { generate: async () => [{ id: "t1", description: "discriminating" }] };
const forkExec: TestExecutor = { run: async (_t, _c, idx) => (idx === 0 ? "pass" : "fail") }; // splits the verified pool

// ── GAP 1: R5 must count a CLEARED-BUT-DEFERRED outcome as deferred (not verified) ──
// R4 can legitimately emit {winnerCleared:true, escalateToHuman:true} (a cleared-but-forked best at exhaustion).
// The cardinal rule must treat that as containment, not resolution. The existing cardinal test only used the
// easy cases (cleared+notHuman, notCleared+human); this pins the subtle one so a naive `if (cleared) verified++`
// simplification can never pass silently.
test("R5 ADVERSARIAL: a CLEARED result that still defers to human is counted DEFERRED, never verified", () => {
  const mk = (issueId: string, winnerCleared: boolean, escalateToHuman: boolean, stoppedReason: string): StagedEvent[] => ([
    { seq: 0, hash: "", prevHash: "", type: "identity.action", actor: "cascade", ts: 1, payload: { event: "resolve.cascade.tier", issueId, tier: "cheap", estCostUsd: 1, ts: 1 } } as unknown as StagedEvent,
    { seq: 0, hash: "", prevHash: "", type: "identity.action", actor: "cascade", ts: 2, payload: { event: "resolve.cascade.done", issueId, tiersUsed: ["cheap"], escalations: 0, stoppedReason, escalateToHuman, winnerCleared, behavioralFork: escalateToHuman, ts: 2 } } as unknown as StagedEvent,
  ]);
  const events = [
    ...mk("verified-1", true, false, "verified"),   // the ONLY genuine resolution
    ...mk("cleared-but-forked", true, true, "exhausted"), // cleared, yet deferred → must NOT count verified
    ...mk("not-cleared", false, true, "exhausted"),
  ];
  const econ = computeResolutionEconomics(events);
  assert.equal(econ.resolutions, 3);
  assert.equal(econ.verified, 1, "only the cleared-AND-not-deferred outcome is verified");
  assert.equal(econ.deferredToHuman, 2, "the cleared-but-deferred outcome is contained, not resolved");
});

// ── GAP 2: R4 must defer to human when the FINAL tier clears but FORKS (no stronger tier to escalate to) ──
// A behavioral fork means the verified candidates disagree; that must never be auto-reported as verified, even
// when it happens at the last tier and there is nowhere to escalate. Otherwise a fork silently becomes a resolution.
test("R4 ADVERSARIAL: a fork at the FINAL tier defers to human — never a false 'verified'", async () => {
  const app: KeepApp = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-adv-")) });
  // Single tier, tests-on: 2 verified candidates that the executor splits → cleared + behavioral fork, and it's
  // the last (only) tier, so the loop exhausts.
  const res = await resolveCascade(
    { tiers: [tier("only", cleanSampler, 1, { useTests: true })], generator, executor: forkExec, spine: app.spine },
    issue,
  );
  assert.equal(res.behavioralFork, true, "the fork was detected");
  assert.notEqual(res.stoppedReason, "verified", "a fork is never a verified stop");
  assert.equal(res.escalateToHuman, true, "an unresolved fork defers to the human — the permanent fallback");
  // And the economics of this run must record it as deferred, not verified.
  const econ = computeResolutionEconomics(app.spine.currentEvents());
  assert.equal(econ.verified, 0, "a forked final tier is not a verified resolution");
  assert.equal(econ.deferredToHuman, 1);
});

// ── GAP 3: R4 exhaustion keeps escalateToHuman even when an EARLIER tier cleared-but-forked ──
// Two tiers both fork; best/bestCleared persist but lastFork tracks only the last tier. Exhaustion must still
// defer to human regardless of the retained bestCleared flag.
test("R4 ADVERSARIAL: cleared-but-forked earlier tier + non-clearing exhaustion still defers to human", async () => {
  const app: KeepApp = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-adv2-")) });
  const res = await resolveCascade(
    { tiers: [tier("cheap", cleanSampler, 1, { useTests: true }), tier("strong", cleanSampler, 5, { useTests: true })], generator, executor: forkExec, spine: app.spine },
    issue,
  );
  // Both tiers fork → never a verified early-return → exhausted → human.
  assert.equal(res.stoppedReason, "exhausted");
  assert.equal(res.escalateToHuman, true, "exhaustion always defers to human, even with a retained cleared best");
});
