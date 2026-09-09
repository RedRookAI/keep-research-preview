import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { selectBestOfN, type CandidateSolver, type CandidateSelector } from "../src/resolve/best_of_n.js";
import { HybridSelector } from "../src/resolve/selector.js";
import { composeKeep } from "../src/compose.js";
import type { Issue, SolveResult, SearchReplaceEdit } from "../src/solve/issue_model.js";
import { SnapshotCandidateWorkspaceFactory } from "../src/resolve/candidate_workspace.js";
import { InMemoryWorkspace } from "../src/solve/workspace.js";

const issue: Issue = { id: "ENG-2", text: "fix it", repoRef: "repo" };
const edit = (file: string, i: number): SearchReplaceEdit => ({ file, search: `find_${i}`, replace: `repl_${i}`, intent: "fix" });
const testEdit = (i: number): SearchReplaceEdit => ({ file: `tests/t${i}.test.ts`, search: `expect_${i}`, replace: `expect2_${i}`, intent: "game" });
function candidate(edits: readonly SearchReplaceEdit[], testsPassed = true, solved = true): SolveResult {
  return solved
    ? { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed, failures: [], vettingCleared: testsPassed, detail: "" }, prProposal: { title: "t", body: "b", branch: "keep/x", edits, testsPassed } }
    : { issueId: issue.id, solved: false, stagesRun: [], repairRounds: 0, gaveUpReason: "gave up" };
}
const samplerOf = (c: readonly SolveResult[]): CandidateSolver => async (_i, idx) => c[idx]!;

test("R2 SAFETY: a confident-wrong MAJORITY cannot override verification — the lone verified candidate wins", async () => {
  // Two candidates agree with each other (same approach) but BOTH fail the sound no-test-modification check.
  const wrongA = candidate([testEdit(1)]);
  const wrongB = candidate([testEdit(1)]); // identical approach → they'd form a consensus cluster of 2
  const rightSolo = candidate([edit("src/a.ts", 1)]); // the one verified candidate
  const res = await selectBestOfN({ sample: samplerOf([wrongA, wrongB, rightSolo]), selector: HybridSelector }, issue, { n: 3, stopWhenClean: false });
  assert.equal(res.selectedIndex, 2, "the verified singleton wins over the agreeing-but-unverified majority");
  assert.equal(res.winnerCleared, true);
});

test("R2 hybrid: among VERIFIED candidates, the consensus approach beats a smaller lone approach", async () => {
  const a0 = candidate([edit("src/a.ts", 1), edit("src/a.ts", 2)]); // approach {src/a.ts}, 2 edits
  const a1 = candidate([edit("src/a.ts", 3), edit("src/a.ts", 4)]); // approach {src/a.ts}, 2 edits → cluster of 2
  const z = candidate([edit("src/z.ts", 5)]);                        // approach {src/z.ts}, 1 edit (smaller)
  // Default (safety-first) would pick the smaller lone candidate z:
  const dflt = await selectBestOfN({ sample: samplerOf([a0, a1, z]) }, issue, { n: 3, stopWhenClean: false });
  assert.equal(dflt.selectedIndex, 2, "default tie-break prefers the smallest verified candidate");
  // Hybrid keeps consensus as the prior → picks from the 2-candidate cluster:
  const hyb = await selectBestOfN({ sample: samplerOf([a0, a1, z]), selector: HybridSelector }, issue, { n: 3, stopWhenClean: false });
  assert.ok(hyb.selectedIndex === 0 || hyb.selectedIndex === 1, "hybrid prefers the consensus approach {src/a.ts}");
  assert.equal(hyb.winner.prProposal?.edits[0]!.file, "src/a.ts");
});

test("R2: within the winning consensus cluster, safety refines the tie (smaller wins)", async () => {
  const big = candidate([edit("src/a.ts", 1), edit("src/a.ts", 2), edit("src/a.ts", 6)]); // {src/a.ts}, 3 edits
  const small = candidate([edit("src/a.ts", 3)]);                                          // {src/a.ts}, 1 edit
  const other = candidate([edit("src/b.ts", 9)]);                                          // {src/b.ts}, singleton
  const res = await selectBestOfN({ sample: samplerOf([big, small, other]), selector: HybridSelector }, issue, { n: 3, stopWhenClean: false });
  assert.equal(res.selectedIndex, 1, "the smaller member of the consensus cluster is chosen");
});

test("R2: a malicious selector cannot pick a non-verified candidate — the floor is structural", async () => {
  const evil: CandidateSelector = { select: () => ({ index: 0, rationale: "always pick the first (evil)" }) };
  const clean = candidate([edit("src/a.ts", 1)]);
  const failing1 = candidate([testEdit(1)]);
  const failing2 = candidate([testEdit(2)]);
  // Even though the selector always returns index 0, it only ever receives the CLEARED set.
  const res = await selectBestOfN({ sample: samplerOf([failing1, failing2, clean]), selector: evil }, issue, { n: 3, stopWhenClean: false });
  assert.equal(res.winnerCleared, true, "the winner is verified despite the malicious selector");
  assert.equal(res.selectedIndex, 2);
});

test("R2: with no cleared candidate, the selector is not consulted (least-bad flows to review)", async () => {
  const res = await selectBestOfN({ sample: samplerOf([candidate([testEdit(1)]), candidate([], true)]), selector: HybridSelector }, issue, { n: 2, stopWhenClean: false });
  assert.equal(res.anyCleared, false);
});

test("R2: the selection rationale is audited", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-sel-")) });
  await selectBestOfN({ sample: samplerOf([candidate([edit("src/a.ts", 1)]), candidate([edit("src/a.ts", 2)])]), selector: HybridSelector, spine: app.spine }, issue, { n: 2, stopWhenClean: false });
  const ev = app.spine.currentEvents().map((e) => e.payload as Record<string, unknown>).find((p) => p["event"] === "resolve.best_of_n");
  assert.match(String(ev!["selection"]), /hybrid/);
});

test("R2 wiring: composeKeep threads candidateSelector into app.bestOfNSolver", async () => {
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-sel2-")),
    candidateSolver: samplerOf([candidate([edit("src/a.ts", 1), edit("src/a.ts", 2)]), candidate([edit("src/a.ts", 3), edit("src/a.ts", 4)]), candidate([edit("src/z.ts", 9)])]),
    candidateSelector: HybridSelector,
    candidateWorkspaceFactory: new SnapshotCandidateWorkspaceFactory(new InMemoryWorkspace({ repo: {} })),
    bestOfN: { n: 3, stopWhenClean: false },
  });
  const winner = await app.bestOfNSolver!(issue);
  assert.equal(winner.prProposal?.edits[0]!.file, "src/a.ts", "the composed hybrid selector chose the consensus approach");
});
