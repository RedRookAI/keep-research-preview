import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { analyzePassMatrix, makeBehavioralSelector, selectBestOfNWithTests, type GeneratedTest, type TestResult, type TestGenerator, type TestExecutor } from "../src/resolve/novel_tests.js";
import { scoreAll } from "../src/resolve/best_of_n.js";
import { composeKeep } from "../src/compose.js";
import type { Issue, SolveResult, SearchReplaceEdit } from "../src/solve/issue_model.js";
import { SnapshotCandidateWorkspaceFactory } from "../src/resolve/candidate_workspace.js";
import { InMemoryWorkspace } from "../src/solve/workspace.js";

const issue: Issue = { id: "ENG-3", text: "fix it", repoRef: "repo" };
const edit = (file: string, i: number): SearchReplaceEdit => ({ file, search: `f_${i}`, replace: `r_${i}`, intent: "fix" });
const testEdit = (i: number): SearchReplaceEdit => ({ file: `tests/t${i}.test.ts`, search: `e_${i}`, replace: `e2_${i}`, intent: "game" });
function candidate(edits: readonly SearchReplaceEdit[], testsPassed = true, solved = true): SolveResult {
  return solved
    ? { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed, failures: [], vettingCleared: testsPassed, detail: "" }, prProposal: { title: "t", body: "b", branch: "keep/x", edits, testsPassed } }
    : { issueId: issue.id, solved: false, stagesRun: [], repairRounds: 0, gaveUpReason: "gave up" };
}
const T = (id: string): GeneratedTest => ({ id, description: id });

test("R3: discriminative weighting — a 50/50 split test is maximal; all-pass is zero; no-pass is discarded", () => {
  const tests = [T("split"), T("allpass"), T("nopass")];
  const matrix: TestResult[][] = [
    ["pass", "fail"],   // split → p=0.5 → weight 1
    ["pass", "pass"],   // all pass → weight 0 (valid, non-discriminating)
    ["fail", "fail"],   // no pass → discarded (invalid)
  ];
  const a = analyzePassMatrix(tests, [0, 1], matrix);
  assert.equal(a.stats[0]!.discriminativeWeight, 1);
  assert.equal(a.stats[0]!.validated, true);
  assert.equal(a.stats[1]!.discriminativeWeight, 0);
  assert.equal(a.stats[1]!.validated, true);
  assert.equal(a.stats[2]!.validated, false, "a test no candidate passes is discarded as likely-wrong");
});

test("R3: behavioral clustering groups candidates by validated-test pass-profile", () => {
  const tests = [T("t1"), T("t2")];
  // c0 and c2 share a profile; c1 differs. (t's are discriminating.)
  const matrix: TestResult[][] = [
    ["pass", "fail", "pass"],
    ["fail", "pass", "fail"],
  ];
  const a = analyzePassMatrix(tests, [0, 1, 2], matrix);
  assert.equal(a.profileByIndex.get(0), a.profileByIndex.get(2), "c0 and c2 behaviorally equivalent");
  assert.notEqual(a.profileByIndex.get(0), a.profileByIndex.get(1));
  assert.equal(a.clusters.length, 2);
});

test("R3: a behavioral fork among verified candidates is flagged (→ escalate to human)", () => {
  const a = analyzePassMatrix([T("d")], [0, 1], [["pass", "fail"]]);
  assert.equal(a.behavioralFork, true);
  // no discriminating test → no fork signal even if profiles differ trivially
  const b = analyzePassMatrix([T("allpass")], [0, 1], [["pass", "pass"]]);
  assert.equal(b.behavioralFork, false);
});

test("R3 SAFETY: generated tests NEVER override the sound floor — a sound-failing candidate stays rejected even if it passes every generated test", () => {
  // candidate 0 modifies test files (sound fail) but "passes" all generated tests; candidate 1 is sound-clean.
  const scored = scoreAll([candidate([testEdit(1)]), candidate([edit("src/a.ts", 1)])]);
  assert.equal(scored[0]!.cleared, false, "the test-modifying candidate fails the sound floor regardless of generated tests");
  assert.equal(scored[1]!.cleared, true);
});

test("R3 end-to-end: floor first, then behavioral selection among verified; fork escalates; never auto-approves", async () => {
  // Three sampled candidates: two clean sharing an approach, one clean lone approach, plus the floor already filters.
  const cands = [candidate([edit("src/a.ts", 1)]), candidate([edit("src/a.ts", 2)]), candidate([edit("src/z.ts", 3)])];
  const sample = async (_i: Issue, idx: number) => cands[idx]!;
  const generator: TestGenerator = { generate: async () => [T("d1")] };
  // d1 splits the pool: candidates 0,1 pass; candidate 2 fails → behavioral fork.
  const executor: TestExecutor = { run: async (_t, _c, idx) => (idx === 2 ? "fail" : "pass") };
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-r3-")) });
  const res = await selectBestOfNWithTests({ sample, generator, executor, spine: app.spine }, issue, { n: 3 });
  assert.equal(res.winnerCleared, true, "winner is verified (floor first)");
  assert.equal(res.behavioralFork, true, "the behavioral divergence is flagged for human review");
  // the winner comes from the larger behavioral cluster {0,1}
  assert.ok(res.selectedIndex === 0 || res.selectedIndex === 1);
  const ev = app.spine.currentEvents().map((e) => e.payload as Record<string, unknown>).find((p) => p["event"] === "resolve.novel_tests");
  assert.equal(ev!["behavioralFork"], true);
  assert.equal(ev!["validatedTests"], 1);
});

test("R3 wiring: composeKeep exposes app.resolveWithTests when the seams are configured", async () => {
  const cands = [candidate([edit("src/a.ts", 1)]), candidate([edit("src/a.ts", 2)]), candidate([edit("src/z.ts", 3)])];
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-r3w-")),
    candidateSolver: async (_i, idx) => cands[idx]!,
    testGenerator: { generate: async () => [T("d1")] },
    testExecutor: { run: async (_t, _c, idx) => (idx === 2 ? "fail" : "pass") },
    candidateWorkspaceFactory: new SnapshotCandidateWorkspaceFactory(new InMemoryWorkspace({ repo: {} })),
    bestOfN: { n: 3 },
  });
  assert.ok(app.resolveWithTests, "app.resolveWithTests is wired");
  const res = await app.resolveWithTests!(issue);
  assert.equal(res.winnerCleared, true);
  assert.equal(res.behavioralFork, true);
});

test("R3: makeBehavioralSelector upgrades R2 clustering to pass-profiles", () => {
  const cleared = scoreAll([candidate([edit("src/a.ts", 1)]), candidate([edit("src/a.ts", 2)]), candidate([edit("src/a.ts", 3)])]);
  // Statically all three share approach {src/a.ts}; behaviorally, tests split them 2 vs 1.
  const analysis = analyzePassMatrix([T("d")], [0, 1, 2], [["pass", "pass", "fail"]]);
  const sel = makeBehavioralSelector(analysis).select(cleared);
  // behavioral cluster {0,1} (profile "1") beats singleton {2} (profile "0")
  assert.ok(sel.index === 0 || sel.index === 1);
  assert.match(sel.rationale, /hybrid/);
});
