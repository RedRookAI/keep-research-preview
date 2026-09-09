import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { selectBestOfN, makeBestOfNSolver, compareCandidates, type CandidateSolver } from "../src/resolve/best_of_n.js";
import { composeKeep } from "../src/compose.js";
import { SnapshotCandidateWorkspaceFactory } from "../src/resolve/candidate_workspace.js";
import { InMemoryWorkspace } from "../src/solve/workspace.js";
import type { Issue, SolveResult, SearchReplaceEdit } from "../src/solve/issue_model.js";

const issue: Issue = { id: "ENG-1", text: "fix the adder", repoRef: "repo" };
const cleanEdit = (file = "src/a.ts", i = 0): SearchReplaceEdit => ({ file, search: `find_${i}`, replace: `repl_${i}`, intent: "fix" });
const testEdit = (): SearchReplaceEdit => ({ file: "tests/a.test.ts", search: "expect(x)", replace: "expect(y)", intent: "game the oracle" });

function candidate(edits: readonly SearchReplaceEdit[], testsPassed: boolean, solved = true): SolveResult {
  return solved
    ? { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed, failures: testsPassed ? [] : ["t1"], vettingCleared: testsPassed, detail: "" }, prProposal: { title: "t", body: "b", branch: "keep/x", edits, testsPassed } }
    : { issueId: issue.id, solved: false, stagesRun: [], repairRounds: 0, gaveUpReason: "no solution" };
}
const samplerOf = (candidates: readonly SolveResult[]): CandidateSolver => async (_i, idx) => candidates[idx]!;

test("R1: a candidate that modifies test files (oracle-gaming) LOSES to a clean one — even if it claims tests passed", async () => {
  const gaming = candidate([testEdit()], true);       // fails the SOUND no-test-modification check
  const honest = candidate([cleanEdit()], true);       // clean
  const res = await selectBestOfN({ sample: samplerOf([gaming, honest]) }, issue, { n: 2, stopWhenClean: false });
  assert.equal(res.selectedIndex, 1, "the honest clean candidate is selected");
  assert.equal(res.winnerCleared, true);
  assert.equal(res.scored[0]!.soundFailures >= 1, true, "the gaming candidate has a sound failure");
});

test("R1 pessimism: among equally-clean candidates the SMALLER (safer) one wins", async () => {
  const big = candidate([cleanEdit("src/a.ts", 1), cleanEdit("src/b.ts", 2), cleanEdit("src/c.ts", 3)], true);
  const small = candidate([cleanEdit("src/a.ts", 1)], true);
  const res = await selectBestOfN({ sample: samplerOf([big, small]) }, issue, { n: 2, stopWhenClean: false });
  assert.equal(res.selectedIndex, 1, "the smaller-blast-radius candidate wins the tie");
});

test("R1: the selection is audited to the spine", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-bon-")) });
  await selectBestOfN({ sample: samplerOf([candidate([cleanEdit()], true)]), spine: app.spine }, issue, { n: 1 });
  const ev = app.spine.currentEvents().map((e) => e.payload as Record<string, unknown>).find((p) => p["event"] === "resolve.best_of_n");
  assert.ok(ev, "a resolve.best_of_n audit event was recorded");
  assert.equal(ev!["issueId"], "ENG-1");
});

test("R1: when NO candidate clears, anyCleared is false (winner is least-bad, not verified)", async () => {
  const a = candidate([testEdit()], true);   // sound fail
  const b = candidate([], true);              // no edits → sound fail (edits-well-formed)
  const res = await selectBestOfN({ sample: samplerOf([a, b]) }, issue, { n: 2, stopWhenClean: false });
  assert.equal(res.anyCleared, false);
});

test("R1 compute-optimal: sampling early-stops once a verified-clean candidate is found", async () => {
  let sampled = 0;
  const sample: CandidateSolver = async (_i, idx) => { sampled++; return idx === 0 ? candidate([cleanEdit()], true) : candidate([testEdit()], true); };
  const res = await selectBestOfN({ sample }, issue, { n: 5, stopWhenClean: true });
  assert.equal(res.sampled, 1, "stopped after the first clean candidate");
  assert.equal(sampled, 1);
});

test("R1: a no-patch candidate sorts last (compareCandidates)", () => {
  const withPatch = { index: 0, result: candidate([cleanEdit()], true), verdict: { cleared: true, outcome: "pass" as const, checks: [], reason: "" }, soundFailures: 0, flags: 0, cleared: true, testsPassed: true, editCount: 1, repairRounds: 0 };
  const noPatch = { index: 1, result: candidate([], false, false), verdict: null, soundFailures: Infinity, flags: Infinity, cleared: false, testsPassed: false, editCount: Infinity, repairRounds: 0 };
  assert.ok(compareCandidates(withPatch, noPatch) < 0);
});

test("R1 wiring: composeKeep with a candidateSolver exposes app.bestOfNSolver, which returns the best candidate", async () => {
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-bon2-")),
    candidateSolver: samplerOf([candidate([testEdit()], true), candidate([cleanEdit()], true)]),
    candidateWorkspaceFactory: new SnapshotCandidateWorkspaceFactory(new InMemoryWorkspace({ repo: {} })),
    bestOfN: { n: 2, stopWhenClean: false },
  });
  assert.ok(app.bestOfNSolver, "app.bestOfNSolver is wired");
  const winner = await app.bestOfNSolver!(issue);
  assert.equal(winner.prProposal?.edits[0]!.file, "src/a.ts", "the clean candidate was chosen");
  assert.ok(app.spine.currentEvents().some((e) => (e.payload as Record<string, unknown>)["event"] === "resolve.best_of_n"));
});

test("R1: best-of-N chooses WHICH candidate, never WHETHER to approve — output is a raw SolveResult", async () => {
  const winner = await makeBestOfNSolver({ sample: samplerOf([candidate([cleanEdit()], true)]) }, { n: 1 })(issue);
  // No disposition / approval / merge on the result — it must still flow through the pipeline + human gate.
  assert.equal("oversight" in winner, false);
  assert.equal("humanApprovalRequired" in winner, false);
  assert.equal(winner.solved, true);
});
