import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import { selectBestOfN, type CandidateExecution, type CandidateSolver } from "../src/resolve/best_of_n.js";
import { isolateCandidateSolver, SnapshotCandidateWorkspaceFactory, type CandidateWorkspaceFactory } from "../src/resolve/candidate_workspace.js";
import { InMemoryWorkspace } from "../src/solve/workspace.js";

const issue = { id: "RESOLVE-02", text: "isolate candidates", repoRef: "repo" };
const noPatch = (index: number) => ({ issueId: issue.id, solved: false, stagesRun: [], repairRounds: 0, gaveUpReason: `candidate ${index}` } as const);

test("RESOLVE-02: two concurrent candidates mutate distinct workspaces and cannot observe each other", async () => {
  const source = new InMemoryWorkspace({ repo: { "state.txt": "base" } });
  const factory = new SnapshotCandidateWorkspaceFactory(source); const workspaces = new Set<object>(); const refs = new Set<string>();
  let arrived = 0; let release!: () => void; const both = new Promise<void>((resolve) => { release = resolve; });
  const sample: CandidateSolver = async (candidateIssue, index, execution) => {
    assert.ok(execution?.workspace && execution.repoRef);
    workspaces.add(execution.workspace); refs.add(execution.repoRef); assert.equal(candidateIssue.repoRef, execution.repoRef);
    await execution.workspace.tree(execution.repoRef).write("state.txt", `candidate-${index}`);
    if (++arrived === 2) release(); await both;
    assert.equal(await execution.workspace.tree(execution.repoRef).read("state.txt"), `candidate-${index}`);
    return noPatch(index);
  };
  await selectBestOfN({ sample: isolateCandidateSolver(sample, factory) }, issue, { n: 2, stopWhenClean: false, concurrency: 2 });
  assert.equal(workspaces.size, 2); assert.equal(refs.size, 2);
  assert.equal(await source.tree("repo").read("state.txt"), "base", "candidate writes never reach the source workspace");
  await source.tree("repo").write("state.txt", "next-base");
  const observed: string[] = [];
  const readOnly: CandidateSolver = async (_candidateIssue, index, execution) => { observed.push((await execution!.workspace!.tree(execution!.repoRef!).read("state.txt"))!); return noPatch(index); };
  await selectBestOfN({ sample: isolateCandidateSolver(readOnly, factory) }, issue, { n: 2, stopWhenClean: false });
  assert.deepEqual(observed, ["next-base", "next-base"], "a later resolution captures a fresh base while its candidates share that base");
});

test("RESOLVE-02: workspace lease releases even when a candidate throws", async () => {
  let released = 0;
  const factory: CandidateWorkspaceFactory = { allocate: async (_issue, execution: CandidateExecution) => ({ workspaceId: execution.executionId, workspace: new InMemoryWorkspace({ isolated: {} }), repoRef: "isolated", release: () => { released++; } }) };
  const isolated = isolateCandidateSolver(async () => { throw new Error("candidate failed"); }, factory);
  await assert.rejects(isolated(issue, 0, { executionId: "failure:0", sampleIndex: 0, resolutionId: "failure-resolution" }), /candidate failed/);
  assert.equal(released, 1);
});

test("RESOLVE-02: installed N>1 composition fails closed without a workspace factory", () => {
  assert.throws(() => composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-resolve02-refuse-")), candidateSolver: async (_issue, index) => noPatch(index), bestOfN: { n: 2 } }), /requires a candidateWorkspaceFactory/);
});

