import assert from "node:assert/strict";
import test from "node:test";
import { existsSync, linkSync, mkdtempSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { localizeProjectRepository } from "../src/autonomy/project_localization.js";
import { buildAutonomyLoop } from "../src/autonomy/autonomy_loop.js";
import type { ProjectState } from "../src/autonomy/project_state.js";
import type { Localizer } from "../src/solve/localize.js";
import { InMemoryWorkspace, LocalFsWorkspace, type Workspace } from "../src/solve/workspace.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";

const projectState = (): ProjectState => ({
  schemaVersion: 1, revision: 3, runId: "loc", goal: "fix validateToken in this local repository", stage: "plan", posture: "autonomous",
  artifacts: {}, stepsRemaining: 20, reworkCount: 0, status: "running",
  retry: { attemptsByStage: {}, attemptsConsumed: 0, runLimit: 8 }, consumedSignals: [],
});

const localizer: Localizer = {
  async localize(_issue, files, k) {
    const file = files.find((candidate) => candidate.path === "src/token.ts")!;
    return { suspects: [{ path: file.path, score: 2, isTest: false, suspectSymbols: ["validateToken"] }].slice(0, k), stages: ["bm25", "graph"] };
  },
};

test("localization persists deterministic repository and candidate identities without file bytes", async () => {
  const secret = "export function validateToken() { return 'private-source-byte'; }";
  const a = new InMemoryWorkspace({ repo: { "test/token.test.ts": "test", "src/token.ts": secret } });
  const b = new InMemoryWorkspace({ repo: { "src/token.ts": secret, "test/token.test.ts": "test" } });
  const first = await localizeProjectRepository(projectState(), a, "repo", localizer);
  const second = await localizeProjectRepository(projectState(), b, "repo", localizer);
  assert.equal(first.repositoryTreeSha256, second.repositoryTreeSha256);
  assert.equal(first.selected[0]?.path, "src/token.ts");
  assert.equal(first.selected[0]?.suspectSymbols[0], "validateToken");
  assert.ok(!JSON.stringify(first).includes("private-source-byte"));
});

test("an exact existing path named by the operator precedes ranked alternatives", async () => {
  const workspace = new InMemoryWorkspace({ repo: { "README.md": "short", "docs/large.txt": "x".repeat(30_000) } });
  const localized = await localizeProjectRepository({ ...projectState(), goal: "Update README.md only." }, workspace, "repo", {
    async localize() { return { suspects: [{ path: "docs/large.txt", score: 99, isTest: false }], stages: ["bm25"] }; },
  }, 1);
  assert.deepEqual(localized.selected.map((candidate) => candidate.path), ["README.md"]);
});

test("default named-path localization avoids full graph construction without losing complete source identity", async () => {
  const workspace = new InMemoryWorkspace({ repo: { "src/token.ts": "export const token = 1;", "src/other.ts": "export const other = 2;" } });
  const named = await localizeProjectRepository({ ...projectState(), goal: "Fix src/token.ts" }, workspace, "repo");
  assert.deepEqual(named.stages, ["bm25"]); assert.equal(named.inspectedFiles, 2); assert.equal(named.selected[0]!.path, "src/token.ts");
  const configured = await localizeProjectRepository({ ...projectState(), goal: "Fix src/token.ts" }, workspace, "repo", localizer);
  assert.deepEqual(configured.stages, ["bm25", "graph"]); assert.equal(configured.repositoryTreeSha256, named.repositoryTreeSha256);
});

test("localization rejects ambiguous workspace identity and invented localizer paths", async () => {
  const duplicate = { files: async () => [{ path: "a.ts", content: "a" }, { path: "a.ts", content: "b" }], tree: () => { throw new Error("unused"); } };
  await assert.rejects(localizeProjectRepository(projectState(), duplicate, "repo", localizer), /duplicate project path/);
  const invented: Localizer = { async localize() { return { suspects: [{ path: "outside.ts", score: 1, isTest: false }], stages: ["bm25"] }; } };
  await assert.rejects(localizeProjectRepository(projectState(), new InMemoryWorkspace({ repo: { "a.ts": "a" } }), "repo", invented), /outside the inspected repository/);
});

test("enterprise localizer metadata cannot become malformed durable project truth", async () => {
  const workspace = new InMemoryWorkspace({ repo: { "a.ts": "a" } });
  const duplicate: Localizer = { async localize() { return { suspects: [{ path: "a.ts", score: 1, isTest: false }, { path: "a.ts", score: 0.5, isTest: false }], stages: ["bm25"] }; } };
  await assert.rejects(localizeProjectRepository(projectState(), workspace, "repo", duplicate), /duplicate candidate path/);
  const badStage = { localize: async () => ({ suspects: [{ path: "a.ts", score: 1, isTest: false }], stages: ["invented"] }) } as unknown as Localizer;
  await assert.rejects(localizeProjectRepository(projectState(), workspace, "repo", badStage), /invalid stage trace/);
  const badSymbols = { localize: async () => ({ suspects: [{ path: "a.ts", score: 1, isTest: false, suspectSymbols: [""] }], stages: ["bm25"] }) } as Localizer;
  await assert.rejects(localizeProjectRepository(projectState(), workspace, "repo", badSymbols), /invalid suspect symbols/);
});

test("localization bounds candidate count and rejects traversal-shaped adapter paths", async () => {
  const unsafe = { files: async () => [{ path: "../secret.ts", content: "secret" }], tree: () => { throw new Error("unused"); } };
  await assert.rejects(localizeProjectRepository(projectState(), unsafe, "repo", localizer), /unsafe or non-canonical/);
  await assert.rejects(localizeProjectRepository(projectState(), new InMemoryWorkspace({ repo: { "a.ts": "a" } }), "repo", localizer, 0), /integer from 1 to 20/);
  const tooMany = { localize: async () => ({ suspects: [{ path: "a.ts", score: 2, isTest: false }, { path: "b.ts", score: 1, isTest: false }], stages: ["bm25"] }) } as Localizer;
  await assert.rejects(localizeProjectRepository(projectState(), new InMemoryWorkspace({ repo: { "a.ts": "a", "b.ts": "b" } }), "repo", tooMany, 1), /more candidates than requested/);
});

test("empty and unrelated repositories are explicit non-blocking localization outcomes", async () => {
  const empty = await localizeProjectRepository(projectState(), new InMemoryWorkspace({ repo: {} }), "repo", localizer);
  assert.equal(empty.disposition, "no-readable-files");
  assert.deepEqual(empty.selected, []);
  const none: Localizer = { async localize() { return { suspects: [], stages: ["bm25"] }; } };
  const unrelated = await localizeProjectRepository(projectState(), new InMemoryWorkspace({ repo: { "a.ts": "a" } }), "repo", none);
  assert.equal(unrelated.disposition, "no-candidates");
});

test("built-in filesystem workspace does not read file or directory symlinks outside its root", async () => {
  const base = mkdtempSync(join(tmpdir(), "keep-workspace-"));
  const repo = join(base, "repo");
  const outside = mkdtempSync(join(tmpdir(), "keep-outside-"));
  mkdirSync(join(repo, "src"), { recursive: true });
  writeFileSync(join(repo, "src", "safe.ts"), "safe");
  writeFileSync(join(outside, "secret.ts"), "outside-secret");
  symlinkSync(join(outside, "secret.ts"), join(repo, "src", "linked.ts"));
  symlinkSync(outside, join(repo, "linked-dir"));
  const files = await new LocalFsWorkspace(base).files("repo");
  assert.deepEqual(files, [{ path: "src/safe.ts", content: "safe" }]);
  assert.ok(!JSON.stringify(files).includes("outside-secret"));
});

test("built-in filesystem tree refuses symlinked read and write targets outside its root", async () => {
  const base = mkdtempSync(join(tmpdir(), "keep-workspace-write-"));
  const repo = join(base, "repo");
  const outside = mkdtempSync(join(tmpdir(), "keep-workspace-write-outside-"));
  mkdirSync(repo);
  writeFileSync(join(outside, "secret.ts"), "unchanged");
  symlinkSync(join(outside, "secret.ts"), join(repo, "linked.ts"));
  symlinkSync(outside, join(repo, "linked-dir"));
  const tree = new LocalFsWorkspace(base).tree("repo");
  assert.equal(await tree.read("linked.ts"), undefined);
  await assert.rejects(tree.write("linked.ts", "overwritten"));
  await assert.rejects(tree.write("linked-dir/new/file.ts", "created"));
  assert.equal(readFileSync(join(outside, "secret.ts"), "utf8"), "unchanged");
  assert.equal(existsSync(join(outside, "new")), false);
});

test("filesystem workspace provides atomic content-bound batch comparison", async () => {
  const base = mkdtempSync(join(tmpdir(), "keep-workspace-cas-"));
  const repo = join(base, "repo");
  mkdirSync(repo);
  writeFileSync(join(repo, "a.ts"), "a1");
  writeFileSync(join(repo, "b.ts"), "b1");
  const tree = new LocalFsWorkspace(base).tree("repo");
  assert.equal(await tree.commitBatchIfUnchanged!({ "a.ts": "a1", "b.ts": "b1" }, [{ path: "a.ts", content: "a2" }, { path: "b.ts", content: "b2" }]), true);
  writeFileSync(join(repo, "b.ts"), "owner-change");
  assert.equal(await tree.commitBatchIfUnchanged!({ "a.ts": "a2", "b.ts": "b2" }, [{ path: "a.ts", content: "a3" }]), false);
  assert.equal(readFileSync(join(repo, "a.ts"), "utf8"), "a2", "a stale batch changes no member");
});

test("built-in filesystem workspace refuses multiply-linked files as ambiguous authority", async () => {
  const base = mkdtempSync(join(tmpdir(), "keep-workspace-hardlink-"));
  const repo = join(base, "repo");
  const outside = mkdtempSync(join(tmpdir(), "keep-workspace-hardlink-outside-"));
  mkdirSync(repo);
  writeFileSync(join(outside, "shared.ts"), "outside");
  linkSync(join(outside, "shared.ts"), join(repo, "shared.ts"));
  const workspace = new LocalFsWorkspace(base);
  assert.deepEqual(await workspace.files("repo"), []);
  assert.equal(await workspace.tree("repo").read("shared.ts"), undefined);
  await assert.rejects(workspace.tree("repo").write("shared.ts", "changed"));
  assert.equal(readFileSync(join(outside, "shared.ts"), "utf8"), "outside");
});

test("the composed project runtime reaches localization before its enforcement-time solve", async () => {
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-localize-spine-"))), new InProcessLock(), new SchemaRegistry());
  let solved = false;
  const loop = buildAutonomyLoop({
    spine,
    solve: async (issue) => { solved = true; return { solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, detail: "ok" } } } as never; },
    projectWorkspace: new InMemoryWorkspace({ repo: { "src/token.ts": "export function validateToken() {}" } }),
    projectLocalizer: localizer,
    repoRef: "repo",
  });
  const run = await loop.runProject("fix validateToken in this local repository", { runId: "localized-runtime", stepBudget: 50 });
  assert.equal(run.state.status, "completed");
  assert.equal(solved, true);
  const plan = run.state.artifacts.plan as { localization?: { repositoryRef?: string; selected?: readonly { path?: string }[] } };
  assert.equal(plan.localization?.repositoryRef, "repo");
  assert.equal(plan.localization?.selected?.[0]?.path, "src/token.ts");
  assert.deepEqual((run.state.artifacts.plan as { steps?: readonly { id?: string }[] }).steps?.map((step) => step.id), ["implement", "verify"]);
  assert.equal((run.state.artifacts.vet_plan as { proceed?: boolean }).proceed, true, "the persisted plan is consumed by deterministic vetting before solve");
});

test("optional localization defects degrade to recorded deterministic planning instead of a human gate", async () => {
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-localize-fallback-spine-"))), new InProcessLock(), new SchemaRegistry());
  const backing = new InMemoryWorkspace({ repo: { "safe.ts": "export const safe = true;" } });
  const hostile: Workspace = {
    files: async () => [{ path: "src\\hostile.ts", content: "x" }],
    tree: (repoRef) => backing.tree(repoRef),
  };
  let solved = false;
  const loop = buildAutonomyLoop({
    spine, projectWorkspace: hostile, repoRef: "repo",
    solve: async (issue) => { solved = true; return { solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, detail: "ok" } } } as never; },
  });
  const run = await loop.runProject("write and test a local parser library", { runId: "localization-fallback", stepBudget: 50 });
  assert.equal(run.state.status, "completed");
  assert.equal(solved, true);
  const plan = run.state.artifacts.plan as { localization?: unknown; localizationFallback?: { mechanism?: string; reason?: string } };
  assert.equal(plan.localization, undefined);
  assert.equal(plan.localizationFallback?.mechanism, "deterministic-without-localization");
  assert.equal(plan.localizationFallback?.reason, "optional localization failed with Error");
  assert.equal((run.state.artifacts.vet_plan as { proceed?: boolean }).proceed, true);
});
