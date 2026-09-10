import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync, symlinkSync, linkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LocalFsWorkspace } from "../src/solve/workspace.js";
import { materializeRepository, spineMaterializationJournal } from "../src/git/repository_materializer.js";
import { materializeOfficialTask } from "../src/eval/official_swebench.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import type { EvalTask } from "../src/eval/swebench_task.js";

// Connected follow-ups from the KEEP-09B-001/11A-004 review sweep, not new
// original audit IDs. All repositories/effects are synthetic and builder-owned.
function fixture() {
  const root = mkdtempSync(join(tmpdir(), "keep-path-workspace-"));
  const source = join(root, "source"), workspace = join(root, "workspace");
  mkdirSync(source); mkdirSync(workspace);
  return { root, source, workspace };
}
function git(cwd: string, ...args: string[]) {
  return execFileSync("git", args, { cwd, encoding: "utf8", timeout: 5000 }).trim();
}
function repository() {
  const f = fixture();
  git(f.source, "init", "-q", "-b", "main");
  git(f.source, "config", "user.name", "Keep Test");
  git(f.source, "config", "user.email", "keep@test.invalid");
  writeFileSync(join(f.source, "work.txt"), "original\n");
  git(f.source, "add", "work.txt"); git(f.source, "commit", "-qm", "synthetic base");
  return { ...f, commit: git(f.source, "rev-parse", "HEAD") };
}

test("path follow-up: real workspace permits dot-prefixed repository and file components", async () => {
  const { workspace } = fixture();
  const repo = join(workspace, "..project");
  mkdirSync(join(repo, "..cache"), { recursive: true });
  writeFileSync(join(repo, "..cache/input.txt"), "before");
  const ws = new LocalFsWorkspace(workspace);
  assert.equal(ws.dir("..project"), repo);
  assert.ok((await ws.files("..project")).some(f => f.path === "..cache/input.txt" && f.content === "before"));
  const tree = ws.tree("..project");
  assert.equal(await tree.read("..cache/input.txt"), "before");
  await tree.write("..cache/new.txt", "created");
  assert.equal(readFileSync(join(repo, "..cache/new.txt"), "utf8"), "created");
  assert.equal(await tree.commitBatchIfUnchanged!({ "..cache/input.txt": "before" }, [{ path: "..cache/input.txt", content: "after" }]), true);
  assert.equal(await tree.read("..cache/input.txt"), "after");
  assert.equal(await tree.commitBatchIfUnchanged!({ "..cache/input.txt": "before" }, [{ path: "..cache/input.txt", content: "wrong" }]), false);
  assert.equal(readFileSync(join(repo, "..cache/input.txt"), "utf8"), "after");
});

test("path follow-up: workspace retains outside, symlink and hardlink refusals", async () => {
  const { source, workspace } = fixture();
  const repo = join(workspace, "project"); mkdirSync(repo);
  const outside = join(source, "secret.txt"); writeFileSync(outside, "unchanged");
  const ws = new LocalFsWorkspace(workspace);
  assert.throws(() => ws.tree("../source"), /escapes/);
  const tree = ws.tree("project");
  await assert.rejects(() => tree.write(outside, "wrong"), /escapes/);
  symlinkSync(source, join(repo, "..alias"), "dir");
  assert.equal(await tree.read("..alias/secret.txt"), undefined);
  await assert.rejects(() => tree.write("..alias/secret.txt", "wrong"), /not a real directory/);
  linkSync(outside, join(repo, "..linked.txt"));
  assert.equal(await tree.read("..linked.txt"), undefined);
  await assert.rejects(() => tree.write("..linked.txt", "wrong"), /escapes/);
  assert.equal(readFileSync(outside, "utf8"), "unchanged");
  symlinkSync(source, join(workspace, "..repo-alias"), "dir");
  assert.throws(() => ws.tree("..repo-alias"), /real directory/);
});

test("path follow-up: exact revision materialization into dot-prefixed child preserves durable reuse", async () => {
  const f = repository();
  const state = join(f.root, "state");
  const makeJournal = () => spineMaterializationJournal(new Spine(new FileSpineStore(state, { fsync: true }), new InProcessLock(), new SchemaRegistry()));
  const request = { sourceDir: f.source, workspaceBase: f.workspace, repoRef: "..project", commit: f.commit };
  const first = await materializeRepository(request, undefined, makeJournal());
  assert.equal(first.projectDir, join(f.workspace, "..project"));
  assert.equal(git(first.projectDir, "rev-parse", "HEAD"), f.commit);
  writeFileSync(join(first.projectDir, "proposal.txt"), "retained work");
  const restored = await materializeRepository(request, undefined, makeJournal());
  assert.equal(restored.commit, f.commit);
  assert.equal(readFileSync(join(restored.projectDir, "proposal.txt"), "utf8"), "retained work");
  await assert.rejects(() => materializeRepository({ ...request, baseBranch: "other" }, undefined, makeJournal()), /durable provenance/);
  assert.equal(git(f.source, "status", "--porcelain"), "");
});

test("path follow-up: materialization still rejects equal, parent, outside and metadata destinations", async () => {
  const f = repository();
  for (const repoRef of [".", "..", "../escape", f.source, ".git"]) {
    await assert.rejects(() => materializeRepository({ sourceDir: f.source, workspaceBase: f.workspace, repoRef, commit: f.commit }), /escapes or aliases/);
  }
  assert.equal(existsSync(join(f.root, "escape")), false);
  assert.equal(git(f.source, "status", "--porcelain"), "");
});

test("path follow-up: synthetic official-task materialization accepts literal dot-prefix without exposing hidden checks", async () => {
  const f = repository();
  const task: EvalTask = { instanceId: "..synthetic-1", repo: "synthetic/project", baseCommit: f.commit,
    problemStatement: "synthetic only", failToPass: ["test_synthetic"], passToPass: [],
    testPatch: "held-out synthetic check", goldPatch: "hidden synthetic answer" };
  const out = await materializeOfficialTask(task, f.source, f.workspace);
  assert.equal(out.projectDir, join(f.workspace, "..synthetic-1"));
  assert.equal(git(out.projectDir, "rev-parse", "HEAD"), f.commit);
  assert.equal(readFileSync(join(out.projectDir, "work.txt"), "utf8"), "original\n");
  assert.equal("testPatch" in out.task, false); assert.equal("goldPatch" in out.task, false);
  for (const instanceId of [".", ".."]) {
    await assert.rejects(() => materializeOfficialTask({ ...task, instanceId }, f.source, f.workspace), /escapes/);
  }
  // Cleanup is confined to the exact newly created synthetic destination.
  await out.cleanup();
  assert.equal(existsSync(out.projectDir), false);
  assert.equal(readFileSync(join(f.source, "work.txt"), "utf8"), "original\n");
});
