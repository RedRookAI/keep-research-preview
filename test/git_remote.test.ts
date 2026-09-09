import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

import { GitAdapter } from "../src/infra/git_adapter.js";
import { GitRemote, ProtectedBranchError } from "../src/git/git_remote.js";
import { pinnedRemoteFetchUrlSha256, pinnedRemoteUrlSha256 } from "../src/git/pinned_remote.js";

/** Set up a real bare remote + a clone with an initial commit on main. Returns paths. */
function setupRepo(): { work: string; bare: string } {
  const root = mkdtempSync(join(tmpdir(), "keep-git-"));
  const bare = join(root, "origin.git");
  const work = join(root, "work");
  execFileSync("git", ["init", "-q", "--bare", bare]);
  execFileSync("git", ["clone", "-q", bare, work]);
  const g = (args: string[]) => execFileSync("git", args, { cwd: work });
  g(["config", "user.email", "t@t"]);
  g(["config", "user.name", "t"]);
  g(["checkout", "-qb", "main"]);
  execFileSync("bash", ["-c", `echo hello > ${join(work, "f.txt")}`]);
  g(["add", "-A"]);
  g(["commit", "-qm", "init"]);
  g(["push", "-q", "-u", "origin", "main"]);
  g(["remote", "set-url", "origin", `file://${bare}`]);
  return { work, bare };
}

function pinnedConfig(bare: string) {
  return { expectedFetchUrlSha256: pinnedRemoteFetchUrlSha256(`file://${bare}`), expectedPushUrlSha256: pinnedRemoteUrlSha256(`file://${bare}`) };
}

test("INVARIANT: classification — isProtected + isKeepBranch", () => {
  assert.equal(GitRemote.isProtected("main"), true);
  assert.equal(GitRemote.isProtected("master"), true);
  assert.equal(GitRemote.isProtected("release/1.2"), true);
  assert.equal(GitRemote.isProtected("keep/solve/BUG-1"), false);
  assert.equal(GitRemote.isKeepBranch("keep/solve/BUG-1"), true);
  assert.equal(GitRemote.isKeepBranch("feature/x"), false);
});

test("INVARIANT: createTaskBranch enforces the keep/ prefix", async () => {
  const { work } = setupRepo();
  const remote = new GitRemote(new GitAdapter(work));
  await remote.createTaskBranch("keep/solve/OK");
  await assert.rejects(() => remote.createTaskBranch("feature/nope"), /keep\/.*prefix/);
});

test("INVARIANT: pushing a keep/ branch to a real bare remote WORKS + is visible in a fresh clone", async () => {
  const { work, bare } = setupRepo();
  const remote = new GitRemote(new GitAdapter(work), { runId: "run-1", ...pinnedConfig(bare) });
  await remote.createTaskBranch("keep/solve/BUG-1");
  execFileSync("bash", ["-c", `echo fix >> ${join(work, "f.txt")}`]);
  await remote.commitWithAttribution("fix BUG-1", "a1");
  await remote.pushTaskBranch("keep/solve/BUG-1", "push-1");

  // Verify in a fresh clone of the bare remote.
  const root = mkdtempSync(join(tmpdir(), "keep-git-verify-"));
  execFileSync("git", ["clone", "-q", bare, root]);
  const branches = execFileSync("git", ["branch", "-a"], { cwd: root }).toString();
  assert.match(branches, /keep\/solve\/BUG-1/, "the keep branch reached the remote");
});

test("INVARIANT: pushing a PROTECTED branch is REFUSED", async () => {
  const { work } = setupRepo();
  const remote = new GitRemote(new GitAdapter(work));
  await assert.rejects(() => remote.pushTaskBranch("main", "p"), (e: unknown) => e instanceof ProtectedBranchError);
  await assert.rejects(() => remote.pushTaskBranch("master", "p"), (e: unknown) => e instanceof ProtectedBranchError);
});

test("INVARIANT: pushing a non-keep branch is refused", async () => {
  const { work } = setupRepo();
  const remote = new GitRemote(new GitAdapter(work));
  await assert.rejects(() => remote.pushTaskBranch("feature/x", "p"), /only keep/);
});

test("INVARIANT: commitWithAttribution appends the audit trailer", async () => {
  const { work } = setupRepo();
  const remote = new GitRemote(new GitAdapter(work), { runId: "run-42", attribution: "Keep <keep@local>" });
  execFileSync("bash", ["-c", `echo x >> ${join(work, "f.txt")}`]);
  await remote.commitWithAttribution("do a thing", "a1");
  const msg = execFileSync("git", ["log", "-1", "--pretty=%B"], { cwd: work }).toString();
  assert.match(msg, /Keep-Run-Id: run-42/);
  assert.match(msg, /Co-authored-by: Keep <keep@local>/);
});

test("INVARIANT: push ReversibleAction undo deletes the remote branch", async () => {
  const { work, bare } = setupRepo();
  const remote = new GitRemote(new GitAdapter(work), pinnedConfig(bare));
  await remote.createTaskBranch("keep/solve/TMP");
  execFileSync("bash", ["-c", `echo y >> ${join(work, "f.txt")}`]);
  await remote.commitWithAttribution("tmp", "a1");
  const action = await remote.pushTaskBranch("keep/solve/TMP", "push-1");

  let remoteBranches = execFileSync("git", ["branch"], { cwd: bare }).toString();
  assert.match(remoteBranches, /keep\/solve\/TMP/, "branch on remote after push");
  await action.undo();
  remoteBranches = execFileSync("git", ["branch"], { cwd: bare }).toString();
  assert.doesNotMatch(remoteBranches, /keep\/solve\/TMP/, "undo removed the remote branch");
});

test("INVARIANT: fetch + pull work against the real remote", async () => {
  const { work, bare } = setupRepo();
  const remote = new GitRemote(new GitAdapter(work), pinnedConfig(bare));
  await remote.fetch(); // should not throw
  await remote.pull("main"); // should not throw
  assert.ok(true);
});

test("listKeepBranches filters to keep/* only", async () => {
  const { work } = setupRepo();
  const g = new GitAdapter(work);
  const remote = new GitRemote(g);
  await remote.createTaskBranch("keep/solve/A");
  await g.git(["checkout", "main"]);
  await g.git(["checkout", "-b", "feature/unrelated"]);
  const keeps = await remote.listKeepBranches();
  assert.ok(keeps.includes("keep/solve/A"));
  assert.ok(!keeps.some((b) => b.includes("feature")), "non-keep branches excluded");
});

test("RED-TEAM REGRESSION: malformed/path-traversal keep branch names are rejected", () => {
  assert.equal(GitRemote.isKeepBranch("keep/../main"), false, "path traversal rejected");
  assert.equal(GitRemote.isKeepBranch("keep//x"), false, "double slash rejected");
  assert.equal(GitRemote.isKeepBranch("keep/x y"), false, "whitespace rejected");
  assert.equal(GitRemote.isKeepBranch("keep/"), false, "empty tail rejected");
  assert.equal(GitRemote.isKeepBranch("keep/solve/BUG-1"), true, "well-formed still accepted");
});
