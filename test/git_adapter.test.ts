import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { RollbackLedger } from "../src/control/rollback.js";
import { GitAdapter } from "../src/infra/git_adapter.js";

/** Create a fresh git repo with an initial commit; return its path. */
function newRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), "keep-git-"));
  execFileSync("git", ["init", "-q"], { cwd: dir });
  execFileSync("git", ["config", "user.email", "keep@test"], { cwd: dir });
  execFileSync("git", ["config", "user.name", "Keep Test"], { cwd: dir });
  writeFileSync(join(dir, "app.txt"), "line one\n");
  execFileSync("git", ["add", "-A"], { cwd: dir });
  execFileSync("git", ["commit", "-q", "-m", "initial"], { cwd: dir });
  return dir;
}

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-git-spine-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

test("commitAll makes a REAL commit and returns its SHA", async () => {
  const dir = newRepo();
  const git = new GitAdapter(dir);
  writeFileSync(join(dir, "app.txt"), "line one\nline two\n");
  const action = await git.commitAll("add line two", "act-1");
  assert.match(action.artifact, /^[0-9a-f]{40}$/); // a real 40-char SHA
  assert.equal(action.artifact, await git.head());
  assert.equal((await git.logOneline()).length, 2);
});

test("undo() REALLY reverts the commit — history preserved (revert, not reset) and file content restored", async () => {
  const dir = newRepo();
  const git = new GitAdapter(dir);
  writeFileSync(join(dir, "app.txt"), "line one\nBAD CHANGE\n");
  const action = await git.commitAll("bad change", "act-1");
  assert.ok(readFileSync(join(dir, "app.txt"), "utf8").includes("BAD CHANGE"));

  await action.undo(); // real git revert

  // File content is restored on disk...
  assert.ok(!readFileSync(join(dir, "app.txt"), "utf8").includes("BAD CHANGE"));
  // ...and history is PRESERVED (a new Revert commit exists; the bad commit remains).
  const log = await git.logOneline();
  assert.equal(log.length, 3); // initial, bad, revert
  assert.ok(log[0]!.toLowerCase().includes("revert"));
});

test("RollbackLedger runs the REAL git inverse end-to-end and records to the spine", async () => {
  const dir = newRepo();
  const git = new GitAdapter(dir);
  const spine = newSpine();
  const ledger = new RollbackLedger(spine);

  writeFileSync(join(dir, "app.txt"), "line one\nregression\n");
  const action = await git.commitAll("introduce regression", "act-1");
  ledger.record(action);

  const result = await ledger.rollback(1, "regression detected");
  assert.equal(result.rolledBack, 1);
  assert.ok(!readFileSync(join(dir, "app.txt"), "utf8").includes("regression")); // real revert ran
  const events = spine.currentEvents().map((e) => (e.payload as Record<string, unknown>)["event"]);
  assert.ok(events.includes("rollback_complete"));
});

test("revert of a specific commit returns a new revert SHA", async () => {
  const dir = newRepo();
  const git = new GitAdapter(dir);
  writeFileSync(join(dir, "app.txt"), "line one\nx\n");
  const action = await git.commitAll("change", "act-1");
  const revertSha = await git.revert(action.artifact);
  assert.match(revertSha, /^[0-9a-f]{40}$/);
  assert.notEqual(revertSha, action.artifact);
});

test("worktree isolation creates a separate checkout sharing the object store", async () => {
  const dir = newRepo();
  const git = new GitAdapter(dir);
  const wt = join(mkdtempSync(join(tmpdir(), "keep-wt-")), "isolated");
  await git.addWorktree(wt, "keep/isolated-work");
  assert.ok(readFileSync(join(wt, "app.txt"), "utf8").includes("line one")); // checked out
  await git.removeWorktree(wt);
});

test("isClean reflects working-tree state", async () => {
  const dir = newRepo();
  const git = new GitAdapter(dir);
  assert.equal(await git.isClean(), true);
  writeFileSync(join(dir, "app.txt"), "dirty\n");
  assert.equal(await git.isClean(), false);
});
