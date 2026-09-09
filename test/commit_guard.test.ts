import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

// tools/commit_guard.mjs refuses to commit a nested git repo / agent worktree / stray .git (the `git add -A` staged-worktree
// hazard). Proven by disproof: a staged nested repo => exit 1; a clean staged file => exit 0.

const GUARD = join(process.cwd(), "tools", "commit_guard.mjs");
const g = (cwd: string, args: string[] = []) => spawnSync("git", args, { cwd, encoding: "utf8" });

function repo(): string {
  const dir = mkdtempSync(join(tmpdir(), "keep-guard-"));
  g(dir, ["init", "-q"]);
  g(dir, ["config", "user.email", "t@t"]); g(dir, ["config", "user.name", "t"]);
  return dir;
}

test("commit guard PASSES a clean staged file (exit 0)", () => {
  const dir = repo();
  try {
    writeFileSync(join(dir, "a.txt"), "hello");
    g(dir, ["add", "a.txt"]);
    const r = spawnSync("node", [GUARD], { cwd: dir, encoding: "utf8" });
    assert.equal(r.status, 0, `guard should pass a clean index\n${r.stdout}\n${r.stderr}`);
    assert.match(r.stdout, /OK/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("commit guard REFUSES a staged NESTED git repository (gitlink — the worktree hazard)", () => {
  const dir = repo();
  try {
    // create a nested git repo and stage it (exactly what `git add -A` does to an agent review worktree).
    const nested = join(dir, "nested");
    mkdirSync(nested, { recursive: true });
    g(nested, ["init", "-q"]);
    g(nested, ["config", "user.email", "t@t"]); g(nested, ["config", "user.name", "t"]);
    writeFileSync(join(nested, "x.txt"), "inner");
    g(nested, ["add", "x.txt"]); g(nested, ["commit", "-q", "-m", "inner"]);
    const add = g(dir, ["add", "-A"]); void add;
    const r = spawnSync("node", [GUARD], { cwd: dir, encoding: "utf8" });
    assert.equal(r.status, 1, `guard must refuse a staged nested repo\n${r.stdout}\n${r.stderr}`);
    assert.match(r.stderr, /REFUSED/);
    assert.match(r.stderr, /nested/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("the REAL committed tree contains no gitlinks / agent worktrees (durable CI check)", () => {
  // catches any nested repo / worktree that ever slipped into a commit. `git ls-tree -r HEAD` mode 160000 = a gitlink.
  const tree = spawnSync("git", ["ls-tree", "-r", "HEAD"], { cwd: process.cwd(), encoding: "utf8" });
  if (tree.status !== 0) return; // not a git checkout (e.g. a tarball) — nothing to check
  const gitlinks = tree.stdout.split("\n").filter((l) => l.startsWith("160000 "));
  assert.deepEqual(gitlinks, [], `committed gitlinks found (nested repos in the tree):\n${gitlinks.join("\n")}`);
  const worktrees = tree.stdout.split("\n").filter((l) => /(\.claude|\/worktrees\/)/.test(l));
  assert.deepEqual(worktrees, [], `committed agent-worktree paths found:\n${worktrees.join("\n")}`);
});

test("commit guard REFUSES a staged .claude worktree path (defense in depth)", () => {
  const dir = repo();
  try {
    mkdirSync(join(dir, ".claude", "worktrees", "agent-x"), { recursive: true });
    writeFileSync(join(dir, ".claude", "worktrees", "agent-x", "f.txt"), "x");
    g(dir, ["add", "-f", ".claude"]); // force-add past a would-be .gitignore
    const r = spawnSync("node", [GUARD], { cwd: dir, encoding: "utf8" });
    assert.equal(r.status, 1, `guard must refuse a staged .claude/worktrees path\n${r.stdout}\n${r.stderr}`);
    assert.match(r.stderr, /REFUSED/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
