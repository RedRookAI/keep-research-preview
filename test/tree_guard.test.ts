import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, appendFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// tools/tree_guard.mjs — the mechanical content-drift tripwire that makes a concurrent modification of a file under
// active work (e.g. an un-isolated review/neuter agent clobbering the live tree) DETECTABLE and fail-loud. Proven by
// disproof: an unchanged tree verifies (exit 0); ANY content change to a snapshotted file is detected (exit 1).

const GUARD = join(process.cwd(), "tools", "tree_guard.mjs");
const g = (cwd: string, args: string[]) => spawnSync("git", args, { cwd, encoding: "utf8" });
const guard = (cwd: string, args: string[]) => spawnSync("node", [GUARD, ...args], { cwd, encoding: "utf8" });

function repo(): string {
  const dir = mkdtempSync(join(tmpdir(), "keep-treeguard-"));
  g(dir, ["init", "-q"]);
  g(dir, ["config", "user.email", "t@t"]); g(dir, ["config", "user.name", "t"]);
  writeFileSync(join(dir, "a.ts"), "export const a = 1;\n");
  writeFileSync(join(dir, "b.ts"), "export const b = 2;\n");
  g(dir, ["add", "-A"]); g(dir, ["commit", "-q", "-m", "init"]);
  return dir;
}

test("tree_guard: an unchanged tree verifies clean (exit 0)", () => {
  const dir = repo();
  try {
    assert.equal(guard(dir, ["snapshot"]).status, 0);
    const v = guard(dir, ["verify"]);
    assert.equal(v.status, 0, `unchanged tree must verify\n${v.stdout}\n${v.stderr}`);
    assert.match(v.stdout, /unchanged/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("tree_guard: a concurrent modification is DETECTED and fails loud (exit 1)", () => {
  const dir = repo();
  try {
    guard(dir, ["snapshot"]);
    appendFileSync(join(dir, "a.ts"), "// a review agent that was NOT isolated wrote this\n");
    const v = guard(dir, ["verify"]);
    assert.equal(v.status, 1, "a modified snapshotted file must be detected");
    assert.match(v.stderr, /DRIFT/);
    assert.match(v.stderr, /a\.ts/);
    assert.match(v.stderr, /isolation/); // the remediation names worktree isolation
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("tree_guard: a removed file is detected as drift", () => {
  const dir = repo();
  try {
    guard(dir, ["snapshot", "b.ts"]);
    rmSync(join(dir, "b.ts"));
    const v = guard(dir, ["verify"]);
    assert.equal(v.status, 1);
    assert.match(v.stderr, /REMOVED/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("tree_guard: verify without a prior snapshot is a usage error (exit 2), not a false pass", () => {
  const dir = repo();
  try {
    const v = guard(dir, ["verify"]);
    assert.equal(v.status, 2, "no snapshot must not silently pass");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("the committed pre-push hook protects main without recursively running verification", () => {
  // Task-branch pushes are continuity operations. CI/merge verification owns the
  // full suite, while the local hook only prevents direct protected-branch pushes.
  const cfg = spawnSync("git", ["config", "core.hooksPath"], { cwd: process.cwd(), encoding: "utf8" });
  if (cfg.status !== 0) return; // not a git checkout (tarball) — nothing to assert
  assert.match(cfg.stdout.trim(), /githooks/, "core.hooksPath must point at the committed hooks");
  const prepush = spawnSync("cat", [join(process.cwd(), "tools", "githooks", "pre-push")], { encoding: "utf8" });
  assert.match(prepush.stdout, /main\|master/);
  assert.doesNotMatch(prepush.stdout, /npm test|discipline_guard|prepush_scope/);
  void mkdirSync; // (imported for parity with other tmp-dir tests)
});
