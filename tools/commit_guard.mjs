#!/usr/bin/env node
/**
 * commit_guard.mjs — refuse to commit a NESTED git repository, an agent review WORKTREE, or a stray `.git`. [netguard-allow]
 *
 * Why (build hygiene, mechanical). `git add -A` will happily stage an agent's isolated review worktree (`.claude/worktrees/…`
 * is a nested git repo) as a GITLINK (mode 160000). That silently corrupts the tree: clones don't get the content, and the
 * build/CI sees a phantom submodule. A `.gitignore` helps but is bypassable (`git add -f`) and doesn't cover every location.
 * This guard is the ENFORCEMENT: it inspects the INDEX (what is about to be committed) and FAILS CLOSED if any staged entry
 * is a gitlink or lives under an agent-worktree / `.git` path. Wired as a pre-commit hook (tools/githooks/pre-commit) via
 * `git config core.hooksPath tools/githooks`, and runnable in CI (`node tools/commit_guard.mjs`).
 *
 * DOGFOOD (Increment parity): Keep is a self-hosting agent that COMMITS to its own repo from spawned sub-agents/worktrees —
 * it has this exact hazard, so it ships this same guard. Zero runtime dep: node builtins + git. Exit 0 = clean, 1 = refused.
 */
import { spawnSync } from "node:child_process";

const git = (args) => {
  const r = spawnSync("git", args, { encoding: "utf8" });
  if (r.status !== 0) { console.error(`[commit-guard] git ${args.join(" ")} failed (fail-closed): ${(r.stderr || "").trim()}`); process.exit(2); }
  return r.stdout || "";
};

// [1] GITLINKS in the index — a nested repo/submodule/worktree staged as mode 160000 (the actual corruption).
//     `git ls-files --stage` lists the whole index: "<mode> <sha> <stage>\t<path>". A gitlink has mode 160000.
const gitlinks = git(["ls-files", "--stage"])
  .split("\n")
  .filter((l) => l.startsWith("160000 "))
  .map((l) => l.split("\t").slice(1).join("\t"))
  .filter(Boolean);

// [2] FORBIDDEN PATHS staged for THIS commit — agent worktrees / stray .git dirs (defense in depth beyond the mode check).
const FORBIDDEN = /(^|\/)(\.claude|worktrees|\.git)(\/|$)/;
const badPaths = git(["diff", "--cached", "--name-only"])
  .split("\n")
  .filter((p) => p.length > 0 && FORBIDDEN.test(p));

const bad = [...new Set([...gitlinks, ...badPaths])].sort();
if (bad.length > 0) {
  console.error(
    "[commit-guard] REFUSED: a nested git repository / agent worktree / .git path is staged — this corrupts the tree.\n" +
    bad.map((b) => `  ${b}`).join("\n") +
    "\n\nFix: `git rm -r --cached <path>` (do NOT delete an active agent worktree), ensure `.claude/` is gitignored, and stage explicit paths instead of `git add -A`.",
  );
  process.exit(1);
}
console.log(`[commit-guard] OK — no nested repos / worktrees / .git staged`);
process.exit(0);
