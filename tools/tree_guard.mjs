#!/usr/bin/env node
/**
 * tree_guard.mjs — mechanical working-tree integrity tripwire. [netguard-allow]
 *
 * THE HAZARD (observed 2026-08-18). A review/neuter sub-agent — or any concurrent process — that runs in the CANONICAL
 * checkout instead of an isolated worktree can mutate source files WHILE they are under active edit: a neuter-verify
 * (`perl -pi src/...` + restore) races the primary editor and the human reader, and in the worst case leaves a
 * safety-disabled ("NEUTERED") file behind. Prevention is `isolation: "worktree"` on the spawned agent (the agent
 * physically cannot reach the canonical tree). This guard is the BACKSTOP: it makes the drift DETECTABLE and fail-loud
 * so it is caught in seconds, not discovered later.
 *
 * This guard uses CONTENT HASHES, not text markers: a "leaked neuter" is not reliably a string (the codebase
 * legitimately discusses neuter-testing throughout), it is an UNEXPECTED CHANGE to a file under active work. The
 * durable, no-false-positive enforcement lives in the pre-push hook (a neutered safety check reddens a test, so a
 * non-green tree cannot be pushed); THIS tool is the fast content-drift tripwire around a review handoff.
 *
 * USAGE (wrap any tree-touching handoff — e.g. before/after spawning review agents, or a review round):
 *   node tools/tree_guard.mjs snapshot            # record sha256 of every git-tracked file + HEAD into the sentinel
 *   node tools/tree_guard.mjs snapshot <paths...> # …or just the paths under active work
 *   node tools/tree_guard.mjs verify              # exit 0 if unchanged; exit 1 (listing drift) if any file changed
 *
 * Exit codes: 0 = clean, 1 = drift detected, 2 = usage/internal error. Zero runtime deps: node builtins + git.
 *
 * DOGFOOD (Keep parity): Keep supervises agents that mutate a repo; a REVIEW / mutation-assurance operation must never
 * mutate the LIVE artifact (it runs in isolation). This is the mechanical assertion of that invariant — the same guard
 * Keep uses to prove a review pass left the supervised tree byte-for-byte untouched.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";

const SENTINEL = ".keep-tree-sentinel.json"; // gitignored; a transient local record, never committed

function git(args) {
  const r = spawnSync("git", args, { encoding: "utf8" });
  if (r.status !== 0) { console.error(`[tree-guard] git ${args.join(" ")} failed: ${(r.stderr || "").trim()}`); process.exit(2); }
  return r.stdout || "";
}
function trackedFiles() {
  return git(["ls-files"]).split("\n").map((s) => s.trim()).filter(Boolean);
}
function sha(path) {
  try { return createHash("sha256").update(readFileSync(path)).digest("hex"); } catch { return "<absent>"; }
}
function head() {
  const r = spawnSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" });
  return r.status === 0 ? (r.stdout || "").trim() : "<none>";
}

function snapshot(paths) {
  const files = paths.length > 0 ? paths : trackedFiles();
  const record = { head: head(), files: {} };
  for (const p of files) record.files[p] = sha(p);
  writeFileSync(SENTINEL, JSON.stringify(record, null, 2));
  console.log(`[tree-guard] snapshot: ${Object.keys(record.files).length} file(s) at HEAD ${record.head.slice(0, 12)}`);
}

function verify() {
  if (!existsSync(SENTINEL)) { console.error(`[tree-guard] no snapshot (${SENTINEL}) — run \`snapshot\` first`); process.exit(2); }
  const record = JSON.parse(readFileSync(SENTINEL, "utf8"));
  const drift = [];
  for (const [p, want] of Object.entries(record.files)) {
    const got = sha(p);
    if (got !== want) drift.push(`  ${p}: ${want.slice(0, 12)} → ${got === "<absent>" ? "REMOVED" : got.slice(0, 12)}`);
  }
  if (drift.length > 0) {
    console.error(`[tree-guard] DRIFT: ${drift.length} snapshotted file(s) changed since the snapshot (concurrent modification?):\n${drift.join("\n")}\n\nIf a review/neuter agent did this, it was NOT isolated — restore with \`git checkout -- <path>\` (committed work is safe) and re-run the agent with isolation: "worktree".`);
    process.exit(1);
  }
  console.log(`[tree-guard] OK — ${Object.keys(record.files).length} file(s) unchanged since snapshot`);
  return record;
}

const cmd = process.argv[2];
const rest = process.argv.slice(3);
if (cmd === "snapshot") { snapshot(rest); process.exit(0); }
else if (cmd === "verify") { verify(); process.exit(0); }
else { console.error("usage: tree_guard.mjs <snapshot [paths...] | verify>"); process.exit(2); }
