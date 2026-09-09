import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, chmodSync, symlinkSync, rmSync, mkdirSync, renameSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

import {
  fingerprintTree,
  gitWriteTreeId,
  leafHash,
  hashLeafBytes,
  hashNodeBytes,
  FP_SCHEME,
} from "../src/spine/tree_fingerprint.js";

/** A throwaway tree; caller populates it, we clean it up. */
function scratch(): string {
  return mkdtempSync(join(tmpdir(), "keep-fp-"));
}
function cleanup(...dirs: string[]): void {
  for (const d of dirs) try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
}

// ─────────────────────────────────────────────────────────────────────────────
// (a) CONTENT — identical content is EQUAL; any byte edit MOVES the hash.
//     Neuter target: the content digest mix-in in the file leaf.
// ─────────────────────────────────────────────────────────────────────────────
test("INVARIANT: identical content fingerprints EQUAL; a content edit MOVES the hash", () => {
  const a = scratch(), b = scratch();
  try {
    mkdirSync(join(a, "sub")); mkdirSync(join(b, "sub"));
    writeFileSync(join(a, "sub", "f.txt"), "hello"); writeFileSync(join(a, "top.txt"), "x");
    writeFileSync(join(b, "sub", "f.txt"), "hello"); writeFileSync(join(b, "top.txt"), "x");

    const fa = fingerprintTree(a);
    assert.ok(fa.startsWith(FP_SCHEME), "self-describing sha256: scheme");
    assert.equal(fa, fingerprintTree(b), "two checkouts of identical content fingerprint identically");

    writeFileSync(join(b, "sub", "f.txt"), "hellp"); // one byte differs
    assert.notEqual(fa, fingerprintTree(b), "a one-byte content change MOVES the fingerprint");

    writeFileSync(join(b, "sub", "f.txt"), "hello"); // restore
    assert.equal(fa, fingerprintTree(b), "restoring the content restores the fingerprint");
  } finally { cleanup(a, b); }
});

// ─────────────────────────────────────────────────────────────────────────────
// (b) MODE — an exec-bit flip MOVES the hash; non-exec umask noise does NOT.
//     Neuter target: the mode mix-in in the file leaf.
// ─────────────────────────────────────────────────────────────────────────────
test("INVARIANT: an exec-bit flip MOVES the hash; umask noise does not", () => {
  const a = scratch();
  try {
    const f = join(a, "run.sh");
    writeFileSync(f, "#!/bin/sh\necho hi\n");
    chmodSync(f, 0o644);
    const base = fingerprintTree(a);

    chmodSync(f, 0o755);
    assert.notEqual(base, fingerprintTree(a), "setting the exec bit MOVES the fingerprint");

    chmodSync(f, 0o644);
    assert.equal(base, fingerprintTree(a), "clearing the exec bit restores it");

    chmodSync(f, 0o640); // umask noise, still non-exec
    assert.equal(base, fingerprintTree(a), "non-exec mode noise does NOT move it");
  } finally { cleanup(a); }
});

// ─────────────────────────────────────────────────────────────────────────────
// (c) KIND — a symlink and a file with identical mode+digest do NOT collide.
//     Isolated at the leaf primitive so ONLY the kind tag differs; then the
//     end-to-end symlink->file swap is also asserted to move.
//     Neuter target: the kind tag in the leaf body.
// ─────────────────────────────────────────────────────────────────────────────
test("INVARIANT: the kind tag distinguishes a symlink from a file at identical mode+digest", () => {
  const digest = "a".repeat(64);
  const asFile = leafHash("file", "120000", digest);
  const asSymlink = leafHash("symlink", "120000", digest);
  assert.notEqual(asFile, asSymlink, "same mode+digest, different kind => different leaf hash");
});

test("INVARIANT: a symlink->file swap with the same target bytes MOVES the fingerprint", () => {
  const a = scratch();
  try {
    symlinkSync("hello", join(a, "l")); // symlink whose target string is "hello"
    const withLink = fingerprintTree(a);
    rmSync(join(a, "l"));
    writeFileSync(join(a, "l"), "hello"); // regular file with the same bytes as the target
    assert.notEqual(withLink, fingerprintTree(a), "symlink vs regular file with identical bytes do not collide");
  } finally { cleanup(a); }
});

// ─────────────────────────────────────────────────────────────────────────────
// (d) DOMAIN SEPARATION — a real node body presented as a leaf does NOT collide
//     with the node (RFC 6962 / Kelsey-Schneier second-preimage).
//     Neuter target: the 0x00 / 0x01 domain prefix.
// ─────────────────────────────────────────────────────────────────────────────
test("INVARIANT: domain separation — a crafted child-concatenation cannot be forged as a subtree", () => {
  // P is exactly the kind of body an interior node hashes (a concatenation of child hashes). An
  // attacker who could present it as a LEAF would forge a subtree as a single datum.
  const childA = leafHash("file", "100644", "b".repeat(64));
  const childB = leafHash("file", "100644", "c".repeat(64));
  const P = new TextEncoder().encode(`a\0${childA}\0b\0${childB}\0`);
  assert.notEqual(hashLeafBytes(P), hashNodeBytes(P), "identical bytes hash differently as leaf vs node");
});

// ─────────────────────────────────────────────────────────────────────────────
// PATH — a rename MOVES the hash (the NFC name committed at each node carries the path).
//     Neuter target: same as (c)/(d) family — the name in the node child row (covered by nodeHash).
// ─────────────────────────────────────────────────────────────────────────────
test("INVARIANT: a rename MOVES the fingerprint even when content is unchanged", () => {
  const a = scratch();
  try {
    writeFileSync(join(a, "old.txt"), "same bytes");
    const before = fingerprintTree(a);
    renameSync(join(a, "old.txt"), join(a, "new.txt"));
    assert.notEqual(before, fingerprintTree(a), "renaming a file (same bytes) MOVES the fingerprint");
  } finally { cleanup(a); }
});

// ─────────────────────────────────────────────────────────────────────────────
// GIT PARITY — where `.git` exists, the pure-JS walk moves EXACTLY when git's own
//     tree id moves. git is the ORACLE/accelerator; the walk is the contract.
// ─────────────────────────────────────────────────────────────────────────────
test("INVARIANT: git write-tree parity — the walk moves iff git's tree id moves", () => {
  const a = scratch();
  try {
    execFileSync("git", ["init", "-q"], { cwd: a });
    execFileSync("git", ["config", "user.email", "t@t"], { cwd: a });
    execFileSync("git", ["config", "user.name", "t"], { cwd: a });
    writeFileSync(join(a, "f.txt"), "hello");

    const git1 = gitWriteTreeId(a);
    assert.ok(git1, "git write-tree available on a real .git");
    const fp1 = fingerprintTree(a);

    // Edit content: BOTH git's tree id and the fingerprint must move.
    writeFileSync(join(a, "f.txt"), "hellp");
    const git2 = gitWriteTreeId(a);
    const fp2 = fingerprintTree(a);
    assert.equal(git1 !== git2, fp1 !== fp2, "content edit: walk moves iff git tree id moves");
    assert.notEqual(fp1, fp2, "content edit moved both");

    // Exec-bit flip: git tracks it in the tree id; so must the fingerprint.
    chmodSync(join(a, "f.txt"), 0o755);
    const git3 = gitWriteTreeId(a);
    const fp3 = fingerprintTree(a);
    assert.equal(git2 !== git3, fp2 !== fp3, "exec-bit flip: walk moves iff git tree id moves");
    assert.notEqual(fp2, fp3, "exec-bit flip moved both");
  } finally { cleanup(a); }
});
