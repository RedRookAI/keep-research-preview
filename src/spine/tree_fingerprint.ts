/**
 * tree_fingerprint — a content-addressed identity for a WHOLE WORKSPACE (a directory tree), not just
 * an individual state blob. The "same source" anchor: two trees fingerprint identically IFF their
 * governed content is byte-identical, so a supply-chain swap of a file cannot pass as "the tree we
 * attested," and a revert/reproducible-build check can ask "is this the same tree?" soundly.
 *
 * WHY KEEP NEEDS ITS OWN (dogfood of redrook-ops/keep-fingerprint.mjs). Keep today content-addresses
 * only per-file state (coderag/code_graph.ts `sha256Hex`/`contentHash`) and per-blob spine hashes. It
 * has NO identity for a whole tree. The loop already ships a whole-tree fingerprint; this is the
 * KEEP-PRODUCT equivalent, HARDENED from that flat manifest into a genuine recursive, domain-separated
 * Merkle tree.
 *
 * THREE PROPERTIES, none optional, each proven RED by an isolating neuter in the tests:
 *   (1) CONTENT   — a file's bytes are mixed in (via the shared sha256), so any edit moves the hash.
 *   (2) METADATA  — the git-style exec-bit MODE (100644 / 100755 / symlink 120000), the PATH (via the
 *                   NFC-normalized name committed at each directory node), and the KIND (file vs
 *                   symlink) are all committed. A pure-bytes hash is BLIND to an exec-bit flip, a
 *                   rename, and a symlink->file swap — so it cannot be a tamper-evident anchor.
 *   (3) DOMAIN SEPARATION — leaf bytes are prefixed 0x00 and node bytes 0x01 (RFC 6962 §2.1). Without
 *                   this an internal node can be presented as a leaf: a crafted directory's child-hash
 *                   concatenation collides with a single file's data (the Kelsey-Schneier 2004 /
 *                   Certificate-Transparency second-preimage). Domain separation forecloses it.
 *
 * OFFLINE IS THE CONTRACT. The pure-JS walk needs no network and no git. Where a `.git` exists,
 * `git write-tree` is an OPTIONAL cross-check/accelerator (see `gitWriteTreeId`) — an ORACLE the tests
 * assert behavioral parity against, NEVER a dependency of the fingerprint.
 *
 * COMPOSED, ZERO-DEP. All hashing goes through the single `sha256Hex` mechanism exported by
 * coderag/code_graph.ts — there is no second hash primitive and no new dependency.
 *
 * HONEST LIMITS (stated, as keep-fingerprint.mjs states its own):
 *   - EMPTY DIRECTORIES: an empty directory IS committed (as a node with no children), unlike a flat
 *     file manifest which cannot see it.
 *   - UNICODE: paths are NFC-normalized before hashing, so the same tree on macOS (NFD) and Linux
 *     (NFC) fingerprints identically — one improvement over the flat manifest's stated NFC/NFD seam.
 *   - LINE ENDINGS are content: a CRLF checkout is a different fingerprint (correct, but surprising if
 *     git autocrlf is on).
 *   - CASE-INSENSITIVE filesystems can still collapse two paths differing only in case.
 *   - The `.gitignore` support is a pragmatic subset (default excludes + basename / path-prefix
 *     patterns), NOT full gitignore semantics; it is a convenience over the offline walk, not a
 *     security boundary.
 */

import { readdirSync, lstatSync, readFileSync, readlinkSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";

import { sha256Hex } from "../coderag/code_graph.js";

/** RFC 6962 §2.1 domain-separation prefixes: leaf bytes carry 0x00, interior-node bytes carry 0x01. */
const LEAF = 0x00;
const NODE = 0x01;

/** Self-describing output: the fingerprint announces its algorithm so it can never be mistaken for a
 *  bare digest or silently reinterpreted under a different hash. */
export const FP_SCHEME = "sha256:";

/** Default excludes mirror solve/workspace.ts and keep-fingerprint.mjs — an unstated exclusion is how
 *  two operators compute different answers for the same tree. */
export const DEFAULT_EXCLUDES: ReadonlySet<string> = new Set([".git", "node_modules", "dist"]);

const nfc = (s: string): string => s.normalize("NFC");

/** git-style exec-bit-only mode. Drops umask noise, keeps the one bit that decides whether a script runs. */
function fileMode(mode: number): string {
  return mode & 0o111 ? "100755" : "100644";
}

/**
 * The domain-separated hash CORE — the ONLY place the leaf/node distinction lives. `tag` is the RFC
 * 6962 prefix byte; everything downstream composes over `sha256Hex`. This function is what neuter (d)
 * targets: collapse the two tags and a subtree becomes forgeable as a leaf.
 */
function tagged(tag: number, body: Uint8Array): string {
  const buf = new Uint8Array(body.length + 1);
  buf[0] = tag;
  buf.set(body, 1);
  return sha256Hex(buf);
}

/** Hash a body AS A LEAF (0x00). Exposed for the domain-separation test. */
export function hashLeafBytes(body: Uint8Array): string {
  return tagged(LEAF, body);
}

/** Hash a body AS A NODE (0x01). Exposed for the domain-separation test. */
export function hashNodeBytes(body: Uint8Array): string {
  return tagged(NODE, body);
}

/**
 * Leaf hash of a blob-like entry (a file or a symlink). The body commits the KIND tag, the MODE, and
 * the content DIGEST — remove any one and a distinct tree collides (the neuters in the tests prove it).
 * `contentDigestHex` is `sha256Hex(bytes)` for a file, or `sha256Hex(symlinkTarget)` for a symlink.
 */
export function leafHash(kind: "file" | "symlink", mode: string, contentDigestHex: string): string {
  return hashLeafBytes(new TextEncoder().encode(`${kind}\0${mode}\0${contentDigestHex}`));
}

/**
 * Node hash of a directory. Children are byte-sorted by NFC name (so walk order is irrelevant and the
 * result is deterministic), then each contributes `name \0 childEntryHash \0`. The name commits the
 * PATH transitively; the childEntryHash already commits that child's kind/mode/content.
 */
export function nodeHash(children: readonly { readonly name: string; readonly hash: string }[]): string {
  const sorted = [...children].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  let body = "";
  for (const c of sorted) body += `${c.name}\0${c.hash}\0`;
  return hashNodeBytes(new TextEncoder().encode(body));
}

export interface FingerprintOptions {
  /** Directory/file basenames to always skip. Defaults to {@link DEFAULT_EXCLUDES}. */
  readonly excludes?: ReadonlySet<string>;
  /** Honor a root `.gitignore` (pragmatic subset). Default true. Never a dependency — a convenience. */
  readonly gitignore?: boolean;
}

/** Build the ignore predicate: default excludes + (optionally) a pragmatic subset of the root .gitignore. */
function buildIgnore(root: string, opts: FingerprintOptions): (relPath: string, name: string) => boolean {
  const excludes = opts.excludes ?? DEFAULT_EXCLUDES;
  const patterns: string[] = [];
  if (opts.gitignore !== false) {
    try {
      const gi = readFileSync(join(root, ".gitignore"), "utf8");
      for (const line of gi.split("\n")) {
        const t = line.trim();
        if (!t || t.startsWith("#") || t.startsWith("!")) continue; // negation unsupported (subset)
        patterns.push(t.replace(/\/+$/, ""));
      }
    } catch {
      /* no .gitignore — fine, offline default */
    }
  }
  return (relPath, name) => {
    if (excludes.has(name)) return true;
    for (const p of patterns) {
      if (p === name || p === relPath) return true;
      if (p.includes("/") && (relPath === p || relPath.startsWith(p + "/"))) return true;
    }
    return false;
  };
}

function walkDir(absDir: string, relDir: string, ignore: (r: string, n: string) => boolean): string {
  const children: { name: string; hash: string }[] = [];
  for (const name of readdirSync(absDir)) {
    const rel = relDir ? `${relDir}/${name}` : name;
    if (ignore(rel, name)) continue;
    const abs = join(absDir, name);
    let st;
    try {
      st = lstatSync(abs);
    } catch {
      continue; // vanished between readdir and lstat — skip, not part of the tree
    }
    let entryHash: string;
    if (st.isSymbolicLink()) {
      entryHash = leafHash("symlink", "120000", sha256Hex(readlinkSync(abs)));
    } else if (st.isDirectory()) {
      entryHash = walkDir(abs, rel, ignore); // a NODE hash (0x01) — recursion carries the tree shape
    } else if (st.isFile()) {
      entryHash = leafHash("file", fileMode(st.mode), sha256Hex(readFileSync(abs)));
    } else {
      continue; // sockets/fifos/devices are not governed content
    }
    children.push({ name: nfc(name), hash: entryHash });
  }
  return nodeHash(children);
}

/**
 * Fingerprint a directory tree. Pure JS, offline, zero-config: returns a self-describing `sha256:<hex>`
 * that is stable across two checkouts of identical content and MOVES on any content, exec-bit, path,
 * kind, or symlink-target change. `root` must be an existing directory.
 */
export function fingerprintTree(root: string, options: FingerprintOptions = {}): string {
  if (!existsSync(root) || !lstatSync(root).isDirectory()) {
    throw new Error(`fingerprintTree: not a directory: ${root}`);
  }
  return FP_SCHEME + walkDir(root, "", buildIgnore(root, options));
}

/**
 * OPTIONAL ACCELERATOR / ORACLE — git's own tree id via `git write-tree`, used by the tests to assert
 * behavioral parity (my walk moves exactly when git's tree id moves). Returns null when `.git` is
 * absent or git is unavailable — NEVER on the offline contract path. Uses a throwaway GIT_INDEX_FILE so
 * it never mutates the caller's staged state.
 */
export function gitWriteTreeId(root: string): string | null {
  if (!existsSync(join(root, ".git"))) return null;
  let idxDir: string | null = null;
  try {
    idxDir = mkdtempSync(join(tmpdir(), "keep-fp-idx-"));
    const env = { ...process.env, GIT_INDEX_FILE: join(idxDir, "index") };
    execFileSync("git", ["add", "-A"], { cwd: root, env, stdio: "ignore" });
    const id = execFileSync("git", ["write-tree"], { cwd: root, env, encoding: "utf8" }).trim();
    return id || null;
  } catch {
    return null;
  } finally {
    if (idxDir) {
      try {
        rmSync(idxDir, { recursive: true, force: true });
      } catch {
        /* best-effort cleanup */
      }
    }
  }
}
