/**
 * ROOT EXPORT OUT OF THE WRITE-SET (Mechanical-Enforcement Increment 12b).
 *
 * WHAT 12a LEFT OPEN. 12a made a consequential effect fail-closed on a DURABLE, fsync-committed pre-effect intent, and
 * the hash-chain (src/spine) is tamper-EVIDENT. But the witness sink defaults into the agent's OWN data directory — the
 * same write-set. The sharpest disproof (from the dual design-attack): "your verifier verifies whatever the producer's
 * disk says; nothing hands a root to anyone else, so every guarantee reduces to 'the producer is internally consistent'."
 *
 * WHAT 12b BUILDS — and the HONESTY BOUNDARY (do not let the name overclaim). The mechanical property this module
 * establishes is OUT-OF-WRITE-SET: the exported root lives OUTSIDE the agent's dataDir (canonicalized against symlinks),
 * so a compromise confined to the dataDir cannot rewrite both the chain and the root. That is NECESSARY but NOT
 * SUFFICIENT for independence: the SAME PROCESS still holds write permission to the export file, so a compromise of the
 * agent process itself can still rewrite it. TRUE INDEPENDENCE begins only when a SEPARATE PRINCIPAL / append-only
 * receiver retains the root (and a WITNESS QUORUM turns split-view DETECTION into PREVENTION) — those are NAMED SEAMS
 * C-4/C-5, never faked here. So: `outOfWriteSet` is the honest label; the standalone verifier says it matched a
 * "caller-supplied external reference", and independence of that reference is the operator's PRECONDITION to establish.
 */

import { readFileSync, existsSync, writeFileSync, realpathSync, lstatSync } from "node:fs";
import { dirname, join, resolve, relative, isAbsolute, basename, sep } from "node:path";
import type { ChainWitness, SealedBlock, WitnessCheck } from "../spine/hashchain.js";
import { verifyAgainstWitness, verifyChain } from "../spine/hashchain.js";
import { NODE_IO, durableAppend, ensureDurableDir, fsyncDir } from "../spine/durable_fs.js";
import type { WitnessSink } from "../spine/witness_sink.js";

export type ExportLocation = { readonly outOfWriteSet: boolean; readonly reason: string };

export class WitnessExportError extends Error {
  constructor(message: string) { super(message); this.name = "WitnessExportError"; }
}

const HEX64 = /^[0-9a-f]{64}$/;
/** A well-formed exported root: a safe non-negative integer seq and two 64-hex digests. */
export function isValidWitness(w: unknown): w is ChainWitness {
  if (w === null || typeof w !== "object") return false;
  const o = w as { seq?: unknown; cumulativeRoot?: unknown; headHash?: unknown };
  return typeof o.seq === "number" && Number.isSafeInteger(o.seq) && o.seq >= 0
    && typeof o.cumulativeRoot === "string" && HEX64.test(o.cumulativeRoot)
    && typeof o.headHash === "string" && HEX64.test(o.headHash);
}

/** Canonicalize a path against symlinks: realpath the DEEPEST EXISTING ANCESTOR, then re-append the not-yet-existing
 *  tail. So `/link/witness` (where /link → /data) resolves to `/data/witness`, defeating a symlink that would otherwise
 *  hide a same-write-set destination behind a lexically-outside path. */
function canonicalPath(p: string): string {
  let cur = resolve(p);
  const tail: string[] = [];
  while (!existsSync(cur)) { const parent = dirname(cur); if (parent === cur) break; tail.unshift(basename(cur)); cur = parent; }
  try { cur = realpathSync(cur); } catch { /* keep the resolved form */ }
  return tail.length > 0 ? join(cur, ...tail) : cur;
}

/**
 * Classify a witness destination relative to the agent's data directory — OUT-OF-WRITE-SET iff the canonicalized
 * witness path is NOT inside (and is not) the canonicalized dataDir. Symlink-resolved (not merely string `resolve`),
 * so a `/outside → /dataDir` alias cannot masquerade as out-of-write-set. This is a NECESSARY condition, not
 * independence (see the module header): the producer process still owns the file — a separate principal / quorum is the
 * independence seam.
 */
export function classifyExportLocation(witnessPath: string, dataDir: string): ExportLocation {
  if (typeof witnessPath !== "string" || witnessPath.length === 0) return { outOfWriteSet: false, reason: "witness path is empty" };
  if (typeof dataDir !== "string" || dataDir.length === 0) return { outOfWriteSet: false, reason: "dataDir is empty" };
  const w = canonicalPath(witnessPath);
  const d = canonicalPath(dataDir);
  if (w === d) return { outOfWriteSet: false, reason: `witness destination equals the dataDir (${d}) — same write-set` };
  const rel = relative(d, w);
  // Only a complete parent component escapes; '..reference' is an ordinary child.
  const inside = rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
  if (inside) return { outOfWriteSet: false, reason: `witness destination (${w}) is INSIDE the dataDir (${d}) — same write-set, detection only` };
  return { outOfWriteSet: true, reason: `witness destination (${w}) is outside the dataDir (${d})` };
}

/** Throw (fail-closed) unless the destination is out-of-write-set. Use when the operator REQUIRES it. */
export function assertOutOfWriteSet(witnessPath: string, dataDir: string): void {
  const v = classifyExportLocation(witnessPath, dataDir);
  if (!v.outOfWriteSet) throw new WitnessExportError(`an out-of-write-set witness was required but ${v.reason}. Point it at a path outside the agent's dataDir (a SEPARATE PRINCIPAL / append-only receiver / quorum is required for true independence — seam C-4/C-5).`);
}

/**
 * A durable (fsync) file-backed WitnessSink whose destination is REQUIRED (by default) to be outside the agent's
 * write-set. Each publish is fsync-flushed (shared durable_fs — short-write loop + durable directory entry) so an
 * exported root survives the crash of the actor it indicts. Content is validated JSONL of ChainWitness records.
 */
export class DurableWitnessExport implements WitnessSink {
  readonly #path: string;
  readonly location: ExportLocation;
  /**
   * @param dir      export directory (SHOULD be outside dataDir)
   * @param dataDir  the agent's data directory (to classify out-of-write-set)
   * @param opts.requireOutOfWriteSet  throw if `dir` is inside dataDir (default true)
   * @param opts.filename  BASENAME only (path separators / ".." rejected — no traversal out of `dir`)
   */
  constructor(dir: string, dataDir: string, opts?: { requireOutOfWriteSet?: boolean; filename?: string }) {
    const require = opts?.requireOutOfWriteSet !== false;
    const filename = opts?.filename ?? "witness-export.jsonl";
    if (filename !== basename(filename) || filename === "" || filename === "." || filename === "..") throw new WitnessExportError(`witness export filename must be a bare basename (no path traversal): got "${filename}"`);
    const absDir = resolve(dir); // fix relative dirs (a relative `dir` must not read as an escape below)
    // Gate BEFORE creation (lexical + existing-ancestor realpath).
    this.location = classifyExportLocation(absDir, dataDir);
    if (require && !this.location.outOfWriteSet) throw new WitnessExportError(`DurableWitnessExport requires an out-of-write-set destination but ${this.location.reason}`);
    // Create the dir durably, then CANONICALIZE it (it now exists → symlinks resolve) and RE-ASSERT + PIN the canonical
    // path: all subsequent creation/publish use the symlink-RESOLVED path, so a later retarget of the ORIGINAL `dir`
    // symlink cannot redirect future witnesses back inside the write-set. SEAM: a component of the CANONICAL path being
    // replaced AFTER construction is a residual TOCTOU. NOTE (self-audit 2026-08-18 correction): the LEAF-swap case is
    // closable with a one-flag O_NOFOLLOW open on the append fd — BUILDABLE here, scheduled as WIRE-BATCH B5, NOT a
    // substrate seam. Only a full directory-COMPONENT-replacement defense (openat2/RESOLVE_BENEATH) is a genuine
    // zero-dep Node limit. (A write-set-confined attacker who re-binds the path is, separately, excluded by the
    // separate-principal independence tier.) Named, not hidden.
    ensureDurableDir(NODE_IO, absDir);
    const canonicalDir = canonicalPath(absDir);
    const reasserted = classifyExportLocation(canonicalDir, dataDir);
    if (require && !reasserted.outOfWriteSet) throw new WitnessExportError(`witness export dir resolves back INTO the write-set (symlink): ${reasserted.reason}`);
    this.location = reasserted;
    this.#path = join(canonicalDir, filename);
    if (dirname(this.#path) !== canonicalDir) throw new WitnessExportError(`witness export path escaped its directory: ${this.#path}`);
    // If a leaf ALREADY exists it must be a REGULAR file — NOT a symlink (durableAppend's "a" open would FOLLOW it,
    // writing INSIDE the write-set while we report outOfWriteSet:true; note a DANGLING symlink's "a" open would even
    // CREATE its target) and not a device/fifo/etc; and the REAL leaf must be out-of-write-set. Validation uses
    // `lstatSync` (which does NOT follow the link, so a dangling symlink is still caught — `existsSync` would return
    // false for it) with ONLY ENOENT meaning "absent". We validate BEFORE create AND again after an EEXIST (a leaf
    // introduced between the two). Residual: a leaf swapped in AFTER the final validation is the named component-
    // replacement TOCTOU seam (needs openat/O_NOFOLLOW substrate = the separate-principal seam); a HARD link into
    // dataDir needs write access to this out-of-write-set dir, i.e. the separate principal the threat model excludes.
    const validateLeaf = (): void => {
      let st;
      try { st = lstatSync(this.#path); } catch (e) { if ((e as { code?: string } | null)?.code === "ENOENT") return; throw e; }
      if (st.isSymbolicLink()) throw new WitnessExportError(`witness export leaf is a symlink (its "a"-open would follow it out of the pinned dir): ${this.#path}`);
      if (!st.isFile()) throw new WitnessExportError(`witness export leaf is not a regular file: ${this.#path}`);
      if (require) { const c = classifyExportLocation(realpathSync(this.#path), dataDir); if (!c.outOfWriteSet) throw new WitnessExportError(`existing witness export leaf resolves INTO the write-set: ${c.reason}`); }
    };
    validateLeaf();
    // EXCLUSIVE create ("wx"): never TRUNCATE an existing export. EEXIST = the file already exists — RE-VALIDATE it
    // (it may have been introduced, e.g. as a symlink, between the check and the create).
    try { writeFileSync(this.#path, "", { flag: "wx" }); }
    catch (e) { if ((e as { code?: string } | null)?.code !== "EEXIST") throw e; validateLeaf(); }
    fsyncDir(NODE_IO, canonicalDir); // fsync the dir entry on BOTH create AND re-open — a first-time cross-process race loser must not publish before the entry is durable
  }

  publish(w: ChainWitness): void {
    if (!isValidWitness(w)) throw new WitnessExportError(`refusing to export a malformed witness (seq/root/headHash): ${JSON.stringify(w)}`);
    durableAppend(NODE_IO, this.#path, JSON.stringify({ seq: w.seq, cumulativeRoot: w.cumulativeRoot, headHash: w.headHash }) + "\n");
  }

  /** Read published roots. Tolerates ONLY a torn UNTERMINATED TRAILING fragment (a crash mid-publish leaves a partial
   *  last line with no newline) so a normal crash never triggers a false tamper. A complete-but-malformed line, or ANY
   *  malformed NON-trailing line, is CORRUPTION and THROWS — surfaced loud (boot reconcile degrades to an auditable
   *  "unreadable" tamper event, compose.ts) rather than silently DROPPED, which would let a rewrite of the highest
   *  witness downgrade consumers to an older root and defeat anti-rollback. */
  history(): readonly ChainWitness[] {
    if (!existsSync(this.#path)) return [];
    const text = readFileSync(this.#path, "utf8");
    const terminated = text.length === 0 || text.endsWith("\n");
    const lines = text.split("\n");
    const out: ChainWitness[] = [];
    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i]!;
      const isLast = i === lines.length - 1;
      // The ONLY legitimately-empty element is the terminator artifact: a terminated file's split yields a trailing "".
      if (isLast && terminated && raw === "") continue;
      // The ONLY forgivable damage is an UNTERMINATED final fragment (a crash mid-publish).
      const tornTrailing = isLast && !terminated;
      const t = raw.trim();
      // A blank/whitespace line that is NOT the terminator artifact and NOT a torn fragment is CORRUPTION — a highest
      // record blanked to whitespace must NOT be silently dropped (which would downgrade consumers to an older root).
      if (t.length === 0) { if (tornTrailing) continue; throw new WitnessExportError(`corrupt witness export at line ${i + 1} (blank record)`); }
      let parsed: unknown;
      try { parsed = JSON.parse(t); } catch { if (tornTrailing) continue; throw new WitnessExportError(`corrupt witness export at line ${i + 1} (unparseable)`); }
      if (!isValidWitness(parsed)) { if (tornTrailing) continue; throw new WitnessExportError(`corrupt witness export at line ${i + 1} (malformed record)`); }
      out.push(parsed);
    }
    return out;
  }

  /** The highest-seq published root, CONFLICT-AWARE: two roots at the same max seq with different digests is an external
   *  fork → THROW (fail-closed; boot reconcile surfaces it). undefined only if nothing valid was published. Not the last
   *  line — a lower-seq line appended after a higher one must not downgrade a consumer. */
  latest(): ChainWitness | undefined {
    const h = this.history();
    if (h.length === 0) return undefined;
    const hwm = highestWitness(h);
    if (hwm.kind === "ok") return hwm.witness;
    throw new WitnessExportError(`witness export unusable: ${hwm.reason}`);
  }
}

/** The highest exported root, with conflict detection: two records at the SAME max seq but DIFFERENT roots is itself
 *  proof of a fork in the external history → tamper. All records must be well-formed. */
export type Hwm =
  | { readonly kind: "ok"; readonly witness: ChainWitness }
  | { readonly kind: "invalid"; readonly reason: string }
  | { readonly kind: "conflict"; readonly reason: string };
export function highestWitness(exported: readonly ChainWitness[]): Hwm {
  // TWO-PASS so the result is ORDER-INDEPENDENT: first the max seq (all records must be well-formed), then a conflict
  // check among ONLY the records AT that max seq. A fork BELOW the high-water-mark does not affect anti-rollback (we
  // verify the local chain against the HWM), so conflict-at-the-HWM is the load-bearing invariant.
  let maxSeq = -1;
  for (const w of exported) { if (!isValidWitness(w)) return { kind: "invalid", reason: `malformed exported root: ${JSON.stringify(w)}` }; if (w.seq > maxSeq) maxSeq = w.seq; }
  if (maxSeq < 0) return { kind: "invalid", reason: "no exported roots" };
  let best: ChainWitness | undefined;
  for (const w of exported) {
    if (w.seq !== maxSeq) continue;
    if (best === undefined) best = w;
    else if (w.cumulativeRoot !== best.cumulativeRoot || w.headHash !== best.headHash)
      return { kind: "conflict", reason: `two exported roots at the max seq ${maxSeq} with different digests — the external history forked` };
  }
  return best === undefined ? { kind: "invalid", reason: "no exported roots" } : { kind: "ok", witness: best };
}

/**
 * Verify a local chain against the HIGHEST exported root (anti-rollback + fork/truncation) held OUTSIDE the write-set.
 * Empty/invalid/conflicting export → not ok (never a false "consistent"); else delegates to the spine's
 * verifyAgainstWitness against the high-water-mark.
 */
export function verifyAgainstExport(localBlocks: readonly SealedBlock[], exported: readonly ChainWitness[]): WitnessCheck {
  if (exported.length === 0) return { ok: false, kind: "internal", reason: "no exported root (unwitnessed) — cannot claim verified against an external reference" };
  const hwm = highestWitness(exported);
  if (hwm.kind !== "ok") return { ok: false, kind: hwm.kind === "conflict" ? "fork" : "internal", reason: hwm.reason };
  return verifyAgainstWitness(localBlocks, hwm.witness);
}

export type VerifyOutcome =
  | { readonly kind: "verified"; readonly seq: number }         // internally valid AND matches the external root
  | { readonly kind: "internally-consistent" }                  // internally valid but NO external root supplied — NOT a verification
  | { readonly kind: "rollback"; readonly reason: string }      // chain does not reach the exported high-water-mark
  | { readonly kind: "tamper"; readonly reason: string };       // internal tamper, fork vs the external root, or a malformed/forked export

/** Re-derive and classify a chain — the SHARED logic the standalone verifier and any in-process consumer both use, so
 *  the third-party check can never drift from the built-in one. Keys off the STRUCTURED WitnessCheck.kind, not prose. */
export function classifyChain(localBlocks: readonly SealedBlock[], exported: readonly ChainWitness[] | undefined): VerifyOutcome {
  const internal = verifyChain(localBlocks);
  if (!internal.ok) return { kind: "tamper", reason: `internal chain invalid: ${internal.reason ?? "unknown"}` };
  if (exported === undefined || exported.length === 0) return { kind: "internally-consistent" };
  const hwm = highestWitness(exported);
  if (hwm.kind !== "ok") return { kind: "tamper", reason: hwm.reason }; // malformed or self-forked export is tamper
  const check = verifyAgainstWitness(localBlocks, hwm.witness);
  if (check.ok) return { kind: "verified", seq: hwm.witness.seq };
  return check.kind === "truncation" ? { kind: "rollback", reason: check.reason ?? "rollback" } : { kind: "tamper", reason: check.reason ?? "fork" };
}
