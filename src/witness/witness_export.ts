/**
 * Export chain roots outside the agent's data directory and verify against the highest retained root.
 * Paths are resolved through symlinks before their location is accepted. An external root can expose
 * changes to a chain when an attacker can modify only the data directory.
 *
 * The producer process still has write access to the export. Independent retention requires a
 * separate principal or an append-only receiver with its own access controls. This module checks
 * agreement with the supplied reference; the operator establishes that reference's independence.
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

/**
 * Resolve the deepest existing ancestor through symlinks, then append the missing path components.
 * This keeps an alias such as /outside -> /data from hiding a destination inside the data directory.
 */
function canonicalPath(p: string): string {
  let cur = resolve(p);
  const tail: string[] = [];
  while (!existsSync(cur)) { const parent = dirname(cur); if (parent === cur) break; tail.unshift(basename(cur)); cur = parent; }
  try { cur = realpathSync(cur); } catch { /* keep the resolved form */ }
  return tail.length > 0 ? join(cur, ...tail) : cur;
}

/**
 * Check whether the canonical witness path is outside the canonical data directory.
 * Filesystem separation alone leaves the producer's write authority unchanged.
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

/** Refuse a destination inside the data directory when external storage is required. */
export function assertOutOfWriteSet(witnessPath: string, dataDir: string): void {
  const v = classifyExportLocation(witnessPath, dataDir);
  if (!v.outOfWriteSet) throw new WitnessExportError(`an out-of-write-set witness was required but ${v.reason}. Use a path outside the agent's dataDir. Independent retention requires a separate principal or append-only receiver.`);
}

/**
 * File-backed witness export with fsync on each published record. By default, the destination
 * must be outside the data directory. Records use validated ChainWitness JSONL.
 */
export class DurableWitnessExport implements WitnessSink {
  readonly #path: string;
  readonly location: ExportLocation;
  /**
   * @param dir      export directory, outside dataDir by default
   * @param dataDir  the agent's data directory (to classify out-of-write-set)
   * @param opts.requireOutOfWriteSet  throw if `dir` is inside dataDir (default true)
   * @param opts.filename  bare filename; path separators and ".." are rejected
   */
  constructor(dir: string, dataDir: string, opts?: { requireOutOfWriteSet?: boolean; filename?: string }) {
    const require = opts?.requireOutOfWriteSet !== false;
    const filename = opts?.filename ?? "witness-export.jsonl";
    if (filename !== basename(filename) || filename === "" || filename === "." || filename === "..") throw new WitnessExportError(`witness export filename must be a bare basename (no path traversal): got "${filename}"`);
    const absDir = resolve(dir); // fix relative dirs (a relative `dir` must not read as an escape below)
    // Check the resolved existing ancestry before creating the directory.
    this.location = classifyExportLocation(absDir, dataDir);
    if (require && !this.location.outOfWriteSet) throw new WitnessExportError(`DurableWitnessExport requires an out-of-write-set destination but ${this.location.reason}`);
    // Resolve and pin the newly created directory. Retargeting the original alias then leaves
    // this path unchanged. Replacing a canonical directory component after validation remains
    // a check/use race; the export directory requires trusted filesystem custody.
    ensureDurableDir(NODE_IO, absDir);
    const canonicalDir = canonicalPath(absDir);
    const reasserted = classifyExportLocation(canonicalDir, dataDir);
    if (require && !reasserted.outOfWriteSet) throw new WitnessExportError(`witness export dir resolves back INTO the write-set (symlink): ${reasserted.reason}`);
    this.location = reasserted;
    this.#path = join(canonicalDir, filename);
    if (dirname(this.#path) !== canonicalDir) throw new WitnessExportError(`witness export path escaped its directory: ${this.#path}`);
    // Require an existing leaf to be a regular file outside the data directory. lstat also
    // catches dangling symlinks. Recheck after a competing create reports EEXIST.
    // Later leaf replacement or a hard link remains possible for a writer with directory
    // access; these checks require that access to remain trusted through publication.
    const validateLeaf = (): void => {
      let st;
      try { st = lstatSync(this.#path); } catch (e) { if ((e as { code?: string } | null)?.code === "ENOENT") return; throw e; }
      if (st.isSymbolicLink()) throw new WitnessExportError(`witness export leaf is a symlink (its "a"-open would follow it out of the pinned dir): ${this.#path}`);
      if (!st.isFile()) throw new WitnessExportError(`witness export leaf is not a regular file: ${this.#path}`);
      if (require) { const c = classifyExportLocation(realpathSync(this.#path), dataDir); if (!c.outOfWriteSet) throw new WitnessExportError(`existing witness export leaf resolves INTO the write-set: ${c.reason}`); }
    };
    validateLeaf();
    // Exclusive creation preserves existing records; validate any concurrently created leaf.
    try { writeFileSync(this.#path, "", { flag: "wx" }); }
    catch (e) { if ((e as { code?: string } | null)?.code !== "EEXIST") throw e; validateLeaf(); }
    fsyncDir(NODE_IO, canonicalDir); // Persist the directory entry even when another process created it.
  }

  publish(w: ChainWitness): void {
    if (!isValidWitness(w)) throw new WitnessExportError(`refusing to export a malformed witness (seq/root/headHash): ${JSON.stringify(w)}`);
    durableAppend(NODE_IO, this.#path, JSON.stringify({ seq: w.seq, cumulativeRoot: w.cumulativeRoot, headHash: w.headHash }) + "\n");
  }

  /**
   * Read published roots, tolerating a torn final record without a newline after a crash.
   * Complete malformed records and malformed interior records throw. Silently discarding them
   * could replace the latest reference with an older root.
   */
  history(): readonly ChainWitness[] {
    if (!existsSync(this.#path)) return [];
    const text = readFileSync(this.#path, "utf8");
    const terminated = text.length === 0 || text.endsWith("\n");
    const lines = text.split("\n");
    const out: ChainWitness[] = [];
    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i]!;
      const isLast = i === lines.length - 1;
      // Splitting a newline-terminated file produces one trailing empty element.
      if (isLast && terminated && raw === "") continue;
      // A crash may leave an incomplete final record without its newline.
      const tornTrailing = isLast && !terminated;
      const t = raw.trim();
      // A blank interior record is corruption; skipping it could hide the highest retained root.
      if (t.length === 0) { if (tornTrailing) continue; throw new WitnessExportError(`corrupt witness export at line ${i + 1} (blank record)`); }
      let parsed: unknown;
      try { parsed = JSON.parse(t); } catch { if (tornTrailing) continue; throw new WitnessExportError(`corrupt witness export at line ${i + 1} (unparseable)`); }
      if (!isValidWitness(parsed)) { if (tornTrailing) continue; throw new WitnessExportError(`corrupt witness export at line ${i + 1} (malformed record)`); }
      out.push(parsed);
    }
    return out;
  }

  /**
   * Return the root with the highest sequence, regardless of append order. Conflicting digests at
   * that sequence throw. Return undefined when the export contains no valid records.
   */
  latest(): ChainWitness | undefined {
    const h = this.history();
    if (h.length === 0) return undefined;
    const hwm = highestWitness(h);
    if (hwm.kind === "ok") return hwm.witness;
    throw new WitnessExportError(`witness export unusable: ${hwm.reason}`);
  }
}

/**
 * Select the highest valid exported root. Conflicting digests at the maximum sequence identify
 * a fork in the retained history.
 */
export type Hwm =
  | { readonly kind: "ok"; readonly witness: ChainWitness }
  | { readonly kind: "invalid"; readonly reason: string }
  | { readonly kind: "conflict"; readonly reason: string };
export function highestWitness(exported: readonly ChainWitness[]): Hwm {
  // Find the maximum sequence first, then compare every root at that sequence. The consumer
  // verifies against this high-water mark, so append order cannot lower its reference.
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
 * Verify a local chain against the highest exported root. Empty, invalid or conflicting exports
 * are rejected. The spine verifier detects divergence or truncation against that retained reference.
 */
export function verifyAgainstExport(localBlocks: readonly SealedBlock[], exported: readonly ChainWitness[]): WitnessCheck {
  if (exported.length === 0) return { ok: false, kind: "internal", reason: "no exported root (unwitnessed) — cannot claim verified against an external reference" };
  const hwm = highestWitness(exported);
  if (hwm.kind !== "ok") return { ok: false, kind: hwm.kind === "conflict" ? "fork" : "internal", reason: hwm.reason };
  return verifyAgainstWitness(localBlocks, hwm.witness);
}

export type VerifyOutcome =
  | { readonly kind: "verified"; readonly seq: number }         // internally valid and matches the external root
  | { readonly kind: "internally-consistent" }                  // internally valid; no external reference supplied
  | { readonly kind: "rollback"; readonly reason: string }      // chain does not reach the exported high-water-mark
  | { readonly kind: "tamper"; readonly reason: string };       // internal tamper, fork vs the external root, or a malformed/forked export

/**
 * Shared chain classification for the standalone verifier and in-process consumers.
 * The result uses the structured WitnessCheck.kind rather than diagnostic text.
 */
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
