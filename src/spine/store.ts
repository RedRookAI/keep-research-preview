/**
 * Storage port for the spine + a zero-dependency filesystem implementation.
 *
 * The port is the swappability seam (DEPENDENCY_AGNOSTICISM): a Postgres impl
 * (staging via `FOR UPDATE SKIP LOCKED`, sealer singleton via transaction-level
 * `pg_advisory_xact_lock`) and a SQLite impl drop in behind this interface
 * without changing spine logic. The filesystem impl below is the zero-dependency
 * tier and honors the plan's "append-to-file substrate" starting point.
 *
 * Two physical stores, matching the two-stage spine (Round 8):
 *  - staging: append-only, concurrent-safe, holds not-yet-sealed events.
 *  - chain:   append-only, sealed hash-chain blocks (leader/sealer writes only).
 */

import { appendFileSync, closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import type { StagedEvent } from "./event.js";
import { validateBlock, type SealedBlock } from "./hashchain.js";
import { NODE_IO, durableAppend, ensureDurableDir as durableMkdir, fsyncDir, type DurableIO } from "./durable_fs.js";

export type { DurableIO } from "./durable_fs.js"; // re-export for back-compat (importers used store.js)

export interface SpineStore {
  /** Append a staged event (concurrent-safe). */
  appendStaged(e: StagedEvent): void;
  /** Read all currently-staged events in append order. */
  readStaged(): StagedEvent[];
  /** Remove the first `count` staged events (called after they are sealed). */
  removeStaged(count: number): void;

  /** Append a sealed block to the chain (sealer only). */
  appendBlock(b: SealedBlock): void;
  /** Read all sealed blocks in order. */
  readBlocks(): SealedBlock[];
  /** The last sealed block, or undefined if the chain is empty (pre-genesis). */
  lastBlock(): SealedBlock | undefined;
  /** Whether appends are fsync-DURABLE (crash-surviving). Optional so an injected store self-reports its real
   *  durability — compose MEASURES this rather than declaring it from config (self-audit: measure, don't declare). */
  readonly durable?: boolean;
  /** Confirm durability of currently visible event carriers after an ambiguous append. */
  confirmEventDurability?(): void;
}

/**
 * Filesystem store: newline-delimited JSON (JSONL) append-only files.
 * - Appends are atomic per line on POSIX for the sizes we write.
 * - No external dependencies; runs anywhere Node runs.
 */
export class FileSpineStore implements SpineStore {
  private readonly stagingPath: string;
  private readonly stagingCursorPath: string;
  private readonly chainPath: string;
  private readonly fsyncOnAppend: boolean;
  private readonly io: DurableIO;
  /** MEASURED durability: appends are fsync-durable iff constructed with `{fsync:true}`. */
  get durable(): boolean { return this.fsyncOnAppend; }

  confirmEventDurability(): void {
    if (!this.fsyncOnAppend) throw new Error("spine store does not provide durable event confirmation");
    for (const path of [this.stagingPath, this.chainPath, this.stagingCursorPath]) {
      const fd = this.io.openSync(path, "r");
      try { this.io.fsyncSync(fd); } finally { this.io.closeSync(fd); }
    }
    fsyncDir(this.io, dirname(this.stagingPath));
  }

  /**
   * `opts.fsync` (default false): flush each append to stable storage with `fsyncSync` before returning — the WAL
   * log-then-act durability the PRE-EFFECT WITNESS INTERLOCK (Increment 12a) depends on, so a `sealIntent` ack proves
   * the intent SURVIVES a process/OS crash, not merely that the write buffer accepted it. New directories/files have
   * their directory entries fsync'd too (see durable_fs.ts). Default false keeps every existing non-witness caller
   * byte-for-byte unchanged. `opts.io` injects the fs primitives (tests only) to verify the fsync + short-write loop.
   */
  constructor(dataDir: string, opts?: { fsync?: boolean; io?: DurableIO }) {
    this.stagingPath = join(dataDir, "staging.jsonl");
    this.stagingCursorPath = join(dataDir, "staging.cursor");
    this.chainPath = join(dataDir, "chain.jsonl");
    this.fsyncOnAppend = opts?.fsync === true;
    this.io = opts?.io ?? NODE_IO;
    for (const p of [this.stagingPath, this.chainPath, this.stagingCursorPath]) {
      const dir = dirname(p);
      if (this.fsyncOnAppend) durableMkdir(this.io, dir); // creates missing dirs AND fsyncs each new dir's parent
      else if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      if (!existsSync(p)) {
        writeFileSync(p, p === this.stagingCursorPath ? "0\n" : "");
        if (this.fsyncOnAppend) {
          const fd = openSync(p, "r+"); try { fsyncSync(fd); } finally { closeSync(fd); }
          fsyncDir(this.io, dir);
        }
      }
    }
  }

  /** Append a line — fsync-durable (shared durable_fs) when opts.fsync, else a plain appendFileSync. */
  private append(path: string, line: string): void {
    if (this.fsyncOnAppend) durableAppend(this.io, path, line);
    else appendFileSync(path, line);
  }

  appendStaged(e: StagedEvent): void {
    this.append(this.stagingPath, JSON.stringify(e) + "\n");
  }

  readStaged(): StagedEvent[] {
    const all = readJsonl<StagedEvent>(this.stagingPath, this.fsyncOnAppend);
    const consumed = this.readStagingCursor(all.length);
    return all.slice(consumed);
  }

  removeStaged(count: number): void {
    if (!Number.isSafeInteger(count) || count < 0) throw new Error("staging removal count must be a non-negative safe integer");
    const total = readJsonl<StagedEvent>(this.stagingPath, this.fsyncOnAppend).length;
    const consumed = this.readStagingCursor(total);
    if (count > total - consumed) throw new Error("staging removal exceeds the unconsumed durable prefix");
    this.publishStagingCursor(consumed + count);
  }

  /**
   * Staging is append-only. Sealing advances this durable consumed-prefix cursor instead of rewriting the live
   * staging file, so an appender racing the sealer cannot be deleted and a power cut cannot expose a half-rewrite.
   * Cursor publication is atomic; after a crash readers see either the old prefix (safe duplicate reseal is refused
   * by the chain identity) or the new prefix, never an invented intermediate count.
   */
  private readStagingCursor(total: number): number {
    const raw = readFileSync(this.stagingCursorPath, "utf8");
    if (!/^(?:0|[1-9][0-9]*)\n$/.test(raw)) throw new Error("staging cursor carrier is malformed");
    const value = Number(raw.slice(0, -1));
    if (!Number.isSafeInteger(value) || value < 0 || value > total) throw new Error("staging cursor is outside the durable staging log");
    return value;
  }

  private publishStagingCursor(value: number): void {
    const dir = dirname(this.stagingCursorPath);
    const temp = `${this.stagingCursorPath}.tmp-${process.pid}-${randomBytes(8).toString("hex")}`;
    try {
      writeFileSync(temp, `${value}\n`, { flag: "wx", mode: 0o600 });
      if (this.fsyncOnAppend) {
        const fd = openSync(temp, "r+");
        try { fsyncSync(fd); } finally { closeSync(fd); }
      }
      renameSync(temp, this.stagingCursorPath);
      if (this.fsyncOnAppend) fsyncDir(this.io, dir);
    } finally {
      try { unlinkSync(temp); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    }
  }

  appendBlock(b: SealedBlock): void {
    // VALIDATE-ON-WRITE (writable iff verifiable). Run the SAME shared predicate that
    // verifyChain re-checks at read time, over this block + its immediate predecessor,
    // and REFUSE (throw, fail-closed) an ill-formed / mis-linked / out-of-sequence /
    // non-recomputing block — so the chain file cannot come to contain a block that a
    // later verifyChain would reject. `append succeeds ⇒ verifyChain passes` by construction.
    //
    // LOCAL and O(1) in the predicate: it compares only against `lastBlock()`, the single
    // predecessor. (Reading the tail is the file tier's pre-existing cost, not a chain
    // re-verification; a DB-backed store would fetch the head row directly.) Global /
    // uniqueness concerns are deliberately NOT here — they belong to a reservation gate.
    //
    // This dogfoods the loop's own ledger.mjs discipline (append runs validateEntry, the
    // same predicate verify uses) into Keep the product.
    const check = validateBlock(b, this.lastBlock());
    if (!check.ok) {
      throw new Error(`FileSpineStore.appendBlock refused an unverifiable block (seq ${b?.seq}): ${check.reason}`);
    }
    this.append(this.chainPath, JSON.stringify(b) + "\n");
  }

  readBlocks(): SealedBlock[] {
    return readJsonl<SealedBlock>(this.chainPath, this.fsyncOnAppend);
  }

  lastBlock(): SealedBlock | undefined {
    const blocks = this.readBlocks();
    return blocks.length > 0 ? blocks[blocks.length - 1] : undefined;
  }
}

function readJsonl<T>(path: string, durable: boolean): T[] {
  if (!existsSync(path)) return [];
  const raw = readFileSync(path, "utf8");
  const out: T[] = [];
  const lines = raw.split("\n");
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]!;
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;
    try { out.push(JSON.parse(trimmed) as T); }
    catch (error) {
      // A crash can leave only the final append partially written. It cannot be a valid linked block/event and is
      // safely discarded; malformed bytes anywhere else are tampering/corruption and remain a hard refusal.
      const isUnterminatedTail = index === lines.length - 1 && !raw.endsWith("\n");
      if (!isUnterminatedTail) throw error;
      const lastNewline = raw.lastIndexOf("\n");
      // Readers never mutate an append log. A concurrent durableAppend may be between short writes;
      // ignoring its unterminated tail is safe, while truncating it would destroy another process's write.
      // Crash-tail repair belongs to an exclusive recovery operation, not an ordinary projection read.
      break;
    }
  }
  return out;
}
