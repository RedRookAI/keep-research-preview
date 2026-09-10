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

import { appendFileSync, closeSync, constants, existsSync, ftruncateSync, linkSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { isUtf8 } from "node:buffer";
import { dirname, join } from "node:path";
import { canonicalize, isWellFormedEvent, type StagedEvent } from "./event.js";
import { blockByteLength, MAX_BLOCK_BYTES, validateBlock, type SealedBlock } from "./hashchain.js";
import { NODE_IO, durableAppend, ensureDurableDir as durableMkdir, fsyncDir, type DurableIO } from "./durable_fs.js";
import { withLogicalAppendLock } from "./logical_append_lock.js";

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
  /** Resolve abandoned append framing before the sealer derives its snapshot/head. */
  prepareForSeal?(): void;
}

export class SpineLogRecoveryError extends Error {
  readonly code = "KEEP_SPINE_LOG_RECOVERY_REQUIRED";
}

/**
 * Filesystem store: newline-delimited JSON (JSONL) append-only files.
 * Logical appends are serialized, including short-write completion and abandoned
 * tail recovery. Requires a coherent local filesystem/common process domain; no
 * network-filesystem or hostile-directory-writer exclusion claim.
 * The caller's sealer lock still owns cursor transaction ordering. These append
 * locks do not make concurrent independent removeStaged calls a transaction.
 * Keep .append-lock and .torn-* sidecars with runtime backups. A recovery-required
 * error retains the affected bytes: stop writers and reconcile a copy against a
 * known history/witness before deliberately repairing them; do not delete locks.
 */
export class FileSpineStore implements SpineStore {
  private readonly stagingPath: string;
  private readonly stagingCursorPath: string;
  private readonly chainPath: string;
  private readonly fsyncOnAppend: boolean;
  private readonly io: DurableIO;
  private readonly appendWaitMs: number;
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
   * their directory entries fsync'd too (see durable_fs.ts). Default false keeps file-data and lock-metadata flushes
   * disabled; it does not promise crash durability. `opts.io` injects data writes/flushes, not every filesystem
   * operation. Lock publication uses its own filesystem primitives.
   */
  constructor(dataDir: string, opts?: { fsync?: boolean; io?: DurableIO; appendWaitMs?: number }) {
    this.stagingPath = join(dataDir, "staging.jsonl");
    this.stagingCursorPath = join(dataDir, "staging.cursor");
    this.chainPath = join(dataDir, "chain.jsonl");
    this.fsyncOnAppend = opts?.fsync === true;
    this.io = opts?.io ?? NODE_IO;
    this.appendWaitMs = opts?.appendWaitMs ?? 30_000;
    for (const p of [this.stagingPath, this.chainPath, this.stagingCursorPath]) {
      const dir = dirname(p);
      if (this.fsyncOnAppend) durableMkdir(this.io, dir); // creates missing dirs AND fsyncs each new dir's parent
      else if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      if (!existsSync(p)) {
        // Publish the complete cursor, not an empty carrier another initializer
        // might observe between open and write. The hard link never replaces data.
        const temp = `${p}.init-${process.pid}-${randomBytes(12).toString("hex")}`;
        try {
          this.writePrivateFile(temp, Buffer.from(p === this.stagingCursorPath ? "0\n" : ""));
          try { linkSync(temp, p); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
          if (this.fsyncOnAppend) fsyncDir(this.io, dir);
        } finally { try { unlinkSync(temp); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; } }
      }
    }
  }

  /** Append a line — fsync-durable (shared durable_fs) when opts.fsync, else a plain appendFileSync. */
  private append(path: string, line: string): void {
    if (this.fsyncOnAppend) durableAppend(this.io, path, line);
    else appendFileSync(path, line);
  }

  appendStaged(e: StagedEvent): void {
    if (!isWellFormedEvent(e)) throw new Error("staged event envelope is malformed");
    this.exclusive(this.stagingPath, () => {
      const all = this.prepare(this.stagingPath) as StagedEvent[];
      const prior = all.find(row => row.id === e.id);
      if (prior !== undefined) {
        if (canonicalize(prior) !== canonicalize(e)) throw new SpineLogRecoveryError("staged identity already has different content");
        this.syncFile(this.stagingPath); return;
      }
      this.append(this.stagingPath, JSON.stringify(e) + "\n");
    });
  }

  prepareForSeal(): void {
    // Do not nest file locks; the sealer separately owns cursor transaction order.
    this.exclusive(this.stagingPath, () => { this.prepare(this.stagingPath); });
    this.exclusive(this.chainPath, () => { this.prepare(this.chainPath); });
  }

  private exclusive<T>(path: string, fn: () => T): T {
    return withLogicalAppendLock(path, fn, { waitMs: this.appendWaitMs, durable: this.fsyncOnAppend });
  }

  private syncFile(path: string): void {
    if (!this.fsyncOnAppend) return;
    const fd = this.io.openSync(path, "r");
    try { this.io.fsyncSync(fd); } finally { this.io.closeSync(fd); }
  }

  /** Complete a private unpublished carrier. The caller owns publication/cleanup. */
  private writePrivateFile(path: string, bytes: Buffer): void {
    writeFileSync(path, "", { flag: "wx", mode: 0o600 });
    const fd = this.io.openSync(path, "r+");
    try {
      let off = 0;
      while (off < bytes.length) {
        const n = this.io.writeSync(fd, bytes, off, bytes.length - off);
        if (!Number.isInteger(n) || n <= 0 || n > bytes.length - off) throw new Error("private carrier made invalid write progress");
        off += n;
      }
      if (this.fsyncOnAppend) this.io.fsyncSync(fd);
    } finally { this.io.closeSync(fd); }
  }

  /** Called only under this carrier's exclusive append lock. Readers never repair. */
  private prepare(path: string): (StagedEvent | SealedBlock)[] {
    const raw = readFileSync(path), end = raw.lastIndexOf(10) + 1;
    const complete = raw.subarray(0, end), tail = raw.subarray(end);
    const all: (StagedEvent | SealedBlock)[] = [];
    const accept = (value: unknown): void => {
      if (path === this.stagingPath) {
        if (!isWellFormedEvent(value)) throw new SpineLogRecoveryError("invalid staged record; preserve log for explicit recovery");
      } else {
        const check = validateBlock(value as SealedBlock, all.at(-1) as SealedBlock | undefined);
        if (!check.ok) throw new SpineLogRecoveryError(`invalid chain record: ${check.reason}; preserve log for explicit recovery`);
      }
      all.push(value as StagedEvent | SealedBlock);
    };
    if (!isUtf8(complete)) throw new SpineLogRecoveryError("complete log contains invalid UTF-8; explicit recovery required");
    for (const line of complete.toString("utf8").split("\n")) {
      if (line.trim() === "") continue;
      let value: unknown;
      try { value = JSON.parse(line); }
      catch { throw new SpineLogRecoveryError("malformed complete log line; preserve log for explicit recovery"); }
      accept(value);
    }
    if (tail.length === 0) {
      if (path === this.stagingPath) this.readStagingCursor(all.length);
      return all;
    }
    let value: unknown, parsed = false;
    if (isUtf8(tail)) { try { value = JSON.parse(tail.toString("utf8")); parsed = true; } catch { /* incomplete write */ } }
    if (parsed) {
      // Only complete, well-formed OBJECT records qualify; e.g. truncated 1234 ->
      // 12 is not a record. A chain tail must link to the validated complete prefix.
      accept(value);
      if (path === this.stagingPath) this.readStagingCursor(all.length);
      this.append(path, "\n");
    } else {
      if (path === this.stagingPath) this.readStagingCursor(all.length);
      this.preserveTail(path, end, tail);
      const fd = openSync(path, constants.O_RDWR | constants.O_NOFOLLOW);
      try { ftruncateSync(fd, end); if (this.fsyncOnAppend) this.io.fsyncSync(fd); }
      finally { closeSync(fd); }
    }
    return all;
  }

  private preserveTail(path: string, offset: number, bytes: Buffer): void {
    const digest = createHash("sha256").update(bytes).digest("hex");
    const saved = `${path}.torn-${offset}-${digest}`;
    if (!existsSync(saved)) {
      const temp = `${path}.recovery-${process.pid}-${randomBytes(12).toString("hex")}`;
      try {
        // A failed temp write leaves the original untouched. Only a complete
        // carrier is linked at the deterministic name, so retries can recover.
        this.writePrivateFile(temp, bytes);
        try { linkSync(temp, saved); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
      } finally { try { unlinkSync(temp); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; } }
    }
    if (!readFileSync(saved).equals(bytes)) throw new SpineLogRecoveryError("preserved tail content differs; explicit recovery required");
    this.syncFile(saved);
    if (this.fsyncOnAppend) fsyncDir(this.io, dirname(path));
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
      this.writePrivateFile(temp, Buffer.from(`${value}\n`));
      renameSync(temp, this.stagingCursorPath);
      if (this.fsyncOnAppend) fsyncDir(this.io, dir);
    } finally {
      try { unlinkSync(temp); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    }
  }

  appendBlock(b: SealedBlock): void {
    this.exclusive(this.chainPath, () => {
      const all = this.prepare(this.chainPath) as SealedBlock[], prior = all.at(-1);
      if (prior !== undefined && canonicalize(prior) === canonicalize(b)) { this.syncFile(this.chainPath); return; }
      const check = validateBlock(b, prior);
      if (!check.ok) throw new Error(`FileSpineStore.appendBlock refused an unverifiable block (seq ${b?.seq}): ${check.reason}`);
      if (blockByteLength(b) > MAX_BLOCK_BYTES) throw new Error(`new spine block exceeds ${MAX_BLOCK_BYTES}-byte size bound`);
      this.append(this.chainPath, JSON.stringify(b) + "\n");
    });
  }

  readBlocks(): SealedBlock[] {
    return readJsonl<SealedBlock>(this.chainPath, this.fsyncOnAppend);
  }

  lastBlock(): SealedBlock | undefined {
    const blocks = this.readBlocks();
    return blocks.length > 0 ? blocks[blocks.length - 1] : undefined;
  }
}

function readJsonl<T>(path: string, _durable: boolean): T[] {
  if (!existsSync(path)) return [];
  const raw = readFileSync(path, "utf8");
  const out: T[] = [];
  const lines = raw.split("\n");
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]!;
    if (index === lines.length - 1 && !raw.endsWith("\n")) break;
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;
    try { out.push(JSON.parse(trimmed) as T); }
    catch { throw new SpineLogRecoveryError("malformed complete log line; preserve log for explicit recovery"); }
  }
  return out;
}
