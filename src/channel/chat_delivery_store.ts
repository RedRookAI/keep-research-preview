import { constants, openSync, closeSync, fstatSync, readSync, renameSync, unlinkSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { dirname } from "node:path";
import { durableAppend, ensureDurableDir, fsyncDir, NODE_IO } from "../spine/durable_fs.js";
import { withLogicalAppendLock } from "../spine/logical_append_lock.js";

const SCHEMA = "keep.chat-delivery/v1", REPLAY_SCHEMA = "keep.chat-replay/v2";
const KEY = /^keep-chat-envelope\/v2:[a-f0-9]{64}$/, HASH = /^[a-f0-9]{64}$/;
export type DeliveryState = "intent" | "entered" | "confirmed" | "unknown" | "reconciled";
interface Ack { status: 200; bodySha256: string; }
interface Row { id: string; expiresAt: number; state: DeliveryState; token: string; at: number; ack?: Ack; outcome?: "confirmed" | "no-effect"; evidenceSha256?: string; }
interface Journal { schema: typeof SCHEMA; replaySha256: string; rows: Row[]; }
export class ChatDeliveryCapacityError extends Error { readonly code = "chat-delivery-capacity"; }
export class ChatDeliveryIntegrityError extends Error { readonly code = "chat-delivery-integrity"; }
export const deliveryDigest = (text: string): string => createHash("sha256").update(text).digest("hex");

/** One coherent local filesystem/process domain; no lock is held while forwarding.
 * Intent is proven unentered because claim publishes intent and entered under ONE
 * lock turn, and network entry is possible only after both durable publications.
 * Entered/unknown never retire automatically, even beyond signature expiry.
 * Fsync obeys the local OS/device contract; this is not a remote exactly-once claim.
 */
export class ChatDeliveryStore {
  readonly file: string;
  readonly #replay: string;
  readonly #maxRecords: number;
  readonly #maxBytes: number;
  constructor(replayFile: string, limits: { maxRecords?: number; maxBytes?: number } = {}) {
    this.file = `${replayFile}.delivery-v1.json`; this.#replay = `${replayFile}.authenticated-v2.jsonl`;
    this.#maxRecords = limits.maxRecords ?? 10_000; this.#maxBytes = limits.maxBytes ?? 8 * 1024 * 1024;
    for (const limit of [this.#maxRecords, this.#maxBytes]) if (!Number.isSafeInteger(limit) || limit <= 0) throw new Error("chat delivery limits must be positive finite safe integers");
    ensureDurableDir(NODE_IO, dirname(this.file));
    this.#locked(() => { const data = this.#load(); if (data.fresh) { this.#admission(data.journal); this.#save(data.journal); } });
  }
  #locked<T>(fn: () => T): T { return withLogicalAppendLock(this.file, fn, { waitMs: 5_000 }); }
  #read(file: string): string | undefined {
    let fd: number;
    try { fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw error; }
    try {
      const stat = fstatSync(fd);
      if (!stat.isFile()) throw new ChatDeliveryIntegrityError("chat delivery carrier must be a regular file");
      if (stat.size > this.#maxBytes) throw new ChatDeliveryCapacityError("chat delivery byte limit exceeded; preserve and reconcile state");
      const chunks: Buffer[] = []; let total = 0;
      for (;;) {
        const buffer = Buffer.alloc(Math.min(64 * 1024, this.#maxBytes + 1 - total));
        const count = readSync(fd, buffer, 0, buffer.length, null); if (!count) break;
        total += count; if (total > this.#maxBytes) throw new ChatDeliveryCapacityError("chat delivery byte limit exceeded during read");
        chunks.push(buffer.subarray(0, count));
      }
      return Buffer.concat(chunks).toString("utf8");
    } finally { closeSync(fd); }
  }
  #load(): { journal: Journal; fresh: boolean } {
    let replay = this.#read(this.#replay);
    if (replay === undefined) { replay = JSON.stringify({ schema: REPLAY_SCHEMA }) + "\n"; this.#publish(this.#replay, replay); }
    const replaySha256 = deliveryDigest(replay), raw = this.#read(this.file);
    if (raw !== undefined) {
      let journal: Journal;
      try { journal = JSON.parse(raw) as Journal; } catch { throw new ChatDeliveryIntegrityError("malformed chat delivery journal; preserve and reconcile state"); }
      if (!journal || journal.schema !== SCHEMA || journal.replaySha256 !== replaySha256 || !Array.isArray(journal.rows)) throw new ChatDeliveryIntegrityError("incompatible or changed chat delivery/replay state; preserve and reconcile it");
      if (journal.rows.length > this.#maxRecords) throw new ChatDeliveryCapacityError("chat delivery record limit exceeded; preserve and reconcile state");
      const keys = new Set<string>();
      for (const row of journal.rows) {
        if (!row || typeof row.id !== "string" || !KEY.test(row.id) || keys.has(row.id) || !Number.isFinite(row.expiresAt) || !Number.isFinite(row.at) || typeof row.token !== "string" || !HASH.test(row.token) || !["intent","entered","confirmed","unknown","reconciled"].includes(row.state)) throw new ChatDeliveryIntegrityError("malformed chat delivery record; preserve and reconcile state");
        if (row.state === "confirmed" && (!row.ack || row.ack.status !== 200 || !HASH.test(row.ack.bodySha256))) throw new ChatDeliveryIntegrityError("chat delivery confirmation has no eligible acknowledgment");
        if (row.state === "reconciled" && (!["confirmed","no-effect"].includes(row.outcome ?? "") || !HASH.test(row.evidenceSha256 ?? ""))) throw new ChatDeliveryIntegrityError("chat delivery reconciliation has no evidence digest");
        keys.add(row.id);
      }
      return { journal, fresh: false };
    }
    const lines = replay.split("\n");
    if (JSON.parse(lines.shift()!).schema !== REPLAY_SCHEMA) throw new Error("invalid authenticated chat replay schema");
    const rows: Row[] = [], keys = new Set<string>();
    for (const line of lines) {
      if (!line.trim()) continue; const row = JSON.parse(line) as { id: string; expiresAt: number };
      if (!row || typeof row.id !== "string" || !KEY.test(row.id) || keys.has(row.id) || !Number.isFinite(row.expiresAt)) throw new ChatDeliveryIntegrityError("malformed authenticated chat replay state");
      // T005 admission alone cannot establish whether remote dispatch succeeded.
      rows.push({ id: row.id, expiresAt: row.expiresAt, state: "unknown", token: "0".repeat(64), at: Date.now() }); keys.add(row.id);
    }
    return { journal: { schema: SCHEMA, replaySha256, rows }, fresh: true };
  }
  #bytes(journal: Journal): string {
    const raw = JSON.stringify(journal) + "\n";
    if (journal.rows.length > this.#maxRecords || Buffer.byteLength(raw) > this.#maxBytes) throw new ChatDeliveryCapacityError("chat delivery capacity exhausted; unknown outcomes remain retained");
    return raw;
  }
  #admission(journal: Journal): void {
    // Reserve the largest future terminal metadata for EVERY unresolved row.
    // Otherwise a near-full entered journal could make reconciliation impossible.
    const reserved: Journal = { ...journal, rows: journal.rows.map(row => ["intent", "entered", "unknown"].includes(row.state)
      ? { ...row, state: "reconciled", at: Number.MAX_SAFE_INTEGER, outcome: "confirmed", evidenceSha256: "f".repeat(64) } : row) };
    this.#bytes(reserved);
  }
  #publish(file: string, raw: string): void {
    const temp = `${file}.${process.pid}.${randomBytes(16).toString("hex")}.tmp`;
    try {
      const fd = openSync(temp, "wx", 0o600); closeSync(fd);
      durableAppend(NODE_IO, temp, raw); renameSync(temp, file); fsyncDir(NODE_IO, dirname(file));
    } finally { try { unlinkSync(temp); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; } }
  }
  #save(journal: Journal): void { this.#publish(this.file, this.#bytes(journal)); }
  claimForEntry(id: string, expiresAt: number, now = Date.now()): { admitted: true; token: string } | { admitted: false; state: DeliveryState } {
    if (!KEY.test(id) || !Number.isFinite(expiresAt) || !Number.isFinite(now) || now > expiresAt) throw new Error("invalid chat delivery claim");
    return this.#locked(() => {
      const { journal } = this.#load();
      journal.rows = journal.rows.filter(row => !(["intent","confirmed","reconciled"].includes(row.state) && now > row.expiresAt));
      const previous = journal.rows.find(row => row.id === id);
      if (previous && previous.state !== "intent") return { admitted: false, state: previous.state };
      if (previous) journal.rows.splice(journal.rows.indexOf(previous), 1);
      const row: Row = { id, expiresAt, state: "intent", token: randomBytes(32).toString("hex"), at: now }; journal.rows.push(row);
      this.#admission(journal); this.#bytes(journal); row.state = "entered"; this.#bytes(journal); row.state = "intent";
      this.#save(journal); row.state = "entered"; this.#save(journal);
      return { admitted: true, token: row.token };
    });
  }
  finish(id: string, token: string, ack?: { status: number; bodySha256: string }): void {
    if (ack && (ack.status !== 200 || !HASH.test(ack.bodySha256))) throw new Error("ineligible chat acknowledgment");
    this.#locked(() => {
      const { journal } = this.#load(), row = journal.rows.find(row => row.id === id);
      if (!row || row.token !== token || row.state !== "entered") throw new ChatDeliveryIntegrityError("chat delivery transition does not own entered state");
      row.state = ack ? "confirmed" : "unknown"; row.at = Date.now(); if (ack) row.ack = { status: 200, bodySha256: ack.bodySha256 };
      this.#save(journal);
    });
  }
  /** Operator supplies a digest of independently obtained reconciliation evidence.
   * Reconciliation does not redispatch. Its tombstone persists through freshness.
   */
  reconcile(id: string, outcome: "confirmed" | "no-effect", evidenceSha256: string): void {
    if (!KEY.test(id) || !["confirmed","no-effect"].includes(outcome) || !HASH.test(evidenceSha256)) throw new Error("valid delivery identity, reconciliation outcome and evidence SHA256 required");
    this.#locked(() => {
      const { journal } = this.#load(), row = journal.rows.find(row => row.id === id);
      if (!row || !["entered","unknown"].includes(row.state)) throw new ChatDeliveryIntegrityError("only unresolved chat delivery can be reconciled");
      row.state = "reconciled"; row.outcome = outcome; row.evidenceSha256 = evidenceSha256; row.at = Date.now(); this.#save(journal);
    });
  }
}
