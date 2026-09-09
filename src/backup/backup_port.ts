/**
 * Backup: BackupPort + content-addressed snapshot + LocalBackup adapter (Increment 9a).
 *
 * SOTA basis (2026-08-04): the modern standard is 3-2-1-1-0 — 3 copies, 2 media, 1 off-site, +1
 * immutable/air-gapped, +0 verified restores (AvePoint/Barracuda/CISA #StopRansomware 2026). The
 * decisive threat (Eon 2026): an AI coding agent deleted a production DB *and its backups* in nine
 * seconds because "three copies behind one set of permissions is one copy with extra steps." Keep IS
 * an autonomous coding agent, so this is our threat model: the backup target must be immutable-by-
 * default — append-only, keyed by content hash — so the routine that manages the instance cannot
 * silently overwrite or delete it. The spine's append-only hash-chain already provides the +1
 * immutability primitive; a snapshot captures its cumulativeRoot so a restore is provably complete.
 *
 * The `BackupPort` is one interface with local/git/s3 adapters behind it (no lock-in, air-gap
 * default). LocalBackup (copy #1) runs from first-run with NO prompt. Zero deps. */

import type { SealedBlock } from "../spine/hashchain.js";

/** A hasher seam (default wired to node:crypto sha256 by the caller) — keeps this module dep-free. */
export type Hasher = (data: string) => string;

/** A content-addressed snapshot of the durable state (the spine chain). */
export interface Snapshot {
  /** The content address: the chain's cumulative root (folds every event). A restore must match this. */
  readonly contentRoot: string;
  /** The sealed blocks (the durable, append-only state). */
  readonly blocks: readonly SealedBlock[];
  /** Number of blocks + events, for a quick completeness check. */
  readonly blockCount: number;
  readonly eventCount: number;
  /** When the snapshot was taken (epoch ms). */
  readonly takenAt: number;
  /** A stable id derived from the content root (immutable key — same content, same id). */
  readonly id: string;
}

/** Metadata about a stored snapshot (without the full blocks). */
export interface SnapshotRef {
  readonly id: string;
  readonly contentRoot: string;
  readonly takenAt: number;
  readonly blockCount: number;
}

/**
 * The backup port — one interface, many adapters (local disk, private git, S3/rsync). Adapters are
 * APPEND-ONLY: put() never overwrites an existing snapshot id, and there is no delete on the port
 * (immutability by construction — a compromised caller cannot erase history through this interface).
 */
export interface BackupPort {
  readonly name: string;
  /** Whether this target needs a network/account (local = false → air-gap safe). */
  readonly requiresAccount: boolean;
  /** Store a snapshot. Idempotent by content id; MUST NOT overwrite a differing snapshot at that id. */
  put(snapshot: Snapshot): Promise<SnapshotRef>;
  /** List stored snapshots, newest first. */
  list(): Promise<readonly SnapshotRef[]>;
  /** Fetch a stored snapshot by id (for restore/verify). */
  get(id: string): Promise<Snapshot | undefined>;
}

/** Build a content-addressed snapshot from the spine's sealed blocks. */
export function buildSnapshot(blocks: readonly SealedBlock[], hasher: Hasher, now: number): Snapshot {
  const last = blocks.length > 0 ? blocks[blocks.length - 1] : undefined;
  const contentRoot = last ? last.cumulativeRoot : "0".repeat(64);
  const eventCount = blocks.reduce((n, b) => n + b.events.length, 0);
  // The snapshot id is derived from the content root — same content ⇒ same id (immutable key).
  const id = `snap_${hasher(contentRoot).slice(0, 32)}`;
  return { contentRoot, blocks, blockCount: blocks.length, eventCount, takenAt: now, id };
}

/**
 * LocalBackup — copy #1, runs from first-run, no prompt, no account (air-gap safe). Append-only:
 * storing a snapshot whose id already exists is a no-op IF the content matches, and a THROW if a
 * different content is offered at the same id (immutability: never silently overwrite history).
 */
export class LocalBackup implements BackupPort {
  readonly name = "local";
  readonly requiresAccount = false;
  private readonly store = new Map<string, Snapshot>();

  async put(snapshot: Snapshot): Promise<SnapshotRef> {
    const existing = this.store.get(snapshot.id);
    if (existing) {
      // Immutability guard: same id must mean same content (content-addressed).
      if (existing.contentRoot !== snapshot.contentRoot) {
        throw new Error(`backup immutability violation: snapshot ${snapshot.id} already exists with a different content root`);
      }
      return refOf(existing);
    }
    this.store.set(snapshot.id, snapshot);
    return refOf(snapshot);
  }

  async list(): Promise<readonly SnapshotRef[]> {
    return [...this.store.values()].sort((a, b) => b.takenAt - a.takenAt).map(refOf);
  }

  async get(id: string): Promise<Snapshot | undefined> {
    return this.store.get(id);
  }
}

function refOf(s: Snapshot): SnapshotRef {
  return { id: s.id, contentRoot: s.contentRoot, takenAt: s.takenAt, blockCount: s.blockCount };
}
