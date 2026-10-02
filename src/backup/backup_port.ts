/**
 * Content-addressed event snapshots and the backup target interface.
 * Snapshot ownership prevents adapter/caller references from modifying source or
 * stored history. Chain verification checks integrity against an expected root;
 * it does not establish source truth, immutable storage or independent custody.
 * LocalBackup is memory-only. Durable/off-machine adapters require their own
 * implementation and qualification. No network or external service is used here.
 */

import { verifyChain, type SealedBlock } from "../spine/hashchain.js";
import { normalizePlainData } from "../spine/witness_reconcile.js";

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
  // The source retains its own live chain; adapters must never receive that reference.
  blocks = normalizePlainData(blocks);
  const last = blocks.length > 0 ? blocks[blocks.length - 1] : undefined;
  const contentRoot = last ? last.cumulativeRoot : "0".repeat(64);
  const eventCount = blocks.reduce((n, b) => n + b.events.length, 0);
  // The snapshot id is derived from the content root — same content ⇒ same id (immutable key).
  const id = `snap_${hasher(contentRoot).slice(0, 32)}`;
  return { contentRoot, blocks, blockCount: blocks.length, eventCount, takenAt: now, id };
}

/**
 * LocalBackup — an in-memory adapter, not durable or off-machine storage. Append-only:
 * storing a snapshot whose id already exists is a no-op IF the content matches, and a THROW if a
 * different content is offered at the same id (immutability: never silently overwrite history).
 */
export class LocalBackup implements BackupPort {
  readonly name = "local";
  readonly requiresAccount = false;
  private readonly store = new Map<string, Snapshot>();

  async put(snapshot: Snapshot): Promise<SnapshotRef> {
    snapshot = normalizePlainData(snapshot);
    const existing = this.store.get(snapshot.id);
    if (existing) {
      // Immutability guard: same id must mean same content (content-addressed).
      if (existing.contentRoot !== snapshot.contentRoot) {
        throw new Error(`backup immutability violation: snapshot ${snapshot.id} already exists with a different content root`);
      }
      validateSnapshot(snapshot);
      return refOf(existing);
    }
    validateSnapshot(snapshot);
    this.store.set(snapshot.id, snapshot);
    return refOf(snapshot);
  }

  async list(): Promise<readonly SnapshotRef[]> {
    return [...this.store.values()].sort((a, b) => b.takenAt - a.takenAt).map(refOf);
  }

  async get(id: string): Promise<Snapshot | undefined> {
    const stored = this.store.get(id);
    return stored === undefined ? undefined : normalizePlainData(stored);
  }
}

/** Validate owned snapshot data before retaining it. No claim of publisher authenticity. */
function validateSnapshot(snapshot: Snapshot): void {
  const chain = verifyChain(snapshot.blocks);
  const root = snapshot.blocks.at(-1)?.cumulativeRoot ?? "0".repeat(64);
  if (!chain.ok || snapshot.contentRoot !== root || snapshot.blockCount !== snapshot.blocks.length ||
      snapshot.eventCount !== snapshot.blocks.reduce((n, b) => n + b.events.length, 0)) {
    throw new Error("backup snapshot has invalid chain, content root or counts");
  }
}

function refOf(s: Snapshot): SnapshotRef {
  return { id: s.id, contentRoot: s.contentRoot, takenAt: s.takenAt, blockCount: s.blockCount };
}
