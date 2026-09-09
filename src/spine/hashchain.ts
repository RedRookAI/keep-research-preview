/**
 * Hash-chain core — tamper-evidence for the spine (Feature 29).
 *
 * Each sealed block links to its predecessor by hash. Any mutation of a historical
 * event or block changes that block's hash, which breaks every subsequent link —
 * so tampering is detectable by re-walking the chain (verifyChain).
 *
 * Block hash = SHA256 over the canonical encoding of:
 *   { seq, prevHash, ts, cumulativeRoot, events: [canonicalEventBytes...] }
 *
 * - Genesis block: seq 0, prevHash = 64 zeros.
 * - cumulativeRoot: a running hash folding every prior event (Round 13 checkpoint
 *   primitive) so a checkpoint can attest the whole history compactly and the
 *   active chain can be bounded.
 */

import { createHash } from "node:crypto";
import type { StagedEvent } from "./event.js";
import { canonicalEventBytes, canonicalize, isWellFormedEvent } from "./event.js";

export const ZERO_HASH = "0".repeat(64);

/** A lowercase 64-char SHA-256 hex digest (or ZERO_HASH). */
const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Local size ceiling for a single block, enforced at write time. A LOCAL bound (it
 * inspects only the one block), never a global/aggregate limit — those belong to a
 * higher gate. Generous: real sealed blocks are orders of magnitude smaller.
 */
export const MAX_BLOCK_BYTES = 1 << 20; // 1 MiB

export interface SealedBlock {
  readonly seq: number;
  readonly prevHash: string;
  readonly ts: number;
  /** Running hash folding all events up to and including this block. */
  readonly cumulativeRoot: string;
  /** The events sealed in this block, in order. */
  readonly events: readonly StagedEvent[];
  /** SHA-256 over the block's canonical content (excluding this field). */
  readonly hash: string;
}

function sha256(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** Fold one event into the running cumulative root. */
export function foldRoot(prevRoot: string, e: StagedEvent): string {
  return sha256(prevRoot + "|" + canonicalEventBytes(e));
}

/** Compute the canonical hash of a block (everything except `hash`). */
export function computeBlockHash(
  seq: number,
  prevHash: string,
  ts: number,
  cumulativeRoot: string,
  events: readonly StagedEvent[],
): string {
  const body = canonicalize({
    seq,
    prevHash,
    ts,
    cumulativeRoot,
    events: events.map(canonicalEventBytes),
  });
  return sha256(body);
}

/**
 * Seal a batch of staged events into the next block, given the current chain head.
 * `prev` is undefined only for the genesis block.
 */
export function sealBlock(
  prev: SealedBlock | undefined,
  events: readonly StagedEvent[],
  now: number,
): SealedBlock {
  const seq = prev ? prev.seq + 1 : 0;
  const prevHash = prev ? prev.hash : ZERO_HASH;
  let cumulativeRoot = prev ? prev.cumulativeRoot : ZERO_HASH;
  for (const e of events) cumulativeRoot = foldRoot(cumulativeRoot, e);
  const hash = computeBlockHash(seq, prevHash, now, cumulativeRoot, events);
  return { seq, prevHash, ts: now, cumulativeRoot, events, hash };
}

export interface VerifyResult {
  readonly ok: boolean;
  /** If not ok, the seq of the first block that failed and why. */
  readonly failedAt?: number;
  readonly reason?: string;
}

/**
 * An external witness of the chain at a point in time (Build Step 1 — the two
 * roots). Published to an independent store/replica so the local chain can be
 * checked against it. Because `cumulativeRoot` folds ALL events up to `seq`, a
 * single witness at `seq` pins the entire prefix [0..seq] — matching it proves
 * the whole history up to that point is byte-identical to what was witnessed.
 *
 * This closes the gap that `verifyChain` alone cannot: a chain that has been
 * TRUNCATED (recent blocks deleted) or ROLLED BACK still verifies internally as
 * a shorter valid chain, and a FORKED chain verifies internally too. Only an
 * independent reference detects those.
 */
export interface ChainWitness {
  readonly seq: number;
  /** cumulativeRoot at `seq` — folds all history [0..seq]. */
  readonly cumulativeRoot: string;
  /** block hash at `seq` (the head when witnessed). */
  readonly headHash: string;
}

export interface WitnessCheck {
  readonly ok: boolean;
  readonly reason?: string;
  /** Structured discriminant so consumers (e.g. the 12b verifier's exit codes) key off shape, not the prose `reason`:
   *  "ok" | "internal" (chain invalid) | "truncation" (chain no longer reaches the witnessed seq) | "fork" (diverges at that seq). */
  readonly kind?: "ok" | "internal" | "truncation" | "fork";
}

/** Produce a witness pinning the current chain head (undefined for an empty chain). */
export function makeWitness(blocks: readonly SealedBlock[]): ChainWitness | undefined {
  if (blocks.length === 0) return undefined;
  const head = blocks[blocks.length - 1]!;
  return { seq: head.seq, cumulativeRoot: head.cumulativeRoot, headHash: head.hash };
}

/**
 * Verify a local chain against an independently-held witness. Detects, in order:
 * internal tampering (via verifyChain), truncation/rollback (the local chain no
 * longer reaches the witnessed seq), and forking/divergence (the block at the
 * witnessed seq differs from what the witness pins). A restoration attestation
 * that legitimately forks history is expected to carry a fresh witness; this
 * check is against whichever witness the caller trusts.
 */
export function verifyAgainstWitness(
  blocks: readonly SealedBlock[],
  witness: ChainWitness,
): WitnessCheck {
  const internal = verifyChain(blocks);
  if (!internal.ok) return { ok: false, kind: "internal", reason: `internal chain invalid: ${internal.reason}` };
  const atSeq = blocks.find((b) => b.seq === witness.seq);
  if (!atSeq) {
    return { ok: false, kind: "truncation", reason: `truncation/rollback: chain does not reach witnessed seq ${witness.seq}` };
  }
  if (atSeq.cumulativeRoot !== witness.cumulativeRoot) {
    return { ok: false, kind: "fork", reason: `fork: cumulativeRoot at seq ${witness.seq} diverges from witness` };
  }
  if (atSeq.hash !== witness.headHash) {
    return { ok: false, kind: "fork", reason: `fork: block hash at seq ${witness.seq} diverges from witness` };
  }
  return { ok: true, kind: "ok" };
}

/** The result of the shared per-block predicate. `ok` iff the block is verifiable. */
export interface BlockCheck {
  readonly ok: boolean;
  readonly reason?: string;
}

/**
 * THE SHARED PREDICATE (VALIDATE-ON-WRITE-SPINE, Build-order 8.3): "writable iff
 * verifiable". `validateBlock` is the SINGLE source of the per-block invariants —
 * called at WRITE time by `FileSpineStore.appendBlock` (so an ill-formed / mis-linked
 * / out-of-sequence block can never enter the chain file) AND at READ time by
 * `verifyChain` below (which merely folds this over the whole chain). Because both
 * ends run the same check, `append succeeds ⇒ verifyChain passes` holds by construction.
 *
 * Every invariant here is LOCAL: it needs only the block and its immediate predecessor
 * (`prior`, undefined for genesis). No chain rescan, no O(n) walk, no uniqueness scan —
 * those are global concerns that belong to a reservation gate or the read-time fold,
 * NEVER a per-append check (the disconfirming case: a write-time global scan re-couples
 * the append-only log it exists to keep decoupled).
 *
 * HONEST SEAM: this closes ILL-FORMED / MIS-LINKED / OUT-OF-SEQUENCE / over-size blocks.
 * It does NOT close a lying-but-well-formed block — a structurally valid, correctly
 * hash-linked block whose payload asserts something false. That remains the province of
 * the higher gates; it is labeled here, never silently claimed as caught.
 *
 * Order: shape/schema/size first (a mis-shaped block can never be verifiable), then the
 * four hash-chain invariants (seq, prevHash link, cumulativeRoot fold, hash recompute).
 */
export function validateBlock(block: SealedBlock, prior: SealedBlock | undefined): BlockCheck {
  // (0) SHAPE / SCHEMA / SIZE — well-formedness of the value itself.
  if (block === null || typeof block !== "object") return { ok: false, reason: "malformed block: not an object" };
  if (typeof block.seq !== "number" || !Number.isInteger(block.seq) || block.seq < 0)
    return { ok: false, reason: "malformed block: seq must be a non-negative integer" };
  if (typeof block.prevHash !== "string" || !HEX64.test(block.prevHash))
    return { ok: false, reason: "malformed block: prevHash must be a 64-char hex digest" };
  if (typeof block.ts !== "number" || !Number.isFinite(block.ts))
    return { ok: false, reason: "malformed block: ts must be a finite number" };
  if (typeof block.cumulativeRoot !== "string" || !HEX64.test(block.cumulativeRoot))
    return { ok: false, reason: "malformed block: cumulativeRoot must be a 64-char hex digest" };
  if (typeof block.hash !== "string" || !HEX64.test(block.hash))
    return { ok: false, reason: "malformed block: hash must be a 64-char hex digest" };
  if (!Array.isArray(block.events) || !block.events.every(isWellFormedEvent))
    return { ok: false, reason: "malformed block: events must be an array of well-formed events" };
  if (canonicalize(block).length > MAX_BLOCK_BYTES)
    return { ok: false, reason: `malformed block: exceeds ${MAX_BLOCK_BYTES}-byte local size bound` };

  // (1) SEQ — monotonic +1 (genesis = 0). LOCAL: only the predecessor's seq.
  const expectedSeq = prior ? prior.seq + 1 : 0;
  if (block.seq !== expectedSeq) return { ok: false, reason: `expected seq ${expectedSeq}, got ${block.seq}` };

  // (2) PREVHASH — links to the predecessor's hash (genesis = ZERO_HASH).
  const expectedPrevHash = prior ? prior.hash : ZERO_HASH;
  if (block.prevHash !== expectedPrevHash) return { ok: false, reason: "prevHash does not link to previous block" };

  // (3) CUMULATIVE ROOT — fold the predecessor's root over this block's events.
  let root = prior ? prior.cumulativeRoot : ZERO_HASH;
  for (const e of block.events) root = foldRoot(root, e);
  if (root !== block.cumulativeRoot) return { ok: false, reason: "cumulativeRoot mismatch (event tampering)" };

  // (4) HASH — recomputes from the block's own content.
  const recomputed = computeBlockHash(block.seq, block.prevHash, block.ts, block.cumulativeRoot, block.events);
  if (recomputed !== block.hash) return { ok: false, reason: "block hash mismatch (block tampering)" };

  return { ok: true };
}

/**
 * Verify the whole chain: recompute every block hash, confirm prev-linkage and
 * the cumulative root fold. Detects any tampering with events or blocks.
 *
 * COMPOSED over `validateBlock` — the read-time scan is exactly the write-time
 * predicate folded across the chain, so the two can never drift.
 */
export function verifyChain(blocks: readonly SealedBlock[]): VerifyResult {
  for (let i = 0; i < blocks.length; i++) {
    const b = blocks[i]!;
    const prior = i > 0 ? blocks[i - 1]! : undefined;
    const check = validateBlock(b, prior);
    // validateBlock always supplies a reason on failure; the fallback satisfies
    // exactOptionalPropertyTypes without changing behaviour.
    if (!check.ok) return { ok: false, failedAt: b.seq, reason: check.reason ?? "block failed local validation" };
  }
  return { ok: true };
}
