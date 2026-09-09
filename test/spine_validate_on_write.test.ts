import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import {
  sealBlock,
  verifyChain,
  validateBlock,
  computeBlockHash,
  foldRoot,
  ZERO_HASH,
  MAX_BLOCK_BYTES,
  type SealedBlock,
} from "../src/spine/hashchain.js";
import type { StagedEvent } from "../src/spine/event.js";

// VALIDATE-ON-WRITE-SPINE (Build-order 8.3). The chain store is "writable iff verifiable":
// FileSpineStore.appendBlock runs the SAME shared predicate (validateBlock) that verifyChain
// re-checks at read time, so an ill-formed / mis-linked / out-of-sequence / non-recomputing
// block CANNOT enter the chain file — `append succeeds ⇒ verifyChain passes` by construction.
// Proven by disproof: each of the four hash-chain checks is isolated by a neuter that reddens
// only its guard test (+ the cross-cutting property test), never a sibling.

function newStore(): FileSpineStore {
  return new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-vows-")));
}
function ev(id: string, payload: Record<string, unknown> = {}): StagedEvent {
  return { id, schemaVersion: 1, type: "generic", ts: 1000, actor: "test", payload };
}
function foldEvents(startRoot: string, events: readonly StagedEvent[]): string {
  let r = startRoot;
  for (const e of events) r = foldRoot(r, e);
  return r;
}
/** Build a block from explicit fields, recomputing `hash` over them (unless overridden) so
 *  the ONLY invariant a crafted block violates is the one under test — that is the isolation. */
function mint(fields: {
  seq: number;
  prevHash: string;
  ts: number;
  cumulativeRoot: string;
  events: readonly StagedEvent[];
  hash?: string;
}): SealedBlock {
  const { seq, prevHash, ts, cumulativeRoot, events } = fields;
  const hash = fields.hash ?? computeBlockHash(seq, prevHash, ts, cumulativeRoot, events);
  return { seq, prevHash, ts, cumulativeRoot, events, hash };
}

// ── FRONT OF HOUSE: the happy path is byte-unchanged and frictionless ──────────────────
test("FRONT: a well-formed sealed block appends with no behaviour change", () => {
  const store = newStore();
  const g = sealBlock(undefined, [ev("a")], 1000);
  const b1 = sealBlock(g, [ev("b"), ev("c")], 1001);
  const b2 = sealBlock(b1, [ev("d")], 1002);
  assert.doesNotThrow(() => store.appendBlock(g));
  assert.doesNotThrow(() => store.appendBlock(b1));
  assert.doesNotThrow(() => store.appendBlock(b2));
  const onDisk = store.readBlocks();
  assert.equal(onDisk.length, 3);
  assert.equal(verifyChain(onDisk).ok, true);
});

// ── NEUTER (a): prevHash-link check ────────────────────────────────────────────────────
test("appendBlock REJECTS a block whose prevHash does not link to the chain head", () => {
  const store = newStore();
  const g = sealBlock(undefined, [ev("a")], 1000);
  store.appendBlock(g);
  // Correct seq, correct fold, hash recomputed over the WRONG prevHash → only the link fails.
  const events = [ev("b")];
  const badLink = mint({
    seq: 1,
    prevHash: "a".repeat(64),
    ts: 1001,
    cumulativeRoot: foldEvents(g.cumulativeRoot, events),
    events,
  });
  assert.equal(validateBlock(badLink, g).ok, false);
  assert.throws(() => store.appendBlock(badLink), /prevHash does not link/);
  assert.equal(store.readBlocks().length, 1); // never persisted
});

// ── NEUTER (b): monotonic-seq check ────────────────────────────────────────────────────
test("appendBlock REJECTS a block with a skipped / non-monotonic seq", () => {
  const store = newStore();
  const g = sealBlock(undefined, [ev("a")], 1000);
  store.appendBlock(g);
  // Correct link, correct fold, hash recomputed over the WRONG seq → only seq fails.
  const events = [ev("b")];
  const skipped = mint({
    seq: 2, // should be 1
    prevHash: g.hash,
    ts: 1001,
    cumulativeRoot: foldEvents(g.cumulativeRoot, events),
    events,
  });
  assert.equal(validateBlock(skipped, g).ok, false);
  assert.throws(() => store.appendBlock(skipped), /expected seq 1, got 2/);
  assert.equal(store.readBlocks().length, 1);
});

// ── NEUTER (c): hash-recompute check ───────────────────────────────────────────────────
test("appendBlock REJECTS a block whose hash does not recompute", () => {
  const store = newStore();
  const g = sealBlock(undefined, [ev("a")], 1000);
  store.appendBlock(g);
  // A well-formed sealed block with its hash overwritten → only the recompute fails.
  const good = sealBlock(g, [ev("b")], 1001);
  const badHash: SealedBlock = { ...good, hash: "c".repeat(64) };
  assert.equal(validateBlock(badHash, g).ok, false);
  assert.throws(() => store.appendBlock(badHash), /block hash mismatch/);
  assert.equal(store.readBlocks().length, 1);
});

// ── NEUTER (d): cumulativeRoot-fold check ──────────────────────────────────────────────
test("appendBlock REJECTS a block whose cumulativeRoot does not fold from its events", () => {
  const store = newStore();
  const g = sealBlock(undefined, [ev("a")], 1000);
  store.appendBlock(g);
  // Correct seq + link, hash recomputed over the WRONG root → only the fold fails.
  const events = [ev("b")];
  const badRoot = mint({
    seq: 1,
    prevHash: g.hash,
    ts: 1001,
    cumulativeRoot: "b".repeat(64), // not the fold
    events,
  });
  assert.equal(validateBlock(badRoot, g).ok, false);
  assert.throws(() => store.appendBlock(badRoot), /cumulativeRoot mismatch/);
  assert.equal(store.readBlocks().length, 1);
});

// ── SCHEMA / SIZE fail-closed (no dedicated neuter; the shape gate) ─────────────────────
test("appendBlock REJECTS a structurally malformed block (schema)", () => {
  const store = newStore();
  const g = sealBlock(undefined, [ev("a")], 1000);
  store.appendBlock(g);
  // events carry a non-well-formed member (missing fields).
  const good = sealBlock(g, [ev("b")], 1001);
  const malformedEvents = { ...good, events: [{ id: "x" } as unknown as StagedEvent] };
  assert.throws(() => store.appendBlock(malformedEvents), /malformed block: events/);
  // prevHash not a 64-hex digest.
  const badShape = { ...good, prevHash: "nope" } as SealedBlock;
  assert.throws(() => store.appendBlock(badShape), /malformed block: prevHash/);
  assert.equal(store.readBlocks().length, 1);
});

test("appendBlock REJECTS an over-size block (local size bound)", () => {
  const store = newStore();
  const g = sealBlock(undefined, [ev("a")], 1000);
  store.appendBlock(g);
  const huge = "x".repeat(MAX_BLOCK_BYTES + 10);
  const big = sealBlock(g, [ev("b", { blob: huge })], 1001); // well-formed but over the bound
  assert.equal(validateBlock(big, g).ok, false);
  assert.throws(() => store.appendBlock(big), /exceeds .* size bound/);
  assert.equal(store.readBlocks().length, 1);
});

// ── GENESIS guard: the first block must be seq 0 / ZERO_HASH ────────────────────────────
test("appendBlock REJECTS a first (genesis) block with a non-zero prevHash or non-zero seq", () => {
  const s1 = newStore();
  const events = [ev("a")];
  const badGenesisLink = mint({ seq: 0, prevHash: "a".repeat(64), ts: 1000, cumulativeRoot: foldEvents(ZERO_HASH, events), events });
  assert.throws(() => s1.appendBlock(badGenesisLink), /prevHash does not link/);

  const s2 = newStore();
  const badGenesisSeq = mint({ seq: 5, prevHash: ZERO_HASH, ts: 1000, cumulativeRoot: foldEvents(ZERO_HASH, events), events });
  assert.throws(() => s2.appendBlock(badGenesisSeq), /expected seq 0, got 5/);
  assert.equal(s1.readBlocks().length, 0);
  assert.equal(s2.readBlocks().length, 0);
});

// ── COMPOSITION: the write predicate IS the read predicate (no drift) ───────────────────
test("COMPOSED: validateBlock and verifyChain agree — verifyChain rejects exactly what appendBlock refuses", () => {
  const g = sealBlock(undefined, [ev("a")], 1000);
  const good = sealBlock(g, [ev("b")], 1001);
  const badHash: SealedBlock = { ...good, hash: "c".repeat(64) };
  // appendBlock refuses it...
  const store = newStore();
  store.appendBlock(g);
  assert.throws(() => store.appendBlock(badHash));
  // ...and verifyChain (which folds the SAME predicate) rejects the same block in a chain.
  const asChain = verifyChain([g, badHash]);
  assert.equal(asChain.ok, false);
  assert.equal(asChain.failedAt, 1);
  // The two ends produce the same reason for the same block (single source of truth).
  assert.equal(validateBlock(badHash, g).reason, asChain.reason);
});

// ── BACK OF HOUSE (the property): append succeeds ⇒ verifyChain passes, across a fuzzed
//    sequence; every corrupt variant is refused and NEVER persists. Neutering ANY one write
//    check lets its corrupt variant slip in → this test reddens (length grows / verify fails). ─
test("BACK: append succeeds ⇒ verifyChain passes across a fuzzed sequence; corrupt blocks never persist", () => {
  const store = newStore();
  let prev: SealedBlock | undefined = undefined;
  const N = 8;
  for (let i = 0; i < N; i++) {
    const b = sealBlock(prev, [ev("e" + i, { i }), ev("f" + i)], 1000 + i);
    store.appendBlock(b); // each well-formed append succeeds
    prev = b;
    // invariant after every append: the persisted chain verifies
    assert.equal(verifyChain(store.readBlocks()).ok, true);
  }
  const head = prev!;
  const events = [ev("z")];
  const goodNext = sealBlock(head, events, 2000);
  const corrupt: SealedBlock[] = [
    mint({ seq: head.seq + 1, prevHash: "a".repeat(64), ts: 2000, cumulativeRoot: foldEvents(head.cumulativeRoot, events), events }), // bad link
    mint({ seq: head.seq + 2, prevHash: head.hash, ts: 2000, cumulativeRoot: foldEvents(head.cumulativeRoot, events), events }), // skipped seq
    mint({ seq: head.seq + 1, prevHash: head.hash, ts: 2000, cumulativeRoot: "b".repeat(64), events }), // bad fold
    { ...goodNext, hash: "c".repeat(64) }, // bad hash
    { ...goodNext, events: [{ id: "x" } as unknown as StagedEvent] }, // malformed
  ];
  for (const c of corrupt) assert.throws(() => store.appendBlock(c));
  // Nothing corrupt reached the file; the chain is exactly the N good blocks and verifies.
  const onDisk = store.readBlocks();
  assert.equal(onDisk.length, N);
  assert.equal(verifyChain(onDisk).ok, true);
});

// ── HONEST SEAM: the write predicate closes ill-formed/mis-linked, NOT lying-but-well-formed ──
test("HONEST SEAM: a structurally valid but semantically lying block is ACCEPTED (not the write predicate's job)", () => {
  const store = newStore();
  const g = sealBlock(undefined, [ev("a")], 1000);
  store.appendBlock(g);
  // A block asserting a falsehood in its payload, but correctly shaped and hash-linked.
  const lying = sealBlock(g, [ev("b", { claim: "the balance is zero", actuallyPositive: true })], 1001);
  assert.equal(validateBlock(lying, g).ok, true);
  assert.doesNotThrow(() => store.appendBlock(lying)); // write predicate does not (and cannot) catch a lie
  assert.equal(verifyChain(store.readBlocks()).ok, true); // it is, after all, a well-formed chain
});
