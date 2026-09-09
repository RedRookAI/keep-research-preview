import { test } from "node:test";
import assert from "node:assert/strict";

import { sealBlock, verifyChain, ZERO_HASH, type SealedBlock } from "../src/spine/hashchain.js";
import type { StagedEvent } from "../src/spine/event.js";

function ev(id: string, payload: Record<string, unknown> = {}): StagedEvent {
  return { id, schemaVersion: 1, type: "generic", ts: 1000, actor: "test", payload };
}

test("genesis block has zero prevHash and seq 0", () => {
  const b = sealBlock(undefined, [ev("a")], 1000);
  assert.equal(b.seq, 0);
  assert.equal(b.prevHash, ZERO_HASH);
  assert.equal(b.hash.length, 64);
});

test("blocks link by prevHash", () => {
  const g = sealBlock(undefined, [ev("a")], 1000);
  const b1 = sealBlock(g, [ev("b")], 1001);
  assert.equal(b1.seq, 1);
  assert.equal(b1.prevHash, g.hash);
});

test("a valid chain verifies", () => {
  const g = sealBlock(undefined, [ev("a")], 1000);
  const b1 = sealBlock(g, [ev("b"), ev("c")], 1001);
  const b2 = sealBlock(b1, [ev("d")], 1002);
  const r = verifyChain([g, b1, b2]);
  assert.equal(r.ok, true);
});

test("tampering with an event payload is detected", () => {
  const g = sealBlock(undefined, [ev("a")], 1000);
  const b1 = sealBlock(g, [ev("b", { amount: 100 })], 1001);
  // Mutate a sealed event's payload after the fact.
  const tampered: SealedBlock = {
    ...b1,
    events: [{ ...b1.events[0]!, payload: { amount: 999 } }],
  };
  const r = verifyChain([g, tampered]);
  assert.equal(r.ok, false);
  assert.equal(r.failedAt, 1);
});

test("tampering with a block hash is detected", () => {
  const g = sealBlock(undefined, [ev("a")], 1000);
  const b1 = sealBlock(g, [ev("b")], 1001);
  const tampered: SealedBlock = { ...b1, hash: "f".repeat(64) };
  const r = verifyChain([g, tampered]);
  assert.equal(r.ok, false);
});

test("reordering blocks is detected", () => {
  const g = sealBlock(undefined, [ev("a")], 1000);
  const b1 = sealBlock(g, [ev("b")], 1001);
  const r = verifyChain([b1, g]);
  assert.equal(r.ok, false);
});

test("deleting a middle block breaks the chain", () => {
  const g = sealBlock(undefined, [ev("a")], 1000);
  const b1 = sealBlock(g, [ev("b")], 1001);
  const b2 = sealBlock(b1, [ev("c")], 1002);
  const r = verifyChain([g, b2]); // b1 removed
  assert.equal(r.ok, false);
});
