import { test } from "node:test";
import assert from "node:assert/strict";

import {
  sealBlock,
  verifyChain,
  makeWitness,
  verifyAgainstWitness,
  type SealedBlock,
} from "../src/spine/hashchain.js";
import type { StagedEvent } from "../src/spine/event.js";

// Build Step 1 (harden the two roots): the spine's external-witness check.
// verifyChain proves a chain is internally consistent, but a TRUNCATED or FORKED
// chain is still internally consistent — so tamper-evidence alone is not enough
// against an adversary who can rewrite the local chain file. An independent
// witness (published to a replica/anchor) closes that gap. These tests are the
// proof-test for that claim.

function ev(id: string, payload: Record<string, unknown> = {}): StagedEvent {
  return { id, schemaVersion: 1, type: "generic", ts: 1000, actor: "test", payload };
}

function buildChain(): SealedBlock[] {
  const g = sealBlock(undefined, [ev("a")], 1000);
  const b1 = sealBlock(g, [ev("b"), ev("c")], 1001);
  const b2 = sealBlock(b1, [ev("d")], 1002);
  const b3 = sealBlock(b2, [ev("e")], 1003);
  return [g, b1, b2, b3];
}

test("WITNESS: a healthy chain verifies against its own witness", () => {
  const chain = buildChain();
  const w = makeWitness(chain);
  assert.ok(w, "witness produced");
  const r = verifyAgainstWitness(chain, w!);
  assert.equal(r.ok, true, r.reason);
});

test("WITNESS: a witness at the head pins the entire prefix (a witnessed seq matches)", () => {
  const chain = buildChain();
  const w = makeWitness(chain)!;
  assert.equal(w.seq, 3);
  // cumulativeRoot at the head folds all history [0..3]
  assert.equal(w.cumulativeRoot, chain[3]!.cumulativeRoot);
  assert.equal(w.headHash, chain[3]!.hash);
});

test("WITNESS: TRUNCATION/ROLLBACK is detected against a later witness (verifyChain alone does NOT catch it)", () => {
  const chain = buildChain();
  const witness = makeWitness(chain)!; // pins seq 3

  // Adversary deletes the last two blocks — a rollback to seq 1.
  const truncated = chain.slice(0, 2);

  // verifyChain alone says the truncated chain is a perfectly valid shorter chain:
  assert.equal(verifyChain(truncated).ok, true, "truncated chain is internally valid — the gap");

  // The witness catches it, because the chain no longer reaches the witnessed seq.
  const r = verifyAgainstWitness(truncated, witness);
  assert.equal(r.ok, false);
  assert.match(r.reason ?? "", /truncation|rollback/);
});

test("WITNESS: FORKING is detected (a rebuilt chain with different events diverges from the witness)", () => {
  const chain = buildChain();
  const witness = makeWitness(chain)!; // pins seq 3 of the authentic chain

  // Adversary rebuilds an alternate history from genesis with a different event at b1.
  const g = sealBlock(undefined, [ev("a")], 1000);
  const f1 = sealBlock(g, [ev("b"), ev("c-EVIL")], 1001); // diverges here
  const f2 = sealBlock(f1, [ev("d")], 1002);
  const f3 = sealBlock(f2, [ev("e")], 1003);
  const forked = [g, f1, f2, f3];

  // The forked chain is internally consistent on its own:
  assert.equal(verifyChain(forked).ok, true, "fork is internally valid — the gap");

  // But it diverges from the authentic witness at the witnessed seq.
  const r = verifyAgainstWitness(forked, witness);
  assert.equal(r.ok, false);
  assert.match(r.reason ?? "", /fork/);
});

test("WITNESS: internal tampering is still reported through the witness check", () => {
  const chain = buildChain();
  const witness = makeWitness(chain)!;
  const tampered: SealedBlock[] = chain.map((b, i) =>
    i === 1 ? { ...b, events: [{ ...b.events[0]!, payload: { amount: 999 } }] } : b,
  );
  const r = verifyAgainstWitness(tampered, witness);
  assert.equal(r.ok, false);
  assert.match(r.reason ?? "", /internal|fork/);
});

test("WITNESS: empty chain yields no witness", () => {
  assert.equal(makeWitness([]), undefined);
});
