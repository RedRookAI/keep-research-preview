import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InMemoryWitnessSink } from "../src/spine/witness_sink.js";
import {
  reconcileWithWitness,
  extractAttestations,
  restoredContentDigest,
  SeenNonceGuard,
  type RestorationRef,
  type RestorationVerifier,
} from "../src/spine/witness_reconcile.js";
import { signRestoration } from "../src/tcb/attestation.js";
import { sealBlock, makeWitness, type SealedBlock } from "../src/spine/hashchain.js";
import type { StagedEvent } from "../src/spine/event.js";

// Build Step 1 — the LIVE spine anchor. The witness mechanism shipped earlier; this
// proves the anchor is wired: a witness is emitted to an independent sink on seal, and
// the chain is reconciled against it — accepting an authorized restore, rejecting an
// unattested fork/truncation. Verify by disproof.

function newSpine() {
  const dir = mkdtempSync(join(tmpdir(), "keep-anchor-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}
function ev(id: string): StagedEvent {
  return { id, schemaVersion: 1, type: "generic", ts: 1000, actor: "t", payload: {} };
}

test("ANCHOR: emit-on-seal publishes a witness to the independent sink", async () => {
  const spine = newSpine();
  const sink = new InMemoryWitnessSink();
  spine.stage({ type: "generic", actor: "t", payload: { n: 1 } });
  await spine.sealAndWitness(sink);
  const w = sink.latest();
  assert.ok(w, "a witness was published on seal");
  assert.equal(w!.seq, 0);
  // and the live chain reconciles as consistent against it:
  assert.deepEqual(spine.reconcileAgainst(sink), { status: "consistent" });
});

test("ANCHOR: a forward extension after more seals still reconciles consistent", async () => {
  const spine = newSpine();
  const sink = new InMemoryWitnessSink();
  spine.stage({ type: "generic", actor: "t", payload: { n: 1 } });
  await spine.sealAndWitness(sink);
  spine.stage({ type: "generic", actor: "t", payload: { n: 2 } });
  await spine.sealAndWitness(sink);
  assert.deepEqual(spine.reconcileAgainst(sink), { status: "consistent" });
});

// The two attacks from the witness's shipping round, now against the LIVE flow.
test("ANCHOR: an unattested TRUNCATION is rejected as tamper against the emitted witness", () => {
  // Build a 4-block chain, witness the head, then truncate.
  const g = sealBlock(undefined, [ev("a")], 1000);
  const b1 = sealBlock(g, [ev("b")], 1001);
  const b2 = sealBlock(b1, [ev("c")], 1002);
  const b3 = sealBlock(b2, [ev("d")], 1003);
  const witness = makeWitness([g, b1, b2, b3])!;
  const truncated = [g, b1]; // rollback to seq 1
  const v = reconcileWithWitness(truncated, witness, []); // no attestation
  assert.equal(v.status, "tamper");
  assert.equal(v.status === "tamper" && v.kind, "truncation");
});

test("ANCHOR: an unattested FORK is rejected as tamper against the emitted witness", () => {
  const g = sealBlock(undefined, [ev("a")], 1000);
  const b1 = sealBlock(g, [ev("b")], 1001);
  const witness = makeWitness([g, b1])!;
  const f1 = sealBlock(g, [ev("b-EVIL")], 1001); // diverges at seq 1
  const forked = [g, f1];
  const v = reconcileWithWitness(forked, witness, []);
  assert.equal(v.status, "tamper");
  assert.equal(v.status === "tamper" && v.kind, "fork");
});

test("ANCHOR: a legitimate operator-ATTESTED restore reconciles as authorized (the reversing-entry)", () => {
  const g = sealBlock(undefined, [ev("a")], 1000);
  const b1 = sealBlock(g, [ev("b")], 1001);
  const b2 = sealBlock(b1, [ev("c")], 1002);
  const witness = makeWitness([g, b1, b2])!; // pins seq 2

  // Authorized restore: fork after seq 1, but with a signed attestation referencing the
  // superseded witnessed hash (double-entry: an append-only, referencing correction).
  const r1 = sealBlock(g, [ev("b")], 1001);
  const restored = [g, r1];
  // BUILD-ORDER 8.44A / 8.44A-FIX: the signature is CRYPTOGRAPHICALLY VERIFIED against the enrolled key over
  // the canonical restore bytes, which now BIND the restored content (contentDigest of `restored`) and its
  // head seq, and bound to a fresh nonce — not merely counted as present.
  const key = Buffer.alloc(32, 7);
  const fields = {
    restoredToSeq: 1,
    priorWitnessedHash: witness.headHash,
    contentDigest: restoredContentDigest(restored),
    nonce: "nonce-anchor-1",
  };
  const attestation: RestorationRef = { ...fields, signature: signRestoration(key, fields) };
  const verifier: RestorationVerifier = { key, replay: new SeenNonceGuard() };
  const v = reconcileWithWitness(restored, witness, [attestation], verifier);
  assert.equal(v.status, "authorized-restore");
});

test("ANCHOR: an attestation that does NOT reference the witnessed hash does NOT launder a fork", () => {
  const g = sealBlock(undefined, [ev("a")], 1000);
  const b1 = sealBlock(g, [ev("b")], 1001);
  const witness = makeWitness([g, b1])!;
  const f1 = sealBlock(g, [ev("b-EVIL")], 1001);
  const forked = [g, f1];
  // attacker supplies an attestation, but referencing the WRONG (stale/unrelated) hash:
  const bogus: RestorationRef = { restoredToSeq: 1, priorWitnessedHash: "deadbeef".repeat(8), contentDigest: "", signature: "x", nonce: "n" };
  const verifier: RestorationVerifier = { key: Buffer.alloc(32, 7), replay: new SeenNonceGuard() };
  const v = reconcileWithWitness(forked, witness, [bogus], verifier);
  assert.equal(v.status, "tamper", "a non-referencing attestation cannot authorize a fork");
});

test("ANCHOR: extractAttestations reads restoration.attestation events from the chain", () => {
  const events: StagedEvent[] = [
    ev("x"),
    { id: "r", schemaVersion: 1, type: "restoration.attestation", ts: 1, actor: "op",
      payload: { restoredToSeq: 3, priorWitnessedHash: "abc", signature: "sig" } },
  ];
  const got = extractAttestations(events);
  assert.equal(got.length, 1);
  assert.equal(got[0]!.priorWitnessedHash, "abc");
});
