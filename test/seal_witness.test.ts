import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  verificationProvenance, sealProvenance, keyedSealSigner, signSeal,
  anchorSeal, checkSealInclusion, type VerificationProvenance,
} from "../src/audit/decision_audit.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";

const rec = (id: string): VerificationProvenance => verificationProvenance({ subjectId: id, deterministicPass: true });
function makeSpine(clock: () => number = () => 1000) {
  const dir = mkdtempSync(join(tmpdir(), "keep-witness-"));
  const store = new FileSpineStore(dir);
  return { spine: new Spine(store, new InProcessLock(), new SchemaRegistry(), clock), store, dir };
}

test("SEAL-WITNESS (a): anchoring a sealed record stages a witness event carrying its hash into the spine", async () => {
  const { spine } = makeSpine();
  const seal = sealProvenance(rec("fix-1"));
  const w = anchorSeal(spine, seal);
  assert.equal(w.sealHash, seal.hash);
  assert.equal(w.scope, "local-spine");
  await spine.seal(); // commit into the chain
  const committed = spine.replay();
  assert.ok(committed.some((e) => e.payload["event"] === "seal_witness" && e.payload["sealHash"] === seal.hash), "the witness event carries the seal hash");
});

test("SEAL-WITNESS (b): an inclusion check confirms a witnessed seal is present in the chain", async () => {
  const { spine } = makeSpine(() => 4242);
  const signed = signSeal(sealProvenance(rec("fix-2")), keyedSealSigner("k", "kid-1"));
  anchorSeal(spine, signed);
  await spine.seal();
  const v = checkSealInclusion(spine, signed.seal.hash);
  assert.equal(v.witnessed, true);
  if (v.witnessed) { assert.equal(v.witnessedAt, 4242, "carries the spine timestamp"); assert.equal(v.chainIntact, true); }
});

test("SEAL-WITNESS (c): a seal NOT anchored is reported un-witnessed (never assumed present)", async () => {
  const { spine } = makeSpine();
  anchorSeal(spine, sealProvenance(rec("anchored")));
  await spine.seal();
  const other = sealProvenance(rec("never-anchored"));
  const v = checkSealInclusion(spine, other.hash);
  assert.equal(v.witnessed, false, "an un-anchored seal is not assumed present");
  if (!v.witnessed) assert.match(v.reason, /un-witnessed/);
});

test("SEAL-WITNESS (d): the witness is ordered/timestamped by the tamper-evident chain (a re-date is detectable)", async () => {
  const { spine, dir } = makeSpine(() => 5000);
  const seal = sealProvenance(rec("fix-4"));
  anchorSeal(spine, seal);
  await spine.seal();
  assert.equal(spine.verify().ok, true, "intact chain verifies");
  // tamper the persisted chain: re-date the witnessed event on disk → the block hash no longer matches → chain breaks
  const chainPath = join(dir, "chain.jsonl");
  const rewritten = readFileSync(chainPath, "utf8").replace(/"ts":5000/g, '"ts":9999');
  writeFileSync(chainPath, rewritten);
  const v = checkSealInclusion(spine, seal.hash);
  if (v.witnessed) assert.equal(v.chainIntact, false, "a re-dated witness breaks the tamper-evident chain");
  assert.equal(spine.verify().ok, false, "spine.verify detects the re-date");
});

test("SEAL-WITNESS (e): honesty — the witness is local-spine ordering, not a public transparency log", () => {
  const { spine } = makeSpine();
  const w = anchorSeal(spine, sealProvenance(rec("fix-e")));
  assert.equal(w.scope, "local-spine", "the witness is honestly scoped local — not a public/trustless transparency log");
  // the external mirror is a named seam — the spine's makeWitness is its primitive
  assert.equal(typeof spine.witnessHead, "function", "an external-witness seam primitive exists (witnessHead)");
});

test("SEAL-WITNESS (both-tracks): a signed seal's witness carries the signature keyid", async () => {
  const { spine } = makeSpine();
  const signed = signSeal(sealProvenance(rec("fix-nr")), keyedSealSigner("k", "org-key-9"));
  const w = anchorSeal(spine, signed);
  assert.equal(w.keyid, "org-key-9", "the witness records which key signed");
});
