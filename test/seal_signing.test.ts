import { test } from "node:test";
import assert from "node:assert/strict";

import {
  verificationProvenance, sealProvenance, keyedSealSigner, signSeal, verifySignedSeal,
  type VerificationProvenance, type SignedSeal, type SealSigner,
} from "../src/audit/decision_audit.js";

const rec = (id: string): VerificationProvenance => verificationProvenance({ subjectId: id, deterministicPass: true });
const KEY = "super-secret-org-key", KID = "org-key-1";
const signer = keyedSealSigner(KEY, KID);
const trusted = new Map([[KID, KEY]]);

test("SEAL-SIGNING (a): with a signer injected, a seal gets a detached signature over its hash, and verify confirms it", () => {
  const signed = signSeal(sealProvenance(rec("fix-1")), signer);
  assert.equal(typeof signed.signature.sig, "string");
  assert.equal(signed.signature.keyid, KID);
  const v = verifySignedSeal(signed, trusted);
  assert.equal(v.valid, true, "the signature verifies over the seal hash");
  if (v.valid) assert.equal(v.keyid, KID);
});

test("SEAL-SIGNING (b): a tampered record OR tampered signature fails signature-verify", () => {
  const signed = signSeal(sealProvenance(rec("fix-2")), signer);
  // tampered record (seal no longer intact)
  const tamperedRec: SignedSeal = { ...signed, seal: { ...signed.seal, record: { ...signed.seal.record, overall: "clean", summary: "DOCTORED" } } };
  assert.equal(verifySignedSeal(tamperedRec, trusted).valid, false, "tampered record → seal invalid");
  // tampered signature
  const tamperedSig: SignedSeal = { ...signed, signature: { ...signed.signature, sig: "0".repeat(64) } };
  assert.equal(verifySignedSeal(tamperedSig, trusted).valid, false, "tampered signature → does not verify");
  assert.equal(verifySignedSeal(signed, trusted).valid, true, "the untouched signed seal still verifies");
});

test("SEAL-SIGNING (c): the default (no signer) stays signed:false self-asserted and still valid", () => {
  const bare = sealProvenance(rec("fix-3"));
  assert.equal(bare.signed, false, "an unsigned seal is self-asserted");
  assert.equal(bare.attribution, "self-asserted");
  // it is a perfectly valid seal — signing is opt-in, not required
  // (verifyProvenanceSeal already tested elsewhere; here we assert the honesty markers hold)
});

test("SEAL-SIGNING (d): a signature over the WRONG hash (record swapped under a stale signature) is detected", () => {
  const sA = signSeal(sealProvenance(rec("A")), signer);
  const sB = signSeal(sealProvenance(rec("B")), signer);
  // the signature BINDS to the record's hash — different records ⇒ different signatures
  assert.notEqual(sA.signature.sig, sB.signature.sig, "signature binds to seal.hash");
  // attach A's stale signature to B's seal → detected on verify
  const forged: SignedSeal = { ...sA, seal: sB.seal };
  assert.equal(verifySignedSeal(forged, trusted).valid, false, "a stale signature over a different record's hash does not verify");
});

test("SEAL-SIGNING (e): honesty — the keyed reference is keyed-integrity, NOT non-repudiation; asymmetric is a seam", () => {
  assert.equal(signer.guarantee, "keyed-integrity", "the shared-secret reference is labeled keyed-integrity, not non-repudiation");
  const signed = signSeal(sealProvenance(rec("fix-e")), signer);
  assert.equal(signed.guarantee, "keyed-integrity", "the signed seal never overclaims non-repudiation for a keyed hash");
  // the underlying seal remains self-asserted (signing wraps, does not rewrite the seal's own honesty markers)
  assert.equal(signed.seal.signed, false);
  assert.equal(signed.seal.attribution, "self-asserted");
});

test("SEAL-SIGNING (untrusted-key): a signature from an untrusted key never verifies", () => {
  const rogue = keyedSealSigner("attacker-key", "rogue-kid");
  const signed = signSeal(sealProvenance(rec("fix-u")), rogue);
  assert.equal(verifySignedSeal(signed, trusted).valid, false, "an untrusted keyid does not chain to a trusted signer");
});

test("SEAL-SIGNING (both-tracks): an asymmetric seam-signer may declare non-repudiation (honest upgrade path)", () => {
  // simulate an injected asymmetric provider declaring the stronger guarantee (the named seam)
  const asymmetric: SealSigner = { signer: signer.signer, guarantee: "non-repudiation" };
  const signed = signSeal(sealProvenance(rec("fix-nr")), asymmetric);
  const v = verifySignedSeal(signed, trusted);
  assert.equal(v.valid, true);
  if (v.valid) assert.equal(v.guarantee, "non-repudiation", "the port carries whatever guarantee the injected provider declares");
});
