import { test } from "node:test";
import assert from "node:assert/strict";

import {
  verificationProvenance, sealProvenance, verifyProvenanceSeal, chainProvenance, verifyProvenanceChain,
  type VerificationProvenance, type SealedProvenance,
} from "../src/audit/decision_audit.js";
import { ZERO_HASH } from "../src/spine/hashchain.js";

const rec = (id: string): VerificationProvenance =>
  verificationProvenance({ subjectId: id, deterministicPass: true, confidence: { score: 1, band: "high", reasons: ["deterministic pass (+0.50)"] } });

test("PROVENANCE-SEAL (a): sealing a record yields a stable hash (same record → same seal)", () => {
  const r = rec("fix-1");
  const s1 = sealProvenance(r);
  const s2 = sealProvenance(r);
  assert.equal(s1.hash, s2.hash, "deterministic content hash");
  assert.equal(s1.hash.length, 64, "sha-256 hex");
  assert.equal(s1.prevHash, ZERO_HASH, "genesis prevHash");
  assert.equal(verifyProvenanceSeal(s1).valid, true);
});

test("PROVENANCE-SEAL (b): any edit to a sealed record is detected on re-verify (TAMPERED)", () => {
  const s = sealProvenance(rec("fix-2"));
  // forge an altered record under the original hash
  const tampered: SealedProvenance = { ...s, record: { ...s.record, overall: "clean", summary: "DOCTORED to look clean" } };
  const v = verifyProvenanceSeal(tampered);
  assert.equal(v.valid, false);
  if (!v.valid) assert.match(v.reason, /TAMPERED|mismatch/);
  // an untouched seal still verifies
  assert.equal(verifyProvenanceSeal(s).valid, true);
});

test("PROVENANCE-SEAL (c): a hash-chain links records; a break/reorder is detected", () => {
  const chain = chainProvenance([rec("a"), rec("b"), rec("c")]);
  assert.equal(chain[0]!.prevHash, ZERO_HASH);
  assert.equal(chain[1]!.prevHash, chain[0]!.hash, "each block links to the prior hash");
  assert.equal(chain[2]!.prevHash, chain[1]!.hash);
  assert.equal(verifyProvenanceChain(chain).valid, true, "intact chain verifies");
  // reorder → break detected
  const reordered = [chain[0]!, chain[2]!, chain[1]!];
  const v = verifyProvenanceChain(reordered);
  assert.equal(v.valid, false);
  if (!v.valid) assert.match(v.reason, /chain break/);
});

test("PROVENANCE-SEAL (d): verification is total — a missing/malformed seal reports invalid, never silently valid", () => {
  assert.equal(verifyProvenanceSeal(null).valid, false);
  assert.equal(verifyProvenanceSeal(undefined).valid, false);
  const s = sealProvenance(rec("fix-d"));
  assert.equal(verifyProvenanceSeal({ ...s, hash: "short" }).valid, false, "malformed hash");
  assert.equal(verifyProvenanceSeal({ ...s, hash: "f".repeat(64) }).valid, false, "wrong hash");
  assert.equal(verifyProvenanceSeal({ ...s, prevHash: 123 as unknown as string }).valid, false, "malformed prevHash");
});

test("PROVENANCE-SEAL (e): the seal is integrity-only and honest — never claims authenticity", () => {
  const s = sealProvenance(rec("fix-e"));
  assert.equal(s.integrity, "tamper-evident", "labeled integrity, not authenticity");
  assert.equal(s.signed, false, "never claims to be signed / authored");
  // @ts-expect-error — there is no field asserting authorship/authenticity on the seal
  assert.equal(s.authentic, undefined);
});

test("PROVENANCE-SEAL (both-tracks): a single n=1 sealed record verifies as a standalone genesis block", () => {
  const s = sealProvenance(rec("solo"));
  assert.equal(verifyProvenanceChain([s]).valid, true, "one sealed record is a valid single-block chain");
});
