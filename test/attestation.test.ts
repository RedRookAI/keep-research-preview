import { test } from "node:test";
import assert from "node:assert/strict";

import {
  StubAttester,
  verifyQuote,
  attestedTcbIntact,
  stubSign,
  type Appraisal,
} from "../src/tcb/attestation.js";
import { pinTcb, measureModule, tcbManifestDigest, sha256Hex } from "../src/tcb/verify_tcb.js";

// R37 — running-binary attestation conformance. Proves the VERIFIER-side appraisal + freshness; the
// real TPM/TEE quote over the loaded binary is the SEAM. Verify by disproof.

const KEY = "attestation-key";
const GOOD_MEASUREMENT = sha256Hex("loaded-tcb-nine-modules"); // stands in for the PCR/report digest

function appraisal(nonce: string, expectedDigest = GOOD_MEASUREMENT): Appraisal {
  return { expectedDigest, challengeNonce: nonce, verifyKey: KEY };
}

test("R37: a valid quote (right measurement, fresh nonce, good signature) verifies", () => {
  const attester = new StubAttester(GOOD_MEASUREMENT, KEY);
  const nonce = "fresh-nonce-1";
  const quote = attester.quote(nonce); // attester echoes the fresh nonce
  const v = verifyQuote(quote, appraisal(nonce));
  assert.equal(v.verified, true);
});

test("R37: a quote over the WRONG measurement fails appraisal (isolated — signature valid, nonce fresh)", () => {
  const tampered = sha256Hex("tampered-running-image");
  const attester = new StubAttester(tampered, KEY); // signs a valid quote over the TAMPERED measurement
  const nonce = "fresh-nonce-2";
  const quote = attester.quote(nonce);
  const v = verifyQuote(quote, appraisal(nonce)); // expects GOOD_MEASUREMENT
  assert.equal(v.verified, false);
  if (!v.verified) assert.equal(v.reason, "measurement-mismatch");
});

test("R37: a STALE nonce is rejected as replay (isolated — signature valid over the old nonce)", () => {
  const attester = new StubAttester(GOOD_MEASUREMENT, KEY);
  const oldQuote = attester.quote("old-nonce"); // a legit quote from a previous challenge
  const v = verifyQuote(oldQuote, appraisal("new-fresh-nonce")); // verifier issued a NEW nonce
  assert.equal(v.verified, false);
  if (!v.verified) assert.equal(v.reason, "stale-nonce");
});

test("R37: a bad signature is rejected (isolated)", () => {
  const nonce = "fresh-nonce-3";
  const forged = { measurementDigest: GOOD_MEASUREMENT, nonce, signature: "not-a-real-signature" };
  const v = verifyQuote(forged, appraisal(nonce));
  assert.equal(v.verified, false);
  if (!v.verified) assert.equal(v.reason, "bad-signature");
});

test("R37: an ABSENT quote denies (fail-safe)", () => {
  const v = verifyQuote(undefined, appraisal("n"));
  assert.equal(v.verified, false);
  if (!v.verified) assert.equal(v.reason, "no-quote");
});

test("R37: attestedTcbIntact maps failed→false (→ gate veto) and verified→true", () => {
  const attester = new StubAttester(GOOD_MEASUREMENT, KEY);
  const nonce = "fresh-nonce-4";
  assert.equal(attestedTcbIntact(verifyQuote(attester.quote(nonce), appraisal(nonce))), true);
  assert.equal(attestedTcbIntact(verifyQuote(undefined, appraisal(nonce))), false);
});

test("R37: the attested measurement binds to the pinned TCB manifest digest (R34 anchor)", () => {
  // a real attester would measure the loaded modules; here we bind the appraisal's expected digest to
  // the verify_tcb pinned manifest digest, so 'what ran' is appraised against 'what we signed off'.
  const measured = new Map([["src/gate/composed_gate.ts", measureModule("export const x = 1;")]]);
  const manifest = pinTcb(measured, {});
  const pinnedDigest = tcbManifestDigest(manifest);
  const attester = new StubAttester(pinnedDigest, KEY);
  const nonce = "fresh-nonce-5";
  const v = verifyQuote(attester.quote(nonce), appraisal(nonce, pinnedDigest));
  assert.equal(v.verified, true, "the attested running measurement matches the pinned manifest digest");
});

test("R37: stubSign is deterministic (the verifier recomputes the expected signature)", () => {
  assert.equal(stubSign(KEY, GOOD_MEASUREMENT, "n"), stubSign(KEY, GOOD_MEASUREMENT, "n"));
});
