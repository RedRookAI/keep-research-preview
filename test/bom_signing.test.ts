import { test } from "node:test";
import assert from "node:assert/strict";

import {
  StubSigner,
  verifySignedBom,
  signedBomVerified,
  signedContent,
  type SignedBom,
  type TrustPolicy,
} from "../src/bom/bom_signing.js";
import type { AiBom } from "../src/bom/ai_bom.js";

// R34 — BOM-signing authenticity conformance. Proves the VERIFY-side authenticity: only a trusted
// signer's signature over the exact content verifies; a forged/tampered/untrusted-key/quorum-short
// envelope is unverifiable. The real HSM/KMS key custody is the SEAM. Verify by disproof.

const bom: AiBom = { subject: "run:1", modelId: "keep", toolSet: ["file.edit"], timestamp: 1000 };

function policy(keys: Record<string, string>, threshold = 1): TrustPolicy {
  return { trustedKeys: new Map(Object.entries(keys)), threshold };
}
function sign(privKey: string, keyid: string, env: Omit<SignedBom, "signatures">): SignedBom {
  const s = new StubSigner(privKey, keyid).sign(signedContent(env.payload, env.attestedMeasurement));
  return { ...env, signatures: [s] };
}

test("R34: a BOM signed by a TRUSTED key verifies", () => {
  const env = sign("priv-A", "key-A", { payload: bom });
  assert.equal(verifySignedBom(env, policy({ "key-A": "priv-A" })).verified, true);
});

test("R34: a TAMPERED payload after signing is unverifiable (isolated — signature over the old content)", () => {
  const env = sign("priv-A", "key-A", { payload: bom });
  const tampered: SignedBom = { ...env, payload: { ...bom, modelId: "evil-model" } }; // change after signing
  const v = verifySignedBom(tampered, policy({ "key-A": "priv-A" }));
  assert.equal(v.verified, false);
  if (!v.verified) assert.ok(v.reason.startsWith("threshold-not-met")); // the one signature no longer validates
});

test("R34: a signature by an UNTRUSTED key is rejected (isolated — the agent's own key is not trusted)", () => {
  const env = sign("agent-priv", "agent-key", { payload: bom }); // the agent signs its own BOM
  const v = verifySignedBom(env, policy({ "key-A": "priv-A" })); // agent-key is NOT in the trust policy
  assert.equal(v.verified, false, "an untrusted signer cannot authenticate a BOM");
});

test("R34: tampering the attested measurement (R37 binding) invalidates the signature (isolated)", () => {
  const env = sign("priv-A", "key-A", { payload: bom, attestedMeasurement: "good-measurement" });
  const swapped: SignedBom = { ...env, attestedMeasurement: "tampered-measurement" };
  assert.equal(verifySignedBom(swapped, policy({ "key-A": "priv-A" })).verified, false);
});

test("R34: an ABSENT envelope and one with NO signatures both deny (fail-safe)", () => {
  assert.equal(verifySignedBom(undefined, policy({ "key-A": "priv-A" })).verified, false);
  assert.equal(verifySignedBom({ payload: bom, signatures: [] }, policy({ "key-A": "priv-A" })).verified, false);
});

test("R34: a k-of-2 threshold with only ONE trusted signer is unverifiable (R25 quorum, isolated)", () => {
  const env = sign("priv-A", "key-A", { payload: bom }); // one signature
  const v = verifySignedBom(env, policy({ "key-A": "priv-A", "key-B": "priv-B" }, 2)); // needs 2
  assert.equal(v.verified, false);
  if (!v.verified) assert.ok(v.reason.startsWith("threshold-not-met"));
});

test("R34: a k-of-2 threshold MET by two distinct trusted signers verifies", () => {
  const content = signedContent(bom, undefined);
  const sA = new StubSigner("priv-A", "key-A").sign(content);
  const sB = new StubSigner("priv-B", "key-B").sign(content);
  const env: SignedBom = { payload: bom, signatures: [sA, sB] };
  const v = verifySignedBom(env, policy({ "key-A": "priv-A", "key-B": "priv-B" }, 2));
  assert.equal(v.verified, true);
  if (v.verified) assert.equal(v.signerCount, 2);
});

test("R34: signedBomVerified maps verified→true (no veto) and unverifiable→false (gate veto)", () => {
  const env = sign("priv-A", "key-A", { payload: bom });
  assert.equal(signedBomVerified(verifySignedBom(env, policy({ "key-A": "priv-A" }))), true);
  assert.equal(signedBomVerified(verifySignedBom(undefined, policy({ "key-A": "priv-A" }))), false);
});
