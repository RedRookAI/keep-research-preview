import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { Ed25519ExternalReviewCorroborationVerifier, externalReviewEvidenceSignaturePreimage, type ExternalReviewTrustRootV1 } from "../src/discipline/external_review_corroboration.js";
import type { Sha256Digest } from "../src/discipline/contracts.js";
import { canonicalize } from "../src/spine/event.js";
import { composeKeep } from "../src/compose.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const digest = (c: string) => c.repeat(64) as Sha256Digest;
const keys = generateKeyPairSync("ed25519");
const trust: ExternalReviewTrustRootV1 = { schema: "keep.external-review-trust-root/v1", anchors: [{ keyId: "provider-key-1", captureClass: "provider-signed", provider: "provider-a", familyId: "family-a", publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }).toString(), validFromMs: 100, validUntilMs: 1_000, revokedAtMs: null }] };
const unsigned = () => ({ schema: "keep.signed-external-review-evidence/v1" as const, candidateDigest: digest("a"), subjectManifestDigest: digest("b"), policyDigest: digest("c"), rawEvidenceDigest: digest("d"), requestDigest: digest("e"), transactionDigest: digest("f"), campaignId: "campaign-1", operationId: "operation-1", operationPredecessorId: null, attemptId: "attempt-1", round: 2, independence: "cross-family-external-technical" as const, verdict: "go" as const, findingDigests: [] as string[], limitations: [] as string[], provider: "provider-a", model: "model-a", familyId: "family-a", sessionId: "session-1", captureClass: "provider-signed" as const, observedAtMs: 200, expiresAtMs: 800, keyId: "provider-key-1" });
const carrier = (overrides: Record<string, unknown> = {}, signingKey = keys.privateKey) => { const row = { ...unsigned(), ...overrides }; return Buffer.from(`${canonicalize({ ...row, signatureBase64: sign(null, externalReviewEvidenceSignaturePreimage(row as ReturnType<typeof unsigned>), signingKey).toString("base64") })}\n`); };
const tamper = (bytes: Buffer, overrides: Record<string, unknown>) => Buffer.from(`${canonicalize({ ...JSON.parse(bytes.toString("utf8")) as Record<string, unknown>, ...overrides })}\n`);
const expected = { candidateDigest: digest("a"), subjectManifestDigest: digest("b"), policyDigest: digest("c"), requestDigest: digest("e"), builderFamilyId: "builder-family" };

test("provider-signed review receipt verifies exact identities without asserting trust-root custody", async () => {
  const result = await new Ed25519ExternalReviewCorroborationVerifier(trust, () => 500).verifyExternalReview(carrier(), expected);
  assert.equal(result.corroboration, "provider-signed"); assert.equal(result.verdict, "go");
});

test("operator witness remains useful but cannot authorize product promotion", async () => {
  const operatorTrust: ExternalReviewTrustRootV1 = { ...trust, anchors: [{ ...trust.anchors[0]!, captureClass: "operator-witnessed" }] };
  const result = await new Ed25519ExternalReviewCorroborationVerifier(operatorTrust, () => 500).verifyExternalReview(carrier({ captureClass: "operator-witnessed" }), expected);
  assert.equal(result.corroboration, "operator-witnessed");
});

test("identity, signature, trust-root, class, provider, family, expiry, and revocation substitutions refuse", async () => {
  const verifier = new Ed25519ExternalReviewCorroborationVerifier(trust, () => 500);
  await assert.rejects(verifier.verifyExternalReview(carrier(), { ...expected, policyDigest: digest("e") }), /identity mismatch/);
  await assert.rejects(verifier.verifyExternalReview(tamper(carrier(), { rawEvidenceDigest: digest("e") }), expected), /signature is invalid/);
  const attacker = generateKeyPairSync("ed25519"); await assert.rejects(verifier.verifyExternalReview(carrier({}, attacker.privateKey), expected), /signature is invalid/);
  await assert.rejects(verifier.verifyExternalReview(carrier({ captureClass: "independent-witness" }), expected), /trust binding/);
  await assert.rejects(verifier.verifyExternalReview(carrier({ provider: "provider-b" }), expected), /trust binding/);
  await assert.rejects(verifier.verifyExternalReview(carrier({ familyId: "family-b" }), expected), /trust binding/);
  await assert.rejects(new Ed25519ExternalReviewCorroborationVerifier(trust, () => 801).verifyExternalReview(carrier(), expected), /not currently valid/);
  await assert.rejects(verifier.verifyExternalReview(carrier({ expiresAtMs: 31 * 24 * 60 * 60 * 1_000 }), expected), /chronology is invalid/);
  const revoked: ExternalReviewTrustRootV1 = { ...trust, anchors: [{ ...trust.anchors[0]!, revokedAtMs: 150 }] };
  await assert.rejects(new Ed25519ExternalReviewCorroborationVerifier(revoked, () => 500).verifyExternalReview(carrier(), expected), /trust binding/);
  const laterRevoked: ExternalReviewTrustRootV1 = { ...trust, anchors: [{ ...trust.anchors[0]!, revokedAtMs: 400 }] };
  await assert.rejects(new Ed25519ExternalReviewCorroborationVerifier(laterRevoked, () => 500).verifyExternalReview(carrier(), expected), /trust binding/);
  await assert.rejects(verifier.verifyExternalReview(carrier(), { ...expected, builderFamilyId: "family-a" }), /independence does not match/);
});

test("unknown fields, unsorted or duplicated findings, non-Ed25519 roots, and malformed input refuse", async () => {
  const verifier = new Ed25519ExternalReviewCorroborationVerifier(trust, () => 500);
  await assert.rejects(verifier.verifyExternalReview(carrier({ surprise: true }), expected), /fields are not exact/);
  await assert.rejects(verifier.verifyExternalReview(carrier({ findingDigests: [digest("b"), digest("a")] }), expected), /unique and sorted/);
  await assert.rejects(verifier.verifyExternalReview(Buffer.from("{}"), expected), /fields are not exact/);
  await assert.rejects(verifier.verifyExternalReview(Buffer.from(carrier().toString("utf8").trim()), expected), /not canonical/);
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const wrong: ExternalReviewTrustRootV1 = { ...trust, anchors: [{ ...trust.anchors[0]!, publicKeyPem: rsa.publicKey.export({ type: "spki", format: "pem" }).toString() }] };
  await assert.rejects(new Ed25519ExternalReviewCorroborationVerifier(wrong, () => 500).verifyExternalReview(carrier(), expected), /not Ed25519/);
});

test("hostile expected identities and trust-root arrays fail without executing accessors", async () => {
  let reads = 0;
  const hostileExpected = { candidateDigest: digest("a"), subjectManifestDigest: digest("b"), requestDigest: digest("e"), builderFamilyId: "builder-family", get policyDigest() { reads++; return digest("c"); } };
  const verifier = new Ed25519ExternalReviewCorroborationVerifier(trust, () => 500);
  await assert.rejects(verifier.verifyExternalReview(carrier(), hostileExpected), /not inert data/); assert.equal(reads, 0);
  const hostileAnchor = { ...trust.anchors[0]!, get provider() { reads++; return "provider-a"; } };
  assert.throws(() => new Ed25519ExternalReviewCorroborationVerifier({ ...trust, anchors: [hostileAnchor] }, () => 500), /not inert data/); assert.equal(reads, 0);
});

test("compose dogfoods explicit corroboration and has no implicit local-trust fallback", async () => {
  const off = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-review-corrob-off-")) });
  assert.equal(off.externalReviewVerifier, undefined);
  const on = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-review-corrob-on-")), externalReviewCorroboration: { trustRoot: trust, trustedNowMs: () => 500 } });
  assert.ok(on.externalReviewVerifier);
  assert.equal((await on.externalReviewVerifier.verifyExternalReview(carrier(), expected)).corroboration, "provider-signed");
});
