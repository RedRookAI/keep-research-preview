import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import type { Sha256Digest } from "../src/discipline/contracts.js";
import { Ed25519ExternalReviewCorroborationVerifier, externalReviewEvidenceSignaturePreimage, type ExternalReviewTrustRootV1 } from "../src/discipline/external_review_corroboration.js";
import { partitionedReviewTransactionDigest, reviewCrossEdgeDigest, verifyPartitionedReviewComposition } from "../src/discipline/review_composition.js";
import { canonicalize } from "../src/spine/event.js";

const hex = (character: string): Sha256Digest => character.repeat(64) as Sha256Digest;
const keys = generateKeyPairSync("ed25519");
const trust: ExternalReviewTrustRootV1 = { schema: "keep.external-review-trust-root/v1", anchors: [{ keyId: "review-key", captureClass: "provider-signed", provider: "review-provider", familyId: "review-family", publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }).toString(), validFromMs: 1, validUntilMs: 1_000, revokedAtMs: null }] };
const verifier = new Ed25519ExternalReviewCorroborationVerifier(trust, () => 500);

async function external(candidateDigest: Sha256Digest, subjectManifestDigest: Sha256Digest, rawEvidenceDigest: Sha256Digest, transactionDigest: Sha256Digest, suffix: string, verdict: "go" | "revise" = "go", findingDigests: readonly Sha256Digest[] = []) {
  const unsigned = { schema: "keep.signed-external-review-evidence/v1" as const, candidateDigest, subjectManifestDigest, policyDigest: hex("e"), rawEvidenceDigest, requestDigest: hex("1"), transactionDigest, campaignId: "campaign", operationId: "operation", operationPredecessorId: null, attemptId: `attempt-${suffix}`, round: 1, independence: "cross-family-external-technical" as const, verdict, findingDigests, limitations: [] as string[], provider: "review-provider", model: "review-model", familyId: "review-family", sessionId: `session-${suffix}`, captureClass: "provider-signed" as const, observedAtMs: 200, expiresAtMs: 800, keyId: "review-key" };
  const carrier = Buffer.from(`${canonicalize({ ...unsigned, signatureBase64: sign(null, externalReviewEvidenceSignaturePreimage(unsigned), keys.privateKey).toString("base64") })}\n`);
  return verifier.verifyExternalReview(carrier, { candidateDigest, subjectManifestDigest, policyDigest: hex("e"), requestDigest: hex("1"), builderFamilyId: "builder-family" });
}

async function fixture() {
  const subjects = [hex("a"), hex("b"), hex("c")];
  const subjectManifestDigest = hex("d"), childTransactions = [hex("2"), hex("3"), hex("4")], raw = [hex("5"), hex("6"), hex("7")], candidates = [hex("8"), hex("9"), hex("0")];
  const endpointDigests = subjects.slice(1) as [Sha256Digest, Sha256Digest], relationDigest = hex("2");
  const crossEdges = [{ edgeDigest: reviewCrossEdgeDigest(endpointDigests, relationDigest), endpointDigests, relationDigest }];
  const parts = [
    { partId: "primary-1", kind: "primary", candidateDigest: candidates[0], subjectDigests: subjects.slice(0, 2), rawEvidenceDigest: raw[0], reviewTransactionDigest: childTransactions[0], coveredEdgeDigests: [] },
    { partId: "primary-2", kind: "primary", candidateDigest: candidates[1], subjectDigests: subjects.slice(2), rawEvidenceDigest: raw[1], reviewTransactionDigest: childTransactions[1], coveredEdgeDigests: [] },
    { partId: "overlap-1", kind: "overlap", candidateDigest: candidates[2], subjectDigests: subjects.slice(1), rawEvidenceDigest: raw[2], reviewTransactionDigest: childTransactions[2], coveredEdgeDigests: [crossEdges[0]!.edgeDigest] },
  ];
  const input = { schema: "keep.partitioned-review-transaction/v1", candidateDigest: hex("f"), subjectManifestDigest, subjectDigests: subjects, parts, crossEdges, unknownInfluenceCount: 0, compositionCandidateDigest: hex("b") };
  const children = await Promise.all(parts.map((part, index) => external(part.candidateDigest!, subjectManifestDigest, part.rawEvidenceDigest!, part.reviewTransactionDigest!, String(index))));
  const composition = await external(input.compositionCandidateDigest, subjectManifestDigest, hex("c"), partitionedReviewTransactionDigest(input), "composition");
  return { subjects, input, children, composition, crossEdges };
}

test("partitioned composition requires exact primary coverage and reviewed cross-part overlap", async () => {
  const value = await fixture();
  const verified = verifyPartitionedReviewComposition(value.input, value.subjects, value.crossEdges, value.children, value.composition);
  assert.equal(verified.exactSubjectCoverage, true);
  assert.equal(verified.allChildResultsPresent, true);
  assert.equal(verified.compositionVerified, true);
  assert.equal(verified.unresolvedCrossPartCriticalCount, 0);
});

test("partition composition refuses omissions, duplicates, unknown influence, and structural review forgeries", async () => {
  const value = await fixture();
  const noOverlap = { ...value.input, parts: value.input.parts.slice(0, 2) };
  assert.throws(() => verifyPartitionedReviewComposition(noOverlap, value.subjects, value.crossEdges, value.children.slice(0, 2), value.composition), /overlap review/);
  assert.throws(() => verifyPartitionedReviewComposition({ ...value.input, unknownInfluenceCount: 1 }, value.subjects, value.crossEdges, value.children, value.composition), /unknown cross-part influence/);
  const duplicate = { ...value.input, parts: [{ ...value.input.parts[0], subjectDigests: [value.subjects[0], value.subjects[1], value.subjects[2]] }, ...value.input.parts.slice(1)] };
  assert.throws(() => verifyPartitionedReviewComposition(duplicate, value.subjects, value.crossEdges, value.children, value.composition), /exactly and uniquely cover/);
  assert.throws(() => verifyPartitionedReviewComposition(value.input, value.subjects, value.crossEdges, [{ ...value.children[0] }, ...value.children.slice(1)], value.composition), /not minted/);
  assert.throws(() => verifyPartitionedReviewComposition(value.input, value.subjects.slice(0, 2), value.crossEdges, value.children, value.composition), /trusted subject manifest/);
  assert.throws(() => verifyPartitionedReviewComposition(value.input, value.subjects, [{ ...value.crossEdges[0], relationDigest: hex("3") }], value.children, value.composition), /does not recompute|differ/);
});

test("verified adverse child evidence is preserved but cannot produce an authority-eligible transaction", async () => {
  const value = await fixture();
  const first = value.input.parts[0]!;
  const adverse = await external(first.candidateDigest!, value.input.subjectManifestDigest, first.rawEvidenceDigest!, first.reviewTransactionDigest!, "adverse", "revise", [hex("f")]);
  const verified = verifyPartitionedReviewComposition(value.input, value.subjects, value.crossEdges, [adverse, ...value.children.slice(1)], value.composition);
  assert.equal(verified.unresolvedCrossPartCriticalCount, 2, "one adverse verdict and one finding are both retained as unresolved");
});
