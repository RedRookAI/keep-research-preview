/** Provider-neutral verification of externally corroborated review evidence. */
import { createPublicKey, verify as verifySignature } from "node:crypto";
import { types } from "node:util";
import { canonicalize } from "../spine/event.js";
import type {
  AttemptId,
  BoundEvidenceIdentity,
  EvidenceIndependence,
  EvidenceVerdict,
  ExternalInvocationCorroboration,
  ExternalTechnicalReviewVerifierPort,
  Sha256Digest,
  StableOperationId,
  VerifiedExternalReview,
} from "./contracts.js";

const HEX64 = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SIGNED_CLASSES = new Set<ExternalInvocationCorroboration>(["operator-witnessed", "provider-signed", "independent-witness"]);
const MAX_REVIEW_LIFETIME_MS = 30 * 24 * 60 * 60 * 1_000;

export interface ExternalReviewTrustAnchorV1 {
  readonly keyId: string;
  readonly captureClass: Exclude<ExternalInvocationCorroboration, "none">;
  readonly provider: string;
  readonly familyId: string;
  readonly publicKeyPem: string;
  readonly validFromMs: number;
  readonly validUntilMs: number;
  readonly revokedAtMs: number | null;
}

export interface ExternalReviewTrustRootV1 {
  readonly schema: "keep.external-review-trust-root/v1";
  readonly anchors: readonly ExternalReviewTrustAnchorV1[];
}

interface SignedReviewFieldsV1 {
  readonly schema: "keep.signed-external-review-evidence/v1";
  readonly candidateDigest: string;
  readonly subjectManifestDigest: string;
  readonly policyDigest: string;
  readonly rawEvidenceDigest: string;
  readonly requestDigest: string;
  readonly transactionDigest: string;
  readonly campaignId: string;
  readonly operationId: string;
  readonly operationPredecessorId: string | null;
  readonly attemptId: string;
  readonly round: number;
  readonly independence: EvidenceIndependence;
  readonly verdict: EvidenceVerdict;
  readonly findingDigests: readonly string[];
  readonly limitations: readonly string[];
  readonly provider: string;
  readonly model: string;
  readonly familyId: string;
  readonly sessionId: string;
  readonly captureClass: Exclude<ExternalInvocationCorroboration, "none">;
  readonly observedAtMs: number;
  readonly expiresAtMs: number;
  readonly keyId: string;
}

interface SignedExternalReviewEvidenceV1 extends SignedReviewFieldsV1 { readonly signatureBase64: string }

function exactObject(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error(`${label} must be an inert plain object`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Object.keys(descriptors).sort();
  if (names.length !== keys.length || names.some((name, index) => name !== [...keys].sort()[index]) || Object.getOwnPropertySymbols(value).length !== 0) throw new Error(`${label} fields are not exact`);
  const out: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const name of names) {
    const descriptor = descriptors[name]!;
    if (!("value" in descriptor) || descriptor.enumerable !== true) throw new Error(`${label}.${name} is not inert data`);
    out[name] = descriptor.value;
  }
  return out;
}

function text(value: unknown, label: string, max = 256): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${label} is malformed`);
  return value;
}
function pem(value: unknown): string {
  if (typeof value !== "string" || value.length < 32 || value.length > 8192 || value.includes("\u0000")) throw new Error("publicKeyPem is malformed");
  return value;
}
function id(value: unknown, label: string): string { const result = text(value, label, 128); if (!ID.test(result)) throw new Error(`${label} is malformed`); return result; }
function digest(value: unknown, label: string): Sha256Digest { if (typeof value !== "string" || !HEX64.test(value)) throw new Error(`${label} is malformed`); return value as Sha256Digest; }
function integer(value: unknown, label: string): number { if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new Error(`${label} is malformed`); return value; }
function stringArray(value: unknown, label: string, maxRows: number, digestRows = false): readonly string[] {
  if (!Array.isArray(value) || types.isProxy(value) || value.length > maxRows) throw new Error(`${label} is malformed`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.getOwnPropertySymbols(value).length !== 0 || Object.keys(descriptors).some((key) => key !== "length" && !/^(0|[1-9][0-9]*)$/.test(key))) throw new Error(`${label} is malformed`);
  const result: string[] = [];
  for (let i = 0; i < value.length; i++) {
    const descriptor = descriptors[String(i)];
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) throw new Error(`${label} must be dense inert data`);
    result.push(digestRows ? digest(descriptor.value, `${label}[${i}]`) : text(descriptor.value, `${label}[${i}]`, 1024));
  }
  if (digestRows && (new Set(result).size !== result.length || result.some((row, index) => index > 0 && result[index - 1]! >= row))) throw new Error(`${label} must be unique and sorted`);
  return Object.freeze(result);
}

const EVIDENCE_KEYS = ["schema", "candidateDigest", "subjectManifestDigest", "policyDigest", "rawEvidenceDigest", "requestDigest", "transactionDigest", "campaignId", "operationId", "operationPredecessorId", "attemptId", "round", "independence", "verdict", "findingDigests", "limitations", "provider", "model", "familyId", "sessionId", "captureClass", "observedAtMs", "expiresAtMs", "keyId", "signatureBase64"] as const;

function captureEvidence(value: unknown): SignedExternalReviewEvidenceV1 {
  const row = exactObject(value, EVIDENCE_KEYS, "external review evidence");
  const independence = row.independence;
  if (independence !== "self-review" && independence !== "same-family" && independence !== "cross-family-external-technical") throw new Error("external review independence is unknown");
  const verdict = row.verdict;
  if (verdict !== "go" && verdict !== "revise" && verdict !== "refuse" && verdict !== "unavailable") throw new Error("external review verdict is unknown");
  const captureClass = row.captureClass;
  if (typeof captureClass !== "string" || !SIGNED_CLASSES.has(captureClass as ExternalInvocationCorroboration)) throw new Error("external review capture class is not externally corroborated");
  const observedAtMs = integer(row.observedAtMs, "observedAtMs");
  const expiresAtMs = integer(row.expiresAtMs, "expiresAtMs");
  if (expiresAtMs < observedAtMs || expiresAtMs - observedAtMs > MAX_REVIEW_LIFETIME_MS) throw new Error("external review chronology is invalid");
  const round = integer(row.round, "round"); if (round < 1 || round > 4) throw new Error("external review round is outside policy");
  const signatureBase64 = text(row.signatureBase64, "signatureBase64", 128);
  let signature: Buffer; try { signature = Buffer.from(signatureBase64, "base64"); } catch { throw new Error("external review signature is malformed"); }
  if (signature.length !== 64 || signature.toString("base64") !== signatureBase64) throw new Error("external review signature is malformed");
  return Object.freeze({
    schema: "keep.signed-external-review-evidence/v1",
    candidateDigest: digest(row.candidateDigest, "candidateDigest"), subjectManifestDigest: digest(row.subjectManifestDigest, "subjectManifestDigest"),
    policyDigest: digest(row.policyDigest, "policyDigest"), rawEvidenceDigest: digest(row.rawEvidenceDigest, "rawEvidenceDigest"), requestDigest: digest(row.requestDigest, "requestDigest"), transactionDigest: digest(row.transactionDigest, "transactionDigest"),
    campaignId: id(row.campaignId, "campaignId"), operationId: id(row.operationId, "operationId"), operationPredecessorId: row.operationPredecessorId === null ? null : id(row.operationPredecessorId, "operationPredecessorId"), attemptId: id(row.attemptId, "attemptId"), round,
    independence, verdict, findingDigests: stringArray(row.findingDigests, "findingDigests", 256, true), limitations: stringArray(row.limitations, "limitations", 256),
    provider: id(row.provider, "provider"), model: id(row.model, "model"), familyId: id(row.familyId, "familyId"), sessionId: id(row.sessionId, "sessionId"),
    captureClass: captureClass as Exclude<ExternalInvocationCorroboration, "none">, observedAtMs, expiresAtMs, keyId: id(row.keyId, "keyId"), signatureBase64,
  });
}

function signaturePreimage(row: SignedReviewFieldsV1): Buffer {
  return Buffer.from(`keep.signed-external-review-evidence/v1\0${canonicalize(row)}`, "utf8");
}

function captureTrustRoot(value: ExternalReviewTrustRootV1): readonly ExternalReviewTrustAnchorV1[] {
  const root = exactObject(value, ["schema", "anchors"], "external review trust root");
  if (root.schema !== "keep.external-review-trust-root/v1" || !Array.isArray(root.anchors) || types.isProxy(root.anchors) || root.anchors.length < 1 || root.anchors.length > 32) throw new Error("external review trust root is malformed");
  const arrayDescriptors = Object.getOwnPropertyDescriptors(root.anchors);
  if (Object.getOwnPropertySymbols(root.anchors).length !== 0 || Object.keys(arrayDescriptors).some((key) => key !== "length" && !/^(0|[1-9][0-9]*)$/.test(key))) throw new Error("external review trust anchors are malformed");
  const anchors: ExternalReviewTrustAnchorV1[] = [];
  for (let index = 0; index < root.anchors.length; index++) {
    const descriptor = arrayDescriptors[String(index)];
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) throw new Error("external review trust anchors must be dense inert data");
    const candidate = descriptor.value;
    const row = exactObject(candidate, ["keyId", "captureClass", "provider", "familyId", "publicKeyPem", "validFromMs", "validUntilMs", "revokedAtMs"], `trust anchor[${index}]`);
    const captureClass = row.captureClass;
    if (captureClass !== "operator-witnessed" && captureClass !== "provider-signed" && captureClass !== "independent-witness") throw new Error("trust anchor capture class is unknown");
    const validFromMs = integer(row.validFromMs, "validFromMs"), validUntilMs = integer(row.validUntilMs, "validUntilMs");
    const revokedAtMs = row.revokedAtMs === null ? null : integer(row.revokedAtMs, "revokedAtMs");
    if (validUntilMs < validFromMs) throw new Error("trust anchor chronology is invalid");
    anchors.push(Object.freeze({ keyId: id(row.keyId, "keyId"), captureClass, provider: id(row.provider, "provider"), familyId: id(row.familyId, "familyId"), publicKeyPem: pem(row.publicKeyPem), validFromMs, validUntilMs, revokedAtMs }));
  }
  if (new Set(anchors.map((row) => row.keyId)).size !== anchors.length) throw new Error("external review trust keys are duplicated");
  return Object.freeze(anchors);
}

/** Verifies bytes only. Deployment must source the trust root from storage outside builder write authority. */
export class Ed25519ExternalReviewCorroborationVerifier implements ExternalTechnicalReviewVerifierPort {
  readonly #anchors: readonly ExternalReviewTrustAnchorV1[];
  readonly #trustedNowMs: () => number;
  constructor(trustRoot: ExternalReviewTrustRootV1, trustedNowMs: () => number) { this.#anchors = captureTrustRoot(trustRoot); this.#trustedNowMs = trustedNowMs; }
  async verifyExternalReview(carrier: Uint8Array, expected: Readonly<Pick<BoundEvidenceIdentity, "candidateDigest" | "subjectManifestDigest" | "policyDigest">> & { readonly requestDigest: Sha256Digest; readonly builderFamilyId: string }): Promise<VerifiedExternalReview> {
    if (!(carrier instanceof Uint8Array) || types.isProxy(carrier) || carrier.byteLength === 0 || carrier.byteLength > 4 * 1024 * 1024) throw new Error("external review carrier is malformed");
    const carrierBytes = Buffer.from(carrier);
    const expectedRow = exactObject(expected, ["candidateDigest", "subjectManifestDigest", "policyDigest", "requestDigest", "builderFamilyId"], "expected external review identity");
    const expectedCandidate = digest(expectedRow.candidateDigest, "expected candidateDigest"), expectedSubject = digest(expectedRow.subjectManifestDigest, "expected subjectManifestDigest"), expectedPolicy = digest(expectedRow.policyDigest, "expected policyDigest");
    const expectedRequest = digest(expectedRow.requestDigest, "expected requestDigest");
    const builderFamilyId = id(expectedRow.builderFamilyId, "expected builderFamilyId");
    let parsed: unknown; try { parsed = JSON.parse(carrierBytes.toString("utf8")); } catch { throw new Error("external review carrier is not JSON"); }
    const row = captureEvidence(parsed);
    const canonicalCarrier = Buffer.from(`${canonicalize(row)}\n`, "utf8");
    if (!carrierBytes.equals(canonicalCarrier)) throw new Error("external review carrier is not canonical");
    if (row.candidateDigest !== expectedCandidate || row.subjectManifestDigest !== expectedSubject || row.policyDigest !== expectedPolicy || row.requestDigest !== expectedRequest) throw new Error("external review expected identity mismatch");
    const now = this.#trustedNowMs(); if (!Number.isSafeInteger(now) || now < row.observedAtMs || now > row.expiresAtMs) throw new Error("external review evidence is not currently valid");
    const anchor = this.#anchors.find((candidate) => candidate.keyId === row.keyId);
    if (!anchor || anchor.captureClass !== row.captureClass || anchor.provider !== row.provider || anchor.familyId !== row.familyId || row.observedAtMs < anchor.validFromMs || row.observedAtMs > anchor.validUntilMs || now > anchor.validUntilMs || (anchor.revokedAtMs !== null && (row.observedAtMs >= anchor.revokedAtMs || now >= anchor.revokedAtMs))) throw new Error("external review trust binding is invalid");
    const key = createPublicKey(anchor.publicKeyPem); if (key.asymmetricKeyType !== "ed25519") throw new Error("external review trust key is not Ed25519");
    const { signatureBase64, ...unsigned } = row;
    if (!verifySignature(null, signaturePreimage(unsigned), key, Buffer.from(signatureBase64, "base64"))) throw new Error("external review signature is invalid");
    const computedIndependence: EvidenceIndependence = row.familyId === builderFamilyId ? "same-family" : "cross-family-external-technical";
    if (row.independence !== computedIndependence) throw new Error("external review independence does not match verified family identities");
    const verified = Object.freeze({ kind: "verified-external-review" as const, candidateDigest: row.candidateDigest as Sha256Digest, subjectManifestDigest: row.subjectManifestDigest as Sha256Digest, policyDigest: row.policyDigest as Sha256Digest, rawEvidenceDigest: row.rawEvidenceDigest as Sha256Digest, requestDigest: row.requestDigest as Sha256Digest, transactionDigest: row.transactionDigest as Sha256Digest, campaignId: row.campaignId as StableOperationId, operationId: row.operationId as StableOperationId, operationPredecessorId: row.operationPredecessorId as StableOperationId | null, attemptId: row.attemptId as AttemptId, round: row.round, independence: row.independence, corroboration: row.captureClass, verdict: row.verdict, findingDigests: row.findingDigests as readonly Sha256Digest[], limitations: row.limitations });
    VERIFIED_EXTERNAL_REVIEWS.add(verified);
    return verified;
  }
}

export function externalReviewEvidenceSignaturePreimage(row: SignedReviewFieldsV1): Buffer { return signaturePreimage(row); }
const VERIFIED_EXTERNAL_REVIEWS = new WeakSet<object>();
/** Runtime provenance check: structural lookalikes cannot enter the review authority path. */
export function isVerifierMintedExternalReview(value: unknown): value is VerifiedExternalReview {
  return value !== null && typeof value === "object" && VERIFIED_EXTERNAL_REVIEWS.has(value);
}
