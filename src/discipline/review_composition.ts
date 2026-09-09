import { createHash } from "node:crypto";
import { types } from "node:util";
import { canonicalize } from "../spine/event.js";
import type { Sha256Digest, VerifiedExternalReview } from "./contracts.js";
import { isVerifierMintedExternalReview } from "./external_review_corroboration.js";

export interface ReviewTransactionEvidence {
  readonly transactionDigest: Sha256Digest;
  readonly kind: "monolithic" | "partitioned-composed";
  readonly exactSubjectCoverage: boolean;
  readonly allChildResultsPresent: boolean;
  readonly compositionVerified: boolean;
  readonly unresolvedCrossPartCriticalCount: number;
}

export type VerifiedReviewTransactionEvidence = ReviewTransactionEvidence & { readonly __verifiedReviewTransactionEvidence: unique symbol };
const VERIFIED_TRANSACTIONS = new WeakSet<object>();
const DIGEST = /^[0-9a-f]{64}$/u;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const sha256 = (bytes: Uint8Array): Sha256Digest => createHash("sha256").update(bytes).digest("hex") as Sha256Digest;

function exactRecord(input: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (input === null || typeof input !== "object" || Array.isArray(input) || types.isProxy(input) || Object.getPrototypeOf(input) !== Object.prototype || Object.getOwnPropertySymbols(input).length !== 0) throw new Error(`${label} must be an inert plain object`);
  const descriptors = Object.getOwnPropertyDescriptors(input) as Record<string, PropertyDescriptor>;
  if (Object.keys(descriptors).sort().join("\0") !== [...keys].sort().join("\0")) throw new Error(`${label} fields are not exact`);
  const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true || !("value" in descriptor)) throw new Error(`${label}.${key} is not inert data`);
    result[key] = descriptor.value;
  }
  return result;
}

function denseArray(input: unknown, maximum: number, label: string): readonly unknown[] {
  if (!Array.isArray(input) || types.isProxy(input) || Object.getOwnPropertySymbols(input).length !== 0) throw new Error(`${label} is malformed`);
  const descriptors = Object.getOwnPropertyDescriptors(input) as Record<string, PropertyDescriptor>;
  const length = descriptors.length?.value;
  if (!Number.isSafeInteger(length) || length < 0 || length > maximum) throw new Error(`${label} is malformed`);
  const expected = new Set(["length", ...Array.from({ length }, (_, index) => String(index))]);
  if (Object.keys(descriptors).length !== expected.size || Object.keys(descriptors).some((key) => !expected.has(key))) throw new Error(`${label} is malformed`);
  const result: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true || !("value" in descriptor)) throw new Error(`${label} is not inert data`);
    result.push(descriptor.value);
  }
  return result;
}

function digest(value: unknown, label: string): Sha256Digest {
  if (typeof value !== "string" || !DIGEST.test(value)) throw new Error(`${label} is malformed`);
  return value as Sha256Digest;
}
function id(value: unknown, label: string): string {
  if (typeof value !== "string" || !ID.test(value)) throw new Error(`${label} is malformed`);
  return value;
}
function digestList(value: unknown, label: string, allowEmpty = false): readonly Sha256Digest[] {
  const rows = denseArray(value, 4096, label).map((row, index) => digest(row, `${label}[${index}]`));
  if ((!allowEmpty && rows.length === 0) || new Set(rows).size !== rows.length || rows.some((row, index) => index > 0 && rows[index - 1]! >= row)) throw new Error(`${label} must be nonempty, unique, and sorted`);
  return Object.freeze(rows);
}

function requireCorroborated(review: VerifiedExternalReview, label: string): void {
  if (!isVerifierMintedExternalReview(review)) throw new Error(`${label} was not minted by the external verifier`);
  if (review.independence !== "cross-family-external-technical" || (review.corroboration !== "provider-signed" && review.corroboration !== "independent-witness")) throw new Error(`${label} lacks promotion-grade independent corroboration`);
}

interface CapturedPart {
  readonly partId: string;
  readonly kind: "primary" | "overlap";
  readonly candidateDigest: Sha256Digest;
  readonly subjectDigests: readonly Sha256Digest[];
  readonly rawEvidenceDigest: Sha256Digest;
  readonly reviewTransactionDigest: Sha256Digest;
  readonly coveredEdgeDigests: readonly Sha256Digest[];
}

function capturePart(input: unknown, index: number): CapturedPart {
  const row = exactRecord(input, ["partId", "kind", "candidateDigest", "subjectDigests", "rawEvidenceDigest", "reviewTransactionDigest", "coveredEdgeDigests"], `part[${index}]`);
  if (row.kind !== "primary" && row.kind !== "overlap") throw new Error(`part[${index}].kind is unknown`);
  const coveredEdgeDigests = digestList(row.coveredEdgeDigests, `part[${index}].coveredEdgeDigests`, row.kind === "primary");
  if ((row.kind === "primary") !== (coveredEdgeDigests.length === 0)) throw new Error(`part[${index}] edge coverage does not match its kind`);
  return Object.freeze({ partId: id(row.partId, `part[${index}].partId`), kind: row.kind, candidateDigest: digest(row.candidateDigest, `part[${index}].candidateDigest`), subjectDigests: digestList(row.subjectDigests, `part[${index}].subjectDigests`), rawEvidenceDigest: digest(row.rawEvidenceDigest, `part[${index}].rawEvidenceDigest`), reviewTransactionDigest: digest(row.reviewTransactionDigest, `part[${index}].reviewTransactionDigest`), coveredEdgeDigests });
}

interface CapturedEdge { readonly edgeDigest: Sha256Digest; readonly endpointDigests: readonly [Sha256Digest, Sha256Digest]; readonly relationDigest: Sha256Digest }
export function reviewCrossEdgeDigest(endpointDigests: readonly [Sha256Digest, Sha256Digest], relationDigest: Sha256Digest): Sha256Digest {
  return sha256(Buffer.from(`keep.review-cross-edge/v1\0${canonicalize({ endpointDigests, relationDigest })}`, "utf8"));
}
function captureEdge(input: unknown, index: number): CapturedEdge {
  const row = exactRecord(input, ["edgeDigest", "endpointDigests", "relationDigest"], `crossEdge[${index}]`);
  const endpoints = digestList(row.endpointDigests, `crossEdge[${index}].endpointDigests`);
  if (endpoints.length !== 2) throw new Error(`crossEdge[${index}] must have exactly two endpoints`);
  const relationDigest = digest(row.relationDigest, `crossEdge[${index}].relationDigest`);
  const endpointDigests = Object.freeze([endpoints[0]!, endpoints[1]!] as [Sha256Digest, Sha256Digest]);
  const edgeDigest = reviewCrossEdgeDigest(endpointDigests, relationDigest);
  if (row.edgeDigest !== edgeDigest) throw new Error(`crossEdge[${index}].edgeDigest does not recompute`);
  return Object.freeze({ edgeDigest, endpointDigests, relationDigest });
}

export function partitionedReviewTransactionDigest(input: unknown): Sha256Digest {
  return sha256(Buffer.from(`keep.partitioned-review-transaction/v1\0${canonicalize(input)}`, "utf8"));
}

export function monolithicReviewTransactionDigest(input: unknown): Sha256Digest {
  const row = exactRecord(input, ["schema", "candidateDigest", "subjectManifestDigest"], "monolithic review transaction");
  if (row.schema !== "keep.monolithic-review-transaction/v1") throw new Error("monolithic review transaction schema is unknown");
  const normalized = Object.freeze({ schema: "keep.monolithic-review-transaction/v1", candidateDigest: digest(row.candidateDigest, "candidateDigest"), subjectManifestDigest: digest(row.subjectManifestDigest, "subjectManifestDigest") });
  return sha256(Buffer.from(`keep.monolithic-review-transaction/v1\0${canonicalize(normalized)}`, "utf8"));
}

export function verifyMonolithicReviewTransaction(input: unknown, review: VerifiedExternalReview): VerifiedReviewTransactionEvidence {
  const row = exactRecord(input, ["schema", "candidateDigest", "subjectManifestDigest"], "monolithic review transaction");
  if (row.schema !== "keep.monolithic-review-transaction/v1") throw new Error("monolithic review transaction schema is unknown");
  const normalized = Object.freeze({ schema: "keep.monolithic-review-transaction/v1", candidateDigest: digest(row.candidateDigest, "candidateDigest"), subjectManifestDigest: digest(row.subjectManifestDigest, "subjectManifestDigest") });
  const transactionDigest = monolithicReviewTransactionDigest(normalized);
  requireCorroborated(review, "monolithic review");
  if (review.candidateDigest !== normalized.candidateDigest || review.subjectManifestDigest !== normalized.subjectManifestDigest || review.transactionDigest !== transactionDigest) throw new Error("monolithic review does not bind the exact transaction ancestor");
  const unresolved = review.findingDigests.length + (review.verdict === "go" ? 0 : 1);
  const result = Object.freeze({ transactionDigest, kind: "monolithic" as const, exactSubjectCoverage: true as const, allChildResultsPresent: true as const, compositionVerified: true as const, unresolvedCrossPartCriticalCount: unresolved }) as VerifiedReviewTransactionEvidence;
  VERIFIED_TRANSACTIONS.add(result);
  return result;
}

/**
 * Mints composition authority only from verifier-owned child results and a
 * mechanically complete subject/edge cover. Summaries alone never satisfy it:
 * every cross-part edge requires a finding-free overlap review over both exact
 * endpoint subjects, and unknown influence is an unconditional hold.
 */
export function verifyPartitionedReviewComposition(
  input: unknown,
  expectedSubjectDigestsInput: unknown,
  expectedCrossEdgesInput: unknown,
  childReviewsInput: unknown,
  compositionReview: VerifiedExternalReview,
): VerifiedReviewTransactionEvidence {
  const row = exactRecord(input, ["schema", "candidateDigest", "subjectManifestDigest", "subjectDigests", "parts", "crossEdges", "unknownInfluenceCount", "compositionCandidateDigest"], "partitioned review transaction");
  if (row.schema !== "keep.partitioned-review-transaction/v1") throw new Error("partitioned review transaction schema is unknown");
  const expectedSubjects = digestList(expectedSubjectDigestsInput, "expectedSubjectDigests");
  const subjects = digestList(row.subjectDigests, "subjectDigests");
  if (canonicalize(subjects) !== canonicalize(expectedSubjects)) throw new Error("partitioned review subject coverage differs from the trusted subject manifest");
  if (row.unknownInfluenceCount !== 0) throw new Error("partitioned review has unknown cross-part influence");
  const partInputs = denseArray(row.parts, 4096, "parts");
  if (partInputs.length === 0) throw new Error("partitioned review has no parts");
  const parts = partInputs.map(capturePart);
  if (new Set(parts.map((part) => part.partId)).size !== parts.length) throw new Error("partition IDs are duplicated");
  const primary = parts.filter((part) => part.kind === "primary");
  const primarySubjects = primary.flatMap((part) => [...part.subjectDigests]).sort();
  if (canonicalize(primarySubjects) !== canonicalize(subjects)) throw new Error("primary partitions do not exactly and uniquely cover the subject");
  const edgeInputs = denseArray(row.crossEdges, 65536, "crossEdges");
  const edges = edgeInputs.map(captureEdge);
  if (new Set(edges.map((edge) => edge.edgeDigest)).size !== edges.length || edges.some((edge, index) => index > 0 && edges[index - 1]!.edgeDigest >= edge.edgeDigest)) throw new Error("cross edges must be unique and sorted");
  const expectedEdges = denseArray(expectedCrossEdgesInput, 65536, "expectedCrossEdges").map(captureEdge);
  if (canonicalize(edges) !== canonicalize(expectedEdges)) throw new Error("cross edges differ from independently discovered influence evidence");
  const subjectSet = new Set(subjects);
  const owner = new Map<Sha256Digest, string>();
  for (const part of primary) for (const subject of part.subjectDigests) owner.set(subject, part.partId);
  for (const edge of edges) {
    const [left, right] = edge.endpointDigests;
    if (!subjectSet.has(left) || !subjectSet.has(right)) throw new Error("cross edge names a subject outside the manifest");
    if (owner.get(left) === owner.get(right)) continue;
    const overlap = parts.filter((part) => part.kind === "overlap" && canonicalize(part.subjectDigests) === canonicalize(edge.endpointDigests) && part.coveredEdgeDigests.includes(edge.edgeDigest));
    if (overlap.length !== 1) throw new Error("each cross-part edge requires exactly one exact-endpoint overlap review");
  }
  const crossPartEdgeDigests = new Set(edges.filter((edge) => owner.get(edge.endpointDigests[0]) !== owner.get(edge.endpointDigests[1])).map((edge) => edge.edgeDigest));
  for (const part of parts.filter((candidate) => candidate.kind === "overlap")) if (part.coveredEdgeDigests.some((edgeDigest) => !crossPartEdgeDigests.has(edgeDigest))) throw new Error("overlap review claims an absent or intra-part edge");
  const reviews = denseArray(childReviewsInput, 4096, "childReviews");
  if (reviews.length !== parts.length) throw new Error("child review count does not match the part manifest");
  const unused = new Set(parts.map((part) => part.partId));
  for (const [index, value] of reviews.entries()) {
    if (value === null || typeof value !== "object") throw new Error(`childReviews[${index}] is malformed`);
    const review = value as VerifiedExternalReview;
    requireCorroborated(review, `childReviews[${index}]`);
    const part = parts.find((candidate) => candidate.rawEvidenceDigest === review.rawEvidenceDigest);
    if (!part || !unused.delete(part.partId) || review.candidateDigest !== part.candidateDigest || review.transactionDigest !== part.reviewTransactionDigest) throw new Error(`childReviews[${index}] does not bind one unique exact part`);
  }
  if (unused.size !== 0) throw new Error("one or more partition results are absent");
  requireCorroborated(compositionReview, "compositionReview");
  const normalized = Object.freeze({ schema: "keep.partitioned-review-transaction/v1", candidateDigest: digest(row.candidateDigest, "candidateDigest"), subjectManifestDigest: digest(row.subjectManifestDigest, "subjectManifestDigest"), subjectDigests: subjects, parts: Object.freeze(parts), crossEdges: Object.freeze(edges), unknownInfluenceCount: 0, compositionCandidateDigest: digest(row.compositionCandidateDigest, "compositionCandidateDigest") });
  const transactionDigest = partitionedReviewTransactionDigest(normalized);
  if (compositionReview.candidateDigest !== normalized.compositionCandidateDigest || compositionReview.subjectManifestDigest !== normalized.subjectManifestDigest || compositionReview.transactionDigest !== transactionDigest) throw new Error("composition result does not bind the exact transaction ancestor");
  const unresolved = [...(reviews as readonly VerifiedExternalReview[]), compositionReview].reduce((count, review) => count + review.findingDigests.length + (review.verdict === "go" ? 0 : 1), 0);
  const result = Object.freeze({ transactionDigest, kind: "partitioned-composed" as const, exactSubjectCoverage: true as const, allChildResultsPresent: true as const, compositionVerified: true as const, unresolvedCrossPartCriticalCount: unresolved }) as VerifiedReviewTransactionEvidence;
  VERIFIED_TRANSACTIONS.add(result);
  return result;
}

export function isVerifiedReviewTransactionEvidence(value: unknown): value is VerifiedReviewTransactionEvidence {
  return value !== null && typeof value === "object" && VERIFIED_TRANSACTIONS.has(value);
}
