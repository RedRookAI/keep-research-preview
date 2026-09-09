/** Provider-neutral ports for Keep's discipline and assurance kernel. */

export type Sha256Digest = string & { readonly __sha256Digest: unique symbol };
export type StableOperationId = string & { readonly __stableOperationId: unique symbol };
export type AttemptId = string & { readonly __attemptId: unique symbol };

export type EvidenceVerdict = "go" | "revise" | "refuse" | "unavailable";
export type EvidenceIndependence = "self-review" | "same-family" | "cross-family-external-technical";
export type ExternalInvocationCorroboration = "none" | "operator-witnessed" | "provider-signed" | "independent-witness";

export interface BoundEvidenceIdentity {
  readonly candidateDigest: Sha256Digest;
  readonly subjectManifestDigest: Sha256Digest;
  readonly policyDigest: Sha256Digest;
  readonly rawEvidenceDigest: Sha256Digest;
}

export interface VerifiedResearchEvidence extends BoundEvidenceIdentity {
  readonly kind: "verified-research-evidence";
  readonly verdict: EvidenceVerdict;
  readonly manifestDigest: Sha256Digest;
  readonly limitations: readonly string[];
}

export interface ResearchEvidenceVerifierPort {
  verifyResearchEvidence(carrier: Uint8Array, expectedCandidate: Sha256Digest): Promise<VerifiedResearchEvidence>;
}

export interface VerifiedExternalReview extends BoundEvidenceIdentity {
  readonly kind: "verified-external-review";
  readonly requestDigest: Sha256Digest;
  readonly transactionDigest: Sha256Digest;
  readonly campaignId: StableOperationId;
  readonly operationId: StableOperationId;
  readonly operationPredecessorId: StableOperationId | null;
  readonly attemptId: AttemptId;
  readonly round: number;
  readonly independence: EvidenceIndependence;
  /** Structural capture and external corroboration are deliberately separate claims. */
  readonly corroboration: ExternalInvocationCorroboration;
  readonly verdict: EvidenceVerdict;
  readonly findingDigests: readonly Sha256Digest[];
  readonly limitations: readonly string[];
}

export interface ExternalTechnicalReviewVerifierPort {
  verifyExternalReview(carrier: Uint8Array, expected: Readonly<Pick<BoundEvidenceIdentity, "candidateDigest" | "subjectManifestDigest" | "policyDigest">> & { readonly requestDigest: Sha256Digest; readonly builderFamilyId: string }): Promise<VerifiedExternalReview>;
}

export interface DisciplineHistoryHead {
  readonly sequence: number;
  readonly eventDigest: Sha256Digest;
}

export interface DisciplineEventPublication {
  readonly expectedHead: DisciplineHistoryHead | null;
  readonly eventCarrier: Uint8Array;
  readonly eventDigest: Sha256Digest;
}

/** Implementations must provide write-once event publication and fenced compare-and-swap HEAD. */
export interface DurableDisciplineStorePort {
  readHead(): Promise<DisciplineHistoryHead | null>;
  readEvent(digest: Sha256Digest): Promise<Uint8Array | null>;
  publishEventAndSwapHead(publication: DisciplineEventPublication): Promise<"published" | "head-moved" | "refused">;
}

export interface VerifiedArtifactSet {
  readonly subjectCommit: string;
  readonly sourceDigest: Sha256Digest;
  readonly integratedDigest: Sha256Digest;
  readonly completeDigest: Sha256Digest;
  readonly verificationEvidenceDigest: Sha256Digest;
}

export interface ArtifactVerifierPort {
  verifyArtifactSet(carrier: Uint8Array, expectedCommit: string): Promise<VerifiedArtifactSet>;
}

export interface TrackerProjection {
  readonly objectiveId: string;
  readonly lifecycle: string;
  readonly canonicalStateDigest: Sha256Digest;
  readonly summary: string;
}

/** A tracker is a projection sink. It never returns or mutates canonical authority. */
export interface TrackerProjectionPort {
  publishProjection(projection: TrackerProjection): Promise<{ readonly receiptDigest: Sha256Digest }>;
}
