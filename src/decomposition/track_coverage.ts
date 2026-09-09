import { createHash } from "node:crypto";

import type { AdmittedTicketAuthorityV1 } from "./ticket_contract.js";

export type TrackCoverageDenial =
  | "MALFORMED_OR_UNKNOWN_FIELD"
  | "PREREQUISITE_AUTHORITY_INVALID"
  | "TRACK_COVERAGE_MISSING"
  | "TRACK_RECEIPT_SUBSTITUTED"
  | "ENTERPRISE_CUSTODY_MISSING"
  | "N1_ENTERPRISE_CEREMONY_FORBIDDEN"
  | "UNSUPPORTED_TRACK_EQUIVALENCE"
  | "STALE_DERIVATION";

export type TrackCoverageReason =
  | "MISSING_N1_DIRECT"
  | "MISSING_ENTERPRISE_DIRECT"
  | "APPROVED_INVENTORY_MISMATCH"
  | "SCOPE_INVALID"
  | "ALLOCATION_SET_MISMATCH"
  | "AUTHORITY_MISSING"
  | "AUTHORITY_BODY_DIGEST_INVALID"
  | "SCOPED_CASE_MISSING";

export type AllocationModeV1 = "paired" | "shared" | "n1" | "enterprise";
export type TrackV1 = "n1" | "enterprise";

export interface TrackWitnessV1 {
  readonly target_track: TrackV1;
  readonly kind: "DIRECT" | "EXCLUSION";
  readonly ceremony: "LOCAL_OWNER" | "ORGANIZATION";
  readonly authority_digest: string;
  readonly case_id: string;
  readonly witness_digest: string;
}

export interface TrackEquivalenceV1 {
  readonly mechanism_digest: string;
  readonly evidence_digest: string;
  readonly n1_witness_digest: string;
  readonly enterprise_witness_digest: string;
  readonly equivalence_digest: string;
}

export interface TrackAllocationV1 {
  readonly logical_ticket_id: string;
  readonly mode: AllocationModeV1;
  readonly mechanism_digest: string;
  readonly n1_witness: TrackWitnessV1;
  readonly enterprise_witness: TrackWitnessV1;
  readonly equivalence: TrackEquivalenceV1 | null;
}

export interface TrackCoverageCandidateV1 {
  readonly schema_version: 1;
  readonly allocation_id: string;
  readonly generation: string;
  readonly candidate_digest: string;
  readonly scope_projection_digest: string;
  readonly allocations: readonly TrackAllocationV1[];
}

export interface TrackAllocationScopeEntryV1 {
  readonly logical_ticket_id: string;
  readonly mode: AllocationModeV1;
  readonly n1_body_digest: string | null;
  readonly enterprise_body_digest: string | null;
  readonly n1_case_id: string;
  readonly enterprise_case_id: string;
  readonly counterpart_ticket_id: string | null;
  readonly shared_mechanism_digest: string | null;
  readonly shared_evidence_digest: string | null;
}

export interface TrustedTrackAllocationScopeV1 {
  readonly schema_version: 1;
  readonly status: "TRACK_ALLOCATION_SCOPE_ADMITTED";
  readonly generation: string;
  readonly approved_ticket_inventory_digest: string;
  readonly logical_allocation_projection_digest: string;
  readonly entries: readonly TrackAllocationScopeEntryV1[];
}

export interface TrackCoveragePrerequisiteV1 {
  readonly closure_bytes: string;
  readonly closure_digest: string;
  readonly product_commit: string;
  readonly closure_profile: "FULL_KEEP_EXACT_COMMIT_V1";
}

export interface AdmittedTrackCoverageAuthorityV1 {
  readonly status: "TRACK_COVERAGE_ADMITTED";
  readonly allocation_id: string;
  readonly generation: string;
  readonly candidate_digest: string;
  readonly scope_projection_digest: string;
  readonly prerequisite_closure_digest: string;
  readonly approved_ticket_inventory_digest: string;
  readonly authority_digests: readonly string[];
  readonly witness_digests: readonly string[];
  readonly candidate: TrackCoverageCandidateV1;
}

export type TrackCoverageResult =
  | { readonly admitted: true; readonly authority: AdmittedTrackCoverageAuthorityV1; readonly owner_stop: null }
  | { readonly admitted: false; readonly denial: TrackCoverageDenial; readonly reason: TrackCoverageReason | null; readonly owner_stop: "UNRESOLVED_TRACK_EQUIVALENCE" | null };

const EXPECTED_T002_CLOSURE = "faa4b817a6769d8de78dca233b2d090472d8cc05d08bde07ea9dccd22cfa30e5";
const EXPECTED_T002_PRODUCT = "79676b4f9134a3b12af6af734eed3c48f23ffc22";
const EXPECTED_APPROVED_TICKET_INVENTORY = "f0b8b60c7b497b6422fc43afeb310d18ea3d28f3decfe666d44deb54963399db";
const HEX = /^[a-f0-9]{64}$/u;
const GENERATION = /^sha256:[a-f0-9]{64}$/u;
const CANDIDATE_KEYS = ["allocation_id", "allocations", "candidate_digest", "generation", "schema_version", "scope_projection_digest"];
const ALLOCATION_KEYS = ["enterprise_witness", "equivalence", "logical_ticket_id", "mechanism_digest", "mode", "n1_witness"];
const WITNESS_KEYS = ["authority_digest", "case_id", "ceremony", "kind", "target_track", "witness_digest"];
const EQUIVALENCE_KEYS = ["enterprise_witness_digest", "equivalence_digest", "evidence_digest", "mechanism_digest", "n1_witness_digest"];
const SCOPE_KEYS = ["approved_ticket_inventory_digest", "entries", "generation", "logical_allocation_projection_digest", "schema_version", "status"];
const SCOPE_ENTRY_KEYS = ["counterpart_ticket_id", "enterprise_body_digest", "enterprise_case_id", "logical_ticket_id", "mode", "n1_body_digest", "n1_case_id", "shared_evidence_digest", "shared_mechanism_digest"];
const AUTHORITY_KEYS = ["body", "status", "ticket_body_digest", "ticket_id", "track"];
const PREREQUISITE_KEYS = ["closure_bytes", "closure_digest", "closure_profile", "product_commit"];

const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const exact = (value: Record<string, unknown>, keys: readonly string[]) => {
  const actual = Object.keys(value).sort(), expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
};
const nonempty = (value: unknown): value is string => typeof value === "string" && value.trim().length > 0;
const nullableHex = (value: unknown) => value === null || (typeof value === "string" && HEX.test(value));
const canonical = (value: unknown): string => Array.isArray(value)
  ? `[${value.map(canonical).join(",")}]`
  : object(value)
    ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`
    : JSON.stringify(value);
const sha = (value: string) => createHash("sha256").update(value).digest("hex");
const digestWithout = (value: Record<string, unknown>, field: string) => {
  const projection = { ...value }; delete projection[field]; return sha(canonical(projection));
};
const clone = <T>(value: T): T => structuredClone(value);
const freeze = <T>(value: T): T => { if (value && typeof value === "object") { Object.freeze(value); for (const child of Object.values(value as Record<string, unknown>)) freeze(child); } return value; };
const deny = (denial: TrackCoverageDenial, reason: TrackCoverageReason | null = null, owner_stop: "UNRESOLVED_TRACK_EQUIVALENCE" | null = null): TrackCoverageResult => ({ admitted: false, denial, reason, owner_stop });

export const trackWitnessDigest = (witness: Omit<TrackWitnessV1, "witness_digest"> | TrackWitnessV1) => digestWithout(witness as unknown as Record<string, unknown>, "witness_digest");
export const trackEquivalenceDigest = (equivalence: Omit<TrackEquivalenceV1, "equivalence_digest"> | TrackEquivalenceV1) => digestWithout(equivalence as unknown as Record<string, unknown>, "equivalence_digest");
export const trackCoverageCandidateDigest = (candidate: Omit<TrackCoverageCandidateV1, "candidate_digest"> | TrackCoverageCandidateV1) => digestWithout(candidate as unknown as Record<string, unknown>, "candidate_digest");
export const trackAllocationScopeDigest = (entries: readonly TrackAllocationScopeEntryV1[]) => sha(canonical([...entries].sort((a, b) => a.logical_ticket_id.localeCompare(b.logical_ticket_id))));
export const admittedTicketAuthorityDigest = (authority: AdmittedTicketAuthorityV1) => sha(canonical(authority));
export const executableTicketBodyDigest = (body: AdmittedTicketAuthorityV1["body"]) => sha(canonical(body));

function recognizableWitness(value: unknown): value is TrackWitnessV1 {
  return object(value) && exact(value, WITNESS_KEYS) && ["n1", "enterprise"].includes(value.target_track as string) && ["DIRECT", "EXCLUSION"].includes(value.kind as string) && ["LOCAL_OWNER", "ORGANIZATION"].includes(value.ceremony as string) && nonempty(value.case_id) && typeof value.authority_digest === "string" && HEX.test(value.authority_digest) && typeof value.witness_digest === "string" && HEX.test(value.witness_digest);
}

function recognizableAuthority(value: unknown): value is AdmittedTicketAuthorityV1 {
  return object(value) && exact(value, AUTHORITY_KEYS) && value.status === "EXECUTABLE_TICKET_ADMITTED" && nonempty(value.ticket_id) && typeof value.ticket_body_digest === "string" && HEX.test(value.ticket_body_digest) && ["n1", "enterprise"].includes(value.track as string) && object(value.body) && Array.isArray(value.body.cases) && value.body.cases.every((item) => object(item) && nonempty(item.id)) && object(value.body.authority);
}

function recognizableCandidate(value: unknown): value is TrackCoverageCandidateV1 {
  if (!object(value) || !exact(value, CANDIDATE_KEYS) || value.schema_version !== 1 || !nonempty(value.allocation_id) || typeof value.generation !== "string" || !GENERATION.test(value.generation) || typeof value.candidate_digest !== "string" || !HEX.test(value.candidate_digest) || typeof value.scope_projection_digest !== "string" || !HEX.test(value.scope_projection_digest) || !Array.isArray(value.allocations) || value.allocations.length === 0) return false;
  const ids = new Set<string>();
  return value.allocations.every((item) => {
    if (!object(item) || !exact(item, ALLOCATION_KEYS) || !nonempty(item.logical_ticket_id) || ids.has(item.logical_ticket_id as string) || !["paired", "shared", "n1", "enterprise"].includes(item.mode as string) || typeof item.mechanism_digest !== "string" || !HEX.test(item.mechanism_digest) || !recognizableWitness(item.n1_witness) || !recognizableWitness(item.enterprise_witness) || !(item.equivalence === null || (object(item.equivalence) && exact(item.equivalence, EQUIVALENCE_KEYS)))) return false;
    ids.add(item.logical_ticket_id as string); return true;
  });
}

function recognizableScope(value: unknown): value is TrustedTrackAllocationScopeV1 {
  if (!object(value) || !exact(value, SCOPE_KEYS) || value.schema_version !== 1 || value.status !== "TRACK_ALLOCATION_SCOPE_ADMITTED" || typeof value.generation !== "string" || !GENERATION.test(value.generation) || typeof value.approved_ticket_inventory_digest !== "string" || !HEX.test(value.approved_ticket_inventory_digest) || typeof value.logical_allocation_projection_digest !== "string" || !HEX.test(value.logical_allocation_projection_digest) || !Array.isArray(value.entries) || value.entries.length === 0) return false;
  const ids = new Set<string>();
  return value.entries.every((entry) => {
    if (!object(entry) || !exact(entry, SCOPE_ENTRY_KEYS) || !nonempty(entry.logical_ticket_id) || ids.has(entry.logical_ticket_id as string) || !["paired", "shared", "n1", "enterprise"].includes(entry.mode as string) || !nullableHex(entry.n1_body_digest) || !nullableHex(entry.enterprise_body_digest) || !nonempty(entry.n1_case_id) || !nonempty(entry.enterprise_case_id) || !(entry.counterpart_ticket_id === null || nonempty(entry.counterpart_ticket_id)) || !nullableHex(entry.shared_mechanism_digest) || !nullableHex(entry.shared_evidence_digest)) return false;
    ids.add(entry.logical_ticket_id as string); return true;
  });
}

function validPrerequisite(value: unknown): boolean {
  if (!object(value) || !exact(value, PREREQUISITE_KEYS) || typeof value.closure_bytes !== "string" || value.closure_digest !== EXPECTED_T002_CLOSURE || sha(value.closure_bytes) !== EXPECTED_T002_CLOSURE || value.product_commit !== EXPECTED_T002_PRODUCT || value.closure_profile !== "FULL_KEEP_EXACT_COMMIT_V1") return false;
  try { const receipt = JSON.parse(value.closure_bytes) as unknown; return object(receipt) && receipt.status === "COMPLETE" && receipt.ticket_id === "PG-04-T002" && receipt.product_commit === EXPECTED_T002_PRODUCT && receipt.closure_profile === "FULL_KEEP_EXACT_COMMIT_V1"; } catch { return false; }
}

const bodyAuthority = (authority: AdmittedTicketAuthorityV1) => authority.body.authority as unknown;
const ownerRecognizable = (value: unknown): value is Record<string, unknown> => object(value) && value.kind === "owner";
const organizationRecognizable = (value: unknown): value is Record<string, unknown> => object(value) && value.kind === "organization";
const validOwner = (value: Record<string, unknown>) => exact(value, ["custody_id", "kind", "owner_id"]) && nonempty(value.owner_id) && nonempty(value.custody_id);
const validOrganization = (value: Record<string, unknown>) => exact(value, ["actor_id", "custody_evidence_digest", "isolation_evidence_digest", "kind", "organization_id", "role_id", "separation_policy_id"]) && [value.actor_id, value.organization_id, value.role_id, value.separation_policy_id].every(nonempty) && typeof value.custody_evidence_digest === "string" && HEX.test(value.custody_evidence_digest) && typeof value.isolation_evidence_digest === "string" && HEX.test(value.isolation_evidence_digest);
const hasCase = (authority: AdmittedTicketAuthorityV1, caseId: string) => authority.body.cases.filter((item) => item.id === caseId).length === 1;

export function admitTrackCoverage(candidate: unknown, t002_authorities: unknown, trusted_scope: unknown, t002_prerequisite: unknown): TrackCoverageResult {
  try {
    return admitTrackCoverageSnapshot(structuredClone(candidate), structuredClone(t002_authorities), structuredClone(trusted_scope), structuredClone(t002_prerequisite));
  } catch {
    return deny("MALFORMED_OR_UNKNOWN_FIELD");
  }
}

function admitTrackCoverageSnapshot(candidate: unknown, t002_authorities: unknown, trusted_scope: unknown, t002_prerequisite: unknown): TrackCoverageResult {
  if (!recognizableCandidate(candidate) || !recognizableScope(trusted_scope) || !Array.isArray(t002_authorities) || t002_authorities.length === 0 || !t002_authorities.every(recognizableAuthority)) return deny("MALFORMED_OR_UNKNOWN_FIELD");
  if (!validPrerequisite(t002_prerequisite)) return deny("PREREQUISITE_AUTHORITY_INVALID");
  if (trusted_scope.approved_ticket_inventory_digest !== EXPECTED_APPROVED_TICKET_INVENTORY) return deny("TRACK_COVERAGE_MISSING", "APPROVED_INVENTORY_MISMATCH");
  if (trusted_scope.logical_allocation_projection_digest !== trackAllocationScopeDigest(trusted_scope.entries) || candidate.generation !== trusted_scope.generation || candidate.scope_projection_digest !== trusted_scope.logical_allocation_projection_digest) return deny("TRACK_COVERAGE_MISSING", "SCOPE_INVALID");
  const scopes = new Map(trusted_scope.entries.map((entry) => [entry.logical_ticket_id, entry]));
  if (candidate.allocations.length !== scopes.size || candidate.allocations.some((allocation) => !scopes.has(allocation.logical_ticket_id) || allocation.mode !== scopes.get(allocation.logical_ticket_id)?.mode)) return deny("TRACK_COVERAGE_MISSING", "ALLOCATION_SET_MISMATCH");
  const authorities = new Map((t002_authorities as AdmittedTicketAuthorityV1[]).map((authority) => [admittedTicketAuthorityDigest(authority), authority]));
  if (authorities.size !== t002_authorities.length) return deny("TRACK_COVERAGE_MISSING", "AUTHORITY_MISSING");
  const used = new Set<string>();
  for (const allocation of candidate.allocations) {
    const scope = scopes.get(allocation.logical_ticket_id) as TrackAllocationScopeEntryV1;
    const expectedKinds = allocation.mode === "n1" ? ["DIRECT", "EXCLUSION"] : allocation.mode === "enterprise" ? ["EXCLUSION", "DIRECT"] : ["DIRECT", "DIRECT"];
    const witnesses = [allocation.n1_witness, allocation.enterprise_witness] as const;
    if (witnesses[0].target_track !== "n1" || witnesses[1].target_track !== "enterprise" || witnesses[0].kind !== expectedKinds[0] || witnesses[1].kind !== expectedKinds[1]) return deny("TRACK_RECEIPT_SUBSTITUTED");
    if ((witnesses[0].kind === "DIRECT" && scope.n1_body_digest === null) || (witnesses[1].kind === "DIRECT" && scope.enterprise_body_digest === null)) return deny("TRACK_COVERAGE_MISSING", "SCOPE_INVALID");
    for (let index = 0; index < witnesses.length; index += 1) {
      const witness = witnesses[index] as TrackWitnessV1, authority = authorities.get(witness.authority_digest);
      if (!authority) return deny("TRACK_COVERAGE_MISSING", witness.kind === "DIRECT" ? (witness.target_track === "n1" ? "MISSING_N1_DIRECT" : "MISSING_ENTERPRISE_DIRECT") : "AUTHORITY_MISSING");
      const expectedBody = index === 0 ? scope.n1_body_digest : scope.enterprise_body_digest;
      if (authority.ticket_body_digest !== executableTicketBodyDigest(authority.body)) return deny("TRACK_COVERAGE_MISSING", "AUTHORITY_BODY_DIGEST_INVALID");
      if (expectedBody !== null && authority.ticket_body_digest !== expectedBody) return deny("TRACK_RECEIPT_SUBSTITUTED");
      const expectedCase = index === 0 ? scope.n1_case_id : scope.enterprise_case_id;
      if (witness.case_id !== expectedCase) return deny("TRACK_RECEIPT_SUBSTITUTED");
      if (!hasCase(authority, witness.case_id)) return deny("TRACK_COVERAGE_MISSING", "SCOPED_CASE_MISSING");
      if (witness.kind === "DIRECT" && authority.track !== witness.target_track) return deny("TRACK_RECEIPT_SUBSTITUTED");
      if (witness.kind === "EXCLUSION" && authority.track === witness.target_track) return deny("TRACK_RECEIPT_SUBSTITUTED");
      used.add(witness.authority_digest);
    }
    if ((allocation.mode === "paired" || allocation.mode === "shared") && allocation.n1_witness.authority_digest === allocation.enterprise_witness.authority_digest) return deny("TRACK_RECEIPT_SUBSTITUTED");
    const n1Authority = authorities.get(allocation.n1_witness.authority_digest) as AdmittedTicketAuthorityV1;
    const enterpriseAuthority = authorities.get(allocation.enterprise_witness.authority_digest) as AdmittedTicketAuthorityV1;
    if (allocation.n1_witness.kind === "DIRECT") {
      const n1Body = bodyAuthority(n1Authority);
      if (!ownerRecognizable(n1Body) || !validOwner(n1Body)) return deny("TRACK_RECEIPT_SUBSTITUTED");
    }
    if (allocation.enterprise_witness.kind === "DIRECT") {
      const enterpriseBody = bodyAuthority(enterpriseAuthority);
      if (!organizationRecognizable(enterpriseBody) || !validOrganization(enterpriseBody)) return deny("ENTERPRISE_CUSTODY_MISSING");
    }
    if (allocation.n1_witness.kind === "DIRECT" && allocation.n1_witness.ceremony !== "LOCAL_OWNER") return deny("N1_ENTERPRISE_CEREMONY_FORBIDDEN");
    if (allocation.enterprise_witness.kind === "DIRECT" && allocation.enterprise_witness.ceremony !== "ORGANIZATION") return deny("TRACK_RECEIPT_SUBSTITUTED");
    if (allocation.mode === "shared") {
      const equivalence = allocation.equivalence;
      if (!equivalence || !object(equivalence) || !exact(equivalence, EQUIVALENCE_KEYS) || equivalence.mechanism_digest !== allocation.mechanism_digest || equivalence.mechanism_digest !== scope.shared_mechanism_digest || equivalence.evidence_digest !== scope.shared_evidence_digest || equivalence.n1_witness_digest !== allocation.n1_witness.witness_digest || equivalence.enterprise_witness_digest !== allocation.enterprise_witness.witness_digest || allocation.n1_witness.witness_digest === allocation.enterprise_witness.witness_digest || equivalence.equivalence_digest !== trackEquivalenceDigest(equivalence)) return deny("UNSUPPORTED_TRACK_EQUIVALENCE", null, "UNRESOLVED_TRACK_EQUIVALENCE");
    } else if (allocation.equivalence !== null) return deny("TRACK_RECEIPT_SUBSTITUTED");
    if ((allocation.mode === "n1" || allocation.mode === "enterprise")) {
      const counterpart = scope.counterpart_ticket_id && scopes.get(scope.counterpart_ticket_id);
      const expectedMode = allocation.mode === "n1" ? "enterprise" : "n1";
      if (!counterpart || counterpart.mode !== expectedMode || counterpart.counterpart_ticket_id !== allocation.logical_ticket_id) return deny("TRACK_COVERAGE_MISSING", "ALLOCATION_SET_MISMATCH");
    }
    if (allocation.n1_witness.witness_digest !== trackWitnessDigest(allocation.n1_witness) || allocation.enterprise_witness.witness_digest !== trackWitnessDigest(allocation.enterprise_witness)) return deny("TRACK_RECEIPT_SUBSTITUTED");
  }
  if ([...authorities.keys()].some((digest) => !used.has(digest))) return deny("TRACK_COVERAGE_MISSING", "ALLOCATION_SET_MISMATCH");
  if (candidate.candidate_digest !== trackCoverageCandidateDigest(candidate)) return deny("STALE_DERIVATION");
  const authorityDigests = [...authorities.keys()].sort(), witnessDigests = candidate.allocations.flatMap((item) => [item.n1_witness.witness_digest, item.enterprise_witness.witness_digest]).sort();
  return { admitted: true, owner_stop: null, authority: freeze({ status: "TRACK_COVERAGE_ADMITTED", allocation_id: candidate.allocation_id, generation: candidate.generation, candidate_digest: candidate.candidate_digest, scope_projection_digest: candidate.scope_projection_digest, prerequisite_closure_digest: EXPECTED_T002_CLOSURE, approved_ticket_inventory_digest: trusted_scope.approved_ticket_inventory_digest, authority_digests: authorityDigests, witness_digests: witnessDigests, candidate: clone(candidate) }) };
}
