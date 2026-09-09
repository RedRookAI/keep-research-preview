import { createHash } from "node:crypto";

export type DecompositionReviewPhase = "UNOPENED" | "VET_1_OPEN" | "VET_1_REPAIR" | "VET_1_PASS" | "VET_2_OPEN" | "VET_2_REPAIR" | "COMPLETE" | "OWNER_STOP";
export type DecompositionReviewCode = "ADVANCED" | "MALFORMED_OR_UNKNOWN_FIELD" | "PREREQUISITE_AUTHORITY_INVALID" | "VET_RECEIPT_INVALID" | "DECOMPOSITION_NOT_REVIEWABLE" | "VET_FINDINGS_OPEN" | "THIRD_VET_REQUIRES_OWNER" | "STALE_DERIVATION";
export type PrerequisiteReason = "MISSING_PREREQUISITE" | "CLOSURE_DIGEST_MISMATCH" | "CLOSURE_CONTENT_INVALID" | "APPROVED_INVENTORY_MISMATCH" | "GENERATION_MISMATCH";

export interface DecompositionReviewPrerequisiteV1 {
  ticket_id: "PG-04-T002" | "PG-04-T003" | "PG-04-T004";
  role: "TICKET_BODIES_AND_BOUNDS" | "GRAPH_AND_RECIPROCAL_COVERAGE" | "TRACK_ALLOCATION";
  closure_bytes: string;
  closure_digest: string;
  product_commit: string;
}

export interface TrustedCandidateScopeV1 {
  readonly schema_version: 1;
  readonly status: "DECOMPOSITION_REVIEW_SCOPE_ADMITTED";
  readonly generation: string;
  readonly approved_inventory_digest: string;
  readonly candidate_digest: string;
  readonly manifest_digest: string;
  readonly scope_digest: string;
  readonly candidate_author_id: string;
  readonly candidate_author_family: string;
  readonly bounds: { readonly maximum_files: number; readonly maximum_bytes: number; readonly maximum_cases: number; readonly maximum_minutes: number };
  readonly disclosed_reviewers: readonly { readonly reviewer_id: string; readonly reviewer_family: string }[];
  readonly prerequisites: DecompositionReviewPrerequisiteV1[];
}

export type TrustedReviewerContextV1 =
  | { readonly schema_version: 1; readonly kind: "n1"; readonly reviewer_id: string; readonly reviewer_family: string; readonly custody_id: string; readonly organization_services: "ABSENT" }
  | { readonly schema_version: 1; readonly kind: "enterprise"; readonly organization_id: string; readonly actor_id: string; readonly reviewer_id: string; readonly reviewer_family: string; readonly role_id: string; readonly separation_policy_id: string; readonly custody_evidence_digest: string; readonly isolation_evidence_digest: string; readonly local_owner_substitution: false };

interface AssessabilityActionV1 { readonly schema_version: 1; readonly kind: "ATTEST_ASSESSABLE"; readonly expected_generation: string; readonly reviewer_id: string; readonly assessable: boolean; readonly observed_files: number; readonly observed_bytes: number; readonly observed_cases: number; readonly estimated_minutes: number; readonly attestation_digest: string }
interface BeginActionV1 { readonly schema_version: 1; readonly kind: "BEGIN_SUBSTANTIVE_REVIEW"; readonly expected_generation: string; readonly reviewer_id: string | null }
interface ReviewActionV1 { readonly schema_version: 1; readonly kind: "SUBMIT_REVIEW"; readonly expected_generation: string; readonly round: 1 | 2 | null; readonly reviewer_id: string | null; readonly candidate_digest: string; readonly manifest_digest: string; readonly verdict: "PASS" | "REVISE"; readonly findings: readonly string[]; readonly predecessor_receipt_digest: string | null; readonly receipt_digest: string }
interface RepairActionV1 { readonly schema_version: 1; readonly kind: "SUBMIT_REPAIR"; readonly expected_generation: string; readonly round: 1 | 2; readonly reviewer_id: string; readonly from_candidate_digest: string; readonly to_candidate_digest: string; readonly prior_receipt_digest: string | null; readonly addressed_findings: readonly string[]; readonly repair_digest: string }
interface ConfirmActionV1 { readonly schema_version: 1; readonly kind: "CONFIRM_REPAIR"; readonly expected_generation: string; readonly round: 1 | 2; readonly reviewer_id: string; readonly candidate_digest: string; readonly dispositions: readonly string[]; readonly prior_repair_digest: string; readonly receipt_digest: string }
export type DecompositionReviewActionV1 = AssessabilityActionV1 | BeginActionV1 | ReviewActionV1 | RepairActionV1 | ConfirmActionV1;

export interface DecompositionReviewRecordV1 { readonly kind: "REVIEW" | "REPAIR" | "CONFIRMATION"; readonly round: 1 | 2; readonly digest: string; readonly reviewer_id: string; readonly candidate_digest: string }
export interface TwoRoundDecompositionReviewDispositionV1 {
  readonly schema_version: 1;
  readonly status: "TWO_ROUND_DECOMPOSITION_REVIEW_COMPLETE";
  readonly generation: string;
  readonly candidate_digest: string;
  readonly manifest_digest: string;
  readonly scope_digest: string;
  readonly used: 2;
  readonly reviewers: readonly { readonly round: 1 | 2; readonly reviewer_id: string; readonly reviewer_family: string; readonly track: "n1" | "enterprise" }[];
  readonly repair_chains: readonly DecompositionReviewRecordV1[];
  readonly open_findings: readonly [];
  readonly disposition_digest: string;
}

export interface DecompositionReviewStateV1 {
  readonly schema_version: 1;
  readonly phase: DecompositionReviewPhase;
  readonly generation: string;
  readonly candidate_digest: string;
  readonly manifest_digest: string;
  readonly scope_digest: string;
  readonly used_rounds: 0 | 1 | 2;
  readonly active_round: 1 | 2 | null;
  readonly active_reviewer_id: string | null;
  readonly active_reviewer_family: string | null;
  readonly active_track: "n1" | "enterprise" | null;
  readonly reviewers: readonly { readonly round: 1 | 2; readonly reviewer_id: string; readonly reviewer_family: string; readonly track: "n1" | "enterprise" }[];
  readonly records: readonly DecompositionReviewRecordV1[];
  readonly receipt_head: string | null;
  readonly open_findings: readonly string[];
  readonly repair_used: boolean;
  readonly confirmation_used: boolean;
  readonly owner_stop: "OWNER_DECISION" | null;
  readonly implementation_authorized: false;
  readonly disposition: TwoRoundDecompositionReviewDispositionV1 | null;
}

export interface DecompositionReviewResultV1 {
  readonly advanced: boolean;
  readonly code: DecompositionReviewCode;
  readonly reason: PrerequisiteReason | null;
  readonly state: DecompositionReviewStateV1 | null;
  readonly owner_stop: "OWNER_DECISION" | null;
}

const HEX = /^[a-f0-9]{64}$/u;
const GENERATION = /^sha256:[a-f0-9]{64}$/u;
const INVENTORY = "f0b8b60c7b497b6422fc43afeb310d18ea3d28f3decfe666d44deb54963399db";
const REQUIRED = new Map<string, { readonly role: string; readonly closure: string; readonly product: string }>([
  ["PG-04-T002", { role: "TICKET_BODIES_AND_BOUNDS", closure: "faa4b817a6769d8de78dca233b2d090472d8cc05d08bde07ea9dccd22cfa30e5", product: "79676b4f9134a3b12af6af734eed3c48f23ffc22" }],
  ["PG-04-T003", { role: "GRAPH_AND_RECIPROCAL_COVERAGE", closure: "41268ed1843199a7cff0775176d702d2940a1b2c0698a2e4e0e588d79825b28d", product: "9cd2e62b505b6e61399b72c9fcf800a3504577de" }],
  ["PG-04-T004", { role: "TRACK_ALLOCATION", closure: "452a60a757fca16df48f5137851e00c48ded8e0f844517089fc585ddc217f797", product: "f27386765d0a964413240a7d8e821b85840311d7" }],
]);
const STATE_KEYS = ["active_reviewer_family", "active_reviewer_id", "active_round", "active_track", "candidate_digest", "confirmation_used", "disposition", "generation", "implementation_authorized", "manifest_digest", "open_findings", "owner_stop", "phase", "receipt_head", "records", "repair_used", "reviewers", "schema_version", "scope_digest", "used_rounds"];
const SCOPE_KEYS = ["approved_inventory_digest", "bounds", "candidate_author_family", "candidate_author_id", "candidate_digest", "disclosed_reviewers", "generation", "manifest_digest", "prerequisites", "schema_version", "scope_digest", "status"];
const BOUND_KEYS = ["maximum_bytes", "maximum_cases", "maximum_files", "maximum_minutes"];
const DISCLOSED_KEYS = ["reviewer_family", "reviewer_id"];
const PREREQUISITE_KEYS = ["closure_bytes", "closure_digest", "product_commit", "role", "ticket_id"];
const N1_KEYS = ["custody_id", "kind", "organization_services", "reviewer_family", "reviewer_id", "schema_version"];
const ENTERPRISE_KEYS = ["actor_id", "custody_evidence_digest", "isolation_evidence_digest", "kind", "local_owner_substitution", "organization_id", "reviewer_family", "reviewer_id", "role_id", "schema_version", "separation_policy_id"];
const ACTION_KEYS: Record<DecompositionReviewActionV1["kind"], readonly string[]> = {
  ATTEST_ASSESSABLE: ["assessable", "attestation_digest", "estimated_minutes", "expected_generation", "kind", "observed_bytes", "observed_cases", "observed_files", "reviewer_id", "schema_version"],
  BEGIN_SUBSTANTIVE_REVIEW: ["expected_generation", "kind", "reviewer_id", "schema_version"],
  SUBMIT_REVIEW: ["candidate_digest", "expected_generation", "findings", "kind", "manifest_digest", "predecessor_receipt_digest", "receipt_digest", "reviewer_id", "round", "schema_version", "verdict"],
  SUBMIT_REPAIR: ["addressed_findings", "expected_generation", "from_candidate_digest", "kind", "prior_receipt_digest", "repair_digest", "reviewer_id", "round", "schema_version", "to_candidate_digest"],
  CONFIRM_REPAIR: ["candidate_digest", "dispositions", "expected_generation", "kind", "prior_repair_digest", "receipt_digest", "reviewer_id", "round", "schema_version"],
};

const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const exact = (value: Record<string, unknown>, keys: readonly string[]) => { const actual = Object.keys(value).sort(), expected = [...keys].sort(); return actual.length === expected.length && actual.every((key, index) => key === expected[index]); };
const nonempty = (value: unknown): value is string => typeof value === "string" && value.length > 0 && value.length <= 256;
const positive = (value: unknown) => Number.isSafeInteger(value) && (value as number) > 0;
const strings = (value: unknown): value is readonly string[] => Array.isArray(value) && value.length <= 64 && value.every(nonempty) && new Set(value).size === value.length;
const canonical = (value: unknown): string => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : object(value) ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
export const decompositionReviewDigest = (value: unknown): string => createHash("sha256").update(canonical(value)).digest("hex");
const digestWithout = (value: Record<string, unknown>, field: string) => { const copy = { ...value }; delete copy[field]; return decompositionReviewDigest(copy); };
const frozen = <T>(value: T): T => { if (value !== null && typeof value === "object" && !Object.isFrozen(value)) { Object.freeze(value); for (const child of Object.values(value as Record<string, unknown>)) frozen(child); } return value; };
const clone = <T>(value: T): T => structuredClone(value);
const result = (advanced: boolean, code: DecompositionReviewCode, state: DecompositionReviewStateV1 | null, reason: PrerequisiteReason | null = null, owner_stop: "OWNER_DECISION" | null = null): DecompositionReviewResultV1 => frozen({ advanced, code, reason, state: state === null ? null : frozen(state), owner_stop });

function recognizableScope(value: unknown): value is TrustedCandidateScopeV1 {
  if (!object(value) || !exact(value, SCOPE_KEYS) || value.schema_version !== 1 || value.status !== "DECOMPOSITION_REVIEW_SCOPE_ADMITTED" || typeof value.generation !== "string" || !GENERATION.test(value.generation) || ![value.approved_inventory_digest, value.candidate_digest, value.manifest_digest, value.scope_digest].every((item) => typeof item === "string" && HEX.test(item)) || !nonempty(value.candidate_author_id) || !nonempty(value.candidate_author_family) || !object(value.bounds) || !exact(value.bounds, BOUND_KEYS) || !Object.values(value.bounds).every(positive) || !Array.isArray(value.disclosed_reviewers) || value.disclosed_reviewers.length !== 2 || !Array.isArray(value.prerequisites) || value.prerequisites.length !== 3) return false;
  const reviewers = new Set<string>();
  if (!value.disclosed_reviewers.every((row) => object(row) && exact(row, DISCLOSED_KEYS) && nonempty(row.reviewer_id) && nonempty(row.reviewer_family) && !reviewers.has(row.reviewer_id) && reviewers.add(row.reviewer_id))) return false;
  return value.prerequisites.every((row) => object(row) && exact(row, PREREQUISITE_KEYS) && nonempty(row.ticket_id) && nonempty(row.role) && typeof row.closure_bytes === "string" && row.closure_bytes.length <= 1_000_000 && typeof row.closure_digest === "string" && HEX.test(row.closure_digest) && typeof row.product_commit === "string" && /^[a-f0-9]{40}$/u.test(row.product_commit));
}

function recognizableContext(value: unknown): value is TrustedReviewerContextV1 {
  if (!object(value) || value.schema_version !== 1) return false;
  if (value.kind === "n1") return exact(value, N1_KEYS) && nonempty(value.reviewer_id) && nonempty(value.reviewer_family) && nonempty(value.custody_id) && value.organization_services === "ABSENT";
  return value.kind === "enterprise" && exact(value, ENTERPRISE_KEYS) && [value.organization_id, value.actor_id, value.reviewer_id, value.reviewer_family, value.role_id, value.separation_policy_id].every(nonempty) && typeof value.custody_evidence_digest === "string" && HEX.test(value.custody_evidence_digest) && typeof value.isolation_evidence_digest === "string" && HEX.test(value.isolation_evidence_digest) && value.local_owner_substitution === false;
}

function recognizableState(value: unknown): value is DecompositionReviewStateV1 {
  if (!object(value) || !exact(value, STATE_KEYS) || value.schema_version !== 1 || !["UNOPENED", "VET_1_OPEN", "VET_1_REPAIR", "VET_1_PASS", "VET_2_OPEN", "VET_2_REPAIR", "COMPLETE", "OWNER_STOP"].includes(value.phase as string) || typeof value.generation !== "string" || !GENERATION.test(value.generation) || ![value.candidate_digest, value.manifest_digest, value.scope_digest].every((item) => typeof item === "string" && HEX.test(item)) || ![0, 1, 2].includes(value.used_rounds as number) || !Array.isArray(value.reviewers) || !Array.isArray(value.records) || !strings(value.open_findings) || value.implementation_authorized !== false || typeof value.repair_used !== "boolean" || typeof value.confirmation_used !== "boolean" || !(value.receipt_head === null || (typeof value.receipt_head === "string" && HEX.test(value.receipt_head)))) return false;
  const reviewers = value.reviewers as unknown[];
  const records = value.records as unknown[];
  if (reviewers.length > 2 || !reviewers.every((row) => object(row) && exact(row, ["reviewer_family", "reviewer_id", "round", "track"]) && [1, 2].includes(row.round as number) && nonempty(row.reviewer_id) && nonempty(row.reviewer_family) && ["n1", "enterprise"].includes(row.track as string)) || new Set(reviewers.map((row) => (row as Record<string, unknown>).reviewer_id)).size !== reviewers.length) return false;
  if (records.length > 6 || !records.every((row) => object(row) && exact(row, ["candidate_digest", "digest", "kind", "reviewer_id", "round"]) && ["REVIEW", "REPAIR", "CONFIRMATION"].includes(row.kind as string) && [1, 2].includes(row.round as number) && nonempty(row.reviewer_id) && typeof row.digest === "string" && HEX.test(row.digest) && typeof row.candidate_digest === "string" && HEX.test(row.candidate_digest)) || new Set(records.map((row) => (row as Record<string, unknown>).digest)).size !== records.length) return false;
  const active = value.active_round === 1 || value.active_round === 2;
  if (active !== (nonempty(value.active_reviewer_id) && nonempty(value.active_reviewer_family) && ["n1", "enterprise"].includes(value.active_track as string))) return false;
  const phase = value.phase as DecompositionReviewPhase, used = value.used_rounds as number;
  if (phase === "UNOPENED" && (used !== 0 || active || reviewers.length !== 0 || records.length !== 0)) return false;
  if (phase === "VET_1_OPEN" && (value.active_round !== 1 || ![0, 1].includes(used))) return false;
  if (phase === "VET_1_REPAIR" && (value.active_round !== 1 || used !== 1 || value.open_findings.length === 0)) return false;
  if (phase === "VET_1_PASS" && (used !== 1 || active || value.open_findings.length !== 0)) return false;
  if (phase === "VET_2_OPEN" && (value.active_round !== 2 || ![1, 2].includes(used))) return false;
  if (phase === "VET_2_REPAIR" && (value.active_round !== 2 || used !== 2 || value.open_findings.length === 0)) return false;
  if (phase === "OWNER_STOP" && value.owner_stop !== "OWNER_DECISION") return false;
  if (phase !== "OWNER_STOP" && value.owner_stop !== null) return false;
  if (phase === "COMPLETE") {
    if (used !== 2 || active || value.open_findings.length !== 0 || !validDisposition(value.disposition, value)) return false;
  } else if (value.disposition !== null && phase !== "OWNER_STOP") return false;
  return true;
}

function validDisposition(value: unknown, state: Record<string, unknown>): value is TwoRoundDecompositionReviewDispositionV1 {
  if (!object(value) || !exact(value, ["candidate_digest", "disposition_digest", "generation", "manifest_digest", "open_findings", "repair_chains", "reviewers", "schema_version", "scope_digest", "status", "used"]) || value.schema_version !== 1 || value.status !== "TWO_ROUND_DECOMPOSITION_REVIEW_COMPLETE" || value.used !== 2 || !Array.isArray(value.open_findings) || value.open_findings.length !== 0 || value.generation !== state.generation || value.candidate_digest !== state.candidate_digest || value.manifest_digest !== state.manifest_digest || value.scope_digest !== state.scope_digest || !Array.isArray(value.reviewers) || !Array.isArray(value.repair_chains) || typeof value.disposition_digest !== "string" || !HEX.test(value.disposition_digest)) return false;
  return value.disposition_digest === digestWithout(value, "disposition_digest");
}

function recognizableAction(value: unknown): value is DecompositionReviewActionV1 {
  if (!object(value) || value.schema_version !== 1 || typeof value.kind !== "string" || !(value.kind in ACTION_KEYS) || !exact(value, ACTION_KEYS[value.kind as DecompositionReviewActionV1["kind"]]!) || typeof value.expected_generation !== "string" || !GENERATION.test(value.expected_generation)) return false;
  if (value.kind === "ATTEST_ASSESSABLE") return nonempty(value.reviewer_id) && typeof value.assessable === "boolean" && [value.observed_files, value.observed_bytes, value.observed_cases, value.estimated_minutes].every(positive) && typeof value.attestation_digest === "string" && HEX.test(value.attestation_digest);
  if (value.kind === "BEGIN_SUBSTANTIVE_REVIEW") return value.reviewer_id === null || nonempty(value.reviewer_id);
  if (value.kind === "SUBMIT_REVIEW") return [1, 2].includes(value.round as number) && (value.reviewer_id === null || nonempty(value.reviewer_id)) && typeof value.candidate_digest === "string" && HEX.test(value.candidate_digest) && typeof value.manifest_digest === "string" && HEX.test(value.manifest_digest) && ["PASS", "REVISE"].includes(value.verdict as string) && strings(value.findings) && (value.predecessor_receipt_digest === null || (typeof value.predecessor_receipt_digest === "string" && HEX.test(value.predecessor_receipt_digest))) && typeof value.receipt_digest === "string" && HEX.test(value.receipt_digest);
  if (value.kind === "SUBMIT_REPAIR") return [1, 2].includes(value.round as number) && nonempty(value.reviewer_id) && [value.from_candidate_digest, value.to_candidate_digest].every((item) => typeof item === "string" && HEX.test(item)) && value.from_candidate_digest !== value.to_candidate_digest && (value.prior_receipt_digest === null || (typeof value.prior_receipt_digest === "string" && HEX.test(value.prior_receipt_digest))) && strings(value.addressed_findings) && typeof value.repair_digest === "string" && HEX.test(value.repair_digest);
  return [1, 2].includes(value.round as number) && nonempty(value.reviewer_id) && typeof value.candidate_digest === "string" && HEX.test(value.candidate_digest) && strings(value.dispositions) && typeof value.prior_repair_digest === "string" && HEX.test(value.prior_repair_digest) && typeof value.receipt_digest === "string" && HEX.test(value.receipt_digest);
}

function prerequisiteFailure(scope: TrustedCandidateScopeV1): PrerequisiteReason | null {
  if (scope.approved_inventory_digest !== INVENTORY) return "APPROVED_INVENTORY_MISMATCH";
  const seen = new Set<string>();
  for (const prerequisite of scope.prerequisites) {
    const expected = REQUIRED.get(prerequisite.ticket_id);
    if (seen.has(prerequisite.ticket_id) || expected === undefined || expected.role !== prerequisite.role) return "MISSING_PREREQUISITE";
    seen.add(prerequisite.ticket_id);
    if (prerequisite.closure_digest !== expected.closure || prerequisite.product_commit !== expected.product || createHash("sha256").update(prerequisite.closure_bytes).digest("hex") !== expected.closure) return "CLOSURE_DIGEST_MISMATCH";
    try { const receipt = JSON.parse(prerequisite.closure_bytes) as unknown; if (!object(receipt) || receipt.status !== "COMPLETE" || receipt.ticket_id !== prerequisite.ticket_id || receipt.closure_profile !== "FULL_KEEP_EXACT_COMMIT_V1" || receipt.product_commit !== expected.product) return "CLOSURE_CONTENT_INVALID"; } catch { return "CLOSURE_CONTENT_INVALID"; }
  }
  return seen.size === REQUIRED.size ? null : "MISSING_PREREQUISITE";
}

function reviewerValid(context: TrustedReviewerContextV1, scope: TrustedCandidateScopeV1): boolean {
  const disclosed = scope.disclosed_reviewers.some((row) => row.reviewer_id === context.reviewer_id && row.reviewer_family === context.reviewer_family);
  return disclosed && context.reviewer_id !== scope.candidate_author_id && context.reviewer_family !== scope.candidate_author_family;
}

export function initialDecompositionReviewState(scopeInput: TrustedCandidateScopeV1): DecompositionReviewStateV1 {
  const scope = clone(scopeInput);
  if (!recognizableScope(scope) || prerequisiteFailure(scope) !== null) throw new Error("invalid decomposition review scope");
  return frozen({ schema_version: 1, phase: "UNOPENED", generation: scope.generation, candidate_digest: scope.candidate_digest, manifest_digest: scope.manifest_digest, scope_digest: scope.scope_digest, used_rounds: 0, active_round: null, active_reviewer_id: null, active_reviewer_family: null, active_track: null, reviewers: [], records: [], receipt_head: null, open_findings: [], repair_used: false, confirmation_used: false, owner_stop: null, implementation_authorized: false, disposition: null });
}

function matchingAuthority(state: DecompositionReviewStateV1, action: DecompositionReviewActionV1, context: TrustedReviewerContextV1): boolean {
  return action.reviewer_id === context.reviewer_id && (state.active_reviewer_id === null || state.active_reviewer_id === context.reviewer_id) && (state.active_reviewer_family === null || state.active_reviewer_family === context.reviewer_family) && (state.active_track === null || state.active_track === context.kind);
}

function selfBound(action: DecompositionReviewActionV1): boolean {
  if (action.kind === "ATTEST_ASSESSABLE") return action.attestation_digest === digestWithout(action as unknown as Record<string, unknown>, "attestation_digest");
  if (action.kind === "SUBMIT_REVIEW" || action.kind === "CONFIRM_REPAIR") return action.receipt_digest === digestWithout(action as unknown as Record<string, unknown>, "receipt_digest");
  if (action.kind === "SUBMIT_REPAIR") return action.repair_digest === digestWithout(action as unknown as Record<string, unknown>, "repair_digest");
  return true;
}

export function advanceDecompositionReview(stateInput: unknown, actionInput: unknown, contextInput: unknown, scopeInput: unknown): DecompositionReviewResultV1 {
  let state: unknown, action: unknown, context: unknown, scope: unknown;
  try { state = clone(stateInput); action = clone(actionInput); context = clone(contextInput); scope = clone(scopeInput); } catch { return result(false, "MALFORMED_OR_UNKNOWN_FIELD", null); }
  if (!recognizableState(state) || !recognizableAction(action) || !recognizableContext(context) || !recognizableScope(scope)) return result(false, "MALFORMED_OR_UNKNOWN_FIELD", null);
  const prerequisite = prerequisiteFailure(scope);
  if (prerequisite !== null || state.generation !== scope.generation || state.scope_digest !== scope.scope_digest || state.manifest_digest !== scope.manifest_digest) return result(false, "PREREQUISITE_AUTHORITY_INVALID", state, prerequisite ?? (state.generation !== scope.generation ? "GENERATION_MISMATCH" : "CLOSURE_CONTENT_INVALID"));
  if (!reviewerValid(context, scope) || !matchingAuthority(state, action, context) || !selfBound(action)) return result(false, "VET_RECEIPT_INVALID", state);

  if (action.kind === "ATTEST_ASSESSABLE") {
    if (state.phase === "COMPLETE" || state.used_rounds === 2) return result(false, "THIRD_VET_REQUIRES_OWNER", { ...state, phase: "OWNER_STOP", owner_stop: "OWNER_DECISION" }, null, "OWNER_DECISION");
    if (action.expected_generation !== state.generation) return result(false, "STALE_DERIVATION", state);
    const nextRound: 1 | 2 | null = state.phase === "UNOPENED" ? 1 : state.phase === "VET_1_PASS" ? 2 : null;
    if (nextRound === null || state.reviewers.some((row) => row.reviewer_id === context.reviewer_id)) return result(false, "VET_RECEIPT_INVALID", state);
    const within = action.assessable && action.observed_files <= scope.bounds.maximum_files && action.observed_bytes <= scope.bounds.maximum_bytes && action.observed_cases <= scope.bounds.maximum_cases && action.estimated_minutes <= scope.bounds.maximum_minutes;
    if (!within) { const stopped = { ...state, phase: "OWNER_STOP" as const, owner_stop: "OWNER_DECISION" as const }; return result(false, "DECOMPOSITION_NOT_REVIEWABLE", stopped, null, "OWNER_DECISION"); }
    const opened = { ...state, phase: nextRound === 1 ? "VET_1_OPEN" as const : "VET_2_OPEN" as const, active_round: nextRound, active_reviewer_id: context.reviewer_id, active_reviewer_family: context.reviewer_family, active_track: context.kind, repair_used: false, confirmation_used: false };
    return result(true, "ADVANCED", opened);
  }
  if (action.expected_generation !== state.generation) return result(false, "STALE_DERIVATION", state);

  if (action.kind === "BEGIN_SUBSTANTIVE_REVIEW") {
    if (!(["VET_1_OPEN", "VET_2_OPEN"] as string[]).includes(state.phase) || state.active_round === null || state.used_rounds !== state.active_round - 1) return result(false, "VET_RECEIPT_INVALID", state);
    const reviewer = { round: state.active_round, reviewer_id: context.reviewer_id, reviewer_family: context.reviewer_family, track: context.kind };
    return result(true, "ADVANCED", { ...state, used_rounds: state.active_round, reviewers: [...state.reviewers, reviewer] } as DecompositionReviewStateV1);
  }

  if (action.kind === "SUBMIT_REVIEW") {
    if (action.round !== state.active_round || state.used_rounds !== state.active_round || action.candidate_digest !== state.candidate_digest || action.manifest_digest !== state.manifest_digest || action.predecessor_receipt_digest !== state.receipt_head || state.records.some((row) => row.digest === action.receipt_digest) || !(["VET_1_OPEN", "VET_2_OPEN"] as string[]).includes(state.phase)) return result(false, "VET_RECEIPT_INVALID", state);
    if (action.verdict === "PASS" && action.findings.length > 0) return result(false, "VET_FINDINGS_OPEN", state);
    const record: DecompositionReviewRecordV1 = { kind: "REVIEW", round: state.active_round, digest: action.receipt_digest, reviewer_id: context.reviewer_id, candidate_digest: state.candidate_digest };
    if (action.verdict === "REVISE") {
      if (action.findings.length === 0) return result(false, "VET_RECEIPT_INVALID", state);
      return result(true, "VET_FINDINGS_OPEN", { ...state, phase: state.active_round === 1 ? "VET_1_REPAIR" : "VET_2_REPAIR", records: [...state.records, record], receipt_head: action.receipt_digest, open_findings: [...action.findings] } as DecompositionReviewStateV1);
    }
    return passRound({ ...state, records: [...state.records, record], receipt_head: action.receipt_digest, open_findings: [] } as DecompositionReviewStateV1);
  }

  if (action.kind === "SUBMIT_REPAIR") {
    if (!(["VET_1_REPAIR", "VET_2_REPAIR"] as string[]).includes(state.phase) || state.repair_used || action.round !== state.active_round || action.from_candidate_digest !== state.candidate_digest || action.prior_receipt_digest !== state.receipt_head || action.addressed_findings.length !== state.open_findings.length || !action.addressed_findings.every((item) => state.open_findings.includes(item))) return result(false, "VET_RECEIPT_INVALID", state);
    const record: DecompositionReviewRecordV1 = { kind: "REPAIR", round: action.round, digest: action.repair_digest, reviewer_id: context.reviewer_id, candidate_digest: action.to_candidate_digest };
    return result(true, "ADVANCED", { ...state, candidate_digest: action.to_candidate_digest, records: [...state.records, record], receipt_head: action.repair_digest, repair_used: true } as DecompositionReviewStateV1);
  }

  if (!(["VET_1_REPAIR", "VET_2_REPAIR"] as string[]).includes(state.phase) || !state.repair_used || state.confirmation_used || action.round !== state.active_round || action.candidate_digest !== state.candidate_digest || action.prior_repair_digest !== state.receipt_head || action.dispositions.length !== state.open_findings.length || !action.dispositions.every((item) => state.open_findings.includes(item))) return result(false, "VET_RECEIPT_INVALID", state);
  const record: DecompositionReviewRecordV1 = { kind: "CONFIRMATION", round: action.round, digest: action.receipt_digest, reviewer_id: context.reviewer_id, candidate_digest: state.candidate_digest };
  return passRound({ ...state, records: [...state.records, record], receipt_head: action.receipt_digest, open_findings: [], confirmation_used: true } as DecompositionReviewStateV1);
}

function passRound(state: DecompositionReviewStateV1): DecompositionReviewResultV1 {
  if (state.active_round === 1) return result(true, "ADVANCED", { ...state, phase: "VET_1_PASS", active_round: null, active_reviewer_id: null, active_reviewer_family: null, active_track: null, repair_used: false, confirmation_used: false } as DecompositionReviewStateV1);
  if (state.active_round !== 2 || state.used_rounds !== 2 || state.open_findings.length !== 0) return result(false, "VET_FINDINGS_OPEN", state);
  const body = { schema_version: 1 as const, status: "TWO_ROUND_DECOMPOSITION_REVIEW_COMPLETE" as const, generation: state.generation, candidate_digest: state.candidate_digest, manifest_digest: state.manifest_digest, scope_digest: state.scope_digest, used: 2 as const, reviewers: state.reviewers, repair_chains: state.records, open_findings: [] as const };
  const disposition = frozen({ ...body, disposition_digest: decompositionReviewDigest(body) });
  return result(true, "ADVANCED", { ...state, phase: "COMPLETE", active_round: null, active_reviewer_id: null, active_reviewer_family: null, active_track: null, owner_stop: null, disposition } as DecompositionReviewStateV1);
}
