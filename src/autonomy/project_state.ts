import { createHash } from "node:crypto";

export {
  FileWorkAttemptAuthorityV1,
  InvalidWorkAttemptError,
  StaleWorkAttemptError,
  WorkAttemptConflictError,
  replayWorkAttemptV1,
  WORK_ATTEMPT_NON_ADVANCING_OUTCOMES_V1,
  WORK_ATTEMPT_STAGES_V1,
} from "../spine/work_attempt_authority_v1.js";
export type {
  WorkAttemptFailureLessonV1,
  WorkAttemptAuthorityV1,
  WorkAttemptFenceV1,
  WorkAttemptIdentityV1,
  WorkAttemptNonAdvancingOutcomeV1,
  WorkAttemptReferenceV1,
  WorkAttemptSnapshotV1,
  WorkAttemptStageV1,
  WorkAttemptTransitionV1,
} from "../spine/work_attempt_authority_v1.js";

/** Durable, edition-independent contract for an autonomous project run. */

export const PROJECT_STATE_SCHEMA_VERSION = 1 as const;

export type AuthorityPosture = "autonomous" | "policy-calibrated" | "approval-required";
export const DOMAIN_WORKFLOW_KINDS = ["long-form-fiction", "academic-paper", "chapter-book", "social-video", "audiobook"] as const;
export type DomainWorkflowKind = typeof DOMAIN_WORKFLOW_KINDS[number];
export type ProjectStrategy = { readonly kind: "software" } | { readonly kind: "domain"; readonly domainKind: DomainWorkflowKind };

/** Closed, non-executable input for the composed goal-to-architecture authority path. */
export interface GoalLifecycleRequestV1 {
  readonly schema_version: 1;
  readonly goal_candidate: unknown;
  readonly authority_context: unknown;
  readonly scope_authority: unknown;
  readonly research_protocol: unknown;
  readonly research_record: unknown;
  readonly observed_at: string;
  readonly current_source_identities: Readonly<Record<string, string>>;
  readonly transition_state: unknown;
  readonly transitions: readonly unknown[];
  readonly executable: false;
}

/** The sole durable projection of a structured goal run. It can never carry execution authority. */
export interface GoalLifecycleArtifactV1 {
  readonly schema_version: 1;
  readonly mode: "goal-to-architecture";
  readonly request: GoalLifecycleRequestV1;
  readonly code: string;
  readonly admitted_goal: unknown | null;
  readonly admitted_research: unknown | null;
  readonly transition_state: unknown;
  readonly next_transition_index: number;
  readonly executable: false;
}

export type Stage = "understand" | "research" | "rag" | "plan" | "vet_plan" | "ticket" | "implement" | "vet_artifact" | "learn" | "done";

export const PROJECT_STAGES: readonly Stage[] = [
  "understand", "research", "rag", "plan", "vet_plan", "ticket", "implement", "vet_artifact", "learn", "done",
];

export type ProjectStatus =
  | "running"
  | "waiting-retry"
  | "waiting-capability"
  | "waiting-approval"
  | "waiting-policy"
  | "waiting-reconciliation"
  | "paused-budget"
  | "completed"
  | "failed";

export type WaitState =
  | { readonly kind: "retry"; readonly activity: Stage; readonly createdAt: number; readonly resumeAt: number; readonly attempt: number; readonly reason: string }
  | { readonly kind: "capability"; readonly activity: Stage; readonly createdAt: number; readonly capability: string; readonly resumeAuthority: "work" | "approval"; readonly reason: string }
  | { readonly kind: "approval"; readonly activity: Stage; readonly createdAt: number; readonly decisionId: string; readonly severity: "routine" | "extreme"; readonly resumeMode: "advance" | "rerun"; readonly reason: string }
  | { readonly kind: "policy"; readonly activity: Stage; readonly createdAt: number; readonly policyId: string; readonly reason: string }
  | { readonly kind: "reconciliation"; readonly activity: Stage; readonly createdAt: number; readonly effectId: string; readonly reason: string };

export interface RetryState {
  readonly attemptsByStage: Readonly<Partial<Record<Stage, number>>>;
  readonly attemptsConsumed: number;
  readonly runLimit: number;
}

export interface ProjectState {
  readonly schemaVersion: typeof PROJECT_STATE_SCHEMA_VERSION;
  readonly revision: number;
  readonly runId: string;
  /** Owning durable project. Required for managed/product runs; absent only on legacy standalone runs. */
  readonly projectId?: import("../session/project_id.js").ProjectId;
  readonly goal: string;
  readonly stage: Stage;
  readonly artifacts: Readonly<Record<string, unknown>>;
  readonly posture: AuthorityPosture;
  /** Durable per-run routing identity. Absent legacy state means software. */
  readonly strategy?: ProjectStrategy;
  readonly stepsRemaining: number;
  readonly reworkCount: number;
  readonly status: ProjectStatus;
  readonly retry: RetryState;
  /** Single-use resume/authority signals already consumed by this run. */
  readonly consumedSignals: readonly string[];
  readonly wait?: WaitState;
  readonly note?: string;
}

export class InvalidProjectStateError extends Error {
  override readonly name = "InvalidProjectStateError";
}

export type TicketResearchTrack = "n1" | "enterprise";
export type TicketResearchAuthorityV1 =
  | { kind: "n1"; owner_id: string; custody_id: string; organization_services: "ABSENT" }
  | { kind: "enterprise"; organization_id: string; actor_id: string; role_id: string; separation_policy_id: string; custody_evidence_digest: string; isolation_evidence_digest: string; local_owner_substitution: false };
export interface TicketResearchCandidateV1 { ticket_id: string; dependency_ticket_ids: string[]; track: TicketResearchTrack }
export interface TicketResearchGenerationV1 { generation: string; publication_receipt_digest: string; remote_readback_commit: string; remote_ref_matched: boolean; tickets: TicketResearchCandidateV1[] }
export interface TicketResearchActivationStateV1 { schema_version: 1; active_generation: string; active_ticket_id: string | null; closed_ticket_ids: string[] }
export interface TicketResearchActivationRequestV1 { schema_version: 1; expected_generation: string; approved_generation: TicketResearchGenerationV1; state: TicketResearchActivationStateV1; selected_ticket_id: string; authority: TicketResearchAuthorityV1; implementation_authorized: false }
export interface TicketResearchAuthorizationReceiptV1 { schema_version: 1; status: "TICKET_RESEARCH_AUTHORIZED"; ticket_id: string; generation: string; publication_receipt_digest: string; remote_readback_commit: string; track: TicketResearchTrack; authority: TicketResearchAuthorityV1; dependency_ticket_ids: readonly string[]; receipt_digest: string; implementation_authorized: false }
export type TicketResearchActivationCode = "TICKET_RESEARCH_AUTHORIZED" | "MALFORMED_OR_UNKNOWN_FIELD" | "PREREQUISITE_AUTHORITY_INVALID" | "ACTIVE_TICKET_CONFLICT" | "STALE_DERIVATION" | "DECOMPOSITION_CANNOT_AUTHORIZE_IMPLEMENTATION" | "TRACK_AUTHORITY_SUBSTITUTION";
export interface TicketResearchActivationResultV1 { advanced: boolean; code: TicketResearchActivationCode; receipt: TicketResearchAuthorizationReceiptV1 | null }

export interface TicketResearchProgressInputV1 { readonly activation: TicketResearchActivationRequestV1; readonly receipt: TicketResearchAuthorizationReceiptV1; readonly current_state: TicketResearchActivationStateV1 }
export interface TicketResearchProgressV1 {
  readonly schema_version: 1; readonly status: "TICKET_RESEARCH_PROGRESS_VALID"; readonly generation: string; readonly receipt_digest: string;
  readonly active_ticket_id: string | null; readonly ticket_status: "ACTIVE" | "CLOSED" | "NOT_ACTIVE_NOT_CLOSED";
  readonly approved_tickets: readonly TicketResearchCandidateV1[]; readonly closed_in_generation: readonly string[];
  readonly closed_outside_generation: readonly string[]; readonly closed_in_generation_count: number;
  readonly authoritative: false; readonly effects_performed: false;
}
export type TicketResearchProgressCodeV1 = "TICKET_RESEARCH_PROGRESS_VALID" | "MALFORMED_OR_UNKNOWN_FIELD" | "RECEIPT_MISMATCH" | "STALE_DERIVATION" | "ACTIVE_TICKET_CONFLICT" | "DEPENDENCY_CLOSURE_REGRESSED";
export type TicketResearchProgressResultV1 = { readonly ok: true; readonly code: "TICKET_RESEARCH_PROGRESS_VALID"; readonly progress: TicketResearchProgressV1 } | { readonly ok: false; readonly code: Exclude<TicketResearchProgressCodeV1, "TICKET_RESEARCH_PROGRESS_VALID"> };

const TICKET_ID = /^(?:PG|SG)-[0-9]{2}-T[0-9]{3}[A-Z]?$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const SHA256_GENERATION = /^sha256:[a-f0-9]{64}$/u;
const GIT_OID = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u;
const researchObject = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const exactKeys = (value: Record<string, unknown>, keys: readonly string[]) => {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
};
const boundedIdentity = (value: unknown) => typeof value === "string" && value.length > 0 && value.length <= 1024;
export const isTicketResearchIdV1 = (value: unknown): value is string => typeof value === "string" && TICKET_ID.test(value);
const validTicketCandidate = (value: unknown): value is TicketResearchCandidateV1 => {
  if (!researchObject(value) || !exactKeys(value, ["dependency_ticket_ids", "ticket_id", "track"]) || !isTicketResearchIdV1(value.ticket_id) || (value.track !== "n1" && value.track !== "enterprise") || !Array.isArray(value.dependency_ticket_ids) || value.dependency_ticket_ids.length > 10_000) return false;
  return value.dependency_ticket_ids.every(isTicketResearchIdV1) && new Set(value.dependency_ticket_ids).size === value.dependency_ticket_ids.length;
};
const validResearchAuthority = (value: unknown): value is TicketResearchAuthorityV1 => {
  if (!researchObject(value)) return false;
  if (value.kind === "n1") return exactKeys(value, ["custody_id", "kind", "organization_services", "owner_id"]) && boundedIdentity(value.owner_id) && boundedIdentity(value.custody_id) && value.organization_services === "ABSENT";
  return value.kind === "enterprise" && exactKeys(value, ["actor_id", "custody_evidence_digest", "isolation_evidence_digest", "kind", "local_owner_substitution", "organization_id", "role_id", "separation_policy_id"]) && boundedIdentity(value.organization_id) && boundedIdentity(value.actor_id) && boundedIdentity(value.role_id) && boundedIdentity(value.separation_policy_id) && typeof value.custody_evidence_digest === "string" && SHA256.test(value.custody_evidence_digest) && typeof value.isolation_evidence_digest === "string" && SHA256.test(value.isolation_evidence_digest) && value.local_owner_substitution === false;
};
const validResearchGeneration = (value: unknown): value is TicketResearchGenerationV1 => {
  if (!researchObject(value) || !exactKeys(value, ["generation", "publication_receipt_digest", "remote_readback_commit", "remote_ref_matched", "tickets"]) || typeof value.generation !== "string" || !SHA256_GENERATION.test(value.generation) || typeof value.publication_receipt_digest !== "string" || !SHA256.test(value.publication_receipt_digest) || typeof value.remote_readback_commit !== "string" || !GIT_OID.test(value.remote_readback_commit) || typeof value.remote_ref_matched !== "boolean" || !Array.isArray(value.tickets) || value.tickets.length === 0 || value.tickets.length > 10_000 || !value.tickets.every(validTicketCandidate)) return false;
  return new Set(value.tickets.map((ticket) => ticket.ticket_id)).size === value.tickets.length;
};
const validResearchState = (value: unknown): value is TicketResearchActivationStateV1 => {
  if (!researchObject(value) || !exactKeys(value, ["active_generation", "active_ticket_id", "closed_ticket_ids", "schema_version"]) || value.schema_version !== 1 || typeof value.active_generation !== "string" || !SHA256_GENERATION.test(value.active_generation) || !(value.active_ticket_id === null || isTicketResearchIdV1(value.active_ticket_id)) || !Array.isArray(value.closed_ticket_ids) || value.closed_ticket_ids.length > 10_000) return false;
  return value.closed_ticket_ids.every(isTicketResearchIdV1) && new Set(value.closed_ticket_ids).size === value.closed_ticket_ids.length;
};
const canonicalResearchValue = (value: unknown): string => Array.isArray(value) ? `[${value.map(canonicalResearchValue).join(",")}]` : researchObject(value) ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalResearchValue(value[key])}`).join(",")}}` : JSON.stringify(value);
const ticketResearchDigest = (value: unknown) => createHash("sha256").update(canonicalResearchValue(value)).digest("hex");
const freezeResearch = <T>(value: T): T => { if (value !== null && typeof value === "object" && !Object.isFrozen(value)) { Object.freeze(value); for (const child of Object.values(value as Record<string, unknown>)) freezeResearch(child); } return value; };
const ticketResearchResult = (code: TicketResearchActivationCode, receipt: TicketResearchAuthorizationReceiptV1 | null = null): TicketResearchActivationResultV1 => freezeResearch({ advanced: code === "TICKET_RESEARCH_AUTHORIZED", code, receipt });

/** Atomically derive research-only authority for one selected, dependency-ready ticket. */
export function activateTicketResearch(value: TicketResearchActivationRequestV1): TicketResearchActivationResultV1 {
  let snapshot: TicketResearchActivationRequestV1;
  try { snapshot = structuredClone(value); } catch { return ticketResearchResult("MALFORMED_OR_UNKNOWN_FIELD"); }
  if (!researchObject(snapshot) || !exactKeys(snapshot, ["approved_generation", "authority", "expected_generation", "implementation_authorized", "schema_version", "selected_ticket_id", "state"]) || snapshot.schema_version !== 1 || typeof snapshot.expected_generation !== "string" || !SHA256_GENERATION.test(snapshot.expected_generation) || !isTicketResearchIdV1(snapshot.selected_ticket_id) || !validResearchGeneration(snapshot.approved_generation) || !validResearchState(snapshot.state) || !validResearchAuthority(snapshot.authority) || typeof snapshot.implementation_authorized !== "boolean") return ticketResearchResult("MALFORMED_OR_UNKNOWN_FIELD");
  if (!snapshot.approved_generation.remote_ref_matched) return ticketResearchResult("PREREQUISITE_AUTHORITY_INVALID");
  if (snapshot.expected_generation !== snapshot.approved_generation.generation || snapshot.expected_generation !== snapshot.state.active_generation) return ticketResearchResult("STALE_DERIVATION");
  const candidate = snapshot.approved_generation.tickets.find((ticket) => ticket.ticket_id === snapshot.selected_ticket_id);
  if (!candidate) return ticketResearchResult("ACTIVE_TICKET_CONFLICT");
  if (candidate.track !== snapshot.authority.kind) return ticketResearchResult("TRACK_AUTHORITY_SUBSTITUTION");
  const closed = new Set(snapshot.state.closed_ticket_ids);
  if (snapshot.state.active_ticket_id !== null || candidate.dependency_ticket_ids.some((dependency) => !closed.has(dependency))) return ticketResearchResult("ACTIVE_TICKET_CONFLICT");
  if (snapshot.implementation_authorized) return ticketResearchResult("DECOMPOSITION_CANNOT_AUTHORIZE_IMPLEMENTATION");
  const body = { schema_version: 1 as const, status: "TICKET_RESEARCH_AUTHORIZED" as const, ticket_id: candidate.ticket_id, generation: snapshot.expected_generation, publication_receipt_digest: snapshot.approved_generation.publication_receipt_digest, remote_readback_commit: snapshot.approved_generation.remote_readback_commit, track: candidate.track, authority: snapshot.authority, dependency_ticket_ids: candidate.dependency_ticket_ids, implementation_authorized: false as const };
  return ticketResearchResult("TICKET_RESEARCH_AUTHORIZED", freezeResearch({ ...body, receipt_digest: ticketResearchDigest(body) }));
}

/** Validate read-only progress for one internally consistent research authorization. */
export function validateTicketResearchProgressV1(value: TicketResearchProgressInputV1): TicketResearchProgressResultV1 {
  let snapshot: TicketResearchProgressInputV1;
  try { snapshot = structuredClone(value); } catch { return freezeResearch({ ok: false, code: "MALFORMED_OR_UNKNOWN_FIELD" }); }
  if (!researchObject(snapshot) || !exactKeys(snapshot, ["activation", "current_state", "receipt"]) || !validResearchState(snapshot.current_state)) return freezeResearch({ ok: false, code: "MALFORMED_OR_UNKNOWN_FIELD" });
  const activated = activateTicketResearch(snapshot.activation);
  if (!activated.advanced || activated.receipt === null) return freezeResearch({ ok: false, code: "MALFORMED_OR_UNKNOWN_FIELD" });
  if (canonicalResearchValue(activated.receipt) !== canonicalResearchValue(snapshot.receipt)) return freezeResearch({ ok: false, code: "RECEIPT_MISMATCH" });
  if (snapshot.current_state.active_generation !== snapshot.receipt.generation) return freezeResearch({ ok: false, code: "STALE_DERIVATION" });
  if (snapshot.current_state.active_ticket_id !== null && snapshot.current_state.active_ticket_id !== snapshot.receipt.ticket_id) return freezeResearch({ ok: false, code: "ACTIVE_TICKET_CONFLICT" });
  const closed = new Set(snapshot.current_state.closed_ticket_ids);
  if (snapshot.current_state.active_ticket_id !== null && closed.has(snapshot.current_state.active_ticket_id)) return freezeResearch({ ok: false, code: "ACTIVE_TICKET_CONFLICT" });
  if (snapshot.receipt.dependency_ticket_ids.some((id) => !closed.has(id))) return freezeResearch({ ok: false, code: "DEPENDENCY_CLOSURE_REGRESSED" });
  const approved = new Set(snapshot.activation.approved_generation.tickets.map((ticket) => ticket.ticket_id));
  const closedInGeneration = snapshot.current_state.closed_ticket_ids.filter((id) => approved.has(id));
  const closedOutsideGeneration = snapshot.current_state.closed_ticket_ids.filter((id) => !approved.has(id));
  const ticketStatus = snapshot.current_state.active_ticket_id === snapshot.receipt.ticket_id ? "ACTIVE" : closed.has(snapshot.receipt.ticket_id) ? "CLOSED" : "NOT_ACTIVE_NOT_CLOSED";
  return freezeResearch({ ok: true, code: "TICKET_RESEARCH_PROGRESS_VALID", progress: {
    schema_version: 1, status: "TICKET_RESEARCH_PROGRESS_VALID", generation: snapshot.receipt.generation,
    receipt_digest: snapshot.receipt.receipt_digest, active_ticket_id: snapshot.current_state.active_ticket_id,
    ticket_status: ticketStatus, approved_tickets: structuredClone(snapshot.activation.approved_generation.tickets),
    closed_in_generation: closedInGeneration, closed_outside_generation: closedOutsideGeneration,
    closed_in_generation_count: closedInGeneration.length, authoritative: false, effects_performed: false,
  } });
}

const STAGES = new Set<string>(PROJECT_STAGES);
const POSTURES = new Set<string>(["autonomous", "policy-calibrated", "approval-required"]);
const DOMAIN_KINDS = new Set<string>(DOMAIN_WORKFLOW_KINDS);
const STATUSES = new Set<string>([
  "running", "waiting-retry", "waiting-capability", "waiting-approval", "waiting-policy",
  "waiting-reconciliation", "paused-budget", "completed", "failed",
]);
const WAIT_FOR_STATUS: Readonly<Partial<Record<ProjectStatus, WaitState["kind"]>>> = {
  "waiting-retry": "retry",
  "waiting-capability": "capability",
  "waiting-approval": "approval",
  "waiting-policy": "policy",
  "waiting-reconciliation": "reconciliation",
};

const MAX_GOAL_BYTES = 1_000_000;
const MAX_NOTE_BYTES = 64_000;
const MAX_DEPTH = 64;
const MAX_ENTRIES = 100_000;

function record(value: unknown, at: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new InvalidProjectStateError(`${at} must be an object`);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new InvalidProjectStateError(`${at} must be a plain object`);
  const out = value as Record<string, unknown>;
  for (const key of Object.keys(out)) {
    if (key === "__proto__" || key === "prototype" || key === "constructor") throw new InvalidProjectStateError(`${at} contains unsafe key ${key}`);
  }
  return out;
}

function text(value: unknown, at: string, maxBytes = MAX_NOTE_BYTES): string {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > maxBytes) throw new InvalidProjectStateError(`${at} must be bounded text`);
  return value;
}

function natural(value: unknown, at: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new InvalidProjectStateError(`${at} must be a non-negative safe integer`);
  return value;
}

function validateJson(value: unknown, at: string, depth = 0, count = { value: 0 }): void {
  if (depth > MAX_DEPTH) throw new InvalidProjectStateError(`${at} exceeds maximum depth`);
  count.value += 1;
  if (count.value > MAX_ENTRIES) throw new InvalidProjectStateError(`${at} exceeds maximum entries`);
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new InvalidProjectStateError(`${at} contains a non-finite number`);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => validateJson(entry, `${at}[${index}]`, depth + 1, count));
    return;
  }
  const obj = record(value, at);
  for (const [key, entry] of Object.entries(obj)) validateJson(entry, `${at}.${key}`, depth + 1, count);
}

/** Decode untrusted durable JSON without guessing or silently migrating it. */
export function decodeProjectState(value: unknown): ProjectState {
  const obj = record(value, "state");
  if (obj["schemaVersion"] !== PROJECT_STATE_SCHEMA_VERSION) throw new InvalidProjectStateError("unsupported project state schemaVersion");
  const revision = natural(obj["revision"], "revision");
  const runId = text(obj["runId"], "runId", 1024);
  if (runId.length === 0) throw new InvalidProjectStateError("runId must not be empty");
  const goal = text(obj["goal"], "goal", MAX_GOAL_BYTES);
  const stage = text(obj["stage"], "stage") as Stage;
  if (!STAGES.has(stage)) throw new InvalidProjectStateError(`unknown stage ${stage}`);
  const posture = text(obj["posture"], "posture") as AuthorityPosture;
  if (!POSTURES.has(posture)) throw new InvalidProjectStateError(`unknown posture ${posture}`);
  const status = text(obj["status"], "status") as ProjectStatus;
  if (!STATUSES.has(status)) throw new InvalidProjectStateError(`unknown status ${status}`);
  const artifacts = record(obj["artifacts"], "artifacts");
  validateJson(artifacts, "artifacts");
  const retryObj = record(obj["retry"], "retry");
  const attemptsObj = record(retryObj["attemptsByStage"], "retry.attemptsByStage");
  const attemptsByStage: Partial<Record<Stage, number>> = {};
  for (const [key, attempt] of Object.entries(attemptsObj)) {
    if (!STAGES.has(key)) throw new InvalidProjectStateError(`unknown retry stage ${key}`);
    attemptsByStage[key as Stage] = natural(attempt, `retry.attemptsByStage.${key}`);
  }
  const retry: RetryState = {
    attemptsByStage,
    attemptsConsumed: natural(retryObj["attemptsConsumed"], "retry.attemptsConsumed"),
    runLimit: natural(retryObj["runLimit"], "retry.runLimit"),
  };
  if (retry.attemptsConsumed > retry.runLimit) throw new InvalidProjectStateError("retry attempts exceed run limit");
  if (!Array.isArray(obj["consumedSignals"]) || obj["consumedSignals"].length > 10_000) throw new InvalidProjectStateError("consumedSignals must be a bounded array");
  const consumedSignals = obj["consumedSignals"].map((entry, index) => text(entry, `consumedSignals[${index}]`, 4096));
  if (new Set(consumedSignals).size !== consumedSignals.length) throw new InvalidProjectStateError("consumedSignals must be unique");
  const stepsRemaining = natural(obj["stepsRemaining"], "stepsRemaining");
  const reworkCount = natural(obj["reworkCount"], "reworkCount");
  const noteValue = obj["note"];
  const note = noteValue === undefined ? undefined : text(noteValue, "note");
  const wait = obj["wait"] === undefined ? undefined : decodeWait(obj["wait"]);
  const strategy = obj["strategy"] === undefined ? undefined : decodeStrategy(obj["strategy"]);
  let projectId: import("../session/project_id.js").ProjectId | undefined;
  if (obj["projectId"] !== undefined) {
    try { projectId = (awaitProjectIdCheck(obj["projectId"])); } catch { throw new InvalidProjectStateError("invalid projectId"); }
  }
  const expectedWait = WAIT_FOR_STATUS[status];
  if ((expectedWait === undefined) !== (wait === undefined) || (expectedWait !== undefined && wait?.kind !== expectedWait)) {
    throw new InvalidProjectStateError(`status ${status} and wait do not match`);
  }
  return {
    schemaVersion: PROJECT_STATE_SCHEMA_VERSION, revision, runId, goal, stage, artifacts, posture,
    stepsRemaining, reworkCount, status, retry, consumedSignals,
    ...(projectId === undefined ? {} : { projectId }), ...(strategy === undefined ? {} : { strategy }), ...(wait === undefined ? {} : { wait }), ...(note === undefined ? {} : { note }),
  };
}

function awaitProjectIdCheck(value: unknown): import("../session/project_id.js").ProjectId {
  if (typeof value !== "string" || !/^prj_[0-9a-f]{32}$/u.test(value)) throw new Error("invalid project id");
  return value as import("../session/project_id.js").ProjectId;
}

function decodeStrategy(value: unknown): ProjectStrategy {
  const obj = record(value, "strategy");
  const kind = text(obj["kind"], "strategy.kind");
  if (kind === "software" && Object.keys(obj).length === 1) return { kind };
  if (kind === "domain" && Object.keys(obj).every((key) => key === "kind" || key === "domainKind")) {
    const domainKind = text(obj["domainKind"], "strategy.domainKind") as DomainWorkflowKind;
    if (DOMAIN_KINDS.has(domainKind)) return { kind, domainKind };
  }
  throw new InvalidProjectStateError("strategy must be exact software or known domain strategy");
}

function decodeWait(value: unknown): WaitState {
  const obj = record(value, "wait");
  const kind = text(obj["kind"], "wait.kind");
  const activity = text(obj["activity"], "wait.activity") as Stage;
  if (!STAGES.has(activity)) throw new InvalidProjectStateError(`unknown wait activity ${activity}`);
  const createdAt = natural(obj["createdAt"], "wait.createdAt");
  const reason = text(obj["reason"], "wait.reason");
  if (kind === "retry") return { kind, activity, createdAt, resumeAt: natural(obj["resumeAt"], "wait.resumeAt"), attempt: natural(obj["attempt"], "wait.attempt"), reason };
  if (kind === "capability") {
    const resumeAuthority = text(obj["resumeAuthority"], "wait.resumeAuthority");
    if (resumeAuthority !== "work" && resumeAuthority !== "approval") throw new InvalidProjectStateError(`unknown capability resumeAuthority ${resumeAuthority}`);
    return { kind, activity, createdAt, capability: text(obj["capability"], "wait.capability"), resumeAuthority, reason };
  }
  if (kind === "approval") {
    const severity = text(obj["severity"], "wait.severity");
    if (severity !== "routine" && severity !== "extreme") throw new InvalidProjectStateError(`unknown approval severity ${severity}`);
    const resumeMode = text(obj["resumeMode"], "wait.resumeMode");
    if (resumeMode !== "advance" && resumeMode !== "rerun") throw new InvalidProjectStateError(`unknown approval resumeMode ${resumeMode}`);
    return { kind, activity, createdAt, decisionId: text(obj["decisionId"], "wait.decisionId"), severity, resumeMode, reason };
  }
  if (kind === "policy") return { kind, activity, createdAt, policyId: text(obj["policyId"], "wait.policyId"), reason };
  if (kind === "reconciliation") return { kind, activity, createdAt, effectId: text(obj["effectId"], "wait.effectId"), reason };
  throw new InvalidProjectStateError(`unknown wait kind ${kind}`);
}
