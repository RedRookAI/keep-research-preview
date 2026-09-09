import { createHash } from "node:crypto";

export type GoalTrack = "n1" | "enterprise";
export type GoalDenial =
  | "MALFORMED_OR_UNKNOWN_FIELD" | "DEPENDENCY_CLOSURE_MISSING" | "INCOMPLETE_GOAL_BODY"
  | "TITLE_OR_SUMMARY_NOT_AUTHORITY" | "GOAL_IDENTITY_MISMATCH" | "AUTHORITY_CONTEXT_INVALID"
  | "UNKNOWN_SCOPE_ID" | "SCOPE_REDUCTION_REQUIRES_OWNER" | "TRACK_AUTHORITY_SUBSTITUTION"
  | "N1_ENTERPRISE_CEREMONY_FORBIDDEN" | "ENTERPRISE_AUTHORITY_REQUIRED" | "GOAL_CANNOT_AUTHORIZE_EXECUTION";

export interface GoalBodyV1 {
  schema_version: 1;
  goal_id: string;
  outcome: string;
  authority: { kind: "owner"; owner_id: string; custody_id: string } | { kind: "organization"; organization_id: string; actor_id: string; role_id: string; separation_policy_id: string };
  scope_ids: string[];
  track_obligations: { n1: string[]; enterprise: string[]; parity: string[]; equivalent: false };
  assumptions: string[];
  finish_conditions: string[];
  non_goals: Array<{ statement: string; retained_by: string[] }>;
  research_contract: { current: string[]; historical: string[]; cross_disciplinary: string[] };
  adverse_evidence_questions: string[];
  falsifiers: string[];
  dependency_closures: Array<{ id: string; digest: string }>;
  created_by: string;
  created_at: string;
  executable: false;
}

export type AuthorityContextV1 =
  | { kind: "n1"; goal_digest: string; decision_id: string; decided_at: string; principal_id: string; authority_domain: "local-owner"; verification_result: "PASS"; custody_id: string }
  | { kind: "enterprise"; goal_digest: string; decision_id: string; decided_at: string; principal_id: string; authority_domain: "organization"; verification_result: "PASS"; organization_id: string; role_id: string; separation_policy_id: string; evidence_digest: string };

export interface GoalScopeAuthorityV1 {
  known_scope_ids: readonly string[];
  required_scope_ids: readonly string[];
  required_track_obligations: Readonly<{ n1: readonly string[]; enterprise: readonly string[]; parity: readonly string[] }>;
  dependency_closures: Readonly<Record<string, string>>;
  owner_reduction_decision?: true;
}

export interface AdmittedGoalAuthorityV1 { status: "GOAL_ADMITTED"; goal_digest: string; body: GoalBodyV1; authority_context: AuthorityContextV1; executable: false }
export type GoalAdmissionResult = { admitted: true; authority: AdmittedGoalAuthorityV1 } | { admitted: false; denial: GoalDenial };

const BODY_KEYS = ["schema_version","goal_id","outcome","authority","scope_ids","track_obligations","assumptions","finish_conditions","non_goals","research_contract","adverse_evidence_questions","falsifiers","dependency_closures","created_by","created_at","executable"].sort();
const HEX = /^[a-f0-9]{64}$/u;
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const exactKeys = (value: Record<string, unknown>, keys: readonly string[]) => JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
const strings = (value: unknown): value is string[] => Array.isArray(value) && value.every((entry) => typeof entry === "string" && entry.length > 0);
const hasUnknownNestedField = (body: Record<string, unknown>): boolean => {
  const authority = body.authority, tracks = body.track_obligations, research = body.research_contract;
  if (object(authority) && !Object.keys(authority).every((key) => (authority.kind === "owner" ? ["kind","owner_id","custody_id"] : ["kind","organization_id","actor_id","role_id","separation_policy_id"]).includes(key))) return true;
  if (object(tracks) && !Object.keys(tracks).every((key) => ["n1","enterprise","parity","equivalent"].includes(key))) return true;
  if (object(research) && !Object.keys(research).every((key) => ["current","historical","cross_disciplinary"].includes(key))) return true;
  if (Array.isArray(body.non_goals) && body.non_goals.some((entry) => object(entry) && !Object.keys(entry).every((key) => ["statement","retained_by"].includes(key)))) return true;
  return Array.isArray(body.dependency_closures) && body.dependency_closures.some((entry) => object(entry) && !Object.keys(entry).every((key) => ["id","digest"].includes(key)));
};
const stable = (value: unknown): unknown => Array.isArray(value) ? value.map(stable) : object(value) ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])])) : value;
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const freeze = <T>(value: T): T => { if (value && typeof value === "object") { Object.freeze(value); for (const child of Object.values(value as Record<string, unknown>)) freeze(child); } return value; };

export function canonicalGoalProjection(body: GoalBodyV1): string {
  return JSON.stringify(stable(body));
}
export function goalDigest(body: GoalBodyV1): string {
  return createHash("sha256").update(canonicalGoalProjection(body)).digest("hex");
}
const deny = (denial: GoalDenial): GoalAdmissionResult => ({ admitted: false, denial });

function complete(body: Record<string, unknown>): boolean {
  const authority = body.authority, tracks = body.track_obligations, research = body.research_contract;
  return body.schema_version === 1 && typeof body.goal_id === "string" && body.goal_id.length > 0 && typeof body.outcome === "string" && body.outcome.length > 0
    && object(authority) && (authority.kind === "owner" ? exactKeys(authority,["kind","owner_id","custody_id"]) && typeof authority.owner_id === "string" && typeof authority.custody_id === "string" : authority.kind === "organization" && exactKeys(authority,["kind","organization_id","actor_id","role_id","separation_policy_id"]) && [authority.organization_id,authority.actor_id,authority.role_id,authority.separation_policy_id].every((x) => typeof x === "string" && x.length > 0))
    && strings(body.scope_ids) && object(tracks) && exactKeys(tracks,["n1","enterprise","parity","equivalent"]) && strings(tracks.n1) && strings(tracks.enterprise) && strings(tracks.parity) && typeof tracks.equivalent === "boolean"
    && strings(body.assumptions) && strings(body.finish_conditions) && Array.isArray(body.non_goals) && body.non_goals.length > 0 && body.non_goals.every((entry) => object(entry) && exactKeys(entry,["statement","retained_by"]) && typeof entry.statement === "string" && entry.statement.length > 0 && strings(entry.retained_by))
    && object(research) && exactKeys(research,["current","historical","cross_disciplinary"]) && strings(research.current) && strings(research.historical) && strings(research.cross_disciplinary)
    && strings(body.adverse_evidence_questions) && strings(body.falsifiers) && Array.isArray(body.dependency_closures) && body.dependency_closures.every((entry) => object(entry) && exactKeys(entry,["id","digest"]) && typeof entry.id === "string" && entry.id.length > 0 && typeof entry.digest === "string" && HEX.test(entry.digest))
    && typeof body.created_by === "string" && body.created_by.length > 0 && typeof body.created_at === "string" && body.created_at.length > 0 && typeof body.executable === "boolean";
}

export function admitGoal(previous: AdmittedGoalAuthorityV1 | null, candidate: unknown, authorityContext: AuthorityContextV1 | null, scope: GoalScopeAuthorityV1): GoalAdmissionResult {
  if (!object(candidate)) return deny("MALFORMED_OR_UNKNOWN_FIELD");
  const displayKeys = Object.keys(candidate).sort(), display = (candidate.kind === "goal-display" && displayKeys.every((key) => ["goal_digest","goal_id","kind","summary","title"].includes(key))) || (displayKeys.every((key) => ["goal_digest","goal_id","summary","title"].includes(key)) && ("title" in candidate || "summary" in candidate));
  const fullCandidate = exactKeys(candidate,["body","goal_digest"]) || exactKeys(candidate,["authority_context","body","goal_digest"]) || exactKeys(candidate,["body","goal_digest","ticket_authority"]);
  if (!fullCandidate) return display ? deny("TITLE_OR_SUMMARY_NOT_AUTHORITY") : deny("MALFORMED_OR_UNKNOWN_FIELD");
  if (!object(candidate.body)) return deny("INCOMPLETE_GOAL_BODY");
  const body = candidate.body;
  if (Object.keys(body).some((key) => !BODY_KEYS.includes(key))) return deny("MALFORMED_OR_UNKNOWN_FIELD");
  if (hasUnknownNestedField(body)) return deny("MALFORMED_OR_UNKNOWN_FIELD");
  const closures = Array.isArray(body.dependency_closures) ? body.dependency_closures : [];
  const dependencyValid = Object.entries(scope.dependency_closures).every(([id,digest]) => closures.some((entry) => object(entry) && entry.id === id && entry.digest === digest));
  if (!dependencyValid) return deny("DEPENDENCY_CLOSURE_MISSING");
  if (!complete(body)) return deny("INCOMPLETE_GOAL_BODY");
  const validBody = body as unknown as GoalBodyV1;
  if (typeof candidate.goal_digest !== "string" || candidate.goal_digest !== goalDigest(validBody)) return deny("GOAL_IDENTITY_MISMATCH");
  if (!authorityContext || authorityContext.verification_result !== "PASS" || authorityContext.goal_digest !== candidate.goal_digest) return deny("AUTHORITY_CONTEXT_INVALID");
  if (validBody.authority.kind === "owner" && authorityContext.kind === "enterprise") return deny("N1_ENTERPRISE_CEREMONY_FORBIDDEN");
  if (validBody.authority.kind === "organization" && authorityContext.kind === "n1") return deny("ENTERPRISE_AUTHORITY_REQUIRED");
  if (validBody.authority.kind === "owner" && (authorityContext.authority_domain !== "local-owner" || authorityContext.principal_id !== validBody.authority.owner_id || authorityContext.custody_id !== validBody.authority.custody_id)) return deny("TRACK_AUTHORITY_SUBSTITUTION");
  if (validBody.authority.kind === "organization" && (authorityContext.authority_domain !== "organization" || authorityContext.organization_id !== validBody.authority.organization_id || authorityContext.principal_id !== validBody.authority.actor_id || authorityContext.role_id !== validBody.authority.role_id || authorityContext.separation_policy_id !== validBody.authority.separation_policy_id || !HEX.test(authorityContext.evidence_digest))) return deny("TRACK_AUTHORITY_SUBSTITUTION");
  if (validBody.scope_ids.some((id) => !scope.known_scope_ids.includes(id))) return deny("UNKNOWN_SCOPE_ID");
  const retains = (actual: readonly string[], required: readonly string[]) => required.every((value) => actual.includes(value));
  const reduced = scope.required_scope_ids.some((id) => !validBody.scope_ids.includes(id)) || !retains(validBody.track_obligations.n1,scope.required_track_obligations.n1) || !retains(validBody.track_obligations.enterprise,scope.required_track_obligations.enterprise) || !retains(validBody.track_obligations.parity,scope.required_track_obligations.parity) || validBody.track_obligations.equivalent !== false;
  if (reduced && scope.owner_reduction_decision !== true) return deny("SCOPE_REDUCTION_REQUIRES_OWNER");
  if (validBody.executable !== false || "ticket_authority" in candidate) return deny("GOAL_CANNOT_AUTHORIZE_EXECUTION");
  const admittedBody = freeze(clone(validBody));
  return { admitted: true, authority: freeze({ status:"GOAL_ADMITTED", goal_digest:candidate.goal_digest, body:admittedBody, authority_context:clone(authorityContext), executable:false }) };
}
