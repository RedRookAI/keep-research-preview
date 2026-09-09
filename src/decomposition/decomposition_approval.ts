import { createHash } from "node:crypto";
import type { TwoRoundDecompositionReviewDispositionV1 } from "./decomposition_review.js";
import { decompositionReviewDigest } from "./decomposition_review.js";
import type { DecompositionTransitionResultV1, DecompositionTransitionStateV1 } from "./decomposition_transition.js";

export type DecompositionApprovalCode = "ADVANCED" | "MALFORMED_OR_UNKNOWN_FIELD" | "PREREQUISITE_AUTHORITY_INVALID" | "OWNER_APPROVAL_INVALID" | "APPROVED_GRAPH_MUTATED" | "AMENDMENT_AUTHORITY_INVALID" | "STALE_DERIVATION";
export type OwnerDecision = "OWNER_DECISION" | null;

export type TrustedDecompositionOwnerContextV1 =
  | { readonly schema_version: 1; readonly kind: "n1"; readonly owner_id: string; readonly custody_id: string; readonly organization_services: "ABSENT" }
  | { readonly schema_version: 1; readonly kind: "enterprise"; readonly organization_id: string; readonly actor_id: string; readonly role_id: string; readonly separation_policy_id: string; readonly custody_evidence_digest: string; readonly isolation_evidence_digest: string; readonly local_owner_substitution: false };

export type ExpectedDecompositionOwnerV1 =
  | { readonly kind: "n1"; readonly owner_id: string }
  | { readonly kind: "enterprise"; readonly organization_id: string; readonly actor_id: string; readonly role_id: string; readonly separation_policy_id: string };

export interface TrustedDecompositionApprovalScopeV1 {
  readonly schema_version: 1;
  readonly status: "DECOMPOSITION_APPROVAL_SCOPE_ADMITTED";
  readonly approved_inventory_digest: string;
  readonly generation: string;
  readonly graph_digest: string;
  readonly candidate_digest: string;
  readonly manifest_digest: string;
  readonly scope_digest: string;
  readonly parent_scope_ids: readonly string[];
  readonly proposed_scope_ids: readonly string[];
  readonly candidate_author_id: string;
  readonly candidate_author_family: string;
  readonly expected_owner: ExpectedDecompositionOwnerV1;
  readonly transition_state: DecompositionTransitionStateV1;
  readonly transition_result: DecompositionTransitionResultV1;
  readonly observed_graph_digest: string | null;
  readonly review_disposition: TwoRoundDecompositionReviewDispositionV1 | null;
  readonly architecture_authority_digest: string;
  readonly decomposition_authority_digest: string;
}

export interface DecompositionGenerationRecordV1 {
  readonly schema_version: 1;
  readonly generation: string;
  readonly parent_record_digest: string | null;
  readonly graph_digest: string;
  readonly candidate_digest: string;
  readonly manifest_digest: string;
  readonly scope_digest: string;
  readonly scope_ids: readonly string[];
  readonly amendment_authorization_digest: string | "GENESIS";
  readonly evidence_digests: readonly string[];
  readonly review_disposition_digest: string | null;
  readonly approval_digest: string | null;
  readonly status: "REVIEW_PENDING" | "APPROVED";
  readonly record_digest: string;
}

export interface DecompositionInvalidationObservationV1 { readonly schema_version: 1; readonly record_digest: string; readonly expected_graph_digest: string; readonly observed_graph_digest: string; readonly transition_result_digest: string; readonly owner_stop: "APPROVED_GRAPH_AMENDMENT_REQUIRES_OWNER"; readonly observation_digest: string }
export interface DecompositionApprovalStateV1 { readonly schema_version: 1; readonly generations: readonly DecompositionGenerationRecordV1[]; readonly invalidation_observations: readonly DecompositionInvalidationObservationV1[]; readonly implementation_authorized: false }

export type DecompositionApprovalActionV1 =
  | { readonly schema_version: 1; readonly kind: "APPROVE_GENERATION"; readonly expected_generation: string; readonly expected_record_digest: string; readonly approval_digest: string }
  | { readonly schema_version: 1; readonly kind: "OBSERVE_GRAPH"; readonly expected_generation: string; readonly expected_record_digest: string }
  | { readonly schema_version: 1; readonly kind: "AUTHORIZE_AMENDMENT"; readonly expected_generation: string; readonly expected_parent_record_digest: string; readonly new_generation: string; readonly new_graph_digest: string; readonly new_candidate_digest: string; readonly new_manifest_digest: string; readonly new_scope_digest: string; readonly prior_record_digests: readonly string[]; readonly prior_observation_digests: readonly string[]; readonly evidence_digests: readonly string[]; readonly amendment_authorization_digest: string };

export interface DecompositionApprovalResultV1 { readonly advanced: boolean; readonly code: DecompositionApprovalCode; readonly state: DecompositionApprovalStateV1 | null; readonly owner_stop: "APPROVED_GRAPH_AMENDMENT_REQUIRES_OWNER" | null; readonly decision: OwnerDecision; readonly transition_reentry: DecompositionTransitionStateV1 | null }

const INVENTORY = "f0b8b60c7b497b6422fc43afeb310d18ea3d28f3decfe666d44deb54963399db";
const HEX = /^[a-f0-9]{64}$/u;
const GEN = /^sha256:[a-f0-9]{64}$/u;
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const exact = (v: Record<string, unknown>, keys: readonly string[]) => { const a = Object.keys(v).sort(), b = [...keys].sort(); return a.length === b.length && a.every((x, i) => x === b[i]); };
const text = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length <= 256;
const hex = (v: unknown): v is string => typeof v === "string" && HEX.test(v);
const generation = (v: unknown): v is string => typeof v === "string" && GEN.test(v);
const stringSet = (v: unknown, hexOnly = false): v is readonly string[] => Array.isArray(v) && v.length <= 256 && v.every(hexOnly ? hex : text) && new Set(v).size === v.length;
const canonical = (v: unknown): string => Array.isArray(v) ? `[${v.map(canonical).join(",")}]` : object(v) ? `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}` : JSON.stringify(v);
export const decompositionApprovalDigest = (v: unknown) => createHash("sha256").update(canonical(v)).digest("hex");
const without = (v: Record<string, unknown>, key: string) => { const copy = { ...v }; delete copy[key]; return decompositionApprovalDigest(copy); };
const freeze = <T>(v: T): T => { if (v !== null && typeof v === "object" && !Object.isFrozen(v)) { Object.freeze(v); for (const child of Object.values(v as Record<string, unknown>)) freeze(child); } return v; };
const cloned = <T>(v: T): T => structuredClone(v);
const answer = (code: DecompositionApprovalCode, state: DecompositionApprovalStateV1 | null, stop: boolean, reentry: DecompositionTransitionStateV1 | null = null): DecompositionApprovalResultV1 => freeze({ advanced: code === "ADVANCED", code, state: state === null ? null : freeze(state), owner_stop: stop ? "APPROVED_GRAPH_AMENDMENT_REQUIRES_OWNER" : null, decision: stop ? "OWNER_DECISION" : null, transition_reentry: reentry === null ? null : freeze(reentry) });

const STATE_KEYS = ["generations", "implementation_authorized", "invalidation_observations", "schema_version"];
const RECORD_KEYS = ["amendment_authorization_digest", "approval_digest", "candidate_digest", "evidence_digests", "generation", "graph_digest", "manifest_digest", "parent_record_digest", "record_digest", "review_disposition_digest", "schema_version", "scope_digest", "scope_ids", "status"];
const OBS_KEYS = ["expected_graph_digest", "observation_digest", "observed_graph_digest", "owner_stop", "record_digest", "schema_version", "transition_result_digest"];
const SCOPE_KEYS = ["approved_inventory_digest", "architecture_authority_digest", "candidate_author_family", "candidate_author_id", "candidate_digest", "decomposition_authority_digest", "expected_owner", "generation", "graph_digest", "manifest_digest", "observed_graph_digest", "parent_scope_ids", "proposed_scope_ids", "review_disposition", "schema_version", "scope_digest", "status", "transition_result", "transition_state"];
const ACTION_KEYS = { APPROVE_GENERATION: ["approval_digest", "expected_generation", "expected_record_digest", "kind", "schema_version"], OBSERVE_GRAPH: ["expected_generation", "expected_record_digest", "kind", "schema_version"], AUTHORIZE_AMENDMENT: ["amendment_authorization_digest", "evidence_digests", "expected_generation", "expected_parent_record_digest", "kind", "new_candidate_digest", "new_generation", "new_graph_digest", "new_manifest_digest", "new_scope_digest", "prior_observation_digests", "prior_record_digests", "schema_version"] } as const;

function validRecord(v: unknown): v is DecompositionGenerationRecordV1 { return object(v) && exact(v, RECORD_KEYS) && v.schema_version === 1 && generation(v.generation) && (v.parent_record_digest === null || hex(v.parent_record_digest)) && [v.graph_digest,v.candidate_digest,v.manifest_digest,v.scope_digest].every(hex) && stringSet(v.scope_ids) && (v.amendment_authorization_digest === "GENESIS" || hex(v.amendment_authorization_digest)) && stringSet(v.evidence_digests,true) && (v.review_disposition_digest === null || hex(v.review_disposition_digest)) && (v.approval_digest === null || hex(v.approval_digest)) && ["REVIEW_PENDING","APPROVED"].includes(v.status as string) && hex(v.record_digest) && v.record_digest === without(v,"record_digest"); }
function validObservation(v: unknown): v is DecompositionInvalidationObservationV1 { return object(v) && exact(v, OBS_KEYS) && v.schema_version === 1 && [v.record_digest,v.expected_graph_digest,v.observed_graph_digest,v.transition_result_digest,v.observation_digest].every(hex) && v.owner_stop === "APPROVED_GRAPH_AMENDMENT_REQUIRES_OWNER" && v.observation_digest === without(v,"observation_digest"); }
function validState(v: unknown): v is DecompositionApprovalStateV1 { if (!object(v) || !exact(v,STATE_KEYS) || v.schema_version !== 1 || v.implementation_authorized !== false || !Array.isArray(v.generations) || v.generations.length < 1 || v.generations.length > 256 || !v.generations.every(validRecord) || !Array.isArray(v.invalidation_observations) || v.invalidation_observations.length > 256 || !v.invalidation_observations.every(validObservation)) return false; const records=v.generations as DecompositionGenerationRecordV1[], observations=v.invalidation_observations as DecompositionInvalidationObservationV1[]; return new Set(records.map(x=>x.record_digest)).size===records.length && new Set(observations.map(x=>x.observation_digest)).size===observations.length && records.every((x,i)=>i===0 ? x.parent_record_digest===null : x.parent_record_digest===records[i-1]!.record_digest); }
function validOwner(v: unknown): v is TrustedDecompositionOwnerContextV1 { if (!object(v) || v.schema_version !== 1) return false; if (v.kind === "n1") return exact(v,["custody_id","kind","organization_services","owner_id","schema_version"]) && text(v.owner_id) && text(v.custody_id) && v.organization_services === "ABSENT"; return v.kind === "enterprise" && exact(v,["actor_id","custody_evidence_digest","isolation_evidence_digest","kind","local_owner_substitution","organization_id","role_id","schema_version","separation_policy_id"]) && [v.organization_id,v.actor_id,v.role_id,v.separation_policy_id].every(text) && hex(v.custody_evidence_digest) && hex(v.isolation_evidence_digest) && v.local_owner_substitution===false; }
function recognizableDisposition(v:unknown):v is TwoRoundDecompositionReviewDispositionV1 { if(!object(v)||!exact(v,["candidate_digest","disposition_digest","generation","manifest_digest","open_findings","repair_chains","reviewers","schema_version","scope_digest","status","used"])||v.schema_version!==1||v.status!=="TWO_ROUND_DECOMPOSITION_REVIEW_COMPLETE"||v.used!==2||!generation(v.generation)||![v.candidate_digest,v.manifest_digest,v.scope_digest,v.disposition_digest].every(hex)||!Array.isArray(v.open_findings)||v.open_findings.length!==0||!Array.isArray(v.reviewers)||v.reviewers.length!==2||!Array.isArray(v.repair_chains)||v.repair_chains.length>6)return false; return v.reviewers.every(row=>object(row)&&exact(row,["reviewer_family","reviewer_id","round","track"])&&[1,2].includes(row.round as number)&&text(row.reviewer_id)&&text(row.reviewer_family)&&["n1","enterprise"].includes(row.track as string))&&v.repair_chains.every(row=>object(row)&&exact(row,["candidate_digest","digest","kind","reviewer_id","round"])&&["REVIEW","REPAIR","CONFIRMATION"].includes(row.kind as string)&&[1,2].includes(row.round as number)&&text(row.reviewer_id)&&hex(row.digest)&&hex(row.candidate_digest)); }
const TRANSITION_PHASES=["ARCHITECTURE_AUTHORIZED","ARCHITECTURE_CANDIDATE","ARCHITECTURE_VALIDATED","DECOMPOSITION_AUTHORIZED","DECOMPOSITION_CANDIDATE","DECOMPOSITION_STRUCTURAL_PASS","DECOMPOSITION_VET_1","DECOMPOSITION_VET_1_PASS","DECOMPOSITION_VET_2","DECOMPOSITION_VET_2_PASS","OWNER_APPROVAL_PENDING","OWNER_APPROVED","DECOMPOSITION_REMOTE_READBACK_PASS","FIRST_TICKET_RESEARCH_AUTHORIZED"];
const DERIVED=["architecture","decomposition","owner_approval","ticket_activation"];
function validTransitionState(v:unknown):v is DecompositionTransitionStateV1 { if(!object(v)||!exact(v,["active_generation","approved_graph_digest","derived_authorities","phase","schema_version"])||v.schema_version!==1||!TRANSITION_PHASES.includes(v.phase as string)||!hex(v.approved_graph_digest)||!generation(v.active_generation)||!object(v.derived_authorities)||!exact(v.derived_authorities,DERIVED)) return false; const derived=v.derived_authorities as Record<string,unknown>; return DERIVED.every(k=>{const row=derived[k];return object(row)&&exact(row,["depends_on","digest","status"])&&hex(row.digest)&&stringSet(row.depends_on)&&["ACTIVE","STALE_DERIVATION"].includes(row.status as string);}); }
function validTransitionResult(v:unknown):v is DecompositionTransitionResultV1 { return object(v)&&exact(v,["advanced","code","owner_stop","stale_descendants","state"])&&["ADVANCED","MALFORMED_OR_UNKNOWN_FIELD","ILLEGAL_PHASE_EDGE","NON_AUTHORITATIVE_FIXTURE","CANONICAL_WRITER_FENCED","APPROVED_GRAPH_MUTATED","STALE_DERIVATION"].includes(v.code as string)&&typeof v.advanced==="boolean"&&v.advanced===(v.code==="ADVANCED")&&Array.isArray(v.stale_descendants)&&v.stale_descendants.length<=4&&v.stale_descendants.every(x=>DERIVED.includes(x))&&new Set(v.stale_descendants).size===v.stale_descendants.length&&(v.owner_stop===null||v.owner_stop==="APPROVED_GRAPH_AMENDMENT_REQUIRES_OWNER")&&(v.state===null||validTransitionState(v.state)); }
function validScope(v: unknown): v is TrustedDecompositionApprovalScopeV1 { if (!object(v) || !exact(v,SCOPE_KEYS) || v.schema_version!==1 || v.status!=="DECOMPOSITION_APPROVAL_SCOPE_ADMITTED" || v.approved_inventory_digest!==INVENTORY || !generation(v.generation) || ![v.graph_digest,v.candidate_digest,v.manifest_digest,v.scope_digest,v.architecture_authority_digest,v.decomposition_authority_digest].every(hex) || !(v.observed_graph_digest===null||hex(v.observed_graph_digest)) || !stringSet(v.parent_scope_ids) || !stringSet(v.proposed_scope_ids) || !text(v.candidate_author_id) || !text(v.candidate_author_family) || !object(v.expected_owner)) return false; const eo=v.expected_owner; if (eo.kind==="n1") { if (!exact(eo,["kind","owner_id"]) || !text(eo.owner_id)) return false; } else if (eo.kind==="enterprise") { if (!exact(eo,["actor_id","kind","organization_id","role_id","separation_policy_id"]) || ![eo.organization_id,eo.actor_id,eo.role_id,eo.separation_policy_id].every(text)) return false; } else return false; return validTransitionState(v.transition_state) && validTransitionResult(v.transition_result) && (v.review_disposition===null || recognizableDisposition(v.review_disposition)); }
function validAction(v: unknown): v is DecompositionApprovalActionV1 { if (!object(v) || v.schema_version!==1 || typeof v.kind!=="string" || !(v.kind in ACTION_KEYS) || !exact(v,ACTION_KEYS[v.kind as keyof typeof ACTION_KEYS])) return false; if (v.kind==="APPROVE_GENERATION") return generation(v.expected_generation)&&hex(v.expected_record_digest)&&hex(v.approval_digest); if(v.kind==="OBSERVE_GRAPH") return generation(v.expected_generation)&&hex(v.expected_record_digest); return generation(v.expected_generation)&&hex(v.expected_parent_record_digest)&&generation(v.new_generation)&&[v.new_graph_digest,v.new_candidate_digest,v.new_manifest_digest,v.new_scope_digest,v.amendment_authorization_digest].every(hex)&&stringSet(v.prior_record_digests,true)&&stringSet(v.prior_observation_digests,true)&&stringSet(v.evidence_digests,true); }
function ownerMatches(owner: TrustedDecompositionOwnerContextV1, expected: ExpectedDecompositionOwnerV1) { return owner.kind===expected.kind && (owner.kind==="n1" ? owner.owner_id===(expected as Extract<ExpectedDecompositionOwnerV1,{kind:"n1"}>).owner_id : owner.organization_id===(expected as Extract<ExpectedDecompositionOwnerV1,{kind:"enterprise"}>).organization_id && owner.actor_id===(expected as Extract<ExpectedDecompositionOwnerV1,{kind:"enterprise"}>).actor_id && owner.role_id===(expected as Extract<ExpectedDecompositionOwnerV1,{kind:"enterprise"}>).role_id && owner.separation_policy_id===(expected as Extract<ExpectedDecompositionOwnerV1,{kind:"enterprise"}>).separation_policy_id); }
function validDisposition(d: TwoRoundDecompositionReviewDispositionV1 | null, scope: TrustedDecompositionApprovalScopeV1) { if (!d || !recognizableDisposition(d) || d.reviewers[0]?.round!==1 || d.reviewers[1]?.round!==2 || d.reviewers[0].reviewer_id===d.reviewers[1].reviewer_id || d.reviewers[0].reviewer_family===d.reviewers[1].reviewer_family || d.generation!==scope.generation || d.candidate_digest!==scope.candidate_digest || d.manifest_digest!==scope.manifest_digest || d.scope_digest!==scope.scope_digest) return false; const body={schema_version:d.schema_version,status:d.status,generation:d.generation,candidate_digest:d.candidate_digest,manifest_digest:d.manifest_digest,scope_digest:d.scope_digest,used:d.used,reviewers:d.reviewers,repair_chains:d.repair_chains,open_findings:d.open_findings}; return d.disposition_digest===decompositionReviewDigest(body); }
function t001IdentityAgrees(scope: TrustedDecompositionApprovalScopeV1) { const s=scope.transition_state,r=scope.transition_result; return s.active_generation===scope.generation && s.approved_graph_digest===scope.graph_digest && r.state?.active_generation===scope.generation && r.state.approved_graph_digest===scope.graph_digest; }
function t001ApprovalReady(scope:TrustedDecompositionApprovalScopeV1){return t001IdentityAgrees(scope)&&scope.transition_result.code==="ADVANCED"&&scope.observed_graph_digest===null&&DERIVED.every(k=>scope.transition_state.derived_authorities[k as keyof typeof scope.transition_state.derived_authorities].status==="ACTIVE")&&DERIVED.every(k=>scope.transition_result.state!.derived_authorities[k as keyof typeof scope.transition_state.derived_authorities].status==="ACTIVE");}

export function initialDecompositionApprovalState(scopeInput: unknown): DecompositionApprovalStateV1 { const scope=cloned(scopeInput); if(!validScope(scope)) throw new Error("invalid decomposition approval scope"); const body={schema_version:1 as const,generation:scope.generation,parent_record_digest:null,graph_digest:scope.graph_digest,candidate_digest:scope.candidate_digest,manifest_digest:scope.manifest_digest,scope_digest:scope.scope_digest,scope_ids:[...scope.parent_scope_ids],amendment_authorization_digest:"GENESIS" as const,evidence_digests:[] as readonly string[],review_disposition_digest:null,approval_digest:null,status:"REVIEW_PENDING" as const}; return freeze({schema_version:1,generations:[{...body,record_digest:decompositionApprovalDigest(body)}],invalidation_observations:[],implementation_authorized:false}); }

export function advanceDecompositionApproval(stateInput: unknown, actionInput: unknown, ownerInput: unknown, scopeInput: unknown): DecompositionApprovalResultV1 {
  let state:unknown,action:unknown,owner:unknown,scope:unknown; try { state=cloned(stateInput); action=cloned(actionInput); owner=cloned(ownerInput); scope=cloned(scopeInput); } catch { return answer("MALFORMED_OR_UNKNOWN_FIELD",null,false); }
  if(!validState(state)||!validAction(action)||!validOwner(owner)||!validScope(scope)) return answer("MALFORMED_OR_UNKNOWN_FIELD",validState(state)?state:null,false);
  const current=state.generations[state.generations.length-1]!;
  if(!t001IdentityAgrees(scope) || scope.generation!==current.generation || scope.graph_digest!==current.graph_digest || scope.candidate_digest!==current.candidate_digest || scope.manifest_digest!==current.manifest_digest || scope.scope_digest!==current.scope_digest) return answer("PREREQUISITE_AUTHORITY_INVALID",state,false);
  if(action.kind==="APPROVE_GENERATION") {
    const approvalBody={schema_version:action.schema_version,kind:action.kind,expected_generation:action.expected_generation,expected_record_digest:action.expected_record_digest,owner,disposition_digest:scope.review_disposition?.disposition_digest??null};
    if(!t001ApprovalReady(scope)) return answer("PREREQUISITE_AUTHORITY_INVALID",state,false);
    if(current.status!=="REVIEW_PENDING" || action.expected_generation!==current.generation || action.expected_record_digest!==current.record_digest || !ownerMatches(owner,scope.expected_owner) || (owner.kind==="n1"?owner.owner_id:owner.actor_id)===scope.candidate_author_id || !validDisposition(scope.review_disposition,scope) || action.approval_digest!==decompositionApprovalDigest(approvalBody)) return answer("OWNER_APPROVAL_INVALID",state,false);
    const body={...current,parent_record_digest:current.record_digest,review_disposition_digest:scope.review_disposition!.disposition_digest,approval_digest:action.approval_digest,status:"APPROVED" as const}; delete (body as {record_digest?:string}).record_digest;
    return answer("ADVANCED",{...state,generations:[...state.generations,{...body,record_digest:decompositionApprovalDigest(body)}]},false);
  }
  if(action.kind==="OBSERVE_GRAPH") {
    if(action.expected_generation!==current.generation || action.expected_record_digest!==current.record_digest) return answer("STALE_DERIVATION",state,false);
    if(scope.transition_result.code!=="APPROVED_GRAPH_MUTATED") return scope.transition_result.code==="ADVANCED" && scope.observed_graph_digest===null ? answer("ADVANCED",state,false) : answer("PREREQUISITE_AUTHORITY_INVALID",state,false);
    if(current.status!=="APPROVED" || scope.transition_result.owner_stop!=="APPROVED_GRAPH_AMENDMENT_REQUIRES_OWNER" || scope.observed_graph_digest===null || scope.observed_graph_digest===current.graph_digest) return answer("PREREQUISITE_AUTHORITY_INVALID",state,false);
    const body={schema_version:1 as const,record_digest:current.record_digest,expected_graph_digest:current.graph_digest,observed_graph_digest:scope.observed_graph_digest,transition_result_digest:decompositionApprovalDigest(scope.transition_result),owner_stop:"APPROVED_GRAPH_AMENDMENT_REQUIRES_OWNER" as const};
    const observation={...body,observation_digest:decompositionApprovalDigest(body)}; if(state.invalidation_observations.some(x=>x.observation_digest===observation.observation_digest)) return answer("APPROVED_GRAPH_MUTATED",state,true);
    return answer("APPROVED_GRAPH_MUTATED",{...state,invalidation_observations:[...state.invalidation_observations,observation]},true);
  }
  const recordPrefix=state.generations.map(x=>x.record_digest), observationPrefix=state.invalidation_observations.map(x=>x.observation_digest), actor=owner.kind==="n1"?owner.owner_id:owner.actor_id;
  const authBody={schema_version:action.schema_version,kind:action.kind,expected_generation:action.expected_generation,expected_parent_record_digest:action.expected_parent_record_digest,new_generation:action.new_generation,new_graph_digest:action.new_graph_digest,new_candidate_digest:action.new_candidate_digest,new_manifest_digest:action.new_manifest_digest,new_scope_digest:action.new_scope_digest,prior_record_digests:action.prior_record_digests,prior_observation_digests:action.prior_observation_digests,evidence_digests:action.evidence_digests,owner};
  const invalid=current.status!=="APPROVED" || state.invalidation_observations.length===0 || action.expected_generation!==current.generation || action.expected_parent_record_digest!==current.record_digest || action.new_generation===current.generation || action.new_graph_digest===current.graph_digest || !ownerMatches(owner,scope.expected_owner) || actor===scope.candidate_author_id || canonical(action.prior_record_digests)!==canonical(recordPrefix) || canonical(action.prior_observation_digests)!==canonical(observationPrefix) || canonical(scope.parent_scope_ids)!==canonical(current.scope_ids) || !current.scope_ids.every(id=>scope.proposed_scope_ids.includes(id)) || action.amendment_authorization_digest!==decompositionApprovalDigest(authBody);
  if(invalid) return answer("AMENDMENT_AUTHORITY_INVALID",state,true);
  const body={schema_version:1 as const,generation:action.new_generation,parent_record_digest:current.record_digest,graph_digest:action.new_graph_digest,candidate_digest:action.new_candidate_digest,manifest_digest:action.new_manifest_digest,scope_digest:action.new_scope_digest,scope_ids:[...scope.proposed_scope_ids],amendment_authorization_digest:action.amendment_authorization_digest,evidence_digests:[...action.evidence_digests],review_disposition_digest:null,approval_digest:null,status:"REVIEW_PENDING" as const};
  const reentry:DecompositionTransitionStateV1={schema_version:1,phase:"DECOMPOSITION_CANDIDATE",approved_graph_digest:action.new_graph_digest,active_generation:action.new_generation,derived_authorities:{architecture:{digest:scope.architecture_authority_digest,depends_on:[],status:"ACTIVE"},decomposition:{digest:scope.decomposition_authority_digest,depends_on:[scope.architecture_authority_digest],status:"ACTIVE"},owner_approval:{digest:decompositionApprovalDigest(body),depends_on:[scope.decomposition_authority_digest],status:"STALE_DERIVATION"},ticket_activation:{digest:decompositionApprovalDigest(action),depends_on:[scope.decomposition_authority_digest],status:"STALE_DERIVATION"}}};
  return answer("ADVANCED",{...state,generations:[...state.generations,{...body,record_digest:decompositionApprovalDigest(body)}]},false,reentry);
}
