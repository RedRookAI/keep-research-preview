import { decodeCanonical, eirDigest } from "../eir/canonical.js";
import type { AuthoritativeReplayV1Event, AuthoritativeReplayV1Result } from "../spine/authoritative_replay_v1.js";
import { EventAdmissionV1HeadDigestDomain } from "../spine/event_admission_v1.js";
import { EventEnvelopeV1Encode } from "../spine/event_envelope_v1.js";
import { advanceDecompositionApproval, type DecompositionApprovalActionV1, type DecompositionApprovalResultV1, type DecompositionApprovalStateV1, type TrustedDecompositionApprovalScopeV1, type TrustedDecompositionOwnerContextV1 } from "./decomposition_approval.js";
import { reconstructDecompositionAuthorityV1, type DecompositionAuthorityReplayBundleV1, type DecompositionEventAuthorityContextV1 } from "./decomposition_review_events_v1.js";
import { verifyDecompositionPublication, type DecompositionPublicationInputV1, type DecompositionPublicationResultV1, type DecompositionPublicationReceiptV1 } from "./decomposition_publication.js";
import { admitExecutableTicket, type AdmittedTicketAuthorityV1, type ExecutableTicketBodyV1, type TicketAdmissionResult, type TicketAdmissionScopeV1 } from "./ticket_contract.js";
import type { DecompositionAuthorityContextV1, DecompositionTransitionResultV1 } from "./decomposition_transition.js";

export const DECOMPOSITION_APPROVAL_EVENT_MIGRATED_WRITERS_V1 = Object.freeze(["W07", "W08", "W09"] as const);
export type DecompositionApprovalEventCodeV1 = "DECOMPOSITION_APPROVAL_HISTORY_INVALID" | "INCOMPLETE_DECOMPOSITION_HISTORY" | "TRACK_AUTHORITY_SUBSTITUTION" | "PREREQUISITE_AUTHORITY_INVALID" | "LEGACY_AUTHORITY_GAP" | "LEGACY_APPROVAL_MUTATION_REJECTED";

export type DecompositionApprovalAuthorityEventV1 =
  | { readonly schema:"keep.decomposition-approval-authority-event"; readonly schema_version:1; readonly run_id:string; readonly operation:"owner-decision-applied"; readonly authority_context:DecompositionEventAuthorityContextV1; readonly state:DecompositionApprovalStateV1; readonly action:DecompositionApprovalActionV1; readonly owner:TrustedDecompositionOwnerContextV1; readonly scope:TrustedDecompositionApprovalScopeV1; readonly result:DecompositionApprovalResultV1 }
  | { readonly schema:"keep.decomposition-approval-authority-event"; readonly schema_version:1; readonly run_id:string; readonly operation:"publication-verified"; readonly authority_context:DecompositionEventAuthorityContextV1; readonly input:DecompositionPublicationInputV1; readonly result:DecompositionPublicationResultV1 }
  | { readonly schema:"keep.decomposition-approval-authority-event"; readonly schema_version:1; readonly run_id:string; readonly operation:"ticket-admitted"; readonly authority_context:DecompositionEventAuthorityContextV1; readonly candidate:ExecutableTicketBodyV1; readonly transition_result:DecompositionTransitionResultV1; readonly ticket_authority:DecompositionAuthorityContextV1; readonly scope:TicketAdmissionScopeV1; readonly result:TicketAdmissionResult };

export interface DecompositionApprovalReplayBundleV1 { readonly events:readonly AuthoritativeReplayV1Event[]; readonly replay:AuthoritativeReplayV1Result }
export interface DecompositionApprovalProjectionV1 { readonly approval:DecompositionApprovalStateV1|null; readonly publication:DecompositionPublicationReceiptV1|null; readonly ticket:AdmittedTicketAuthorityV1|null; readonly event_count:number; readonly implementation_authorized:false }
export type DecompositionApprovalReconstructionV1 = {readonly ok:true;readonly projection:DecompositionApprovalProjectionV1}|{readonly ok:false;readonly code:DecompositionApprovalEventCodeV1};

const plain=(v:unknown):v is Record<string,unknown>=>v!==null&&typeof v==="object"&&!Array.isArray(v);
const stable=(v:unknown):unknown=>Array.isArray(v)?v.map(stable):plain(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])])):v;
const equal=(a:unknown,b:unknown)=>JSON.stringify(stable(a))===JSON.stringify(stable(b));
const clone=<T>(v:T):T=>structuredClone(v);

function decode(row:AuthoritativeReplayV1Event):DecompositionApprovalAuthorityEventV1|null{
  const encoded=EventEnvelopeV1Encode(row.proposal); if(!encoded.ok)return null;
  try{const envelope=decodeCanonical(encoded.canonical_bytes) as Record<string,unknown>;
    if(!["decomposition.approved","decomposition.published","ticket.admitted"].includes(String(envelope.event_type)))return null;
    const payload=envelope.payload;if(!plain(payload)||Object.keys(payload).join(",")!=="domain_json"||typeof payload.domain_json!=="string")return null;
    const event=JSON.parse(payload.domain_json) as unknown;
    if(!plain(event)||event.schema!=="keep.decomposition-approval-authority-event"||event.schema_version!==1||typeof event.run_id!=="string"||!["owner-decision-applied","publication-verified","ticket-admitted"].includes(String(event.operation))||!plain(event.authority_context))return null;
    return event as DecompositionApprovalAuthorityEventV1;
  }catch{return null;}
}
function matchesTrack(context:DecompositionEventAuthorityContextV1,replay:Extract<AuthoritativeReplayV1Result,{ok:true}>):boolean{
  const a=replay.receipt.authority;
  return context.kind==="n1"?a.kind==="n1"&&a.actor_id===context.principal_id&&a.authority_domain==="local-owner"&&a.custody_id===context.custody_id:a.kind==="enterprise"&&a.actor_id===context.actor_id&&a.authority_domain==="organization"&&a.organization_id===context.organization_id&&a.tenant_id===context.tenant_id&&a.actor_role_id===context.role_id&&a.isolation_id===context.isolation_id&&a.custody_id===context.custody_id;
}
function bundleBound(id:string,b:DecompositionApprovalReplayBundleV1,r:Extract<AuthoritativeReplayV1Result,{ok:true}>):boolean{
  let pe:string|null=null,ph:string|null=null;
  for(let i=0;i<b.events.length;i++){const encoded=EventEnvelopeV1Encode(b.events[i]!.proposal);if(!encoded.ok)return false;const value=decodeCanonical(encoded.canonical_bytes) as Record<string,unknown>;if(value.history_id!==id||value.sequence!==BigInt(i)||value.predecessor_event_id!==pe||value.predecessor_head_id!==ph)return false;ph=eirDigest(EventAdmissionV1HeadDigestDomain,{history_id:id,sequence:BigInt(i),event_id:encoded.event_digest,predecessor_head_id:ph});pe=encoded.event_digest;}
  return b.events.length>0&&r.receipt.event_count===BigInt(b.events.length)&&r.receipt.final_sequence===BigInt(b.events.length-1)&&r.receipt.final_event_id===pe&&r.receipt.final_head_id===ph;
}
function ownerBound(event:Extract<DecompositionApprovalAuthorityEventV1,{operation:"owner-decision-applied"}>):boolean{
  const c=event.authority_context,o=event.owner;
  return c.kind==="n1"?o.kind==="n1"&&o.owner_id===c.principal_id&&o.custody_id===c.custody_id&&o.organization_services==="ABSENT":o.kind==="enterprise"&&o.organization_id===c.organization_id&&o.actor_id===c.actor_id&&o.role_id===c.role_id&&o.separation_policy_id===c.separation_policy_id&&o.custody_evidence_digest.length===64&&o.isolation_evidence_digest.length===64;
}
function ticketTrackBound(c:DecompositionEventAuthorityContextV1,t:DecompositionAuthorityContextV1):boolean{
  return c.kind==="n1"?t.kind==="n1"&&t.principal_id===c.principal_id&&t.custody_id===c.custody_id&&t.organization_services==="ABSENT":t.kind==="enterprise"&&t.organization_id===c.organization_id&&t.actor_id===c.actor_id&&t.role_id===c.role_id&&t.separation_policy_id===c.separation_policy_id&&t.local_owner_substitution===false;
}

export function reconstructDecompositionApprovalAuthorityV1(reviewHistoryId:string,reviewBundle:DecompositionAuthorityReplayBundleV1|null,id:string,bundle:DecompositionApprovalReplayBundleV1|null):DecompositionApprovalReconstructionV1{
  const predecessor=reconstructDecompositionAuthorityV1(reviewHistoryId,reviewBundle);
  if(!predecessor.ok||predecessor.projection.transition?.phase!=="DECOMPOSITION_VET_2_PASS"||predecessor.projection.review?.phase!=="COMPLETE"||predecessor.projection.review.disposition===null||predecessor.projection.review_scope===null)return {ok:false,code:"PREREQUISITE_AUTHORITY_INVALID"};
  if(bundle===null)return {ok:true,projection:{approval:null,publication:null,ticket:null,event_count:0,implementation_authorized:false}};
  if(!bundle.replay.ok)return {ok:false,code:bundle.replay.code==="TRACK_AUTHORITY_SUBSTITUTION"?"TRACK_AUTHORITY_SUBSTITUTION":"DECOMPOSITION_APPROVAL_HISTORY_INVALID"};
  if(bundle.replay.receipt.history_id!==id||!bundleBound(id,bundle,bundle.replay))return {ok:false,code:"DECOMPOSITION_APPROVAL_HISTORY_INVALID"};
  const first=decode(bundle.events[0]!);
  if(first===null||reviewBundle===null||!reviewBundle.replay.ok||!matchesTrack(first.authority_context,reviewBundle.replay))return {ok:false,code:"TRACK_AUTHORITY_SUBSTITUTION"};
  let approval:DecompositionApprovalStateV1|null=null,publication:DecompositionPublicationReceiptV1|null=null,ticket:AdmittedTicketAuthorityV1|null=null,context:DecompositionEventAuthorityContextV1|null=null;
  for(let i=0;i<bundle.events.length;i++){
    const event=decode(bundle.events[i]!);if(event===null||event.run_id!==id)return {ok:false,code:"DECOMPOSITION_APPROVAL_HISTORY_INVALID"};
    if(context===null)context=event.authority_context;else if(!equal(context,event.authority_context))return {ok:false,code:"TRACK_AUTHORITY_SUBSTITUTION"};
    if(!matchesTrack(event.authority_context,bundle.replay))return {ok:false,code:"TRACK_AUTHORITY_SUBSTITUTION"};
    if(event.operation==="owner-decision-applied"){
      const source=predecessor.projection.review_scope;
      if(i!==0||approval!==null||!ownerBound(event)||!equal(event.scope.review_disposition,predecessor.projection.review.disposition)||event.scope.generation!==source.generation||event.scope.candidate_digest!==source.candidate_digest||event.scope.manifest_digest!==source.manifest_digest||event.scope.scope_digest!==source.scope_digest||event.scope.candidate_author_id!==source.candidate_author_id||event.scope.candidate_author_family!==source.candidate_author_family)return {ok:false,code:"PREREQUISITE_AUTHORITY_INVALID"};
      const actual=advanceDecompositionApproval(event.state,event.action,event.owner,event.scope);
      if(!equal(actual,event.result)||!actual.advanced||actual.state?.generations.at(-1)?.status!=="APPROVED")return {ok:false,code:"INCOMPLETE_DECOMPOSITION_HISTORY"};
      approval=clone(actual.state);continue;
    }
    if(approval===null)return {ok:false,code:"LEGACY_AUTHORITY_GAP"};
    if(event.operation==="publication-verified"){
      if(publication!==null||ticket!==null||!equal(event.input.approved_generation,approval.generations.at(-1)))return {ok:false,code:"PREREQUISITE_AUTHORITY_INVALID"};
      const actual=verifyDecompositionPublication(event.input);if(!equal(actual,event.result)||!actual.advanced||actual.receipt===null)return {ok:false,code:"INCOMPLETE_DECOMPOSITION_HISTORY"};publication=clone(actual.receipt);continue;
    }
    if(publication===null||ticket!==null)return {ok:false,code:"PREREQUISITE_AUTHORITY_INVALID"};
    if(!ticketTrackBound(event.authority_context,event.ticket_authority)||event.scope.active_generation!==publication.generation)return {ok:false,code:"TRACK_AUTHORITY_SUBSTITUTION"};
    const actual=admitExecutableTicket(event.candidate,event.transition_result,event.ticket_authority,event.scope);
    if(!equal(actual,event.result)||!actual.admitted)return {ok:false,code:"INCOMPLETE_DECOMPOSITION_HISTORY"};ticket=clone(actual.authority);
  }
  return {ok:true,projection:{approval,publication,ticket,event_count:bundle.events.length,implementation_authorized:false}};
}

export function rejectLegacyApprovalMutationV1():{readonly ok:false;readonly code:"LEGACY_APPROVAL_MUTATION_REJECTED"}{return {ok:false,code:"LEGACY_APPROVAL_MUTATION_REJECTED"};}
