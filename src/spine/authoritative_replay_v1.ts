import { types } from "node:util";

import { decodeCanonical, eirDigest, encodeCanonical, type CanonicalValue } from "../eir/canonical.js";
import { CommittedHeadV1CheckpointDigestDomain, type CommittedHeadV1Result } from "./committed_head_v1.js";
import { EventAdmissionV1HeadDigestDomain, type EventAdmissionV1Authority, type EventAdmissionV1LineageRecord, type EventAdmissionV1TrustedContext } from "./event_admission_v1.js";
import { EventEnvelopeV1CodecIdentity, EventEnvelopeV1Encode } from "./event_envelope_v1.js";
import { ReducerRegistryV1, type ReducerRegistryV1Result } from "./reducer_registry_v1.js";
import { validateReplayProjectionV1 } from "./replay_projection_v1.js";
import { EventVersionRegistryV1, type EventVersionRegistryV1Result } from "./version_registry_v1.js";

export interface AuthoritativeReplayV1Event {
  readonly proposal: unknown;
  readonly target_version: bigint;
  readonly interpreter_set_digest: string;
}
export interface AuthoritativeReplayV1Request {
  readonly committed_head: Extract<CommittedHeadV1Result, { ok: true }>;
  readonly authority_context: EventAdmissionV1TrustedContext;
  readonly events: readonly AuthoritativeReplayV1Event[] | readonly (readonly AuthoritativeReplayV1Event[])[];
  readonly initial_state_bytes: Uint8Array;
  readonly versions: EventVersionRegistryV1;
  readonly reducers: ReducerRegistryV1;
  readonly projection?: unknown;
  readonly expected_result_digest?: string;
}
export interface AuthoritativeReplayV1Receipt {
  readonly schema: "keep.spine.authoritative-replay-receipt";
  readonly schema_version: 1n;
  readonly history_id: string;
  readonly event_count: bigint;
  readonly final_sequence: bigint;
  readonly final_event_id: string;
  readonly final_head_id: string;
  readonly witness_id: string;
  readonly checkpoint_digest: string;
  readonly codec: typeof EventEnvelopeV1CodecIdentity;
  readonly codec_version: 1n;
  readonly reducer_identities: readonly string[];
  readonly interpreter_set_digests: readonly string[];
  readonly state_digest: string;
  readonly authority: EventAdmissionV1Authority;
  readonly effects_performed: false;
  readonly projection_authoritative: false;
  readonly closed: true;
}
export type AuthoritativeReplayV1Result =
  | { readonly ok: true; readonly state_bytes: Uint8Array; readonly receipt: AuthoritativeReplayV1Receipt; readonly result_digest:string }
  | { readonly ok: false; readonly code: "PHYSICAL_HISTORY_INVALID" | "HISTORY_INTEGRITY_MISMATCH" | "TRACK_AUTHORITY_SUBSTITUTION" | "VERSION_INTERPRETER_REFUSED" | "REDUCTION_REFUSED" | "REPLAY_DETERMINISM_MISMATCH" };

const hex64 = /^[0-9a-f]{64}$/;
const sameBytes = (a: Uint8Array, b: Uint8Array) => Buffer.from(a).equals(Buffer.from(b));
function plainArray(value: unknown): value is readonly unknown[] {
  return Array.isArray(value) && !types.isProxy(value) && Object.getPrototypeOf(value) === Array.prototype && Reflect.ownKeys(value).length === value.length + 1;
}
function sameAuthority(a: unknown, b: unknown): boolean {
  try { return sameBytes(encodeCanonical(a as CanonicalValue), encodeCanonical(b as CanonicalValue)); } catch { return false; }
}
function capturedEvent(value: unknown): AuthoritativeReplayV1Event | null {
  if(value===null||typeof value!=="object"||types.isProxy(value)||Object.getPrototypeOf(value)!==Object.prototype)return null;
  const keys=["proposal","target_version","interpreter_set_digest"],actual=Reflect.ownKeys(value);if(actual.length!==keys.length||actual.some(k=>typeof k!=="string"||!keys.includes(k)))return null;
  const out:Record<string,unknown>=Object.create(null);for(const key of keys){const d=Object.getOwnPropertyDescriptor(value,key);if(d===undefined||!("value" in d)||!d.enumerable)return null;out[key]=d.value;}
  return typeof out.target_version==="bigint"&&hex64.test(String(out.interpreter_set_digest))?out as unknown as AuthoritativeReplayV1Event:null;
}
function contextFor(base: EventAdmissionV1TrustedContext, lineage: readonly EventAdmissionV1LineageRecord[]): EventAdmissionV1TrustedContext {
  const witnessed_head = lineage.length === 0 ? null : { sequence: lineage.at(-1)!.sequence, event_id: lineage.at(-1)!.event_id, head_id: lineage.at(-1)!.head_id };
  return base.kind === "n1"
    ? { kind:"n1", track:"n1", history_id:base.history_id, actor_id:base.actor_id, authority_domain:base.authority_domain, custody_id:base.custody_id, committed_lineage:lineage, witnessed_head }
    : { kind:"enterprise", track:"enterprise", history_id:base.history_id, actor_id:base.actor_id, authority_domain:base.authority_domain, custody_id:base.custody_id, organization_id:base.organization_id, tenant_id:base.tenant_id, actor_role_id:base.actor_role_id, isolation_id:base.isolation_id, committed_lineage:lineage, witnessed_head };
}
function authorityOf(c: EventAdmissionV1TrustedContext): EventAdmissionV1Authority {
  return c.kind === "n1"
    ? { kind:"n1", track:"n1", actor_id:c.actor_id, authority_domain:c.authority_domain, custody_id:c.custody_id }
    : { kind:"enterprise", track:"enterprise", actor_id:c.actor_id, authority_domain:c.authority_domain, custody_id:c.custody_id, organization_id:c.organization_id, tenant_id:c.tenant_id, actor_role_id:c.actor_role_id, isolation_id:c.isolation_id };
}
function flatten(value: AuthoritativeReplayV1Request["events"]): readonly AuthoritativeReplayV1Event[] | null {
  if (!plainArray(value)) return null;
  const out: AuthoritativeReplayV1Event[] = [];
  for (const item of value) {
    if (plainArray(item)) { for (const nested of item) out.push(nested as AuthoritativeReplayV1Event); }
    else out.push(item as AuthoritativeReplayV1Event);
  }
  return out;
}
function validCommittedHead(head: Extract<CommittedHeadV1Result,{ok:true}>, authority: EventAdmissionV1Authority): boolean {
  try { const r=head.receipt;
    const checkpoint=decodeCanonical(r.checkpoint_bytes);if(checkpoint===null||typeof checkpoint!=="object"||Array.isArray(checkpoint)||checkpoint instanceof Uint8Array)return false;const c=checkpoint as Record<string,CanonicalValue>,keys=["schema","schema_version","witness_id","history_storage_domain","witness_storage_domain","history_id","sequence","event_id","head_id","record_digest","authority","prior_witness_digest"];
    if(Reflect.ownKeys(c).length!==keys.length||Reflect.ownKeys(c).some(k=>typeof k!=="string"||!keys.includes(k)))return false;
    return r.durable===true&&r.witnessed===true&&r.committed===true&&r.authoritative===false&&r.durability_profile==="verified-local-posix-v1"&&hex64.test(r.event_id)&&hex64.test(r.next_head_id)&&hex64.test(r.checkpoint_digest)&&r.checkpoint_digest===eirDigest(CommittedHeadV1CheckpointDigestDomain,r.checkpoint_bytes)&&r.witness_signature.length>0&&sameAuthority(r.authority,authority)&&c.schema==="keep.spine.committed-head-checkpoint"&&c.schema_version===1n&&c.witness_id===r.witness_id&&c.history_id===r.history_id&&c.sequence===r.sequence&&c.event_id===r.event_id&&c.head_id===r.next_head_id&&c.record_digest===r.record_digest&&sameAuthority(c.authority,authority);
  } catch { return false; }
}
const versionFailed = (r:EventVersionRegistryV1Result):r is Extract<EventVersionRegistryV1Result,{ok:false}> => !r.ok;
const reductionFailed = (r:ReducerRegistryV1Result):r is Extract<ReducerRegistryV1Result,{ok:false}> => !r.ok;

export function replayAuthoritativeHistoryV1(request: AuthoritativeReplayV1Request): AuthoritativeReplayV1Result {
  const events=flatten(request.events), authority=authorityOf(request.authority_context);
  if(events===null||events.length===0||request.authority_context.committed_lineage.length!==0||request.authority_context.witnessed_head!==null||request.authority_context.history_id!==request.committed_head.receipt.history_id)return{ok:false,code:"PHYSICAL_HISTORY_INVALID"};
  let state:Uint8Array;try{state=encodeCanonical(decodeCanonical(request.initial_state_bytes));if(!sameBytes(state,request.initial_state_bytes))return{ok:false,code:"PHYSICAL_HISTORY_INVALID"}}catch{return{ok:false,code:"PHYSICAL_HISTORY_INVALID"}}
  const lineage:EventAdmissionV1LineageRecord[]=[], reducers:string[]=[], interpreters:string[]=[];let lastReduction:Extract<ReducerRegistryV1Result,{ok:true}>|null=null,lastVersion:Extract<EventVersionRegistryV1Result,{ok:true}>|null=null;
  for(let i=0;i<events.length;i++){
    const row=capturedEvent(events[i]);if(row===null)return{ok:false,code:"PHYSICAL_HISTORY_INVALID"};
    const encoded=EventEnvelopeV1Encode(row.proposal);if(!encoded.ok)return{ok:false,code:"PHYSICAL_HISTORY_INVALID"};
    let value:Record<string,unknown>;try{value=decodeCanonical(encoded.canonical_bytes) as Record<string,unknown>}catch{return{ok:false,code:"PHYSICAL_HISTORY_INVALID"}}
    const prior=lineage.at(-1),sequence=BigInt(i);
    if(value.history_id!==request.authority_context.history_id||value.sequence!==sequence||value.predecessor_event_id!==(prior?.event_id??null)||value.predecessor_head_id!==(prior?.head_id??null))return{ok:false,code:"HISTORY_INTEGRITY_MISMATCH"};
    const expectedAuthority=authorityOf(request.authority_context);if(value.track!==expectedAuthority.track||value.actor_id!==expectedAuthority.actor_id||value.authority_domain!==expectedAuthority.authority_domain)return{ok:false,code:"TRACK_AUTHORITY_SUBSTITUTION"};
    const nextHead=eirDigest(EventAdmissionV1HeadDigestDomain,{history_id:value.history_id as string,sequence,event_id:encoded.event_digest,predecessor_head_id:prior?.head_id??null});
    const ctx=contextFor(request.authority_context,lineage),version=request.versions.upcast(row.proposal,ctx,row.target_version,row.interpreter_set_digest);if(versionFailed(version))return{ok:false,code:"VERSION_INTERPRETER_REFUSED"};
    const reduction=request.reducers.reduce(state,row.proposal,ctx);if(reductionFailed(reduction))return{ok:false,code:"REDUCTION_REFUSED"};
    if(!sameAuthority(reduction.authority,authority)||!sameAuthority(version.authority,authority))return{ok:false,code:"TRACK_AUTHORITY_SUBSTITUTION"};
    state=reduction.state_bytes.slice();reducers.push(reduction.reducer_identity);interpreters.push(version.interpreter_set_digest);lastReduction=reduction;lastVersion=version;lineage.push({sequence,event_id:encoded.event_digest,head_id:nextHead,predecessor_event_id:prior?.event_id??null,predecessor_head_id:prior?.head_id??null});
  }
  const tail=lineage.at(-1)!;if(tail.sequence!==request.committed_head.receipt.sequence||tail.event_id!==request.committed_head.receipt.event_id||tail.head_id!==request.committed_head.receipt.next_head_id)return{ok:false,code:"HISTORY_INTEGRITY_MISMATCH"};
  if(!validCommittedHead(request.committed_head,authority))return{ok:false,code:"TRACK_AUTHORITY_SUBSTITUTION"};
  if(request.projection!==undefined){const p=validateReplayProjectionV1({committed_head:request.committed_head,reduction:lastReduction!,version:lastVersion!,codec:EventEnvelopeV1CodecIdentity,codec_version:1n},request.projection);if(p.ok&&!sameBytes(p.state_bytes,state))return{ok:false,code:"REPLAY_DETERMINISM_MISMATCH"};}
  const receipt=Object.freeze({schema:"keep.spine.authoritative-replay-receipt" as const,schema_version:1n,history_id:request.authority_context.history_id,event_count:BigInt(events.length),final_sequence:tail.sequence,final_event_id:tail.event_id,final_head_id:tail.head_id,witness_id:request.committed_head.receipt.witness_id,checkpoint_digest:request.committed_head.receipt.checkpoint_digest,codec:EventEnvelopeV1CodecIdentity,codec_version:1n,reducer_identities:Object.freeze(reducers),interpreter_set_digests:Object.freeze(interpreters),state_digest:eirDigest("keep.spine.reducer-state-bytes.v1",state),authority,effects_performed:false as const,projection_authoritative:false as const,closed:true as const});
  const result_digest=eirDigest("keep.spine.authoritative-replay-result.v1",{state_bytes:state,receipt:receipt as unknown as CanonicalValue});
  if(request.expected_result_digest!==undefined&&!hex64.test(request.expected_result_digest))return{ok:false,code:"PHYSICAL_HISTORY_INVALID"};
  if(request.expected_result_digest!==undefined&&request.expected_result_digest!==result_digest)return{ok:false,code:"REPLAY_DETERMINISM_MISMATCH"};
  return{ok:true,state_bytes:state.slice(),receipt,result_digest};
}
