import { types } from "node:util";

import { decodeCanonical, eirDigest, encodeCanonical, isWellFormedText, type CanonicalValue } from "../eir/canonical.js";
import { CommittedHeadV1CheckpointDigestDomain, type CommittedHeadV1Result } from "./committed_head_v1.js";
import { type EventAdmissionV1Authority } from "./event_admission_v1.js";
import { EventEnvelopeV1CodecIdentity } from "./event_envelope_v1.js";
import { type ReducerRegistryV1Result } from "./reducer_registry_v1.js";
import { type EventVersionRegistryV1Result } from "./version_registry_v1.js";

export interface ReplayProjectionV1Authority {
  readonly committed_head:Extract<CommittedHeadV1Result,{ok:true}>;
  readonly reduction:Extract<ReducerRegistryV1Result,{ok:true}>;
  readonly version:Extract<EventVersionRegistryV1Result,{ok:true}>;
  readonly codec:typeof EventEnvelopeV1CodecIdentity;
  readonly codec_version:1n;
}
export interface ReplayProjectionV1Value {
  readonly schema:"keep.spine.replay-projection";
  readonly schema_version:1n;
  readonly history_id:string;
  readonly next_head_id:string;
  readonly event_id:string;
  readonly sequence:bigint;
  readonly event_count:bigint;
  readonly authority:EventAdmissionV1Authority;
  readonly codec:typeof EventEnvelopeV1CodecIdentity;
  readonly codec_version:1n;
  readonly reducer_identity:string;
  readonly interpreter_set_digest:string;
  readonly state_bytes:Uint8Array;
  readonly state_digest:string;
  readonly authoritative:false;
  readonly acceleration_only:true;
}
type StateResult={readonly state_bytes:Uint8Array;readonly state_digest:string;readonly authority:EventAdmissionV1Authority;readonly authoritative_source:"history-replay";readonly projection_authoritative:false};
export type ReplayProjectionV1Result=
  | {readonly ok:false;readonly code:"HISTORY_REQUIRED"}
  | ({readonly ok:false;readonly code:"PROJECTION_HISTORY_MISMATCH"|"PROJECTION_INTERPRETER_MISMATCH"|"TRACK_AUTHORITY_SUBSTITUTION";readonly projection_discarded:true}&StateResult)
  | ({readonly ok:true;readonly projection_accepted:true;readonly acceleration_only:true}&StateResult);

const hex64=/^[0-9a-f]{64}$/,max=0xffff_ffff_ffff_ffffn;
const text=(v:unknown):v is string=>typeof v==="string"&&v.length>0&&v.length<=256&&isWellFormedText(v)&&v.normalize("NFC")===v;
const digest=(v:unknown):v is string=>typeof v==="string"&&hex64.test(v);
const uint=(v:unknown):v is bigint=>typeof v==="bigint"&&v>=0n&&v<=max;
const bytes=(v:unknown):v is Uint8Array=>v instanceof Uint8Array&&!types.isProxy(v);
const sameBytes=(a:Uint8Array,b:Uint8Array)=>Buffer.from(a).equals(Buffer.from(b));
function own(value:unknown,keys:readonly string[]):Record<string,unknown>|null{
  if(value===null||typeof value!=="object"||types.isProxy(value)||Object.getPrototypeOf(value)!==Object.prototype)return null;
  const actual=Reflect.ownKeys(value);if(actual.length!==keys.length||actual.some(k=>typeof k!=="string"||!keys.includes(k)))return null;
  const out:Record<string,unknown>=Object.create(null);for(const key of keys){const d=Object.getOwnPropertyDescriptor(value,key);if(d===undefined||!("value" in d)||!d.enumerable)return null;out[key]=d.value}return out;
}
function strictArray(value:unknown):readonly unknown[]|null{
  if(!Array.isArray(value)||types.isProxy(value)||Object.getPrototypeOf(value)!==Array.prototype||Reflect.ownKeys(value).length!==value.length+1)return null;
  const out:unknown[]=[];for(let i=0;i<value.length;i++){const d=Object.getOwnPropertyDescriptor(value,String(i));if(d===undefined||!("value" in d)||!d.enumerable)return null;out.push(d.value)}return out;
}
function canonicalBytes(value:unknown):value is Uint8Array{if(!bytes(value))return false;try{return sameBytes(encodeCanonical(decodeCanonical(value)),value)}catch{return false}}
function authority(value:unknown):EventAdmissionV1Authority|null{
  const base=["kind","track","actor_id","authority_domain","custody_id"],kind=value!==null&&typeof value==="object"&&!types.isProxy(value)?Object.getOwnPropertyDescriptor(value,"kind")?.value:undefined,keys=kind==="enterprise"?[...base,"organization_id","tenant_id","actor_role_id","isolation_id"]:base,row=own(value,keys);if(row===null||!(kind==="n1"||kind==="enterprise")||row.track!==kind||!text(row.actor_id)||!text(row.authority_domain)||!text(row.custody_id))return null;
  if(kind==="n1")return Object.freeze({kind,track:kind,actor_id:row.actor_id,authority_domain:row.authority_domain,custody_id:row.custody_id});
  if(!text(row.organization_id)||!text(row.tenant_id)||!text(row.actor_role_id)||!text(row.isolation_id))return null;return Object.freeze({kind,track:kind,actor_id:row.actor_id,authority_domain:row.authority_domain,custody_id:row.custody_id,organization_id:row.organization_id,tenant_id:row.tenant_id,actor_role_id:row.actor_role_id,isolation_id:row.isolation_id});
}
const sameAuthority=(a:EventAdmissionV1Authority,b:EventAdmissionV1Authority)=>sameBytes(encodeCanonical(a as unknown as CanonicalValue),encodeCanonical(b as unknown as CanonicalValue));
type Captured={history_id:string;next_head_id:string;event_id:string;sequence:bigint;authority:EventAdmissionV1Authority;codec:typeof EventEnvelopeV1CodecIdentity;codec_version:1n;reducer_identity:string;interpreter_set_digest:string;state_bytes:Uint8Array;state_digest:string};
function captureReplay(value:unknown):Captured|null{
  const wrapper=own(value,["committed_head","reduction","version","codec","codec_version"]);if(wrapper===null||wrapper.codec!==EventEnvelopeV1CodecIdentity||wrapper.codec_version!==1n)return null;
  const committed=own(wrapper.committed_head,["ok","receipt"]),receipt=committed?.ok===true?own(committed.receipt,["history_id","sequence","event_id","next_head_id","authority","record_digest","final_path","record_bytes","durability_profile","durable","authoritative","witness_id","checkpoint_digest","checkpoint_bytes","witness_signature","witnessed","committed"]):null;
  const reduction=own(wrapper.reduction,["ok","state_bytes","state_digest","reducer_identity","event_id","authority","pure","effects_performed","authoritative"]);
  const version=own(wrapper.version,["ok","original_event_id","original_event_bytes","current_event_value","current_event_bytes","source_version","target_version","adapter_identities","interpreter_set_digest","authority","pure","historical_bytes_mutated","authoritative"]);
  if(receipt===null||reduction===null||version===null||receipt.durable!==true||receipt.witnessed!==true||receipt.committed!==true||receipt.authoritative!==false||receipt.durability_profile!=="verified-local-posix-v1"||reduction.ok!==true||reduction.pure!==true||reduction.effects_performed!==false||reduction.authoritative!==false||version.ok!==true||version.pure!==true||version.historical_bytes_mutated!==false||version.authoritative!==false)return null;
  const a=authority(receipt.authority),ra=authority(reduction.authority),va=authority(version.authority),adapters=strictArray(version.adapter_identities);
  if(a===null||ra===null||va===null||!sameAuthority(a,ra)||!sameAuthority(a,va)||!text(receipt.history_id)||!uint(receipt.sequence)||!digest(receipt.event_id)||!digest(receipt.next_head_id)||receipt.event_id!==reduction.event_id||receipt.event_id!==version.original_event_id||!digest(receipt.record_digest)||!digest(receipt.checkpoint_digest)||!bytes(receipt.checkpoint_bytes)||receipt.checkpoint_digest!==eirDigest(CommittedHeadV1CheckpointDigestDomain,receipt.checkpoint_bytes)||!bytes(receipt.record_bytes)||!bytes(receipt.witness_signature)||receipt.witness_signature.length===0)return null;
  if(!canonicalBytes(reduction.state_bytes)||!digest(reduction.state_digest)||reduction.state_digest!==eirDigest("keep.spine.reducer-state-bytes.v1",reduction.state_bytes)||!digest(reduction.reducer_identity)||!digest(version.interpreter_set_digest)||adapters===null||adapters.some(x=>typeof x!=="string"||!hex64.test(x))||!canonicalBytes(version.original_event_bytes)||!canonicalBytes(version.current_event_bytes)||!uint(version.source_version)||!uint(version.target_version))return null;
  return{history_id:receipt.history_id,next_head_id:receipt.next_head_id,event_id:receipt.event_id,sequence:receipt.sequence,authority:a,codec:EventEnvelopeV1CodecIdentity,codec_version:1n,reducer_identity:reduction.reducer_identity,state_bytes:reduction.state_bytes.slice(),state_digest:reduction.state_digest,interpreter_set_digest:version.interpreter_set_digest};
}
const projectionKeys=["schema","schema_version","history_id","next_head_id","event_id","sequence","event_count","authority","codec","codec_version","reducer_identity","interpreter_set_digest","state_bytes","state_digest","authoritative","acceleration_only"] as const;
const withState=(r:Captured):StateResult=>({state_bytes:r.state_bytes.slice(),state_digest:r.state_digest,authority:r.authority,authoritative_source:"history-replay",projection_authoritative:false});
export function validateReplayProjectionV1(replay:unknown,projection:unknown):ReplayProjectionV1Result{
  const r=captureReplay(replay);if(r===null)return{ok:false,code:"HISTORY_REQUIRED"};const p=own(projection,projectionKeys);if(p===null)return{ok:false,code:"PROJECTION_HISTORY_MISMATCH",projection_discarded:true,...withState(r)};
  const pa=authority(p.authority);if(pa===null||!sameAuthority(r.authority,pa))return{ok:false,code:"TRACK_AUTHORITY_SUBSTITUTION",projection_discarded:true,...withState(r)};
  if(p.schema!=="keep.spine.replay-projection"||p.schema_version!==1n||!text(p.history_id)||!hex64.test(String(p.next_head_id))||!hex64.test(String(p.event_id))||!uint(p.sequence)||!uint(p.event_count)||p.authoritative!==false||p.acceleration_only!==true||!canonicalBytes(p.state_bytes)||!hex64.test(String(p.state_digest))||p.state_digest!==eirDigest("keep.spine.reducer-state-bytes.v1",p.state_bytes)||p.history_id!==r.history_id||p.next_head_id!==r.next_head_id||p.event_id!==r.event_id||p.sequence!==r.sequence||p.event_count!==r.sequence+1n||p.state_digest!==r.state_digest)return{ok:false,code:"PROJECTION_HISTORY_MISMATCH",projection_discarded:true,...withState(r)};
  if(p.codec!==r.codec||p.codec_version!==r.codec_version||p.reducer_identity!==r.reducer_identity||p.interpreter_set_digest!==r.interpreter_set_digest)return{ok:false,code:"PROJECTION_INTERPRETER_MISMATCH",projection_discarded:true,...withState(r)};
  return{ok:true,projection_accepted:true,acceleration_only:true,...withState(r)};
}
