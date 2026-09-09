import { createHash, createPublicKey, verify, type KeyObject } from "node:crypto";

import { decodeCanonical, eirDigest, encodeCanonical, type CanonicalValue } from "../eir/canonical.js";
import { type AuthoritativeAppendV1, type AuthoritativeAppendV1Receipt, type AuthoritativeAppendV1Result } from "./authoritative_append_v1.js";
import { type EventAdmissionV1Authority, type EventAdmissionV1TrustedContext } from "./event_admission_v1.js";

export const CommittedHeadV1CheckpointDigestDomain = "keep.spine.committed-head-checkpoint-bytes.v1" as const;

export type CommittedHeadV1WitnessAck =
  | { readonly ok:true; readonly durable:true; readonly checkpoint_bytes:Uint8Array; readonly checkpoint_digest:string; readonly signature:Uint8Array }
  | { readonly ok:false; readonly code:"WITNESS_CONFLICT" };

export interface CommittedHeadV1WitnessPort {
  latest(historyId:string): Promise<CommittedHeadV1WitnessAck | null>;
  compareAndPersist(expectedPriorDigest:string|null, checkpointBytes:Uint8Array): Promise<CommittedHeadV1WitnessAck>;
}

export interface CommittedHeadV1Options {
  readonly append: AuthoritativeAppendV1;
  readonly history_storage_domain:string;
  readonly witness_storage_domain:string;
  readonly witness?:CommittedHeadV1WitnessPort;
  readonly witness_public_key:string|Uint8Array;
}

export interface CommittedHeadV1Receipt extends Omit<AuthoritativeAppendV1Receipt,"witnessed"|"committed"> {
  readonly witness_id:string;
  readonly checkpoint_digest:string;
  readonly checkpoint_bytes:Uint8Array;
  readonly witness_signature:Uint8Array;
  readonly witnessed:true;
  readonly committed:true;
}

type OwnRefusal = {readonly ok:false;readonly code:"WITNESS_REQUIRED"|"WITNESS_NOT_INDEPENDENT"|"WITNESS_HEAD_MISMATCH"|"WITNESS_PERSISTENCE_FAILED"|"WITNESS_CONFLICT"|"HISTORY_WITNESS_MISMATCH"};
export type CommittedHeadV1Result = {readonly ok:true;readonly receipt:CommittedHeadV1Receipt}|OwnRefusal|Exclude<AuthoritativeAppendV1Result,{ok:true}>;

const hex64=/^[0-9a-f]{64}$/;
const sameBytes=(a:Uint8Array,b:Uint8Array)=>Buffer.from(a).equals(Buffer.from(b));
const authorityFor=(context:EventAdmissionV1TrustedContext):EventAdmissionV1Authority=>context.kind==="n1"
  ? {kind:"n1",track:"n1",actor_id:context.actor_id,authority_domain:context.authority_domain,custody_id:context.custody_id}
  : {kind:"enterprise",track:"enterprise",actor_id:context.actor_id,authority_domain:context.authority_domain,custody_id:context.custody_id,organization_id:context.organization_id,tenant_id:context.tenant_id,actor_role_id:context.actor_role_id,isolation_id:context.isolation_id};
const sameAuthority=(a:unknown,b:EventAdmissionV1Authority):boolean=>{
  try{return sameBytes(encodeCanonical(a as CanonicalValue),encodeCanonical(b as unknown as CanonicalValue));}catch{return false;}
};
function enrolledKey(value:string|Uint8Array):{key:KeyObject;id:string}|null {
  try { const key=createPublicKey(typeof value==="string"?value:Buffer.from(value)); if(key.asymmetricKeyType!=="ed25519")return null; const der=key.export({type:"spki",format:"der"}); return {key,id:createHash("sha256").update(der).digest("hex")}; } catch { return null; }
}
function validAck(ack:CommittedHeadV1WitnessAck,key:KeyObject):ack is Extract<CommittedHeadV1WitnessAck,{ok:true}>{
  return ack.ok && ack.durable===true && hex64.test(ack.checkpoint_digest) && ack.checkpoint_digest===eirDigest(CommittedHeadV1CheckpointDigestDomain,ack.checkpoint_bytes) && verify(null,ack.checkpoint_bytes,key,ack.signature);
}
function latestMatches(ack:Extract<CommittedHeadV1WitnessAck,{ok:true}>,context:EventAdmissionV1TrustedContext,witnessId:string,historyDomain:string,witnessDomain:string):boolean {
  try {
    const v=decodeCanonical(ack.checkpoint_bytes) as Record<string,unknown>,tail=context.committed_lineage.at(-1);
    if(tail===undefined)return false;
    return v.schema==="keep.spine.committed-head-checkpoint"&&v.schema_version===1n&&v.witness_id===witnessId&&v.history_storage_domain===historyDomain&&v.witness_storage_domain===witnessDomain&&v.history_id===context.history_id&&v.sequence===tail.sequence&&v.event_id===tail.event_id&&v.head_id===tail.head_id&&sameAuthority(v.authority,authorityFor(context));
  } catch{return false;}
}

export class CommittedHeadV1 {
  constructor(private readonly options:CommittedHeadV1Options) {}
  async commit(proposal:unknown,context:EventAdmissionV1TrustedContext):Promise<CommittedHeadV1Result>{
    const witness=this.options.witness,key=enrolledKey(this.options.witness_public_key);
    if(witness===undefined||key===null)return {ok:false,code:"WITNESS_REQUIRED"};
    if(this.options.history_storage_domain.length===0||this.options.witness_storage_domain.length===0||this.options.history_storage_domain===this.options.witness_storage_domain)return {ok:false,code:"WITNESS_NOT_INDEPENDENT"};
    let prior:CommittedHeadV1WitnessAck|null;
    try{prior=await witness.latest(context.history_id);}catch{return {ok:false,code:"WITNESS_PERSISTENCE_FAILED"};}
    if(prior!==null&&(!validAck(prior,key.key)||!latestMatches(prior,context,key.id,this.options.history_storage_domain,this.options.witness_storage_domain)))return {ok:false,code:"HISTORY_WITNESS_MISMATCH"};
    if(prior===null&&context.committed_lineage.length!==0)return {ok:false,code:"HISTORY_WITNESS_MISMATCH"};
    const appended=await this.options.append.append(proposal,context);if(!appended.ok)return appended;
    const a=appended.receipt;
    const checkpoint=encodeCanonical({schema:"keep.spine.committed-head-checkpoint",schema_version:1n,witness_id:key.id,history_storage_domain:this.options.history_storage_domain,witness_storage_domain:this.options.witness_storage_domain,history_id:a.history_id,sequence:a.sequence,event_id:a.event_id,head_id:a.next_head_id,record_digest:a.record_digest,authority:a.authority as unknown as CanonicalValue,prior_witness_digest:prior?.ok===true?prior.checkpoint_digest:null});
    let ack:CommittedHeadV1WitnessAck;
    try{ack=await witness.compareAndPersist(prior?.ok===true?prior.checkpoint_digest:null,checkpoint);}catch{return {ok:false,code:"WITNESS_PERSISTENCE_FAILED"};}
    if(!ack.ok)return ack;
    if(!sameBytes(ack.checkpoint_bytes,checkpoint)||!validAck(ack,key.key))return {ok:false,code:"WITNESS_HEAD_MISMATCH"};
    return {ok:true,receipt:Object.freeze({...a,witness_id:key.id,checkpoint_digest:ack.checkpoint_digest,checkpoint_bytes:ack.checkpoint_bytes,witness_signature:ack.signature,witnessed:true,committed:true})};
  }
}
