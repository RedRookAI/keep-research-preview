import { types } from "node:util";

import { decodeCanonical, eirDigest, encodeCanonical, isWellFormedText, type CanonicalValue } from "../eir/canonical.js";
import { EventAdmissionV1Admit, type EventAdmissionV1Authority, type EventAdmissionV1Result, type EventAdmissionV1TrustedContext } from "./event_admission_v1.js";
import { EventEnvelopeV1Encode } from "./event_envelope_v1.js";

type Base={readonly event_type:string;readonly from_version:bigint;readonly to_version:bigint;readonly upcaster_id:string;readonly upcaster_version:bigint};
export type EventVersionRegistryV1Definition=
  | Base&{readonly operation:"retain-payload"}
  | Base&{readonly operation:"replace-payload";readonly payload:CanonicalValue}
  | Base&{readonly operation:"merge-record-fields";readonly fields:{readonly[k:string]:CanonicalValue}};
export type EventVersionRegistryV1RefusalCode="VERSION_REGISTRY_DEFINITION_INVALID"|"UNKNOWN_EVENT_VERSION"|"UPCASTER_CHAIN_INCOMPLETE"|"UPCASTER_SET_MISMATCH"|"UPCASTER_EVENT_MISMATCH"|"UPCASTER_PAYLOAD_INVALID";
type Refusal={readonly ok:false;readonly code:EventVersionRegistryV1RefusalCode}|Exclude<EventAdmissionV1Result,{ok:true}>;
export type EventVersionRegistryV1SetResult={readonly ok:true;readonly adapter_identities:readonly string[];readonly interpreter_set_digest:string}|{readonly ok:false;readonly code:"VERSION_REGISTRY_DEFINITION_INVALID"|"UNKNOWN_EVENT_VERSION"|"UPCASTER_CHAIN_INCOMPLETE"};
export type EventVersionRegistryV1Result=Refusal|{readonly ok:true;readonly original_event_id:string;readonly original_event_bytes:Uint8Array;readonly current_event_value:CanonicalValue;readonly current_event_bytes:Uint8Array;readonly source_version:bigint;readonly target_version:bigint;readonly adapter_identities:readonly string[];readonly interpreter_set_digest:string;readonly authority:EventAdmissionV1Authority;readonly pure:true;readonly historical_bytes_mutated:false;readonly authoritative:false};

const baseKeys=["event_type","from_version","to_version","upcaster_id","upcaster_version","operation"] as const;
const max=0xffff_ffff_ffff_ffffn,hex=/^[0-9a-f]{64}$/;
const text=(v:unknown):v is string=>typeof v==="string"&&v.length>0&&v.length<=256&&isWellFormedText(v)&&v.normalize("NFC")===v;
const uint=(v:unknown):v is bigint=>typeof v==="bigint"&&v>=0n&&v<=max;
type Init={ok:true;definitions:readonly EventVersionRegistryV1Definition[]}|{ok:false;code:"VERSION_REGISTRY_DEFINITION_INVALID"|"UPCASTER_CHAIN_INCOMPLETE"};

function ownRecord(value:unknown,keys:readonly string[]):Record<string,unknown>|null{
  if(value===null||typeof value!=="object"||types.isProxy(value))return null;const proto=Object.getPrototypeOf(value);if(proto!==Object.prototype&&proto!==null)return null;
  const own=Reflect.ownKeys(value);if(own.length!==keys.length||own.some(k=>typeof k!=="string"||!keys.includes(k)))return null;const out:Record<string,unknown>=Object.create(null);
  for(const key of keys){const d=Object.getOwnPropertyDescriptor(value,key);if(d===undefined||!("value" in d)||!d.enumerable)return null;out[key]=d.value;}return out;
}
function ownOperation(value:unknown):unknown{if(value===null||typeof value!=="object"||types.isProxy(value))return undefined;const proto=Object.getPrototypeOf(value);if(proto!==Object.prototype&&proto!==null)return undefined;const d=Object.getOwnPropertyDescriptor(value,"operation");return d!==undefined&&"value" in d&&d.enumerable?d.value:undefined}
function canonical(value:unknown):CanonicalValue|null{try{return decodeCanonical(encodeCanonical(value as CanonicalValue));}catch{return null}}
function record(value:CanonicalValue):value is{readonly[k:string]:CanonicalValue}{return value!==null&&typeof value==="object"&&!Array.isArray(value)&&!(value instanceof Uint8Array)}
function initialize(value:unknown):Init{
  if(!Array.isArray(value)||types.isProxy(value)||Object.getPrototypeOf(value)!==Array.prototype||Reflect.ownKeys(value).length!==value.length+1)return{ok:false,code:"VERSION_REGISTRY_DEFINITION_INVALID"};
  const definitions:EventVersionRegistryV1Definition[]=[],seen=new Set<string>(),last=new Map<string,bigint>();
  for(let i=0;i<value.length;i++){
    const item=Object.getOwnPropertyDescriptor(value,String(i));if(item===undefined||!("value" in item)||!item.enumerable)return{ok:false,code:"VERSION_REGISTRY_DEFINITION_INVALID"};
    const op=ownOperation(item.value),keys=op==="replace-payload"?[...baseKeys,"payload"]:op==="merge-record-fields"?[...baseKeys,"fields"]:baseKeys,row=ownRecord(item.value,keys);
    if(row===null||!text(row.event_type)||!uint(row.from_version)||!uint(row.to_version)||!text(row.upcaster_id)||!uint(row.upcaster_version)||!(["retain-payload","replace-payload","merge-record-fields"] as unknown[]).includes(row.operation))return{ok:false,code:"VERSION_REGISTRY_DEFINITION_INVALID"};
    if(row.to_version!==row.from_version+1n)return{ok:false,code:"UPCASTER_CHAIN_INCOMPLETE"};const selector=`${row.event_type}\0${row.from_version}`;if(seen.has(selector)||(last.get(row.event_type)??-1n)>=row.from_version)return{ok:false,code:"UPCASTER_CHAIN_INCOMPLETE"};seen.add(selector);last.set(row.event_type,row.from_version);
    const base={event_type:row.event_type,from_version:row.from_version,to_version:row.to_version,upcaster_id:row.upcaster_id,upcaster_version:row.upcaster_version};
    if(row.operation==="retain-payload")definitions.push(Object.freeze({...base,operation:"retain-payload"}));
    else if(row.operation==="replace-payload"){const payload=canonical(row.payload);if(payload===null&&row.payload!==null)return{ok:false,code:"VERSION_REGISTRY_DEFINITION_INVALID"};definitions.push(Object.freeze({...base,operation:"replace-payload",payload:payload!}));}
    else{const fields=canonical(row.fields);if(fields===null||!record(fields))return{ok:false,code:"VERSION_REGISTRY_DEFINITION_INVALID"};definitions.push(Object.freeze({...base,operation:"merge-record-fields",fields}));}
  }
  return{ok:true,definitions:Object.freeze(definitions)};
}
function identity(definition:EventVersionRegistryV1Definition):string{return eirDigest("keep.spine.upcaster-definition.v1",definition as unknown as CanonicalValue)}

export class EventVersionRegistryV1{
  private readonly initialized:Init;
  constructor(definitions:unknown){this.initialized=initialize(definitions)}
  interpreterSet(eventType:string,sourceVersion:bigint,targetVersion:bigint):EventVersionRegistryV1SetResult{
    if(!this.initialized.ok)return this.initialized;if(!text(eventType)||!uint(sourceVersion)||!uint(targetVersion)||targetVersion<sourceVersion||sourceVersion===0n)return{ok:false,code:"UNKNOWN_EVENT_VERSION"};
    const chain:EventVersionRegistryV1Definition[]=[];for(let version=sourceVersion;version<targetVersion;version+=1n){const d=this.initialized.definitions.find(x=>x.event_type===eventType&&x.from_version===version&&x.to_version===version+1n);if(d===undefined)return{ok:false,code:"UPCASTER_CHAIN_INCOMPLETE"};chain.push(d)}
    const adapter_identities=Object.freeze(chain.map(identity)),interpreter_set_digest=eirDigest("keep.spine.interpreter-set.v1",{event_type:eventType,source_version:sourceVersion,target_version:targetVersion,adapter_identities} as CanonicalValue);return{ok:true,adapter_identities,interpreter_set_digest};
  }
  upcast(proposal:unknown,trustedContext:EventAdmissionV1TrustedContext,targetVersion:bigint,expectedInterpreterSetDigest:string):EventVersionRegistryV1Result{
    const admitted=EventAdmissionV1Admit(proposal,trustedContext);if(!admitted.ok){if(admitted.code==="EVENT_PROPOSAL_INVALID"&&admitted.upstream_code==="EVENT_SCHEMA_UNSUPPORTED")return{ok:false,code:"UNKNOWN_EVENT_VERSION"};return admitted}
    const encoded=EventEnvelopeV1Encode(proposal);if(!encoded.ok||encoded.event_digest!==admitted.admission.event_id)return{ok:false,code:"UPCASTER_EVENT_MISMATCH"};
    let decoded:CanonicalValue;try{decoded=decodeCanonical(encoded.canonical_bytes)}catch{return{ok:false,code:"UPCASTER_EVENT_MISMATCH"}}if(!record(decoded)||typeof decoded.event_type!=="string"||typeof decoded.schema_version!=="bigint")return{ok:false,code:"UPCASTER_EVENT_MISMATCH"};const eventType=decoded.event_type,sourceVersion=decoded.schema_version;let current:{[k:string]:CanonicalValue}=decoded;
    const set=this.interpreterSet(eventType,sourceVersion,targetVersion);if(!set.ok)return set;if(!hex.test(expectedInterpreterSetDigest)||expectedInterpreterSetDigest!==set.interpreter_set_digest)return{ok:false,code:"UPCASTER_SET_MISMATCH"};
    if(!this.initialized.ok)return this.initialized;for(let i=0;i<set.adapter_identities.length;i++){
      const d=this.initialized.definitions.find(x=>x.event_type===eventType&&x.from_version===sourceVersion+BigInt(i));if(d===undefined)return{ok:false,code:"UPCASTER_CHAIN_INCOMPLETE"};let payload:CanonicalValue=current.payload!;
      if(d.operation==="replace-payload")payload=d.payload;else if(d.operation==="merge-record-fields"){if(!record(payload))return{ok:false,code:"UPCASTER_PAYLOAD_INVALID"};payload=Object.assign(Object.create(null),payload,d.fields)}
      current=Object.assign(Object.create(null),current,{schema_version:d.to_version,payload});
    }
    const current_event_bytes=encodeCanonical(current);
    return{ok:true,original_event_id:admitted.admission.event_id,original_event_bytes:encoded.canonical_bytes.slice(),current_event_value:decodeCanonical(current_event_bytes),current_event_bytes,source_version:sourceVersion,target_version:targetVersion,adapter_identities:set.adapter_identities,interpreter_set_digest:set.interpreter_set_digest,authority:admitted.admission.authority,pure:true,historical_bytes_mutated:false,authoritative:false};
  }
}
