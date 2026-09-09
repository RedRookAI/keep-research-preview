import { types } from "node:util";

import { decodeCanonical, eirDigest, encodeCanonical, isWellFormedText, type CanonicalValue } from "../eir/canonical.js";
import { EventAdmissionV1Admit, type EventAdmissionV1Authority, type EventAdmissionV1Result, type EventAdmissionV1TrustedContext } from "./event_admission_v1.js";
import { EventEnvelopeV1Encode } from "./event_envelope_v1.js";

export type ReducerRegistryV1Capability = "clock"|"randomness"|"environment"|"filesystem"|"network"|"io"|"model"|"effect"|"actuator";
export interface ReducerRegistryV1Definition {
  readonly event_type:string;
  readonly event_schema_version:bigint;
  readonly reducer_id:string;
  readonly reducer_version:bigint;
  readonly transition:"retain-state"|"replace-state-with-event-payload";
  readonly capabilities:readonly ReducerRegistryV1Capability[];
}
export interface ReducerRegistryV1Receipt {
  readonly state_bytes:Uint8Array;
  readonly state_digest:string;
  readonly reducer_identity:string;
  readonly event_id:string;
  readonly authority:EventAdmissionV1Authority;
  readonly pure:true;
  readonly effects_performed:false;
  readonly authoritative:false;
}
type Refusal=Exclude<EventAdmissionV1Result,{ok:true}>|{readonly ok:false;readonly code:"STATE_CANONICAL_INVALID"|"REDUCER_DEFINITION_INVALID"|"REDUCER_CAPABILITY_FORBIDDEN"|"REPLAY_EFFECT_FORBIDDEN"|"REDUCER_UNAVAILABLE"|"REDUCER_EVENT_MISMATCH"};
export type ReducerRegistryV1Result={readonly ok:true}&ReducerRegistryV1Receipt|Refusal;

const keys=["event_type","event_schema_version","reducer_id","reducer_version","transition","capabilities"] as const;
const text=(v:unknown)=>typeof v==="string"&&v.length>0&&v.length<=256&&isWellFormedText(v);
const exactBytes=(a:Uint8Array,b:Uint8Array)=>Buffer.from(a).equals(Buffer.from(b));
type Init={ok:true;definitions:readonly ReducerRegistryV1Definition[]}|{ok:false;code:"REDUCER_DEFINITION_INVALID"|"REDUCER_CAPABILITY_FORBIDDEN"|"REPLAY_EFFECT_FORBIDDEN"};
function captureArray(value:unknown):readonly unknown[]|null{
  if(!Array.isArray(value)||types.isProxy(value)||Object.getPrototypeOf(value)!==Array.prototype)return null;
  const own=Reflect.ownKeys(value),length=Object.getOwnPropertyDescriptor(value,"length");
  if(length===undefined||!("value" in length)||own.length!==value.length+1)return null;
  const out:unknown[]=[];for(let i=0;i<value.length;i++){const d=Object.getOwnPropertyDescriptor(value,String(i));if(d===undefined||!("value" in d)||!d.enumerable)return null;out.push(d.value)}return out;
}
function initialize(value:unknown):Init{
  const rows=captureArray(value);if(rows===null)return{ok:false,code:"REDUCER_DEFINITION_INVALID"};const definitions:ReducerRegistryV1Definition[]=[],seen=new Set<string>();
  for(const row of rows){
    if(row===null||typeof row!=="object"||types.isProxy(row)||Object.getPrototypeOf(row)!==Object.prototype)return{ok:false,code:"REDUCER_DEFINITION_INVALID"};
    const own=Reflect.ownKeys(row),get=(k:string)=>{const d=Object.getOwnPropertyDescriptor(row,k);return d!==undefined&&"value" in d&&d.enumerable?d.value:undefined};
    const capabilities=captureArray(get("capabilities"));
    if(capabilities?.some(x=>x==="effect"||x==="actuator"))return{ok:false,code:"REPLAY_EFFECT_FORBIDDEN"};
    if(capabilities!==null&&capabilities!==undefined&&capabilities.length>0)return{ok:false,code:"REDUCER_CAPABILITY_FORBIDDEN"};
    if(own.length!==keys.length||own.some(k=>typeof k!=="string"||!keys.includes(k as typeof keys[number]))||capabilities===null||capabilities===undefined)return{ok:false,code:"REDUCER_DEFINITION_INVALID"};
    const event_type=get("event_type"),event_schema_version=get("event_schema_version"),reducer_id=get("reducer_id"),reducer_version=get("reducer_version"),transition=get("transition");
    if(!text(event_type)||typeof event_schema_version!=="bigint"||!text(reducer_id)||typeof reducer_version!=="bigint"||typeof transition!=="string")return{ok:false,code:"REDUCER_DEFINITION_INVALID"};
    const selector=`${event_type}\0${event_schema_version}`;if(seen.has(selector))return{ok:false,code:"REDUCER_DEFINITION_INVALID"};seen.add(selector);
    definitions.push(Object.freeze({event_type,event_schema_version,reducer_id,reducer_version,transition,capabilities:Object.freeze([])}) as ReducerRegistryV1Definition);
  }
  return{ok:true,definitions:Object.freeze(definitions)};
}

export class ReducerRegistryV1{
  private readonly initialized:Init;
  constructor(definitions:unknown){this.initialized=initialize(definitions)}
  reduce(stateBytes:Uint8Array,proposal:unknown,trustedContext:EventAdmissionV1TrustedContext):ReducerRegistryV1Result{
    if(!this.initialized.ok)return this.initialized;
    let state:CanonicalValue;try{state=decodeCanonical(stateBytes);if(!exactBytes(encodeCanonical(state),stateBytes))return{ok:false,code:"STATE_CANONICAL_INVALID"}}catch{return{ok:false,code:"STATE_CANONICAL_INVALID"}}
    const admitted=EventAdmissionV1Admit(proposal,trustedContext);if(!admitted.ok)return admitted;
    const encoded=EventEnvelopeV1Encode(proposal);if(!encoded.ok||encoded.event_digest!==admitted.admission.event_id)return{ok:false,code:"REDUCER_EVENT_MISMATCH"};
    let event:Record<string,CanonicalValue>;try{event=decodeCanonical(encoded.canonical_bytes) as Record<string,CanonicalValue>}catch{return{ok:false,code:"REDUCER_EVENT_MISMATCH"}}
    const definition=this.initialized.definitions.find(d=>d.event_type===event.event_type&&d.event_schema_version===event.schema_version);
    if(definition===undefined||definition.reducer_version!==1n||(definition.transition!=="retain-state"&&definition.transition!=="replace-state-with-event-payload"))return{ok:false,code:"REDUCER_UNAVAILABLE"};
    const next=definition.transition==="retain-state"?state:event.payload;if(next===undefined)return{ok:false,code:"REDUCER_EVENT_MISMATCH"};
    const state_bytes=encodeCanonical(next),reducer_identity=eirDigest("keep.spine.reducer-definition.v1",definition as unknown as CanonicalValue);
    return{ok:true,state_bytes,state_digest:eirDigest("keep.spine.reducer-state-bytes.v1",state_bytes),reducer_identity,event_id:admitted.admission.event_id,authority:admitted.admission.authority,pure:true,effects_performed:false,authoritative:false};
  }
}
