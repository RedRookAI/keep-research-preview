import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";

import { decodeCanonical, encodeCanonical, type CanonicalValue } from "../src/eir/canonical.js";
import { ReducerRegistryV1, type ReducerRegistryV1Definition } from "../src/spine/reducer_registry_v1.js";
import { type EventAdmissionV1TrustedContext } from "../src/spine/event_admission_v1.js";
import { EventEnvelopeV1CodecIdentity, EventEnvelopeV1Schema, type EventEnvelopeV1Value } from "../src/spine/event_envelope_v1.js";

const definition=(transition:"retain-state"|"replace-state-with-event-payload"="retain-state"):ReducerRegistryV1Definition=>({event_type:"goal.admitted",event_schema_version:1n,reducer_id:`goal-${transition}`,reducer_version:1n,transition,capabilities:[]});
const n1=():EventAdmissionV1TrustedContext=>({kind:"n1",track:"n1",history_id:"reduce-history",actor_id:"owner",authority_domain:"local",custody_id:"disk",committed_lineage:[],witnessed_head:null});
const enterprise=():EventAdmissionV1TrustedContext=>({kind:"enterprise",track:"enterprise",history_id:"reduce-history",actor_id:"agent",authority_domain:"org/tenant",custody_id:"hsm",organization_id:"org",tenant_id:"tenant",actor_role_id:"role",isolation_id:"iso",committed_lineage:[],witnessed_head:null});
const proposal=(c:EventAdmissionV1TrustedContext,payload:CanonicalValue={value:"event"}):EventEnvelopeV1Value=>({schema:EventEnvelopeV1Schema,schema_version:1n,codec:EventEnvelopeV1CodecIdentity,codec_version:1n,history_id:c.history_id,sequence:0n,predecessor_event_id:null,predecessor_head_id:null,event_type:"goal.admitted",actor_id:c.actor_id,authority_domain:c.authority_domain,track:c.track,payload,effect_correlation:null});
const state=encodeCanonical({count:1n,label:"prior"});
const reduce=(defs:unknown,c=n1(),p=proposal(c))=>new ReducerRegistryV1(defs).reduce(state,p,c);

if(process.env.KEEP_T005_CHILD==="1"){
  const r=reduce([definition("replace-state-with-event-payload")]);
  if(!r.ok)process.exit(2);
  process.stdout.write(JSON.stringify({bytes:Buffer.from(r.state_bytes).toString("base64"),reducer:r.reducer_identity}));
  process.exit(0);
}
const child=()=>new Promise<string>((resolve,reject)=>{const p=spawn(process.execPath,[new URL(import.meta.url).pathname],{env:{...process.env,KEEP_T005_CHILD:"1"},stdio:["ignore","pipe","pipe"]});let out="",err="";p.stdout.on("data",d=>out+=d);p.stderr.on("data",d=>err+=d);p.once("error",reject);p.once("exit",code=>code===0?resolve(out):reject(new Error(err||`child ${code}`)));});

test("PG-05-T005-FC01 identical inputs yield byte-identical state and reducer identity in fresh process",async()=>{const registry=new ReducerRegistryV1([definition("replace-state-with-event-payload")]),a=registry.reduce(state,proposal(n1()),n1()),b=registry.reduce(state,proposal(n1()),n1());assert.equal(a.ok,true);assert.deepEqual(a,b);const remote=JSON.parse(await child()) as {bytes:string;reducer:string};if(a.ok){assert.equal(remote.bytes,Buffer.from(a.state_bytes).toString("base64"));assert.equal(remote.reducer,a.reducer_identity);}});
test("PG-05-T005-FC02 neutral event preserves state semantics and separate track authority",()=>{const local=reduce([definition()],n1(),proposal(n1())),org=reduce([definition()],enterprise(),proposal(enterprise()));assert.equal(local.ok,true);assert.equal(org.ok,true);if(local.ok&&org.ok){assert.deepEqual(local.state_bytes,state);assert.deepEqual(org.state_bytes,state);assert.equal(local.authority.kind,"n1");assert.equal(org.authority.kind,"enterprise");if(org.authority.kind==="enterprise")assert.equal(org.authority.tenant_id,"tenant");}});
test("PG-05-T005-FC03 ambient capability requests refuse and no callback is accepted",()=>{for(const capability of ["clock","randomness","environment","filesystem","network","io","model"]){const d={...definition(),capabilities:[capability]};assert.deepEqual(reduce([d]),{ok:false,code:"REDUCER_CAPABILITY_FORBIDDEN"});}assert.deepEqual(reduce([{...definition(),callback:()=>Date.now()}]),{ok:false,code:"REDUCER_DEFINITION_INVALID"});});
test("PG-05-T005-FC04 actuator request returns replay refusal with zero calls",()=>{let calls=0;const d={...definition(),capabilities:["actuator"],actuator:()=>{calls++;}};assert.deepEqual(reduce([d]),{ok:false,code:"REPLAY_EFFECT_FORBIDDEN"});assert.equal(calls,0);});
test("PG-05-T005-FC05 unknown event reducer kind or version never falls back",()=>{assert.deepEqual(reduce([]),{ok:false,code:"REDUCER_UNAVAILABLE"});assert.deepEqual(reduce([{...definition(),reducer_version:2n}]),{ok:false,code:"REDUCER_UNAVAILABLE"});assert.deepEqual(reduce([{...definition(),transition:"unknown"}]),{ok:false,code:"REDUCER_UNAVAILABLE"});const c=n1(),p={...proposal(c),event_type:"effect.intent" as const,effect_correlation:{phase:"intent" as const,correlation_id:"effect-1"}} satisfies EventEnvelopeV1Value;assert.deepEqual(reduce([definition()],c,p),{ok:false,code:"REDUCER_UNAVAILABLE"});});
test("PG-05-T005-FC06 mutation aliases accessors proxies and extra fields refuse without changing inputs",()=>{const c=n1(),p=proposal(c),before=encodeCanonical(p as unknown as CanonicalValue),d={...definition(),mutate:"state"};assert.deepEqual(reduce([d],c,p),{ok:false,code:"REDUCER_DEFINITION_INVALID"});assert.deepEqual(encodeCanonical(p as unknown as CanonicalValue),before);const accessor=Object.defineProperty({...definition()},"reducer_id",{enumerable:true,get(){throw new Error("ran getter")}});assert.deepEqual(reduce([accessor]),{ok:false,code:"REDUCER_DEFINITION_INVALID"});assert.deepEqual(reduce([new Proxy(definition(),{})]),{ok:false,code:"REDUCER_DEFINITION_INVALID"});const decoded=decodeCanonical(state) as Record<string,CanonicalValue>;assert.equal(decoded.count,1n);assert.equal(decoded.label,"prior");});
