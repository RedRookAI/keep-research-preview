import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { FileProjectCheckpointStore } from "../src/autonomy/project_checkpoint_store.js";
import { PROJECT_STATE_SCHEMA_VERSION, type ProjectState } from "../src/autonomy/project_state.js";
import type { ProjectId } from "../src/session/project_id.js";
import { AuthoritativeAppendV1 } from "../src/spine/authoritative_append_v1.js";
import type { EventAdmissionV1TrustedContext } from "../src/spine/event_admission_v1.js";
import { EventEnvelopeV1CodecIdentity, EventEnvelopeV1Encode, EventEnvelopeV1Schema, type EventEnvelopeV1Value } from "../src/spine/event_envelope_v1.js";
import { FileWorkAttemptAuthorityV1, InvalidWorkAttemptError, StaleWorkAttemptError, WorkAttemptConflictError, WORK_ATTEMPT_STAGES_V1, replayWorkAttemptV1, type WorkAttemptIdentityV1, type WorkAttemptReferenceV1 } from "../src/spine/work_attempt_authority_v1.js";

const H = (character: string) => character.repeat(64);
const canonical = (value: unknown): string => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value !== null && typeof value === "object" ? `{${Object.keys(value as Record<string, unknown>).sort().map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(",")}}` : JSON.stringify(value);
const digest = (value: unknown) => createHash("sha256").update(canonical(value)).digest("hex");
const fresh = () => mkdtempSync(join(tmpdir(), "keep-sg01-t003-"));
const ticketBody = { id: "SG-01-T003", title: "Fence one attempt", requirements: ["fence every port"], finish_conditions: ["resume exact attempt"], research_contract: { lanes: ["current", "historical", "cross"] }, mutation_surface: ["work-attempt"] };
const identity = (track: "n1" | "enterprise" = "n1"): WorkAttemptIdentityV1 => ({
  project_id: `prj_${"1".repeat(32)}`, goal_id: "goal-1", subgoal_id: "SG-01", ticket_id: "SG-01-T003",
  ticket_body: ticketBody, ticket_body_digest: digest(ticketBody), failure_lessons: [{ id: "stale-writer", digest: H("a") }], track,
  authority: track === "n1" ? { kind: "n1", owner_id: "owner", custody_id: "local", organization_services: "ABSENT" } : { kind: "enterprise", organization_id: "org", tenant_id:"tenant", actor_id: "agent", role_id: "maintainer", separation_policy_id: "sod", custody_id:"org-custody", isolation_id:"isolation", custody_evidence_digest: H("b"), isolation_evidence_digest: H("c"), local_owner_substitution: false },
  product_commit: "f3d1ca30b090ba97837440be8cb67f7750895f8f", interpreter_identity: "node-22.23.0",
});
const reference = (value: {identity_digest:string;attempt_id:string;generation:number}): WorkAttemptReferenceV1 => ({ identity_digest:value.identity_digest, attempt_id:value.attempt_id, generation:value.generation });
const projectState = (runId:string,projectId:WorkAttemptIdentityV1["project_id"],revision=0): ProjectState => ({ schemaVersion:PROJECT_STATE_SCHEMA_VERSION, revision, runId, projectId:projectId as ProjectId, goal:"goal", stage:"implement", artifacts:{}, posture:"autonomous", stepsRemaining:1, reworkCount:0, status:"running", retry:{attemptsByStage:{},attemptsConsumed:0,runLimit:1}, consumedSignals:[] });
const context = (track: "n1" | "enterprise"): EventAdmissionV1TrustedContext => track === "n1" ? { kind:"n1",track:"n1",history_id:"history-n1",actor_id:"owner",authority_domain:"local",custody_id:"local",committed_lineage:[],witnessed_head:null } : { kind:"enterprise",track:"enterprise",history_id:"history-enterprise",actor_id:"agent",authority_domain:"org/tenant",custody_id:"org-custody",organization_id:"org",tenant_id:"tenant",actor_role_id:"maintainer",isolation_id:"isolation",committed_lineage:[],witnessed_head:null };
const proposal = (trusted:EventAdmissionV1TrustedContext):EventEnvelopeV1Value => ({ schema:EventEnvelopeV1Schema,schema_version:1n,codec:EventEnvelopeV1CodecIdentity,codec_version:1n,history_id:trusted.history_id,sequence:0n,predecessor_event_id:null,predecessor_head_id:null,event_type:"generic",actor_id:trusted.actor_id,authority_domain:trusted.authority_domain,track:trusted.track,payload:{ticket:"SG-01-T003"},effect_correlation:null });

const childRoot = process.env.KEEP_SG01_T003_CHILD_ROOT;
if (childRoot !== undefined) {
  const ref = JSON.parse(process.env.KEEP_SG01_T003_REFERENCE!) as WorkAttemptReferenceV1;
  const authority = new FileWorkAttemptAuthorityV1(childRoot);
  const snapshot = authority.load(ref);
  writeFileSync(process.env.KEEP_SG01_T003_RESULT!, JSON.stringify({ attempt_id:snapshot.attempt_id, generation:snapshot.generation, replay:replayWorkAttemptV1(snapshot.transitions) }));
  process.exit(0);
}

for (const track of ["n1", "enterprise"] as const) test(`SG-01-T003-${track === "n1" ? "C01" : "C02"} direct ${track} attempt fences real append and checkpoint`, async () => {
  const root=fresh(), authority=new FileWorkAttemptAuthorityV1(join(root,"attempt")), admitted=await authority.admit(identity(track)), fence=authority.fence(reference(admitted));
  const trusted=context(track), event=proposal(trusted);assert.equal(EventEnvelopeV1Encode(event).ok,true);
  const historyRoot=join(root,"history");mkdirSync(historyRoot,{mode:0o700});
  const append=new AuthoritativeAppendV1({storage_root:historyRoot,durability_profile:{kind:"verified-local-posix-v1",max_record_bytes:1_048_576n},attempt_fence:fence});
  const appended=await append.append(event,trusted);assert.equal(appended.ok,true);
  const checkpoints=new FileProjectCheckpointStore(join(root,"checkpoints"));const saved=await checkpoints.saveAttempt(projectState(admitted.identity_digest,admitted.identity.project_id),undefined,fence);assert.equal(saved.state.revision,0);
  let current=admitted;
  for(let i=0;i<WORK_ATTEMPT_STAGES_V1.length;i++){
    current=await authority.record(reference(current),WORK_ATTEMPT_STAGES_V1[i]!,"FAILURE",H((i%10).toString(16)));
    assert.equal(replayWorkAttemptV1(current.transitions).next_stage,WORK_ATTEMPT_STAGES_V1[i]);
    current=await authority.record(reference(current),WORK_ATTEMPT_STAGES_V1[i]!,"ADVANCE",H(((i+1)%10).toString(16)));
  }
  assert.equal(replayWorkAttemptV1(current.transitions).next_stage,null);
  await assert.rejects(authority.record(reference(current),"COMPLETE","ADVANCE",H("d")),InvalidWorkAttemptError);
});

test("SG-01-T003-C03 incomplete, regenerated, duplicate, and phase-skipping attempts fail closed", async () => {
  const root=fresh(), authority=new FileWorkAttemptAuthorityV1(root), good=identity(), admitted=await authority.admit(good);
  await assert.rejects(authority.admit(good),WorkAttemptConflictError);
  await assert.rejects(authority.withCurrent({...reference(admitted),attempt_id:"f".repeat(32)},async()=>undefined),StaleWorkAttemptError);
  await assert.rejects(new FileWorkAttemptAuthorityV1(fresh()).admit({...good,ticket_body:{id:good.ticket_id,title:"projection"}}),InvalidWorkAttemptError);
  for(const changed of [{...good,project_id:""},{...good,goal_id:"  "},{...good,interpreter_identity:" node-22 "},{...good,ticket_id:"SG-1-T3"},{...good,product_commit:"abc"},{...good,failure_lessons:[]},{...good,failure_lessons:[good.failure_lessons[0],good.failure_lessons[0]]}])await assert.rejects(new FileWorkAttemptAuthorityV1(fresh()).admit(changed),InvalidWorkAttemptError);
  await assert.rejects(authority.record(reference(admitted),"IMPLEMENTING","ADVANCE",H("e")),InvalidWorkAttemptError);
});

test("SG-01-T003-C04 one takeover wins, continues the checkpoint lineage, and fences the loser", async () => {
  const root=fresh(), authority=new FileWorkAttemptAuthorityV1(join(root,"attempt")), admitted=await authority.admit(identity()), old=reference(admitted), fence=authority.fence(old);
  const checkpoints=new FileProjectCheckpointStore(join(root,"stale-checkpoints"));await checkpoints.saveAttempt(projectState(admitted.identity_digest,admitted.identity.project_id),undefined,fence);
  const historyRoot=join(root,"stale-history");mkdirSync(historyRoot,{mode:0o700});const trusted=context("n1"), firstAppend=new AuthoritativeAppendV1({storage_root:historyRoot,durability_profile:{kind:"verified-local-posix-v1",max_record_bytes:1_048_576n},attempt_fence:fence});const first=await firstAppend.append(proposal(trusted),trusted);assert.equal(first.ok,true);
  let release!:()=>void, entered!:()=>void;const started=new Promise<void>(resolve=>entered=resolve),hold=new Promise<void>(resolve=>release=resolve);
  const commit=fence.withCurrent(async()=>{entered();await hold;return "committed";});await started;
  let takeoverDone=false;const takeover=authority.takeover(old).then(value=>{takeoverDone=true;return value;});await new Promise(resolve=>setImmediate(resolve));assert.equal(takeoverDone,false);release();assert.equal(await commit,"committed");const current=await takeover;
  const second=await Promise.allSettled([authority.takeover(reference(current)),authority.takeover(reference(current))]);assert.equal(second.filter(x=>x.status==="fulfilled").length,1);
  const winnerResult=second.find((x)=>x.status==="fulfilled");if(winnerResult?.status!=="fulfilled")throw new Error("takeover winner missing");const winner=winnerResult.value,winnerFence=authority.fence(reference(winner));
  const continued=await checkpoints.saveAttempt(projectState(admitted.identity_digest,admitted.identity.project_id,1),0,winnerFence);assert.equal(continued.state.revision,1);
  if(!first.ok)throw new Error("unreachable");const lineage={sequence:0n,event_id:first.receipt.event_id,predecessor_event_id:null,predecessor_head_id:null,head_id:first.receipt.next_head_id},continuedTrusted={...trusted,committed_lineage:[lineage],witnessed_head:{sequence:0n,event_id:first.receipt.event_id,head_id:first.receipt.next_head_id}},next={...proposal(trusted),sequence:1n,predecessor_event_id:first.receipt.event_id,predecessor_head_id:first.receipt.next_head_id};const appended=await new AuthoritativeAppendV1({storage_root:historyRoot,durability_profile:{kind:"verified-local-posix-v1",max_record_bytes:1_048_576n},attempt_fence:winnerFence}).append(next,continuedTrusted);assert.equal(appended.ok,true);
  const advanced=await authority.record(reference(winner),"RESEARCH_PENDING","ADVANCE",H("d"));assert.equal(replayWorkAttemptV1(advanced.transitions).next_stage,"RESEARCH_COMPLETE");
  const staleAppend=new AuthoritativeAppendV1({storage_root:historyRoot,durability_profile:{kind:"verified-local-posix-v1",max_record_bytes:1_048_576n},attempt_fence:fence});assert.deepEqual(await staleAppend.append(proposal(trusted),trusted),{ok:false,code:"WRITER_FENCED"});
  await assert.rejects(checkpoints.saveAttempt(projectState(admitted.identity_digest,admitted.identity.project_id,2),1,fence),StaleWorkAttemptError);
});

test("SG-01-T003-C05 scope, track, product, interpreter, and authority substitutions refuse", async () => {
  const authority=new FileWorkAttemptAuthorityV1(fresh()), admitted=await authority.admit(identity("enterprise"));
  for(const field of ["identity_digest","attempt_id"] as const)await assert.rejects(authority.withCurrent({...reference(admitted),[field]:field==="attempt_id"?"e".repeat(32):H("e")},async()=>undefined),StaleWorkAttemptError);
  for(const changed of [{...identity("enterprise"),project_id:"project-2"},{...identity("enterprise"),product_commit:"e".repeat(40)},{...identity("enterprise"),interpreter_identity:"node-other"}])await assert.rejects(authority.withCurrent({...reference(admitted),identity_digest:digest(changed)},async()=>undefined),StaleWorkAttemptError);
  await assert.rejects(new FileWorkAttemptAuthorityV1(fresh()).admit({...identity("enterprise"),track:"n1"}),InvalidWorkAttemptError);
  const n1Authority=new FileWorkAttemptAuthorityV1(fresh()),n1=await n1Authority.admit(identity("n1")),root=fresh(),enterprise=context("enterprise");const cross=new AuthoritativeAppendV1({storage_root:root,durability_profile:{kind:"verified-local-posix-v1",max_record_bytes:1_048_576n},attempt_fence:n1Authority.fence(reference(n1))});assert.deepEqual(await cross.append(proposal(enterprise),enterprise),{ok:false,code:"TRACK_AUTHORITY_SUBSTITUTION"});
  assert.equal(authority.load(reference(admitted)).identity.track,"enterprise");
});

test("SG-01-T003-C06 a fresh OS process resumes exact durable identity at first unmet transition", async () => {
  const root=fresh(), authority=new FileWorkAttemptAuthorityV1(root), admitted=await authority.admit(identity()), ref=reference(admitted);
  await authority.record(ref,"RESEARCH_PENDING","ADVANCE",H("1"));await authority.record(ref,"RESEARCH_COMPLETE","FAILURE",H("2"));
  const result=join(root,"child-result.json"),child=spawnSync(process.execPath,[new URL(import.meta.url).pathname],{env:{...process.env,KEEP_SG01_T003_CHILD_ROOT:root,KEEP_SG01_T003_REFERENCE:JSON.stringify(ref),KEEP_SG01_T003_RESULT:result},encoding:"utf8"});
  assert.equal(child.status,0,child.stderr);const recovered=JSON.parse(readFileSync(result,"utf8"));assert.deepEqual(recovered,{attempt_id:ref.attempt_id,generation:0,replay:{next_stage:"RESEARCH_COMPLETE",advancing_count:1}});
});
