import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { decodeCanonical, eirDigest } from "../src/eir/canonical.js";
import { AuthoritativeAppendV1 } from "../src/spine/authoritative_append_v1.js";
import {
  CommittedHeadV1,
  type CommittedHeadV1WitnessAck,
  type CommittedHeadV1WitnessPort,
} from "../src/spine/committed_head_v1.js";
import { EventAdmissionV1HeadDigestDomain, type EventAdmissionV1LineageRecord, type EventAdmissionV1TrustedContext } from "../src/spine/event_admission_v1.js";
import { EventEnvelopeV1CodecIdentity, EventEnvelopeV1Encode, EventEnvelopeV1Schema, type EventEnvelopeV1Value } from "../src/spine/event_envelope_v1.js";

const profile = { kind: "verified-local-posix-v1" as const, max_record_bytes: 1_048_576n };
const keys = generateKeyPairSync("ed25519");
const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
const fresh = () => mkdtempSync(join(tmpdir(), "keep-t004-"));
const n1 = (lineage: readonly EventAdmissionV1LineageRecord[] = []): EventAdmissionV1TrustedContext => ({ kind:"n1", track:"n1", history_id:"h-local", actor_id:"owner", authority_domain:"local", custody_id:"disk", committed_lineage:lineage, witnessed_head:lineage.length ? { sequence:lineage.at(-1)!.sequence, event_id:lineage.at(-1)!.event_id, head_id:lineage.at(-1)!.head_id } : null });
const enterprise = (): EventAdmissionV1TrustedContext => ({ kind:"enterprise", track:"enterprise", history_id:"h-enterprise", actor_id:"agent", authority_domain:"org/tenant", custody_id:"hsm", organization_id:"org", tenant_id:"tenant", actor_role_id:"release", isolation_id:"iso", committed_lineage:[], witnessed_head:null });
const proposal = (c: EventAdmissionV1TrustedContext): EventEnvelopeV1Value => { const t=c.committed_lineage.at(-1); return { schema:EventEnvelopeV1Schema, schema_version:1n, codec:EventEnvelopeV1CodecIdentity, codec_version:1n, history_id:c.history_id, sequence:t?t.sequence+1n:0n, predecessor_event_id:t?.event_id??null, predecessor_head_id:t?.head_id??null, event_type:"goal.admitted", actor_id:c.actor_id, authority_domain:c.authority_domain, track:c.track, payload:{value:"one"}, effect_correlation:null }; };

class Witness implements CommittedHeadV1WitnessPort {
  current: CommittedHeadV1WitnessAck | null = null;
  fail = false;
  wrong = false;
  async latest(): Promise<CommittedHeadV1WitnessAck | null> { return this.current; }
  async compareAndPersist(expected: string | null, bytes: Uint8Array): Promise<CommittedHeadV1WitnessAck> {
    if (this.fail) throw new Error("witness disk failed");
    const currentDigest=this.current?.ok===true?this.current.checkpoint_digest:null;
    if(currentDigest!==expected) return { ok:false, code:"WITNESS_CONFLICT" };
    const persisted=this.wrong ? new Uint8Array([...bytes,0]) : bytes;
    const ack:CommittedHeadV1WitnessAck={ok:true,durable:true,checkpoint_bytes:persisted,checkpoint_digest:eirDigest("keep.spine.committed-head-checkpoint-bytes.v1",persisted),signature:new Uint8Array(sign(null,persisted,keys.privateKey))};
    this.current=ack; return ack;
  }
}
const build=(root:string,witness?:CommittedHeadV1WitnessPort,historyDomain="history-disk",witnessDomain="witness-disk")=>new CommittedHeadV1({append:new AuthoritativeAppendV1({storage_root:root,durability_profile:profile}),history_storage_domain:historyDomain,witness_storage_domain:witnessDomain,...(witness===undefined?{}:{witness}),witness_public_key:publicKey});

test("PG-05-T004-FC01 exact durable append plus separate durable witness commits",async()=>{const witness=new Witness(),c=n1(),r=await build(fresh(),witness).commit(proposal(c),c);assert.equal(r.ok,true);if(!r.ok)return;assert.deepEqual({durable:r.receipt.durable,witnessed:r.receipt.witnessed,committed:r.receipt.committed,authoritative:r.receipt.authoritative},{durable:true,witnessed:true,committed:true,authoritative:false});assert.equal(witness.current?.ok,true);});
test("PG-05-T004-FC02 enterprise attribution is retained exactly",async()=>{const c=enterprise(),r=await build(fresh(),new Witness()).commit(proposal(c),c);assert.equal(r.ok,true);if(!r.ok)return;assert.equal(r.receipt.authority.kind,"enterprise");if(r.receipt.authority.kind==="enterprise")assert.deepEqual([r.receipt.authority.organization_id,r.receipt.authority.tenant_id,r.receipt.authority.actor_role_id,r.receipt.authority.isolation_id],["org","tenant","release","iso"]);});
test("PG-05-T004-FC03 missing witness refuses before append",async()=>{const r=await build(fresh()).commit(proposal(n1()),n1());assert.deepEqual(r,{ok:false,code:"WITNESS_REQUIRED"});});
test("PG-05-T004-FC04 same-history witness is not independent",async()=>{const r=await build(fresh(),new Witness(),"same","same").commit(proposal(n1()),n1());assert.deepEqual(r,{ok:false,code:"WITNESS_NOT_INDEPENDENT"});});
test("PG-05-T004-FC05 wrong acknowledged bytes cannot commit",async()=>{const w=new Witness();w.wrong=true;const r=await build(fresh(),w).commit(proposal(n1()),n1());assert.deepEqual(r,{ok:false,code:"WITNESS_HEAD_MISMATCH"});});
test("PG-05-T004-FC06 witness persistence failure returns no committed receipt",async()=>{const w=new Witness();w.fail=true;const r=await build(fresh(),w).commit(proposal(n1()),n1());assert.deepEqual(r,{ok:false,code:"WITNESS_PERSISTENCE_FAILED"});});
test("PG-05-T004-FC07 fork or truncation against witness refuses before append",async()=>{const w=new Witness(),c=n1(),first=await build(fresh(),w).commit(proposal(c),c);assert.equal(first.ok,true);const root=fresh();const r=await build(root,w).commit(proposal(c),c);assert.deepEqual(r,{ok:false,code:"HISTORY_WITNESS_MISMATCH"});if(w.current?.ok){const checkpoint=decodeCanonical(w.current.checkpoint_bytes) as Record<string,unknown>;assert.notEqual(checkpoint.head_id,null);}});
