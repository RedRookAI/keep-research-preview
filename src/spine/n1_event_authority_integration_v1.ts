import { createHash, createPrivateKey, createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { closeSync, constants, existsSync, fstatSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, unlinkSync, writeFileSync, writeSync } from "node:fs";
import { join } from "node:path";

import type { GoalLifecycleRequestV1, TicketResearchActivationRequestV1 } from "../autonomy/project_state.js";
import { FileEngineeringStatusProjectionStoreV1 } from "../autonomy/project_checkpoint_store.js";
import { reconstructDecompositionApprovalAuthorityV1, type DecompositionApprovalAuthorityEventV1, type DecompositionApprovalReplayBundleV1 } from "../decomposition/decomposition_approval_events_v1.js";
import { reconstructDecompositionAuthorityV1, type DecompositionAuthorityEventV1, type DecompositionAuthorityReplayBundleV1 } from "../decomposition/decomposition_review_events_v1.js";
import { runN1DecompositionJourney } from "../decomposition/n1_decomposition_integration.js";
import { FileSystemLock, type DistributedLock } from "../lock/lock.js";
import { decodeCanonical, eirDigest, encodeCanonical, type CanonicalValue } from "../eir/canonical.js";
import { AuthoritativeAppendV1, AuthoritativeAppendV1HistoryPath, type AuthoritativeAppendV1Receipt } from "./authoritative_append_v1.js";
import { replayAuthoritativeHistoryV1, type AuthoritativeReplayV1Event, type AuthoritativeReplayV1Result } from "./authoritative_replay_v1.js";
import { CommittedHeadV1, CommittedHeadV1CheckpointDigestDomain, type CommittedHeadV1Receipt, type CommittedHeadV1Result, type CommittedHeadV1WitnessAck, type CommittedHeadV1WitnessPort } from "./committed_head_v1.js";
import { deriveDecompositionResultEventV1 } from "./decomposition_result_events_v1.js";
import { rebuildEngineeringStatusProjectionV1 } from "./engineering_status_projection_v1.js";
import { EventAdmissionV1HeadDigestDomain, type EventAdmissionV1LineageRecord, type EventAdmissionV1N1Context } from "./event_admission_v1.js";
import { EventEnvelopeV1CodecIdentity, EventEnvelopeV1Encode, EventEnvelopeV1Schema, type EventEnvelopeV1EventType, type EventEnvelopeV1Value } from "./event_envelope_v1.js";
import { reconstructGoalAuthorityEventsV1, type GoalAuthorityEventV1, type GoalAuthorityReplayBundleV1 } from "./goal_authority_events_v1.js";
import { ReducerRegistryV1 } from "./reducer_registry_v1.js";
import { EventVersionRegistryV1 } from "./version_registry_v1.js";

type Stream = "goal" | "review" | "approval";
type DomainEvent = GoalAuthorityEventV1 | DecompositionAuthorityEventV1 | DecompositionApprovalAuthorityEventV1;
type ReplayBundle = GoalAuthorityReplayBundleV1 | DecompositionAuthorityReplayBundleV1 | DecompositionApprovalReplayBundleV1;
const MAX_RECORD_BYTES = 8_388_608n;
const HEX = /^[0-9a-f]{64}$/u;
const ACK = /^([0-9a-f]{16})-([0-9a-f]{64})\.ack$/u;
const RECORD = /^([0-9a-f]{16})-([0-9a-f]{64})\.record$/u;
export const N1EventAuthorityProductBuildIdentityV1 = "keep.product-build.n1-event-authority.v1" as const;

export type N1EventAuthorityJourneyCodeV1 = "N1_EVENT_AUTHORITY_COMPLETE" | "N1_EVENT_AUTHORITY_RECOVERED" | "N1_UNWITNESSED_TAIL_RECOVERED" | "N1_WITNESS_FORK" | "N1_ENTERPRISE_CEREMONY_FORBIDDEN" | "TRACK_AUTHORITY_SUBSTITUTION" | "RESTART_AUTHORITY_REQUIRED" | "N1_EVENT_HISTORY_INVALID";
export interface N1EventAuthorityJourneyInputV1 {
  readonly schema_version: 1;
  readonly project_id: string;
  readonly run_id: string;
  readonly data_directory: string;
  readonly history_directory: string;
  readonly witness_directory: string;
  readonly owner_id: string;
  readonly custody_id: string;
  readonly organization_services: "ABSENT" | "REQUIRED";
  readonly witness_public_key: string | Uint8Array;
  readonly witness_private_key?: string | Uint8Array;
  readonly expected_product_build_identity?: string;
  readonly goal_request: GoalLifecycleRequestV1;
  readonly goal_events: readonly GoalAuthorityEventV1[];
  readonly review_events: readonly DecompositionAuthorityEventV1[];
  readonly approval_events: readonly DecompositionApprovalAuthorityEventV1[];
  readonly activation: TicketResearchActivationRequestV1;
}
export interface N1EventAuthorityJourneyReceiptV1 {
  readonly schema: "keep.n1-event-authority-journey";
  readonly schema_version: 1;
  readonly project_id: string;
  readonly run_id: string;
  readonly track: "n1";
  readonly organization_services: "ABSENT";
  readonly owner_id: string;
  readonly custody_id: string;
  readonly product_build_identity: typeof N1EventAuthorityProductBuildIdentityV1;
  readonly source_heads: Readonly<Record<Stream, { readonly event_count: number; readonly final_event_id: string; readonly final_head_id: string; readonly result_digest: string }>>;
  readonly decomposition_result_event_digest: string;
  readonly projection_digest: string;
  readonly tail_quarantined: boolean;
  readonly enterprise_authoritative: false;
  readonly lifecycle_authoritative: false;
  readonly receipt_digest: string;
}
export interface N1EventAuthorityRecoveryStreamV1 {
  readonly status: "WITNESSED" | "TAIL_QUARANTINED" | "EMPTY";
  readonly prior_witnessed_sequence: number | null;
  readonly prior_witnessed_event_id: string | null;
  readonly prior_witnessed_head_id: string | null;
  readonly prior_state_digest: string | null;
  readonly tail_sequence: number | null;
  readonly tail_quarantined: boolean;
}
export interface N1EventAuthorityTailRecoveryV1 {
  readonly product_build_identity: typeof N1EventAuthorityProductBuildIdentityV1;
  readonly streams: Readonly<Record<Stream,N1EventAuthorityRecoveryStreamV1>>;
}
export type N1EventAuthorityJourneyResultV1 =
  | {readonly ok:true;readonly code:"N1_EVENT_AUTHORITY_COMPLETE"|"N1_EVENT_AUTHORITY_RECOVERED";readonly receipt:N1EventAuthorityJourneyReceiptV1;readonly recovery?:never}
  | {readonly ok:true;readonly code:"N1_UNWITNESSED_TAIL_RECOVERED";readonly receipt:null;readonly recovery:N1EventAuthorityTailRecoveryV1}
  | {readonly ok:false;readonly code:Exclude<N1EventAuthorityJourneyCodeV1,"N1_EVENT_AUTHORITY_COMPLETE"|"N1_EVENT_AUTHORITY_RECOVERED"|"N1_UNWITNESSED_TAIL_RECOVERED">;readonly receipt:null;readonly recovery?:never};

const plain = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const privateDirectory = (path: string): boolean => { try { const s=lstatSync(path),uid=typeof process.getuid==="function"?process.getuid():s.uid;return s.isDirectory()&&!s.isSymbolicLink()&&s.uid===uid&&(s.mode&0o077)===0; } catch { return false; } };
const ensurePrivate = (path:string):void => { if(!existsSync(path))mkdirSync(path,{recursive:true,mode:0o700});if(!privateDirectory(path))throw new Error("private directory required"); };
const syncDirectory=(path:string):void=>{const fd=openSync(path,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW|constants.O_NONBLOCK);try{fsyncSync(fd)}finally{closeSync(fd)}};
const readPrivate=(path:string,maximum=Number(MAX_RECORD_BYTES)):Uint8Array|null=>{let fd:number|undefined;try{fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);const s=fstatSync(fd),uid=typeof process.getuid==="function"?process.getuid():s.uid;if(!s.isFile()||s.uid!==uid||(s.mode&0o077)!==0||s.size>maximum)return null;return new Uint8Array(readFileSync(fd));}catch{return null}finally{if(fd!==undefined)closeSync(fd)}};
const sequenceHex=(n:bigint)=>n.toString(16).padStart(16,"0");
const stable=(v:unknown):unknown=>Array.isArray(v)?v.map(stable):plain(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])])):v;
const digest=(domain:string,v:unknown)=>createHash("sha256").update(domain).update("\0").update(JSON.stringify(stable(v))).digest("hex");
const streamRoot=(root:string,stream:Stream)=>join(root,stream);

function signer(value:string|Uint8Array|undefined):KeyObject|null{if(value===undefined)return null;try{const key=createPrivateKey(typeof value==="string"?value:Buffer.from(value));return key.asymmetricKeyType==="ed25519"?key:null}catch{return null}}
function verifier(value:string|Uint8Array):KeyObject|null{try{const key=createPublicKey(typeof value==="string"?value:Buffer.from(value));return key.asymmetricKeyType==="ed25519"?key:null}catch{return null}}

const alreadyHeldLock:DistributedLock={withLock:async <T>(_key:string,fn:()=>Promise<T>)=>await fn()};
type ValidAck=Extract<CommittedHeadV1WitnessAck,{ok:true}>;
type AckScan={ok:true;acks:readonly ValidAck[]}|{ok:false;code:"INVALID"|"FORK"};
const witnessDirectory=(root:string,historyId:string)=>join(root,createHash("sha256").update("keep.n1-witness/v1\0").update(historyId).digest("hex"));
function scanAcks(root:string,historyId:string,key:KeyObject):AckScan{
  const dir=witnessDirectory(root,historyId);if(!existsSync(dir))return {ok:true,acks:[]};if(!privateDirectory(dir))return {ok:false,code:"INVALID"};
  const names=readdirSync(dir).sort(),acks:ValidAck[]=[];let prior:string|null=null,priorSequence:bigint|null=null;
  for(const name of names){
    const match=ACK.exec(name);if(match===null)return {ok:false,code:"INVALID"};const sequence=BigInt(`0x${match[1]}`);
    if(priorSequence!==null&&sequence===priorSequence)return {ok:false,code:"FORK"};if(sequence!==BigInt(acks.length))return {ok:false,code:"INVALID"};
    const bytes=readPrivate(join(dir,name));if(bytes===null)return {ok:false,code:"INVALID"};
    try{
      const row=decodeCanonical(bytes);if(!plain(row)||row.schema!=="keep.n1-witness-ack"||row.schema_version!==1n||row.history_id!==historyId||!(row.checkpoint_bytes instanceof Uint8Array)||typeof row.checkpoint_digest!=="string"||!(row.signature instanceof Uint8Array))return {ok:false,code:"INVALID"};
      if(row.checkpoint_digest!==match[2]||row.checkpoint_digest!==eirDigest(CommittedHeadV1CheckpointDigestDomain,row.checkpoint_bytes)||!verify(null,row.checkpoint_bytes,key,row.signature))return {ok:false,code:"INVALID"};
      const checkpoint=decodeCanonical(row.checkpoint_bytes);if(!plain(checkpoint)||checkpoint.history_id!==historyId||checkpoint.sequence!==sequence||checkpoint.prior_witness_digest!==prior)return {ok:false,code:"INVALID"};
      acks.push({ok:true,durable:true,checkpoint_bytes:row.checkpoint_bytes,checkpoint_digest:row.checkpoint_digest,signature:row.signature});prior=row.checkpoint_digest;priorSequence=sequence;
    }catch{return {ok:false,code:"INVALID"}}
  }
  return {ok:true,acks};
}

export class FileN1CommittedHeadWitnessV1 implements CommittedHeadV1WitnessPort {
  readonly #key:KeyObject|null;
  readonly #publicKey:KeyObject|null;
  constructor(readonly root:string,private readonly lock:DistributedLock,publicKey:string|Uint8Array,privateKey?:string|Uint8Array){ensurePrivate(root);this.#key=signer(privateKey);this.#publicKey=verifier(publicKey)}
  async latest(historyId:string):Promise<CommittedHeadV1WitnessAck|null>{
    return await this.lock.withLock(historyId,async()=>{if(this.#publicKey===null)return {ok:false,code:"WITNESS_CONFLICT"};const scan=scanAcks(this.root,historyId,this.#publicKey);return scan.ok?(scan.acks.at(-1)??null):{ok:false,code:"WITNESS_CONFLICT"}});
  }
  async compareAndPersist(expectedPriorDigest:string|null,checkpointBytes:Uint8Array):Promise<CommittedHeadV1WitnessAck>{
    if(this.#key===null||this.#publicKey===null)throw new Error("witness key unavailable");const signingKey=this.#key,publicKey=this.#publicKey,checkpoint=decodeCanonical(checkpointBytes);if(!plain(checkpoint)||typeof checkpoint.history_id!=="string"||typeof checkpoint.sequence!=="bigint")throw new Error("invalid checkpoint");const historyId=checkpoint.history_id,sequence=checkpoint.sequence;
    return await this.lock.withLock(historyId,async()=>{
      const scan=scanAcks(this.root,historyId,publicKey);if(!scan.ok)return {ok:false,code:"WITNESS_CONFLICT"};const current=scan.acks.at(-1)??null,checkpointDigest=eirDigest(CommittedHeadV1CheckpointDigestDomain,checkpointBytes);
      if(current!==null&&current.checkpoint_digest===checkpointDigest&&Buffer.from(current.checkpoint_bytes).equals(Buffer.from(checkpointBytes)))return current;
      if((current?.checkpoint_digest??null)!==expectedPriorDigest||sequence!==BigInt(scan.acks.length)||checkpoint.prior_witness_digest!==expectedPriorDigest)return {ok:false,code:"WITNESS_CONFLICT"};
      const signature=new Uint8Array(sign(null,checkpointBytes,signingKey)),dir=witnessDirectory(this.root,historyId);ensurePrivate(dir);const target=join(dir,`${sequenceHex(sequence)}-${checkpointDigest}.ack`),bytes=encodeCanonical({schema:"keep.n1-witness-ack",schema_version:1n,history_id:historyId,checkpoint_bytes:checkpointBytes,checkpoint_digest:checkpointDigest,signature});
      let fd:number|undefined;try{fd=openSync(target,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW,0o600);let offset=0;while(offset<bytes.length){const n=writeSync(fd,bytes,offset,bytes.length-offset,offset);if(n<=0)throw new Error("witness write stalled");offset+=n}fsyncSync(fd);closeSync(fd);fd=undefined;syncDirectory(dir);}finally{if(fd!==undefined)closeSync(fd)}
      return {ok:true,durable:true,checkpoint_bytes:checkpointBytes.slice(),checkpoint_digest:checkpointDigest,signature};
    });
  }
}

function eventType(event:DomainEvent):EventEnvelopeV1EventType|null{
  if(event.schema==="keep.goal-authority-event")return event.operation==="goal-admitted"?"goal.admitted":"goal.transitioned";
  if(event.schema==="keep.decomposition-authority-event")return event.operation==="candidate-created"?"decomposition.proposed":event.operation==="transition-applied"?"decomposition.transitioned":"decomposition.reviewed";
  if(event.schema==="keep.decomposition-approval-authority-event")return event.operation==="owner-decision-applied"?"decomposition.approved":event.operation==="publication-verified"?"decomposition.published":"ticket.admitted";
  return null;
}
function proposal(input:N1EventAuthorityJourneyInputV1,event:DomainEvent,sequence:bigint,prior:EventAdmissionV1LineageRecord|undefined):EventEnvelopeV1Value|null{
  const type=eventType(event);if(type===null||event.run_id!==input.run_id)return null;
  return {schema:EventEnvelopeV1Schema,schema_version:1n,codec:EventEnvelopeV1CodecIdentity,codec_version:1n,history_id:input.run_id,sequence,predecessor_event_id:prior?.event_id??null,predecessor_head_id:prior?.head_id??null,event_type:type,actor_id:input.owner_id,authority_domain:"local-owner",track:"n1",payload:{domain_json:JSON.stringify(event)},effect_correlation:null};
}
function context(input:N1EventAuthorityJourneyInputV1,lineage:readonly EventAdmissionV1LineageRecord[]):EventAdmissionV1N1Context{return {kind:"n1",track:"n1",history_id:input.run_id,actor_id:input.owner_id,authority_domain:"local-owner",custody_id:input.custody_id,committed_lineage:lineage,witnessed_head:lineage.length===0?null:{sequence:lineage.at(-1)!.sequence,event_id:lineage.at(-1)!.event_id,head_id:lineage.at(-1)!.head_id}}}

type ParsedRecord={path:string;bytes:Uint8Array;proposal:EventEnvelopeV1Value;payload:Record<string,CanonicalValue>};
function parsedRecord(path:string,bytes:Uint8Array,historyId:string,sequence:bigint):ParsedRecord|null{
  try{
    const outer=decodeCanonical(bytes);if(!plain(outer)||outer.schema!=="keep.spine.authoritative-frame"||outer.schema_version!==1n||!(outer.payload instanceof Uint8Array)||outer.payload_length!==BigInt(outer.payload.length)||outer.payload_digest!==createHash("sha256").update(outer.payload).digest("hex"))return null;
    const payload=decodeCanonical(outer.payload);if(!plain(payload)||!(payload.event_bytes instanceof Uint8Array)||payload.history_id!==historyId||payload.sequence!==sequence||typeof payload.event_id!=="string"||!HEX.test(payload.event_id)||typeof payload.next_head_id!=="string"||!HEX.test(payload.next_head_id))return null;
    const decoded=decodeCanonical(payload.event_bytes) as unknown;if(!plain(decoded))return null;const proposal=decoded as unknown as EventEnvelopeV1Value,encoded=EventEnvelopeV1Encode(proposal);if(!encoded.ok||encoded.event_digest!==payload.event_id||proposal.history_id!==historyId||proposal.sequence!==sequence||proposal.predecessor_event_id!==payload.predecessor_event_id||proposal.predecessor_head_id!==payload.predecessor_head_id)return null;
    if(payload.next_head_id!==eirDigest(EventAdmissionV1HeadDigestDomain,{history_id:historyId,sequence,event_id:payload.event_id,predecessor_head_id:payload.predecessor_head_id as string|null}))return null;
    return {path,bytes,proposal,payload:payload as Record<string,CanonicalValue>};
  }catch{return null}
}
function records(root:string,historyId:string):ParsedRecord[]|null{
  const dir=AuthoritativeAppendV1HistoryPath(root,historyId);if(!privateDirectory(dir))return null;const names=readdirSync(dir).filter(n=>n.endsWith(".record")).sort(),out:ParsedRecord[]=[];
  for(let i=0;i<names.length;i++){const match=RECORD.exec(names[i]!);if(match===null||BigInt(`0x${match[1]}`)!==BigInt(i))return null;const path=join(dir,names[i]!),bytes=readPrivate(path);if(bytes===null)return null;const row=parsedRecord(path,bytes,historyId,BigInt(i));if(row===null)return null;if(i===0&&(row.payload.predecessor_event_id!==null||row.payload.predecessor_head_id!==null))return null;const prior=out.at(-1);if(prior!==undefined&&(row.payload.predecessor_event_id!==prior.payload.event_id||row.payload.predecessor_head_id!==prior.payload.next_head_id))return null;out.push(row)}return out;
}
function appendReceipt(row:ParsedRecord):AuthoritativeAppendV1Receipt{return {history_id:row.payload.history_id as string,sequence:row.payload.sequence as bigint,event_id:row.payload.event_id as string,next_head_id:row.payload.next_head_id as string,authority:row.payload.authority as never,record_digest:eirDigest("keep.spine.authoritative-record-bytes.v1",row.bytes),final_path:row.path,record_bytes:row.bytes,durability_profile:"verified-local-posix-v1",durable:true,witnessed:false,committed:false,authoritative:false}}
function committedReceipt(row:ParsedRecord,ack:Extract<CommittedHeadV1WitnessAck,{ok:true}>):CommittedHeadV1Receipt{return {...appendReceipt(row),witness_id:(decodeCanonical(ack.checkpoint_bytes) as Record<string,CanonicalValue>).witness_id as string,checkpoint_digest:ack.checkpoint_digest,checkpoint_bytes:ack.checkpoint_bytes,witness_signature:ack.signature,witnessed:true,committed:true}}

const COMPLETE_QUARANTINE=/^([0-9a-f]{16})-([0-9a-f]{64})\.unwitnessed-complete-([0-9a-f]{64})\.record$/u;
const completeDigest=(bytes:Uint8Array)=>createHash("sha256").update("keep.n1.complete-unwitnessed-record-bytes.v1").update("\0").update(bytes).digest("hex");
function quarantineCompleteTail(root:string,historyId:string,prior:ParsedRecord|null,active:ParsedRecord|null):{ok:true;tail_sequence:number|null;tail_quarantined:boolean}|{ok:false}{
  const history=AuthoritativeAppendV1HistoryPath(root,historyId),sequence=(prior?.payload.sequence as bigint|undefined)??-1n,successor=sequence+1n,directory=join(history,".quarantine");let candidates:string[]=[];
  if(existsSync(directory)){if(!privateDirectory(directory))return {ok:false};candidates=readdirSync(directory).filter(name=>{const m=COMPLETE_QUARANTINE.exec(name);return m!==null&&BigInt(`0x${m[1]}`)===successor});if(candidates.length>1)return {ok:false}}
  if(active===null){if(candidates.length===0)return {ok:true,tail_sequence:null,tail_quarantined:false};const name=candidates[0]!,match=COMPLETE_QUARANTINE.exec(name)!,path=join(directory,name),bytes=readPrivate(path),row=bytes===null?null:parsedRecord(path,bytes,historyId,successor);if(row===null||row.payload.event_id!==match[2]||completeDigest(bytes!)!==match[3]||row.payload.predecessor_event_id!==(prior?.payload.event_id??null)||row.payload.predecessor_head_id!==(prior?.payload.next_head_id??null))return {ok:false};syncDirectory(history);return {ok:true,tail_sequence:Number(successor),tail_quarantined:true}}
  if(active.payload.sequence!==successor||active.payload.predecessor_event_id!==(prior?.payload.event_id??null)||active.payload.predecessor_head_id!==(prior?.payload.next_head_id??null))return {ok:false};
  const d=completeDigest(active.bytes),name=`${sequenceHex(successor)}-${active.payload.event_id as string}.unwitnessed-complete-${d}.record`,target=join(directory,name);if(candidates.length===1&&candidates[0]!==name)return {ok:false};
  try{
    if(!existsSync(directory)){mkdirSync(directory,{mode:0o700});if(!privateDirectory(directory))return {ok:false};syncDirectory(history)}
    try{linkSync(active.path,target)}catch(error){if((error as NodeJS.ErrnoException).code!=="EEXIST")throw error}
    syncDirectory(directory);const retained=readPrivate(target),live=readPrivate(active.path);if(retained===null||live===null||!Buffer.from(retained).equals(Buffer.from(active.bytes))||!Buffer.from(live).equals(Buffer.from(active.bytes))||completeDigest(retained)!==d)return {ok:false};unlinkSync(active.path);
    try{syncDirectory(history)}catch{try{linkSync(target,active.path);syncDirectory(history)}catch{}return {ok:false}}
    return {ok:true,tail_sequence:Number(successor),tail_quarantined:true};
  }catch{return {ok:false}}
}

function registries(rows:readonly ParsedRecord[]){const types=[...new Set(rows.map(r=>r.proposal.event_type))],versions=new EventVersionRegistryV1([]),reducers=new ReducerRegistryV1(types.map(type=>({event_type:type,event_schema_version:1n,reducer_id:`keep.n1.${type}.v1`,reducer_version:1n,transition:"replace-state-with-event-payload",capabilities:[]})));return {versions,reducers}}
type Loaded={bundle:ReplayBundle|null;recovery:N1EventAuthorityRecoveryStreamV1};
type LoadResult={ok:true;loaded:Loaded}|{ok:false;code:"INVALID"|"FORK"};
async function load(input:N1EventAuthorityJourneyInputV1,stream:Stream,allowTail:boolean):Promise<LoadResult>{
  const root=streamRoot(input.history_directory,stream),witnessRoot=streamRoot(input.witness_directory,stream),lockRoot=join(root,".locks"),key=verifier(input.witness_public_key);if(key===null||!privateDirectory(root)||!privateDirectory(witnessRoot)||!privateDirectory(lockRoot))return {ok:false,code:"INVALID"};const lock=new FileSystemLock(lockRoot);
  try{return await lock.withLock(input.run_id,async()=>{
    const scan=scanAcks(witnessRoot,input.run_id,key);if(!scan.ok)return {ok:false,code:scan.code} as const;let rows=records(root,input.run_id);if(rows===null){const history=AuthoritativeAppendV1HistoryPath(root,input.run_id);if(existsSync(history)||scan.acks.length>0)return {ok:false,code:"INVALID"} as const;return {ok:true,loaded:{bundle:null,recovery:{status:"EMPTY",prior_witnessed_sequence:null,prior_witnessed_event_id:null,prior_witnessed_head_id:null,prior_state_digest:null,tail_sequence:null,tail_quarantined:false}}} as const}
    const ack=scan.acks.at(-1)??null;if(ack===null){if(!allowTail||rows.length>1)return {ok:false,code:"INVALID"} as const;const disposed=quarantineCompleteTail(root,input.run_id,null,rows[0]??null);if(!disposed.ok)return {ok:false,code:"INVALID"} as const;return {ok:true,loaded:{bundle:null,recovery:{status:disposed.tail_quarantined?"TAIL_QUARANTINED":"EMPTY",prior_witnessed_sequence:null,prior_witnessed_event_id:null,prior_witnessed_head_id:null,prior_state_digest:null,tail_sequence:disposed.tail_sequence,tail_quarantined:disposed.tail_quarantined}}} as const}
    const checkpoint=decodeCanonical(ack.checkpoint_bytes) as Record<string,CanonicalValue>;if(checkpoint.history_id!==input.run_id||typeof checkpoint.sequence!=="bigint"||checkpoint.sequence!==BigInt(scan.acks.length-1))return {ok:false,code:"INVALID"} as const;const prior=rows[Number(checkpoint.sequence)];if(prior===undefined)return {ok:false,code:"INVALID"} as const;
    let disposed:{ok:true;tail_sequence:number|null;tail_quarantined:boolean}|{ok:false}={ok:true,tail_sequence:null,tail_quarantined:false};if(rows.length===Number(checkpoint.sequence)+2){if(!allowTail)return {ok:false,code:"INVALID"} as const;disposed=quarantineCompleteTail(root,input.run_id,prior,rows.at(-1)! );if(!disposed.ok)return {ok:false,code:"INVALID"} as const;rows=records(root,input.run_id);if(rows===null)return {ok:false,code:"INVALID"} as const}else if(rows.length!==Number(checkpoint.sequence)+1)return {ok:false,code:"INVALID"} as const;
    if(allowTail&&!disposed.tail_quarantined){const retry=quarantineCompleteTail(root,input.run_id,prior,null);if(!retry.ok)return {ok:false,code:"INVALID"} as const;disposed=retry}
    if(rows.length!==Number(checkpoint.sequence)+1)return {ok:false,code:"INVALID"} as const;const final=committedReceipt(rows.at(-1)!,ack),{versions,reducers}=registries(rows),setRows:AuthoritativeReplayV1Event[]=[];for(const row of rows){const set=versions.interpreterSet(row.proposal.event_type,1n,1n);if(!set.ok)return {ok:false,code:"INVALID"} as const;setRows.push({proposal:row.proposal,target_version:1n,interpreter_set_digest:set.interpreter_set_digest})}
    const replay=replayAuthoritativeHistoryV1({committed_head:{ok:true,receipt:final},authority_context:context(input,[]),events:setRows,initial_state_bytes:encodeCanonical(null),versions,reducers});if(!replay.ok)return {ok:false,code:"INVALID"} as const;const status=disposed.tail_quarantined?"TAIL_QUARANTINED":"WITNESSED" as const;return {ok:true,loaded:{bundle:{events:setRows,replay},recovery:{status,prior_witnessed_sequence:Number(replay.receipt.final_sequence),prior_witnessed_event_id:replay.receipt.final_event_id,prior_witnessed_head_id:replay.receipt.final_head_id,prior_state_digest:replay.receipt.state_digest,tail_sequence:disposed.tail_sequence,tail_quarantined:disposed.tail_quarantined}}} as const;
  })}catch{return {ok:false,code:"INVALID"}}
}

interface TestCheckpoint{readonly stream:Stream;readonly sequence:number;readonly afterDurableAppend:()=>never}
async function commit(input:N1EventAuthorityJourneyInputV1,stream:Stream,events:readonly DomainEvent[],testCheckpoint?:TestCheckpoint):Promise<"ok"|"invalid"|"fork">{
  const root=streamRoot(input.history_directory,stream),witnessRoot=streamRoot(input.witness_directory,stream);ensurePrivate(root);ensurePrivate(witnessRoot);const privateKey=input.witness_private_key,key=verifier(input.witness_public_key);if(privateKey===undefined||key===null)return "invalid";const outer=new FileSystemLock(join(root,".locks")),lineage:EventAdmissionV1LineageRecord[]=[];
  for(let i=0;i<events.length;i++){const p=proposal(input,events[i]!,BigInt(i),lineage.at(-1));if(p===null)return "invalid";const result=await outer.withLock(input.run_id,async()=>{const scan=scanAcks(witnessRoot,input.run_id,key);if(!scan.ok)return scan.code==="FORK"?"fork" as const:"invalid" as const;const checkpoint=testCheckpoint?.stream===stream&&testCheckpoint.sequence===i?testCheckpoint:undefined,witness=new FileN1CommittedHeadWitnessV1(witnessRoot,alreadyHeldLock,input.witness_public_key,privateKey),appendOptions={storage_root:root,durability_profile:{kind:"verified-local-posix-v1" as const,max_record_bytes:MAX_RECORD_BYTES},lock:alreadyHeldLock,...(checkpoint===undefined?{}:{io:{checkpoint:(name:string)=>{if(name==="CLEANUP_DIRECTORY_SYNCED")checkpoint.afterDurableAppend()}}})},append=new AuthoritativeAppendV1(appendOptions),committer=new CommittedHeadV1({append,history_storage_domain:`keep.n1.history.${stream}`,witness_storage_domain:`keep.n1.witness.${stream}`,witness,witness_public_key:input.witness_public_key}),committed=await committer.commit(p,context(input,lineage));return committed.ok?committed:"invalid" as const});if(result==="fork"||result==="invalid")return result;lineage.push({sequence:result.receipt.sequence,event_id:result.receipt.event_id,head_id:result.receipt.next_head_id,predecessor_event_id:p.predecessor_event_id,predecessor_head_id:p.predecessor_head_id});}
  return "ok";
}

type FailureCode=Exclude<N1EventAuthorityJourneyCodeV1,"N1_EVENT_AUTHORITY_COMPLETE"|"N1_EVENT_AUTHORITY_RECOVERED"|"N1_UNWITNESSED_TAIL_RECOVERED">;
function validInput(input:N1EventAuthorityJourneyInputV1):FailureCode|null{if(input.schema_version!==1||input.organization_services!=="ABSENT")return "N1_ENTERPRISE_CEREMONY_FORBIDDEN";if(input.expected_product_build_identity!==undefined&&input.expected_product_build_identity!==N1EventAuthorityProductBuildIdentityV1)return "N1_EVENT_HISTORY_INVALID";if(input.activation.authority.kind!=="n1"||input.activation.authority.owner_id!==input.owner_id||input.activation.authority.custody_id!==input.custody_id)return "TRACK_AUTHORITY_SUBSTITUTION";if(input.run_id.length===0||input.project_id.length===0||input.goal_events.length===0||input.review_events.length===0||input.approval_events.length===0)return "N1_EVENT_HISTORY_INVALID";return null}
function failed(code:FailureCode):Extract<N1EventAuthorityJourneyResultV1,{ok:false}>{return {ok:false,code,receipt:null}}
type OrdinaryJourneyResult=Extract<N1EventAuthorityJourneyResultV1,{receipt:N1EventAuthorityJourneyReceiptV1}>|Extract<N1EventAuthorityJourneyResultV1,{ok:false}>;
function receipt(input:N1EventAuthorityJourneyInputV1,goal:GoalAuthorityReplayBundleV1,review:DecompositionAuthorityReplayBundleV1,approval:DecompositionApprovalReplayBundleV1,tail:boolean):OrdinaryJourneyResult{
  const g=reconstructGoalAuthorityEventsV1(input.run_id,input.goal_request,goal),d=reconstructDecompositionAuthorityV1(input.run_id,review),a=reconstructDecompositionApprovalAuthorityV1(input.run_id,review,input.run_id,approval);if(!g.ok||g.artifact===null||g.artifact.code!=="ARCHITECTURE_AUTHORIZED"||!d.ok||d.projection.transition?.phase!=="DECOMPOSITION_VET_2_PASS"||d.projection.review?.phase!=="COMPLETE"||!a.ok||a.projection.approval===null||a.projection.publication===null||a.projection.ticket===null)return failed("N1_EVENT_HISTORY_INVALID");
  const resultInput={review_history_id:input.run_id,review_history:review,approval_history_id:input.run_id,approval_history:approval,activation:input.activation},result=deriveDecompositionResultEventV1(resultInput);if(!result.ok)return failed(result.code==="TRACK_AUTHORITY_SUBSTITUTION"?"TRACK_AUTHORITY_SUBSTITUTION":"N1_EVENT_HISTORY_INVALID");
  const projected=rebuildEngineeringStatusProjectionV1({schema_version:1,project_id:input.project_id,run_id:input.run_id,authority:{kind:"n1",principal_id:input.owner_id,custody_id:input.custody_id,organization_services:"ABSENT"},sources:[{kind:"goal",receipt:(goal.replay as Extract<AuthoritativeReplayV1Result,{ok:true}>).receipt,status:{code:g.artifact.code,phase:"ARCHITECTURE_AUTHORIZED"}},{kind:"decomposition",receipt:(review.replay as Extract<AuthoritativeReplayV1Result,{ok:true}>).receipt,status:{transition_phase:d.projection.transition.phase,review_phase:d.projection.review.phase}},{kind:"approval",receipt:(approval.replay as Extract<AuthoritativeReplayV1Result,{ok:true}>).receipt,status:{ticket_id:a.projection.ticket.ticket_id,implementation_authorized:false}}]});if(!projected.ok)return failed("N1_EVENT_HISTORY_INVALID");
  const projectionStore=new FileEngineeringStatusProjectionStoreV1(join(input.data_directory,"projections")),cached=projectionStore.load(input.project_id);if(!projectionStore.compareAndSave(input.project_id,cached?.projection_digest??null,projected.projection))return failed("N1_EVENT_HISTORY_INVALID");
  const sourceHeads=Object.fromEntries(([ ["goal",goal],["review",review],["approval",approval] ] as const).map(([name,b])=>{const r=b.replay as Extract<AuthoritativeReplayV1Result,{ok:true}>;return [name,{event_count:Number(r.receipt.event_count),final_event_id:r.receipt.final_event_id,final_head_id:r.receipt.final_head_id,result_digest:r.result_digest}]})) as N1EventAuthorityJourneyReceiptV1["source_heads"];
  const body={schema:"keep.n1-event-authority-journey" as const,schema_version:1 as const,project_id:input.project_id,run_id:input.run_id,track:"n1" as const,organization_services:"ABSENT" as const,owner_id:input.owner_id,custody_id:input.custody_id,product_build_identity:N1EventAuthorityProductBuildIdentityV1,source_heads:sourceHeads,decomposition_result_event_digest:result.event.event_digest,projection_digest:projected.projection.projection_digest,tail_quarantined:tail,enterprise_authoritative:false as const,lifecycle_authoritative:false as const};return {ok:true,code:"N1_EVENT_AUTHORITY_RECOVERED",receipt:Object.freeze({...body,receipt_digest:digest("keep.n1-event-authority-journey.v1",body)})};
}

/** Create the three physical histories, witness every committed head, and derive only replay-bound results. */
async function runJourney(input:N1EventAuthorityJourneyInputV1,testCheckpoint?:TestCheckpoint):Promise<N1EventAuthorityJourneyResultV1>{
  const invalid=validInput(input);if(invalid!==null)return failed(invalid);try{ensurePrivate(input.data_directory);ensurePrivate(input.history_directory);ensurePrivate(input.witness_directory);for(const [stream,events] of [["goal",input.goal_events],["review",input.review_events],["approval",input.approval_events]] as const){const result=await commit(input,stream,events,testCheckpoint);if(result==="fork")return failed("N1_WITNESS_FORK");if(result!=="ok")return failed("N1_EVENT_HISTORY_INVALID")}const loaded=await Promise.all((["goal","review","approval"] as const).map(s=>load(input,s,false)));if(loaded.some(x=>!x.ok))return failed(loaded.some(x=>!x.ok&&x.code==="FORK")?"N1_WITNESS_FORK":"N1_EVENT_HISTORY_INVALID");const values=loaded.map(x=>(x as Extract<LoadResult,{ok:true}>).loaded);if(values.length!==3)return failed("N1_EVENT_HISTORY_INVALID");const goal=values[0]!,review=values[1]!,approval=values[2]!;if(goal.bundle===null||review.bundle===null||approval.bundle===null)return failed("N1_EVENT_HISTORY_INVALID");const resultInput={schema_version:1 as const,data_directory:join(input.data_directory,"result"),organization_services:"ABSENT" as const,public_seam_authorized:true,implementation_authorized:false as const,review_history_id:input.run_id,review_history:review.bundle as DecompositionAuthorityReplayBundleV1,approval_history_id:input.run_id,approval_history:approval.bundle as DecompositionApprovalReplayBundleV1,activation:input.activation};const recorded=runN1DecompositionJourney(resultInput);if(recorded.code!=="N1_DECOMPOSITION_JOURNEY_COMPLETE")return failed(recorded.code==="TRACK_AUTHORITY_SUBSTITUTION"?"TRACK_AUTHORITY_SUBSTITUTION":"N1_EVENT_HISTORY_INVALID");const built=receipt(input,goal.bundle as GoalAuthorityReplayBundleV1,review.bundle as DecompositionAuthorityReplayBundleV1,approval.bundle as DecompositionApprovalReplayBundleV1,false);return built.ok?{...built,code:"N1_EVENT_AUTHORITY_COMPLETE"}:built;}catch{return failed("N1_EVENT_HISTORY_INVALID")}
}

export async function runN1EventAuthorityJourneyV1(input:N1EventAuthorityJourneyInputV1):Promise<N1EventAuthorityJourneyResultV1>{return await runJourney(input)}

/** Internal installed-test adapter; deliberately excluded from the package's supported index exports. */
export async function runN1EventAuthorityCrashAfterDurableAppendTestOnlyV1(input:N1EventAuthorityJourneyInputV1,stream:Stream,sequence:number):Promise<never>{await runJourney(input,{stream,sequence,afterDurableAppend:()=>process.kill(process.pid,"SIGKILL") as never});throw new Error("test checkpoint not reached")}

/** Reconstruct from raw records and witnessed checkpoints only; saved views and live receipts are not inputs. */
export async function recoverN1EventAuthorityJourneyV1(input:N1EventAuthorityJourneyInputV1):Promise<N1EventAuthorityJourneyResultV1>{const invalid=validInput(input);if(invalid!==null)return failed(invalid);try{const results=await Promise.all((["goal","review","approval"] as const).map(s=>load(input,s,true)));if(results.some(x=>!x.ok))return failed(results.some(x=>!x.ok&&x.code==="FORK")?"N1_WITNESS_FORK":"RESTART_AUTHORITY_REQUIRED");const loaded=results.map(x=>(x as Extract<LoadResult,{ok:true}>).loaded),streams={goal:loaded[0]!.recovery,review:loaded[1]!.recovery,approval:loaded[2]!.recovery};if(loaded.some(x=>x.recovery.tail_quarantined))return {ok:true,code:"N1_UNWITNESSED_TAIL_RECOVERED",receipt:null,recovery:{product_build_identity:N1EventAuthorityProductBuildIdentityV1,streams}};if(loaded.some(x=>x.bundle===null))return failed("RESTART_AUTHORITY_REQUIRED");return receipt(input,loaded[0]!.bundle as GoalAuthorityReplayBundleV1,loaded[1]!.bundle as DecompositionAuthorityReplayBundleV1,loaded[2]!.bundle as DecompositionApprovalReplayBundleV1,false);}catch{return failed("RESTART_AUTHORITY_REQUIRED")}}

export function requireEnterpriseFromN1JourneyV1(_receipt:N1EventAuthorityJourneyReceiptV1):{readonly ok:false;readonly code:"TRACK_AUTHORITY_SUBSTITUTION"}{return {ok:false,code:"TRACK_AUTHORITY_SUBSTITUTION"}}
