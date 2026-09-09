import { createHash, randomBytes } from "node:crypto";
import { closeSync, constants, fstatSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, unlinkSync, writeSync } from "node:fs";
import { join } from "node:path";

import { decodeCanonical, eirDigest, encodeCanonical, type CanonicalValue } from "../eir/canonical.js";
import { FileSystemLock, type DistributedLock } from "../lock/lock.js";
import { EventAdmissionV1Admit, EventAdmissionV1HeadDigestDomain, type EventAdmissionV1Authority, type EventAdmissionV1Result, type EventAdmissionV1TrustedContext } from "./event_admission_v1.js";
import { EventEnvelopeV1Encode, type EventEnvelopeV1Value } from "./event_envelope_v1.js";
import type { WorkAttemptFenceV1 } from "./work_attempt_authority_v1.js";

export type AuthoritativeAppendV1Checkpoint = "HISTORY_DIRECTORY_CREATED" | "HISTORY_DIRECTORY_SYNCED" | "PARENT_DIRECTORY_SYNCED" | "TEMP_CREATED" | "TEMP_FILE_SYNCED" | "FINAL_LINKED" | "FINAL_DIRECTORY_SYNCED" | "TEMP_UNLINKED" | "CLEANUP_DIRECTORY_SYNCED";
export interface AuthoritativeAppendV1Io {
  write(fd: number, bytes: Uint8Array, offset: number, length: number, position: number, native: typeof writeSync): number;
  fsync(fd: number, native: typeof fsyncSync): void;
  checkpoint(point: AuthoritativeAppendV1Checkpoint): void;
}
export type AuthoritativeAppendV1DurabilityProfile = { readonly kind: "verified-local-posix-v1"; readonly max_record_bytes: bigint } | { readonly kind: "unverified-or-network" };
export interface AuthoritativeAppendV1Options { readonly storage_root: string; readonly durability_profile: AuthoritativeAppendV1DurabilityProfile; readonly io?: Partial<AuthoritativeAppendV1Io>; readonly lock?: DistributedLock; readonly attempt_fence?: WorkAttemptFenceV1 }
export interface AuthoritativeAppendV1Receipt {
  readonly history_id: string; readonly sequence: bigint; readonly event_id: string; readonly next_head_id: string;
  readonly authority: EventAdmissionV1Authority; readonly record_digest: string; readonly final_path: string;
  readonly record_bytes: Uint8Array; readonly durability_profile: "verified-local-posix-v1";
  readonly durable: true; readonly witnessed: false; readonly committed: false; readonly authoritative: false;
}
type Refusal = Exclude<EventAdmissionV1Result, { ok: true }> | { readonly ok: false; readonly code: "UNSUPPORTED_DURABILITY_PROFILE" | "ADMISSION_EVENT_MISMATCH" | "STORAGE_SHAPE_REFUSED" | "APPEND_DURABILITY_UNPROVEN" | "HEAD_CONFLICT" | "WRITER_FENCED" | "APPEND_IO_FAILED" };
export type AuthoritativeAppendV1Result = { readonly ok: true; readonly receipt: AuthoritativeAppendV1Receipt } | Refusal;

const recordPattern = /^([0-9a-f]{16})-([0-9a-f]{64})\.record$/;
const temporaryPattern = /^\.tmp-[1-9][0-9]*-[0-9a-f]{24}$/;
const hex64 = /^[0-9a-f]{64}$/;
const sequenceHex = (n: bigint): string => n.toString(16).padStart(16, "0");
const digestBytes = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");
export function AuthoritativeAppendV1HistoryPath(root: string, historyId: string): string {
  return join(root, createHash("sha256").update("keep.authoritative-history/v1\0").update(historyId).digest("hex"));
}
function syncDirectory(path: string, sync: (fd:number,native:typeof fsyncSync)=>void): void { const fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_NONBLOCK); try { sync(fd,fsyncSync); } finally { closeSync(fd); } }
function privateDirectory(path: string): boolean { try { const s = lstatSync(path); const uid = typeof process.getuid === "function" ? process.getuid() : s.uid; return s.isDirectory() && !s.isSymbolicLink() && s.uid === uid && (s.mode & 0o077) === 0; } catch { return false; } }
function readPrivateFile(path: string, maximumBytes: number): Uint8Array | null {
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = fstatSync(fd); const uid = typeof process.getuid === "function" ? process.getuid() : stat.uid;
    if (!stat.isFile() || stat.uid !== uid || (stat.mode & 0o077) !== 0 || stat.size > maximumBytes) return null;
    return new Uint8Array(readFileSync(fd));
  } catch { return null; }
  finally { if (fd !== undefined) closeSync(fd); }
}
function exactCoordinates(event: EventEnvelopeV1Value, admission: Extract<EventAdmissionV1Result, {ok:true}>["admission"]): boolean {
  return event.history_id === admission.history_id && event.sequence === admission.sequence && event.predecessor_event_id === admission.predecessor_event_id && event.predecessor_head_id === admission.predecessor_head_id && event.actor_id === admission.authority.actor_id && event.authority_domain === admission.authority.authority_domain && event.track === admission.authority.track;
}
function frame(admission: Extract<EventAdmissionV1Result, {ok:true}>["admission"], eventBytes: Uint8Array): Uint8Array {
  const payload: CanonicalValue = { schema: "keep.spine.authoritative-record", schema_version: 1n, event_bytes: eventBytes, history_id: admission.history_id, sequence: admission.sequence, predecessor_event_id: admission.predecessor_event_id, predecessor_head_id: admission.predecessor_head_id, event_id: admission.event_id, next_head_id: admission.next_head_id, authority: admission.authority as unknown as CanonicalValue };
  const canonical = encodeCanonical(payload); const digest = digestBytes(canonical);
  return encodeCanonical({ schema: "keep.spine.authoritative-frame", schema_version: 1n, payload: canonical, payload_length: BigInt(canonical.length), payload_digest: digest });
}
function exactKeys(value: unknown, keys: readonly string[]): value is Record<string, CanonicalValue> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || value instanceof Uint8Array) return false;
  const actual = Reflect.ownKeys(value); return actual.length === keys.length && actual.every(key => typeof key === "string" && keys.includes(key));
}
function validateRecord(bytes: Uint8Array): { history_id: string; sequence: bigint; event_id: string; next_head_id: string; predecessor_event_id: string | null; predecessor_head_id: string | null } | null {
  try {
    const decodedOuter = decodeCanonical(bytes);
    if (!exactKeys(decodedOuter,["schema","schema_version","payload","payload_length","payload_digest"])) return null;
    const outer=decodedOuter;
    if (outer.schema!=="keep.spine.authoritative-frame" || outer.schema_version!==1n || !(outer.payload instanceof Uint8Array) || outer.payload_length !== BigInt(outer.payload.length) || outer.payload_digest !== digestBytes(outer.payload)) return null;
    const decodedPayload=decodeCanonical(outer.payload);
    if(!exactKeys(decodedPayload,["schema","schema_version","event_bytes","history_id","sequence","predecessor_event_id","predecessor_head_id","event_id","next_head_id","authority"]))return null;
    const p=decodedPayload;
    if (p.schema !== "keep.spine.authoritative-record" || p.schema_version !== 1n || !(p.event_bytes instanceof Uint8Array) || typeof p.history_id !== "string" || typeof p.sequence !== "bigint" || typeof p.event_id !== "string" || typeof p.next_head_id !== "string" || !hex64.test(p.event_id) || !hex64.test(p.next_head_id) || !(p.predecessor_event_id===null||(typeof p.predecessor_event_id==="string"&&hex64.test(p.predecessor_event_id))) || !(p.predecessor_head_id===null||(typeof p.predecessor_head_id==="string"&&hex64.test(p.predecessor_head_id)))) return null;
    const event=decodeCanonical(p.event_bytes); if(!exactKeys(event,["schema","schema_version","codec","codec_version","history_id","sequence","predecessor_event_id","predecessor_head_id","event_type","actor_id","authority_domain","track","payload","effect_correlation"]))return null;
    const encoded=EventEnvelopeV1Encode(event); if(!encoded.ok||encoded.event_digest!==p.event_id||!Buffer.from(encoded.canonical_bytes).equals(Buffer.from(p.event_bytes)))return null;
    if(event.history_id!==p.history_id||event.sequence!==p.sequence||event.predecessor_event_id!==p.predecessor_event_id||event.predecessor_head_id!==p.predecessor_head_id)return null;
    if(!exactKeys(p.authority,event.track==="enterprise"?["kind","track","actor_id","authority_domain","custody_id","organization_id","tenant_id","actor_role_id","isolation_id"]:["kind","track","actor_id","authority_domain","custody_id"]))return null;
    if(p.authority.kind!==event.track||p.authority.track!==event.track||p.authority.actor_id!==event.actor_id||p.authority.authority_domain!==event.authority_domain)return null;
    if(p.next_head_id!==eirDigest(EventAdmissionV1HeadDigestDomain,{history_id:p.history_id,sequence:p.sequence,event_id:p.event_id,predecessor_head_id:p.predecessor_head_id}))return null;
    return { history_id:p.history_id, sequence:p.sequence, event_id:p.event_id, next_head_id:p.next_head_id, predecessor_event_id:p.predecessor_event_id as string|null, predecessor_head_id:p.predecessor_head_id as string|null };
  } catch { return null; }
}

export class AuthoritativeAppendV1 {
  constructor(private readonly options: AuthoritativeAppendV1Options) {}
  async append(proposal: unknown, trustedContext: EventAdmissionV1TrustedContext): Promise<AuthoritativeAppendV1Result> {
    if (this.options.attempt_fence !== undefined) {
      const authority=this.options.attempt_fence.identity.authority;
      const matching=authority.kind===trustedContext.kind && authority.kind===this.options.attempt_fence.identity.track && (authority.kind==="n1"
        ? trustedContext.kind==="n1"&&authority.owner_id===trustedContext.actor_id&&authority.custody_id===trustedContext.custody_id
        : trustedContext.kind==="enterprise"&&authority.organization_id===trustedContext.organization_id&&authority.tenant_id===trustedContext.tenant_id&&authority.actor_id===trustedContext.actor_id&&authority.role_id===trustedContext.actor_role_id&&authority.custody_id===trustedContext.custody_id&&authority.isolation_id===trustedContext.isolation_id);
      if(!matching)return {ok:false,code:"TRACK_AUTHORITY_SUBSTITUTION"};
      try { return await this.options.attempt_fence.withCurrent(async () => await this.appendResource(proposal, trustedContext)); }
      catch { return { ok: false, code: "WRITER_FENCED" }; }
    }
    return await this.appendResource(proposal, trustedContext);
  }
  private async appendResource(proposal: unknown, trustedContext: EventAdmissionV1TrustedContext): Promise<AuthoritativeAppendV1Result> {
    const profile = this.options.durability_profile;
    if (profile.kind !== "verified-local-posix-v1" || profile.max_record_bytes <= 0n || profile.max_record_bytes > 67_108_864n) return { ok:false, code:"UNSUPPORTED_DURABILITY_PROFILE" };
    const maximumBytes=Number(profile.max_record_bytes);
    const admitted = EventAdmissionV1Admit(proposal, trustedContext); if (!admitted.ok) return admitted;
    const encoded = EventEnvelopeV1Encode(proposal); if (!encoded.ok) return { ok:false, code:"ADMISSION_EVENT_MISMATCH" };
    let event: EventEnvelopeV1Value; try { event = decodeCanonical(encoded.canonical_bytes) as unknown as EventEnvelopeV1Value; } catch { return {ok:false,code:"ADMISSION_EVENT_MISMATCH"}; }
    if (encoded.event_digest !== admitted.admission.event_id || !exactCoordinates(event, admitted.admission)) return {ok:false,code:"ADMISSION_EVENT_MISMATCH"};
    const bytes = frame(admitted.admission, encoded.canonical_bytes); if (BigInt(bytes.length) > profile.max_record_bytes) return {ok:false,code:"APPEND_IO_FAILED"};
    if (!privateDirectory(this.options.storage_root)) return {ok:false,code:"STORAGE_SHAPE_REFUSED"};
    const history = AuthoritativeAppendV1HistoryPath(this.options.storage_root, admitted.admission.history_id);
    const io = { write: this.options.io?.write ?? ((fd:number,b:Uint8Array,o:number,l:number,p:number,n:typeof writeSync) => n(fd,b,o,l,p)), fsync:this.options.io?.fsync??((fd:number,n:typeof fsyncSync)=>n(fd)), checkpoint: this.options.io?.checkpoint ?? (()=>{}) };
    const lock = this.options.lock ?? new FileSystemLock(join(this.options.storage_root, ".locks"));
    try { return await lock.withLock(admitted.admission.history_id, async () => {
      if (!privateDirectory(history)) {
        try { mkdirSync(history, {mode:0o700}); io.checkpoint("HISTORY_DIRECTORY_CREATED"); syncDirectory(history,io.fsync); io.checkpoint("HISTORY_DIRECTORY_SYNCED"); syncDirectory(this.options.storage_root,io.fsync); io.checkpoint("PARENT_DIRECTORY_SYNCED"); }
        catch (e) { if (!privateDirectory(history)) return {ok:false,code:"STORAGE_SHAPE_REFUSED"} as const; throw e; }
      }
      const entries = readdirSync(history);
      let removedTemporary = false;
      for (const name of entries) if (temporaryPattern.test(name)) { const path=join(history,name); const temporary=readPrivateFile(path,maximumBytes); if(temporary===null)continue; unlinkSync(path); removedTemporary=true; }
      if (removedTemporary) syncDirectory(history,io.fsync);
      const names = entries.filter(n => n.endsWith(".record")).sort(); let prior: ReturnType<typeof validateRecord> = null;
      for (let i=0;i<names.length;i++) { const m=recordPattern.exec(names[i]!); if (!m || BigInt(`0x${m[1]}`)!==BigInt(i)) return {ok:false,code:"APPEND_DURABILITY_UNPROVEN"} as const; const raw=readPrivateFile(join(history,names[i]!),maximumBytes); const r=raw===null?null:validateRecord(raw); if (!r || r.sequence!==BigInt(i)||r.event_id!==m[2]||r.history_id!==admitted.admission.history_id || (prior && (r.predecessor_event_id!==prior.event_id||r.predecessor_head_id!==prior.next_head_id))) return {ok:false,code:"APPEND_DURABILITY_UNPROVEN"} as const; prior=r; }
      const expectedSequence=prior?prior.sequence+1n:0n; const expectedEvent=prior?.event_id??null; const expectedHead=prior?.next_head_id??null;
      const finalName=`${sequenceHex(admitted.admission.sequence)}-${admitted.admission.event_id}.record`; const finalPath=join(history,finalName);
      if (admitted.admission.sequence!==expectedSequence || admitted.admission.predecessor_event_id!==expectedEvent || admitted.admission.predecessor_head_id!==expectedHead) {
        if (admitted.admission.sequence<expectedSequence) { const existing=readPrivateFile(finalPath,maximumBytes); if (existing!==null && Buffer.from(existing).equals(Buffer.from(bytes))) return this.success(admitted.admission,bytes,finalPath); }
        return {ok:false,code:"HEAD_CONFLICT"} as const;
      }
      const temp=join(history,`.tmp-${process.pid}-${randomBytes(12).toString("hex")}`); let fd:number|undefined;
      try { fd=openSync(temp,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW,0o600); io.checkpoint("TEMP_CREATED"); let offset=0; while(offset<bytes.length){const n=io.write(fd,bytes,offset,bytes.length-offset,offset,writeSync); if(n<=0) throw new Error("zero write"); offset+=n;} io.fsync(fd,fsyncSync); io.checkpoint("TEMP_FILE_SYNCED"); closeSync(fd); fd=undefined; linkSync(temp,finalPath); io.checkpoint("FINAL_LINKED"); syncDirectory(history,io.fsync); io.checkpoint("FINAL_DIRECTORY_SYNCED"); unlinkSync(temp); io.checkpoint("TEMP_UNLINKED"); syncDirectory(history,io.fsync); io.checkpoint("CLEANUP_DIRECTORY_SYNCED"); const observed=readPrivateFile(finalPath,maximumBytes); if(observed===null||!Buffer.from(observed).equals(Buffer.from(bytes))) return {ok:false,code:"APPEND_DURABILITY_UNPROVEN"} as const; return this.success(admitted.admission,bytes,finalPath); }
      catch(e) { if(fd!==undefined) try{closeSync(fd);}catch{}; try{unlinkSync(temp);}catch{}; if((e as NodeJS.ErrnoException).code==="EEXIST") return {ok:false,code:"HEAD_CONFLICT"} as const; return {ok:false,code:"APPEND_IO_FAILED"} as const; }
    }); } catch { return {ok:false,code:"WRITER_FENCED"}; }
  }
  private success(admission: Extract<EventAdmissionV1Result,{ok:true}>["admission"], record_bytes:Uint8Array, final_path:string): AuthoritativeAppendV1Result { return {ok:true,receipt:Object.freeze({history_id:admission.history_id,sequence:admission.sequence,event_id:admission.event_id,next_head_id:admission.next_head_id,authority:admission.authority,record_digest:eirDigest("keep.spine.authoritative-record-bytes.v1",record_bytes),final_path,record_bytes,durability_profile:"verified-local-posix-v1",durable:true,witnessed:false,committed:false,authoritative:false})}; }
}
