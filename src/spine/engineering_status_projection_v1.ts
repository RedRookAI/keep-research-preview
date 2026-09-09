import { createHash } from "node:crypto";

import type { AuthoritativeReplayV1Receipt } from "./authoritative_replay_v1.js";

export const ENGINEERING_STATUS_PROJECTION_MIGRATED_WRITERS_V1 = Object.freeze([
  "W10", "W11", "W12", "W13",
] as const);

export type EngineeringStatusProjectionCodeV1 =
  | "HISTORY_REQUIRED"
  | "EVENT_COMMIT_REQUIRED"
  | "TRACK_AUTHORITY_SUBSTITUTION"
  | "STALE_PROJECTION"
  | "PROJECTION_AUTHORITY_FORBIDDEN"
  | "LEGACY_AUTHORITY_GAP";

export type EngineeringStatusProjectionAuthorityV1 =
  | { readonly kind:"n1"; readonly principal_id:string; readonly custody_id:string; readonly organization_services:"ABSENT" }
  | { readonly kind:"enterprise"; readonly organization_id:string; readonly tenant_id:string; readonly actor_id:string; readonly role_id:string; readonly custody_id:string; readonly isolation_id:string; readonly local_owner_substitution:false };

export type EngineeringLifecycleSourceKindV1 = "goal" | "decomposition" | "approval";
export interface EngineeringLifecycleSourceV1 {
  readonly kind: EngineeringLifecycleSourceKindV1;
  readonly receipt: AuthoritativeReplayV1Receipt;
  /** Closed semantic reconstruction from the matching T010, T011, or T012 adapter. */
  readonly status: Readonly<Record<string, unknown>>;
}
export interface EngineeringStatusProjectionInputV1 {
  readonly schema_version: 1;
  readonly project_id: string;
  readonly run_id: string;
  readonly authority: EngineeringStatusProjectionAuthorityV1;
  readonly sources: readonly EngineeringLifecycleSourceV1[];
}
export interface EngineeringStatusSourceHeadV1 {
  readonly kind: EngineeringLifecycleSourceKindV1;
  readonly history_id: string;
  readonly event_count: number;
  readonly final_sequence: number;
  readonly final_event_id: string;
  readonly final_head_id: string;
  readonly state_digest: string;
}
export interface EngineeringStatusProjectionV1 {
  readonly schema: "keep.engineering-status-projection";
  readonly schema_version: 1;
  readonly project_id: string;
  readonly run_id: string;
  readonly authority: EngineeringStatusProjectionAuthorityV1;
  readonly source_heads: readonly EngineeringStatusSourceHeadV1[];
  readonly statuses: Readonly<Partial<Record<EngineeringLifecycleSourceKindV1, Readonly<Record<string, unknown>>>>>;
  readonly projection_digest: string;
  readonly authoritative: false;
  readonly implementation_authorized: false;
}
export type EngineeringStatusProjectionResultV1 =
  | { readonly ok:true; readonly projection:EngineeringStatusProjectionV1; readonly disposition:"REBUILT"|"MATCH"|"STALE_REPLACED"|"FORGED_REPLACED" }
  | { readonly ok:false; readonly code:EngineeringStatusProjectionCodeV1 };

export interface EngineeringStatusProjectionStoreV1 {
  load(projectId:string): EngineeringStatusProjectionV1 | undefined;
  compareAndSave(projectId:string, expectedDigest:string | null, projection:EngineeringStatusProjectionV1): boolean;
}

const HEX64=/^[0-9a-f]{64}$/u;
const kinds:readonly EngineeringLifecycleSourceKindV1[]=["goal","decomposition","approval"];
const plain=(v:unknown):v is Record<string,unknown>=>v!==null&&typeof v==="object"&&!Array.isArray(v);
const stable=(v:unknown):unknown=>Array.isArray(v)?v.map(stable):plain(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])])):typeof v==="bigint"?v.toString():v;
const digest=(v:unknown)=>createHash("sha256").update(JSON.stringify(stable(v))).digest("hex");
const finite=(v:bigint)=>v>=0n&&v<=BigInt(Number.MAX_SAFE_INTEGER);

function authorityMatches(expected:EngineeringStatusProjectionAuthorityV1, receipt:AuthoritativeReplayV1Receipt):boolean {
  const actual=receipt.authority;
  return expected.kind==="n1"
    ? actual.kind==="n1"&&actual.track==="n1"&&actual.actor_id===expected.principal_id&&actual.authority_domain==="local-owner"&&actual.custody_id===expected.custody_id
    : actual.kind==="enterprise"&&actual.track==="enterprise"&&actual.actor_id===expected.actor_id&&actual.authority_domain==="organization"&&actual.organization_id===expected.organization_id&&actual.tenant_id===expected.tenant_id&&actual.actor_role_id===expected.role_id&&actual.custody_id===expected.custody_id&&actual.isolation_id===expected.isolation_id;
}
function sameAuthority(a:EngineeringStatusProjectionAuthorityV1,b:EngineeringStatusProjectionAuthorityV1):boolean{return digest(a)===digest(b);}
function validIdentity(v:string):boolean{return v.length>0&&Buffer.byteLength(v,"utf8")<=1024;}
export function isEngineeringStatusProjectionV1(v:unknown):v is EngineeringStatusProjectionV1{
  if(!plain(v)||v.schema!=="keep.engineering-status-projection"||v.schema_version!==1||typeof v.project_id!=="string"||typeof v.run_id!=="string"||!plain(v.authority)||!Array.isArray(v.source_heads)||!plain(v.statuses)||typeof v.projection_digest!=="string"||!HEX64.test(v.projection_digest)||v.authoritative!==false||v.implementation_authorized!==false)return false;
  return v.source_heads.every(h=>plain(h)&&kinds.includes(h.kind as EngineeringLifecycleSourceKindV1)&&typeof h.history_id==="string"&&Number.isSafeInteger(h.event_count)&&Number.isSafeInteger(h.final_sequence)&&typeof h.final_event_id==="string"&&HEX64.test(h.final_event_id)&&typeof h.final_head_id==="string"&&HEX64.test(h.final_head_id)&&typeof h.state_digest==="string"&&HEX64.test(h.state_digest));
}

/** Build a read-only view only after T010-T012 semantic replay has closed successfully. */
export function rebuildEngineeringStatusProjectionV1(input:EngineeringStatusProjectionInputV1):EngineeringStatusProjectionResultV1 {
  if(input.schema_version!==1||!validIdentity(input.project_id)||!validIdentity(input.run_id)||input.sources.length===0)return {ok:false,code:"HISTORY_REQUIRED"};
  const seen=new Set<EngineeringLifecycleSourceKindV1>();
  const heads:EngineeringStatusSourceHeadV1[]=[];const statuses:Partial<Record<EngineeringLifecycleSourceKindV1,Readonly<Record<string,unknown>>>>={};
  for(const source of input.sources){
    const r=source.receipt;
    if(!kinds.includes(source.kind)||seen.has(source.kind)||!plain(source.status))return {ok:false,code:"LEGACY_AUTHORITY_GAP"};
    if(r.closed!==true||r.effects_performed!==false||r.projection_authoritative!==false||r.history_id!==input.run_id||r.event_count<=0n||!finite(r.event_count)||!finite(r.final_sequence)||r.final_sequence!==r.event_count-1n||!HEX64.test(r.final_event_id)||!HEX64.test(r.final_head_id)||!HEX64.test(r.state_digest))return {ok:false,code:r.history_id===input.run_id?"EVENT_COMMIT_REQUIRED":"TRACK_AUTHORITY_SUBSTITUTION"};
    if(!authorityMatches(input.authority,r))return {ok:false,code:"TRACK_AUTHORITY_SUBSTITUTION"};
    seen.add(source.kind);heads.push({kind:source.kind,history_id:r.history_id,event_count:Number(r.event_count),final_sequence:Number(r.final_sequence),final_event_id:r.final_event_id,final_head_id:r.final_head_id,state_digest:r.state_digest});statuses[source.kind]=structuredClone(source.status);
  }
  heads.sort((a,b)=>kinds.indexOf(a.kind)-kinds.indexOf(b.kind));
  const body={schema:"keep.engineering-status-projection" as const,schema_version:1 as const,project_id:input.project_id,run_id:input.run_id,authority:structuredClone(input.authority),source_heads:Object.freeze(heads.map(h=>Object.freeze(h))),statuses:Object.freeze(statuses),authoritative:false as const,implementation_authorized:false as const};
  return {ok:true,projection:Object.freeze({...body,projection_digest:digest(body)}),disposition:"REBUILT"};
}

/** Cached bytes never select state: foreign caches are refused; stale/forged local caches are replaced. */
export function reconcileEngineeringStatusProjectionV1(input:EngineeringStatusProjectionInputV1,cached:EngineeringStatusProjectionV1|undefined):EngineeringStatusProjectionResultV1 {
  const rebuilt=rebuildEngineeringStatusProjectionV1(input);if(!rebuilt.ok)return rebuilt;
  if(cached===undefined)return rebuilt;
  if(!isEngineeringStatusProjectionV1(cached))return {...rebuilt,disposition:"FORGED_REPLACED"};
  if(cached.project_id!==input.project_id||cached.run_id!==input.run_id||!sameAuthority(cached.authority,input.authority))return {ok:false,code:"TRACK_AUTHORITY_SUBSTITUTION"};
  const canonical=rebuilt.projection;
  if(cached.projection_digest===canonical.projection_digest&&digest({...cached,projection_digest:undefined})===digest({...canonical,projection_digest:undefined}))return {...rebuilt,disposition:"MATCH"};
  const cachedHeads=new Map(cached.source_heads.map(h=>[h.kind,h]));
  const claimsNewer=canonical.source_heads.some(h=>{const c=cachedHeads.get(h.kind);return c!==undefined&&(c.event_count>h.event_count||(c.event_count===h.event_count&&c.final_head_id!==h.final_head_id));});
  return {...rebuilt,disposition:claimsNewer?"FORGED_REPLACED":"STALE_REPLACED"};
}

/** Publish only a view freshly rebuilt from a closed event head; CAS prevents stale processes winning. */
export function publishEngineeringStatusProjectionV1(input:EngineeringStatusProjectionInputV1,store:EngineeringStatusProjectionStoreV1,expectedDigest:string|null):EngineeringStatusProjectionResultV1 {
  const rebuilt=rebuildEngineeringStatusProjectionV1(input);if(!rebuilt.ok)return rebuilt;
  return store.compareAndSave(input.project_id,expectedDigest,rebuilt.projection)?rebuilt:{ok:false,code:"STALE_PROJECTION"};
}

export function requireEngineeringStatusAuthorityV1(_projection:EngineeringStatusProjectionV1):{readonly ok:false;readonly code:"PROJECTION_AUTHORITY_FORBIDDEN"}{return {ok:false,code:"PROJECTION_AUTHORITY_FORBIDDEN"};}

export class InMemoryEngineeringStatusProjectionStoreV1 implements EngineeringStatusProjectionStoreV1 {
  readonly #values=new Map<string,EngineeringStatusProjectionV1>();
  load(projectId:string):EngineeringStatusProjectionV1|undefined{const value=this.#values.get(projectId);return value===undefined?undefined:structuredClone(value);}
  compareAndSave(projectId:string,expectedDigest:string|null,projection:EngineeringStatusProjectionV1):boolean{
    const current=this.#values.get(projectId);if((current?.projection_digest??null)!==expectedDigest||projection.project_id!==projectId)return false;
    this.#values.set(projectId,structuredClone(projection));return true;
  }
}
