import { createHash } from "node:crypto";
import type { AdmittedGoalAuthorityV1 } from "../goal/goal_authority.js";

export type GoalResearchLane = "current" | "historical" | "cross-disciplinary";
export type ResearchSourceClass = "mutable-current" | "versioned-standard" | "immutable-local";

export interface ResearchProtocolV1 {
  schema_version: 1;
  goal_digest: string;
  predecessor_digest: string;
  questions: { current: string; historical: string; cross_disciplinary: string };
  inclusion_rules: string[];
  exclusion_rules: string[];
  freshness_policies: { mutable_current_months: 3; versioned_standard: "IDENTITY"; immutable_local: "IDENTITY" };
  expected_adverse_evidence: string[];
  falsifiers: string[];
  required_consequence_classes: Array<"goal_question" | "scope" | "architecture" | "requirement" | "threat" | "test_oracle">;
}

export interface GoalResearchRowV1 {
  row_id: string;
  lane: GoalResearchLane;
  locator: string;
  query: string;
  candidate: string;
  observation: string;
  observed_at: string;
  observed_identity: string;
  source_class: ResearchSourceClass;
  disposition: "SELECTED" | "REJECTED" | "LIMITED";
  disposition_reason: string;
  uncertainty: string;
  evidence_stance: "SUPPORTS" | "ADVERSE" | "MIXED";
}

export interface ResearchConsequenceV1 {
  consequence_id: string;
  class: "goal_question" | "scope" | "architecture" | "requirement" | "threat" | "test_oracle";
  statement: string;
  mechanism: string;
  source_row_ids: string[];
}

export interface GoalResearchRecordV1 {
  schema_version: 1;
  goal_digest: string;
  predecessor_digest: string;
  protocol_digest: string;
  rows: GoalResearchRowV1[];
  adverse_evidence: string[];
  falsifiers: string[];
  consequences: ResearchConsequenceV1[];
  executable: false;
}

const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
export const stableResearchJson = (value: unknown): string => JSON.stringify(stable(value));
const stable = (value: unknown): unknown => Array.isArray(value) ? value.map(stable) : object(value) ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])])) : value;
export const researchProtocolDigest = (protocol: ResearchProtocolV1): string => createHash("sha256").update(stableResearchJson(protocol)).digest("hex");
export const deepFreezeResearch = <T>(value: T): T => { if (value && typeof value === "object") { Object.freeze(value); for (const child of Object.values(value as Record<string, unknown>)) deepFreezeResearch(child); } return value; };
export const cloneResearch = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

export type ResearchDenial = "RESEARCH_PROTOCOL_MISSING" | "RESEARCH_LANE_MISSING" | "SOURCE_LEDGER_INCOMPLETE" | "SOURCE_STALE" | "ADVERSE_EVIDENCE_MISSING" | "CONSEQUENCE_ORPHAN";
export type CurrentResearchIdentities = Readonly<Record<string, string>>;
export type GoalResearchAdmissionResult = { admitted:false; denial:ResearchDenial } | { admitted:true; authority:Readonly<GoalResearchRecordV1 & { status:"GOAL_RESEARCH_ADMITTED" }> };
const HEX=/^[a-f0-9]{64}$/u,RFC3339=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/u;
const LANES:GoalResearchLane[]=["current","historical","cross-disciplinary"],CLASSES:ResearchConsequenceV1["class"][]=["goal_question","scope","architecture","requirement","threat","test_oracle"];
const exact=(v:Record<string,unknown>,keys:string[])=>JSON.stringify(Object.keys(v).sort())===JSON.stringify([...keys].sort());
const nonempty=(v:unknown):v is string=>typeof v==="string"&&v.length>0,nonemptyStrings=(v:unknown):v is string[]=>Array.isArray(v)&&v.length>0&&v.every(nonempty);
const denial=(code:ResearchDenial):GoalResearchAdmissionResult=>({admitted:false,denial:code});
function plusMonths(date:Date,months:number):Date{const y=date.getUTCFullYear(),m=date.getUTCMonth()+months,d=date.getUTCDate(),last=new Date(Date.UTC(y,m+1,0)).getUTCDate();return new Date(Date.UTC(y,m,Math.min(d,last),date.getUTCHours(),date.getUTCMinutes(),date.getUTCSeconds(),date.getUTCMilliseconds()));}
function protocolValid(value:unknown,goal:AdmittedGoalAuthorityV1,predecessor:string):value is ResearchProtocolV1{
  if(!object(value)||!exact(value,["schema_version","goal_digest","predecessor_digest","questions","inclusion_rules","exclusion_rules","freshness_policies","expected_adverse_evidence","falsifiers","required_consequence_classes"])||value.schema_version!==1||value.goal_digest!==goal.goal_digest||value.predecessor_digest!==predecessor||!HEX.test(predecessor))return false;
  const q=value.questions,p=value.freshness_policies,r=value.required_consequence_classes;
  return object(q)&&exact(q,["current","historical","cross_disciplinary"])&&nonempty(q.current)&&nonempty(q.historical)&&nonempty(q.cross_disciplinary)&&nonemptyStrings(value.inclusion_rules)&&nonemptyStrings(value.exclusion_rules)&&nonemptyStrings(value.expected_adverse_evidence)&&nonemptyStrings(value.falsifiers)&&object(p)&&exact(p,["mutable_current_months","versioned_standard","immutable_local"])&&p.mutable_current_months===3&&p.versioned_standard==="IDENTITY"&&p.immutable_local==="IDENTITY"&&Array.isArray(r)&&CLASSES.every(k=>r.includes(k));
}
function rowValid(value:unknown):value is GoalResearchRowV1{
  const allowed=["row_id","lane","locator","query","candidate","observation","observed_at","observed_identity","source_class","disposition","disposition_reason","uncertainty","evidence_stance"];
  if(!object(value)||Object.keys(value).some(key=>!allowed.includes(key)))return false;
  return nonempty(value.row_id)&&LANES.includes(value.lane as GoalResearchLane)&&nonempty(value.locator)&&value.locator===value.locator.trim()&&!/[\s,;]/u.test(value.locator)&&(value.locator.match(/[a-z][a-z0-9+.-]*:\/\//giu)?.length??0)<=1&&nonempty(value.query)&&nonempty(value.candidate)&&nonempty(value.observation)&&nonempty(value.observed_identity)&&nonempty(value.observed_at)&&RFC3339.test(value.observed_at)&&!Number.isNaN(Date.parse(value.observed_at))&&["mutable-current","versioned-standard","immutable-local"].includes(value.source_class as string);
}
export function admitGoalResearch(goal:AdmittedGoalAuthorityV1,protocol:unknown,recordInput:unknown,clock:string,currentIdentities:CurrentResearchIdentities):GoalResearchAdmissionResult{
  const predecessor=object(recordInput)&&typeof recordInput.predecessor_digest==="string"?recordInput.predecessor_digest:"";
  if(!protocolValid(protocol,goal,predecessor)||!object(recordInput)||recordInput.protocol_digest!==researchProtocolDigest(protocol))return denial("RESEARCH_PROTOCOL_MISSING");
  if(!exact(recordInput,["schema_version","goal_digest","predecessor_digest","protocol_digest","rows","adverse_evidence","falsifiers","consequences","executable"])||recordInput.schema_version!==1||recordInput.goal_digest!==goal.goal_digest||recordInput.predecessor_digest!==protocol.predecessor_digest||recordInput.executable!==false||!Array.isArray(recordInput.rows))return denial("SOURCE_LEDGER_INCOMPLETE");
  const rows=recordInput.rows;
  if(!LANES.every(l=>rows.some(r=>object(r)&&r.lane===l))||new Set(Object.values(protocol.questions)).size!==3)return denial("RESEARCH_LANE_MISSING");
  if(!rows.every(rowValid))return denial("SOURCE_LEDGER_INCOMPLETE");
  const rowIds=new Set<string>(); for(const row of rows){if(rowIds.has(row.row_id))return denial("SOURCE_LEDGER_INCOMPLETE");rowIds.add(row.row_id);for(const other of rows)if(other!==row&&other.lane!==row.lane&&other.locator===row.locator&&other.query===row.query&&other.disposition===row.disposition)return denial("SOURCE_LEDGER_INCOMPLETE");}
  const now=RFC3339.test(clock)?new Date(clock):new Date(Number.NaN);for(const row of rows){if(Number.isNaN(now.getTime())||currentIdentities[row.locator]!==row.observed_identity)return denial("SOURCE_STALE");if(row.source_class==="mutable-current"&&now>plusMonths(new Date(row.observed_at),3))return denial("SOURCE_STALE");}
  if(rows.some(r=>!["SELECTED","REJECTED","LIMITED"].includes(r.disposition)||!nonempty(r.disposition_reason)||!nonempty(r.uncertainty)||!["SUPPORTS","ADVERSE","MIXED"].includes(r.evidence_stance))||!nonemptyStrings(recordInput.adverse_evidence)||!nonemptyStrings(recordInput.falsifiers)||!rows.some(r=>r.evidence_stance!=="SUPPORTS"))return denial("ADVERSE_EVIDENCE_MISSING");
  const consequences=recordInput.consequences;if(!Array.isArray(consequences)||!consequences.every((c:unknown)=>object(c)&&exact(c,["consequence_id","class","statement","mechanism","source_row_ids"])&&nonempty(c.consequence_id)&&CLASSES.includes(c.class as ResearchConsequenceV1["class"])&&nonempty(c.statement)&&nonempty(c.mechanism)&&nonemptyStrings(c.source_row_ids)&&c.source_row_ids.every(id=>rowIds.has(id)))||!CLASSES.every(k=>consequences.some((c:unknown)=>object(c)&&c.class===k))||!rows.every(row=>consequences.some((c:unknown)=>object(c)&&Array.isArray(c.source_row_ids)&&c.source_row_ids.includes(row.row_id))))return denial("CONSEQUENCE_ORPHAN");
  const authority={...(cloneResearch(recordInput) as unknown as GoalResearchRecordV1),status:"GOAL_RESEARCH_ADMITTED" as const};return {admitted:true,authority:deepFreezeResearch(authority)};
}
