export const GOAL_TRANSITION_PHASES = [
  "GOAL_PROPOSED", "GOAL_ADMITTED", "RESEARCH_PROTOCOL_FROZEN", "RESEARCH_CANDIDATE",
  "RESEARCH_STRUCTURAL_PASS", "RESEARCH_SEMANTIC_PASS", "ARCHITECTURE_AUTHORIZED",
] as const;
export type GoalTransitionPhase = typeof GOAL_TRANSITION_PHASES[number];
export type GoalTransitionDenial = "MALFORMED_OR_UNKNOWN_FIELD" | "ILLEGAL_PHASE_EDGE" | "STALE_DERIVATION" | "CONSEQUENCE_ORPHAN" | "SEMANTIC_ADMISSION_MISSING" | "SEMANTIC_ADMISSION_INVALID" | "SEMANTIC_ADMISSION_REJECTED";
export type GoalTransitionCode = GoalTransitionDenial | "OWNER_DECISION" | "AUTHORITY_REJECTED" | "ADVANCED";
export type DescendantKind = "protocol" | "research" | "semantic_admission" | "architecture" | "decomposition" | "owner_approval" | "tickets";

export interface TransitionDescendantV1 { digest:string; depends_on:string[]; status:"ACTIVE"|"STALE_DERIVATION" }
export interface GoalTransitionStateV1 {
  schema_version:1; phase:GoalTransitionPhase; active_head_digest:string;
  ancestor_digests:Record<string,string>; descendants:Record<DescendantKind,TransitionDescendantV1>;
  downstream_vets_consumed:0|1|2;
}
export interface ConsequenceGraphV1 {
  questions:string[]; scope_ids:string[]; sources:string[]; mechanisms:string[]; consequences:string[];
  edges:Array<{from:string;to:string}>; owner_stops:string[];
}
export interface SemanticAdmissionV1 {
  schema_version:1; ticket_digest:string; round:1; research_digest:string; author_family:string;
  reviewer_family:string; reviewer_id:string; policy_digest:string; evidence_digest:string;
  reviewed_at:string; verdict:"PASS"|"REJECT";
}
export interface DownstreamVetRequestV1 { ticket_digest:string; round:number; receipt_ticket_digest:string; receipt_round:number }
export type GoalTransitionAuthorityContextV1 =
  | { kind:"n1"; principal_id:string; custody_id:string; organization_services:"ABSENT" }
  | { kind:"enterprise"; organization_id:string; actor_id:string; role_id:string; separation_policy_id:string; local_owner_substitution:false };
export interface GoalTransitionProposalV1 {
  schema_version:1; from_phase:GoalTransitionPhase; to_phase:GoalTransitionPhase;
  expected_active_head_digest:string; next_head_digest:string; required_ancestor_digests:Record<string,string>;
  consequence_graph:ConsequenceGraphV1; semantic_admission:SemanticAdmissionV1|null;
  trusted_reviewer_ids:string[]; expected_ticket_digest:string; expected_policy_digest:string; expected_evidence_digest:string;
  authority_verdict:"PASS"|"REJECT"; supersedes:"goal"|"protocol"|"research"|null;
  authority_context:GoalTransitionAuthorityContextV1; downstream_vet:DownstreamVetRequestV1|null;
}
export type GoalTransitionResult = { code:GoalTransitionCode; advanced:boolean; state:GoalTransitionStateV1; stale_descendants:DescendantKind[]; vet_consumed:boolean };

const HEX=/^[a-f0-9]{64}$/u, RFC3339=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/u;
const STATE_KEYS=["schema_version","phase","active_head_digest","ancestor_digests","descendants","downstream_vets_consumed"];
const PROPOSAL_KEYS=["schema_version","from_phase","to_phase","expected_active_head_digest","next_head_digest","required_ancestor_digests","consequence_graph","semantic_admission","trusted_reviewer_ids","expected_ticket_digest","expected_policy_digest","expected_evidence_digest","authority_verdict","supersedes","authority_context","downstream_vet"];
const GRAPH_KEYS=["questions","scope_ids","sources","mechanisms","consequences","edges","owner_stops"];
const SEMANTIC_KEYS=["schema_version","ticket_digest","round","research_digest","author_family","reviewer_family","reviewer_id","policy_digest","evidence_digest","reviewed_at","verdict"];
const VET_KEYS=["ticket_digest","round","receipt_ticket_digest","receipt_round"];
const DESCENDANTS:DescendantKind[]=["protocol","research","semantic_admission","architecture","decomposition","owner_approval","tickets"];
const object=(v:unknown):v is Record<string,unknown>=>v!==null&&typeof v==="object"&&!Array.isArray(v);
const exact=(v:Record<string,unknown>,keys:string[])=>Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const strings=(v:unknown):v is string[]=>Array.isArray(v)&&v.every(x=>typeof x==="string"&&x.length>0)&&new Set(v).size===v.length;
const clone=<T>(v:T):T=>JSON.parse(JSON.stringify(v)) as T;
const result=(code:GoalTransitionCode,state:GoalTransitionStateV1,advanced=false,stale_descendants:DescendantKind[]=[],vet_consumed=false):GoalTransitionResult=>({code,advanced,state:clone(state),stale_descendants,vet_consumed});

function validState(v:unknown):v is GoalTransitionStateV1 {
  if(!object(v)||!exact(v,STATE_KEYS)||v.schema_version!==1||!GOAL_TRANSITION_PHASES.includes(v.phase as GoalTransitionPhase)||typeof v.active_head_digest!=="string"||!HEX.test(v.active_head_digest)||!object(v.ancestor_digests)||!Object.values(v.ancestor_digests).every(x=>typeof x==="string"&&HEX.test(x))||!object(v.descendants)||![0,1,2].includes(v.downstream_vets_consumed as number))return false;
  const descendants=v.descendants;return exact(descendants,DESCENDANTS)&&DESCENDANTS.every(k=>{const d=descendants[k];return object(d)&&exact(d,["digest","depends_on","status"])&&typeof d.digest==="string"&&HEX.test(d.digest)&&strings(d.depends_on)&&["ACTIVE","STALE_DERIVATION"].includes(d.status as string)});
}
function validProposal(v:unknown):v is GoalTransitionProposalV1 {
  if(!object(v)||!exact(v,PROPOSAL_KEYS)||v.schema_version!==1||!GOAL_TRANSITION_PHASES.includes(v.from_phase as GoalTransitionPhase)||!GOAL_TRANSITION_PHASES.includes(v.to_phase as GoalTransitionPhase)||typeof v.expected_active_head_digest!=="string"||!HEX.test(v.expected_active_head_digest)||typeof v.next_head_digest!=="string"||!HEX.test(v.next_head_digest)||!object(v.required_ancestor_digests)||!Object.values(v.required_ancestor_digests).every(x=>typeof x==="string"&&HEX.test(x))||!strings(v.trusted_reviewer_ids)||typeof v.expected_ticket_digest!=="string"||!HEX.test(v.expected_ticket_digest)||typeof v.expected_policy_digest!=="string"||!HEX.test(v.expected_policy_digest)||typeof v.expected_evidence_digest!=="string"||!HEX.test(v.expected_evidence_digest)||!["PASS","REJECT"].includes(v.authority_verdict as string)||![null,"goal","protocol","research"].includes(v.supersedes as string|null))return false;
  if(!object(v.consequence_graph)||!exact(v.consequence_graph,GRAPH_KEYS)||!strings(v.consequence_graph.questions)||!strings(v.consequence_graph.scope_ids)||!strings(v.consequence_graph.sources)||!strings(v.consequence_graph.mechanisms)||!strings(v.consequence_graph.consequences)||!strings(v.consequence_graph.owner_stops)||!Array.isArray(v.consequence_graph.edges)||!v.consequence_graph.edges.every(e=>object(e)&&exact(e,["from","to"])&&typeof e.from==="string"&&typeof e.to==="string"))return false;
  if(v.semantic_admission!==null&&(!object(v.semantic_admission)||!exact(v.semantic_admission,SEMANTIC_KEYS)))return false;
  if(!object(v.authority_context))return false;const a=v.authority_context;
  if(a.kind==="n1"){if(!exact(a,["kind","principal_id","custody_id","organization_services"])||typeof a.principal_id!=="string"||!a.principal_id||typeof a.custody_id!=="string"||!a.custody_id||a.organization_services!=="ABSENT")return false}
  else if(a.kind==="enterprise"){if(!exact(a,["kind","organization_id","actor_id","role_id","separation_policy_id","local_owner_substitution"])||![a.organization_id,a.actor_id,a.role_id,a.separation_policy_id].every(x=>typeof x==="string"&&x.length>0)||a.local_owner_substitution!==false)return false}
  else return false;
  if(v.downstream_vet!==null&&(!object(v.downstream_vet)||!exact(v.downstream_vet,VET_KEYS)||![1,2,3].includes(v.downstream_vet.round as number)))return false;
  return true;
}
function graphClosed(g:ConsequenceGraphV1):boolean {
  const toMechanism=(id:string)=>g.edges.some(e=>e.from===id&&g.mechanisms.includes(e.to)),toConsequence=(id:string)=>g.edges.some(e=>e.from===id&&g.consequences.includes(e.to)),incoming=(id:string,from:string[])=>g.edges.some(e=>e.to===id&&from.includes(e.from));
  const legal=g.edges.every(e=>(g.questions.includes(e.from)||g.scope_ids.includes(e.from)||g.sources.includes(e.from))&&g.mechanisms.includes(e.to)||g.sources.includes(e.from)&&g.consequences.includes(e.to)||g.mechanisms.includes(e.from)&&g.consequences.includes(e.to));
  return legal&&g.owner_stops.every(x=>g.questions.includes(x))&&g.questions.every(x=>toMechanism(x)||g.owner_stops.includes(x))&&g.scope_ids.every(toMechanism)&&g.sources.every(toMechanism)&&g.mechanisms.every(toConsequence)&&g.consequences.every(x=>incoming(x,g.sources)&&incoming(x,g.mechanisms));
}
function semanticCode(p:GoalTransitionProposalV1):GoalTransitionCode|null {
  const r=p.semantic_admission;if(!r)return "SEMANTIC_ADMISSION_MISSING";
  if(r.schema_version!==1||r.round!==1||!HEX.test(r.research_digest)||r.research_digest!==p.required_ancestor_digests.research||r.ticket_digest!==p.expected_ticket_digest||r.author_family===r.reviewer_family||!p.trusted_reviewer_ids.includes(r.reviewer_id)||r.policy_digest!==p.expected_policy_digest||r.evidence_digest!==p.expected_evidence_digest||!RFC3339.test(r.reviewed_at)||!Number.isFinite(Date.parse(r.reviewed_at))||!["PASS","REJECT"].includes(r.verdict))return "SEMANTIC_ADMISSION_INVALID";
  return r.verdict==="REJECT"?"SEMANTIC_ADMISSION_REJECTED":null;
}
function invalidate(state:GoalTransitionStateV1,root:string):DescendantKind[]{
  const reachable=new Set<string>([root]),newlyStale:DescendantKind[]=[];let changed=true;while(changed){changed=false;for(const kind of DESCENDANTS){const d=state.descendants[kind];if(!reachable.has(kind)&&d.depends_on.some(x=>reachable.has(x))){reachable.add(kind);changed=true;if(d.status==="ACTIVE"){d.status="STALE_DERIVATION";newlyStale.push(kind)}}}}return newlyStale;
}
function prerequisiteIsStale(state:GoalTransitionStateV1):boolean {
  const required:Partial<Record<GoalTransitionPhase,DescendantKind[]>>={RESEARCH_PROTOCOL_FROZEN:["protocol"],RESEARCH_CANDIDATE:["protocol","research"],RESEARCH_STRUCTURAL_PASS:["protocol","research"],RESEARCH_SEMANTIC_PASS:["protocol","research","semantic_admission"]};return (required[state.phase]??[]).some(kind=>state.descendants[kind].status==="STALE_DERIVATION");
}
function activateTarget(state:GoalTransitionStateV1,to:GoalTransitionPhase,digest:string):void {
  const target:Partial<Record<GoalTransitionPhase,DescendantKind>>={RESEARCH_PROTOCOL_FROZEN:"protocol",RESEARCH_CANDIDATE:"research",RESEARCH_STRUCTURAL_PASS:"research",RESEARCH_SEMANTIC_PASS:"semantic_admission",ARCHITECTURE_AUTHORIZED:"architecture"};const kind=target[to];if(kind){state.descendants[kind].digest=digest;state.descendants[kind].status="ACTIVE"}if(to==="GOAL_ADMITTED")state.ancestor_digests.goal=digest;if(to==="RESEARCH_PROTOCOL_FROZEN")state.ancestor_digests.protocol=digest;if(to==="RESEARCH_CANDIDATE"||to==="RESEARCH_STRUCTURAL_PASS")state.ancestor_digests.research=digest;
}

export function evaluateGoalTransition(stateInput:unknown,proposalInput:unknown):GoalTransitionResult {
  if(!validState(stateInput)||!validProposal(proposalInput))return result("MALFORMED_OR_UNKNOWN_FIELD",validState(stateInput)?stateInput:({} as GoalTransitionStateV1));
  const state=stateInput,proposal=proposalInput,index=GOAL_TRANSITION_PHASES.indexOf(state.phase);
  if(proposal.from_phase!==state.phase||GOAL_TRANSITION_PHASES[index+1]!==proposal.to_phase)return result("ILLEGAL_PHASE_EDGE",state);
  if(proposal.expected_active_head_digest!==state.active_head_digest||Object.entries(proposal.required_ancestor_digests).some(([k,v])=>state.ancestor_digests[k]!==v)||prerequisiteIsStale(state))return result("STALE_DERIVATION",state);
  if(!graphClosed(proposal.consequence_graph))return result("CONSEQUENCE_ORPHAN",state);
  if(proposal.to_phase==="RESEARCH_SEMANTIC_PASS"){const code=semanticCode(proposal);if(code)return result(code,state)}
  if(proposal.authority_verdict==="REJECT")return result("AUTHORITY_REJECTED",state);
  const vet=proposal.downstream_vet;if(vet&&(vet.round>2||vet.round!==state.downstream_vets_consumed+1||vet.ticket_digest!==proposal.expected_ticket_digest||vet.receipt_ticket_digest!==proposal.expected_ticket_digest||vet.receipt_round!==vet.round))return result("OWNER_DECISION",state);
  const next=clone(state);next.phase=proposal.to_phase;next.active_head_digest=proposal.next_head_digest;let stale:DescendantKind[]=[];
  if(proposal.supersedes)stale=invalidate(next,proposal.supersedes);activateTarget(next,proposal.to_phase,proposal.next_head_digest);
  if(vet)next.downstream_vets_consumed=vet.round as 1|2;
  return result("ADVANCED",next,true,stale,Boolean(vet));
}
