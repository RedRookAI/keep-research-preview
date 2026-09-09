import { createHash } from "node:crypto";

import { decodeCanonical, eirDigest } from "../eir/canonical.js";
import type { GoalLifecycleArtifactV1, GoalLifecycleRequestV1 } from "../autonomy/project_state.js";
import { admitGoal, type AuthorityContextV1, type GoalScopeAuthorityV1 } from "../goal/goal_authority.js";
import { evaluateGoalTransition, type GoalTransitionProposalV1, type GoalTransitionResult, type GoalTransitionStateV1 } from "../goal/goal_transition.js";
import { admitGoalResearch, type CurrentResearchIdentities, type GoalResearchRecordV1, type ResearchProtocolV1 } from "../research/goal_research.js";
import type { AuthoritativeReplayV1Event, AuthoritativeReplayV1Result } from "./authoritative_replay_v1.js";
import { EventEnvelopeV1Encode } from "./event_envelope_v1.js";
import { EventAdmissionV1HeadDigestDomain } from "./event_admission_v1.js";

export type GoalAuthorityEventV1Code =
  | "GOAL_EVENT_AUTHORITY_REQUIRED"
  | "GOAL_HISTORY_INVALID"
  | "INCOMPLETE_GOAL_HISTORY"
  | "TRACK_AUTHORITY_SUBSTITUTION"
  | "LEGACY_GOAL_MUTATION_REJECTED";

export interface GoalAuthorityEventV1 {
  readonly schema: "keep.goal-authority-event";
  readonly schema_version: 1;
  readonly run_id: string;
  readonly request_digest: string;
  readonly operation: "goal-admitted" | "research-admitted" | "goal-transitioned";
  readonly transition_index: number | null;
  readonly artifact: GoalLifecycleArtifactV1;
  readonly transition_result: GoalTransitionResult | null;
}

export interface GoalAuthorityReplayBundleV1 {
  readonly events: readonly AuthoritativeReplayV1Event[];
  readonly replay: AuthoritativeReplayV1Result;
}

/** Storage owns append, witness, commit, and T009 replay. This layer owns goal semantics. */
export interface GoalAuthorityEventPortV1 {
  load(historyId: string): Promise<GoalAuthorityReplayBundleV1 | null>;
  appendAndReplay(historyId: string, event: GoalAuthorityEventV1): Promise<GoalAuthorityReplayBundleV1>;
}

export type GoalAuthorityReconstructionV1 =
  | { readonly ok: true; readonly artifact: GoalLifecycleArtifactV1 | null; readonly event_count: number }
  | { readonly ok: false; readonly code: GoalAuthorityEventV1Code };

const hex64 = /^[0-9a-f]{64}$/u;
const plain = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const stableValue = (value: unknown): unknown => Array.isArray(value)
  ? value.map(stableValue)
  : plain(value)
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]))
    : value;
const stableJson = (value: unknown): string => JSON.stringify(stableValue(value));
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

export function goalAuthorityRequestDigestV1(request: GoalLifecycleRequestV1): string {
  // The event envelope and T009 bind these bytes cryptographically. This digest is the
  // domain-level request identity used to reject a different request on resume.
  return createHash("sha256").update(stableJson(request)).digest("hex");
}

function decodeDomainEvent(row: AuthoritativeReplayV1Event): GoalAuthorityEventV1 | null {
  const encoded = EventEnvelopeV1Encode(row.proposal);
  if (!encoded.ok) return null;
  try {
    const envelope = decodeCanonical(encoded.canonical_bytes) as Record<string, unknown>;
    if (envelope.event_type !== "goal.admitted" && envelope.event_type !== "goal.transitioned") return null;
    const payload = envelope.payload;
    if (!plain(payload) || Object.keys(payload).sort().join(",") !== "domain_json") return null;
    if (typeof payload.domain_json !== "string") return null;
    const event = JSON.parse(payload.domain_json) as unknown;
    if (!plain(event) || event.schema !== "keep.goal-authority-event" || event.schema_version !== 1
      || typeof event.run_id !== "string" || typeof event.request_digest !== "string" || !hex64.test(event.request_digest)
      || !["goal-admitted", "research-admitted", "goal-transitioned"].includes(String(event.operation))
      || !(event.transition_index === null || Number.isSafeInteger(event.transition_index))
      || !plain(event.artifact) || !(event.transition_result === null || plain(event.transition_result))) return null;
    return event as unknown as GoalAuthorityEventV1;
  } catch { return null; }
}

function trackMatches(request: GoalLifecycleRequestV1, replay: Extract<AuthoritativeReplayV1Result, { ok: true }>): boolean {
  const goal = request.authority_context as AuthorityContextV1;
  const authority = replay.receipt.authority;
  if (goal.kind === "n1") return authority.kind === "n1" && authority.actor_id === goal.principal_id
    && authority.authority_domain === "local-owner" && authority.custody_id === goal.custody_id;
  return authority.kind === "enterprise" && authority.actor_id === goal.principal_id
    && authority.authority_domain === "organization" && authority.organization_id === goal.organization_id
    && authority.actor_role_id === goal.role_id && authority.isolation_id === goal.separation_policy_id
    && authority.tenant_id.length > 0 && authority.custody_id.length > 0;
}

function bundleMatchesReplay(historyId:string,bundle:GoalAuthorityReplayBundleV1,replay:Extract<AuthoritativeReplayV1Result,{ok:true}>):boolean {
  let priorEvent:string|null=null,priorHead:string|null=null;
  for(let index=0;index<bundle.events.length;index+=1){
    const encoded=EventEnvelopeV1Encode(bundle.events[index]!.proposal);if(!encoded.ok)return false;
    try{
      const event=decodeCanonical(encoded.canonical_bytes) as Record<string,unknown>;
      if(event.history_id!==historyId||event.sequence!==BigInt(index)||event.predecessor_event_id!==priorEvent||event.predecessor_head_id!==priorHead)return false;
      priorHead=eirDigest(EventAdmissionV1HeadDigestDomain,{history_id:historyId,sequence:BigInt(index),event_id:encoded.event_digest,predecessor_head_id:priorHead});
      priorEvent=encoded.event_digest;
    }catch{return false}
  }
  return bundle.events.length>0&&replay.receipt.event_count===BigInt(bundle.events.length)
    &&replay.receipt.final_sequence===BigInt(bundle.events.length-1)&&replay.receipt.final_event_id===priorEvent&&replay.receipt.final_head_id===priorHead;
}

function initialArtifact(request: GoalLifecycleRequestV1): GoalLifecycleArtifactV1 {
  return {
    schema_version: 1, mode: "goal-to-architecture", request, code: "IN_PROGRESS",
    admitted_goal: null, admitted_research: null,
    transition_state: request.transition_state, next_transition_index: 0, executable: false,
  };
}

function expectedEvents(request: GoalLifecycleRequestV1): readonly GoalAuthorityEventV1[] | null {
  const goal = admitGoal(null, request.goal_candidate, request.authority_context as AuthorityContextV1 | null, request.scope_authority as GoalScopeAuthorityV1);
  if (!goal.admitted) return null;
  const research = admitGoalResearch(goal.authority, request.research_protocol as ResearchProtocolV1, request.research_record as GoalResearchRecordV1,
    request.observed_at, request.current_source_identities as CurrentResearchIdentities);
  if (!research.admitted) return null;
  const digest = goalAuthorityRequestDigestV1(request);
  let artifact = initialArtifact(request);
  const out: GoalAuthorityEventV1[] = [];
  artifact = { ...artifact, admitted_goal: goal.authority };
  out.push({ schema:"keep.goal-authority-event", schema_version:1, run_id:"", request_digest:digest, operation:"goal-admitted", transition_index:null, artifact:clone(artifact), transition_result:null });
  artifact = { ...artifact, admitted_research: research.authority };
  out.push({ schema:"keep.goal-authority-event", schema_version:1, run_id:"", request_digest:digest, operation:"research-admitted", transition_index:null, artifact:clone(artifact), transition_result:null });
  for (let index = 0; index < request.transitions.length; index += 1) {
    const result = evaluateGoalTransition(artifact.transition_state, request.transitions[index] as GoalTransitionProposalV1);
    // A rejected future proposal does not invalidate the already-committed prefix.
    // The autonomy caller returns that denial without appending another event.
    if (!result.advanced) break;
    const terminal = result.state.phase === "ARCHITECTURE_AUTHORIZED";
    artifact = { ...artifact, code:terminal ? "ARCHITECTURE_AUTHORIZED" : "IN_PROGRESS", transition_state:result.state, next_transition_index:index + 1 };
    out.push({ schema:"keep.goal-authority-event", schema_version:1, run_id:"", request_digest:digest, operation:"goal-transitioned", transition_index:index, artifact:clone(artifact), transition_result:clone(result) });
  }
  return out;
}

export function reconstructGoalAuthorityEventsV1(historyId: string, request: GoalLifecycleRequestV1, bundle: GoalAuthorityReplayBundleV1 | null): GoalAuthorityReconstructionV1 {
  if (bundle === null) return { ok:true, artifact:null, event_count:0 };
  if (!bundle.replay.ok) return { ok:false, code:bundle.replay.code === "TRACK_AUTHORITY_SUBSTITUTION" ? "TRACK_AUTHORITY_SUBSTITUTION" : "GOAL_HISTORY_INVALID" };
  if (bundle.replay.receipt.history_id !== historyId || !bundleMatchesReplay(historyId,bundle,bundle.replay)) return { ok:false, code:"GOAL_HISTORY_INVALID" };
  if (!trackMatches(request,bundle.replay)) return { ok:false, code:"TRACK_AUTHORITY_SUBSTITUTION" };
  const expected = expectedEvents(request);
  if (expected === null || expected.length < bundle.events.length) return { ok:false, code:"GOAL_HISTORY_INVALID" };
  let artifact: GoalLifecycleArtifactV1 | null = null;
  for (let index = 0; index < bundle.events.length; index += 1) {
    const actual = decodeDomainEvent(bundle.events[index]!);
    const wanted = expected[index]!;
    if (actual === null || actual.run_id !== historyId || actual.request_digest !== wanted.request_digest
      || actual.operation !== wanted.operation || actual.transition_index !== wanted.transition_index) return { ok:false, code:"GOAL_HISTORY_INVALID" };
    const wantedWithRun = { ...wanted, run_id:historyId };
    if (stableJson(actual) !== stableJson(wantedWithRun)) return { ok:false, code:actual.operation === "goal-transitioned" ? "INCOMPLETE_GOAL_HISTORY" : "GOAL_HISTORY_INVALID" };
    artifact = clone(actual.artifact);
  }
  return { ok:true, artifact, event_count:bundle.events.length };
}

export function nextGoalAuthorityEventV1(historyId:string, request:GoalLifecycleRequestV1, eventCount:number):GoalAuthorityEventV1 | null {
  const expected=expectedEvents(request); if(expected===null||eventCount<0||eventCount>=expected.length)return null;
  return { ...clone(expected[eventCount]!), run_id:historyId };
}

export function rejectLegacyGoalMutationV1(): { readonly ok:false; readonly code:"LEGACY_GOAL_MUTATION_REJECTED" } {
  return { ok:false, code:"LEGACY_GOAL_MUTATION_REJECTED" };
}
