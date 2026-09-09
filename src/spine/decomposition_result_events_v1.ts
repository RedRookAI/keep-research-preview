import { createHash } from "node:crypto";
import {
  reconstructDecompositionApprovalAuthorityV1,
  type DecompositionApprovalReplayBundleV1,
} from "../decomposition/decomposition_approval_events_v1.js";
import type { DecompositionAuthorityReplayBundleV1 } from "../decomposition/decomposition_review_events_v1.js";
import {
  activateTicketResearch,
  isTicketResearchIdV1,
  type TicketResearchActivationRequestV1,
  type TicketResearchAuthorityV1,
} from "../autonomy/project_state.js";

export const DECOMPOSITION_RESULT_EVENT_MIGRATED_WRITERS_V1 = Object.freeze(["W14", "W15"] as const);

type ReplaySourceHeadV1 = {
  readonly history_id: string;
  readonly event_count: number;
  readonly final_sequence: number;
  readonly final_event_id: string;
  readonly final_head_id: string;
  readonly state_digest: string;
};

export type DecompositionResultAuthorityV1 =
  | {
      readonly kind: "n1";
      readonly owner_id: string;
      readonly custody_id: string;
      readonly organization_services: "ABSENT";
    }
  | {
      readonly kind: "enterprise";
      readonly organization_id: string;
      readonly tenant_id: string;
      readonly actor_id: string;
      readonly role_id: string;
      readonly separation_policy_id: string;
      readonly custody_id: string;
      readonly isolation_id: string;
      readonly custody_evidence_digest: string;
      readonly isolation_evidence_digest: string;
      readonly local_owner_substitution: false;
    };

export interface DecompositionResultEventV1 {
  readonly schema: "keep.decomposition-result-event";
  readonly schema_version: 1;
  readonly status: "DECOMPOSITION_RESULT_RECORDED";
  readonly source_heads: {
    readonly review: ReplaySourceHeadV1;
    readonly approval: ReplaySourceHeadV1;
  };
  readonly generation: string;
  readonly publication_receipt_digest: string;
  readonly remote_readback_commit: string;
  readonly product_commit: string;
  readonly active_ticket_id: string;
  readonly track: "n1" | "enterprise";
  readonly authority: DecompositionResultAuthorityV1;
  readonly research_receipt_digest: string;
  readonly lifecycle_authoritative: false;
  readonly effects_performed: false;
  readonly event_digest: string;
}

export interface DecompositionResultInputV1 {
  readonly review_history_id: string;
  readonly review_history: DecompositionAuthorityReplayBundleV1;
  readonly approval_history_id: string;
  readonly approval_history: DecompositionApprovalReplayBundleV1;
  readonly activation: TicketResearchActivationRequestV1;
}

export type DecompositionResultEventCodeV1 =
  | "DECOMPOSITION_RESULT_RECORDED"
  | "DECOMPOSITION_RESULT_HISTORY_INVALID"
  | "DECOMPOSITION_RESULT_SUBJECT_MISMATCH"
  | "TRACK_AUTHORITY_SUBSTITUTION"
  | "TENANT_ISOLATION_MISMATCH"
  | "LEGACY_AUTHORITY_GAP";

export type DecompositionResultEventResultV1 =
  | { readonly ok: true; readonly code: "DECOMPOSITION_RESULT_RECORDED"; readonly event: DecompositionResultEventV1 }
  | { readonly ok: false; readonly code: Exclude<DecompositionResultEventCodeV1, "DECOMPOSITION_RESULT_RECORDED"> };

const HEX = /^[a-f0-9]{64}$/u;
const GIT_OID = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u;
const GENERATION = /^sha256:[a-f0-9]{64}$/u;
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const exact = (value: Record<string, unknown>, keys: readonly string[]) => {
  const actual = Object.keys(value).sort(), expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
};
const canonical = (value: unknown): string => Array.isArray(value)
  ? `[${value.map(canonical).join(",")}]`
  : object(value)
    ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`
    : JSON.stringify(value);
const digest = (value: unknown) => createHash("sha256").update(canonical(value)).digest("hex");
const freeze = <T>(value: T): T => {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) freeze(child);
  }
  return value;
};
const finite = (value: bigint) => value >= 0n && value <= BigInt(Number.MAX_SAFE_INTEGER);

function sourceHead(bundle: DecompositionAuthorityReplayBundleV1 | DecompositionApprovalReplayBundleV1): ReplaySourceHeadV1 | null {
  if (!bundle.replay.ok) return null;
  const receipt = bundle.replay.receipt;
  if (!receipt.closed || receipt.effects_performed || receipt.projection_authoritative || receipt.event_count <= 0n || !finite(receipt.event_count) || !finite(receipt.final_sequence)) return null;
  return {
    history_id: receipt.history_id,
    event_count: Number(receipt.event_count),
    final_sequence: Number(receipt.final_sequence),
    final_event_id: receipt.final_event_id,
    final_head_id: receipt.final_head_id,
    state_digest: receipt.state_digest,
  };
}

function authority(input: DecompositionResultInputV1): DecompositionResultAuthorityV1 | DecompositionResultEventCodeV1 {
  if (!input.approval_history.replay.ok) return "DECOMPOSITION_RESULT_HISTORY_INVALID";
  const replay = input.approval_history.replay.receipt.authority;
  const requested = input.activation.authority;
  if (requested.kind === "n1") {
    if (replay.kind !== "n1" || replay.actor_id !== requested.owner_id || replay.custody_id !== requested.custody_id || requested.organization_services !== "ABSENT") return "TRACK_AUTHORITY_SUBSTITUTION";
    return { kind: "n1", owner_id: requested.owner_id, custody_id: requested.custody_id, organization_services: "ABSENT" };
  }
  if (replay.kind !== "enterprise" || replay.organization_id !== requested.organization_id || replay.actor_id !== requested.actor_id || replay.actor_role_id !== requested.role_id) return "TRACK_AUTHORITY_SUBSTITUTION";
  if (!replay.tenant_id || !replay.custody_id || !replay.isolation_id) return "TENANT_ISOLATION_MISMATCH";
  return {
    kind: "enterprise",
    organization_id: replay.organization_id,
    tenant_id: replay.tenant_id,
    actor_id: replay.actor_id,
    role_id: replay.actor_role_id,
    separation_policy_id: requested.separation_policy_id,
    custody_id: replay.custody_id,
    isolation_id: replay.isolation_id,
    custody_evidence_digest: requested.custody_evidence_digest,
    isolation_evidence_digest: requested.isolation_evidence_digest,
    local_owner_substitution: false,
  };
}

export function deriveDecompositionResultEventV1(input: DecompositionResultInputV1): DecompositionResultEventResultV1 {
  let snapshot: DecompositionResultInputV1;
  try { snapshot = structuredClone(input); } catch { return { ok: false, code: "DECOMPOSITION_RESULT_HISTORY_INVALID" }; }
  const review = sourceHead(snapshot.review_history), approval = sourceHead(snapshot.approval_history);
  if (review === null || approval === null || review.history_id !== snapshot.review_history_id || approval.history_id !== snapshot.approval_history_id) return { ok: false, code: "DECOMPOSITION_RESULT_HISTORY_INVALID" };
  const reconstructed = reconstructDecompositionApprovalAuthorityV1(snapshot.review_history_id, snapshot.review_history, snapshot.approval_history_id, snapshot.approval_history);
  if (!reconstructed.ok) return { ok: false, code: reconstructed.code === "TRACK_AUTHORITY_SUBSTITUTION" ? "TRACK_AUTHORITY_SUBSTITUTION" : "DECOMPOSITION_RESULT_HISTORY_INVALID" };
  if (reconstructed.projection.publication === null || reconstructed.projection.ticket === null) return { ok: false, code: "DECOMPOSITION_RESULT_HISTORY_INVALID" };
  const publication = reconstructed.projection.publication, ticket = reconstructed.projection.ticket;
  if (ticket.track !== snapshot.activation.authority.kind) return { ok: false, code: "TRACK_AUTHORITY_SUBSTITUTION" };
  if (snapshot.activation.expected_generation !== publication.generation || snapshot.activation.approved_generation.generation !== publication.generation || snapshot.activation.approved_generation.publication_receipt_digest !== publication.receipt_digest || snapshot.activation.approved_generation.remote_readback_commit !== publication.remote_commit || !snapshot.activation.approved_generation.remote_ref_matched || snapshot.activation.selected_ticket_id !== ticket.ticket_id) return { ok: false, code: "DECOMPOSITION_RESULT_SUBJECT_MISMATCH" };
  const activated = activateTicketResearch(snapshot.activation);
  if (!activated.advanced || activated.receipt === null) return { ok: false, code: activated.code === "TRACK_AUTHORITY_SUBSTITUTION" ? "TRACK_AUTHORITY_SUBSTITUTION" : "DECOMPOSITION_RESULT_SUBJECT_MISMATCH" };
  const boundAuthority = authority(snapshot);
  if (typeof boundAuthority === "string") return { ok: false, code: boundAuthority as Exclude<DecompositionResultEventCodeV1, "DECOMPOSITION_RESULT_RECORDED"> };
  const body = {
    schema: "keep.decomposition-result-event" as const,
    schema_version: 1 as const,
    status: "DECOMPOSITION_RESULT_RECORDED" as const,
    source_heads: { review, approval },
    generation: publication.generation,
    publication_receipt_digest: publication.receipt_digest,
    remote_readback_commit: publication.remote_commit,
    product_commit: publication.product_commit,
    active_ticket_id: ticket.ticket_id,
    track: ticket.track,
    authority: boundAuthority,
    research_receipt_digest: activated.receipt.receipt_digest,
    lifecycle_authoritative: false as const,
    effects_performed: false as const,
  };
  return { ok: true, code: "DECOMPOSITION_RESULT_RECORDED", event: freeze({ ...body, event_digest: digest(body) }) };
}

export function isDecompositionResultEventV1(value: unknown): value is DecompositionResultEventV1 {
  if (!object(value) || !exact(value, ["active_ticket_id", "authority", "effects_performed", "event_digest", "generation", "lifecycle_authoritative", "product_commit", "publication_receipt_digest", "remote_readback_commit", "research_receipt_digest", "schema", "schema_version", "source_heads", "status", "track"])) return false;
  if (value.schema !== "keep.decomposition-result-event" || value.schema_version !== 1 || value.status !== "DECOMPOSITION_RESULT_RECORDED" || !object(value.source_heads) || !exact(value.source_heads, ["approval", "review"]) || !GENERATION.test(String(value.generation)) || !HEX.test(String(value.publication_receipt_digest)) || !GIT_OID.test(String(value.remote_readback_commit)) || !GIT_OID.test(String(value.product_commit)) || !isTicketResearchIdV1(value.active_ticket_id) || !["n1", "enterprise"].includes(String(value.track)) || !HEX.test(String(value.research_receipt_digest)) || value.lifecycle_authoritative !== false || value.effects_performed !== false || !HEX.test(String(value.event_digest))) return false;
  for (const head of [value.source_heads.review, value.source_heads.approval]) if (!object(head) || !exact(head, ["event_count", "final_event_id", "final_head_id", "final_sequence", "history_id", "state_digest"]) || typeof head.history_id !== "string" || !Number.isSafeInteger(head.event_count) || !Number.isSafeInteger(head.final_sequence) || !HEX.test(String(head.final_event_id)) || !HEX.test(String(head.final_head_id)) || !HEX.test(String(head.state_digest))) return false;
  if (!object(value.authority) || value.authority.kind !== value.track) return false;
  const body = Object.fromEntries(Object.entries(value).filter(([key]) => key !== "event_digest"));
  return value.event_digest === digest(body);
}

export function verifyDecompositionResultEventV1(input: DecompositionResultInputV1, event: unknown): DecompositionResultEventResultV1 {
  const expected = deriveDecompositionResultEventV1(input);
  if (!expected.ok) return expected;
  const recognizableEvent = object(event) && event.schema === "keep.decomposition-result-event";
  if (recognizableEvent && (event.track !== expected.event.track || (object(event.authority) && event.authority.kind !== expected.event.authority.kind))) return { ok: false, code: "TRACK_AUTHORITY_SUBSTITUTION" };
  if (recognizableEvent && expected.event.authority.kind === "enterprise" && object(event.authority) && event.authority.kind === "enterprise" && (event.authority.tenant_id !== expected.event.authority.tenant_id || event.authority.custody_id !== expected.event.authority.custody_id || event.authority.isolation_id !== expected.event.authority.isolation_id)) return { ok: false, code: "TENANT_ISOLATION_MISMATCH" };
  if (!isDecompositionResultEventV1(event)) return { ok: false, code: "LEGACY_AUTHORITY_GAP" };
  if (expected.event.event_digest !== event.event_digest || canonical(expected.event) !== canonical(event)) {
    if (expected.event.track !== event.track || expected.event.authority.kind !== event.authority.kind) return { ok: false, code: "TRACK_AUTHORITY_SUBSTITUTION" };
    if (expected.event.authority.kind === "enterprise" && event.authority.kind === "enterprise" && (expected.event.authority.tenant_id !== event.authority.tenant_id || expected.event.authority.custody_id !== event.authority.custody_id || expected.event.authority.isolation_id !== event.authority.isolation_id)) return { ok: false, code: "TENANT_ISOLATION_MISMATCH" };
    return { ok: false, code: "DECOMPOSITION_RESULT_SUBJECT_MISMATCH" };
  }
  return expected;
}

export function rejectLegacyDecompositionReceiptV1(): { readonly ok: false; readonly code: "LEGACY_AUTHORITY_GAP" } {
  return { ok: false, code: "LEGACY_AUTHORITY_GAP" };
}
