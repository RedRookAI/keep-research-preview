import type { ProjectState } from "../autonomy/project_state.js";
import {
  decomposeProjectPlan,
  type ProjectDecompositionArtifact,
} from "../autonomy/decomposition_stage.js";
import { decodeCanonical, eirDigest } from "../eir/canonical.js";
import type {
  AuthoritativeReplayV1Event,
  AuthoritativeReplayV1Result,
} from "../spine/authoritative_replay_v1.js";
import { EventAdmissionV1HeadDigestDomain } from "../spine/event_admission_v1.js";
import { EventEnvelopeV1Encode } from "../spine/event_envelope_v1.js";
import {
  advanceDecompositionReview,
  initialDecompositionReviewState,
  type DecompositionReviewActionV1,
  type DecompositionReviewResultV1,
  type DecompositionReviewStateV1,
  type TrustedCandidateScopeV1,
  type TrustedReviewerContextV1,
} from "./decomposition_review.js";
import {
  DECOMPOSITION_TRANSITION_PHASES,
  evaluateDecompositionTransition,
  type DecompositionTransitionAuthorityV1,
  type DecompositionTransitionProposalV1,
  type DecompositionTransitionResultV1,
  type DecompositionTransitionStateV1,
} from "./decomposition_transition.js";

export type DecompositionEventAuthorityCodeV1 =
  | "DECOMPOSITION_EVENT_AUTHORITY_REQUIRED"
  | "DECOMPOSITION_HISTORY_INVALID"
  | "INCOMPLETE_DECOMPOSITION_HISTORY"
  | "TRACK_AUTHORITY_SUBSTITUTION"
  | "REVIEWER_AUTHORITY_MISMATCH"
  | "THIRD_VET_REQUIRES_OWNER"
  | "LEGACY_DECOMPOSITION_MUTATION_REJECTED"
  | "LEGACY_AUTHORITY_GAP";
export const DECOMPOSITION_EVENT_MIGRATED_WRITERS_V1 = Object.freeze([
  "W04",
  "W05",
  "W06",
] as const);
export type DecompositionEventAuthorityContextV1 =
  | {
      readonly kind: "n1";
      readonly principal_id: string;
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
      readonly local_owner_substitution: false;
    };

export type DecompositionAuthorityEventV1 =
  | {
      readonly schema: "keep.decomposition-authority-event";
      readonly schema_version: 1;
      readonly run_id: string;
      readonly operation: "candidate-created";
      readonly authority_context: DecompositionEventAuthorityContextV1;
      readonly project_state: ProjectState;
      readonly artifact: ProjectDecompositionArtifact;
    }
  | {
      readonly schema: "keep.decomposition-authority-event";
      readonly schema_version: 1;
      readonly run_id: string;
      readonly operation: "transition-applied";
      readonly authority_context: DecompositionEventAuthorityContextV1;
      readonly state: DecompositionTransitionStateV1;
      readonly proposal: DecompositionTransitionProposalV1;
      readonly authority: DecompositionTransitionAuthorityV1;
      readonly result: DecompositionTransitionResultV1;
    }
  | {
      readonly schema: "keep.decomposition-authority-event";
      readonly schema_version: 1;
      readonly run_id: string;
      readonly operation: "review-action-applied";
      readonly authority_context: DecompositionEventAuthorityContextV1;
      readonly state: DecompositionReviewStateV1;
      readonly action: DecompositionReviewActionV1;
      readonly reviewer: TrustedReviewerContextV1;
      readonly scope: TrustedCandidateScopeV1;
      readonly result: DecompositionReviewResultV1;
    };

export interface DecompositionAuthorityReplayBundleV1 {
  readonly events: readonly AuthoritativeReplayV1Event[];
  readonly replay: AuthoritativeReplayV1Result;
}
export interface DecompositionAuthorityEventPortV1 {
  load(historyId: string): Promise<DecompositionAuthorityReplayBundleV1 | null>;
  appendAndReplay(
    historyId: string,
    event: DecompositionAuthorityEventV1,
  ): Promise<DecompositionAuthorityReplayBundleV1>;
}
export interface DecompositionAuthorityProjectionV1 {
  readonly candidate: ProjectDecompositionArtifact | null;
  readonly transition: DecompositionTransitionStateV1 | null;
  readonly review: DecompositionReviewStateV1 | null;
  readonly review_scope: TrustedCandidateScopeV1 | null;
  readonly event_count: number;
}
export type DecompositionAuthorityReconstructionV1 =
  | {
      readonly ok: true;
      readonly projection: DecompositionAuthorityProjectionV1;
    }
  | { readonly ok: false; readonly code: DecompositionEventAuthorityCodeV1 };

const plain = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);
const stable = (v: unknown): unknown =>
  Array.isArray(v)
    ? v.map(stable)
    : plain(v)
      ? Object.fromEntries(
          Object.keys(v)
            .sort()
            .map((k) => [k, stable(v[k])]),
        )
      : v;
const equal = (a: unknown, b: unknown) =>
  JSON.stringify(stable(a)) === JSON.stringify(stable(b));
const clone = <T>(v: T): T => structuredClone(v);
function decode(
  row: AuthoritativeReplayV1Event,
): DecompositionAuthorityEventV1 | null {
  const encoded = EventEnvelopeV1Encode(row.proposal);
  if (!encoded.ok) return null;
  try {
    const envelope = decodeCanonical(encoded.canonical_bytes) as Record<
      string,
      unknown
    >;
    if (
      ![
        "decomposition.proposed",
        "decomposition.transitioned",
        "decomposition.reviewed",
      ].includes(String(envelope.event_type))
    )
      return null;
    const payload = envelope.payload;
    if (
      !plain(payload) ||
      Object.keys(payload).join(",") !== "domain_json" ||
      typeof payload.domain_json !== "string"
    )
      return null;
    const event = JSON.parse(payload.domain_json) as unknown;
    if (
      !plain(event) ||
      event.schema !== "keep.decomposition-authority-event" ||
      event.schema_version !== 1 ||
      typeof event.run_id !== "string" ||
      ![
        "candidate-created",
        "transition-applied",
        "review-action-applied",
      ].includes(String(event.operation)) ||
      !plain(event.authority_context)
    )
      return null;
    return event as DecompositionAuthorityEventV1;
  } catch {
    return null;
  }
}
function matchesTrack(
  context: DecompositionEventAuthorityContextV1,
  replay: Extract<AuthoritativeReplayV1Result, { ok: true }>,
): boolean {
  const a = replay.receipt.authority;
  return context.kind === "n1"
    ? a.kind === "n1" &&
        a.actor_id === context.principal_id &&
        a.authority_domain === "local-owner" &&
        a.custody_id === context.custody_id
    : a.kind === "enterprise" &&
        a.actor_id === context.actor_id &&
        a.authority_domain === "organization" &&
        a.organization_id === context.organization_id &&
        a.tenant_id === context.tenant_id &&
        a.actor_role_id === context.role_id &&
        a.isolation_id === context.isolation_id &&
        a.custody_id === context.custody_id;
}
function bundleBound(
  id: string,
  b: DecompositionAuthorityReplayBundleV1,
  r: Extract<AuthoritativeReplayV1Result, { ok: true }>,
): boolean {
  let pe: string | null = null,
    ph: string | null = null;
  for (let i = 0; i < b.events.length; i++) {
    const e = EventEnvelopeV1Encode(b.events[i]!.proposal);
    if (!e.ok) return false;
    const value = decodeCanonical(e.canonical_bytes) as Record<string, unknown>;
    if (
      value.history_id !== id ||
      value.sequence !== BigInt(i) ||
      value.predecessor_event_id !== pe ||
      value.predecessor_head_id !== ph
    )
      return false;
    ph = eirDigest(EventAdmissionV1HeadDigestDomain, {
      history_id: id,
      sequence: BigInt(i),
      event_id: e.event_digest,
      predecessor_head_id: ph,
    });
    pe = e.event_digest;
  }
  return (
    b.events.length > 0 &&
    r.receipt.event_count === BigInt(b.events.length) &&
    r.receipt.final_sequence === BigInt(b.events.length - 1) &&
    r.receipt.final_event_id === pe &&
    r.receipt.final_head_id === ph
  );
}
function reviewerBound(
  event: Extract<
    DecompositionAuthorityEventV1,
    { operation: "review-action-applied" }
  >,
): boolean {
  const c = event.authority_context,
    r = event.reviewer;
  if (c.kind === "n1") return r.kind === "n1" && r.custody_id === c.custody_id;
  return (
    r.kind === "enterprise" &&
    r.organization_id === c.organization_id &&
    r.actor_id === r.reviewer_id &&
    r.separation_policy_id === c.separation_policy_id &&
    r.custody_evidence_digest.length === 64 &&
    r.isolation_evidence_digest.length === 64
  );
}

export function reconstructDecompositionAuthorityV1(
  id: string,
  bundle: DecompositionAuthorityReplayBundleV1 | null,
): DecompositionAuthorityReconstructionV1 {
  if (bundle === null)
    return {
      ok: true,
      projection: {
        candidate: null,
        transition: null,
        review: null,
        review_scope: null,
        event_count: 0,
      },
    };
  if (!bundle.replay.ok)
    return {
      ok: false,
      code:
        bundle.replay.code === "TRACK_AUTHORITY_SUBSTITUTION"
          ? "TRACK_AUTHORITY_SUBSTITUTION"
          : "DECOMPOSITION_HISTORY_INVALID",
    };
  if (
    bundle.replay.receipt.history_id !== id ||
    !bundleBound(id, bundle, bundle.replay)
  )
    return { ok: false, code: "DECOMPOSITION_HISTORY_INVALID" };
  let candidate: ProjectDecompositionArtifact | null = null,
    transition: DecompositionTransitionStateV1 | null = null,
    review: DecompositionReviewStateV1 | null = null,
    reviewScope: TrustedCandidateScopeV1 | null = null,
    context: DecompositionEventAuthorityContextV1 | null = null;
  for (let i = 0; i < bundle.events.length; i++) {
    const event = decode(bundle.events[i]!);
    if (event === null || event.run_id !== id)
      return { ok: false, code: "DECOMPOSITION_HISTORY_INVALID" };
    if (context === null) context = event.authority_context;
    else if (!equal(context, event.authority_context))
      return { ok: false, code: "TRACK_AUTHORITY_SUBSTITUTION" };
    if (!matchesTrack(event.authority_context, bundle.replay))
      return { ok: false, code: "TRACK_AUTHORITY_SUBSTITUTION" };
    if (event.operation === "candidate-created") {
      if (i !== 0 || candidate !== null)
        return { ok: false, code: "LEGACY_AUTHORITY_GAP" };
      let actual: ProjectDecompositionArtifact;
      try {
        actual = decomposeProjectPlan(event.project_state);
      } catch {
        return { ok: false, code: "INCOMPLETE_DECOMPOSITION_HISTORY" };
      }
      if (!equal(actual, event.artifact))
        return { ok: false, code: "INCOMPLETE_DECOMPOSITION_HISTORY" };
      candidate = clone(actual);
      continue;
    }
    if (candidate === null) return { ok: false, code: "LEGACY_AUTHORITY_GAP" };
    if (event.operation === "transition-applied") {
      if (
        review !== null &&
        !(
          (event.proposal.to_phase === "DECOMPOSITION_VET_1_PASS" &&
            review.phase === "VET_1_PASS") ||
          (event.proposal.to_phase === "DECOMPOSITION_VET_2" &&
            review.phase === "VET_1_PASS") ||
          (event.proposal.to_phase === "DECOMPOSITION_VET_2_PASS" &&
            review.phase === "COMPLETE")
        )
      )
        return { ok: false, code: "INCOMPLETE_DECOMPOSITION_HISTORY" };
      if (
        transition === null
          ? event.state.phase !== "ARCHITECTURE_AUTHORIZED"
          : !equal(event.state, transition)
      )
        return { ok: false, code: "INCOMPLETE_DECOMPOSITION_HISTORY" };
      if (
        DECOMPOSITION_TRANSITION_PHASES.indexOf(event.proposal.to_phase) >
        DECOMPOSITION_TRANSITION_PHASES.indexOf("DECOMPOSITION_VET_2_PASS")
      )
        return { ok: false, code: "LEGACY_AUTHORITY_GAP" };
      const actual = evaluateDecompositionTransition(
        event.state,
        event.proposal,
        event.authority,
      );
      if (!equal(actual, event.result))
        return { ok: false, code: "INCOMPLETE_DECOMPOSITION_HISTORY" };
      if (actual.advanced) transition = clone(actual.state);
      continue;
    }
    if (!reviewerBound(event))
      return { ok: false, code: "REVIEWER_AUTHORITY_MISMATCH" };
    if (reviewScope !== null && !equal(reviewScope, event.scope))
      return { ok: false, code: "INCOMPLETE_DECOMPOSITION_HISTORY" };
    let expectedReview: DecompositionReviewStateV1;
    try {
      expectedReview = review ?? initialDecompositionReviewState(event.scope);
    } catch {
      return { ok: false, code: "INCOMPLETE_DECOMPOSITION_HISTORY" };
    }
    if (!equal(event.state, expectedReview))
      return { ok: false, code: "INCOMPLETE_DECOMPOSITION_HISTORY" };
    const round =
      transition?.phase === "DECOMPOSITION_VET_2" ||
      event.state.phase.startsWith("VET_2") || event.state.phase === "COMPLETE"
        ? 2
        : 1;
    if (
      transition === null ||
      transition.phase !==
        (round === 1 ? "DECOMPOSITION_VET_1" : "DECOMPOSITION_VET_2")
    )
      return { ok: false, code: "INCOMPLETE_DECOMPOSITION_HISTORY" };
    const actual = advanceDecompositionReview(
      event.state,
      event.action,
      event.reviewer,
      event.scope,
    );
    if (!equal(actual, event.result))
      return { ok: false, code: "INCOMPLETE_DECOMPOSITION_HISTORY" };
    if (actual.code === "THIRD_VET_REQUIRES_OWNER")
      return { ok: false, code: "THIRD_VET_REQUIRES_OWNER" };
    if (actual.code === "VET_RECEIPT_INVALID")
      return { ok: false, code: "REVIEWER_AUTHORITY_MISMATCH" };
    if (actual.advanced) {
      review = clone(actual.state);
      reviewScope ??= clone(event.scope);
    }
  }
  return {
    ok: true,
    projection: {
      candidate,
      transition,
      review,
      review_scope: reviewScope,
      event_count: bundle.events.length,
    },
  };
}

export function candidateCreatedEventV1(
  runId: string,
  state: ProjectState,
  context: DecompositionEventAuthorityContextV1,
): DecompositionAuthorityEventV1 {
  return {
    schema: "keep.decomposition-authority-event",
    schema_version: 1,
    run_id: runId,
    operation: "candidate-created",
    authority_context: clone(context),
    project_state: clone(state),
    artifact: decomposeProjectPlan(state),
  };
}
export function rejectLegacyDecompositionMutationV1(): {
  readonly ok: false;
  readonly code: "LEGACY_DECOMPOSITION_MUTATION_REJECTED";
} {
  return { ok: false, code: "LEGACY_DECOMPOSITION_MUTATION_REJECTED" };
}
