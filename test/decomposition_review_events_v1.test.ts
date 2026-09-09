import assert from "node:assert/strict";
import test from "node:test";

import { createProjectPlan } from "../src/autonomy/plan_stage.js";
import { vetProjectPlan } from "../src/autonomy/plan_gate_stage.js";
import { captureProjectIntent } from "../src/autonomy/understand_stage.js";
import { buildDecompositionStageExecutor } from "../src/autonomy/decomposition_stage.js";
import {
  PROJECT_STATE_SCHEMA_VERSION,
  type ProjectState,
} from "../src/autonomy/project_state.js";
import {
  candidateCreatedEventV1,
  DECOMPOSITION_EVENT_MIGRATED_WRITERS_V1,
  reconstructDecompositionAuthorityV1,
  rejectLegacyDecompositionMutationV1,
  type DecompositionAuthorityEventV1,
  type DecompositionAuthorityReplayBundleV1,
  type DecompositionEventAuthorityContextV1,
} from "../src/decomposition/decomposition_review_events_v1.js";
import {
  evaluateDecompositionTransition,
  type DecompositionTransitionAuthorityV1,
  type DecompositionTransitionProposalV1,
  type DecompositionTransitionStateV1,
} from "../src/decomposition/decomposition_transition.js";
import type {
  AuthoritativeReplayV1Event,
  AuthoritativeReplayV1Result,
} from "../src/spine/authoritative_replay_v1.js";
import { eirDigest } from "../src/eir/canonical.js";
import { EventAdmissionV1HeadDigestDomain } from "../src/spine/event_admission_v1.js";
import {
  EventEnvelopeV1CodecIdentity,
  EventEnvelopeV1Encode,
  EventEnvelopeV1Schema,
  type EventEnvelopeV1Value,
} from "../src/spine/event_envelope_v1.js";
import { advanceDecompositionReview, initialDecompositionReviewState } from "../src/decomposition/decomposition_review.js";
import { attest, n1 as n1Reviewer, scope as reviewScope } from "./decomposition_review.test.js";

const H = (c: string) => c.repeat(64).slice(0, 64),
  G = (c: string) => `sha256:${H(c)}`;
function project(runId = "decomp"): ProjectState {
  const goal = "implement deterministic parser recovery",
    base: ProjectState = {
      schemaVersion: PROJECT_STATE_SCHEMA_VERSION,
      revision: 0,
      runId,
      goal,
      stage: "plan",
      stepsRemaining: 5,
      reworkCount: 0,
      status: "running",
      posture: "autonomous",
      retry: { attemptsByStage: {}, attemptsConsumed: 0, runLimit: 8 },
      consumedSignals: [],
      artifacts: {
        understand: captureProjectIntent(goal, {
          shape: "concrete-task",
          confidence: 1,
          via: "rule",
          note: "test",
        }),
        research: { decision: { required: false } },
      },
    };
  const plan = createProjectPlan(base),
    withPlan = {
      ...base,
      stage: "vet_plan" as const,
      artifacts: { ...base.artifacts, plan },
    };
  return {
    ...withPlan,
    stage: "ticket",
    artifacts: { ...withPlan.artifacts, vet_plan: vetProjectPlan(withPlan) },
  };
}
const n1: DecompositionEventAuthorityContextV1 = {
  kind: "n1",
  principal_id: "owner",
  custody_id: "local-custody",
  organization_services: "ABSENT",
};
const enterprise: DecompositionEventAuthorityContextV1 = {
  kind: "enterprise",
  organization_id: "org",
  tenant_id: "tenant",
  actor_id: "alice",
  role_id: "reviewer",
  separation_policy_id: "sod",
  custody_id: "org-custody",
  isolation_id: "isolation",
  local_owner_substitution: false,
};
function bundle(
  id: string,
  events: readonly DecompositionAuthorityEventV1[],
  context: DecompositionEventAuthorityContextV1,
): DecompositionAuthorityReplayBundleV1 {
  let predecessorEvent: string | null = null,
    predecessorHead: string | null = null;
  const rows: AuthoritativeReplayV1Event[] = events.map((event, index) => {
    const proposal: EventEnvelopeV1Value = {
      schema: EventEnvelopeV1Schema,
      schema_version: 1n,
      codec: EventEnvelopeV1CodecIdentity,
      codec_version: 1n,
      history_id: id,
      sequence: BigInt(index),
      predecessor_event_id: predecessorEvent,
      predecessor_head_id: predecessorHead,
      event_type:
        event.operation === "candidate-created"
          ? "decomposition.proposed"
          : event.operation === "transition-applied"
            ? "decomposition.transitioned"
            : "decomposition.reviewed",
      actor_id: context.kind === "n1" ? context.principal_id : context.actor_id,
      authority_domain: context.kind === "n1" ? "local-owner" : "organization",
      track: context.kind,
      payload: { domain_json: JSON.stringify(event) },
      effect_correlation: null,
    };
    const encoded = EventEnvelopeV1Encode(proposal);
    if (!encoded.ok) throw new Error(encoded.code);
    predecessorHead = eirDigest(EventAdmissionV1HeadDigestDomain, {
      history_id: id,
      sequence: BigInt(index),
      event_id: encoded.event_digest,
      predecessor_head_id: predecessorHead,
    });
    predecessorEvent = encoded.event_digest;
    return { proposal, target_version: 1n, interpreter_set_digest: H("c") };
  });
  const authority =
    context.kind === "n1"
      ? {
          kind: "n1" as const,
          track: "n1" as const,
          actor_id: context.principal_id,
          authority_domain: "local-owner",
          custody_id: context.custody_id,
        }
      : {
          kind: "enterprise" as const,
          track: "enterprise" as const,
          actor_id: context.actor_id,
          authority_domain: "organization",
          custody_id: context.custody_id,
          organization_id: context.organization_id,
          tenant_id: context.tenant_id,
          actor_role_id: context.role_id,
          isolation_id: context.isolation_id,
        };
  const replay = {
    ok: true,
    state_bytes: new Uint8Array(),
    result_digest: H("d"),
    receipt: {
      schema: "keep.spine.authoritative-replay-receipt",
      schema_version: 1n,
      history_id: id,
      event_count: BigInt(rows.length),
      final_sequence: BigInt(rows.length - 1),
      final_event_id: predecessorEvent!,
      final_head_id: predecessorHead!,
      witness_id: H("1"),
      checkpoint_digest: H("2"),
      codec: EventEnvelopeV1CodecIdentity,
      codec_version: 1n,
      reducer_identities: [],
      interpreter_set_digests: [],
      state_digest: H("3"),
      authority,
      effects_performed: false,
      projection_authoritative: false,
      closed: true,
    },
  } as AuthoritativeReplayV1Result;
  return { events: rows, replay };
}

class TestPort {
  private readonly events = new Map<string, DecompositionAuthorityEventV1[]>();
  async load(id: string) { const rows = this.events.get(id); return rows === undefined ? null : bundle(id, rows, rows[0]!.authority_context); }
  async appendAndReplay(id: string, event: DecompositionAuthorityEventV1) { const rows = [...(this.events.get(id) ?? []), event]; this.events.set(id, rows); return bundle(id, rows, event.authority_context); }
}

test("PG-05-T011-FC01 exact W04-W06 inventory remains classified", () =>
  assert.deepEqual(DECOMPOSITION_EVENT_MIGRATED_WRITERS_V1, [
    "W04",
    "W05",
    "W06",
  ]));
test("PG-05-T011-FC02 n1 candidate and transition reconstruct only from committed events", () => {
  const id = "n1",
    candidate = candidateCreatedEventV1(id, project(id), n1),
    state: DecompositionTransitionStateV1 = {
      schema_version: 1,
      phase: "ARCHITECTURE_AUTHORIZED",
      approved_graph_digest: H("b"),
      active_generation: G("c"),
      derived_authorities: {
        architecture: {
          digest: H("1"),
          depends_on: ["graph"],
          status: "ACTIVE",
        },
        decomposition: {
          digest: H("2"),
          depends_on: ["architecture"],
          status: "ACTIVE",
        },
        owner_approval: {
          digest: H("3"),
          depends_on: ["decomposition"],
          status: "ACTIVE",
        },
        ticket_activation: {
          digest: H("4"),
          depends_on: ["owner_approval"],
          status: "ACTIVE",
        },
      },
    },
    authority: DecompositionTransitionAuthorityV1 = {
      schema_version: 1,
      evaluation_mode: "LIVE",
      canonical_writer_id: "writer",
      canonical_writer_generation: G("a"),
    },
    proposal: DecompositionTransitionProposalV1 = {
      schema_version: 1,
      from_phase: "ARCHITECTURE_AUTHORIZED",
      to_phase: "ARCHITECTURE_CANDIDATE",
      writer_id: "writer",
      writer_generation: G("a"),
      observed_graph_digest: H("b"),
      expected_generation: G("c"),
      record_class: "CANONICAL",
      authority_context: n1,
    },
    result = evaluateDecompositionTransition(state, proposal, authority),
    transition: DecompositionAuthorityEventV1 = {
      schema: "keep.decomposition-authority-event",
      schema_version: 1,
      run_id: id,
      operation: "transition-applied",
      authority_context: n1,
      state,
      proposal,
      authority,
      result,
    },
    replayed = reconstructDecompositionAuthorityV1(
      id,
      bundle(id, [candidate, transition], n1),
    );
  assert.equal(replayed.ok, true);
  if (replayed.ok) {
    assert.equal(replayed.projection.candidate?.admittedTaskId, "task-01");
    assert.equal(
      replayed.projection.transition?.phase,
      "ARCHITECTURE_CANDIDATE",
    );
  }
});
test("PG-05-T011-FC03 enterprise receipt binds tenant and full authority", () => {
  const id = "enterprise",
    replayed = reconstructDecompositionAuthorityV1(
      id,
      bundle(
        id,
        [candidateCreatedEventV1(id, project(id), enterprise)],
        enterprise,
      ),
    );
  assert.equal(replayed.ok, true);
});
test("PG-05-T011-FC02 a committed W06 review action reconstructs successfully", () => {
  const id = "review-success", candidate = candidateCreatedEventV1(id, project(id), n1);
  let state: DecompositionTransitionStateV1 = { schema_version: 1, phase: "ARCHITECTURE_AUTHORIZED", approved_graph_digest: H("b"), active_generation: G("c"), derived_authorities: { architecture: { digest: H("1"), depends_on: ["graph"], status: "ACTIVE" }, decomposition: { digest: H("2"), depends_on: ["architecture"], status: "ACTIVE" }, owner_approval: { digest: H("3"), depends_on: ["decomposition"], status: "ACTIVE" }, ticket_activation: { digest: H("4"), depends_on: ["owner_approval"], status: "ACTIVE" } } };
  const authority: DecompositionTransitionAuthorityV1 = { schema_version: 1, evaluation_mode: "LIVE", canonical_writer_id: "writer", canonical_writer_generation: G("a") }, events: DecompositionAuthorityEventV1[] = [candidate];
  for (const to of ["ARCHITECTURE_CANDIDATE", "ARCHITECTURE_VALIDATED", "DECOMPOSITION_AUTHORIZED", "DECOMPOSITION_CANDIDATE", "DECOMPOSITION_STRUCTURAL_PASS", "DECOMPOSITION_VET_1"] as const) {
    const proposal: DecompositionTransitionProposalV1 = { schema_version: 1, from_phase: state.phase, to_phase: to, writer_id: "writer", writer_generation: G("a"), observed_graph_digest: H("b"), expected_generation: G("c"), record_class: "CANONICAL", authority_context: n1 }, result = evaluateDecompositionTransition(state, proposal, authority);
    events.push({ schema: "keep.decomposition-authority-event", schema_version: 1, run_id: id, operation: "transition-applied", authority_context: n1, state, proposal, authority, result });
    assert.equal(result.advanced, true); state = result.state!;
  }
  const trusted = reviewScope(), reviewState = initialDecompositionReviewState(trusted), action = attest(reviewState, n1Reviewer), result = advanceDecompositionReview(reviewState, action, n1Reviewer, trusted);
  events.push({ schema: "keep.decomposition-authority-event", schema_version: 1, run_id: id, operation: "review-action-applied", authority_context: n1, state: reviewState, action, reviewer: n1Reviewer, scope: trusted, result });
  const replayed = reconstructDecompositionAuthorityV1(id, bundle(id, events, n1));
  assert.equal(replayed.ok, true, JSON.stringify(replayed)); if (replayed.ok) assert.equal(replayed.projection.review?.phase, "VET_1_OPEN");
});
test("PG-05-T011-FC05 substituted reviewer identity is refused before review authority", () => {
  const id = "reviewer",
    candidate = candidateCreatedEventV1(id, project(id), enterprise),
    event = {
      schema: "keep.decomposition-authority-event",
      schema_version: 1,
      run_id: id,
      operation: "review-action-applied",
      authority_context: enterprise,
      state: {},
      action: {},
      reviewer: {
        schema_version: 1,
        kind: "enterprise",
        organization_id: "org",
        actor_id: "mallory",
        reviewer_id: "substituted-reviewer",
        reviewer_family: "other",
        role_id: "reviewer",
        separation_policy_id: "sod",
        custody_evidence_digest: H("c"),
        isolation_evidence_digest: H("d"),
        local_owner_substitution: false,
      },
      scope: {},
      result: {},
    } as unknown as DecompositionAuthorityEventV1;
  assert.deepEqual(
    reconstructDecompositionAuthorityV1(
      id,
      bundle(id, [candidate, event], enterprise),
    ),
    { ok: false, code: "REVIEWER_AUTHORITY_MISMATCH" },
  );
});
test("PG-05-T011-FC06 forged mutable projection cannot affect replay", () => {
  const id = "projection",
    event = candidateCreatedEventV1(id, project(id), n1) as Extract<
      DecompositionAuthorityEventV1,
      { operation: "candidate-created" }
    >,
    forged = { ...event, artifact: { ...event.artifact, admittedTaskId: "task-99" } };
  assert.deepEqual(reconstructDecompositionAuthorityV1(id, bundle(id, [forged], n1)), { ok: false, code: "INCOMPLETE_DECOMPOSITION_HISTORY" });
});
test("PG-05-T011 receipt authority substitution is refused", () => {
  const id = "track-substitution", event = candidateCreatedEventV1(id, project(id), n1), captured = bundle(id, [event], n1);
  ((captured.replay as Extract<AuthoritativeReplayV1Result, { ok: true }>).receipt as unknown as { authority: unknown }).authority = { kind: "enterprise", track: "enterprise", actor_id: "owner", authority_domain: "organization", custody_id: "local", organization_id: "org", tenant_id: "tenant", actor_role_id: "role", isolation_id: "isolation" };
  assert.deepEqual(reconstructDecompositionAuthorityV1(id, captured), { ok: false, code: "TRACK_AUTHORITY_SUBSTITUTION" });
});
test("PG-05-T011-FC07 legacy mutation guard refuses directly", () =>
  assert.deepEqual(rejectLegacyDecompositionMutationV1(), {
    ok: false,
    code: "LEGACY_DECOMPOSITION_MUTATION_REJECTED",
  }));

test("configured W04 commits and verifies before returning its projection", async () => {
  const result = await buildDecompositionStageExecutor(new TestPort(), () => n1)(project("configured-w04"));
  assert.equal(result.control, "advance");
  assert.equal((result.output as { admittedTaskId: string }).admittedTaskId, "task-01");
  const partial = await buildDecompositionStageExecutor(new TestPort())(project("partial-w04"));
  assert.equal(partial.control, "capability-unavailable");
});
