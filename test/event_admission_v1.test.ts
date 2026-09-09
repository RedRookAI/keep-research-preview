import { test } from "node:test";
import assert from "node:assert/strict";

import { eirDigest } from "../src/eir/canonical.js";
import {
  EventAdmissionV1Admit,
  EventAdmissionV1HeadDigestDomain,
  type EventAdmissionV1LineageRecord,
} from "../src/spine/event_admission_v1.js";
import { EventEnvelopeV1CodecIdentity, EventEnvelopeV1Encode, EventEnvelopeV1Schema, type EventEnvelopeV1Value } from "../src/spine/event_envelope_v1.js";

const eventId = (value: EventEnvelopeV1Value): string => {
  const result = EventEnvelopeV1Encode(value);
  if (!result.ok) assert.fail(result.code);
  return result.event_digest;
};

const headId = (history_id: string, sequence: bigint, event_id: string, predecessor_head_id: string | null): string =>
  eirDigest(EventAdmissionV1HeadDigestDomain, { history_id, sequence, event_id, predecessor_head_id });

const envelope = (overrides: Partial<EventEnvelopeV1Value> = {}): EventEnvelopeV1Value => ({
  schema: EventEnvelopeV1Schema,
  schema_version: 1n,
  codec: EventEnvelopeV1CodecIdentity,
  codec_version: 1n,
  history_id: "history-local",
  sequence: 1n,
  predecessor_event_id: "0".repeat(64),
  predecessor_head_id: "1".repeat(64),
  event_type: "goal.admitted",
  actor_id: "owner-1",
  authority_domain: "local-owner",
  track: "n1",
  payload: { goal: "build Keep correctly" },
  effect_correlation: null,
  ...overrides,
});

const lineage = (history = "history-local"): readonly EventAdmissionV1LineageRecord[] => {
  const firstEvent = eventId(envelope({ history_id: history, sequence: 0n, predecessor_event_id: null, predecessor_head_id: null }));
  return [{ sequence: 0n, event_id: firstEvent, predecessor_event_id: null, predecessor_head_id: null, head_id: headId(history, 0n, firstEvent, null) }];
};

const twoRecordLineage = (history = "history-local"): readonly EventAdmissionV1LineageRecord[] => {
  const first = lineage(history)[0]!;
  const secondValue = envelope({ history_id: history, sequence: 1n, predecessor_event_id: first.event_id, predecessor_head_id: first.head_id });
  const secondEvent = eventId(secondValue);
  return [first, { sequence: 1n, event_id: secondEvent, predecessor_event_id: first.event_id, predecessor_head_id: first.head_id, head_id: headId(history, 1n, secondEvent, first.head_id) }];
};

const n1Context = () => {
  const committed_lineage = lineage();
  const tail = committed_lineage[0]!;
  return {
    kind: "n1" as const,
    track: "n1" as const,
    history_id: "history-local",
    actor_id: "owner-1",
    authority_domain: "local-owner",
    custody_id: "local-custody-1",
    committed_lineage,
    witnessed_head: { sequence: tail.sequence, event_id: tail.event_id, head_id: tail.head_id },
  };
};

const enterpriseContext = () => {
  const history_id = "tenant-acme/history-1";
  const committed_lineage = lineage(history_id);
  const tail = committed_lineage[0]!;
  return {
    kind: "enterprise" as const,
    track: "enterprise" as const,
    history_id,
    actor_id: "org-actor-1",
    authority_domain: "org-acme/tenant-acme",
    custody_id: "hsm-custody-1",
    organization_id: "org-acme",
    tenant_id: "tenant-acme",
    actor_role_id: "release-engineer",
    isolation_id: "isolation-acme",
    committed_lineage,
    witnessed_head: { sequence: tail.sequence, event_id: tail.event_id, head_id: tail.head_id },
  };
};

const proposalFor = (context: ReturnType<typeof n1Context> | ReturnType<typeof enterpriseContext>, overrides: Partial<EventEnvelopeV1Value> = {}) => {
  const tail = context.committed_lineage.at(-1)!;
  return envelope({
    history_id: context.history_id,
    sequence: tail.sequence + 1n,
    predecessor_event_id: tail.event_id,
    predecessor_head_id: tail.head_id,
    actor_id: context.actor_id,
    authority_domain: context.authority_domain,
    track: context.track,
    ...overrides,
  });
};

test("PG-05-T002-FC01 admits an exact-next local-owner identity", () => {
  const context = n1Context();
  const proposal = proposalFor(context);
  const result = EventAdmissionV1Admit(proposal, context);
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.admission.event_id, eventId(proposal));
  assert.equal(result.admission.next_head_id, headId(context.history_id, 1n, result.admission.event_id, context.committed_lineage[0]!.head_id));
  assert.deepEqual(result.admission.authority, { kind: "n1", track: "n1", actor_id: "owner-1", authority_domain: "local-owner", custody_id: "local-custody-1" });
  assert.ok(Object.isFrozen(result.admission));
  assert.ok(Object.isFrozen(result.admission.authority));
});

test("PG-05-T002-FC02 admits and retains attributed enterprise scope", () => {
  const context = enterpriseContext();
  const result = EventAdmissionV1Admit(proposalFor(context), context);
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.deepEqual(result.admission.authority, {
    kind: "enterprise", track: "enterprise", actor_id: "org-actor-1", authority_domain: "org-acme/tenant-acme",
    custody_id: "hsm-custody-1", organization_id: "org-acme", tenant_id: "tenant-acme",
    actor_role_id: "release-engineer", isolation_id: "isolation-acme",
  });
});

test("PG-05-T002-FC03 candidate actor cannot mint actor authority", () => {
  const context = n1Context();
  assert.deepEqual(EventAdmissionV1Admit(proposalFor(context, { actor_id: "attacker" }), context), { ok: false, code: "ACTOR_AUTHORITY_MISMATCH" });
});

test("PG-05-T002-FC04 n1 and enterprise authority cannot substitute", () => {
  const local = n1Context();
  assert.deepEqual(EventAdmissionV1Admit(proposalFor(local, { track: "enterprise" }), local), { ok: false, code: "TRACK_AUTHORITY_SUBSTITUTION" });
  const enterprise = enterpriseContext();
  assert.deepEqual(EventAdmissionV1Admit(proposalFor(enterprise, { track: "n1" }), enterprise), { ok: false, code: "TRACK_AUTHORITY_SUBSTITUTION" });
  assert.deepEqual(EventAdmissionV1Admit(proposalFor(enterprise, { authority_domain: "local-owner" }), enterprise), { ok: false, code: "TRACK_AUTHORITY_SUBSTITUTION" });
});

test("PG-05-T002-FC05 duplicate and gap refuse", () => {
  const context = n1Context();
  assert.deepEqual(EventAdmissionV1Admit(proposalFor(context, { sequence: 0n, predecessor_event_id: null, predecessor_head_id: null }), context), { ok: false, code: "EVENT_SEQUENCE_MISMATCH" });
  assert.deepEqual(EventAdmissionV1Admit(proposalFor(context, { sequence: 2n }), context), { ok: false, code: "EVENT_SEQUENCE_MISMATCH" });
});

test("PG-05-T002-FC06 predecessor and witnessed-head mismatch refuse", () => {
  const context = n1Context();
  assert.deepEqual(EventAdmissionV1Admit(proposalFor(context, { predecessor_event_id: "a".repeat(64) }), context), { ok: false, code: "EVENT_PREDECESSOR_MISMATCH", failed_at: 0n });
  assert.deepEqual(EventAdmissionV1Admit(proposalFor(context, { predecessor_head_id: "b".repeat(64) }), context), { ok: false, code: "EVENT_PREDECESSOR_MISMATCH", failed_at: 0n });
  const forkedWitness = { ...context, witnessed_head: { ...context.witnessed_head!, head_id: "c".repeat(64) } };
  assert.deepEqual(EventAdmissionV1Admit(proposalFor(context), forkedWitness), { ok: false, code: "EVENT_PREDECESSOR_MISMATCH", failed_at: 0n });
  const emptyWithWitness = { ...context, committed_lineage: [] };
  assert.deepEqual(EventAdmissionV1Admit(envelope({ sequence: 0n, predecessor_event_id: null, predecessor_head_id: null }), emptyWithWitness), { ok: false, code: "EVENT_PREDECESSOR_MISMATCH", failed_at: null });
});

test("PG-05-T002-FC07 malformed proposal wins before authority mismatch", () => {
  const context = { ...n1Context(), actor_id: "different", track: "enterprise" };
  const proposal = { ...proposalFor(n1Context()), extra: "malformed" };
  assert.deepEqual(EventAdmissionV1Admit(proposal, context), { ok: false, code: "EVENT_PROPOSAL_INVALID", upstream_code: "EVENT_ENVELOPE_FIELDS_INVALID" });
});

test("PG-05-T002-FC08 edited or reordered first record fails at array index zero", () => {
  const context = n1Context();
  const edited = { ...context, committed_lineage: [{ ...context.committed_lineage[0]!, event_id: "d".repeat(64) }] };
  assert.deepEqual(EventAdmissionV1Admit(proposalFor(context), edited), { ok: false, code: "EVENT_PREDECESSOR_MISMATCH", failed_at: 0n });
  const first = context.committed_lineage[0]!;
  const secondEvent = eventId(proposalFor(context));
  const second = { sequence: 1n, event_id: secondEvent, predecessor_event_id: first.event_id, predecessor_head_id: first.head_id, head_id: headId(context.history_id, 1n, secondEvent, first.head_id) };
  const reordered = { ...context, committed_lineage: [second, first] };
  assert.deepEqual(EventAdmissionV1Admit(proposalFor(context), reordered), { ok: false, code: "EVENT_PREDECESSOR_MISMATCH", failed_at: 0n });
});

test("PG-05-T002 hostile structures and projections cannot become authority", () => {
  const context = n1Context();
  assert.deepEqual(EventAdmissionV1Admit(proposalFor(context), new Proxy(context, {})), { ok: false, code: "TRUSTED_CONTEXT_INVALID" });
  const accessor = { ...context }; Object.defineProperty(accessor, "actor_id", { enumerable: true, get: () => "owner-1" });
  assert.deepEqual(EventAdmissionV1Admit(proposalFor(context), accessor), { ok: false, code: "TRUSTED_CONTEXT_INVALID" });
  assert.deepEqual(EventAdmissionV1Admit(proposalFor(context), { ...context, mutable_projection_status: "approved" }), { ok: false, code: "TRUSTED_CONTEXT_INVALID" });
  assert.deepEqual(EventAdmissionV1Admit(proposalFor(context), { ...context, committed_lineage: [, ...context.committed_lineage] }), { ok: false, code: "TRUSTED_CONTEXT_INVALID" });
});

test("PG-05-T002 controls: multi-record lineage and terminal witness use the final index", () => {
  const base = n1Context();
  const committed_lineage = twoRecordLineage();
  const tail = committed_lineage[1]!;
  const context = { ...base, committed_lineage, witnessed_head: { sequence: tail.sequence, event_id: tail.event_id, head_id: tail.head_id } };
  const proposal = proposalFor(context);
  const accepted = EventAdmissionV1Admit(proposal, context);
  assert.equal(accepted.ok, true);
  if (accepted.ok) assert.equal(accepted.admission.sequence, 2n);
  const forged = { ...context, witnessed_head: { ...context.witnessed_head, head_id: "f".repeat(64) } };
  assert.deepEqual(EventAdmissionV1Admit(proposal, forged), { ok: false, code: "EVENT_PREDECESSOR_MISMATCH", failed_at: 1n });
});

test("PG-05-T002 controls: genesis admits only with empty lineage and null witness", () => {
  const context = { ...n1Context(), committed_lineage: [], witnessed_head: null };
  const proposal = envelope({ sequence: 0n, predecessor_event_id: null, predecessor_head_id: null });
  const result = EventAdmissionV1Admit(proposal, context);
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.admission.sequence, 0n);
    assert.equal(result.admission.predecessor_event_id, null);
    assert.equal(result.admission.predecessor_head_id, null);
  }
  const nonemptyWithoutWitness = { ...n1Context(), witnessed_head: null };
  assert.deepEqual(EventAdmissionV1Admit(proposalFor(n1Context()), nonemptyWithoutWitness), { ok: false, code: "TRUSTED_CONTEXT_INVALID" });
});

test("PG-05-T002 controls: admission never mutates proposal or trusted context", () => {
  const context = n1Context();
  const proposal = proposalFor(context);
  const beforeProposal = structuredClone(proposal);
  const beforeContext = structuredClone(context);
  assert.equal(EventAdmissionV1Admit(proposal, context).ok, true);
  assert.deepEqual(proposal, beforeProposal);
  assert.deepEqual(context, beforeContext);
});
