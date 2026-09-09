import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  YoloTicketCoordinatorV1,
  StaleWorkAttemptError,
  activateTicketResearch,
  type TicketResearchActivationRequestV1,
  type TicketResearchProgressInputV1,
  type WorkAttemptAuthorityV1,
  type WorkAttemptIdentityV1,
  type WorkAttemptReferenceV1,
  type YoloTicketBoundaryFactsV1,
  type YoloTicketCoordinatorInputV1,
  FileWorkAttemptAuthorityV1,
} from "../src/index.js";

const H = (character: string): string => character.repeat(64);
const canonical = (value: unknown): string => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value !== null && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(",")}}` : JSON.stringify(value);
const digest = (value: unknown): string => createHash("sha256").update(canonical(value)).digest("hex");
const body = { id: "SG-01-T003B", title: "Resume the fenced ticket through installed YOLO and honest status", requirements: ["advance one bounded step"], finish_conditions: ["resume exactly"], research_contract: { lanes: ["current", "historical", "cross"] }, mutation_surface: ["coordinator"], scope_rows: ["K-001"], resource_bounds: { peak_ram_mib: 2048, peak_disk_mib: 10240, max_parallel_processes: 3 } };

function authority(track: "n1" | "enterprise"): WorkAttemptAuthorityV1 {
  return track === "n1"
    ? { kind: "n1", owner_id: "owner", custody_id: "local", organization_services: "ABSENT" }
    : { kind: "enterprise", organization_id: "org", tenant_id: "tenant", actor_id: "agent", role_id: "maintainer", separation_policy_id: "sod", custody_id: "org-custody", isolation_id: "iso", custody_evidence_digest: H("c"), isolation_evidence_digest: H("e"), local_owner_substitution: false };
}

function activation(track: "n1" | "enterprise"): TicketResearchActivationRequestV1 {
  const generation = `sha256:${H("a")}`;
  return {
    schema_version: 1,
    approved_generation: {
      generation,
      publication_receipt_digest: H("d"),
      remote_readback_commit: "b".repeat(40),
      remote_ref_matched: true,
      tickets: [
        { ticket_id: "PG-04-T008", track, dependency_ticket_ids: [] },
        { ticket_id: "SG-01-T003B", track, dependency_ticket_ids: ["PG-04-T008"] },
        { ticket_id: "SG-01-T004", track, dependency_ticket_ids: ["SG-01-T003B"] },
      ],
    },
    state: { schema_version: 1, active_generation: generation, active_ticket_id: null, closed_ticket_ids: ["PG-04-T008"] },
    selected_ticket_id: "SG-01-T003B",
    expected_generation: generation,
    authority: track === "n1"
      ? { kind: "n1", owner_id: "owner", custody_id: "local", organization_services: "ABSENT" }
      : { kind: "enterprise", organization_id: "org", actor_id: "agent", role_id: "maintainer", separation_policy_id: "sod", custody_evidence_digest: H("c"), isolation_evidence_digest: H("e"), local_owner_substitution: false },
    implementation_authorized: false,
  };
}

function progress(track: "n1" | "enterprise", closed = ["PG-04-T008"], active: string | null = "SG-01-T003B"): TicketResearchProgressInputV1 {
  const request = activation(track);
  const result = activateTicketResearch(request);
  assert.equal(result.advanced, true);
  assert.notEqual(result.receipt, null);
  return { activation: request, receipt: result.receipt!, current_state: { schema_version: 1, active_generation: request.expected_generation, active_ticket_id: active, closed_ticket_ids: closed } };
}

const ordinaryFacts = (): YoloTicketBoundaryFactsV1 => ({
  requested_scope_ids: ["K-001"], protected_workload_effects: [],
  requested_effects: [{ description: "bounded injected local work", class: "pure-local" }], requested_vet_round: 0,
  resources: { estimated_ram_mib: 64, estimated_disk_mib: 10, estimated_processes: 1 },
});

async function fixture(track: "n1" | "enterprise" = "n1", ticketBody: Readonly<Record<string, unknown>> = body) {
  const root = mkdtempSync(join(tmpdir(), `keep-yolo-${track}-`));
  const attempt_authority = new FileWorkAttemptAuthorityV1(join(root, "attempt"));
  const identity: WorkAttemptIdentityV1 = { project_id: `prj_${track === "n1" ? "1".repeat(32) : "2".repeat(32)}`, goal_id: "goal", subgoal_id: "SG-01", ticket_id: "SG-01-T003B", ticket_body: ticketBody, ticket_body_digest: digest(ticketBody), failure_lessons: [{ id: "FL-004", digest: H("f") }], track, authority: authority(track), product_commit: "9".repeat(40), interpreter_identity: process.version };
  const admitted = await attempt_authority.admit(identity);
  const attempt: WorkAttemptReferenceV1 = { identity_digest: admitted.identity_digest, attempt_id: admitted.attempt_id, generation: admitted.generation };
  return { root, attempt_authority, attempt, identity };
}

function input(base: Awaited<ReturnType<typeof fixture>>, track: "n1" | "enterprise", overrides: Partial<YoloTicketCoordinatorInputV1> = {}): YoloTicketCoordinatorInputV1 {
  return {
    attempt_authority: base.attempt_authority,
    attempt: base.attempt,
    configured_posture: "autonomous",
    research_progress: progress(track),
    boundary_facts: ordinaryFacts(),
    action: async () => ({ outcome: "ADVANCE", evidence_digest: H("e") }),
    ...overrides,
  };
}

for (const track of ["n1", "enterprise"] as const) test(`SG-01-T003-C0${track === "n1" ? "7" : "8"}: ${track} autonomous step retains track authority and advances once`, async () => {
  const f = await fixture(track); const published: unknown[] = [];
  const result = await new YoloTicketCoordinatorV1().step(input(f, track, { status_sink: { publish: (status) => { published.push(status); } } }));
  assert.equal(result.advanced, true); assert.equal(result.attempt.transitions.length, 1); assert.equal(result.attempt.identity.authority.kind, track);
  if (track === "enterprise" && result.attempt.identity.authority.kind === "enterprise") {
    assert.deepEqual({ organization_id: result.attempt.identity.authority.organization_id, tenant_id: result.attempt.identity.authority.tenant_id, custody_id: result.attempt.identity.authority.custody_id, isolation_id: result.attempt.identity.authority.isolation_id }, { organization_id: "org", tenant_id: "tenant", custody_id: "org-custody", isolation_id: "iso" });
  }
  assert.equal(result.status.completion.display, "1/3 (33.33%)"); assert.match(result.status.current_work, /Resume the fenced ticket/u); assert.match(result.status.value, /custody or evidence/u);
  assert.equal(result.status.authoritative, false); assert.equal(published.length, 1); assert.equal(Object.isFrozen(result.status), true);
});

test("SG-01-T003-C11: every retained boundary stops distinctly before action or transition", async () => {
  const cases: [string, (facts: YoloTicketBoundaryFactsV1) => void][] = [
    ["PROTECTED_WORKLOAD_IMPACT", (facts) => (facts.protected_workload_effects as {resource:string;consequence_order:1}[]).push({ resource: "protected-service", consequence_order: 1 })],
    ["SCOPE_CONFLICT", (facts) => (facts.requested_scope_ids as string[]).push("outside")],
    ["OWNER_RESERVED_EFFECT", (facts) => (facts.requested_effects as {description:string;class:"public"}[]).push({ description: "publish", class: "public" })],
    ["THIRD_VET_REQUIRED", (facts) => Object.assign(facts, { requested_vet_round: 3 })],
    ["RESOURCE_CEILING", (facts) => Object.assign(facts.resources, { estimated_ram_mib: 2049 })],
    ["AMBIGUOUS_EFFECT", (facts) => (facts.requested_effects as {description:string;class:"unknown"}[]).push({ description: "unclear", class: "unknown" })],
  ];
  for (const [expected, mutate] of cases) {
    const f = await fixture(); const facts = ordinaryFacts(); mutate(facts); let calls = 0;
    const result = await new YoloTicketCoordinatorV1().step(input(f, "n1", { boundary_facts: facts, action: async () => { calls++; return { outcome: "ADVANCE", evidence_digest: H("e") }; } }));
    assert.equal(result.code, expected); assert.equal(calls, 0); assert.equal(f.attempt_authority.load(f.attempt).transitions.length, 0);
  }
});

test("SG-01-T003-C18: requested or configured posture can tighten but never relax to autonomous", async () => {
  for (const [configured, requested] of [["policy-calibrated", undefined], ["approval-required", "autonomous"], ["autonomous", "approval-required"], ["autonomous", "observer"], ["approver", "autonomous"], ["autonomous", "collaborator"], ["operator", undefined]] as const) {
    const f = await fixture(); let calls = 0;
    const result = await new YoloTicketCoordinatorV1().step(input(f, "n1", { configured_posture: configured as never, ...(requested === undefined ? {} : { requested_posture: requested as never }), action: async () => { calls++; return { outcome: "ADVANCE", evidence_digest: H("e") }; } }));
    assert.equal(result.code, "POSTURE_NOT_AUTONOMOUS"); assert.equal(result.status.mode, ["autonomous", "policy-calibrated", "approval-required"].includes(configured) && (requested === undefined || ["autonomous", "policy-calibrated", "approval-required"].includes(requested)) ? configured === "autonomous" ? requested : configured : "approval-required"); assert.equal(calls, 0);
  }
});

test("SG-01-T003-C09/C14/C15: fresh coordinator resumes first unmet stage and takeover fences the old process", async () => {
  const f = await fixture(); const first = await new YoloTicketCoordinatorV1().step(input(f, "n1"));
  assert.equal(first.status.next_stage, "RESEARCH_COMPLETE");
  const resumed = await new YoloTicketCoordinatorV1().step(input(f, "n1"));
  assert.equal(resumed.attempt.transitions[1]?.stage, "RESEARCH_COMPLETE");
  const successor = await f.attempt_authority.takeover(f.attempt); const next = { identity_digest: successor.identity_digest, attempt_id: successor.attempt_id, generation: successor.generation };
  await assert.rejects(new YoloTicketCoordinatorV1().step(input(f, "n1")), StaleWorkAttemptError);
  const continued = await new YoloTicketCoordinatorV1().step(input({ ...f, attempt: next }, "n1"));
  assert.equal(continued.attempt.transitions[2]?.stage, "VET_1_PASS");
});

test("SG-01-T003-C10: wrong research track, inactive ticket, and a second attempt refuse", async () => {
  const f = await fixture("n1");
  const wrongTrack = await new YoloTicketCoordinatorV1().step(input(f, "n1", { research_progress: progress("enterprise") }));
  assert.equal(wrongTrack.code, "RESEARCH_AUTHORITY_INVALID");
  const inactive = await new YoloTicketCoordinatorV1().step(input(f, "n1", { research_progress: progress("n1", ["PG-04-T008"], null) }));
  assert.equal(inactive.code, "RESEARCH_AUTHORITY_INVALID");
  const missing = structuredClone(progress("n1")); delete (missing.receipt as unknown as Record<string, unknown>).receipt_digest;
  const absent = await new YoloTicketCoordinatorV1().step(input(f, "n1", { research_progress: missing }));
  assert.equal(absent.code, "RESEARCH_AUTHORITY_INVALID"); assert.equal(absent.status.completion.display, "0/1 (0.00%)"); assert.equal(absent.status.source_receipt_digest, H("0"));
  await assert.rejects(f.attempt_authority.admit(f.identity), /one active ticket/u);
});

test("SG-01-T003-C12/C13/C16: projection is rebuilt, contextual, and closure-derived", async () => {
  const f = await fixture(); const forged: { value: unknown } = { value: { completion: "100%" } };
  const first = await new YoloTicketCoordinatorV1().step(input(f, "n1", { status_sink: { publish: (status) => { forged.value = status; } } }));
  assert.equal((forged.value as { completion: { display: string } }).completion.display, "1/3 (33.33%)");
  forged.value = { completion: "100%" };
  const rebuilt = await new YoloTicketCoordinatorV1().step(input(f, "n1", { research_progress: progress("n1", ["PG-04-T008", "SG-01-T003B"], null), status_sink: { publish: (status) => { forged.value = status; } } }));
  assert.equal(rebuilt.code, "RESEARCH_AUTHORITY_INVALID"); assert.equal(rebuilt.status.completion.display, "2/3 (66.66%)");
  assert.match(rebuilt.status.current_work, /Resume the fenced ticket/u); assert.equal((forged.value as { projection_digest: string }).projection_digest, rebuilt.status.projection_digest);
  assert.equal(first.status.projection_digest === rebuilt.status.projection_digest, false);
});

test("SG-01-T003-C09/C11: failed work is retained at the same first-unmet stage", async () => {
  const f = await fixture();
  const failed = await new YoloTicketCoordinatorV1().step(input(f, "n1", { action: async () => ({ outcome: "FAILURE", evidence_digest: H("d") }) }));
  assert.equal(failed.code, "ACTION_FAILURE"); assert.equal(failed.status.next_stage, "RESEARCH_PENDING"); assert.equal(failed.status.last_outcome, "FAILURE");
  const retried = await new YoloTicketCoordinatorV1().step(input(f, "n1"));
  assert.equal(retried.advanced, true); assert.equal(retried.attempt.transitions.map((row) => row.stage).join(","), "RESEARCH_PENDING,RESEARCH_PENDING");
});

test("SG-01-T003-C11: ticket-bound scope/resource controls cannot be widened by facts", async () => {
  for (const mutate of [
    (facts: YoloTicketBoundaryFactsV1) => Object.assign(facts.resources, { estimated_disk_mib: 10241 }),
    (facts: YoloTicketBoundaryFactsV1) => Object.assign(facts.resources, { estimated_processes: 4 }),
  ]) {
    const f = await fixture(), facts = ordinaryFacts(); mutate(facts);
    assert.equal((await new YoloTicketCoordinatorV1().step(input(f, "n1", { boundary_facts: facts }))).code, "RESOURCE_CEILING");
  }
  const f = await fixture(), malformed = ordinaryFacts(); (malformed.resources as unknown as Record<string, unknown>).estimated_ram_mib = "64";
  assert.equal((await new YoloTicketCoordinatorV1().step(input(f, "n1", { boundary_facts: malformed }))).code, "AMBIGUOUS_EFFECT");
  const f2 = await fixture(), reversible = ordinaryFacts(); (reversible.requested_effects as {description:string;class:"external-reversible"}[])[0] = { description: "remote write", class: "external-reversible" };
  assert.equal((await new YoloTicketCoordinatorV1().step(input(f2, "n1", { boundary_facts: reversible }))).code, "AMBIGUOUS_EFFECT");
  const { resource_bounds: _removed, ...withoutControls } = body;
  const f3 = await fixture("n1", withoutControls);
  assert.equal((await new YoloTicketCoordinatorV1().step(input(f3, "n1"))).code, "AMBIGUOUS_EFFECT");
});

test("SG-01-T003-C17: cross-root attempt and protected-resource fact cannot reach the action", async () => {
  const left = await fixture(), right = await fixture(); let calls = 0;
  await assert.rejects(new YoloTicketCoordinatorV1().step(input(left, "n1", { attempt_authority: right.attempt_authority })), StaleWorkAttemptError);
  const facts = ordinaryFacts(); (facts.protected_workload_effects as {resource:string;consequence_order:1}[]).push({ resource: "unrelated protected workload", consequence_order: 1 });
  const stopped = await new YoloTicketCoordinatorV1().step(input(left, "n1", { boundary_facts: facts, action: async () => { calls++; return { outcome: "ADVANCE", evidence_digest: H("e") }; } }));
  assert.equal(stopped.code, "PROTECTED_WORKLOAD_IMPACT"); assert.equal(calls, 0); assert.equal(left.attempt_authority.load(left.attempt).transitions.length, 0);
});

test("SG-01-T003-C12: a failed projection sink cannot fail or duplicate an authoritative step", async () => {
  const f = await fixture(); let loads = 0;
  const sink = { load: () => { loads++; throw new Error("forged cache read"); }, publish: () => { throw new Error("disk full"); } };
  const result = await new YoloTicketCoordinatorV1().step(input(f, "n1", { status_sink: sink }));
  assert.equal(result.advanced, true); assert.equal(result.attempt.transitions.length, 1); assert.equal(loads, 0);
});

test("SG-01-T003-C09: a complete attempt stops and never invokes another action", async () => {
  const f = await fixture(); const coordinator = new YoloTicketCoordinatorV1(); let calls = 0;
  for (let index = 0; index < 10; index++) await coordinator.step(input(f, "n1"));
  const complete = await coordinator.step(input(f, "n1", { action: async () => { calls++; return { outcome: "ADVANCE", evidence_digest: H("e") }; } }));
  assert.equal(complete.code, "ATTEMPT_COMPLETE"); assert.equal(calls, 0); assert.equal(complete.status.next_stage, null);
});
