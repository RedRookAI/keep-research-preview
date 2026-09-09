import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  activateTicketResearch,
  FileWorkAttemptAuthorityV1,
  InvalidWorkAttemptError,
  isTicketResearchIdV1,
  validateTicketResearchProgressV1,
  type TicketResearchActivationRequestV1,
} from "../src/autonomy/project_state.js";
import { isDecompositionResultEventV1 } from "../src/spine/decomposition_result_events_v1.js";

const hex = (character: string) => character.repeat(64);
const generation = `sha256:${hex("a")}`;
const stable = (value: unknown): unknown => Array.isArray(value) ? value.map(stable) : value !== null && typeof value === "object" ? Object.fromEntries(Object.keys(value as Record<string, unknown>).sort().map((key) => [key, stable((value as Record<string, unknown>)[key])])) : value;
const digest = (value: unknown) => createHash("sha256").update(JSON.stringify(stable(value))).digest("hex");

function request(track: "n1" | "enterprise" = "n1"): TicketResearchActivationRequestV1 {
  return {
    schema_version: 1,
    expected_generation: generation,
    approved_generation: {
      generation,
      publication_receipt_digest: hex("b"),
      remote_readback_commit: hex("c"),
      remote_ref_matched: true,
      tickets: [{ ticket_id: "PG-04-T009", dependency_ticket_ids: ["PG-04-T008"], track }],
    },
    state: {
      schema_version: 1,
      active_generation: generation,
      active_ticket_id: null,
      closed_ticket_ids: ["PG-04-T008"],
    },
    selected_ticket_id: "PG-04-T009",
    authority: track === "n1"
      ? { kind: "n1", owner_id: "owner", custody_id: "local", organization_services: "ABSENT" }
      : {
          kind: "enterprise",
          organization_id: "org",
          actor_id: "alice",
          role_id: "maintainer",
          separation_policy_id: "sod",
          custody_evidence_digest: hex("d"),
          isolation_evidence_digest: hex("e"),
          local_owner_substitution: false,
        },
    implementation_authorized: false,
  };
}

test("PG-04-T008-FC01 first ready local ticket receives research-only authority", () => {
  const result = activateTicketResearch(request());
  assert.equal(result.code, "TICKET_RESEARCH_AUTHORIZED");
  assert.equal(result.receipt?.track, "n1");
  assert.equal(result.receipt?.implementation_authorized, false);
  assert.equal(result.receipt?.authority.kind, "n1");
  assert.equal(result.receipt?.remote_readback_commit, request().approved_generation.remote_readback_commit);
  assert.equal("organization_id" in (result.receipt?.authority ?? {}), false);
});

test("PG-04-T008-FC02 first ready enterprise ticket retains attributed custody and isolation", () => {
  const result = activateTicketResearch(request("enterprise"));
  assert.equal(result.code, "TICKET_RESEARCH_AUTHORIZED");
  assert.equal(result.receipt?.track, "enterprise");
  assert.deepEqual(result.receipt?.authority, request("enterprise").authority);
  assert.equal(result.receipt?.implementation_authorized, false);
});

test("PG-04-T008-FC03 an already active ticket prevents a second activation", () => {
  const value = request();
  value.state.active_ticket_id = "PG-04-T010";
  assert.equal(activateTicketResearch(value).code, "ACTIVE_TICKET_CONFLICT");
});

test("PG-04-T008-FC04 an unready dependency is denied without a competing active ticket", () => {
  const value = request();
  value.state.closed_ticket_ids = [];
  assert.equal(value.state.active_ticket_id, null);
  assert.equal(activateTicketResearch(value).code, "ACTIVE_TICKET_CONFLICT");
});

test("PG-04-T008-FC05 stale generation is denied", () => {
  const value = request();
  value.expected_generation = `sha256:${hex("f")}`;
  assert.equal(activateTicketResearch(value).code, "STALE_DERIVATION");
  const staleState = request();
  staleState.state.active_generation = `sha256:${hex("f")}`;
  assert.equal(activateTicketResearch(staleState).code, "STALE_DERIVATION");
  const notDurable = request();
  notDurable.approved_generation.remote_ref_matched = false;
  assert.equal(activateTicketResearch(notDurable).code, "PREREQUISITE_AUTHORITY_INVALID");
});

test("PG-04-T008-FC06 activation cannot claim implementation authority", () => {
  const value = request() as unknown as Record<string, unknown>;
  value.implementation_authorized = true;
  assert.equal(
    activateTicketResearch(value as unknown as TicketResearchActivationRequestV1).code,
    "DECOMPOSITION_CANNOT_AUTHORIZE_IMPLEMENTATION",
  );
  const stale = request() as unknown as Record<string, unknown>;
  stale.expected_generation = `sha256:${hex("f")}`;
  stale.implementation_authorized = true;
  assert.equal(activateTicketResearch(stale as unknown as TicketResearchActivationRequestV1).code, "STALE_DERIVATION");
  const notDurable = request() as unknown as Record<string, unknown>;
  (notDurable.approved_generation as Record<string, unknown>).remote_ref_matched = false;
  notDurable.implementation_authorized = true;
  assert.equal(activateTicketResearch(notDurable as unknown as TicketResearchActivationRequestV1).code, "PREREQUISITE_AUTHORITY_INVALID");
  for (const mutate of [
    (value: Record<string, unknown>) => { value.extra = true; },
    (value: Record<string, unknown>) => { (value.approved_generation as Record<string, unknown>).extra = true; },
    (value: Record<string, unknown>) => { (((value.approved_generation as Record<string, unknown>).tickets as Record<string, unknown>[])[0]!).extra = true; },
    (value: Record<string, unknown>) => { (value.state as Record<string, unknown>).extra = true; },
    (value: Record<string, unknown>) => { (value.authority as Record<string, unknown>).organization_id = "forged"; },
  ]) {
    const value = request() as unknown as Record<string, unknown>;
    mutate(value);
    assert.equal(activateTicketResearch(value as unknown as TicketResearchActivationRequestV1).code, "MALFORMED_OR_UNKNOWN_FIELD");
  }
});

test("PG-04-T008-FC07 enterprise authority cannot substitute in n=1", () => {
  const local = request();
  local.authority = request("enterprise").authority;
  assert.equal(activateTicketResearch(local).code, "TRACK_AUTHORITY_SUBSTITUTION");
});

test("PG-04-T008-FC08 local authority cannot substitute in enterprise", () => {
  const enterprise = request("enterprise");
  enterprise.authority = request().authority;
  assert.equal(activateTicketResearch(enterprise).code, "TRACK_AUTHORITY_SUBSTITUTION");
  for (const mutate of [
    (authority: Record<string, unknown>) => { delete authority.custody_evidence_digest; },
    (authority: Record<string, unknown>) => { authority.isolation_evidence_digest = "not-a-digest"; },
    (authority: Record<string, unknown>) => { authority.local_owner_substitution = true; },
  ]) {
    const malformed = request("enterprise") as unknown as Record<string, unknown>;
    mutate(malformed.authority as Record<string, unknown>);
    assert.equal(activateTicketResearch(malformed as unknown as TicketResearchActivationRequestV1).code, "MALFORMED_OR_UNKNOWN_FIELD");
  }
});

test("PG-04-T008-FC09 recovery derives identical frozen authority once and stays research-only", () => {
  const value = request("enterprise");
  const first = activateTicketResearch(value);
  const recovered = activateTicketResearch(structuredClone(value));
  assert.deepEqual(recovered, first);
  assert.equal(recovered.receipt?.implementation_authorized, false);
  assert.equal(Object.isFrozen(recovered), true);
  assert.equal(Object.isFrozen(recovered.receipt), true);

  let reads = 0;
  const adversarial = request();
  const original = adversarial.approved_generation.tickets;
  Object.defineProperty(adversarial.approved_generation, "tickets", {
    enumerable: true,
    get: () => ++reads === 1 ? original : [],
  });
  assert.equal(activateTicketResearch(adversarial).code, "TICKET_RESEARCH_AUTHORIZED");
  assert.equal(reads, 1);
});

test("PG-04-T008 repair accepts the exact PG and SG ticket families and rejects broader forms", () => {
  const accepted = ["PG-04-T008", "SG-01-T003", "SG-01-T003B", "SG-99-T999Z"];
  const refused = ["pg-04-t008", "XX-01-T001", "SG-1-T001", "SG-01-T01", "SG-01-T000AA", " SG-01-T003", "SG-０１-T003"];
  for (const id of accepted) assert.equal(isTicketResearchIdV1(id), true, id);
  for (const id of refused) assert.equal(isTicketResearchIdV1(id), false, id);
  for (const track of ["n1", "enterprise"] as const) for (const id of ["SG-01-T003", "SG-01-T003B"]) {
    const value = request(track); value.approved_generation.tickets[0]!.ticket_id = id; value.selected_ticket_id = id;
    assert.equal(activateTicketResearch(value).code, "TICKET_RESEARCH_AUTHORIZED");
  }
  for (const position of ["ticket", "dependency", "selected", "active", "closed"] as const) for (const id of refused) {
    const value = request();
    if (position === "ticket") value.approved_generation.tickets[0]!.ticket_id = id;
    if (position === "dependency") value.approved_generation.tickets[0]!.dependency_ticket_ids = [id];
    if (position === "selected") value.selected_ticket_id = id;
    if (position === "active") value.state.active_ticket_id = id;
    if (position === "closed") value.state.closed_ticket_ids = [id];
    assert.equal(activateTicketResearch(value).code, "MALFORMED_OR_UNKNOWN_FIELD", `${position}:${id}`);
  }
});

test("PG-04-T008 repair validates active progress and partitions prior closures", () => {
  const activation = request(); activation.approved_generation.tickets[0]!.ticket_id = "SG-01-T003B"; activation.selected_ticket_id = "SG-01-T003B";
  const admitted = activateTicketResearch(activation); assert.equal(admitted.advanced, true); assert.ok(admitted.receipt);
  const current_state = { ...activation.state, active_ticket_id: "SG-01-T003B", closed_ticket_ids: ["PG-04-T008"] };
  const result = validateTicketResearchProgressV1({ activation, receipt: admitted.receipt!, current_state });
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.progress.ticket_status, "ACTIVE"); assert.equal(result.progress.closed_in_generation_count, 0);
    assert.deepEqual(result.progress.closed_outside_generation, ["PG-04-T008"]); assert.equal(result.progress.receipt_digest, admitted.receipt!.receipt_digest);
    assert.equal(result.progress.authoritative, false); assert.equal(result.progress.effects_performed, false); assert.equal(Object.isFrozen(result.progress), true);
  }
});

test("PG-04-T008 repair derives closed and not-active states without inventing closure", () => {
  const activation = request(); activation.approved_generation.tickets[0]!.ticket_id = "SG-01-T003B"; activation.selected_ticket_id = "SG-01-T003B";
  const receipt = activateTicketResearch(activation).receipt!;
  const closed = validateTicketResearchProgressV1({ activation, receipt, current_state: { ...activation.state, closed_ticket_ids: ["PG-04-T008", "SG-01-T003B"] } });
  assert.equal(closed.ok && closed.progress.ticket_status, "CLOSED");
  if (closed.ok) { assert.deepEqual(closed.progress.closed_in_generation, ["SG-01-T003B"]); assert.equal(closed.progress.closed_in_generation_count, 1); assert.deepEqual(closed.progress.closed_outside_generation, ["PG-04-T008"]); }
  const absent = validateTicketResearchProgressV1({ activation, receipt, current_state: { ...activation.state, closed_ticket_ids: ["PG-04-T008"] } });
  assert.equal(absent.ok && absent.progress.ticket_status, "NOT_ACTIVE_NOT_CLOSED");
});

test("PG-04-T008 repair refuses inconsistent or regressed progress evidence", () => {
  const activation = request(); activation.approved_generation.tickets[0]!.ticket_id = "SG-01-T003B"; activation.selected_ticket_id = "SG-01-T003B";
  const receipt = activateTicketResearch(activation).receipt!;
  const check = (current_state: typeof activation.state, candidate = receipt) => validateTicketResearchProgressV1({ activation, receipt: candidate, current_state }).code;
  assert.equal(check({ ...activation.state, active_ticket_id: "SG-01-T004" }), "ACTIVE_TICKET_CONFLICT");
  assert.equal(check({ ...activation.state, active_generation: `sha256:${hex("f")}` }), "STALE_DERIVATION");
  assert.equal(check({ ...activation.state, closed_ticket_ids: [] }), "DEPENDENCY_CLOSURE_REGRESSED");
  assert.equal(check({ ...activation.state, closed_ticket_ids: ["PG-04-T008", "PG-04-T008"] }), "MALFORMED_OR_UNKNOWN_FIELD");
  assert.equal(check(activation.state, { ...receipt, receipt_digest: hex("f") }), "RECEIPT_MISMATCH");
  assert.equal(check({ ...activation.state, active_ticket_id: "SG-01-T003B", closed_ticket_ids: ["PG-04-T008", "SG-01-T003B"] }), "ACTIVE_TICKET_CONFLICT");
});

test("PG-04-T008 repair applies the same corpus at T014 readback and T003 attempt admission", async () => {
  const eventFor = (ticket: string) => { const body = { schema:"keep.decomposition-result-event",schema_version:1,status:"DECOMPOSITION_RESULT_RECORDED",source_heads:{review:{history_id:"review",event_count:1,final_sequence:0,final_event_id:hex("1"),final_head_id:hex("2"),state_digest:hex("3")},approval:{history_id:"approval",event_count:1,final_sequence:0,final_event_id:hex("4"),final_head_id:hex("5"),state_digest:hex("6")}},generation,publication_receipt_digest:hex("7"),remote_readback_commit:"8".repeat(40),product_commit:"9".repeat(40),active_ticket_id:ticket,track:"n1",authority:{kind:"n1"},research_receipt_digest:hex("a"),lifecycle_authoritative:false,effects_performed:false }; return { ...body, event_digest:digest(body) }; };
  for (const id of ["PG-04-T008", "SG-01-T003", "SG-01-T003B"]) assert.equal(isDecompositionResultEventV1(eventFor(id)), true, `T014:${id}`);
  for (const id of ["sg-01-t003", "SG-01-T003AA", "XX-01-T003"]) assert.equal(isDecompositionResultEventV1(eventFor(id)), false, `T014:${id}`);
  const bodyFor = (id: string) => ({ id, requirements:["R"], finish_conditions:["F"], research_contract:{current:"c"}, mutation_surface:["src/x.ts"] });
  for (const id of ["PG-04-T008", "SG-01-T003", "SG-01-T003B"]) { const root=mkdtempSync(join(tmpdir(),"keep-t008-grammar-")); try { const body=bodyFor(id); await new FileWorkAttemptAuthorityV1(root).admit({project_id:"project",goal_id:"goal",subgoal_id:"subgoal",ticket_id:id,ticket_body:body,ticket_body_digest:digest(body),failure_lessons:[{id:"FL",digest:hex("b")}],track:"n1",authority:{kind:"n1",owner_id:"owner",custody_id:"local",organization_services:"ABSENT"},product_commit:"c".repeat(40),interpreter_identity:"node"}); } finally { rmSync(root,{recursive:true,force:true}); } }
  for (const id of ["sg-01-t003", "SG-01-T003AA", "XX-01-T003"]) { const root=mkdtempSync(join(tmpdir(),"keep-t008-grammar-")); try { const body=bodyFor(id); await assert.rejects(new FileWorkAttemptAuthorityV1(root).admit({project_id:"project",goal_id:"goal",subgoal_id:"subgoal",ticket_id:id,ticket_body:body,ticket_body_digest:digest(body),failure_lessons:[{id:"FL",digest:hex("b")}],track:"n1",authority:{kind:"n1",owner_id:"owner",custody_id:"local",organization_services:"ABSENT"},product_commit:"c".repeat(40),interpreter_identity:"node"}),InvalidWorkAttemptError); } finally { rmSync(root,{recursive:true,force:true}); } }
});

test("PG-04-T008 repair leaves one grammar literal in the repaired modules and matches the T003 contract", () => {
  const stateSource = readFileSync("src/autonomy/project_state.ts", "utf8");
  const eventSource = readFileSync("src/spine/decomposition_result_events_v1.ts", "utf8");
  const attemptSource = readFileSync("src/spine/work_attempt_authority_v1.ts", "utf8");
  const literal = String.raw`^(?:PG|SG)-[0-9]{2}-T[0-9]{3}[A-Z]?$`;
  assert.equal(stateSource.includes(literal), true); assert.equal(eventSource.includes(literal), false);
  assert.equal(attemptSource.includes(literal), true); assert.equal((stateSource + eventSource).split(literal).length - 1, 1);
});
