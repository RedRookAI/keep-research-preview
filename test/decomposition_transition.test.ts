import assert from "node:assert/strict";
import test from "node:test";
import {
  DECOMPOSITION_TRANSITION_PHASES,
  evaluateDecompositionTransition,
  type DecompositionTransitionAuthorityV1,
  type DecompositionTransitionProposalV1,
  type DecompositionTransitionStateV1,
} from "../src/decomposition/decomposition_transition.js";

const hex = (value: string) => value.repeat(64).slice(0, 64);
const generation = (value: string) => `sha256:${hex(value)}`;
const authority = (): DecompositionTransitionAuthorityV1 => ({
  schema_version: 1,
  evaluation_mode: "LIVE",
  canonical_writer_id: "writer",
  canonical_writer_generation: generation("a"),
});
const state = (): DecompositionTransitionStateV1 => ({
  schema_version: 1,
  phase: "ARCHITECTURE_AUTHORIZED",
  approved_graph_digest: hex("b"),
  active_generation: generation("c"),
  derived_authorities: {
    architecture: { digest: hex("1"), depends_on: ["graph"], status: "ACTIVE" },
    decomposition: {
      digest: hex("2"),
      depends_on: ["architecture"],
      status: "ACTIVE",
    },
    owner_approval: {
      digest: hex("3"),
      depends_on: ["decomposition"],
      status: "ACTIVE",
    },
    ticket_activation: {
      digest: hex("4"),
      depends_on: ["owner_approval"],
      status: "ACTIVE",
    },
  },
});
const proposal = (): DecompositionTransitionProposalV1 => ({
  schema_version: 1,
  from_phase: "ARCHITECTURE_AUTHORIZED",
  to_phase: "ARCHITECTURE_CANDIDATE",
  writer_id: "writer",
  writer_generation: generation("a"),
  observed_graph_digest: hex("b"),
  expected_generation: generation("c"),
  record_class: "CANONICAL",
  authority_context: {
    kind: "n1",
    principal_id: "owner",
    custody_id: "local",
    organization_services: "ABSENT",
  },
});
const code = (
  s: unknown,
  p: unknown,
  a: unknown = authority(),
) => evaluateDecompositionTransition(s, p, a).code;

test("PG-04-T001-FC01 and FC02 neutral n=1 and enterprise decisions are identical", () => {
  const local = evaluateDecompositionTransition(state(), proposal(), authority());
  const enterpriseProposal: DecompositionTransitionProposalV1 = {
    ...proposal(),
    authority_context: {
      kind: "enterprise",
      organization_id: "org",
      actor_id: "alice",
      role_id: "maintainer",
      separation_policy_id: "separation",
      local_owner_substitution: false,
    },
  };
  const enterprise = evaluateDecompositionTransition(
    state(),
    enterpriseProposal,
    authority(),
  );
  assert.deepEqual(enterprise, local);
  assert.equal(local.code, "ADVANCED");
});

test("PG-04-T001-FC03 and FC10 malformed or unknown input fails first", () => {
  assert.equal(code(state(), { ...proposal(), unknown: true }), "MALFORMED_OR_UNKNOWN_FIELD");
  assert.equal(code(state(), "{"), "MALFORMED_OR_UNKNOWN_FIELD");
});

test("PG-04-T001-FC04 and FC05 every non-adjacent edge is illegal", () => {
  for (const from of DECOMPOSITION_TRANSITION_PHASES) {
    for (const to of DECOMPOSITION_TRANSITION_PHASES) {
      const index = DECOMPOSITION_TRANSITION_PHASES.indexOf(from);
      if (to === DECOMPOSITION_TRANSITION_PHASES[index + 1]) continue;
      const s: DecompositionTransitionStateV1 = { ...state(), phase: from };
      const p: DecompositionTransitionProposalV1 = {
        ...proposal(),
        from_phase: from,
        to_phase: to,
      };
      assert.equal(code(s, p), "ILLEGAL_PHASE_EDGE", `${from}->${to}`);
    }
  }
});

test("PG-04-T001-FC06 and FC07 writer identity and generation are separate fences", () => {
  assert.equal(code(state(), { ...proposal(), writer_id: "other" }), "CANONICAL_WRITER_FENCED");
  assert.equal(code(state(), { ...proposal(), writer_generation: generation("d") }), "CANONICAL_WRITER_FENCED");
});

test("PG-04-T001-FC08 fixture authority cannot enter live evaluation", () => {
  assert.equal(code(state(), { ...proposal(), record_class: "FIXTURE" }), "NON_AUTHORITATIVE_FIXTURE");
});

test("PG-04-T001-FC09 first-failure precedence is stable", () => {
  const malformed = { ...proposal(), unknown: true, to_phase: "OWNER_APPROVED", writer_id: "other" };
  assert.equal(code(state(), malformed), "MALFORMED_OR_UNKNOWN_FIELD");
  const illegal = { ...proposal(), to_phase: "OWNER_APPROVED", record_class: "FIXTURE" as const, writer_id: "other" };
  assert.equal(code(state(), illegal), "ILLEGAL_PHASE_EDGE");
  const fixture = { ...proposal(), record_class: "FIXTURE" as const, writer_id: "other", observed_graph_digest: hex("f") };
  assert.equal(code(state(), fixture), "NON_AUTHORITATIVE_FIXTURE");
  const fenced = { ...proposal(), writer_id: "other", observed_graph_digest: hex("f"), expected_generation: generation("f") };
  assert.equal(code(state(), fenced), "CANONICAL_WRITER_FENCED");
  const mutated = { ...proposal(), observed_graph_digest: hex("f"), expected_generation: generation("f") };
  assert.equal(code(state(), mutated), "APPROVED_GRAPH_MUTATED");
});

test("PG-04-T001-FC11 graph mutation invalidates descendants and stops for owner", () => {
  const original = state();
  const result = evaluateDecompositionTransition(
    original,
    { ...proposal(), observed_graph_digest: hex("f") },
    authority(),
  );
  assert.equal(result.code, "APPROVED_GRAPH_MUTATED");
  assert.equal(result.advanced, false);
  assert.equal(result.owner_stop, "APPROVED_GRAPH_AMENDMENT_REQUIRES_OWNER");
  assert.deepEqual(result.stale_descendants, ["architecture", "decomposition", "owner_approval", "ticket_activation"]);
  assert.ok(result.state && Object.values(result.state.derived_authorities).every((item) => item.status === "STALE_DERIVATION"));
  assert.ok(Object.values(original.derived_authorities).every((item) => item.status === "ACTIVE"));
});

test("PG-04-T001-FC12 stale generation and derived replay cannot advance", () => {
  assert.equal(code(state(), { ...proposal(), expected_generation: generation("f") }), "STALE_DERIVATION");
  const baseline = state();
  const stale: DecompositionTransitionStateV1 = {
    ...baseline,
    derived_authorities: {
      ...baseline.derived_authorities,
      decomposition: {
        ...baseline.derived_authorities.decomposition,
        status: "STALE_DERIVATION",
      },
    },
  };
  assert.equal(code(stale, proposal()), "STALE_DERIVATION");
});

test("all successful transitions preserve caller inputs", () => {
  const s = state();
  const p = proposal();
  const beforeState = structuredClone(s);
  const beforeProposal = structuredClone(p);
  evaluateDecompositionTransition(s, p, authority());
  assert.deepEqual(s, beforeState);
  assert.deepEqual(p, beforeProposal);
});
