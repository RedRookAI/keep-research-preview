import assert from "node:assert/strict";
import test from "node:test";
import {
  admitExecutableTicket,
  type DecompositionAuthorityContextV1,
  type DecompositionTransitionResultV1,
  type ExecutableTicketBodyV1,
  type TicketAdmissionScopeV1,
} from "../src/index.js";

const hex = (character: string) => character.repeat(64);
const generation = (character: string) => `sha256:${hex(character)}`;
const cases = () =>
  Array.from({ length: 13 }, (_, index) => ({
    id: `PG-04-T002-FC${String(index + 1).padStart(2, "0")}`,
    input: `fixed input ${index + 1}`,
    oracle: `fixed oracle ${index + 1}`,
    classification: index < 2 ? "ACCEPTANCE" : "HOSTILE_DENIAL",
  }));
const body = (track: "n1" | "enterprise" = "n1"): ExecutableTicketBodyV1 => ({
  schema_version: 1,
  node_kind: "EXECUTABLE_LEAF",
  ticket_id: "PG-04-T002",
  title: "Enforce cold-pickup executable-ticket bodies",
  outcomes: [
    {
      kind: "PRODUCT_CHANGE",
      statement: "Admit one bounded ticket",
      invariant: "Only complete bounded bodies enter execution",
    },
  ],
  scope_ids: ["ES-S004", "ES-S011", "ES-S012"],
  requirements: ["PG-04-T002-R1", "PG-04-T002-R6"],
  threats: ["non-executable node activation", "unbounded surface"],
  mutation_surface: [
    "product:/workspace/fixture-product:src/decomposition/ticket_contract.ts",
  ],
  effect_surface: ["ticket-contract-admission"],
  cases: cases(),
  resources: {
    max_changed_subsystems: 2,
    focused_test_minutes: 45,
    full_closure_minutes: 120,
    max_new_runtime_dependencies: 0,
    fixed_case_count: 13,
  },
  ambiguities: [],
  closure: {
    profile: "FULL_KEEP_EXACT_COMMIT_V1",
    steps: [
      { id: "focused", command: "node --test focused", maximum_minutes: 45 },
      { id: "full", command: "npm test", maximum_minutes: 60 },
      { id: "package", command: "npm pack", maximum_minutes: 15 },
    ],
    source_push: true,
    source_readback: true,
    package_push: true,
    package_readback: true,
    blank_install: true,
    n1_journey: true,
    enterprise_journey: true,
  },
  authority:
    track === "n1"
      ? { kind: "owner", owner_id: "owner", custody_id: "local" }
      : {
          kind: "organization",
          organization_id: "org",
          actor_id: "alice",
          role_id: "maintainer",
          separation_policy_id: "sod",
          custody_evidence_digest: hex("c"),
          isolation_evidence_digest: hex("d"),
        },
});
const context = (
  track: "n1" | "enterprise" = "n1",
): DecompositionAuthorityContextV1 =>
  track === "n1"
    ? {
        kind: "n1",
        principal_id: "owner",
        custody_id: "local",
        organization_services: "ABSENT",
      }
    : {
        kind: "enterprise",
        organization_id: "org",
        actor_id: "alice",
        role_id: "maintainer",
        separation_policy_id: "sod",
        local_owner_substitution: false,
      };
const scope = (): TicketAdmissionScopeV1 => ({
  ticket_id: "PG-04-T002",
  ticket_body_digest: hex("e"),
  approved_graph_digest: hex("f"),
  active_generation: generation("a"),
});
const transition = (): DecompositionTransitionResultV1 => ({
  code: "ADVANCED",
  advanced: true,
  state: {
    schema_version: 1,
    phase: "FIRST_TICKET_RESEARCH_AUTHORIZED",
    approved_graph_digest: hex("f"),
    active_generation: generation("a"),
    derived_authorities: {
      architecture: {
        digest: hex("1"),
        depends_on: ["graph"],
        status: "ACTIVE",
      },
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
  },
  stale_descendants: [],
  owner_stop: null,
});
const denial = (
  candidate: unknown,
  suppliedContext: unknown = context(),
  suppliedTransition: unknown = transition(),
  suppliedScope: unknown = scope(),
) => {
  const result = admitExecutableTicket(
    candidate,
    suppliedTransition,
    suppliedContext,
    suppliedScope,
  );
  assert.equal(result.admitted, false);
  return result.admitted ? null : result.denial;
};

test("PG-04-T002-FC01 accepts bounded n=1 without organization ceremony", () => {
  const result = admitExecutableTicket(
    body(),
    transition(),
    context(),
    scope(),
  );
  assert.equal(result.admitted, true);
  if (result.admitted) {
    assert.equal(result.authority.track, "n1");
    assert.equal(result.authority.body.authority.kind, "owner");
    assert.equal("organization_id" in result.authority.body.authority, false);
  }
});

test("PG-04-T002-FC02 accepts attributed enterprise custody and isolation", () => {
  const result = admitExecutableTicket(
    body("enterprise"),
    transition(),
    context("enterprise"),
    scope(),
  );
  assert.equal(result.admitted, true);
  if (result.admitted) {
    assert.equal(result.authority.track, "enterprise");
    assert.equal(result.authority.body.authority.kind, "organization");
    if (result.authority.body.authority.kind === "organization")
      assert.equal(result.authority.body.authority.actor_id, "alice");
  }
});

test("PG-04-T002-FC03 title-only projection is not executable", () => {
  assert.equal(
    denial({ ticket_id: "PG-04-T002", title: "title only" }),
    "NON_EXECUTABLE_NODE",
  );
});

test("PG-04-T002-FC04 and FC10 require exactly one outcome", () => {
  assert.equal(
    denial({
      ...body(),
      outcomes: [
        body().outcomes[0],
        { ...body().outcomes[0], statement: "Second independent result" },
      ],
    }),
    "TICKET_NOT_COHERENT",
  );
  assert.equal(denial({ ...body(), outcomes: [] }), "TICKET_NOT_COHERENT");
});

test("PG-04-T002-FC05, FC11, and FC12 reject unbounded or unnamed surfaces", () => {
  for (const mutation_surface of [
    ["src/**"],
    ["src/../secret"],
    ["related files"],
  ])
    assert.equal(
      denial({ ...body(), mutation_surface }),
      "TICKET_SURFACE_UNBOUNDED",
    );
  assert.equal(
    denial({ ...body(), effect_surface: [" "] }),
    "TICKET_SURFACE_UNBOUNDED",
  );
});

test("PG-04-T002-FC06 rejects open matrices and absent ceilings", () => {
  assert.equal(denial({ ...body(), cases: [] }), "TICKET_NOT_FEASIBLE");
  const { full_closure_minutes: _, ...incomplete } = body().resources;
  assert.equal(
    denial({ ...body(), resources: incomplete }),
    "TICKET_NOT_FEASIBLE",
  );
});

test("PG-04-T002-FC07 successor-generating outcome is not executable", () => {
  assert.equal(
    denial({
      ...body(),
      outcomes: [{ ...body().outcomes[0], kind: "SUCCESSOR_CREATION" }],
    }),
    "NON_EXECUTABLE_NODE",
  );
});

test("PG-04-T002-FC08 unresolved ambiguity is incoherent", () => {
  assert.equal(
    denial({ ...body(), ambiguities: ["who decides?"] }),
    "TICKET_NOT_COHERENT",
  );
  assert.equal(denial({ ...body(), ambiguities: [""] }), "TICKET_NOT_COHERENT");
});

test("PG-04-T002-FC09 closure work must fit its declared envelope", () => {
  assert.equal(
    denial({
      ...body(),
      resources: { ...body().resources, full_closure_minutes: 119 },
    }),
    "TICKET_NOT_FEASIBLE",
  );
  assert.equal(
    denial({
      ...body(),
      closure: { ...body().closure, package_readback: false },
    }),
    "TICKET_NOT_FEASIBLE",
  );
});

test("PG-04-T002-FC13 recovery is deterministic and does not mutate inputs", () => {
  const candidate = body(),
    before = structuredClone(candidate);
  const first = admitExecutableTicket(
    candidate,
    transition(),
    context(),
    scope(),
  );
  const recovered = admitExecutableTicket(
    structuredClone(candidate),
    transition(),
    context(),
    scope(),
  );
  assert.deepEqual(first, recovered);
  assert.deepEqual(candidate, before);
  assert.equal(first.admitted && Object.isFrozen(first.authority.body), true);
});

test("track authority variants cannot substitute for one another", () => {
  assert.equal(
    denial(body(), context("enterprise")),
    "TRACK_AUTHORITY_INVALID",
  );
  assert.equal(
    denial(body("enterprise"), context()),
    "TRACK_AUTHORITY_INVALID",
  );
  assert.equal(
    denial(body("enterprise"), {
      ...context("enterprise"),
      actor_id: "mallory",
    }),
    "TRACK_AUTHORITY_INVALID",
  );
});

test("the exact T001 transition result and scope are required", () => {
  assert.equal(
    denial(body(), context(), {
      ...transition(),
      code: "STALE_DERIVATION",
      advanced: false,
    }),
    "PREDECESSOR_TRANSITION_INVALID",
  );
  const wrongPhase = transition();
  assert.ok(wrongPhase.state);
  assert.equal(
    denial(body(), context(), {
      ...wrongPhase,
      state: { ...wrongPhase.state, phase: "OWNER_APPROVED" },
    }),
    "PREDECESSOR_TRANSITION_INVALID",
  );
  assert.equal(
    denial(body(), context(), transition(), {
      ...scope(),
      active_generation: generation("z"),
    }),
    "PREDECESSOR_TRANSITION_INVALID",
  );
  assert.equal(
    denial(body(), context(), {
      ...transition(),
      state: { ...transition().state, derived_authorities: {} },
    }),
    "PREDECESSOR_TRANSITION_INVALID",
  );
});

test("denial precedence is stable and unknown keys fail closed", () => {
  const hostile = {
    ...body(),
    extra: true,
    outcomes: [],
    mutation_surface: ["*"],
    ambiguities: ["x"],
  };
  assert.equal(denial(hostile), "NON_EXECUTABLE_NODE");
  assert.equal(
    denial({ ...body(), outcomes: [], mutation_surface: ["*"] }),
    "TICKET_NOT_COHERENT",
  );
  assert.equal(
    denial({ ...body(), mutation_surface: ["*"], cases: [] }),
    "TICKET_SURFACE_UNBOUNDED",
  );
});
