export const DECOMPOSITION_TRANSITION_PHASES = [
  "ARCHITECTURE_AUTHORIZED",
  "ARCHITECTURE_CANDIDATE",
  "ARCHITECTURE_VALIDATED",
  "DECOMPOSITION_AUTHORIZED",
  "DECOMPOSITION_CANDIDATE",
  "DECOMPOSITION_STRUCTURAL_PASS",
  "DECOMPOSITION_VET_1",
  "DECOMPOSITION_VET_1_PASS",
  "DECOMPOSITION_VET_2",
  "DECOMPOSITION_VET_2_PASS",
  "OWNER_APPROVAL_PENDING",
  "OWNER_APPROVED",
  "DECOMPOSITION_REMOTE_READBACK_PASS",
  "FIRST_TICKET_RESEARCH_AUTHORIZED",
] as const;

export type DecompositionTransitionPhase =
  (typeof DECOMPOSITION_TRANSITION_PHASES)[number];
export type DecompositionTransitionCode =
  | "ADVANCED"
  | "MALFORMED_OR_UNKNOWN_FIELD"
  | "ILLEGAL_PHASE_EDGE"
  | "NON_AUTHORITATIVE_FIXTURE"
  | "CANONICAL_WRITER_FENCED"
  | "APPROVED_GRAPH_MUTATED"
  | "STALE_DERIVATION";
export type DecompositionDerivedAuthorityKind =
  | "architecture"
  | "decomposition"
  | "owner_approval"
  | "ticket_activation";

export interface DecompositionTransitionAuthorityV1 {
  readonly schema_version: 1;
  readonly evaluation_mode: "LIVE" | "FIXTURE";
  readonly canonical_writer_id: string;
  readonly canonical_writer_generation: string;
}

export interface DecompositionDerivedAuthorityV1 {
  readonly digest: string;
  readonly depends_on: readonly string[];
  readonly status: "ACTIVE" | "STALE_DERIVATION";
}

export interface DecompositionTransitionStateV1 {
  readonly schema_version: 1;
  readonly phase: DecompositionTransitionPhase;
  readonly approved_graph_digest: string;
  readonly active_generation: string;
  readonly derived_authorities: Readonly<
    Record<DecompositionDerivedAuthorityKind, DecompositionDerivedAuthorityV1>
  >;
}

export type DecompositionAuthorityContextV1 =
  | {
      readonly kind: "n1";
      readonly principal_id: string;
      readonly custody_id: string;
      readonly organization_services: "ABSENT";
    }
  | {
      readonly kind: "enterprise";
      readonly organization_id: string;
      readonly actor_id: string;
      readonly role_id: string;
      readonly separation_policy_id: string;
      readonly local_owner_substitution: false;
    };

export interface DecompositionTransitionProposalV1 {
  readonly schema_version: 1;
  readonly from_phase: DecompositionTransitionPhase;
  readonly to_phase: DecompositionTransitionPhase;
  readonly writer_id: string;
  readonly writer_generation: string;
  readonly observed_graph_digest: string;
  readonly expected_generation: string;
  readonly record_class: "CANONICAL" | "FIXTURE";
  readonly authority_context: DecompositionAuthorityContextV1;
}

export interface DecompositionTransitionResultV1 {
  readonly code: DecompositionTransitionCode;
  readonly advanced: boolean;
  readonly state: DecompositionTransitionStateV1 | null;
  readonly stale_descendants: readonly DecompositionDerivedAuthorityKind[];
  readonly owner_stop: "APPROVED_GRAPH_AMENDMENT_REQUIRES_OWNER" | null;
}

const PHASES = new Set<string>(DECOMPOSITION_TRANSITION_PHASES);
const EDGES = new Set(
  DECOMPOSITION_TRANSITION_PHASES.slice(0, -1).map(
    (phase, index) => `${phase}->${DECOMPOSITION_TRANSITION_PHASES[index + 1]}`,
  ),
);
const DERIVED: readonly DecompositionDerivedAuthorityKind[] = [
  "architecture",
  "decomposition",
  "owner_approval",
  "ticket_activation",
];
const HEX = /^[a-f0-9]{64}$/u;
const GENERATION = /^sha256:[a-f0-9]{64}$/u;

const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const exact = (value: Record<string, unknown>, keys: readonly string[]) => {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
};
const nonempty = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0;
const strings = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every(nonempty);

function validContext(value: unknown): value is DecompositionAuthorityContextV1 {
  if (!object(value)) return false;
  if (value.kind === "n1")
    return (
      exact(value, [
        "kind",
        "principal_id",
        "custody_id",
        "organization_services",
      ]) &&
      nonempty(value.principal_id) &&
      nonempty(value.custody_id) &&
      value.organization_services === "ABSENT"
    );
  if (value.kind === "enterprise")
    return (
      exact(value, [
        "kind",
        "organization_id",
        "actor_id",
        "role_id",
        "separation_policy_id",
        "local_owner_substitution",
      ]) &&
      nonempty(value.organization_id) &&
      nonempty(value.actor_id) &&
      nonempty(value.role_id) &&
      nonempty(value.separation_policy_id) &&
      value.local_owner_substitution === false
    );
  return false;
}

function validAuthority(
  value: unknown,
): value is DecompositionTransitionAuthorityV1 {
  return (
    object(value) &&
    exact(value, [
      "schema_version",
      "evaluation_mode",
      "canonical_writer_id",
      "canonical_writer_generation",
    ]) &&
    value.schema_version === 1 &&
    ["LIVE", "FIXTURE"].includes(value.evaluation_mode as string) &&
    nonempty(value.canonical_writer_id) &&
    typeof value.canonical_writer_generation === "string" &&
    GENERATION.test(value.canonical_writer_generation)
  );
}

function validState(value: unknown): value is DecompositionTransitionStateV1 {
  if (
    !object(value) ||
    !exact(value, [
      "schema_version",
      "phase",
      "approved_graph_digest",
      "active_generation",
      "derived_authorities",
    ]) ||
    value.schema_version !== 1 ||
    !PHASES.has(value.phase as string) ||
    typeof value.approved_graph_digest !== "string" ||
    !HEX.test(value.approved_graph_digest) ||
    typeof value.active_generation !== "string" ||
    !GENERATION.test(value.active_generation) ||
    !object(value.derived_authorities) ||
    !exact(value.derived_authorities, DERIVED)
  )
    return false;
  const derived = value.derived_authorities as Record<string, unknown>;
  return DERIVED.every((kind) => {
    const item = derived[kind];
    return (
      object(item) &&
      exact(item, ["digest", "depends_on", "status"]) &&
      typeof item.digest === "string" &&
      HEX.test(item.digest) &&
      strings(item.depends_on) &&
      ["ACTIVE", "STALE_DERIVATION"].includes(item.status as string)
    );
  });
}

function validProposal(
  value: unknown,
): value is DecompositionTransitionProposalV1 {
  return (
    object(value) &&
    exact(value, [
      "schema_version",
      "from_phase",
      "to_phase",
      "writer_id",
      "writer_generation",
      "observed_graph_digest",
      "expected_generation",
      "record_class",
      "authority_context",
    ]) &&
    value.schema_version === 1 &&
    PHASES.has(value.from_phase as string) &&
    PHASES.has(value.to_phase as string) &&
    nonempty(value.writer_id) &&
    typeof value.writer_generation === "string" &&
    GENERATION.test(value.writer_generation) &&
    typeof value.observed_graph_digest === "string" &&
    HEX.test(value.observed_graph_digest) &&
    typeof value.expected_generation === "string" &&
    GENERATION.test(value.expected_generation) &&
    ["CANONICAL", "FIXTURE"].includes(value.record_class as string) &&
    validContext(value.authority_context)
  );
}

function result(
  code: DecompositionTransitionCode,
  state: DecompositionTransitionStateV1 | null,
  stale: readonly DecompositionDerivedAuthorityKind[] = [],
  ownerStop: "APPROVED_GRAPH_AMENDMENT_REQUIRES_OWNER" | null = null,
): DecompositionTransitionResultV1 {
  return {
    code,
    advanced: code === "ADVANCED",
    state,
    stale_descendants: stale,
    owner_stop: ownerStop,
  };
}

export function evaluateDecompositionTransition(
  stateInput: unknown,
  proposalInput: unknown,
  authorityInput: unknown,
): DecompositionTransitionResultV1 {
  const stateValid = validState(stateInput);
  if (
    !stateValid ||
    !validProposal(proposalInput) ||
    !validAuthority(authorityInput)
  )
    return result(
      "MALFORMED_OR_UNKNOWN_FIELD",
      stateValid ? structuredClone(stateInput) : null,
    );

  const state = structuredClone(stateInput);
  const proposal = proposalInput;
  const authority = authorityInput;
  if (!EDGES.has(`${proposal.from_phase}->${proposal.to_phase}`))
    return result("ILLEGAL_PHASE_EDGE", state);
  if (
    authority.evaluation_mode === "LIVE" &&
    proposal.record_class === "FIXTURE"
  )
    return result("NON_AUTHORITATIVE_FIXTURE", state);
  if (
    proposal.writer_id !== authority.canonical_writer_id ||
    proposal.writer_generation !== authority.canonical_writer_generation
  )
    return result("CANONICAL_WRITER_FENCED", state);
  if (proposal.observed_graph_digest !== state.approved_graph_digest) {
    const stale: DecompositionDerivedAuthorityKind[] = [];
    const derived = { ...state.derived_authorities };
    for (const kind of DERIVED) {
      if (derived[kind].status === "ACTIVE") {
        derived[kind] = {
          ...derived[kind],
          status: "STALE_DERIVATION",
        };
        stale.push(kind);
      }
    }
    return result(
      "APPROVED_GRAPH_MUTATED",
      { ...state, derived_authorities: derived },
      stale,
      "APPROVED_GRAPH_AMENDMENT_REQUIRES_OWNER",
    );
  }
  if (
    proposal.from_phase !== state.phase ||
    proposal.expected_generation !== state.active_generation ||
    DERIVED.some(
      (kind) => state.derived_authorities[kind].status === "STALE_DERIVATION",
    )
  )
    return result("STALE_DERIVATION", state);
  return result("ADVANCED", { ...state, phase: proposal.to_phase });
}
