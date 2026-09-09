import type {
  DecompositionAuthorityContextV1,
  DecompositionTransitionResultV1,
} from "./decomposition_transition.js";

export type TicketDenial =
  | "NON_EXECUTABLE_NODE"
  | "TICKET_NOT_COHERENT"
  | "TICKET_SURFACE_UNBOUNDED"
  | "TICKET_NOT_FEASIBLE"
  | "TRACK_AUTHORITY_INVALID"
  | "PREDECESSOR_TRANSITION_INVALID";

export type ExecutableOutcomeKind =
  | "PRODUCT_CHANGE"
  | "PLAN"
  | "INVENTORY"
  | "FUTURE_DECOMPOSITION"
  | "RECONCILIATION"
  | "SUCCESSOR_CREATION";

export interface ExecutableTicketBodyV1 {
  readonly schema_version: 1;
  readonly node_kind: "EXECUTABLE_LEAF";
  readonly ticket_id: string;
  readonly title: string;
  readonly outcomes: readonly {
    readonly kind: ExecutableOutcomeKind;
    readonly statement: string;
    readonly invariant: string;
  }[];
  readonly scope_ids: readonly string[];
  readonly requirements: readonly string[];
  readonly threats: readonly string[];
  readonly mutation_surface: readonly string[];
  readonly effect_surface: readonly string[];
  readonly cases: readonly {
    readonly id: string;
    readonly input: string;
    readonly oracle: string;
    readonly classification: string;
  }[];
  readonly resources: {
    readonly max_changed_subsystems: number;
    readonly focused_test_minutes: number;
    readonly full_closure_minutes: number;
    readonly max_new_runtime_dependencies: 0;
    readonly fixed_case_count: number;
  };
  readonly ambiguities: readonly string[];
  readonly closure: {
    readonly profile: "FULL_KEEP_EXACT_COMMIT_V1";
    readonly steps: readonly {
      readonly id: string;
      readonly command: string;
      readonly maximum_minutes: number;
    }[];
    readonly source_push: true;
    readonly source_readback: true;
    readonly package_push: true;
    readonly package_readback: true;
    readonly blank_install: true;
    readonly n1_journey: true;
    readonly enterprise_journey: true;
  };
  readonly authority:
    | {
        readonly kind: "owner";
        readonly owner_id: string;
        readonly custody_id: string;
      }
    | {
        readonly kind: "organization";
        readonly organization_id: string;
        readonly actor_id: string;
        readonly role_id: string;
        readonly separation_policy_id: string;
        readonly custody_evidence_digest: string;
        readonly isolation_evidence_digest: string;
      };
}

export interface TicketAdmissionScopeV1 {
  readonly ticket_id: string;
  readonly ticket_body_digest: string;
  readonly approved_graph_digest: string;
  readonly active_generation: string;
}

export interface AdmittedTicketAuthorityV1 {
  readonly status: "EXECUTABLE_TICKET_ADMITTED";
  readonly ticket_id: string;
  readonly ticket_body_digest: string;
  readonly track: "n1" | "enterprise";
  readonly body: ExecutableTicketBodyV1;
}

export type TicketAdmissionResult =
  | { readonly admitted: true; readonly authority: AdmittedTicketAuthorityV1 }
  | { readonly admitted: false; readonly denial: TicketDenial };

const BODY_KEYS = [
  "ambiguities",
  "authority",
  "cases",
  "closure",
  "effect_surface",
  "mutation_surface",
  "node_kind",
  "outcomes",
  "requirements",
  "resources",
  "schema_version",
  "scope_ids",
  "threats",
  "ticket_id",
  "title",
] as const;
const OUTCOME_KEYS = ["invariant", "kind", "statement"] as const;
const CASE_KEYS = ["classification", "id", "input", "oracle"] as const;
const RESOURCE_KEYS = [
  "fixed_case_count",
  "focused_test_minutes",
  "full_closure_minutes",
  "max_changed_subsystems",
  "max_new_runtime_dependencies",
] as const;
const CLOSURE_KEYS = [
  "blank_install",
  "enterprise_journey",
  "n1_journey",
  "package_push",
  "package_readback",
  "profile",
  "source_push",
  "source_readback",
  "steps",
] as const;
const STEP_KEYS = ["command", "id", "maximum_minutes"] as const;
const SCOPE_KEYS = [
  "active_generation",
  "approved_graph_digest",
  "ticket_body_digest",
  "ticket_id",
] as const;
const RESULT_KEYS = [
  "advanced",
  "code",
  "owner_stop",
  "stale_descendants",
  "state",
] as const;
const STATE_KEYS = [
  "active_generation",
  "approved_graph_digest",
  "derived_authorities",
  "phase",
  "schema_version",
] as const;
const DERIVED_AUTHORITY_KEYS = [
  "architecture",
  "decomposition",
  "owner_approval",
  "ticket_activation",
] as const;
const DERIVED_KEYS = ["depends_on", "digest", "status"] as const;
const HEX = /^[a-f0-9]{64}$/u;
const GENERATION = /^sha256:[a-f0-9]{64}$/u;
const PATH_PLACEHOLDER =
  /(^|[\s:/_-])(related|unnamed)([\s:/_-]|$)|as\s+needed/iu;
const GLOB_OR_TRAVERSAL = /[*?\[\]{}]|(^|[/\\])\.\.($|[/\\])/u;

const object = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const exact = (value: Record<string, unknown>, keys: readonly string[]) => {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
};
const nonempty = (value: unknown): value is string =>
  typeof value === "string" && value.trim().length > 0;
const positiveInteger = (value: unknown): value is number =>
  Number.isSafeInteger(value) && (value as number) > 0;
const uniqueNonempty = (value: unknown): value is string[] =>
  Array.isArray(value) &&
  value.length > 0 &&
  value.every(nonempty) &&
  new Set(value).size === value.length;
const clone = <T>(value: T): T => structuredClone(value);
const freeze = <T>(value: T): T => {
  if (value && typeof value === "object") {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>))
      freeze(child);
  }
  return value;
};
const deny = (denial: TicketDenial): TicketAdmissionResult => ({
  admitted: false,
  denial,
});

function recognizedProjection(value: Record<string, unknown>): boolean {
  if (
    ["ROADMAP", "ROLLUP", "SUCCESSOR_PROMISE"].includes(
      value.node_kind as string,
    )
  )
    return true;
  const keys = Object.keys(value);
  return (
    keys.every((key) =>
      ["ticket_id", "title", "summary", "node_kind"].includes(key),
    ) &&
    ("title" in value || "summary" in value)
  );
}

function coherent(body: Record<string, unknown>): boolean {
  if (!Array.isArray(body.outcomes) || body.outcomes.length !== 1) return false;
  const outcome = body.outcomes[0];
  if (
    !object(outcome) ||
    !exact(outcome, OUTCOME_KEYS) ||
    !nonempty(outcome.statement) ||
    !nonempty(outcome.invariant)
  )
    return false;
  if (![body.scope_ids, body.requirements, body.threats].every(uniqueNonempty))
    return false;
  if (!Array.isArray(body.ambiguities) || body.ambiguities.length !== 0)
    return false;
  return true;
}

function boundedSurface(value: unknown): value is string[] {
  return (
    uniqueNonempty(value) &&
    value.every(
      (entry) =>
        !GLOB_OR_TRAVERSAL.test(entry) && !PATH_PLACEHOLDER.test(entry),
    )
  );
}

function feasible(body: Record<string, unknown>): boolean {
  if (!Array.isArray(body.cases) || body.cases.length === 0) return false;
  const caseIds = new Set<string>();
  for (const item of body.cases) {
    if (
      !object(item) ||
      !exact(item, CASE_KEYS) ||
      ![item.id, item.input, item.oracle, item.classification].every(
        nonempty,
      ) ||
      caseIds.has(item.id as string)
    )
      return false;
    caseIds.add(item.id as string);
  }
  if (!object(body.resources) || !exact(body.resources, RESOURCE_KEYS))
    return false;
  const resources = body.resources;
  if (
    !positiveInteger(resources.max_changed_subsystems) ||
    !positiveInteger(resources.focused_test_minutes) ||
    !positiveInteger(resources.full_closure_minutes) ||
    resources.max_new_runtime_dependencies !== 0 ||
    !positiveInteger(resources.fixed_case_count) ||
    !Array.isArray(body.cases) ||
    resources.fixed_case_count !== body.cases.length
  )
    return false;
  if (!object(body.closure) || !exact(body.closure, CLOSURE_KEYS)) return false;
  const closure = body.closure;
  if (
    closure.profile !== "FULL_KEEP_EXACT_COMMIT_V1" ||
    ![
      closure.source_push,
      closure.source_readback,
      closure.package_push,
      closure.package_readback,
      closure.blank_install,
      closure.n1_journey,
      closure.enterprise_journey,
    ].every((value) => value === true) ||
    !Array.isArray(closure.steps) ||
    closure.steps.length === 0
  )
    return false;
  const ids = new Set<string>();
  let maximum = 0;
  for (const step of closure.steps) {
    if (
      !object(step) ||
      !exact(step, STEP_KEYS) ||
      !nonempty(step.id) ||
      !nonempty(step.command) ||
      !positiveInteger(step.maximum_minutes) ||
      ids.has(step.id)
    )
      return false;
    ids.add(step.id);
    maximum += step.maximum_minutes as number;
    if (!Number.isSafeInteger(maximum)) return false;
  }
  return maximum <= (resources.full_closure_minutes as number);
}

function validAuthority(
  body: Record<string, unknown>,
  context: unknown,
): context is DecompositionAuthorityContextV1 {
  if (!object(body.authority) || !object(context)) return false;
  const authority = body.authority;
  if (authority.kind === "owner") {
    return (
      exact(authority, ["custody_id", "kind", "owner_id"]) &&
      nonempty(authority.owner_id) &&
      nonempty(authority.custody_id) &&
      exact(context, [
        "custody_id",
        "kind",
        "organization_services",
        "principal_id",
      ]) &&
      context.kind === "n1" &&
      context.organization_services === "ABSENT" &&
      context.principal_id === authority.owner_id &&
      context.custody_id === authority.custody_id
    );
  }
  if (authority.kind === "organization") {
    return (
      exact(authority, [
        "actor_id",
        "custody_evidence_digest",
        "isolation_evidence_digest",
        "kind",
        "organization_id",
        "role_id",
        "separation_policy_id",
      ]) &&
      [
        authority.organization_id,
        authority.actor_id,
        authority.role_id,
        authority.separation_policy_id,
      ].every(nonempty) &&
      typeof authority.custody_evidence_digest === "string" &&
      HEX.test(authority.custody_evidence_digest) &&
      typeof authority.isolation_evidence_digest === "string" &&
      HEX.test(authority.isolation_evidence_digest) &&
      exact(context, [
        "actor_id",
        "kind",
        "local_owner_substitution",
        "organization_id",
        "role_id",
        "separation_policy_id",
      ]) &&
      context.kind === "enterprise" &&
      context.local_owner_substitution === false &&
      context.organization_id === authority.organization_id &&
      context.actor_id === authority.actor_id &&
      context.role_id === authority.role_id &&
      context.separation_policy_id === authority.separation_policy_id
    );
  }
  return false;
}

function validScope(value: unknown): value is TicketAdmissionScopeV1 {
  return (
    object(value) &&
    exact(value, SCOPE_KEYS) &&
    nonempty(value.ticket_id) &&
    typeof value.ticket_body_digest === "string" &&
    HEX.test(value.ticket_body_digest) &&
    typeof value.approved_graph_digest === "string" &&
    HEX.test(value.approved_graph_digest) &&
    typeof value.active_generation === "string" &&
    GENERATION.test(value.active_generation)
  );
}

function validTransition(
  value: unknown,
  scope: TicketAdmissionScopeV1,
): value is DecompositionTransitionResultV1 {
  if (
    !object(value) ||
    !exact(value, RESULT_KEYS) ||
    value.code !== "ADVANCED" ||
    value.advanced !== true ||
    value.owner_stop !== null ||
    !Array.isArray(value.stale_descendants) ||
    value.stale_descendants.length !== 0 ||
    !object(value.state) ||
    !exact(value.state, STATE_KEYS)
  )
    return false;
  const state = value.state;
  if (
    state.schema_version !== 1 ||
    state.phase !== "FIRST_TICKET_RESEARCH_AUTHORIZED" ||
    state.approved_graph_digest !== scope.approved_graph_digest ||
    state.active_generation !== scope.active_generation ||
    !object(state.derived_authorities) ||
    !exact(state.derived_authorities, DERIVED_AUTHORITY_KEYS)
  )
    return false;
  const derived = state.derived_authorities as Record<string, unknown>;
  return DERIVED_AUTHORITY_KEYS.every((kind) => {
    const item = derived[kind];
    return (
      object(item) &&
      exact(item, DERIVED_KEYS) &&
      typeof item.digest === "string" &&
      HEX.test(item.digest) &&
      uniqueNonempty(item.depends_on) &&
      item.status === "ACTIVE"
    );
  });
}

export function admitExecutableTicket(
  candidate: unknown,
  transition_result: unknown,
  authority_context: unknown,
  scope: unknown,
): TicketAdmissionResult {
  if (
    !object(candidate) ||
    !exact(candidate, BODY_KEYS) ||
    recognizedProjection(candidate) ||
    candidate.schema_version !== 1 ||
    candidate.node_kind !== "EXECUTABLE_LEAF" ||
    !nonempty(candidate.ticket_id) ||
    !nonempty(candidate.title)
  )
    return deny("NON_EXECUTABLE_NODE");
  const outcome = Array.isArray(candidate.outcomes)
    ? candidate.outcomes[0]
    : null;
  if (object(outcome) && outcome.kind !== "PRODUCT_CHANGE")
    return deny("NON_EXECUTABLE_NODE");
  if (!coherent(candidate)) return deny("TICKET_NOT_COHERENT");
  if (
    !boundedSurface(candidate.mutation_surface) ||
    !boundedSurface(candidate.effect_surface)
  )
    return deny("TICKET_SURFACE_UNBOUNDED");
  if (!feasible(candidate)) return deny("TICKET_NOT_FEASIBLE");
  if (!validAuthority(candidate, authority_context))
    return deny("TRACK_AUTHORITY_INVALID");
  if (
    !validScope(scope) ||
    candidate.ticket_id !== scope.ticket_id ||
    !validTransition(transition_result, scope)
  )
    return deny("PREDECESSOR_TRANSITION_INVALID");
  const body = freeze(clone(candidate as unknown as ExecutableTicketBodyV1));
  return {
    admitted: true,
    authority: freeze({
      status: "EXECUTABLE_TICKET_ADMITTED",
      ticket_id: body.ticket_id,
      ticket_body_digest: scope.ticket_body_digest,
      track: (authority_context as DecompositionAuthorityContextV1).kind,
      body,
    }),
  };
}
