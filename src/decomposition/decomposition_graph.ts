import { createHash } from "node:crypto";

import type { DecompositionAuthorityContextV1 } from "./decomposition_transition.js";
import type { AdmittedTicketAuthorityV1 } from "./ticket_contract.js";

export type DecompositionGraphDenial =
  | "DEPENDENCY_INVALID"
  | "COVERAGE_ORPHAN"
  | "TRACK_AUTHORITY_INVALID"
  | "PREREQUISITE_AUTHORITY_INVALID"
  | "STALE_DERIVATION";

export type CoverageClassV1 =
  | "scope"
  | "research"
  | "requirement"
  | "threat_control"
  | "test"
  | "track"
  | "surface"
  | "retained_work";

export interface DecompositionGraphCandidateV1 {
  readonly schema_version: 1;
  readonly graph_id: string;
  readonly generation: string;
  readonly node_inventory_digest: string;
  readonly candidate_digest: string;
  readonly nodes: readonly GraphNodeV1[];
  readonly dependency_edges: readonly DependencyEdgeV1[];
  readonly coverage_universes: CoverageUniversesV1;
  readonly coverage_relations: readonly CoverageRelationV1[];
  readonly trace_relations: readonly TraceRelationV1[];
  readonly node_coverage: readonly NodeCoverageV1[];
  readonly track_authority: GraphTrackAuthorityV1;
}

export interface GraphNodeV1 {
  readonly ticket_id: string;
  readonly ticket_body_digest: string;
}

export interface DependencyEdgeV1 {
  readonly upstream_ticket_id: string;
  readonly downstream_ticket_id: string;
  readonly required_receipt_class: "FULL_KEEP_EXACT_COMMIT_V1_TICKET_CLOSURE";
  readonly consumed_behavior: string;
}

export type CoverageUniversesV1 = Readonly<Record<CoverageClassV1, readonly string[]>>;

export interface CoverageRelationV1 {
  readonly coverage_class: CoverageClassV1;
  readonly item_id: string;
  readonly ticket_id: string;
}

export interface TraceRelationV1 {
  readonly from_class: "research" | "scope";
  readonly from_item_id: string;
  readonly to_class: "surface" | "threat_control" | "test" | "retained_work";
  readonly to_item_id: string;
}

export interface NodeCoverageV1 extends CoverageUniversesV1 {
  readonly ticket_id: string;
}

export type GraphTrackAuthorityV1 =
  | { readonly kind: "owner"; readonly owner_id: string; readonly custody_id: string }
  | {
      readonly kind: "organization";
      readonly organization_id: string;
      readonly actor_id: string;
      readonly role_id: string;
      readonly separation_policy_id: string;
      readonly custody_evidence_digest: string;
      readonly isolation_evidence_digest: string;
    };

export interface GraphPrerequisiteV1 {
  readonly closure_bytes: string;
  readonly closure_digest: string;
  readonly product_commit: string;
  readonly closure_profile: "FULL_KEEP_EXACT_COMMIT_V1";
}

export interface AdmittedDecompositionGraphAuthorityV1 {
  readonly status: "DECOMPOSITION_GRAPH_ADMITTED";
  readonly graph_id: string;
  readonly generation: string;
  readonly candidate_digest: string;
  readonly node_inventory_digest: string;
  readonly prerequisite_closure_digest: string;
  readonly track: "n1" | "enterprise";
  readonly graph: DecompositionGraphCandidateV1;
}

export type DecompositionGraphAdmissionResult =
  | { readonly admitted: true; readonly authority: AdmittedDecompositionGraphAuthorityV1 }
  | { readonly admitted: false; readonly denial: DecompositionGraphDenial };

const EXPECTED_CLOSURE_DIGEST = "faa4b817a6769d8de78dca233b2d090472d8cc05d08bde07ea9dccd22cfa30e5";
const EXPECTED_PRODUCT_COMMIT = "79676b4f9134a3b12af6af734eed3c48f23ffc22";
const PROFILE = "FULL_KEEP_EXACT_COMMIT_V1";
const RECEIPT_CLASS = "FULL_KEEP_EXACT_COMMIT_V1_TICKET_CLOSURE";
const HEX = /^[a-f0-9]{64}$/u;
const GENERATION = /^sha256:[a-f0-9]{64}$/u;
const CLASSES = ["scope", "research", "requirement", "threat_control", "test", "track", "surface", "retained_work"] as const;
const DESTINATIONS = ["surface", "threat_control", "test", "retained_work"] as const;
const ORDER_ONLY = new Set(["before", "after", "then", "next", "blocks", "blocked by", "depends on", "prerequisite", "for ordering only"]);
const ROOT_KEYS = ["candidate_digest", "coverage_relations", "coverage_universes", "dependency_edges", "generation", "graph_id", "node_coverage", "node_inventory_digest", "nodes", "schema_version", "trace_relations", "track_authority"];
const NODE_KEYS = ["ticket_body_digest", "ticket_id"];
const EDGE_KEYS = ["consumed_behavior", "downstream_ticket_id", "required_receipt_class", "upstream_ticket_id"];
const COVERAGE_KEYS = [...CLASSES];
const NODE_COVERAGE_KEYS = [...CLASSES, "ticket_id"];
const COVERAGE_RELATION_KEYS = ["coverage_class", "item_id", "ticket_id"];
const TRACE_KEYS = ["from_class", "from_item_id", "to_class", "to_item_id"];
const PREREQUISITE_KEYS = ["closure_bytes", "closure_digest", "closure_profile", "product_commit"];
const ADMITTED_KEYS = ["body", "status", "ticket_body_digest", "ticket_id", "track"];
const OWNER_KEYS = ["custody_id", "kind", "owner_id"];
const ORGANIZATION_KEYS = ["actor_id", "custody_evidence_digest", "isolation_evidence_digest", "kind", "organization_id", "role_id", "separation_policy_id"];
const N1_CONTEXT_KEYS = ["custody_id", "kind", "organization_services", "principal_id"];
const ENTERPRISE_CONTEXT_KEYS = ["actor_id", "kind", "local_owner_substitution", "organization_id", "role_id", "separation_policy_id"];

const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const exact = (value: Record<string, unknown>, keys: readonly string[]) => {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
};
const nonempty = (value: unknown): value is string => typeof value === "string" && value.trim().length > 0;
const uniqueNonempty = (value: unknown): value is string[] => Array.isArray(value) && value.length > 0 && value.every(nonempty) && new Set(value).size === value.length;
const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");
const canonical = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (object(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
};
const clone = <T>(value: T): T => structuredClone(value);
const freeze = <T>(value: T): T => {
  if (value && typeof value === "object") {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) freeze(child);
  }
  return value;
};
const deny = (denial: DecompositionGraphDenial): DecompositionGraphAdmissionResult => ({ admitted: false, denial });
const normalize = (value: string) => value.trim().toLowerCase().replace(/[\t\n\r ]+/gu, " ");
const compare = (left: string, right: string) => left < right ? -1 : left > right ? 1 : 0;
const nodeOrder = (left: GraphNodeV1, right: GraphNodeV1) => compare(left.ticket_id, right.ticket_id) || compare(left.ticket_body_digest, right.ticket_body_digest);
const inventoryDigest = (nodes: readonly GraphNodeV1[]) => sha256(canonical([...nodes].sort(nodeOrder)));
export const decompositionGraphCandidateDigest = (candidate: Omit<DecompositionGraphCandidateV1, "candidate_digest"> | DecompositionGraphCandidateV1) => {
  const projection = { ...(candidate as unknown as Record<string, unknown>) };
  delete projection.candidate_digest;
  return sha256(canonical(projection));
};

function validAdmittedNodes(value: unknown): value is AdmittedTicketAuthorityV1[] {
  if (!Array.isArray(value) || value.length === 0) return false;
  const identities = new Set<string>();
  for (const item of value) {
    if (!object(item) || !exact(item, ADMITTED_KEYS) || item.status !== "EXECUTABLE_TICKET_ADMITTED" || !nonempty(item.ticket_id) || typeof item.ticket_body_digest !== "string" || !HEX.test(item.ticket_body_digest) || !["n1", "enterprise"].includes(item.track as string) || !object(item.body) || item.body.ticket_id !== item.ticket_id) return false;
    const identity = `${item.ticket_id}:${item.ticket_body_digest}`;
    if (identities.has(identity)) return false;
    identities.add(identity);
  }
  return true;
}

function validGraphShape(candidate: unknown, admittedNodes: unknown): candidate is DecompositionGraphCandidateV1 {
  if (!object(candidate) || !exact(candidate, ROOT_KEYS) || candidate.schema_version !== 1 || !nonempty(candidate.graph_id) || typeof candidate.generation !== "string" || !GENERATION.test(candidate.generation) || typeof candidate.node_inventory_digest !== "string" || !HEX.test(candidate.node_inventory_digest) || typeof candidate.candidate_digest !== "string" || !HEX.test(candidate.candidate_digest) || !validAdmittedNodes(admittedNodes)) return false;
  if (!Array.isArray(candidate.nodes) || candidate.nodes.length === 0) return false;
  const nodes: GraphNodeV1[] = [];
  const nodeIds = new Set<string>();
  for (const item of candidate.nodes) {
    if (!object(item) || !exact(item, NODE_KEYS) || !nonempty(item.ticket_id) || typeof item.ticket_body_digest !== "string" || !HEX.test(item.ticket_body_digest) || nodeIds.has(item.ticket_id)) return false;
    nodeIds.add(item.ticket_id); nodes.push(item as unknown as GraphNodeV1);
  }
  const supplied = (admittedNodes as AdmittedTicketAuthorityV1[]).map(({ ticket_id, ticket_body_digest }) => ({ ticket_id, ticket_body_digest })).sort(nodeOrder);
  if (canonical([...nodes].sort(nodeOrder)) !== canonical(supplied) || candidate.node_inventory_digest !== inventoryDigest(nodes)) return false;
  if (!Array.isArray(candidate.dependency_edges)) return false;
  const pairs = new Set<string>();
  const indegree = new Map([...nodeIds].map((id) => [id, 0]));
  const outgoing = new Map([...nodeIds].map((id) => [id, [] as string[]]));
  for (const edge of candidate.dependency_edges) {
    if (!object(edge) || !exact(edge, EDGE_KEYS) || !nonempty(edge.upstream_ticket_id) || !nonempty(edge.downstream_ticket_id) || edge.upstream_ticket_id === edge.downstream_ticket_id || !nodeIds.has(edge.upstream_ticket_id) || !nodeIds.has(edge.downstream_ticket_id) || edge.required_receipt_class !== RECEIPT_CLASS || !nonempty(edge.consumed_behavior) || ORDER_ONLY.has(normalize(edge.consumed_behavior))) return false;
    const pair = `${edge.upstream_ticket_id}\u0000${edge.downstream_ticket_id}`;
    if (pairs.has(pair)) return false;
    pairs.add(pair); outgoing.get(edge.upstream_ticket_id)?.push(edge.downstream_ticket_id); indegree.set(edge.downstream_ticket_id, (indegree.get(edge.downstream_ticket_id) ?? 0) + 1);
  }
  const ready = [...nodeIds].filter((id) => indegree.get(id) === 0).sort();
  let visited = 0;
  while (ready.length) {
    const id = ready.shift() as string; visited += 1;
    for (const target of [...(outgoing.get(id) ?? [])].sort()) {
      const next = (indegree.get(target) ?? 0) - 1; indegree.set(target, next);
      if (next === 0) { ready.push(target); ready.sort(); }
    }
  }
  return visited === nodeIds.size;
}

function validCoverage(candidate: DecompositionGraphCandidateV1): boolean {
  if (!object(candidate.coverage_universes) || !exact(candidate.coverage_universes as unknown as Record<string, unknown>, COVERAGE_KEYS)) return false;
  const universes = new Map<CoverageClassV1, Set<string>>();
  for (const name of CLASSES) {
    const values = candidate.coverage_universes[name];
    if (!uniqueNonempty(values)) return false;
    universes.set(name, new Set(values));
  }
  const nodeIds = new Set(candidate.nodes.map((node) => node.ticket_id));
  if (!Array.isArray(candidate.coverage_relations) || !Array.isArray(candidate.node_coverage) || candidate.node_coverage.length !== nodeIds.size) return false;
  const relations = new Set<string>();
  const coveredItems = new Map<CoverageClassV1, Set<string>>(CLASSES.map((name) => [name, new Set()]));
  for (const relation of candidate.coverage_relations) {
    if (!object(relation) || !exact(relation, COVERAGE_RELATION_KEYS) || !CLASSES.includes(relation.coverage_class as CoverageClassV1) || !nonempty(relation.item_id) || !nonempty(relation.ticket_id)) return false;
    const name = relation.coverage_class as CoverageClassV1;
    if (!universes.get(name)?.has(relation.item_id) || !nodeIds.has(relation.ticket_id)) return false;
    const key = `${name}\u0000${relation.item_id}\u0000${relation.ticket_id}`;
    if (relations.has(key)) return false;
    relations.add(key); coveredItems.get(name)?.add(relation.item_id);
  }
  for (const name of CLASSES) if (coveredItems.get(name)?.size !== universes.get(name)?.size) return false;
  const projection = new Set<string>();
  const projectedNodes = new Set<string>();
  for (const record of candidate.node_coverage) {
    if (!object(record) || !exact(record, NODE_COVERAGE_KEYS) || !nonempty(record.ticket_id) || !nodeIds.has(record.ticket_id) || projectedNodes.has(record.ticket_id)) return false;
    projectedNodes.add(record.ticket_id);
    for (const name of CLASSES) {
      const values = record[name];
      if (!uniqueNonempty(values) || values.some((item) => !universes.get(name)?.has(item))) return false;
      for (const item of values) projection.add(`${name}\u0000${item}\u0000${record.ticket_id}`);
    }
  }
  if (projection.size !== relations.size || [...projection].some((key) => !relations.has(key))) return false;
  if (!Array.isArray(candidate.trace_relations)) return false;
  const traces = new Set<string>();
  const incoming = new Map<string, Set<string>>();
  for (const relation of candidate.trace_relations) {
    if (!object(relation) || !exact(relation, TRACE_KEYS) || !["research", "scope"].includes(relation.from_class as string) || !DESTINATIONS.includes(relation.to_class as (typeof DESTINATIONS)[number]) || !nonempty(relation.from_item_id) || !nonempty(relation.to_item_id)) return false;
    const from = relation.from_class as "research" | "scope";
    const to = relation.to_class as (typeof DESTINATIONS)[number];
    if (!universes.get(from)?.has(relation.from_item_id) || !universes.get(to)?.has(relation.to_item_id)) return false;
    const key = `${from}\u0000${relation.from_item_id}\u0000${to}\u0000${relation.to_item_id}`;
    if (traces.has(key)) return false;
    traces.add(key);
    const target = `${to}\u0000${relation.to_item_id}`;
    const origins = incoming.get(target) ?? new Set<string>(); origins.add(from); incoming.set(target, origins);
  }
  for (const to of DESTINATIONS) for (const item of universes.get(to) ?? []) {
    const origins = incoming.get(`${to}\u0000${item}`);
    if (!origins?.has("research") || !origins.has("scope")) return false;
  }
  return true;
}

function validTrack(authority: unknown, context: unknown): context is DecompositionAuthorityContextV1 {
  if (!object(authority) || !object(context)) return false;
  if (authority.kind === "owner") return exact(authority, OWNER_KEYS) && exact(context, N1_CONTEXT_KEYS) && context.kind === "n1" && nonempty(authority.owner_id) && nonempty(authority.custody_id) && context.principal_id === authority.owner_id && context.custody_id === authority.custody_id && context.organization_services === "ABSENT";
  return authority.kind === "organization" && exact(authority, ORGANIZATION_KEYS) && exact(context, ENTERPRISE_CONTEXT_KEYS) && context.kind === "enterprise" && [authority.organization_id, authority.actor_id, authority.role_id, authority.separation_policy_id].every(nonempty) && typeof authority.custody_evidence_digest === "string" && HEX.test(authority.custody_evidence_digest) && typeof authority.isolation_evidence_digest === "string" && HEX.test(authority.isolation_evidence_digest) && context.organization_id === authority.organization_id && context.actor_id === authority.actor_id && context.role_id === authority.role_id && context.separation_policy_id === authority.separation_policy_id && context.local_owner_substitution === false;
}

function validPrerequisite(value: unknown): value is GraphPrerequisiteV1 {
  if (!object(value) || !exact(value, PREREQUISITE_KEYS) || typeof value.closure_bytes !== "string" || value.closure_digest !== EXPECTED_CLOSURE_DIGEST || sha256(value.closure_bytes) !== EXPECTED_CLOSURE_DIGEST || value.product_commit !== EXPECTED_PRODUCT_COMMIT || value.closure_profile !== PROFILE) return false;
  try {
    const receipt = JSON.parse(value.closure_bytes) as unknown;
    return object(receipt) && receipt.ticket_id === "PG-04-T002" && receipt.status === "COMPLETE" && receipt.product_commit === EXPECTED_PRODUCT_COMMIT && receipt.closure_profile === PROFILE;
  } catch { return false; }
}

export function admitDecompositionGraph(candidate: unknown, admitted_nodes: unknown, prerequisite: unknown, authority_context: unknown): DecompositionGraphAdmissionResult {
  if (!validGraphShape(candidate, admitted_nodes)) return deny("DEPENDENCY_INVALID");
  if (!validCoverage(candidate)) return deny("COVERAGE_ORPHAN");
  if (!validTrack(candidate.track_authority, authority_context)) return deny("TRACK_AUTHORITY_INVALID");
  if (!validPrerequisite(prerequisite)) return deny("PREREQUISITE_AUTHORITY_INVALID");
  if (candidate.candidate_digest !== decompositionGraphCandidateDigest(candidate)) return deny("STALE_DERIVATION");
  const track = (authority_context as DecompositionAuthorityContextV1).kind;
  return { admitted: true, authority: freeze({ status: "DECOMPOSITION_GRAPH_ADMITTED", graph_id: candidate.graph_id, generation: candidate.generation, candidate_digest: candidate.candidate_digest, node_inventory_digest: candidate.node_inventory_digest, prerequisite_closure_digest: EXPECTED_CLOSURE_DIGEST, track, graph: clone(candidate) }) };
}
