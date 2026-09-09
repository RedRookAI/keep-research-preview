/**
 * A4 capability graph v2 — runtime-safe semantic kernel.
 *
 * This module accepts no favorable ledger from a caller. It captures one bounded exact-key graph, reconciles its
 * declarations against independently produced installed observations, rejects cycles/placeholders/stale compatibility
 * rows, and derives the ledgers and claim results from that owned snapshot. Signing, package inventory collection and
 * boot/dispatch consumption are separate A4 layers over this kernel. Producer ids/domains and the verifier-current
 * clock are structural bindings here, not self-authenticating facts: the signed-closure verifier must authenticate
 * every producer binding and inject `trustedNowMs` from its own clock, never deserialize it from the closure bundle.
 */
import { types } from "node:util";
import { performance } from "node:perf_hooks";
import { eirDigest, isWellFormedText, type CanonicalValue } from "../eir/canonical.js";
import type { EnforcementStatus } from "../platform/enforcement_profile.js";

export const CAPABILITY_GRAPH_V2 = Object.freeze({ name: "keep.capability-graph", version: 2 } as const);
export const BUILT_AHEAD_COMPATIBILITY_IDS = Object.freeze([
  "profile_attestation", "tree_fingerprint", "ingress_registry", "monitor.channel", "monitor.boundary", "admission",
] as const);

export type DeploymentDomain = "D1" | "D2" | "D3" | "PROBER" | "EXTERNAL" | "NONE";
export type GraphNodeKind = "role" | "entrypoint" | "component" | "raw-sink" | "credential" | "evidence" | "claim";
export type GraphEdgeKind = "invokes" | "authenticates" | "owns" | "can-read" | "can-use" | "targets" | "depends-on" | "observed-by";
export type GraphEvidenceKind = "artifact-scan" | "reachability" | "neuter" | "installed-experiment" | "peer-measurement" | "trusted-time" | "signature" | "residual";
export type CompatibilityDisposition = "consume" | "supersede" | "retain-inert";

export interface GraphNode {
  readonly id: string;
  readonly kind: GraphNodeKind;
  readonly domain: DeploymentDomain;
  readonly module: string;
  readonly moduleDigest: string;
  readonly evidenceIds: readonly string[];
  readonly declaredAssurance: EnforcementStatus;
}

export interface GraphEdge {
  readonly id: string;
  readonly from: string;
  readonly to: string;
  readonly kind: GraphEdgeKind;
  readonly operations: readonly string[];
  readonly targetScopes: readonly string[];
  readonly evidenceIds: readonly string[];
  readonly declaredAssurance: EnforcementStatus;
}

export type EvidenceFreshness =
  | { readonly kind: "non-expiring" }
  | { readonly kind: "window"; readonly observedAtMs: bigint; readonly expiresAtMs: bigint };

export interface GraphEvidence {
  readonly id: string;
  readonly kind: GraphEvidenceKind;
  readonly subjectDigest: string;
  readonly releaseEpoch: bigint;
  readonly producerId: string;
  readonly mechanismId: string;
  readonly contentDigest: string;
  readonly subjectIds: readonly string[];
  readonly digest: string;
  readonly assurance: EnforcementStatus;
  readonly freshness: EvidenceFreshness;
}

export interface GraphClaim {
  readonly id: string;
  readonly operationIds: readonly string[];
  readonly requiredNodeIds: readonly string[];
  readonly requiredEdgeIds: readonly string[];
  readonly requiredEvidenceIds: readonly string[];
}

export interface BuiltAheadDisposition {
  readonly builtAheadId: string;
  readonly disposition: CompatibilityDisposition;
  readonly replacementOrConsumerId: string;
  readonly preservedInvariants: readonly string[];
  readonly evidenceIds: readonly string[];
  readonly nextBlockingStep: string;
}

export interface CapabilityGraphV2Input {
  readonly version: 2;
  readonly subjectDigest: string;
  readonly releaseEpoch: bigint;
  readonly declarationProducerId: string;
  readonly declarationMechanismId: string;
  readonly nodes: readonly GraphNode[];
  readonly edges: readonly GraphEdge[];
  readonly evidence: readonly GraphEvidence[];
  readonly claims: readonly GraphClaim[];
  readonly compatibility: readonly BuiltAheadDisposition[];
}

export interface CapturedCapabilityGraphV2 extends CapabilityGraphV2Input { readonly digest: string }

export interface CapabilityInventory {
  readonly rawSinks: readonly string[];
  readonly credentials: readonly string[];
  readonly effectfulEntrypoints: readonly string[];
  readonly builtAhead: readonly string[];
  readonly builtAheadConsumers: readonly string[];
  readonly modules: readonly { readonly nodeId: string; readonly module: string; readonly digest: string }[];
}

export interface InstalledCapabilityInventory {
  readonly rawSinks: readonly string[];
  readonly credentials: readonly string[];
  readonly effectfulEntrypoints: readonly string[];
  readonly modules: readonly { readonly nodeId: string; readonly module: string; readonly digest: string }[];
}

export interface InventoryObservation {
  readonly producerId: string;
  readonly mechanismId: string;
  readonly kind: "installed-runtime" | "installed-artifact" | "source-scan";
  readonly subjectDigest: string;
  readonly releaseEpoch: bigint;
  readonly evidenceId: string;
  readonly inventory: InstalledCapabilityInventory;
}

export interface ObservedWorld {
  readonly clockEvidenceId: string;
  readonly declaration: { readonly producerId: string; readonly mechanismId: string; readonly inventory: CapabilityInventory };
  readonly observations: readonly InventoryObservation[];
}

export interface CapabilityVerificationContext { readonly trustedNowMs: bigint }

export interface InventoryVerdict {
  readonly valid: boolean;
  readonly reasons: readonly string[];
  readonly observedWorldDigest: string;
}

export interface ClaimLedgerRow {
  readonly id: string;
  readonly assurance: EnforcementStatus;
  readonly taxonomyCeiling: "Specified" | "Implemented" | "Integrated" | "Load-bearing";
  readonly supported: boolean;
  readonly reasons: readonly string[];
}

export interface CapabilityLedgers {
  readonly graphDigest: string;
  readonly subjectDigest: string;
  readonly releaseEpoch: bigint;
  readonly deployment: readonly { readonly id: string; readonly kind: GraphNodeKind; readonly domain: DeploymentDomain; readonly module: string; readonly moduleDigest: string; readonly declaredAssurance: EnforcementStatus; readonly assurance: EnforcementStatus; readonly evidenceIds: readonly string[] }[];
  readonly authority: readonly { readonly resourceId: string; readonly reachableD1NodeIds: readonly string[]; readonly assurance: EnforcementStatus }[];
  readonly residuals: readonly { readonly resourceId: string; readonly d1Reachable: boolean; readonly targetScopes: readonly string[]; readonly assurance: EnforcementStatus }[];
  readonly compatibility: readonly (BuiltAheadDisposition & { readonly assurance: EnforcementStatus })[];
  readonly claims: readonly ClaimLedgerRow[];
  readonly evidence: readonly { readonly id: string; readonly kind: GraphEvidenceKind; readonly producerId: string; readonly producerDomain: DeploymentDomain; readonly mechanismId: string; readonly assurance: EnforcementStatus; readonly freshness: EvidenceFreshness; readonly consumers: readonly string[] }[];
  readonly inventory: InventoryVerdict;
  readonly verifiedAtMs: bigint | null;
  readonly diagnosticsDigest: string;
  readonly digest: string;
}

export class CapabilityGraphError extends Error {
  constructor(message: string) { super(`capability graph v2: ${message}`); this.name = "CapabilityGraphError"; }
}

const HEX64 = /^[0-9a-f]{64}$/;
const EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const ID = /^[a-z0-9][a-z0-9._/-]{0,127}$/;
const EVIDENCE_SUBJECT_ID = /^(?:node|edge|claim|inventory|clock|compatibility):[a-z0-9][a-z0-9._/-]{0,127}$/;
export const CAPABILITY_GRAPH_LIMITS = Object.freeze({
  nodes: 8_192, edges: 16_384, evidence: 16_384, claims: 2_048, compatibility: 64, observations: 64,
  list: 256, textBytes: 2_048, totalValues: 500_000, totalTextBytes: 33_554_432, canonicalDepth: 16, verificationBudgetMs: 5_000,
});
export const MAX_FRESH_EVIDENCE_TTL_MS = 86_400_000n;
const LIMITS = CAPABILITY_GRAPH_LIMITS;
const NODE_KINDS = new Set<GraphNodeKind>(["role", "entrypoint", "component", "raw-sink", "credential", "evidence", "claim"]);
const DOMAINS = new Set<DeploymentDomain>(["D1", "D2", "D3", "PROBER", "EXTERNAL", "NONE"]);
const EDGE_KINDS = new Set<GraphEdgeKind>(["invokes", "authenticates", "owns", "can-read", "can-use", "targets", "depends-on", "observed-by"]);
const EVIDENCE_KINDS = new Set<GraphEvidenceKind>(["artifact-scan", "reachability", "neuter", "installed-experiment", "peer-measurement", "trusted-time", "signature", "residual"]);
const ASSURANCE = new Set<EnforcementStatus>(["enforced", "detected-only", "unavailable", "unknown"]);
const DISPOSITIONS = new Set<CompatibilityDisposition>(["consume", "supersede", "retain-inert"]);

function preflightPlainData(input: unknown, deadline: number, label: string): void {
  let values = 0; let textBytes = 0;
  const visit = (value: unknown, depth: number): void => {
    if (++values > LIMITS.totalValues) throw new CapabilityGraphError(`${label} exceeds ${LIMITS.totalValues} total values`);
    if (performance.now() > deadline) throw new CapabilityGraphError(`${label} preflight exceeded ${LIMITS.verificationBudgetMs}ms budget`);
    if (depth > LIMITS.canonicalDepth) throw new CapabilityGraphError(`${label} exceeds canonical depth ${LIMITS.canonicalDepth}`);
    if (typeof value === "string") { textBytes += new TextEncoder().encode(value).length; if (textBytes > LIMITS.totalTextBytes) throw new CapabilityGraphError(`${label} exceeds ${LIMITS.totalTextBytes} total text bytes`); return; }
    if (value === null || typeof value === "boolean" || typeof value === "bigint" || typeof value === "number") return;
    if (typeof value !== "object" || types.isProxy(value)) throw new CapabilityGraphError(`${label} contains non-plain data`);
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype || Object.getOwnPropertySymbols(value).length !== 0 || Object.getOwnPropertyNames(value).length !== value.length + 1) throw new CapabilityGraphError(`${label} contains a sparse or extended array`);
      for (let index = 0; index < value.length; index++) { const descriptor = Object.getOwnPropertyDescriptor(value, index); if (descriptor === undefined || !descriptor.enumerable || descriptor.get || descriptor.set || !("value" in descriptor)) throw new CapabilityGraphError(`${label} contains an accessor, hole or non-enumerable array value`); visit(descriptor.value, depth + 1); }
      return;
    }
    const proto = Object.getPrototypeOf(value); if (proto !== Object.prototype && proto !== null) throw new CapabilityGraphError(`${label} contains a non-plain object`);
    if (Object.getOwnPropertySymbols(value).length !== 0) throw new CapabilityGraphError(`${label} contains symbol keys`);
    for (const key of Object.getOwnPropertyNames(value)) { const descriptor = Object.getOwnPropertyDescriptor(value, key)!; if (!descriptor.enumerable || descriptor.get || descriptor.set || !("value" in descriptor)) throw new CapabilityGraphError(`${label} contains an accessor or non-enumerable property`); visit(key, depth + 1); visit(descriptor.value, depth + 1); }
  };
  visit(input, 0);
}

function plain(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) throw new CapabilityGraphError(`${label} must be a plain object`);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) throw new CapabilityGraphError(`${label} must be a plain object`);
  if (Object.getOwnPropertySymbols(value).length !== 0) throw new CapabilityGraphError(`${label} has symbol keys`);
  const out: Record<string, unknown> = Object.create(null);
  for (const key of Object.getOwnPropertyNames(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (!descriptor.enumerable || descriptor.get || descriptor.set || !("value" in descriptor)) throw new CapabilityGraphError(`${label}.${key} is not a plain enumerable value`);
    out[key] = descriptor.value;
  }
  return out;
}

function exact(record: Record<string, unknown>, keys: readonly string[], label: string): void {
  const actual = Object.keys(record).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) throw new CapabilityGraphError(`${label} keys must be exactly ${expected.join(",")}`);
}

function list(value: unknown, limit: number, label: string): readonly unknown[] {
  if (!Array.isArray(value) || types.isProxy(value) || Object.getPrototypeOf(value) !== Array.prototype) throw new CapabilityGraphError(`${label} must be a plain array`);
  if (value.length > limit) throw new CapabilityGraphError(`${label} exceeds ${limit} records`);
  if (Object.getOwnPropertySymbols(value).length !== 0 || Object.getOwnPropertyNames(value).length !== value.length + 1) throw new CapabilityGraphError(`${label} is sparse or has extra properties`);
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (descriptor === undefined || !descriptor.enumerable || descriptor.get || descriptor.set || !("value" in descriptor)) throw new CapabilityGraphError(`${label}[${index}] is an accessor, hole or non-enumerable value`);
  }
  return value;
}

function text(value: unknown, label: string, allowEmpty = false): string {
  if (typeof value !== "string" || (!allowEmpty && value.length === 0) || new TextEncoder().encode(value).length > LIMITS.textBytes || !isWellFormedText(value) || value.normalize("NFC") !== value) throw new CapabilityGraphError(`${label} is not bounded NFC text`);
  return value;
}

function freeText(value: unknown, label: string, allowEmpty = false): string {
  const result = text(value, label, allowEmpty);
  if ((result !== "" && result.trim().length === 0) || /[\p{Cc}\p{Cf}\p{Cn}\p{Co}\p{Default_Ignorable_Code_Point}\p{Zl}\p{Zp}\u00a0\u1680\u2000-\u200a\u202f\u205f\u2800\u3000]/u.test(result)) throw new CapabilityGraphError(`${label} contains blank, control, separator, private-use, unassigned, or invisible text`);
  return result;
}

function id(value: unknown, label: string): string {
  const result = text(value, label);
  if (!ID.test(result)) throw new CapabilityGraphError(`${label} is not a stable identifier`);
  return result;
}

function digest(value: unknown, label: string): string {
  const result = text(value, label);
  if (!HEX64.test(result) || result === EMPTY_SHA256 || /^([0-9a-f])\1{63}$/.test(result)) throw new CapabilityGraphError(`${label} is not a non-placeholder SHA-256 digest`);
  return result;
}

function epoch(value: unknown, label: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > 0xffffffffffffffffn) throw new CapabilityGraphError(`${label} must be a bounded non-negative bigint`);
  return value;
}

function enumValue<T extends string>(value: unknown, choices: ReadonlySet<T>, label: string): T {
  if (typeof value !== "string" || !choices.has(value as T)) throw new CapabilityGraphError(`${label} is unsupported`);
  return value as T;
}

function stringList(value: unknown, label: string, identifiers = true, limit: number = LIMITS.list): readonly string[] {
  const values = list(value, limit, label).map((entry, index) => identifiers ? id(entry, `${label}[${index}]`) : freeText(entry, `${label}[${index}]`));
  const sorted = [...values].sort(utf8Order);
  if (new Set(values).size !== values.length) throw new CapabilityGraphError(`${label} contains duplicates`);
  return Object.freeze(sorted);
}

function evidenceSubjectList(value: unknown, label: string): readonly string[] {
  const values = list(value, LIMITS.list, label).map((entry, index) => { const result = freeText(entry, `${label}[${index}]`); if (!EVIDENCE_SUBJECT_ID.test(result)) throw new CapabilityGraphError(`${label}[${index}] is not a typed evidence subject`); return result; });
  const sorted = [...values].sort(utf8Order); if (new Set(sorted).size !== sorted.length) throw new CapabilityGraphError(`${label} contains duplicates`); return Object.freeze(sorted);
}

function targetScopeList(value: unknown, label: string): readonly string[] {
  const scopes = stringList(value, label, false);
  for (const scope of scopes) {
    const match = /^([a-z][a-z0-9.-]*):([A-Za-z0-9_~@+=,-]+(?:\.[A-Za-z0-9_~@+=,-]+)*(?:\/[A-Za-z0-9_~@+=,-]+(?:\.[A-Za-z0-9_~@+=,-]+)*)*)$/.exec(scope);
    if (match === null || match[2]!.split("/").some((segment) => segment === "." || segment === "..")) throw new CapabilityGraphError(`${label} contains a wildcard, traversal, alias, escape, or non-canonical target scope`);
  }
  return scopes;
}

function modulePath(value: unknown, label: string): string {
  const result = freeText(value, label);
  if (!/^[A-Za-z0-9_@+-]+(?:\.[A-Za-z0-9_@+-]+)*(?:\/[A-Za-z0-9_@+-]+(?:\.[A-Za-z0-9_@+-]+)*)*$/.test(result) || result.split("/").some((segment) => segment === "." || segment === "..")) throw new CapabilityGraphError(`${label} is not a canonical relative module path`);
  return result;
}

function unique<T extends { readonly id: string }>(values: readonly T[], label: string): void {
  const seen = new Set<string>();
  for (const value of values) { if (seen.has(value.id)) throw new CapabilityGraphError(`duplicate ${label} id ${value.id}`); seen.add(value.id); }
}

function uniqueCompatibility(values: readonly BuiltAheadDisposition[]): void {
  const seen = new Set<string>();
  for (const value of values) { if (seen.has(value.builtAheadId)) throw new CapabilityGraphError(`duplicate compatibility id ${value.builtAheadId}`); seen.add(value.builtAheadId); }
}

function node(value: unknown, index: number): GraphNode {
  const r = plain(value, `nodes[${index}]`); exact(r, ["id", "kind", "domain", "module", "moduleDigest", "evidenceIds", "declaredAssurance"], `nodes[${index}]`);
  const kind = enumValue(r.kind, NODE_KINDS, `nodes[${index}].kind`); const module = text(r.module, `nodes[${index}].module`, true);
  if ((kind === "entrypoint" || kind === "component" || kind === "raw-sink") !== (module !== "")) throw new CapabilityGraphError(`nodes[${index}].module must be non-empty exactly for entrypoint/component/raw-sink nodes`);
  const moduleDigest = module === "" ? text(r.moduleDigest, `nodes[${index}].moduleDigest`, true) : digest(r.moduleDigest, `nodes[${index}].moduleDigest`);
  if ((module === "") !== (moduleDigest === "")) throw new CapabilityGraphError(`nodes[${index}].moduleDigest must accompany module exactly`);
  return Object.freeze({ id: id(r.id, `nodes[${index}].id`), kind, domain: enumValue(r.domain, DOMAINS, `nodes[${index}].domain`), module: module === "" ? "" : modulePath(module, `nodes[${index}].module`), moduleDigest, evidenceIds: stringList(r.evidenceIds, `nodes[${index}].evidenceIds`), declaredAssurance: enumValue(r.declaredAssurance, ASSURANCE, `nodes[${index}].declaredAssurance`) });
}

function edge(value: unknown, index: number): GraphEdge {
  const r = plain(value, `edges[${index}]`); exact(r, ["id", "from", "to", "kind", "operations", "targetScopes", "evidenceIds", "declaredAssurance"], `edges[${index}]`);
  const kind = enumValue(r.kind, EDGE_KINDS, `edges[${index}].kind`); const operations = stringList(r.operations, `edges[${index}].operations`); const targetScopes = targetScopeList(r.targetScopes, `edges[${index}].targetScopes`);
  if (REACHABILITY_EDGE_KINDS.has(kind) && operations.length === 0) throw new CapabilityGraphError(`edges[${index}].operations must not be empty for authority/reachability edges`);
  if ((kind === "owns" || kind === "can-read" || kind === "can-use" || kind === "targets") && targetScopes.length === 0) throw new CapabilityGraphError(`edges[${index}].targetScopes must not be empty for authority edges`);
  return Object.freeze({ id: id(r.id, `edges[${index}].id`), from: id(r.from, `edges[${index}].from`), to: id(r.to, `edges[${index}].to`), kind, operations, targetScopes, evidenceIds: stringList(r.evidenceIds, `edges[${index}].evidenceIds`), declaredAssurance: enumValue(r.declaredAssurance, ASSURANCE, `edges[${index}].declaredAssurance`) });
}

function freshness(value: unknown, evidenceKind: GraphEvidenceKind, label: string): EvidenceFreshness {
  const r = plain(value, label);
  if (r.kind === "non-expiring") {
    exact(r, ["kind"], label);
    if (["reachability", "neuter", "installed-experiment", "peer-measurement", "trusted-time", "residual"].includes(evidenceKind)) throw new CapabilityGraphError(`${label} must be a bounded window for freshness-sensitive evidence`);
    return Object.freeze({ kind: "non-expiring" });
  }
  exact(r, ["kind", "observedAtMs", "expiresAtMs"], label);
  if (r.kind !== "window") throw new CapabilityGraphError(`${label}.kind is unsupported`);
  const observedAtMs = epoch(r.observedAtMs, `${label}.observedAtMs`); const expiresAtMs = epoch(r.expiresAtMs, `${label}.expiresAtMs`);
  if (expiresAtMs <= observedAtMs) throw new CapabilityGraphError(`${label} must expire after observation`);
  if (expiresAtMs - observedAtMs > MAX_FRESH_EVIDENCE_TTL_MS) throw new CapabilityGraphError(`${label} exceeds the maximum evidence TTL`);
  return Object.freeze({ kind: "window", observedAtMs, expiresAtMs });
}

function evidence(value: unknown, index: number): GraphEvidence {
  const r = plain(value, `evidence[${index}]`); exact(r, ["id", "kind", "subjectDigest", "releaseEpoch", "producerId", "mechanismId", "contentDigest", "subjectIds", "digest", "assurance", "freshness"], `evidence[${index}]`);
  const kind = enumValue(r.kind, EVIDENCE_KINDS, `evidence[${index}].kind`);
  const captured = Object.freeze({ id: id(r.id, `evidence[${index}].id`), kind, subjectDigest: digest(r.subjectDigest, `evidence[${index}].subjectDigest`), releaseEpoch: epoch(r.releaseEpoch, `evidence[${index}].releaseEpoch`), producerId: id(r.producerId, `evidence[${index}].producerId`), mechanismId: id(r.mechanismId, `evidence[${index}].mechanismId`), contentDigest: digest(r.contentDigest, `evidence[${index}].contentDigest`), subjectIds: evidenceSubjectList(r.subjectIds, `evidence[${index}].subjectIds`), digest: digest(r.digest, `evidence[${index}].digest`), assurance: enumValue(r.assurance, ASSURANCE, `evidence[${index}].assurance`), freshness: freshness(r.freshness, kind, `evidence[${index}].freshness`) });
  if (captured.subjectIds.length === 0 || captured.digest !== capabilityEvidenceBindingDigest(captured)) throw new CapabilityGraphError(`evidence[${index}] binding digest does not commit its subjects and content`);
  return captured;
}

function claim(value: unknown, index: number): GraphClaim {
  const r = plain(value, `claims[${index}]`); exact(r, ["id", "operationIds", "requiredNodeIds", "requiredEdgeIds", "requiredEvidenceIds"], `claims[${index}]`);
  const operationIds = stringList(r.operationIds, `claims[${index}].operationIds`);
  if (operationIds.length === 0) throw new CapabilityGraphError(`claims[${index}].operationIds must not be empty`);
  const requiredEvidenceIds = stringList(r.requiredEvidenceIds, `claims[${index}].requiredEvidenceIds`, true, LIMITS.evidence);
  return Object.freeze({ id: id(r.id, `claims[${index}].id`), operationIds, requiredNodeIds: stringList(r.requiredNodeIds, `claims[${index}].requiredNodeIds`, true, LIMITS.nodes), requiredEdgeIds: stringList(r.requiredEdgeIds, `claims[${index}].requiredEdgeIds`, true, LIMITS.edges), requiredEvidenceIds });
}

function compatibility(value: unknown, index: number): BuiltAheadDisposition {
  const r = plain(value, `compatibility[${index}]`); exact(r, ["builtAheadId", "disposition", "replacementOrConsumerId", "preservedInvariants", "evidenceIds", "nextBlockingStep"], `compatibility[${index}]`);
  return Object.freeze({ builtAheadId: id(r.builtAheadId, `compatibility[${index}].builtAheadId`), disposition: enumValue(r.disposition, DISPOSITIONS, `compatibility[${index}].disposition`), replacementOrConsumerId: r.replacementOrConsumerId === "" ? "" : id(r.replacementOrConsumerId, `compatibility[${index}].replacementOrConsumerId`), preservedInvariants: stringList(r.preservedInvariants, `compatibility[${index}].preservedInvariants`, false), evidenceIds: stringList(r.evidenceIds, `compatibility[${index}].evidenceIds`), nextBlockingStep: freeText(r.nextBlockingStep, `compatibility[${index}].nextBlockingStep`) });
}

function freshnessCanonical(value: EvidenceFreshness): CanonicalValue {
  return value.kind === "non-expiring" ? { kind: value.kind } : { kind: value.kind, observedAtMs: value.observedAtMs, expiresAtMs: value.expiresAtMs };
}

function graphCanonical(graph: CapabilityGraphV2Input): CanonicalValue {
  return {
    schema: CAPABILITY_GRAPH_V2.name, version: BigInt(graph.version), subjectDigest: graph.subjectDigest, releaseEpoch: graph.releaseEpoch,
    declarationProducerId: graph.declarationProducerId, declarationMechanismId: graph.declarationMechanismId,
    nodes: graph.nodes.map((n) => ({ id: n.id, kind: n.kind, domain: n.domain, module: n.module, moduleDigest: n.moduleDigest, evidenceIds: n.evidenceIds, declaredAssurance: n.declaredAssurance })),
    edges: graph.edges.map((e) => ({ id: e.id, from: e.from, to: e.to, kind: e.kind, operations: e.operations, targetScopes: e.targetScopes, evidenceIds: e.evidenceIds, declaredAssurance: e.declaredAssurance })),
    evidence: graph.evidence.map((e) => ({ id: e.id, kind: e.kind, subjectDigest: e.subjectDigest, releaseEpoch: e.releaseEpoch, producerId: e.producerId, mechanismId: e.mechanismId, contentDigest: e.contentDigest, subjectIds: e.subjectIds, digest: e.digest, assurance: e.assurance, freshness: freshnessCanonical(e.freshness) })),
    claims: graph.claims.map((c) => ({ id: c.id, operationIds: c.operationIds, requiredNodeIds: c.requiredNodeIds, requiredEdgeIds: c.requiredEdgeIds, requiredEvidenceIds: c.requiredEvidenceIds })),
    compatibility: graph.compatibility.map((c) => ({ builtAheadId: c.builtAheadId, disposition: c.disposition, replacementOrConsumerId: c.replacementOrConsumerId, preservedInvariants: c.preservedInvariants, evidenceIds: c.evidenceIds, nextBlockingStep: c.nextBlockingStep })),
  };
}

function assertAcyclic(nodes: readonly GraphNode[], edges: readonly GraphEdge[]): void {
  const dependencies = new Map(nodes.map((n) => [n.id, [] as string[]]));
  for (const edge of edges) if (edge.kind === "depends-on") {
    const from = dependencies.get(edge.from);
    if (from === undefined || !dependencies.has(edge.to)) throw new CapabilityGraphError(`dependency edge ${edge.id} references a missing node`);
    from.push(edge.to);
  }
  const visiting = new Set<string>(); const visited = new Set<string>();
  const visit = (nodeId: string): void => {
    if (visiting.has(nodeId)) throw new CapabilityGraphError(`dependency cycle at ${nodeId}`);
    if (visited.has(nodeId)) return;
    visiting.add(nodeId); for (const dependency of dependencies.get(nodeId) ?? []) visit(dependency); visiting.delete(nodeId); visited.add(nodeId);
  };
  for (const node of nodes) visit(node.id);
}

function utf8Order(a: string, b: string): number {
  const left = new TextEncoder().encode(a); const right = new TextEncoder().encode(b); const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index++) if (left[index] !== right[index]) return left[index]! - right[index]!;
  return left.length - right.length;
}

function captureCapabilityGraphV2Within(input: unknown, deadline: number): CapturedCapabilityGraphV2 {
  preflightPlainData(input, deadline, "graph");
  const checkBudget = (): void => { if (performance.now() > deadline) throw new CapabilityGraphError(`capture exceeded ${LIMITS.verificationBudgetMs}ms budget`); };
  const r = plain(input, "graph"); exact(r, ["version", "subjectDigest", "releaseEpoch", "declarationProducerId", "declarationMechanismId", "nodes", "edges", "evidence", "claims", "compatibility"], "graph");
  if (r.version !== 2) throw new CapabilityGraphError("unsupported version");
  const subjectDigest = digest(r.subjectDigest, "subjectDigest"); const releaseEpoch = epoch(r.releaseEpoch, "releaseEpoch");
  const declarationProducerId = id(r.declarationProducerId, "declarationProducerId"); const declarationMechanismId = id(r.declarationMechanismId, "declarationMechanismId");
  const nodes = Object.freeze(list(r.nodes, LIMITS.nodes, "nodes").map(node).sort((a, b) => utf8Order(a.id, b.id)));
  const edges = Object.freeze(list(r.edges, LIMITS.edges, "edges").map(edge).sort((a, b) => utf8Order(a.id, b.id)));
  const evidenceRows = Object.freeze(list(r.evidence, LIMITS.evidence, "evidence").map(evidence).sort((a, b) => utf8Order(a.id, b.id)));
  const claims = Object.freeze(list(r.claims, LIMITS.claims, "claims").map(claim).sort((a, b) => utf8Order(a.id, b.id)));
  const compatibilityRows = Object.freeze(list(r.compatibility, LIMITS.compatibility, "compatibility").map(compatibility).sort((a, b) => utf8Order(a.builtAheadId, b.builtAheadId)));
  unique(nodes, "node"); unique(edges, "edge"); unique(evidenceRows, "evidence"); unique(claims, "claim"); uniqueCompatibility(compatibilityRows);
  const namespacedIds = [...nodes.map((row) => row.id), ...edges.map((row) => row.id), ...evidenceRows.map((row) => row.id), ...claims.map((row) => row.id)];
  if (new Set(namespacedIds).size !== namespacedIds.length) throw new CapabilityGraphError("node, edge, evidence and claim ids must be globally unique");
  const nodeIds = new Set(nodes.map((n) => n.id)); const nodeById = new Map(nodes.map((n) => [n.id, n])); const evidenceIds = new Set(evidenceRows.map((e) => e.id)); const edgeIds = new Set(edges.map((e) => e.id)); const edgeById = new Map(edges.map((row) => [row.id, row]));
  const evidenceById = new Map(evidenceRows.map((row) => [row.id, row]));
  if (!nodeIds.has(declarationProducerId)) throw new CapabilityGraphError("declarationProducerId does not resolve to a graph node");
  for (const nodeRow of nodes) { checkBudget(); for (const evidenceId of nodeRow.evidenceIds) { const proof = evidenceById.get(evidenceId); if (proof === undefined) throw new CapabilityGraphError(`node ${nodeRow.id} references missing evidence ${evidenceId}`); if (!proof.subjectIds.includes(`node:${nodeRow.id}`)) throw new CapabilityGraphError(`evidence ${evidenceId} is not proposition-bound to node ${nodeRow.id}`); if (proof.producerId === nodeRow.id) throw new CapabilityGraphError(`evidence ${evidenceId} self-attests node ${nodeRow.id}`); } }
  for (const nodeRow of nodes) if ((nodeRow.kind === "raw-sink" || nodeRow.kind === "credential") && nodeRow.evidenceIds.length === 0) throw new CapabilityGraphError(`high-risk node ${nodeRow.id} lacks evidence`);
  const behavioralEvidenceKinds = new Set<GraphEvidenceKind>(["reachability", "installed-experiment", "peer-measurement", "residual"]);
  for (const nodeRow of nodes) if (nodeRow.declaredAssurance !== "unknown" && !nodeRow.evidenceIds.some((evidenceId) => { const proof = evidenceById.get(evidenceId)!; return proof.assurance !== "unknown" && behavioralEvidenceKinds.has(proof.kind); })) throw new CapabilityGraphError(`node ${nodeRow.id} declares assurance without non-unknown evidence of a behavioral kind`);
  for (const evidenceRow of evidenceRows) if (!nodeIds.has(evidenceRow.producerId)) throw new CapabilityGraphError(`evidence ${evidenceRow.id} producer does not resolve to a graph node`);
  for (const evidenceRow of evidenceRows) if (evidenceRow.assurance !== "unknown") { const producer = nodeById.get(evidenceRow.producerId)!; if ((producer.domain !== "PROBER" && producer.domain !== "EXTERNAL") || evidenceRow.producerId === declarationProducerId || evidenceRow.mechanismId === declarationMechanismId) throw new CapabilityGraphError(`evidence ${evidenceRow.id} lacks an independent external producer and mechanism`); }
  for (const edgeRow of edges) {
    checkBudget();
    if (!nodeIds.has(edgeRow.from) || !nodeIds.has(edgeRow.to)) throw new CapabilityGraphError(`edge ${edgeRow.id} references a missing node`);
    if (edgeRow.from === edgeRow.to) throw new CapabilityGraphError(`edge ${edgeRow.id} is a self-edge`);
    for (const evidenceId of edgeRow.evidenceIds) if (!evidenceIds.has(evidenceId)) throw new CapabilityGraphError(`edge ${edgeRow.id} references missing evidence ${evidenceId}`);
    for (const evidenceId of edgeRow.evidenceIds) if (!evidenceById.get(evidenceId)!.subjectIds.includes(`edge:${edgeRow.id}`)) throw new CapabilityGraphError(`evidence ${evidenceId} is not proposition-bound to edge ${edgeRow.id}`);
    for (const evidenceId of edgeRow.evidenceIds) { const proof = evidenceById.get(evidenceId)!; if (proof.producerId === edgeRow.from || proof.producerId === edgeRow.to) throw new CapabilityGraphError(`evidence ${evidenceId} self-attests edge ${edgeRow.id}`); }
    if (edgeRow.declaredAssurance !== "unknown" && !edgeRow.evidenceIds.some((evidenceId) => { const proof = evidenceById.get(evidenceId)!; return proof.assurance !== "unknown" && behavioralEvidenceKinds.has(proof.kind); })) throw new CapabilityGraphError(`edge ${edgeRow.id} declares assurance without non-unknown evidence of a behavioral kind`);
    if (edgeRow.kind === "authenticates" && edgeRow.evidenceIds.length === 0) throw new CapabilityGraphError(`authenticated edge ${edgeRow.id} lacks evidence`);
    if (edgeRow.kind === "authenticates" && !edgeRow.evidenceIds.some((evidenceId) => {
      const proof = evidenceById.get(evidenceId)!;
      const producer = nodeById.get(proof.producerId)!;
      return proof.kind === "peer-measurement" && proof.assurance !== "unknown" && proof.mechanismId !== declarationMechanismId && proof.producerId !== edgeRow.from && proof.producerId !== edgeRow.to && (producer.domain === "PROBER" || producer.domain === "EXTERNAL");
    })) throw new CapabilityGraphError(`authenticated edge ${edgeRow.id} lacks distinct-observer peer measurement`);
  }
  for (const evidenceRow of evidenceRows) if (evidenceRow.subjectDigest !== subjectDigest || evidenceRow.releaseEpoch !== releaseEpoch) throw new CapabilityGraphError(`evidence ${evidenceRow.id} belongs to another subject or release epoch`);
  const operationToEdges = new Map<string, GraphEdge[]>();
  for (const edgeRow of edges) for (const operation of edgeRow.operations) { const rows = operationToEdges.get(operation); if (rows === undefined) operationToEdges.set(operation, [edgeRow]); else rows.push(edgeRow); }
  for (const claimRow of claims) {
    checkBudget();
    for (const nodeId of claimRow.requiredNodeIds) if (!nodeIds.has(nodeId)) throw new CapabilityGraphError(`claim ${claimRow.id} references missing node ${nodeId}`);
    for (const edgeId of claimRow.requiredEdgeIds) if (!edgeIds.has(edgeId)) throw new CapabilityGraphError(`claim ${claimRow.id} references missing edge ${edgeId}`);
    for (const evidenceId of claimRow.requiredEvidenceIds) { const proof = evidenceById.get(evidenceId); if (proof === undefined) throw new CapabilityGraphError(`claim ${claimRow.id} references missing evidence ${evidenceId}`); if (!proof.subjectIds.includes(`claim:${claimRow.id}`)) throw new CapabilityGraphError(`evidence ${evidenceId} is not proposition-bound to claim ${claimRow.id}`); }
    for (const evidenceId of claimRow.requiredEvidenceIds) if (claimRow.requiredNodeIds.includes(evidenceById.get(evidenceId)!.producerId)) throw new CapabilityGraphError(`evidence ${evidenceId} self-attests claim ${claimRow.id}`);
    const scopedEdges = [...new Map(claimRow.operationIds.flatMap((operation) => operationToEdges.get(operation) ?? []).map((edgeRow) => [edgeRow.id, edgeRow])).values()];
    if (scopedEdges.length === 0) throw new CapabilityGraphError(`claim ${claimRow.id} operations cover no graph edge`);
    for (const operationId of claimRow.operationIds) if (!operationToEdges.has(operationId)) throw new CapabilityGraphError(`claim ${claimRow.id} operation ${operationId} covers no graph edge`);
    const scopedEdgeIds = scopedEdges.map((edgeRow) => edgeRow.id).sort(utf8Order);
    const scopedNodeIds = [...new Set(scopedEdges.flatMap((edgeRow) => [edgeRow.from, edgeRow.to]))].sort(utf8Order);
    if (claimRow.requiredEdgeIds.join("\0") !== scopedEdgeIds.join("\0") || claimRow.requiredNodeIds.join("\0") !== scopedNodeIds.join("\0")) throw new CapabilityGraphError(`claim ${claimRow.id} required nodes/edges do not exactly cover its operations`);
  }
  const expectedCompatibility = [...BUILT_AHEAD_COMPATIBILITY_IDS].sort(); const actualCompatibility = compatibilityRows.map((c) => c.builtAheadId);
  if (actualCompatibility.length !== expectedCompatibility.length || actualCompatibility.some((value, index) => value !== expectedCompatibility[index])) throw new CapabilityGraphError("compatibility dispositions must cover exactly the six built-ahead groups");
  for (const row of compatibilityRows) {
    for (const evidenceId of row.evidenceIds) { const proof = evidenceById.get(evidenceId); if (proof === undefined) throw new CapabilityGraphError(`compatibility ${row.builtAheadId} references missing evidence ${evidenceId}`); if (!proof.subjectIds.includes(`compatibility:${row.builtAheadId}`)) throw new CapabilityGraphError(`evidence ${evidenceId} is not proposition-bound to compatibility ${row.builtAheadId}`); }
    if (row.preservedInvariants.length === 0) throw new CapabilityGraphError(`compatibility ${row.builtAheadId} preserves no invariant`);
    if (!row.evidenceIds.some((evidenceId) => evidenceById.get(evidenceId)!.assurance !== "unknown")) throw new CapabilityGraphError(`compatibility ${row.builtAheadId} lacks non-unknown evidence`);
    if (row.disposition !== "retain-inert" && row.replacementOrConsumerId === "") throw new CapabilityGraphError(`compatibility ${row.builtAheadId} lacks its consumer/replacement`);
    if (row.disposition !== "retain-inert" && !nodeIds.has(row.replacementOrConsumerId)) throw new CapabilityGraphError(`compatibility ${row.builtAheadId} names an absent consumer/replacement`);
    if (row.disposition !== "retain-inert") { const consumer = nodeById.get(row.replacementOrConsumerId)!; if (consumer.kind !== "component" || !["D1", "D2", "D3"].includes(consumer.domain)) throw new CapabilityGraphError(`compatibility ${row.builtAheadId} consumer/replacement is not a deployed component`); if (!edges.some((edgeRow) => edgeRow.from === consumer.id || edgeRow.to === consumer.id)) throw new CapabilityGraphError(`compatibility ${row.builtAheadId} consumer/replacement is isolated from the graph`); for (const evidenceId of row.evidenceIds) if (evidenceById.get(evidenceId)!.producerId === consumer.id) throw new CapabilityGraphError(`evidence ${evidenceId} self-attests compatibility ${row.builtAheadId}`); }
    if (row.disposition === "retain-inert" && row.replacementOrConsumerId !== "") throw new CapabilityGraphError(`compatibility ${row.builtAheadId} retain-inert row already names a consumer`);
    if (row.disposition === "retain-inert" && !row.evidenceIds.some((evidenceId) => evidenceById.get(evidenceId)!.kind === "neuter")) throw new CapabilityGraphError(`compatibility ${row.builtAheadId} retain-inert row lacks neuter evidence`);
  }
  const claimsById = new Map(claims.map((row) => [row.id, row])); const compatibilityIds = new Set(compatibilityRows.map((row) => row.builtAheadId));
  for (const proof of evidenceRows) {
    checkBudget();
    const subjectKinds = new Set(proof.subjectIds.map((subjectId) => subjectId.slice(0, subjectId.indexOf(":"))));
    if (subjectKinds.has("inventory") && (proof.subjectIds.length !== 1 || (proof.kind !== "installed-experiment" && proof.kind !== "artifact-scan"))) throw new CapabilityGraphError(`evidence ${proof.id} mixes inventory observation with other propositions`);
    if (subjectKinds.has("clock") && (proof.subjectIds.length !== 1 || proof.kind !== "trusted-time")) throw new CapabilityGraphError(`evidence ${proof.id} mixes trusted time with other propositions`);
    if (subjectKinds.has("compatibility") && (subjectKinds.size !== 1 || (proof.kind !== "artifact-scan" && proof.kind !== "neuter"))) throw new CapabilityGraphError(`evidence ${proof.id} has an invalid compatibility proposition class`);
    const claimSubjects = proof.subjectIds.filter((subjectId) => subjectId.startsWith("claim:"));
    if (claimSubjects.length > 1) throw new CapabilityGraphError(`evidence ${proof.id} cannot underwrite multiple claims`);
    const claimSubject = claimSubjects[0]?.slice("claim:".length); const boundClaim = claimSubject === undefined ? undefined : claimsById.get(claimSubject);
    if (claimSubject !== undefined && boundClaim === undefined) throw new CapabilityGraphError(`evidence ${proof.id} references absent claim ${claimSubject}`);
    for (const subjectId of proof.subjectIds) {
      const separator = subjectId.indexOf(":"); const subjectKind = subjectId.slice(0, separator); const targetId = subjectId.slice(separator + 1);
      checkBudget();
      if (subjectKind === "node" && (!nodeIds.has(targetId) || !nodeById.get(targetId)!.evidenceIds.includes(proof.id))) throw new CapabilityGraphError(`evidence ${proof.id} has an unresolved or unused node subject ${targetId}`);
      if (subjectKind === "edge" && (!edgeIds.has(targetId) || !edgeById.get(targetId)!.evidenceIds.includes(proof.id))) throw new CapabilityGraphError(`evidence ${proof.id} has an unresolved or unused edge subject ${targetId}`);
      if (subjectKind === "claim" && (boundClaim === undefined || !boundClaim.requiredEvidenceIds.includes(proof.id))) throw new CapabilityGraphError(`evidence ${proof.id} has an unused claim subject ${targetId}`);
      if (subjectKind === "compatibility" && (!compatibilityIds.has(targetId) || !compatibilityRows.find((row) => row.builtAheadId === targetId)!.evidenceIds.includes(proof.id))) throw new CapabilityGraphError(`evidence ${proof.id} has an unresolved or unused compatibility subject ${targetId}`);
      if (boundClaim !== undefined && subjectKind === "node" && !boundClaim.requiredNodeIds.includes(targetId)) throw new CapabilityGraphError(`evidence ${proof.id} node subject escapes claim ${boundClaim.id}`);
      if (boundClaim !== undefined && subjectKind === "edge" && !boundClaim.requiredEdgeIds.includes(targetId)) throw new CapabilityGraphError(`evidence ${proof.id} edge subject escapes claim ${boundClaim.id}`);
    }
  }
  assertAcyclic(nodes, edges);
  const withoutDigest = Object.freeze({ version: 2 as const, subjectDigest, releaseEpoch, declarationProducerId, declarationMechanismId, nodes, edges, evidence: evidenceRows, claims, compatibility: compatibilityRows });
  return Object.freeze({ ...withoutDigest, digest: eirDigest("keep.capability-graph/v2", graphCanonical(withoutDigest)) });
}

export function captureCapabilityGraphV2(input: unknown): CapturedCapabilityGraphV2 {
  return captureCapabilityGraphV2Within(input, performance.now() + LIMITS.verificationBudgetMs);
}

function captureGraphArgument(input: unknown, deadline: number): CapturedCapabilityGraphV2 {
  preflightPlainData(input, deadline, "graph"); const record = plain(input, "graph");
  if (!Object.prototype.hasOwnProperty.call(record, "digest")) return captureCapabilityGraphV2Within(input, deadline);
  exact(record, ["version", "subjectDigest", "releaseEpoch", "declarationProducerId", "declarationMechanismId", "nodes", "edges", "evidence", "claims", "compatibility", "digest"], "capturedGraph");
  const suppliedDigest = digest(record.digest, "capturedGraph.digest");
  const raw = { version: record.version, subjectDigest: record.subjectDigest, releaseEpoch: record.releaseEpoch, declarationProducerId: record.declarationProducerId, declarationMechanismId: record.declarationMechanismId, nodes: record.nodes, edges: record.edges, evidence: record.evidence, claims: record.claims, compatibility: record.compatibility };
  const captured = captureCapabilityGraphV2Within(raw, deadline);
  if (captured.digest !== suppliedDigest) throw new CapabilityGraphError("captured graph digest does not verify");
  return captured;
}

/** Capture either raw graph input or a previously captured graph, rechecking a supplied digest rather than trusting it. */
export function captureCapabilityGraphArgument(input: unknown): CapturedCapabilityGraphV2 {
  return captureGraphArgument(input, performance.now() + LIMITS.verificationBudgetMs);
}

function captureInventory(value: unknown, label: string): CapabilityInventory {
  const r = plain(value, label); exact(r, ["rawSinks", "credentials", "effectfulEntrypoints", "builtAhead", "builtAheadConsumers", "modules"], label);
  const modules = Object.freeze(list(r.modules, LIMITS.nodes, `${label}.modules`).map((value, index) => { const row = plain(value, `${label}.modules[${index}]`); exact(row, ["nodeId", "module", "digest"], `${label}.modules[${index}]`); return Object.freeze({ nodeId: id(row.nodeId, `${label}.modules[${index}].nodeId`), module: modulePath(row.module, `${label}.modules[${index}].module`), digest: digest(row.digest, `${label}.modules[${index}].digest`) }); }).sort((a, b) => utf8Order(a.nodeId, b.nodeId)));
  if (new Set(modules.map((row) => row.nodeId)).size !== modules.length) throw new CapabilityGraphError(`${label}.modules contains duplicate node ids`);
  return Object.freeze({ rawSinks: stringList(r.rawSinks, `${label}.rawSinks`, true, LIMITS.nodes), credentials: stringList(r.credentials, `${label}.credentials`, true, LIMITS.nodes), effectfulEntrypoints: stringList(r.effectfulEntrypoints, `${label}.effectfulEntrypoints`, true, LIMITS.nodes), builtAhead: stringList(r.builtAhead, `${label}.builtAhead`), builtAheadConsumers: stringList(r.builtAheadConsumers, `${label}.builtAheadConsumers`, true, LIMITS.nodes), modules });
}

function captureInstalledInventory(value: unknown, label: string): InstalledCapabilityInventory {
  const r = plain(value, label); exact(r, ["rawSinks", "credentials", "effectfulEntrypoints", "modules"], label);
  const full = captureInventory({ rawSinks: r.rawSinks, credentials: r.credentials, effectfulEntrypoints: r.effectfulEntrypoints, builtAhead: [], builtAheadConsumers: [], modules: r.modules }, label);
  return Object.freeze({ rawSinks: full.rawSinks, credentials: full.credentials, effectfulEntrypoints: full.effectfulEntrypoints, modules: full.modules });
}

export function capabilityInventoryDigest(inventoryInput: unknown): string {
  const inventory = captureInventory(inventoryInput, "inventoryDigest.input");
  return eirDigest("keep.capability-inventory/v2", { rawSinks: [...inventory.rawSinks].sort(utf8Order), credentials: [...inventory.credentials].sort(utf8Order), effectfulEntrypoints: [...inventory.effectfulEntrypoints].sort(utf8Order), builtAhead: [...inventory.builtAhead].sort(utf8Order), builtAheadConsumers: [...inventory.builtAheadConsumers].sort(utf8Order), modules: inventory.modules.map((row) => ({ nodeId: row.nodeId, module: row.module, digest: row.digest })) });
}

export function capabilityInstalledInventoryDigest(inventoryInput: unknown): string {
  const inventory = captureInstalledInventory(inventoryInput, "installedInventoryDigest.input");
  return eirDigest("keep.installed-capability-inventory/v2", { rawSinks: inventory.rawSinks, credentials: inventory.credentials, effectfulEntrypoints: inventory.effectfulEntrypoints, modules: inventory.modules.map((row) => ({ nodeId: row.nodeId, module: row.module, digest: row.digest })) });
}

export function capabilityClockEvidenceDigest(input: { readonly subjectDigest: string; readonly releaseEpoch: bigint; readonly observedAtMs: bigint; readonly expiresAtMs: bigint; readonly producerId: string; readonly mechanismId: string }): string {
  return eirDigest("keep.capability-clock-evidence/v2", { subjectDigest: input.subjectDigest, releaseEpoch: input.releaseEpoch, observedAtMs: input.observedAtMs, expiresAtMs: input.expiresAtMs, producerId: input.producerId, mechanismId: input.mechanismId });
}

export function capabilityEvidenceBindingDigest(input: Omit<GraphEvidence, "digest">): string {
  const freshnessValue: CanonicalValue = input.freshness.kind === "non-expiring" ? { kind: "non-expiring" } : { kind: "window", observedAtMs: input.freshness.observedAtMs, expiresAtMs: input.freshness.expiresAtMs };
  return eirDigest("keep.capability-evidence-binding/v2", { id: input.id, kind: input.kind, subjectDigest: input.subjectDigest, releaseEpoch: input.releaseEpoch, producerId: input.producerId, mechanismId: input.mechanismId, contentDigest: input.contentDigest, subjectIds: [...input.subjectIds].sort(utf8Order), assurance: input.assurance, freshness: freshnessValue });
}

export function capabilityObservationEvidenceDigest(input: { readonly kind: InventoryObservation["kind"]; readonly subjectDigest: string; readonly releaseEpoch: bigint; readonly producerId: string; readonly mechanismId: string; readonly inventoryDigest: string }): string {
  return eirDigest("keep.capability-observation-evidence/v2", { kind: input.kind, subjectDigest: input.subjectDigest, releaseEpoch: input.releaseEpoch, producerId: input.producerId, mechanismId: input.mechanismId, inventoryDigest: input.inventoryDigest });
}

function evidenceFreshAt(row: GraphEvidence, nowMs: bigint): boolean {
  return row.freshness.kind === "non-expiring" || (row.freshness.observedAtMs <= nowMs && nowMs < row.freshness.expiresAtMs);
}

interface CapturedWorld {
  readonly clockEvidenceId: string;
  readonly declaration: { readonly producerId: string; readonly mechanismId: string; readonly inventory: CapabilityInventory };
  readonly observations: readonly InventoryObservation[];
  readonly digest: string;
}

function captureObservedWorld(worldInput: unknown, deadline: number): CapturedWorld {
  preflightPlainData(worldInput, deadline, "observedWorld");
  const world = plain(worldInput, "observedWorld"); exact(world, ["clockEvidenceId", "declaration", "observations"], "observedWorld");
  const clockEvidenceId = id(world.clockEvidenceId, "observedWorld.clockEvidenceId");
  const declarationRecord = plain(world.declaration, "observedWorld.declaration"); exact(declarationRecord, ["producerId", "mechanismId", "inventory"], "observedWorld.declaration");
  const declaration = Object.freeze({ producerId: id(declarationRecord.producerId, "observedWorld.declaration.producerId"), mechanismId: id(declarationRecord.mechanismId, "observedWorld.declaration.mechanismId"), inventory: captureInventory(declarationRecord.inventory, "observedWorld.declaration.inventory") });
  const observations = Object.freeze(list(world.observations, LIMITS.observations, "observedWorld.observations").map((value, index) => {
    const row = plain(value, `observations[${index}]`); exact(row, ["producerId", "mechanismId", "kind", "subjectDigest", "releaseEpoch", "evidenceId", "inventory"], `observations[${index}]`);
    return Object.freeze({ producerId: id(row.producerId, `observations[${index}].producerId`), mechanismId: id(row.mechanismId, `observations[${index}].mechanismId`), kind: enumValue(row.kind, new Set(["installed-runtime", "installed-artifact", "source-scan"] as const), `observations[${index}].kind`), subjectDigest: digest(row.subjectDigest, `observations[${index}].subjectDigest`), releaseEpoch: epoch(row.releaseEpoch, `observations[${index}].releaseEpoch`), evidenceId: id(row.evidenceId, `observations[${index}].evidenceId`), inventory: captureInstalledInventory(row.inventory, `observations[${index}].inventory`) });
  }).sort((a, b) => utf8Order(`${a.producerId}\0${a.mechanismId}`, `${b.producerId}\0${b.mechanismId}`)));
  const canonical: CanonicalValue = { clockEvidenceId, declaration: { producerId: declaration.producerId, mechanismId: declaration.mechanismId, inventoryDigest: capabilityInventoryDigest(declaration.inventory) }, observations: observations.map((row) => ({ producerId: row.producerId, mechanismId: row.mechanismId, kind: row.kind, subjectDigest: row.subjectDigest, releaseEpoch: row.releaseEpoch, evidenceId: row.evidenceId, inventoryDigest: capabilityInstalledInventoryDigest(row.inventory) })) };
  return Object.freeze({ clockEvidenceId, declaration, observations, digest: eirDigest("keep.observed-capability-world/v2", canonical) });
}

function captureVerificationContext(input: unknown, deadline: number): CapabilityVerificationContext {
  preflightPlainData(input, deadline, "verificationContext");
  const context = plain(input, "verificationContext"); exact(context, ["trustedNowMs"], "verificationContext");
  return Object.freeze({ trustedNowMs: epoch(context.trustedNowMs, "verificationContext.trustedNowMs") });
}

function reconcileCapturedWorld(graph: CapturedCapabilityGraphV2, world: CapturedWorld, context: CapabilityVerificationContext, deadline: number): InventoryVerdict {
  const reasons: string[] = [];
  if (world.declaration.producerId !== graph.declarationProducerId || world.declaration.mechanismId !== graph.declarationMechanismId) reasons.push("inventory declaration producer/mechanism differs from graph binding");
  const clockProof = graph.evidence.find((row) => row.id === world.clockEvidenceId);
  const clockProducer = clockProof === undefined ? undefined : graph.nodes.find((row) => row.id === clockProof.producerId);
  if (clockProof === undefined || clockProof.kind !== "trusted-time" || clockProof.assurance !== "enforced" || clockProof.freshness.kind !== "window" || !clockProof.subjectIds.includes("clock:current") || !evidenceFreshAt(clockProof, context.trustedNowMs) || clockProof.contentDigest !== capabilityClockEvidenceDigest({ subjectDigest: graph.subjectDigest, releaseEpoch: graph.releaseEpoch, observedAtMs: clockProof.freshness.observedAtMs, expiresAtMs: clockProof.freshness.expiresAtMs, producerId: clockProof.producerId, mechanismId: clockProof.mechanismId }) || clockProducer === undefined || (clockProducer.domain !== "PROBER" && clockProducer.domain !== "EXTERNAL") || clockProof.producerId === graph.declarationProducerId || clockProof.mechanismId === graph.declarationMechanismId) reasons.push("verifier time lacks independent enforced graph-bound trusted-time window evidence");
  const declaration = world.declaration.inventory;
  const expectedInstalled = capabilityInstalledInventoryDigest({ rawSinks: declaration.rawSinks, credentials: declaration.credentials, effectfulEntrypoints: declaration.effectfulEntrypoints, modules: declaration.modules }); let independentInstalled = false;
    const graphRawSinks = graph.nodes.filter((node) => node.kind === "raw-sink").map((node) => node.id).sort();
    const graphCredentials = graph.nodes.filter((node) => node.kind === "credential").map((node) => node.id).sort();
    const graphEntrypoints = graph.nodes.filter((node) => node.kind === "entrypoint").map((node) => node.id).sort();
    const graphModules = graph.nodes.filter((node) => node.module !== "").map((node) => ({ nodeId: node.id, module: node.module, digest: node.moduleDigest })).sort((a, b) => utf8Order(a.nodeId, b.nodeId));
    if (declaration.rawSinks.join("\0") !== graphRawSinks.join("\0")) reasons.push("declared raw-sink inventory differs from graph nodes");
    if (declaration.credentials.join("\0") !== graphCredentials.join("\0")) reasons.push("declared credential inventory differs from graph nodes");
    if (declaration.effectfulEntrypoints.join("\0") !== graphEntrypoints.join("\0")) reasons.push("declared effectful-entrypoint inventory differs from graph nodes");
    if (capabilityInstalledInventoryDigest({ rawSinks: [], credentials: [], effectfulEntrypoints: [], modules: declaration.modules }) !== capabilityInstalledInventoryDigest({ rawSinks: [], credentials: [], effectfulEntrypoints: [], modules: graphModules })) reasons.push("declared installed-module inventory differs from graph module bindings");
    if (declaration.builtAhead.join("\0") !== [...BUILT_AHEAD_COMPATIBILITY_IDS].sort().join("\0")) reasons.push("declared built-ahead inventory differs from compatibility closure");
    const expectedConsumers = [...new Set(graph.compatibility.filter((row) => row.disposition !== "retain-inert").map((row) => row.replacementOrConsumerId))].sort(utf8Order);
    if (declaration.builtAheadConsumers.join("\0") !== expectedConsumers.join("\0")) reasons.push("declared built-ahead consumer inventory differs from compatibility dispositions");
    const seenProducerMechanism = new Set<string>();
    for (const [index, row] of world.observations.entries()) {
      if (performance.now() > deadline) throw new CapabilityGraphError(`inventory reconciliation exceeded ${LIMITS.verificationBudgetMs}ms budget`);
      const { producerId, mechanismId, kind, evidenceId } = row; const proof = graph.evidence.find((evidence) => evidence.id === evidenceId);
      const observedInventoryDigest = capabilityInstalledInventoryDigest(row.inventory);
      let proofValid = proof !== undefined && proof.subjectIds.includes(`inventory:${kind}`) && proof.producerId === producerId && proof.mechanismId === mechanismId && proof.contentDigest === capabilityObservationEvidenceDigest({ kind, subjectDigest: row.subjectDigest, releaseEpoch: row.releaseEpoch, producerId, mechanismId, inventoryDigest: observedInventoryDigest });
      if (!proofValid) reasons.push(`observation ${index} is not bound to matching graph evidence`);
      else if (proof !== undefined) {
        const expectedKind: GraphEvidenceKind = kind === "installed-runtime" ? "installed-experiment" : kind === "installed-artifact" ? "artifact-scan" : "artifact-scan";
        const installedHasWindow = kind === "source-scan" || proof.freshness.kind === "window";
        if (proof.kind !== expectedKind || !installedHasWindow || !evidenceFreshAt(proof, context.trustedNowMs)) { reasons.push(`observation ${index} evidence kind/freshness is invalid`); proofValid = false; }
      }
      const producerNode = graph.nodes.find((node) => node.id === producerId);
      if (producerNode === undefined || (producerNode.domain !== "PROBER" && producerNode.domain !== "EXTERNAL")) reasons.push(`observation ${index} producer is not a bound independent graph identity`);
      const key = `${producerId}\0${mechanismId}`; if (seenProducerMechanism.has(key)) reasons.push(`duplicate observation producer/mechanism ${producerId}/${mechanismId}`); seenProducerMechanism.add(key);
      if (producerId === graph.declarationProducerId) reasons.push(`observation ${index} producer collides with declaration producer`);
      if (mechanismId === graph.declarationMechanismId) reasons.push(`observation ${index} mechanism collides with declaration mechanism`);
      if (row.subjectDigest !== graph.subjectDigest || row.releaseEpoch !== graph.releaseEpoch) reasons.push(`observation ${index} belongs to another subject or release epoch`);
      if (observedInventoryDigest !== expectedInstalled) reasons.push(`observation ${index} inventory differs from declaration`);
      if ((kind === "installed-runtime" || kind === "installed-artifact") && proofValid && producerNode !== undefined && producerId !== graph.declarationProducerId && mechanismId !== graph.declarationMechanismId) independentInstalled = true;
      if (clockProof !== undefined && (clockProof.producerId === producerId || clockProof.mechanismId === mechanismId)) reasons.push(`observation ${index} is not independent of trusted-time evidence`);
    }
  if (!independentInstalled) reasons.push("no producer-and-mechanism-independent installed observation");
  return Object.freeze({ valid: reasons.length === 0, reasons: Object.freeze(reasons), observedWorldDigest: world.digest });
}

export function reconcileCapabilityInventories(graphInput: unknown, worldInput: unknown, contextInput: unknown): InventoryVerdict {
  const deadline = performance.now() + LIMITS.verificationBudgetMs;
  try { return reconcileCapturedWorld(captureGraphArgument(graphInput, deadline), captureObservedWorld(worldInput, deadline), captureVerificationContext(contextInput, deadline), deadline); }
  catch (error) { return Object.freeze({ valid: false, reasons: Object.freeze([error instanceof Error ? error.message : "malformed observed world"]), observedWorldDigest: "" }); }
}

function assuranceMeet(values: readonly EnforcementStatus[]): { assurance: EnforcementStatus; incomparable: boolean } {
  if (values.length === 0) return { assurance: "unknown", incomparable: false };
  if (values.includes("unknown")) return { assurance: "unknown", incomparable: false };
  if (values.includes("unavailable") && values.includes("detected-only")) return { assurance: "unknown", incomparable: true };
  if (values.includes("unavailable")) return { assurance: "unavailable", incomparable: false };
  if (values.includes("detected-only")) return { assurance: "detected-only", incomparable: false };
  return { assurance: "enforced", incomparable: false };
}

const REACHABILITY_EDGE_KINDS = new Set<GraphEdgeKind>(["invokes", "authenticates", "owns", "can-read", "can-use", "targets", "depends-on"]);

function buildAdjacency(edges: readonly GraphEdge[]): ReadonlyMap<string, readonly string[]> {
  const adjacency = new Map<string, string[]>();
  for (const edge of edges) if (REACHABILITY_EDGE_KINDS.has(edge.kind)) {
    const destinations = adjacency.get(edge.from);
    if (destinations === undefined) adjacency.set(edge.from, [edge.to]); else destinations.push(edge.to);
  }
  return adjacency;
}

function transitiveReachableMany(starts: readonly string[], adjacency: ReadonlyMap<string, readonly string[]>, checkBudget: () => void): readonly string[] {
  const seen = new Set<string>(); const todo = [...starts];
  while (todo.length) { checkBudget(); const current = todo.pop()!; for (const next of adjacency.get(current) ?? []) if (!seen.has(next)) { seen.add(next); todo.push(next); } }
  return Object.freeze([...seen].sort(utf8Order));
}

function transitiveReachable(start: string, adjacency: ReadonlyMap<string, readonly string[]>, checkBudget: () => void): readonly string[] { return transitiveReachableMany([start], adjacency, checkBudget); }

export function deriveCapabilityLedgers(graphInput: unknown, worldInput: unknown, contextInput: unknown): CapabilityLedgers {
  const deadline = performance.now() + LIMITS.verificationBudgetMs;
  const checkBudget = (): void => { if (performance.now() > deadline) throw new CapabilityGraphError(`verification exceeded ${LIMITS.verificationBudgetMs}ms budget`); };
  const graph = captureGraphArgument(graphInput, deadline); checkBudget();
  let world: CapturedWorld | undefined; let context: CapabilityVerificationContext | undefined; const captureReasons: string[] = [];
  try { world = captureObservedWorld(worldInput, deadline); } catch (error) { captureReasons.push(error instanceof Error ? error.message : "malformed observed world"); }
  try { context = captureVerificationContext(contextInput, deadline); } catch (error) { captureReasons.push(error instanceof Error ? error.message : "malformed verification context"); }
  const inventory = world === undefined || context === undefined ? Object.freeze({ valid: false, reasons: Object.freeze(captureReasons), observedWorldDigest: "" }) : reconcileCapturedWorld(graph, world, context, deadline);
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node])); const edgeById = new Map(graph.edges.map((edge) => [edge.id, edge])); const evidenceById = new Map(graph.evidence.map((evidence) => [evidence.id, evidence]));
  const evidenceAssurance = new Map(graph.evidence.map((row) => [row.id, inventory.valid && context !== undefined && evidenceFreshAt(row, context.trustedNowMs) ? row.assurance : "unknown" as const]));
  const nodeAssurance = new Map(graph.nodes.map((node) => [node.id, assuranceMeet([node.declaredAssurance, ...node.evidenceIds.map((evidenceId) => evidenceAssurance.get(evidenceId)!)]).assurance]));
  const edgeAssurance = new Map(graph.edges.map((edge) => [edge.id, assuranceMeet([edge.declaredAssurance, ...edge.evidenceIds.map((evidenceId) => evidenceAssurance.get(evidenceId)!)]).assurance]));
  const d1Nodes = graph.nodes.filter((node) => node.domain === "D1"); const resources = graph.nodes.filter((node) => node.kind === "raw-sink" || node.kind === "credential");
  const adjacency = buildAdjacency(graph.edges); const reachableByD1Node = new Map(d1Nodes.map((node) => [node.id, new Set(transitiveReachable(node.id, adjacency, checkBudget))]));
  const relevantEdgesByResource = new Map(resources.map((resource) => [resource.id, [] as GraphEdge[]]));
  for (const edge of graph.edges) { checkBudget(); if (edge.kind === "authenticates" || edge.kind === "can-read" || edge.kind === "can-use" || edge.kind === "targets" || edge.kind === "owns") relevantEdgesByResource.get(edge.to)?.push(edge); }
  const deployment = Object.freeze(graph.nodes.map((node) => Object.freeze({ id: node.id, kind: node.kind, domain: node.domain, module: node.module, moduleDigest: node.moduleDigest, declaredAssurance: node.declaredAssurance, assurance: nodeAssurance.get(node.id)!, evidenceIds: node.evidenceIds })));
  const residuals = Object.freeze(resources.map((resource) => {
    checkBudget();
    const relevant = relevantEdgesByResource.get(resource.id)!; const d1Reachable = resource.domain === "D1" || d1Nodes.some((node) => reachableByD1Node.get(node.id)!.has(resource.id));
    const targetScopes = [...new Set(relevant.flatMap((edge) => edge.targetScopes))].sort(utf8Order); const meet = assuranceMeet([nodeAssurance.get(resource.id)!, ...relevant.map((edge) => edgeAssurance.get(edge.id)!)]);
    const externallyEnforcedScope = relevant.some((edge) => edge.targetScopes.length > 0 && edgeAssurance.get(edge.id) === "enforced" && edge.evidenceIds.some((evidenceId) => {
      const proof = evidenceById.get(evidenceId)!;
      const producer = nodeById.get(proof.producerId);
      return evidenceAssurance.get(evidenceId) === "enforced" && (proof.kind === "installed-experiment" || proof.kind === "peer-measurement") && producer !== undefined && (producer.domain === "PROBER" || producer.domain === "EXTERNAL") && proof.producerId !== edge.from && proof.producerId !== edge.to && proof.producerId !== graph.declarationProducerId && proof.mechanismId !== graph.declarationMechanismId;
    }));
    return Object.freeze({ resourceId: resource.id, d1Reachable, targetScopes: Object.freeze(targetScopes), assurance: d1Reachable && !externallyEnforcedScope ? "unknown" as const : meet.assurance });
  }));
  const residualById = new Map(residuals.map((row) => [row.resourceId, row]));
  const authority = Object.freeze(resources.map((resource) => {
    checkBudget();
    const reachableD1NodeIds = d1Nodes.filter((node) => node.id === resource.id || reachableByD1Node.get(node.id)!.has(resource.id)).map((node) => node.id).sort(utf8Order);
    const relevant = relevantEdgesByResource.get(resource.id)!;
    return Object.freeze({ resourceId: resource.id, reachableD1NodeIds: Object.freeze(reachableD1NodeIds), assurance: assuranceMeet([nodeAssurance.get(resource.id)!, ...relevant.map((edge) => edgeAssurance.get(edge.id)!), residualById.get(resource.id)!.assurance]).assurance });
  }));
  const claims = Object.freeze(graph.claims.map((claim) => {
    checkBudget();
    const requiredEdges = claim.requiredEdgeIds.map((edgeId) => edgeById.get(edgeId)!); const requiredEvidence = claim.requiredEvidenceIds.map((evidenceId) => evidenceById.get(evidenceId)!);
    const dependencyStarts = [...new Set([...claim.requiredNodeIds, ...requiredEdges.flatMap((edge) => [edge.from, edge.to])])];
    const dependencyClosure = new Set([...dependencyStarts, ...transitiveReachableMany(dependencyStarts, adjacency, checkBudget)]);
    const closureAssurance = [...dependencyClosure].flatMap((nodeId) => [nodeAssurance.get(nodeId)!, ...(residualById.has(nodeId) ? [residualById.get(nodeId)!.assurance] : [])]);
    const reasons: string[] = []; const meet = assuranceMeet([...requiredEdges.map((edge) => edgeAssurance.get(edge.id)!), ...requiredEvidence.map((row) => evidenceAssurance.get(row.id)!), ...closureAssurance]);
    if (meet.incomparable) reasons.push("assurance dependencies are incomparable"); if (!inventory.valid) reasons.push("installed inventory reconciliation failed");
    const clockEvidence = world === undefined ? undefined : evidenceById.get(world.clockEvidenceId);
    const independentInstalled = requiredEvidence.some((evidence) => { const producer = nodeById.get(evidence.producerId); return evidence.kind === "installed-experiment" && evidenceAssurance.get(evidence.id) !== "unknown" && evidence.producerId !== graph.declarationProducerId && evidence.mechanismId !== graph.declarationMechanismId && (clockEvidence === undefined || (evidence.producerId !== clockEvidence.producerId && evidence.mechanismId !== clockEvidence.mechanismId)) && producer !== undefined && (producer.domain === "PROBER" || producer.domain === "EXTERNAL"); });
    if (!independentInstalled) reasons.push("claim lacks independent installed experiment evidence");
    if (meet.assurance !== "enforced") reasons.push(`claim dependency assurance is ${meet.assurance}`);
    const assurance = inventory.valid && independentInstalled ? meet.assurance : "unknown";
    const allRequiredEvidenceObserved = requiredEvidence.length > 0 && requiredEvidence.every((row) => evidenceAssurance.get(row.id) !== "unknown");
    const taxonomyCeiling = !inventory.valid ? "Specified" : assurance === "enforced" ? "Load-bearing" : assurance === "detected-only" ? "Integrated" : allRequiredEvidenceObserved ? "Implemented" : "Specified";
    return Object.freeze({ id: claim.id, assurance, taxonomyCeiling, supported: assurance === "enforced" && reasons.length === 0, reasons: Object.freeze(reasons) });
  }));
  const consumersByEvidence = new Map(graph.evidence.map((row) => [row.id, [] as string[]]));
  for (const node of graph.nodes) for (const evidenceId of node.evidenceIds) consumersByEvidence.get(evidenceId)!.push(`node:${node.id}`);
  for (const edge of graph.edges) for (const evidenceId of edge.evidenceIds) consumersByEvidence.get(evidenceId)!.push(`edge:${edge.id}`);
  for (const claim of graph.claims) for (const evidenceId of claim.requiredEvidenceIds) consumersByEvidence.get(evidenceId)!.push(`claim:${claim.id}`);
  for (const row of graph.compatibility) for (const evidenceId of row.evidenceIds) consumersByEvidence.get(evidenceId)!.push(`compatibility:${row.builtAheadId}`);
  const compatibilityLedger = Object.freeze(graph.compatibility.map((row) => { checkBudget(); const inputs = row.evidenceIds.map((evidenceId) => evidenceAssurance.get(evidenceId)!); if (row.disposition !== "retain-inert") inputs.push(nodeAssurance.get(row.replacementOrConsumerId)!); return Object.freeze({ ...row, assurance: assuranceMeet(inputs).assurance }); }));
  const evidenceLedger = Object.freeze(graph.evidence.map((evidence) => Object.freeze({ id: evidence.id, kind: evidence.kind, producerId: evidence.producerId, producerDomain: nodeById.get(evidence.producerId)!.domain, mechanismId: evidence.mechanismId, assurance: evidenceAssurance.get(evidence.id)!, freshness: evidence.freshness, consumers: Object.freeze(consumersByEvidence.get(evidence.id)!.sort(utf8Order)) })));
  checkBudget();
  const verifiedAtMs = context?.trustedNowMs ?? null;
  const diagnosticsDigest = eirDigest("keep.capability-ledger-diagnostics/v2", { inventoryReasons: inventory.reasons, claimReasons: claims.map((row) => ({ id: row.id, reasons: row.reasons })) });
  const withoutDigest = { graphDigest: graph.digest, subjectDigest: graph.subjectDigest, releaseEpoch: graph.releaseEpoch, deployment, authority, residuals, compatibility: compatibilityLedger, claims, evidence: evidenceLedger, inventory, verifiedAtMs, diagnosticsDigest };
  const canonical: CanonicalValue = { graphDigest: graph.digest, subjectDigest: graph.subjectDigest, releaseEpoch: graph.releaseEpoch, declarationProducerId: graph.declarationProducerId, declarationMechanismId: graph.declarationMechanismId, observedWorldDigest: inventory.observedWorldDigest, verifiedAtMs, diagnosticsDigest, deployment: deployment.map((row) => ({ id: row.id, kind: row.kind, domain: row.domain, module: row.module, moduleDigest: row.moduleDigest, declaredAssurance: row.declaredAssurance, assurance: row.assurance, evidenceIds: row.evidenceIds })), authority: authority.map((row) => ({ resourceId: row.resourceId, reachableD1NodeIds: row.reachableD1NodeIds, assurance: row.assurance })), residuals: residuals.map((row) => ({ resourceId: row.resourceId, d1Reachable: row.d1Reachable, targetScopes: row.targetScopes, assurance: row.assurance })), compatibility: compatibilityLedger.map((row) => ({ builtAheadId: row.builtAheadId, disposition: row.disposition, replacementOrConsumerId: row.replacementOrConsumerId, preservedInvariants: row.preservedInvariants, evidenceIds: row.evidenceIds, nextBlockingStep: row.nextBlockingStep, assurance: row.assurance })), claims: claims.map((row) => ({ id: row.id, assurance: row.assurance, taxonomyCeiling: row.taxonomyCeiling, supported: row.supported })), evidence: evidenceLedger.map((row) => ({ id: row.id, kind: row.kind, producerId: row.producerId, producerDomain: row.producerDomain, mechanismId: row.mechanismId, assurance: row.assurance, freshness: freshnessCanonical(row.freshness), consumers: row.consumers })), inventory: { valid: inventory.valid, observedWorldDigest: inventory.observedWorldDigest } };
  return Object.freeze({ ...withoutDigest, digest: eirDigest("keep.capability-ledgers/v2", canonical) });
}
