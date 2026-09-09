/** Machine materializer for A4 graph/world artifacts from one captured installed tree and measured experiment plan. */
import { createHash, randomBytes } from "node:crypto";
import { readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, join, relative, sep } from "node:path";
import {
  BUILT_AHEAD_COMPATIBILITY_IDS,
  capabilityClockEvidenceDigest,
  capabilityEvidenceBindingDigest,
  capabilityInstalledInventoryDigest,
  capabilityObservationEvidenceDigest,
  captureCapabilityGraphV2,
  type BuiltAheadDisposition,
  type CapabilityGraphV2Input,
  type CapturedCapabilityGraphV2,
  type GraphClaim,
  type GraphEdge,
  type GraphEvidence,
  type GraphNode,
  type InventoryObservation,
  type ObservedWorld,
} from "./capability_graph_v2.js";
import { decodeCanonical, eirDigest, encodeCanonical, type CanonicalValue } from "../eir/canonical.js";
import type { ReleaseSnapshotEntry } from "./release_snapshot.js";
import type { EffectFinding } from "../effect/effect_scan_port.js";

type NodeBlueprint = Omit<GraphNode, "moduleDigest">;
type ExperimentCheck = { readonly kind: "file"; readonly path: string } | { readonly kind: "contains"; readonly path: string; readonly needle: string };
type ExperimentBlueprint = { readonly module: string; readonly checks: readonly ExperimentCheck[] };
type EvidenceBlueprint = Omit<GraphEvidence, "subjectDigest" | "releaseEpoch" | "contentDigest" | "digest"> & { readonly experiment?: ExperimentBlueprint };
type ObservationBlueprint = Pick<InventoryObservation, "producerId" | "mechanismId" | "kind" | "evidenceId"> & { readonly experiment: ExperimentBlueprint };
export interface InstalledCapabilityBlueprint {
  readonly declarationProducerId: string; readonly declarationMechanismId: string;
  readonly nodes: readonly NodeBlueprint[]; readonly edges: readonly GraphEdge[]; readonly evidence: readonly EvidenceBlueprint[];
  readonly claims: readonly GraphClaim[]; readonly compatibility: readonly BuiltAheadDisposition[]; readonly observations: readonly ObservationBlueprint[];
}
export interface InstalledCapabilityCompilation { readonly graph: CapturedCapabilityGraphV2; readonly world: ObservedWorld; }
export class InstalledCapabilityCompilerError extends Error { constructor(message: string) { super(`installed capability compiler: ${message}`); this.name = "InstalledCapabilityCompilerError"; } }
const HEX64 = /^[0-9a-f]{64}$/;
const sha256File = (path: string): string => createHash("sha256").update(readFileSync(path)).digest("hex");

export function compileInstalledCapabilityGraph(input: { readonly snapshotRoot: string; readonly snapshotEntries: readonly ReleaseSnapshotEntry[]; readonly discoveredEffects: readonly EffectFinding[]; readonly discoveryGraphDigest: string; readonly subjectDigest: string; readonly releaseEpoch: bigint; readonly blueprint: InstalledCapabilityBlueprint }): InstalledCapabilityCompilation {
  if (!isAbsolute(input.snapshotRoot) || !HEX64.test(input.subjectDigest)) throw new InstalledCapabilityCompilerError("snapshot identity is malformed");
  const root = realpathSync(input.snapshotRoot);
  let blueprint: InstalledCapabilityBlueprint; try { blueprint = decodeCanonical(encodeCanonical(input.blueprint as unknown as CanonicalValue)) as unknown as InstalledCapabilityBlueprint; } catch (error) { throw new InstalledCapabilityCompilerError(`blueprint is not bounded inert canonical data: ${error instanceof Error ? error.message : String(error)}`); }
  const declaredCodeModules = input.snapshotEntries.map((entry) => entry.path).filter((path) => !/\.d\.[cm]?ts$/i.test(path) && /\.(?:[cm]?[jt]sx?|wasm|node)$/i.test(path)).sort();
  // Without native D3 load provenance, an interpreter or read+eval path can turn
  // any regular artifact byte into executable behavior regardless of suffix/mode.
  const artifactInfluenceModules: string[] = []; for (let index = 0; index < input.snapshotEntries.length; index++) { const entry = input.snapshotEntries[index]; if (entry === undefined || typeof entry.path !== "string" || entry.path === "") throw new InstalledCapabilityCompilerError(`snapshot contains an invalid artifact path at ${index}/${input.snapshotEntries.length}`); artifactInfluenceModules.push(entry.path); } artifactInfluenceModules.sort();
  const discoveredModules = declaredCodeModules.filter((path) => !path.startsWith("node_modules/") && !path.startsWith("tools/"));
  const declaredModules = [...new Set(blueprint.nodes.filter((node) => node.module !== "").map((node) => node.module))].sort();
  if (discoveredModules.length !== declaredModules.length || discoveredModules.some((path, index) => path !== declaredModules[index])) { const missing = discoveredModules.filter((path) => !declaredModules.includes(path)).slice(0, 8); const extra = declaredModules.filter((path) => !discoveredModules.includes(path)).slice(0, 8); throw new InstalledCapabilityCompilerError(`blueprint module closure differs from installed executable inventory; missing=${missing.join(",") || "none"}; extra=${extra.join(",") || "none"}`); }
  let nodes = blueprint.nodes.map((node) => {
    if (node.module === "") return { ...node, moduleDigest: "" };
    let path: string; try { path = realpathSync(join(root, ...node.module.split("/"))); const rel = relative(root, path); if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel) || !statSync(path).isFile()) throw new Error("escape"); } catch { throw new InstalledCapabilityCompilerError(`module is absent or escapes snapshot: ${node.module}`); }
    return { ...node, moduleDigest: sha256File(path) };
  });
  // The static scanner is intentionally not claimed sound for computed imports,
  // native loaders, or data-driven dispatch. Every executable module therefore
  // receives a machine-owned conservative raw-sink shadow until stronger runtime
  // isolation can prove the boundary absent.
  for (const module of artifactInfluenceModules) {
    if (nodes.some((node) => node.kind === "raw-sink" && node.module === module)) continue;
    const suffix = createHash("sha256").update(module).digest("hex").slice(0, 20);
    nodes.push({ id: `sink.unknown-executable.${suffix}`, kind: "raw-sink", domain: "D1", module, moduleDigest: sha256File(join(root, ...module.split("/"))), evidenceIds: [], declaredAssurance: "detected-only" });
  }
  if (input.discoveredEffects.some((finding) => finding.family === "env") && !nodes.some((node) => node.id === "credential.ambient-environment")) nodes.push({ id: "credential.ambient-environment", kind: "credential", domain: "D1", module: "", moduleDigest: "", evidenceIds: [], declaredAssurance: "detected-only" });
  const clockWindow = blueprint.evidence.find((row) => row.kind === "trusted-time")?.freshness; if (clockWindow?.kind !== "window") throw new InstalledCapabilityCompilerError("blueprint lacks a bounded trusted-time window");
  if (!nodes.some((node) => node.id === "role.d1" && node.kind === "role")) throw new InstalledCapabilityCompilerError("blueprint lacks the current D1 role");
  const resourceNodes = nodes.filter((node) => node.kind === "raw-sink" || node.kind === "credential");
  const generatedEvidence: GraphEvidence[] = []; const generatedEdges: GraphEdge[] = [];
  nodes = nodes.map((node) => {
    if (node.module !== "" || node.kind === "credential" || node.kind === "raw-sink") {
      const suffix = createHash("sha256").update(node.id).digest("hex").slice(0, 20);
      return { ...node, domain: "D1" as const, ...(node.kind === "credential" || node.kind === "raw-sink" ? { declaredAssurance: "detected-only" as const, evidenceIds: [...node.evidenceIds, `e.discovered.${suffix}`] } : {}) };
    }
    return node;
  });
  for (const resource of resourceNodes) {
    const suffix = createHash("sha256").update(resource.id).digest("hex").slice(0, 20); const evidenceId = `e.discovered.${suffix}`; const edgeId = `edge.discovered.${suffix}`;
    const edge: GraphEdge = Object.freeze({ id: edgeId, from: "role.d1", to: resource.id, kind: resource.kind === "credential" ? "can-read" : "can-use", operations: Object.freeze([resource.kind === "credential" ? "credential.read" : "effect.invoke"]), targetScopes: Object.freeze([resource.module === "" ? `credential:${resource.id}` : `module:${resource.module}`]), evidenceIds: Object.freeze([evidenceId]), declaredAssurance: "detected-only" }); generatedEdges.push(edge);
    const unsigned = { id: evidenceId, kind: "residual" as const, subjectDigest: input.subjectDigest, releaseEpoch: input.releaseEpoch, producerId: "installed.observer", mechanismId: "closed-world-effect-discovery", contentDigest: input.discoveryGraphDigest, subjectIds: [`node:${resource.id}`, `edge:${edgeId}`], assurance: "detected-only" as const, freshness: clockWindow };
    generatedEvidence.push(Object.freeze({ ...unsigned, digest: capabilityEvidenceBindingDigest(unsigned) }));
  }
  const installedInventory = Object.freeze({ rawSinks: nodes.filter((node) => node.kind === "raw-sink").map((node) => node.id), credentials: nodes.filter((node) => node.kind === "credential").map((node) => node.id), effectfulEntrypoints: nodes.filter((node) => node.kind === "entrypoint").map((node) => node.id), modules: nodes.filter((node) => node.module !== "").map((node) => ({ nodeId: node.id, module: node.module, digest: node.moduleDigest })) });
  const consumers = [...new Set(blueprint.compatibility.filter((row) => row.disposition !== "retain-inert").map((row) => row.replacementOrConsumerId))];
  const declarationInventory = Object.freeze({ ...installedInventory, builtAhead: [...BUILT_AHEAD_COMPATIBILITY_IDS], builtAheadConsumers: consumers });
  const observationByEvidence = new Map(blueprint.observations.map((row) => [row.evidenceId, row] as const));
  const runExperiment = (evidenceId: string, mechanismId: string, experiment: ExperimentBlueprint): string => {
    const experimentPath = realpathSync(join(root, ...experiment.module.split("/"))); const rel = relative(root, experimentPath); if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel) || !statSync(experimentPath).isFile()) throw new InstalledCapabilityCompilerError(`evidence ${evidenceId} experiment escapes the snapshot`);
    if (!Array.isArray(experiment.checks) || experiment.checks.length === 0 || experiment.checks.length > 128) throw new InstalledCapabilityCompilerError(`evidence ${evidenceId} experiment has no bounded typed predicates`);
    const facts = experiment.checks.map((check) => { let path: string; try { path = realpathSync(join(root, ...check.path.split("/"))); const rel = relative(root, path); if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel) || !statSync(path).isFile()) throw new Error("escape"); } catch { throw new InstalledCapabilityCompilerError(`evidence ${evidenceId} predicate path is absent or escapes`); } const bytes = readFileSync(path); const matched = check.kind === "file" || bytes.toString("utf8").includes(check.needle); if (!matched) throw new InstalledCapabilityCompilerError(`evidence ${evidenceId} predicate did not hold`); return { kind: check.kind, path: check.path, digest: createHash("sha256").update(bytes).digest("hex"), matched }; });
    const nonce = randomBytes(16).toString("hex"); const propositionDigest = eirDigest("keep.capability-experiment-proposition/v2", { evidenceId, subjectDigest: input.subjectDigest, releaseEpoch: input.releaseEpoch, mechanismId, checks: experiment.checks as unknown as CanonicalValue });
    // Do not execute artifact-owned code in the compiler's ambient authority. The
    // compiler itself is the bounded observer for these typed, read-only probes.
    // Native D3 may later replace this with a sandboxed external observer.
    return eirDigest("keep.installed-capability-experiment-receipt/v2", { evidenceId, subjectDigest: input.subjectDigest, releaseEpoch: input.releaseEpoch, mechanismId, experimentModuleDigest: sha256File(experimentPath), propositionDigest, nonce, facts: facts as unknown as CanonicalValue });
  };
  const evidence = [...blueprint.evidence.map((row): GraphEvidence => {
    const observation = observationByEvidence.get(row.id); let contentDigest: string;
    if (observation !== undefined) { runExperiment(row.id, row.mechanismId, observation.experiment); contentDigest = capabilityObservationEvidenceDigest({ kind: observation.kind, subjectDigest: input.subjectDigest, releaseEpoch: input.releaseEpoch, producerId: observation.producerId, mechanismId: observation.mechanismId, inventoryDigest: capabilityInstalledInventoryDigest(installedInventory) }); }
    else if (row.kind === "trusted-time" && row.freshness.kind === "window") contentDigest = capabilityClockEvidenceDigest({ subjectDigest: input.subjectDigest, releaseEpoch: input.releaseEpoch, observedAtMs: row.freshness.observedAtMs, expiresAtMs: row.freshness.expiresAtMs, producerId: row.producerId, mechanismId: row.mechanismId });
    else {
      if (row.experiment === undefined) throw new InstalledCapabilityCompilerError(`evidence ${row.id} lacks an invoked experiment`);
      contentDigest = runExperiment(row.id, row.mechanismId, row.experiment);
    }
    const { experiment: _experiment, ...base } = row;
    // An experiment shipped inside the subject can corroborate detected facts, but it
    // cannot independently enforce a proposition about its own artifact.
    const assurance = row.kind === "trusted-time" ? row.assurance : "detected-only";
    const unsigned = { ...base, assurance, subjectDigest: input.subjectDigest, releaseEpoch: input.releaseEpoch, contentDigest };
    return Object.freeze({ ...unsigned, digest: capabilityEvidenceBindingDigest(unsigned) });
  }), ...generatedEvidence];
  const graphInput: CapabilityGraphV2Input = { version: 2, subjectDigest: input.subjectDigest, releaseEpoch: input.releaseEpoch, declarationProducerId: blueprint.declarationProducerId, declarationMechanismId: blueprint.declarationMechanismId, nodes, edges: [...blueprint.edges, ...generatedEdges], evidence, claims: blueprint.claims, compatibility: blueprint.compatibility };
  const graph = captureCapabilityGraphV2(graphInput);
  const world: ObservedWorld = Object.freeze({ clockEvidenceId: evidence.find((row) => row.kind === "trusted-time")?.id ?? "", declaration: Object.freeze({ producerId: blueprint.declarationProducerId, mechanismId: blueprint.declarationMechanismId, inventory: declarationInventory }), observations: Object.freeze(blueprint.observations.map(({ experiment: _experiment, ...row }) => Object.freeze({ ...row, subjectDigest: input.subjectDigest, releaseEpoch: input.releaseEpoch, inventory: installedInventory }))) });
  return Object.freeze({ graph, world });
}
