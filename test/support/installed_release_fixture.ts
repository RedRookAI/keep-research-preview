import { createHash, generateKeyPairSync } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import {
  BUILT_AHEAD_COMPATIBILITY_IDS,
  capabilityClockEvidenceDigest,
  capabilityEvidenceBindingDigest,
  capabilityInstalledInventoryDigest,
  capabilityObservationEvidenceDigest,
  deriveCapabilityLedgers as deriveCapabilityLedgersRaw,
  reconcileCapabilityInventories as reconcileCapabilityInventoriesRaw,
  type GraphEvidence,
} from "../../src/graph/capability_graph_v2.js";
import { captureReleaseSnapshot } from "../../src/graph/release_snapshot.js";
import type { InstalledCapabilityBlueprint } from "../../src/graph/installed_capability_compiler.js";
import { Ed25519ReleaseClosureSigner, compileReleaseClosureV2 } from "../../src/graph/release_closure_v2.js";
import { encodeReleaseBootBundle, encodeReleaseTrustRoot } from "../../src/graph/release_bundle.js";
import { compilePolicy, type CompilerSigner } from "../../src/policy/compiler.js";
import { StubSigner, type TrustPolicy } from "../../src/bom/bom_signing.js";
import type { JsonValue } from "../../src/policy/json.js";
import { validateEffectDecl, type EffectFamily } from "../../src/effect/effect.js";
import { compileEffectManifest, type EffectManifestSigner } from "../../src/effect/effect_manifest.js";
import { scanEffects } from "../../src/effect/effect_scan_port.js";
import { compileWaiver, scannerRuntimeDigest, type WaiverSigner } from "../../src/effect/authority_gate.js";

export const SUBJECT = "ab".repeat(32);
export const digest = (pair: string): string => pair.repeat(32);
export const inventoryFixture = () => ({
  rawSinks: ["sink.net"], credentials: ["credential.provider"], effectfulEntrypoints: ["entry.cli.message"],
  builtAhead: [...BUILT_AHEAD_COMPATIBILITY_IDS], builtAheadConsumers: ["component.broker"],
  modules: [
    { nodeId: "component.broker", module: "src/effect/broker.ts", digest: digest("45") },
    { nodeId: "entry.cli.message", module: "src/cli.ts", digest: digest("67") },
    { nodeId: "sink.net", module: "src/gateway/http_provider.ts", digest: digest("89") },
  ],
});
export const installedInventoryFixture = () => { const { rawSinks, credentials, effectfulEntrypoints, modules } = inventoryFixture(); return { rawSinks, credentials, effectfulEntrypoints, modules }; };
export const evidenceRow = (row: Omit<GraphEvidence, "digest">): GraphEvidence => ({ ...row, digest: capabilityEvidenceBindingDigest(row) });
export const deriveCapabilityLedgers = (graph: unknown, world: unknown, trustedNowMs = 15n) => deriveCapabilityLedgersRaw(graph, world, { trustedNowMs });
export const reconcileCapabilityInventories = (graph: unknown, world: unknown, trustedNowMs = 15n) => reconcileCapabilityInventoriesRaw(graph, world, { trustedNowMs });
export function rebindEvidence(input: Record<string, unknown>, evidenceId: string): void {
  const row = (input.evidence as Array<Record<string, unknown>>).find((entry) => entry.id === evidenceId)!;
  row.digest = capabilityEvidenceBindingDigest(row as unknown as Omit<GraphEvidence, "digest">);
}

export function graphInput(): Record<string, unknown> {
  const compatibilityEvidenceId = "e.compatibility";
  return {
    version: 2,
    subjectDigest: SUBJECT,
    releaseEpoch: 7n,
    declarationProducerId: "release.declarer",
    declarationMechanismId: "source-scanner",
    nodes: [
      { id: "release.declarer", kind: "role", domain: "EXTERNAL", module: "", moduleDigest: "", evidenceIds: [], declaredAssurance: "unknown" },
      { id: "prober.external", kind: "role", domain: "PROBER", module: "", moduleDigest: "", evidenceIds: [], declaredAssurance: "unknown" },
      { id: "installed.observer", kind: "role", domain: "EXTERNAL", module: "", moduleDigest: "", evidenceIds: [], declaredAssurance: "unknown" },
      { id: "artifact.observer", kind: "role", domain: "EXTERNAL", module: "", moduleDigest: "", evidenceIds: [], declaredAssurance: "unknown" },
      { id: "clock.observer", kind: "role", domain: "EXTERNAL", module: "", moduleDigest: "", evidenceIds: [], declaredAssurance: "unknown" },
      { id: "entry.cli.message", kind: "entrypoint", domain: "D1", module: "src/cli.ts", moduleDigest: digest("67"), evidenceIds: ["e.entry"], declaredAssurance: "enforced" },
      { id: "role.d1", kind: "role", domain: "D1", module: "", moduleDigest: "", evidenceIds: ["e.peer"], declaredAssurance: "enforced" },
      { id: "component.broker", kind: "component", domain: "D1", module: "src/effect/broker.ts", moduleDigest: digest("45"), evidenceIds: ["e.path"], declaredAssurance: "enforced" },
      { id: "sink.net", kind: "raw-sink", domain: "D1", module: "src/gateway/http_provider.ts", moduleDigest: digest("89"), evidenceIds: ["e.path"], declaredAssurance: "enforced" },
      { id: "credential.provider", kind: "credential", domain: "D1", module: "", moduleDigest: "", evidenceIds: ["e.residual"], declaredAssurance: "detected-only" },
    ],
    edges: [
      { id: "edge.invoke", from: "role.d1", to: "component.broker", kind: "invokes", operations: ["model.send"], targetScopes: [], evidenceIds: ["e.path"], declaredAssurance: "enforced" },
      { id: "edge.auth", from: "role.d1", to: "component.broker", kind: "authenticates", operations: ["model.send"], targetScopes: [], evidenceIds: ["e.peer"], declaredAssurance: "enforced" },
      { id: "edge.net", from: "component.broker", to: "sink.net", kind: "can-use", operations: ["model.send"], targetScopes: ["loopback:test-endpoint"], evidenceIds: ["e.path"], declaredAssurance: "enforced" },
      { id: "edge.key", from: "role.d1", to: "credential.provider", kind: "can-read", operations: ["provider.authenticate"], targetScopes: ["credential:provider"], evidenceIds: ["e.residual"], declaredAssurance: "detected-only" },
    ],
    evidence: [
      evidenceRow({ id: "e.peer", kind: "peer-measurement", subjectDigest: SUBJECT, releaseEpoch: 7n, producerId: "prober.external", mechanismId: "role-channel-probe", contentDigest: digest("cd"), subjectIds: ["node:role.d1", "edge:edge.auth", "claim:claim.broker-mediation"], assurance: "enforced", freshness: { kind: "window", observedAtMs: 10n, expiresAtMs: 20n } }),
      evidenceRow({ id: "e.installed", kind: "installed-experiment", subjectDigest: SUBJECT, releaseEpoch: 7n, producerId: "installed.observer", mechanismId: "loopback-wire-observer", contentDigest: capabilityObservationEvidenceDigest({ kind: "installed-runtime", subjectDigest: SUBJECT, releaseEpoch: 7n, producerId: "installed.observer", mechanismId: "loopback-wire-observer", inventoryDigest: capabilityInstalledInventoryDigest(installedInventoryFixture()) }), subjectIds: ["inventory:installed-runtime"], assurance: "enforced", freshness: { kind: "window", observedAtMs: 10n, expiresAtMs: 20n } }),
      evidenceRow({ id: "e.entry", kind: "installed-experiment", subjectDigest: SUBJECT, releaseEpoch: 7n, producerId: "installed.observer", mechanismId: "installed-entrypoint-scan", contentDigest: digest("dc"), subjectIds: ["node:entry.cli.message"], assurance: "enforced", freshness: { kind: "window", observedAtMs: 10n, expiresAtMs: 20n } }),
      evidenceRow({ id: "e.path", kind: "installed-experiment", subjectDigest: SUBJECT, releaseEpoch: 7n, producerId: "installed.observer", mechanismId: "loopback-path-experiment", contentDigest: digest("fe"), subjectIds: ["node:component.broker", "node:sink.net", "edge:edge.invoke", "edge:edge.net", "claim:claim.broker-mediation"], assurance: "enforced", freshness: { kind: "window", observedAtMs: 10n, expiresAtMs: 20n } }),
      evidenceRow({ id: "e.residual", kind: "residual", subjectDigest: SUBJECT, releaseEpoch: 7n, producerId: "installed.observer", mechanismId: "credential-read-probe", contentDigest: digest("12"), subjectIds: ["node:credential.provider", "edge:edge.key", "claim:claim.credential-isolation"], assurance: "detected-only", freshness: { kind: "window", observedAtMs: 10n, expiresAtMs: 20n } }),
      evidenceRow({ id: "e.clock", kind: "trusted-time", subjectDigest: SUBJECT, releaseEpoch: 7n, producerId: "clock.observer", mechanismId: "signed-clock", contentDigest: capabilityClockEvidenceDigest({ subjectDigest: SUBJECT, releaseEpoch: 7n, observedAtMs: 10n, expiresAtMs: 20n, producerId: "clock.observer", mechanismId: "signed-clock" }), subjectIds: ["clock:current"], assurance: "enforced", freshness: { kind: "window", observedAtMs: 10n, expiresAtMs: 20n } }),
      evidenceRow({ id: compatibilityEvidenceId, kind: "artifact-scan", subjectDigest: SUBJECT, releaseEpoch: 7n, producerId: "artifact.observer", mechanismId: "package-inventory", contentDigest: digest("34"), subjectIds: BUILT_AHEAD_COMPATIBILITY_IDS.map((id) => `compatibility:${id}`), assurance: "enforced", freshness: { kind: "non-expiring" } }),
      evidenceRow({ id: "e.neuter", kind: "neuter", subjectDigest: SUBJECT, releaseEpoch: 7n, producerId: "artifact.observer", mechanismId: "inertness-probe", contentDigest: digest("35"), subjectIds: BUILT_AHEAD_COMPATIBILITY_IDS.filter((id) => id !== "tree_fingerprint" && id !== "monitor.channel").map((id) => `compatibility:${id}`), assurance: "enforced", freshness: { kind: "window", observedAtMs: 10n, expiresAtMs: 20n } }),
    ],
    claims: [
      { id: "claim.broker-mediation", operationIds: ["model.send"], requiredNodeIds: ["role.d1", "component.broker", "sink.net"], requiredEdgeIds: ["edge.auth", "edge.invoke", "edge.net"], requiredEvidenceIds: ["e.path", "e.peer"] },
      { id: "claim.credential-isolation", operationIds: ["provider.authenticate"], requiredNodeIds: ["role.d1", "credential.provider"], requiredEdgeIds: ["edge.key"], requiredEvidenceIds: ["e.residual"] },
    ],
    compatibility: BUILT_AHEAD_COMPATIBILITY_IDS.map((builtAheadId) => ({
      builtAheadId,
      disposition: builtAheadId === "tree_fingerprint" ? "consume" : builtAheadId === "monitor.channel" ? "supersede" : "retain-inert",
      replacementOrConsumerId: builtAheadId === "tree_fingerprint" || builtAheadId === "monitor.channel" ? "component.broker" : "",
      preservedInvariants: [`invariant:${builtAheadId}`],
      evidenceIds: builtAheadId === "tree_fingerprint" || builtAheadId === "monitor.channel" ? [compatibilityEvidenceId] : [compatibilityEvidenceId, "e.neuter"],
      nextBlockingStep: builtAheadId === "profile_attestation" ? "A7" : "A5-or-later",
    })),
  };
}

export function worldInput(): Record<string, unknown> {
  const inventory = inventoryFixture();
  return {
    clockEvidenceId: "e.clock",
    declaration: { producerId: "release.declarer", mechanismId: "source-scanner", inventory },
    observations: [{
      producerId: "installed.observer",
      mechanismId: "loopback-wire-observer",
      kind: "installed-runtime",
      subjectDigest: SUBJECT,
      releaseEpoch: 7n,
      evidenceId: "e.installed",
      inventory: installedInventoryFixture(),
    }],
  };
}

export function bindGraphToPackage(packageRoot: string, observedAtMs = 10n, expiresAtMs = 20n): { graph: Record<string, unknown>; world: Record<string, unknown>; subjectDigest: string } {
  const graph = graphInput();
  const world = worldInput();
  const moduleAliases = new Map([["src/effect/broker.ts", existsSync(join(packageRoot, "src/effect/broker.ts")) ? "src/effect/broker.ts" : "src/broker/broker.ts"], ["src/cli.ts", existsSync(join(packageRoot, "src/cli.ts")) ? "src/cli.ts" : "src/cli/keep.ts"], ["src/gateway/http_provider.ts", "src/gateway/http_provider.ts"]]);
  const moduleRows = [...moduleAliases].map(([declared, module]) => ({ declared, module,
    digest: createHash("sha256").update(readFileSync(join(packageRoot, module))).digest("hex"),
  }));
  for (const node of graph.nodes as Array<Record<string, unknown>>) {
    const row = moduleRows.find((entry) => entry.declared === node.module);
    if (row) { node.module = row.module; node.moduleDigest = row.digest; }
  }
  const inventory = inventoryFixture();
  inventory.modules = inventory.modules.map((row) => { const found = moduleRows.find((entry) => entry.declared === row.module)!; return { ...row, module: found.module, digest: found.digest }; });
  const installed = { rawSinks: inventory.rawSinks, credentials: inventory.credentials, effectfulEntrypoints: inventory.effectfulEntrypoints, modules: inventory.modules };
  (world.declaration as Record<string, unknown>).inventory = inventory;
  ((world.observations as Array<Record<string, unknown>>)[0]!).inventory = installed;
  const snapshot = captureReleaseSnapshot(packageRoot); const subjectDigest = snapshot.digest; snapshot.dispose();
  graph.subjectDigest = subjectDigest;
  for (const evidence of graph.evidence as Array<Record<string, unknown>>) { evidence.subjectDigest = subjectDigest; const freshness = evidence.freshness as Record<string, unknown>; if (freshness.kind === "window") { freshness.observedAtMs = observedAtMs; freshness.expiresAtMs = expiresAtMs; } }
  const installedEvidence = (graph.evidence as Array<Record<string, unknown>>).find((row) => row.id === "e.installed")!;
  installedEvidence.contentDigest = capabilityObservationEvidenceDigest({ kind: "installed-runtime", subjectDigest, releaseEpoch: 7n, producerId: "installed.observer", mechanismId: "loopback-wire-observer", inventoryDigest: capabilityInstalledInventoryDigest(installed) });
  const clockEvidence = (graph.evidence as Array<Record<string, unknown>>).find((row) => row.id === "e.clock")!;
  clockEvidence.contentDigest = capabilityClockEvidenceDigest({ subjectDigest, releaseEpoch: 7n, observedAtMs, expiresAtMs, producerId: "clock.observer", mechanismId: "signed-clock" });
  for (const evidence of graph.evidence as Array<Record<string, unknown>>) rebindEvidence(graph, evidence.id as string);
  const observation = (world.observations as Array<Record<string, unknown>>)[0]!;
  observation.subjectDigest = subjectDigest;
  return { graph, world, subjectDigest };
}

export function capabilityBlueprintFixture(): InstalledCapabilityBlueprint {
  const graph = graphInput(); const world = worldInput();
  (graph.evidence as unknown[]).push(evidenceRow({ id: "e.discovered-sinks", kind: "installed-experiment", subjectDigest: SUBJECT, releaseEpoch: 7n, producerId: "artifact.observer", mechanismId: "effect-discovery-scan", contentDigest: digest("d7"), subjectIds: ["node:sink.fs", "node:sink.probe-hostinfo"], assurance: "enforced", freshness: { kind: "window", observedAtMs: 10n, expiresAtMs: 20n } }));
  const nodes = (graph.nodes as Array<Record<string, unknown>>).map(({ moduleDigest: _digest, ...node }) => node);
  nodes.push({ id: "component.evidence-probe", kind: "component", domain: "PROBER", module: "probe.mjs", evidenceIds: [], declaredAssurance: "unknown" });
  nodes.push({ id: "sink.fs", kind: "raw-sink", domain: "D1", module: "src/effect/broker.ts", evidenceIds: ["e.discovered-sinks"], declaredAssurance: "enforced" });
  nodes.push({ id: "sink.probe-hostinfo", kind: "raw-sink", domain: "PROBER", module: "probe.mjs", evidenceIds: ["e.discovered-sinks"], declaredAssurance: "enforced" });
  return {
    declarationProducerId: graph.declarationProducerId as string, declarationMechanismId: graph.declarationMechanismId as string,
    nodes: nodes as unknown as InstalledCapabilityBlueprint["nodes"],
    edges: graph.edges as unknown as InstalledCapabilityBlueprint["edges"],
    evidence: (graph.evidence as Array<Record<string, unknown>>).map(({ subjectDigest: _subject, releaseEpoch: _epoch, contentDigest: _content, digest: _digest, ...evidence }) => ({ ...evidence, ...((evidence.kind === "trusted-time" || evidence.id === "e.installed") ? {} : { experiment: { module: "probe.mjs", checks: [{ kind: "file", path: "src/cli.ts" }] } }) })) as unknown as InstalledCapabilityBlueprint["evidence"],
    claims: graph.claims as unknown as InstalledCapabilityBlueprint["claims"], compatibility: graph.compatibility as unknown as InstalledCapabilityBlueprint["compatibility"],
    observations: (world.observations as Array<Record<string, unknown>>).map(({ producerId, mechanismId, kind, evidenceId }) => ({ producerId, mechanismId, kind, evidenceId, experiment: { module: "probe.mjs", checks: [{ kind: "contains", path: "src/cli.ts", needle: "cli" }] } })) as unknown as InstalledCapabilityBlueprint["observations"],
  };
}

/** Organization-side deployment fixture. The returned keys and bundles stay outside the installed package. */
export function createSignedInstalledReleaseFixture(packageRoot: string, providerDescriptorDigest: string, nowMs = BigInt(Date.now()), scannerEnginePath?: string): { readonly bundle: Uint8Array; readonly trustRoot: Uint8Array } {
  const expiresAtMs = nowMs + 15n * 60n * 1_000n;
  const { graph, world, subjectDigest } = bindGraphToPackage(packageRoot, nowMs, expiresAtMs);
  const policySigner: CompilerSigner = { signer: new StubSigner("enterprise-policy-secret", "enterprise.policy"), keyid: "enterprise.policy", verifyKey: "enterprise-policy-secret" };
  const policyTrust: TrustPolicy = { trustedKeys: new Map([["enterprise.policy", "enterprise-policy-secret"]]), threshold: 1 };
  const policy: JsonValue = { version: 1n, combiningAlgorithm: "deny-overrides", principals: [{ name: "agent", labels: [] }], effects: [{ id: "e-net", effectType: "http.post", resourceSelector: "*" }], guards: [], rules: [{ id: "allow-net", decision: "permit", subjects: ["agent"], entryPoints: ["egress.net"], effect: "e-net" }] };
  const policyBundle = compilePolicy(policy, [policySigner]);
  const scan = scanEffects({ root: packageRoot, owners: new Map<EffectFamily, string>([["net", "src/gateway/http_provider.ts"]]), ...(scannerEnginePath === undefined ? {} : { enginePath: scannerEnginePath }) });
  const effectSigner: EffectManifestSigner = { signer: new StubSigner("enterprise-effect-secret", "enterprise.effect"), keyid: "enterprise.effect", verifyKey: "enterprise-effect-secret" };
  const manifestTrust: TrustPolicy = { trustedKeys: new Map([["enterprise.effect", "enterprise-effect-secret"]]), threshold: 1 };
  const scannerToolDigest = scannerRuntimeDigest(scannerEnginePath);
  const manifest = compileEffectManifest([validateEffectDecl({ family: "net", owner: "src/gateway/http_provider.ts" })], policyBundle, { artifactGraphDigest: scan.graphDigest, scannerToolDigest }, [effectSigner]);
  const waiverSigner: WaiverSigner = { signer: new StubSigner("enterprise-waiver-secret", "enterprise.waiver"), keyid: "enterprise.waiver", verifyKey: "enterprise-waiver-secret" };
  const waiverTrust: TrustPolicy = { trustedKeys: new Map([["enterprise.waiver", "enterprise-waiver-secret"]]), threshold: 1 };
  const counts = new Map<string, { file: string; family: string; construct: string; count: number; reason: string }>();
  for (const finding of scan.findings) {
    const key = `${finding.file}\0${finding.family}\0${finding.construct}`;
    const prior = counts.get(key);
    counts.set(key, { file: finding.file, family: finding.family, construct: finding.construct, count: (prior?.count ?? 0) + 1, reason: "exact installed enterprise baseline; residualized by the capability graph" });
  }
  const waiver = compileWaiver({ generation: 0, predecessorDigest: "" }, [...counts.values()], [waiverSigner]);
  const authority = { manifest, policyBundle, trust: { manifestTrust, policyTrust }, waiver, baseline: waiver, boundWaiverDigest: waiver.payloadDigest, previousReleaseHead: "", waiverTrust };
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const bindings = { artifactInventoryDigest: subjectDigest, effectManifestDigest: manifest.payloadDigest, policyBundleDigest: policyBundle.payloadDigest, scannerToolDigest, authorityWaiverDigest: waiver.payloadDigest, providerDescriptorDigest };
  const security = { trustedTime: "enforced" as const, signerRevocation: "enforced" as const, rollbackProtection: "enforced" as const, immutableArtifact: "enforced" as const };
  const closure = compileReleaseClosureV2({ profile: "production", graph, world, context: { trustedNowMs: nowMs }, bindings, lineage: { sequence: 0n, predecessorClosureDigest: "" }, security, issuedAtMs: nowMs, expiresAtMs, keyEpoch: 1n, signers: [new Ed25519ReleaseClosureSigner("release.enterprise", 1n, privatePem)] });
  const releaseTrust = { threshold: 1, anchors: [{ keyId: "release.enterprise", algorithm: "ed25519" as const, verifyKey: publicPem, keyEpoch: 1n, validFromMs: nowMs - 1_000n, validUntilMs: expiresAtMs + 1_000n, revokedAtMs: null }] };
  const verification = { closure, graph, world, context: { trustedNowMs: nowMs }, bindings, trust: releaseTrust, lineage: { sequence: 0n, predecessorClosureDigest: "" }, expectedProfile: "production" as const, observedSecurity: security, bootNonce: "boot.enterprise.installed" };
  return { bundle: encodeReleaseBootBundle({ verification, authority }), trustRoot: encodeReleaseTrustRoot({ releaseTrust, manifestTrust, policyTrust, waiverTrust }) };
}
