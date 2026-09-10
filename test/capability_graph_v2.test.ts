import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync, spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import {
  BUILT_AHEAD_COMPATIBILITY_IDS,
  CAPABILITY_GRAPH_LIMITS,
  CapabilityGraphError,
  capabilityClockEvidenceDigest,
  capabilityEvidenceBindingDigest,
  capabilityInstalledInventoryDigest,
  capabilityObservationEvidenceDigest,
  captureCapabilityGraphV2,
  deriveCapabilityLedgers as deriveCapabilityLedgersRaw,
  reconcileCapabilityInventories as reconcileCapabilityInventoriesRaw,
  type GraphEvidence,
} from "../src/graph/capability_graph_v2.js";
import {
  Ed25519ReleaseClosureSigner,
  StubReleaseClosureSigner,
  compileReleaseClosureV2,
  verifyReleaseAdmissionToken,
  verifyReleaseClosureV2,
} from "../src/graph/release_closure_v2.js";
import { compileInstalledReleaseV2 } from "../src/graph/release_compiler.js";
import type { InstalledCapabilityBlueprint } from "../src/graph/installed_capability_compiler.js";
import { captureReleaseSnapshot } from "../src/graph/release_snapshot.js";
import { verifyInstalledReleaseAtBoot, verifyRestrictedReleaseAdmission } from "../src/graph/release_boot.js";
import { compilePolicy, type CompilerSigner } from "../src/policy/compiler.js";
import { StubSigner, type TrustPolicy } from "../src/bom/bom_signing.js";
import type { JsonValue } from "../src/policy/json.js";
import { validateEffectDecl, type EffectFamily } from "../src/effect/effect.js";
import { compileEffectManifest, type EffectManifestSigner } from "../src/effect/effect_manifest.js";
import { scanEffects } from "../src/effect/effect_scan_port.js";
import { compileWaiver, scannerRuntimeDigest, type WaiverSigner } from "../src/effect/authority_gate.js";
import { composeKeep } from "../src/compose.js";
import { remoteProviderIdentityDigest } from "../src/gateway/provider_descriptor.js";
import { constructCapturedRemoteProvider } from "../src/gateway/provider_descriptor.js";
import { buildDefaultBrokeredEgress } from "../src/gateway/brokered_egress.js";
import { decodeCanonical, encodeCanonical, type CanonicalValue } from "../src/eir/canonical.js";
import { decodeReleaseBootBundle, decodeReleaseTrustRoot, encodeReleaseBootBundle, encodeReleaseTrustRoot } from "../src/graph/release_bundle.js";

import { SUBJECT, bindGraphToPackage, capabilityBlueprintFixture, createSignedInstalledReleaseFixture, deriveCapabilityLedgers, digest, evidenceRow, graphInput, installedInventoryFixture, rebindEvidence, reconcileCapabilityInventories, worldInput } from "./support/installed_release_fixture.js";

test("organization-side fixture emits a production release bundle bound to the exact provider descriptor", () => {
  const packageRoot = mkdtempSync(join(tmpdir(), "keep-enterprise-release-fixture-"));
  try {
    for (const name of ["dist", "src", "tools", "package.json", "package-lock.json", "tsconfig.json", "README.md", "LICENSE"]) if (existsSync(join(process.cwd(), name))) execFileSync("cp", ["-a", join(process.cwd(), name), packageRoot]);
    const descriptor = remoteProviderIdentityDigest({ mode: "openai-compatible", baseUrl: "https://models.enterprise.example/v1", model: "enterprise-model", apiKey: "deployment-only" });
    const fixture = createSignedInstalledReleaseFixture(packageRoot, descriptor);
    const trust = decodeReleaseTrustRoot(fixture.trustRoot);
    const decoded = decodeReleaseBootBundle(fixture.bundle, trust);
    assert.equal(decoded.verification.expectedProfile, "production");
    assert.equal(decoded.verification.bindings.providerDescriptorDigest, descriptor);
    const closure = decoded.verification.closure as { readonly payload: { readonly providerDescriptorDigest: string } };
    assert.equal(closure.payload.providerDescriptorDigest, descriptor);
  } finally { rmSync(packageRoot, { recursive: true, force: true }); }
});

test("A4 graph capture is bounded, exact, owned, sorted and digest-deterministic", () => {
  const first = graphInput();
  const second = structuredClone(first) as Record<string, unknown>;
  (second.nodes as unknown[]).reverse();
  (second.edges as unknown[]).reverse();
  (second.evidence as unknown[]).reverse();
  const a = captureCapabilityGraphV2(first);
  const b = captureCapabilityGraphV2(second);
  assert.equal(a.digest, b.digest);
  assert.deepEqual(a.nodes.map((node) => node.id), [...a.nodes.map((node) => node.id)].sort());
  (first.nodes as Array<Record<string, unknown>>)[0]!.id = "mutated.after.capture";
  assert.equal(a.nodes.some((node) => node.id === "mutated.after.capture"), false);
  assert.throws(() => captureCapabilityGraphV2({ ...graphInput(), surprise: true }), /keys must be exactly/);
  assert.throws(() => captureCapabilityGraphV2(new Proxy(graphInput(), {})), /non-plain data/);
  assert.equal(CAPABILITY_GRAPH_LIMITS.canonicalDepth, 16);
  assert.equal(CAPABILITY_GRAPH_LIMITS.verificationBudgetMs, 5_000);

  const sparse = graphInput();
  const operations = new Array(2); operations[1] = "model.send"; Object.defineProperty(operations, "extra", { value: true, enumerable: true });
  (sparse.edges as Array<Record<string, unknown>>)[0]!.operations = operations;
  assert.throws(() => captureCapabilityGraphV2(sparse), CapabilityGraphError);
});

test("A4 graph ordering is code-point deterministic and node module policy is exact", () => {
  const ordered = graphInput();
  (ordered.nodes as Array<Record<string, unknown>>).push(
    { id: "z.node", kind: "role", domain: "NONE", module: "", moduleDigest: "", evidenceIds: [], declaredAssurance: "unknown" },
    { id: "a/node", kind: "role", domain: "NONE", module: "", moduleDigest: "", evidenceIds: [], declaredAssurance: "unknown" },
  );
  const ids = captureCapabilityGraphV2(ordered).nodes.map((row) => row.id);
  assert.ok(ids.indexOf("a/node") < ids.indexOf("artifact.observer"));
  const invalidModule = graphInput();
  (invalidModule.nodes as Array<Record<string, unknown>>).find((row) => row.id === "credential.provider")!.module = "src/secret.ts";
  assert.throws(() => captureCapabilityGraphV2(invalidModule), /module must be non-empty exactly/);
});

test("A4 graph rejects placeholder digests, cross-subject evidence and accessor input", () => {
  assert.throws(() => captureCapabilityGraphV2({ ...graphInput(), subjectDigest: "0".repeat(64) }), /non-placeholder/);
  const crossSubject = graphInput();
  (crossSubject.evidence as Array<Record<string, unknown>>)[0]!.subjectDigest = digest("56");
  rebindEvidence(crossSubject, "e.peer");
  assert.throws(() => captureCapabilityGraphV2(crossSubject), /another subject or release epoch/);
  const accessor = graphInput();
  Object.defineProperty(accessor, "subjectDigest", { enumerable: true, get: () => SUBJECT });
  assert.throws(() => captureCapabilityGraphV2(accessor), /accessor or non-enumerable/);
});

test("A4 graph rejects missing references, cycles, self-attested authentication and unscoped raw use", () => {
  const missing = graphInput();
  (missing.edges as Array<Record<string, unknown>>)[0]!.to = "component.absent";
  assert.throws(() => captureCapabilityGraphV2(missing), /missing node/);

  const cycle = graphInput();
  (cycle.edges as unknown[]).push({ id: "edge.dep.a", from: "role.d1", to: "component.broker", kind: "depends-on", operations: ["dependency.cycle"], targetScopes: [], evidenceIds: [], declaredAssurance: "unknown" });
  (cycle.edges as unknown[]).push({ id: "edge.dep.b", from: "component.broker", to: "role.d1", kind: "depends-on", operations: ["dependency.cycle"], targetScopes: [], evidenceIds: [], declaredAssurance: "unknown" });
  assert.throws(() => captureCapabilityGraphV2(cycle), /dependency cycle/);

  const selfAttested = graphInput();
  (selfAttested.evidence as Array<Record<string, unknown>>)[0]!.producerId = "role.d1";
  rebindEvidence(selfAttested, "e.peer");
  assert.throws(() => captureCapabilityGraphV2(selfAttested), /self-attests|independent external/);

  const unscoped = graphInput();
  (unscoped.edges as Array<Record<string, unknown>>).find((edge) => edge.id === "edge.net")!.targetScopes = [];
  assert.throws(() => captureCapabilityGraphV2(unscoped), /must not be empty for authority edges/);
});

test("A4 compatibility closure covers exactly six groups and prevents stale inert consumers", () => {
  const absent = graphInput();
  (absent.compatibility as unknown[]).pop();
  assert.throws(() => captureCapabilityGraphV2(absent), /exactly the six/);

  const stale = graphInput();
  const row = (stale.compatibility as Array<Record<string, unknown>>).find((entry) => entry.builtAheadId === "profile_attestation")!;
  row.replacementOrConsumerId = "component.broker";
  assert.throws(() => captureCapabilityGraphV2(stale), /retain-inert row already names a consumer/);

  const absentReplacement = graphInput();
  (absentReplacement.compatibility as Array<Record<string, unknown>>).find((entry) => entry.builtAheadId === "monitor.channel")!.replacementOrConsumerId = "component.absent";
  assert.throws(() => captureCapabilityGraphV2(absentReplacement), /absent consumer\/replacement/);

  const wrongProposition = graphInput();
  const proof = (wrongProposition.evidence as Array<Record<string, unknown>>).find((entry) => entry.id === "e.compatibility")!;
  proof.subjectIds = (proof.subjectIds as string[]).filter((subject) => subject !== "compatibility:profile_attestation");
  rebindEvidence(wrongProposition, "e.compatibility");
  assert.throws(() => captureCapabilityGraphV2(wrongProposition), /not proposition-bound to compatibility profile_attestation/);
});

test("A4 inventory reconciliation requires distinct producer and mechanism plus installed observation", () => {
  const graph = captureCapabilityGraphV2(graphInput());
  const valid = reconcileCapabilityInventories(graph, worldInput());
  assert.equal(valid.valid, true);
  assert.deepEqual(valid.reasons, []);
  assert.match(valid.observedWorldDigest, /^[0-9a-f]{64}$/);

  const sameProducer = worldInput();
  (sameProducer.observations as Array<Record<string, unknown>>)[0]!.producerId = "release.declarer";
  assert.equal(reconcileCapabilityInventories(graph, sameProducer).valid, false);

  const sameMechanism = worldInput();
  (sameMechanism.observations as Array<Record<string, unknown>>)[0]!.mechanismId = "source-scanner";
  assert.equal(reconcileCapabilityInventories(graph, sameMechanism).valid, false);

  const sourceOnly = worldInput();
  (sourceOnly.observations as Array<Record<string, unknown>>)[0]!.kind = "source-scan";
  assert.match(reconcileCapabilityInventories(graph, sourceOnly).reasons.join(";"), /no producer-and-mechanism-independent installed observation/);

  const mismatch = worldInput();
  ((mismatch.observations as Array<Record<string, unknown>>)[0]!.inventory as Record<string, unknown>).rawSinks = [];
  assert.match(reconcileCapabilityInventories(graph, mismatch).reasons.join(";"), /inventory differs/);

  const moduleMismatch = worldInput();
  (((moduleMismatch.observations as Array<Record<string, unknown>>)[0]!.inventory as Record<string, unknown>).modules as Array<Record<string, unknown>>)[0]!.digest = digest("bc");
  assert.match(reconcileCapabilityInventories(graph, moduleMismatch).reasons.join(";"), /not bound/);

  const stale = worldInput();
  assert.match(reconcileCapabilityInventories(graph, stale, 20n).reasons.join(";"), /trusted-time|kind\/freshness is invalid/);

  const staleConsumer = worldInput();
  ((staleConsumer.declaration as Record<string, unknown>).inventory as Record<string, unknown>).builtAheadConsumers = ["component.absent"];
  assert.match(reconcileCapabilityInventories(graph, staleConsumer).reasons.join(";"), /consumer inventory differs/);
});

test("A4 freshness-sensitive evidence cannot be declared non-expiring", () => {
  const input = graphInput();
  (input.evidence as Array<Record<string, unknown>>).find((row) => row.id === "e.installed")!.freshness = { kind: "non-expiring" };
  assert.throws(() => captureCapabilityGraphV2(input), /bounded window/);

  const immortal = graphInput();
  (immortal.evidence as Array<Record<string, unknown>>).find((row) => row.id === "e.peer")!.freshness = { kind: "window", observedAtMs: 1n, expiresAtMs: 86_400_002n };
  assert.throws(() => captureCapabilityGraphV2(immortal), /maximum evidence TTL/);
});

test("A4 caller declarations cannot manufacture observed assurance", () => {
  const input = graphInput();
  const broker = (input.nodes as Array<Record<string, unknown>>).find((row) => row.id === "component.broker")!;
  broker.evidenceIds = [];
  assert.throws(() => captureCapabilityGraphV2(input), /declares assurance without non-unknown evidence/);
  broker.declaredAssurance = "unknown";
  const path = (input.evidence as Array<Record<string, unknown>>).find((row) => row.id === "e.path")!;
  path.subjectIds = (path.subjectIds as string[]).filter((subject) => subject !== "node:component.broker");
  rebindEvidence(input, "e.path");
  const ledger = deriveCapabilityLedgers(input, worldInput());
  assert.equal(ledger.deployment.find((row) => row.id === "component.broker")!.assurance, "unknown");
});

test("A4 residual limits propagate through required dependency closure", () => {
  const input = graphInput();
  (input.edges as unknown[]).push({ id: "edge.secret-dependency", from: "component.broker", to: "credential.provider", kind: "depends-on", operations: ["model.send"], targetScopes: [], evidenceIds: ["e.secret"], declaredAssurance: "detected-only" });
  (input.evidence as unknown[]).push(evidenceRow({ id: "e.secret", kind: "residual", subjectDigest: SUBJECT, releaseEpoch: 7n, producerId: "installed.observer", mechanismId: "secret-dependency-probe", contentDigest: digest("ca"), subjectIds: ["edge:edge.secret-dependency", "claim:claim.broker-mediation"], assurance: "detected-only", freshness: { kind: "window", observedAtMs: 10n, expiresAtMs: 20n } }));
  const claimInput = (input.claims as Array<Record<string, unknown>>).find((row) => row.id === "claim.broker-mediation")!;
  claimInput.requiredEdgeIds = ["edge.auth", "edge.invoke", "edge.net", "edge.secret-dependency"];
  claimInput.requiredNodeIds = ["role.d1", "component.broker", "sink.net", "credential.provider"];
  claimInput.requiredEvidenceIds = ["e.path", "e.peer", "e.secret"];
  const claim = deriveCapabilityLedgers(input, worldInput()).claims.find((row) => row.id === "claim.broker-mediation")!;
  assert.equal(claim.supported, false);
  assert.equal(claim.assurance, "unknown");
});

test("A4 ledgers cap mediation and credential isolation while ambient same-principal authority remains", () => {
  const ledgers = deriveCapabilityLedgers(graphInput(), worldInput());
  assert.equal(ledgers.inventory.valid, true);
  const mediation = ledgers.claims.find((claim) => claim.id === "claim.broker-mediation")!;
  assert.deepEqual({ assurance: mediation.assurance, ceiling: mediation.taxonomyCeiling, supported: mediation.supported }, { assurance: "unknown", ceiling: "Implemented", supported: false });
  const isolation = ledgers.claims.find((claim) => claim.id === "claim.credential-isolation")!;
  assert.equal(isolation.supported, false);
  assert.equal(isolation.assurance, "unknown");
  assert.equal(isolation.taxonomyCeiling, "Implemented");
  const credentialResidual = ledgers.residuals.find((row) => row.resourceId === "credential.provider")!;
  assert.deepEqual({ d1Reachable: credentialResidual.d1Reachable, targetScopes: credentialResidual.targetScopes, assurance: credentialResidual.assurance }, { d1Reachable: true, targetScopes: ["credential:provider"], assurance: "unknown" });
  assert.match(ledgers.digest, /^[0-9a-f]{64}$/);
});

test("A4 claim support fails closed when installed inventory evidence is absent or scanner-derived", () => {
  const noInstalled = worldInput();
  (noInstalled.observations as Array<Record<string, unknown>>)[0]!.kind = "source-scan";
  const ledgers = deriveCapabilityLedgers(graphInput(), noInstalled);
  assert.equal(ledgers.claims.every((claim) => !claim.supported && claim.assurance === "unknown"), true);

  const noClaimExperiment = graphInput();
  (noClaimExperiment.claims as Array<Record<string, unknown>>)[0]!.requiredEvidenceIds = ["e.peer"];
  const pathEvidence = (noClaimExperiment.evidence as Array<Record<string, unknown>>).find((row) => row.id === "e.path")!;
  pathEvidence.subjectIds = (pathEvidence.subjectIds as string[]).filter((subject) => subject !== "claim:claim.broker-mediation");
  rebindEvidence(noClaimExperiment, "e.path");
  const claim = deriveCapabilityLedgers(noClaimExperiment, worldInput()).claims.find((row) => row.id === "claim.broker-mediation")!;
  assert.match(claim.reasons.join(";"), /lacks independent installed experiment/);
});

test("A4 ledger digest commits to graph identity and otherwise-unused authority edges", () => {
  const baseline = deriveCapabilityLedgers(graphInput(), worldInput()).digest;
  const altered = graphInput();
  (altered.nodes as unknown[]).push({ id: "role.second", kind: "role", domain: "D1", module: "", moduleDigest: "", evidenceIds: [], declaredAssurance: "unknown" });
  (altered.edges as unknown[]).push({ id: "edge.extra-target", from: "role.second", to: "sink.net", kind: "targets", operations: ["diagnostic.probe"], targetScopes: ["loopback:test-endpoint"], evidenceIds: [], declaredAssurance: "unknown" });
  const changed = deriveCapabilityLedgers(altered, worldInput());
  assert.notEqual(changed.digest, baseline);
  assert.notEqual(changed.graphDigest, deriveCapabilityLedgers(graphInput(), worldInput()).graphDigest);
  assert.ok(changed.authority.find((row) => row.resourceId === "sink.net")!.reachableD1NodeIds.includes("role.second"));
});

test("A4 installed observations are content-bound and installed artifacts require a freshness window", () => {
  const badDigest = graphInput();
  (badDigest.evidence as Array<Record<string, unknown>>).find((row) => row.id === "e.installed")!.contentDigest = digest("56");
  rebindEvidence(badDigest, "e.installed");
  assert.match(reconcileCapabilityInventories(captureCapabilityGraphV2(badDigest), worldInput()).reasons.join(";"), /not bound/);

  const artifact = graphInput();
  const proof = (artifact.evidence as Array<Record<string, unknown>>).find((row) => row.id === "e.installed")!;
  proof.kind = "artifact-scan";
  proof.freshness = { kind: "non-expiring" };
  proof.contentDigest = capabilityObservationEvidenceDigest({ kind: "installed-artifact", subjectDigest: SUBJECT, releaseEpoch: 7n, producerId: "installed.observer", mechanismId: "loopback-wire-observer", inventoryDigest: capabilityInstalledInventoryDigest(installedInventoryFixture()) });
  proof.subjectIds = ["inventory:installed-artifact"];
  rebindEvidence(artifact, "e.installed");
  const world = worldInput();
  (world.observations as Array<Record<string, unknown>>)[0]!.kind = "installed-artifact";
  assert.match(reconcileCapabilityInventories(captureCapabilityGraphV2(artifact), world).reasons.join(";"), /kind\/freshness is invalid/);
});

test("A4 expires every freshness-sensitive assurance, not only inventory observations", () => {
  const input = graphInput();
  (input.evidence as Array<Record<string, unknown>>).find((row) => row.id === "e.peer")!.freshness = { kind: "window", observedAtMs: 1n, expiresAtMs: 15n };
  rebindEvidence(input, "e.peer");
  const ledgers = deriveCapabilityLedgers(input, worldInput());
  assert.equal(ledgers.deployment.find((row) => row.id === "role.d1")!.assurance, "unknown");
  assert.equal(ledgers.claims.find((row) => row.id === "claim.broker-mediation")!.supported, false);
});

test("A4 residual caps cannot be lifted by endpoint self-attestation", () => {
  const input = graphInput();
  const key = (input.edges as Array<Record<string, unknown>>).find((row) => row.id === "edge.key")!;
  key.targetScopes = ["credential:provider"];
  key.declaredAssurance = "enforced";
  const residual = (input.evidence as Array<Record<string, unknown>>).find((row) => row.id === "e.residual")!;
  residual.kind = "installed-experiment"; residual.producerId = "role.d1"; residual.assurance = "enforced";
  rebindEvidence(input, "e.residual");
  const credential = (input.nodes as Array<Record<string, unknown>>).find((row) => row.id === "credential.provider")!;
  credential.declaredAssurance = "enforced";
  assert.throws(() => deriveCapabilityLedgers(input, worldInput()), /independent external producer/);
});

test("A4 evidence cannot be reused outside its proposition subjects", () => {
  const input = graphInput();
  const key = (input.edges as Array<Record<string, unknown>>).find((row) => row.id === "edge.key")!;
  key.evidenceIds = ["e.installed"];
  key.declaredAssurance = "enforced";
  assert.throws(() => captureCapabilityGraphV2(input), /not proposition-bound to edge edge.key/);

  const mixed = graphInput();
  const installed = (mixed.evidence as Array<Record<string, unknown>>).find((row) => row.id === "e.installed")!;
  installed.subjectIds = ["inventory:installed-runtime", "claim:claim.broker-mediation"];
  rebindEvidence(mixed, "e.installed");
  assert.throws(() => captureCapabilityGraphV2(mixed), /mixes inventory observation/);

  const selfClaim = graphInput();
  const path = (selfClaim.evidence as Array<Record<string, unknown>>).find((row) => row.id === "e.path")!;
  path.producerId = "component.broker";
  rebindEvidence(selfClaim, "e.path");
  assert.throws(() => captureCapabilityGraphV2(selfClaim), /independent external producer|self-attests/);
});

test("A4 claims cannot shrink their operation closure or ignore unavailable evidence", () => {
  const shaped = graphInput();
  const claim = (shaped.claims as Array<Record<string, unknown>>).find((row) => row.id === "claim.broker-mediation")!;
  claim.requiredNodeIds = ["sink.net"];
  claim.requiredEdgeIds = [];
  assert.throws(() => captureCapabilityGraphV2(shaped), /exactly cover its operations/);

  const unavailable = graphInput();
  (unavailable.evidence as Array<Record<string, unknown>>).find((row) => row.id === "e.peer")!.assurance = "unavailable";
  rebindEvidence(unavailable, "e.peer");
  const result = deriveCapabilityLedgers(unavailable, worldInput()).claims.find((row) => row.id === "claim.broker-mediation")!;
  assert.equal(result.supported, false);
  assert.match(result.reasons.join(";"), /dependency assurance/);

  const vacuous = graphInput();
  const vacuousEvidence = evidenceRow({ id: "e.vacuous", kind: "artifact-scan", subjectDigest: SUBJECT, releaseEpoch: 7n, producerId: "artifact.observer", mechanismId: "vacuous-scan", contentDigest: digest("78"), subjectIds: ["claim:claim.vacuous"], assurance: "enforced", freshness: { kind: "non-expiring" } });
  (vacuous.evidence as unknown[]).push(vacuousEvidence);
  (vacuous.claims as unknown[]).push({ id: "claim.vacuous", operationIds: ["operation.absent"], requiredNodeIds: [], requiredEdgeIds: [], requiredEvidenceIds: ["e.vacuous"] });
  assert.throws(() => captureCapabilityGraphV2(vacuous), /operations cover no graph edge/);

  const partlyVacuous = graphInput();
  ((partlyVacuous.claims as Array<Record<string, unknown>>).find((row) => row.id === "claim.broker-mediation")!.operationIds as string[]).push("operation.absent");
  assert.throws(() => captureCapabilityGraphV2(partlyVacuous), /operation operation.absent covers no graph edge/);

  const specified = graphInput();
  const specifiedClaim = (specified.claims as Array<Record<string, unknown>>).find((row) => row.id === "claim.credential-isolation")!;
  specifiedClaim.requiredEvidenceIds = [];
  const residual = (specified.evidence as Array<Record<string, unknown>>).find((row) => row.id === "e.residual")!;
  residual.subjectIds = (residual.subjectIds as string[]).filter((subject) => subject !== "claim:claim.credential-isolation");
  rebindEvidence(specified, "e.residual");
  const specifiedResult = deriveCapabilityLedgers(specified, worldInput()).claims.find((row) => row.id === "claim.credential-isolation")!;
  assert.equal(specifiedResult.taxonomyCeiling, "Specified");
});

test("A4 D1 authority and residual capping survive role-to-component relabeling", () => {
  const input = graphInput();
  const actor = (input.nodes as Array<Record<string, unknown>>).find((row) => row.id === "role.d1")!;
  actor.kind = "component"; actor.module = "src/agent.ts"; actor.moduleDigest = digest("ac");
  const ledgers = deriveCapabilityLedgers(input, worldInput());
  assert.ok(ledgers.authority.find((row) => row.resourceId === "credential.provider")!.reachableD1NodeIds.includes("role.d1"));
  assert.equal(ledgers.residuals.find((row) => row.resourceId === "credential.provider")!.d1Reachable, true);
  assert.equal(ledgers.claims.find((row) => row.id === "claim.credential-isolation")!.supported, false);
});

test("A4 trusted time is verifier-current and independent of observation producers", () => {
  const samePrincipal = graphInput();
  const clock = (samePrincipal.evidence as Array<Record<string, unknown>>).find((row) => row.id === "e.clock")!;
  clock.producerId = "installed.observer";
  clock.contentDigest = capabilityClockEvidenceDigest({ subjectDigest: SUBJECT, releaseEpoch: 7n, observedAtMs: 10n, expiresAtMs: 20n, producerId: "installed.observer", mechanismId: "signed-clock" });
  rebindEvidence(samePrincipal, "e.clock");
  assert.match(reconcileCapabilityInventories(captureCapabilityGraphV2(samePrincipal), worldInput()).reasons.join(";"), /not independent of trusted-time evidence/);

  const prebuilt = reconcileCapabilityInventoriesRaw(captureCapabilityGraphV2(graphInput()), worldInput(), { trustedNowMs: 16n });
  assert.equal(prebuilt.valid, true);
  const replay = reconcileCapabilityInventoriesRaw(captureCapabilityGraphV2(graphInput()), worldInput(), { trustedNowMs: 20n });
  assert.match(replay.reasons.join(";"), /trusted-time|kind\/freshness/);
  assert.notEqual(deriveCapabilityLedgers(graphInput(), worldInput()).digest, deriveCapabilityLedgers(graphInput(), worldInput(), 16n).digest);

  const staleClock = graphInput();
  (staleClock.evidence as Array<Record<string, unknown>>).find((row) => row.id === "e.clock")!.freshness = { kind: "window", observedAtMs: 1n, expiresAtMs: 15n };
  rebindEvidence(staleClock, "e.clock");
  assert.match(reconcileCapabilityInventories(captureCapabilityGraphV2(staleClock), worldInput()).reasons.join(";"), /trusted-time window evidence/);
});

test("A4 captured-graph inputs are fully reverified and forged digests fail closed", () => {
  const captured = captureCapabilityGraphV2(graphInput());
  assert.equal(reconcileCapabilityInventories(captured, worldInput()).valid, true);
  const forged = { ...captured, digest: digest("de") };
  assert.match(reconcileCapabilityInventories(forged, worldInput()).reasons.join(";"), /digest does not verify/);
});

test("A4 owns authority and ambient residuals cap otherwise detected claims", () => {
  const owned = graphInput();
  (owned.edges as unknown[]).push({ id: "edge.owns-key", from: "component.broker", to: "credential.provider", kind: "owns", operations: ["credential.ownership"], targetScopes: ["credential:provider"], evidenceIds: [], declaredAssurance: "unknown" });
  const ledgers = deriveCapabilityLedgers(owned, worldInput());
  assert.equal(ledgers.authority.find((row) => row.resourceId === "credential.provider")!.assurance, "unknown");
  assert.equal(ledgers.residuals.find((row) => row.resourceId === "credential.provider")!.assurance, "unknown");
  assert.equal(ledgers.authority.find((row) => row.resourceId === "credential.provider")!.assurance, ledgers.residuals.find((row) => row.resourceId === "credential.provider")!.assurance);

  const detected = graphInput();
  (detected.nodes as Array<Record<string, unknown>>).find((row) => row.id === "role.d1")!.declaredAssurance = "detected-only";
  const peer = (detected.evidence as Array<Record<string, unknown>>).find((row) => row.id === "e.peer")!;
  peer.assurance = "detected-only";
  (detected.edges as Array<Record<string, unknown>>).find((row) => row.id === "edge.auth")!.declaredAssurance = "detected-only";
  rebindEvidence(detected, "e.peer");
  const claim = deriveCapabilityLedgers(detected, worldInput()).claims.find((row) => row.id === "claim.broker-mediation")!;
  assert.deepEqual({ assurance: claim.assurance, ceiling: claim.taxonomyCeiling, supported: claim.supported }, { assurance: "unknown", ceiling: "Implemented", supported: false });
});

test("A4 wildcard scopes and module-byte substitutions fail closed", () => {
  const wildcard = graphInput();
  (wildcard.edges as Array<Record<string, unknown>>).find((row) => row.id === "edge.net")!.targetScopes = ["*"];
  assert.throws(() => captureCapabilityGraphV2(wildcard), /wildcard, traversal, alias, escape, or non-canonical target scope/);

  for (const scope of ["file:../secrets", "file:./secrets", "file:a//b", "file:a/", "file:a:b", "file:%2a", "file:a?b"]) {
    const aliased = graphInput();
    (aliased.edges as Array<Record<string, unknown>>).find((row) => row.id === "edge.net")!.targetScopes = [scope];
    assert.throws(() => captureCapabilityGraphV2(aliased), /non-canonical target scope/);
  }

  for (const spoof of [" ", "\u2028", "\u2029", "\u00a0", "\ufff9", "\u115f", "\u1160", "\u3164", "\uffa0", "\u2800", "\ue000"]) {
    const textSpoof = graphInput();
    (textSpoof.compatibility as Array<Record<string, unknown>>)[0]!.nextBlockingStep = spoof;
    assert.throws(() => captureCapabilityGraphV2(textSpoof), /blank, control, separator, private-use, unassigned, or invisible text/);
  }

  for (const module of ["../src/broker.ts", "/src/broker.ts", "src//broker.ts", "src/./broker.ts", "https://example.test/broker.ts", " "]) {
    const moduleAlias = graphInput();
    (moduleAlias.nodes as Array<Record<string, unknown>>).find((row) => row.id === "component.broker")!.module = module;
    assert.throws(() => captureCapabilityGraphV2(moduleAlias), /canonical relative module path|blank, control, separator/);
  }
  const controlModule = worldInput();
  ((controlModule.declaration as Record<string, unknown>).inventory as Record<string, unknown>).modules = [{ nodeId: "component.broker", module: "src/effect\u0000/broker.ts", digest: digest("45") }];
  assert.equal(deriveCapabilityLedgers(graphInput(), controlModule).inventory.valid, false);

  const moduleSwap = graphInput();
  (moduleSwap.nodes as Array<Record<string, unknown>>).find((row) => row.id === "component.broker")!.moduleDigest = digest("bd");
  const result = deriveCapabilityLedgers(moduleSwap, worldInput());
  assert.equal(result.inventory.valid, false);
  assert.equal(result.deployment.every((row) => row.assurance === "unknown"), true);
});

test("A4 ids are globally unambiguous and evidence consumers are namespaced", () => {
  const collision = graphInput();
  (collision.claims as Array<Record<string, unknown>>)[0]!.id = "edge.net";
  assert.throws(() => captureCapabilityGraphV2(collision), /globally unique/);
  const consumers = deriveCapabilityLedgers(graphInput(), worldInput()).evidence.find((row) => row.id === "e.path")!.consumers;
  assert.ok(consumers.includes("edge:edge.net"));
  assert.ok(consumers.includes("claim:claim.broker-mediation"));
});

test("A4 malformed observed worlds downgrade every assurance-bearing ledger", () => {
  const ledgers = deriveCapabilityLedgers(graphInput(), null);
  assert.equal(ledgers.inventory.valid, false);
  assert.equal(ledgers.deployment.every((row) => row.assurance === "unknown"), true);
  assert.equal(ledgers.authority.every((row) => row.assurance === "unknown"), true);
  assert.equal(ledgers.residuals.every((row) => row.assurance === "unknown"), true);
  assert.equal(ledgers.claims.every((row) => row.taxonomyCeiling === "Specified" && !row.supported), true);
  assert.equal(ledgers.verifiedAtMs, 15n);
  assert.equal(deriveCapabilityLedgersRaw(graphInput(), worldInput(), null).verifiedAtMs, null);
});

test("A4 clock and compatibility assurance require enforced dependencies", () => {
  const weakClock = graphInput();
  (weakClock.evidence as Array<Record<string, unknown>>).find((row) => row.id === "e.clock")!.assurance = "unknown";
  rebindEvidence(weakClock, "e.clock");
  assert.equal(reconcileCapabilityInventories(weakClock, worldInput()).valid, false);

  const weakConsumer = graphInput();
  (weakConsumer.nodes as Array<Record<string, unknown>>).find((row) => row.id === "component.broker")!.declaredAssurance = "unknown";
  const row = deriveCapabilityLedgers(weakConsumer, worldInput()).compatibility.find((entry) => entry.builtAheadId === "tree_fingerprint")!;
  assert.equal(row.assurance, "unknown");
});

test("A4 advertised record, list and byte limits reject oversized hostile inputs", () => {
  const tooManyNodes = graphInput();
  tooManyNodes.nodes = Array.from({ length: CAPABILITY_GRAPH_LIMITS.nodes + 1 }, (_, index) => ({ id: `role.limit-${index}`, kind: "role", domain: "NONE", module: "", moduleDigest: "", evidenceIds: [], declaredAssurance: "unknown" }));
  assert.throws(() => captureCapabilityGraphV2(tooManyNodes), new RegExp(`exceeds ${CAPABILITY_GRAPH_LIMITS.nodes} records`));
  const tooLongList = graphInput();
  (tooLongList.nodes as Array<Record<string, unknown>>)[0]!.evidenceIds = Array.from({ length: CAPABILITY_GRAPH_LIMITS.list + 1 }, (_, index) => `e.${index}`);
  assert.throws(() => captureCapabilityGraphV2(tooLongList), /exceeds 256 records/);
  const tooLongText = graphInput();
  (tooLongText.nodes as Array<Record<string, unknown>>).find((row) => row.id === "component.broker")!.module = "x".repeat(CAPABILITY_GRAPH_LIMITS.textBytes + 1);
  assert.throws(() => captureCapabilityGraphV2(tooLongText), /bounded NFC text/);
  const tooManyObservations = worldInput();
  tooManyObservations.observations = Array.from({ length: CAPABILITY_GRAPH_LIMITS.observations + 1 }, () => structuredClone((worldInput().observations as unknown[])[0]));
  assert.match(reconcileCapabilityInventories(captureCapabilityGraphV2(graphInput()), tooManyObservations).reasons.join(";"), /exceeds 64 records/);
});

test("A4 near-limit claim capture stays within the enforced verification budget", () => {
  const input = graphInput();
  const edges = input.edges as unknown[]; const claims = input.claims as unknown[]; const evidence = input.evidence as unknown[];
  for (let index = 0; index < 400; index++) {
    const suffix = String(index).padStart(3, "0"); const edgeId = `edge.scale-${suffix}`; const claimId = `claim.scale-${suffix}`; const evidenceId = `e.scale-${suffix}`; const operationId = `operation.scale-${suffix}`;
    edges.push({ id: edgeId, from: "role.d1", to: "component.broker", kind: "invokes", operations: [operationId], targetScopes: [], evidenceIds: [], declaredAssurance: "unknown" });
    evidence.push(evidenceRow({ id: evidenceId, kind: "artifact-scan", subjectDigest: SUBJECT, releaseEpoch: 7n, producerId: "artifact.observer", mechanismId: `scale-${suffix}`, contentDigest: digest(index % 2 === 0 ? "9a" : "a9"), subjectIds: [`claim:${claimId}`], assurance: "unknown", freshness: { kind: "non-expiring" } }));
    claims.push({ id: claimId, operationIds: [operationId], requiredNodeIds: ["role.d1", "component.broker"], requiredEdgeIds: [edgeId], requiredEvidenceIds: [evidenceId] });
  }
  const started = performance.now();
  captureCapabilityGraphV2(input);
  assert.ok(performance.now() - started < CAPABILITY_GRAPH_LIMITS.verificationBudgetMs);
});

test("A4 signed closure re-derives exact ledgers and mints only verifier-owned boot admission", () => {
  const signer = new StubReleaseClosureSigner("local.release", 3n, "test-only-local-key");
  const bindings = { artifactInventoryDigest: SUBJECT, effectManifestDigest: digest("a2"), policyBundleDigest: digest("a3"), scannerToolDigest: digest("a4"), authorityWaiverDigest: digest("a5"), providerDescriptorDigest: digest("a6") };
  const closure = compileReleaseClosureV2({
    profile: "local-development", graph: graphInput(), world: worldInput(), context: { trustedNowMs: 15n }, bindings,
    lineage: { sequence: 0n, predecessorClosureDigest: "" },
    security: { trustedTime: "enforced", signerRevocation: "unavailable", rollbackProtection: "unavailable", immutableArtifact: "unavailable" },
    issuedAtMs: 15n, expiresAtMs: 20n, keyEpoch: 3n, signers: [signer],
  });
  assert.equal(closure.payload.claimCeiling, "Specified");
  const base = { closure, graph: graphInput(), world: worldInput(), context: { trustedNowMs: 16n }, bindings, trust: { threshold: 1, anchors: [{ keyId: "local.release", algorithm: "stub-sha256" as const, verifyKey: "test-only-local-key", keyEpoch: 3n, validFromMs: 1n, validUntilMs: 30n, revokedAtMs: null }] }, lineage: { sequence: 0n, predecessorClosureDigest: "" }, expectedProfile: "local-development" as const, observedSecurity: { trustedTime: "enforced" as const, signerRevocation: "unavailable" as const, rollbackProtection: "unavailable" as const, immutableArtifact: "unavailable" as const }, bootNonce: "boot.1" };
  const verdict = verifyReleaseClosureV2(base);
  assert.equal(verdict.valid, true);
  if (!verdict.valid) return;
  assert.equal(verdict.effectiveLedgers.claims.every((claim) => claim.taxonomyCeiling === "Specified" && !claim.supported), true);
  assert.equal(verdict.effectiveLedgers.deployment.every((row) => row.assurance === "unknown"), true);
  assert.equal(verdict.effectiveLedgers.authority.every((row) => row.assurance === "unknown"), true);
  assert.equal(verdict.effectiveLedgers.evidence.every((row) => row.assurance === "unknown"), true);
  assert.equal(verifyReleaseAdmissionToken(verdict.admission, { closureDigest: closure.payloadDigest, graphDigest: verdict.graph.digest, subjectDigest: SUBJECT, releaseEpoch: 7n, profile: "local-development", claimCeiling: "Specified", bootNonce: "boot.1", issuedAtMs: 15n, nowMs: 16n }), true);
  assert.equal(verifyRestrictedReleaseAdmission({ token: verdict.admission, expected: { closureDigest: closure.payloadDigest, graphDigest: verdict.graph.digest, subjectDigest: SUBJECT, releaseEpoch: 7n, profile: "local-development", claimCeiling: "Specified", bootNonce: "boot.1", issuedAtMs: 15n }, nowMs: () => 16n }), false);
  assert.equal(verifyReleaseAdmissionToken({ ...verdict.admission }, { closureDigest: closure.payloadDigest, graphDigest: verdict.graph.digest, subjectDigest: SUBJECT, releaseEpoch: 7n, profile: "local-development", claimCeiling: "Specified", bootNonce: "boot.1", issuedAtMs: 15n, nowMs: 16n }), false);
  assert.equal(verifyReleaseAdmissionToken(verdict.admission, { closureDigest: closure.payloadDigest, graphDigest: verdict.graph.digest, subjectDigest: SUBJECT, releaseEpoch: 7n, profile: "local-development", claimCeiling: "Specified", bootNonce: "boot.1", issuedAtMs: 15n, nowMs: 14n }), false);
  assert.equal(verifyReleaseClosureV2({ ...base, bindings: { ...bindings, scannerToolDigest: digest("ff") } }).valid, false);
  assert.equal(verifyReleaseClosureV2({ ...base, lineage: { sequence: 1n, predecessorClosureDigest: digest("bb") } }).valid, false);
  assert.equal(verifyReleaseClosureV2({ ...base, trust: { ...base.trust, anchors: [{ ...base.trust.anchors[0]!, revokedAtMs: 14n }] } }).valid, false);
  assert.equal(verifyReleaseClosureV2({ ...base, expectedProfile: "production" }).valid, false);
  assert.equal(verifyReleaseClosureV2({ ...base, observedSecurity: { ...base.observedSecurity, immutableArtifact: "enforced" } }).valid, false);
  class HostileSignatures extends Array<unknown> { override map(): never { throw new Error("attacker map ran"); } }
  const hostile = new HostileSignatures(...closure.signatures);
  assert.equal(verifyReleaseClosureV2({ ...base, closure: { ...closure, signatures: hostile } }).valid, false);
  assert.equal(verifyReleaseClosureV2({ ...base, bindings: { ...bindings, futureUnverifiedBinding: digest("f1") } as unknown as typeof bindings }).valid, false);
  assert.equal(verifyReleaseClosureV2({ ...base, trust: { threshold: 1, anchors: [{ ...base.trust.anchors[0]!, keyEpoch: 2n }] } }).valid, false);
  assert.equal(verifyReleaseClosureV2({ ...base, trust: { threshold: 1, anchors: [{ ...base.trust.anchors[0]!, validUntilMs: 1n }] } }).valid, false);
  assert.throws(() => compileReleaseClosureV2({ profile: "local-development", graph: graphInput(), world: worldInput(), context: { trustedNowMs: 15n }, bindings: { ...bindings, scannerToolDigest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }, lineage: { sequence: 0n, predecessorClosureDigest: "" }, security: base.observedSecurity, issuedAtMs: 15n, expiresAtMs: 20n, keyEpoch: 3n, signers: [signer] }), /non-placeholder digest/);
  assert.throws(() => compileReleaseClosureV2({ profile: "local-development", graph: graphInput(), world: worldInput(), context: { trustedNowMs: 15n }, bindings: { ...bindings, artifactInventoryDigest: digest("a1") }, lineage: { sequence: 0n, predecessorClosureDigest: "" }, security: base.observedSecurity, issuedAtMs: 15n, expiresAtMs: 20n, keyEpoch: 3n, signers: [signer] }), /must equal capability graph subject/);
  assert.throws(() => compileReleaseClosureV2({ profile: "local-development", graph: graphInput(), world: worldInput(), context: { trustedNowMs: 16n }, bindings, lineage: { sequence: 0n, predecessorClosureDigest: "" }, security: base.observedSecurity, issuedAtMs: 15n, expiresAtMs: 20n, keyEpoch: 3n, signers: [signer] }), /exact issuedAtMs/);
  const expiring = compileReleaseClosureV2({ profile: "local-development", graph: graphInput(), world: worldInput(), context: { trustedNowMs: 15n }, bindings, lineage: { sequence: 0n, predecessorClosureDigest: "" }, security: base.observedSecurity, issuedAtMs: 15n, expiresAtMs: 19n, keyEpoch: 3n, signers: [signer] });
  assert.equal(verifyReleaseClosureV2({ ...base, closure: expiring, context: { trustedNowMs: 19n } }).valid, false);
  const signer2 = new StubReleaseClosureSigner("local.release.backup", 3n, "test-only-local-key");
  const duplicateMaterial = compileReleaseClosureV2({ profile: "local-development", graph: graphInput(), world: worldInput(), context: { trustedNowMs: 15n }, bindings, lineage: { sequence: 0n, predecessorClosureDigest: "" }, security: base.observedSecurity, issuedAtMs: 15n, expiresAtMs: 20n, keyEpoch: 3n, signers: [signer, signer2], threshold: 2 });
  assert.equal(verifyReleaseClosureV2({ ...base, closure: duplicateMaterial, trust: { threshold: 2, anchors: [base.trust.anchors[0]!, { ...base.trust.anchors[0]!, keyId: "local.release.backup" }] } }).valid, false);
  class HostileSignerArray extends Array<StubReleaseClosureSigner> { override map(): never { throw new Error("hostile signer map executed"); } }
  assert.throws(() => compileReleaseClosureV2({ profile: "local-development", graph: graphInput(), world: worldInput(), context: { trustedNowMs: 15n }, bindings, lineage: { sequence: 0n, predecessorClosureDigest: "" }, security: base.observedSecurity, issuedAtMs: 15n, expiresAtMs: 20n, keyEpoch: 3n, signers: new HostileSignerArray(signer) }), /dense plain array/);
});

test("A4 production closure requires Ed25519 plus enforced revocation, rollback, time and immutability", () => {
  const bindings = { artifactInventoryDigest: SUBJECT, effectManifestDigest: digest("b2"), policyBundleDigest: digest("b3"), scannerToolDigest: digest("b4"), authorityWaiverDigest: digest("b5"), providerDescriptorDigest: digest("b6") };
  const common = { profile: "production" as const, graph: graphInput(), world: worldInput(), context: { trustedNowMs: 15n }, bindings, lineage: { sequence: 0n, predecessorClosureDigest: "" }, issuedAtMs: 15n, expiresAtMs: 20n, keyEpoch: 4n };
  assert.throws(() => compileReleaseClosureV2({ ...common, security: { trustedTime: "enforced", signerRevocation: "unavailable", rollbackProtection: "enforced", immutableArtifact: "enforced" }, signers: [new StubReleaseClosureSigner("bad.release", 4n, "not-production")] }), /every security mechanism enforced/);
  assert.throws(() => compileReleaseClosureV2({ ...common, security: { trustedTime: "enforced", signerRevocation: "enforced", rollbackProtection: "enforced", immutableArtifact: "enforced" }, signers: [new StubReleaseClosureSigner("bad.release", 4n, "not-production")] }), /refuses stub signers/);
  const keys = generateKeyPairSync("ed25519");
  const privatePem = keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString(); const publicPem = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
  const closure = compileReleaseClosureV2({ ...common, security: { trustedTime: "enforced", signerRevocation: "enforced", rollbackProtection: "enforced", immutableArtifact: "enforced" }, signers: [new Ed25519ReleaseClosureSigner("prod.release", 4n, privatePem)] });
  const verdict = verifyReleaseClosureV2({ closure, graph: graphInput(), world: worldInput(), context: { trustedNowMs: 16n }, bindings, trust: { threshold: 1, anchors: [{ keyId: "prod.release", algorithm: "ed25519", verifyKey: publicPem, keyEpoch: 4n, validFromMs: 1n, validUntilMs: 30n, revokedAtMs: null }] }, lineage: { sequence: 0n, predecessorClosureDigest: "" }, expectedProfile: "production", observedSecurity: { trustedTime: "enforced", signerRevocation: "enforced", rollbackProtection: "enforced", immutableArtifact: "enforced" }, bootNonce: "boot.prod" });
  assert.equal(verdict.valid, true);
});

test("A4 installed release compiler binds package bytes, module bytes, authority scan and signed closure", () => {
  const packageRoot = mkdtempSync(join(tmpdir(), "keep-release-compiler-"));
  try {
    mkdirSync(join(packageRoot, "src/effect"), { recursive: true });
    mkdirSync(join(packageRoot, "src/gateway"), { recursive: true });
    mkdirSync(join(packageRoot, "node_modules/pkg"), { recursive: true });
    mkdirSync(join(packageRoot, "tools"), { recursive: true });
    writeFileSync(join(packageRoot, "src/cli.ts"), "export const cli = true;\n");
    writeFileSync(join(packageRoot, "src/effect/broker.ts"), "import { readFileSync } from 'node:fs';\nexport const broker = () => [readFileSync('/x'), process.env['KEEP_TEST']];\n");
    writeFileSync(join(packageRoot, "src/gateway/http_provider.ts"), "export const provider = true;\n");
    writeFileSync(join(packageRoot, "node_modules/pkg/index.js"), "export const send = (...args) => globalThis['fet' + 'ch'](...args);\n");
    writeFileSync(join(packageRoot, "tools/invoked.mjs"), "export const load = (name) => import(name);\n");
    writeFileSync(join(packageRoot, "tools/helper"), "#!/bin/sh\nprintf helper\n"); chmodSync(join(packageRoot, "tools/helper"), 0o755);
    writeFileSync(join(packageRoot, "tools/run.py"), "print('helper')\n");
    writeFileSync(join(packageRoot, "libpayload.so"), new Uint8Array([0x7f, 0x45, 0x4c, 0x46]));
    writeFileSync(join(packageRoot, "tools/payload"), "globalThis['fet' + 'ch']('https://example.invalid')\n");
    writeFileSync(join(packageRoot, "tools/payload.txt"), "printf interpreted\n");
    writeFileSync(join(packageRoot, "payload.dat"), "globalThis.compromised = true\n");
    writeFileSync(join(packageRoot, "probe.mjs"), readFileSync(join(process.cwd(), "tools/a4_capability_probe.mjs")));
    const subjectSnapshot = captureReleaseSnapshot(packageRoot); const subjectDigest = subjectSnapshot.digest; subjectSnapshot.dispose();

    const policySigner: CompilerSigner = { signer: new StubSigner("release-policy-secret", "release.policy"), keyid: "release.policy", verifyKey: "release-policy-secret" };
    const policyTrust: TrustPolicy = { trustedKeys: new Map([["release.policy", "release-policy-secret"]]), threshold: 1 };
    const policy: JsonValue = { version: 1n, combiningAlgorithm: "deny-overrides", principals: [{ name: "agent", labels: [] }], effects: [{ id: "read", effectType: "fs.read", resourceSelector: "/x" }], guards: [], rules: [{ id: "permit-read", decision: "permit", subjects: ["agent"], entryPoints: ["*"], effect: "read" }] };
    const policyBundle = compilePolicy(policy, [policySigner]);
    const owners = new Map<EffectFamily, string>([["fs", "src/effect/broker.ts"], ["env", "src/effect/broker.ts"], ["hostinfo", "probe.mjs"]]);
    const scan = scanEffects({ root: packageRoot, owners });
    const effectSigner: EffectManifestSigner = { signer: new StubSigner("release-effect-secret", "release.effect"), keyid: "release.effect", verifyKey: "release-effect-secret" };
    const manifestTrust: TrustPolicy = { trustedKeys: new Map([["release.effect", "release-effect-secret"]]), threshold: 1 };
    const scannerToolDigest = scannerRuntimeDigest();
    const manifest = compileEffectManifest([validateEffectDecl({ family: "fs", owner: "src/effect/broker.ts" }), validateEffectDecl({ family: "env", owner: "src/effect/broker.ts" }), validateEffectDecl({ family: "hostinfo", owner: "probe.mjs" })], policyBundle, { artifactGraphDigest: scan.graphDigest, scannerToolDigest }, [effectSigner]);
    const waiverSigner: WaiverSigner = { signer: new StubSigner("release-waiver-secret", "release.waiver"), keyid: "release.waiver", verifyKey: "release-waiver-secret" };
    const waiverTrust: TrustPolicy = { trustedKeys: new Map([["release.waiver", "release-waiver-secret"]]), threshold: 1 };
    const waiverCounts = new Map<string, { file: string; family: string; construct: string; count: number; reason: string }>(); for (const finding of scan.findings) { const key = `${finding.file}\0${finding.family}\0${finding.construct}`; const prior = waiverCounts.get(key); waiverCounts.set(key, { file: finding.file, family: finding.family, construct: finding.construct, count: (prior?.count ?? 0) + 1, reason: "test fixture: exact observed probe debt" }); }
    const waiver = compileWaiver({ generation: 0, predecessorDigest: "" }, [...waiverCounts.values()], [waiverSigner]);
    const authority = { manifest, policyBundle, trust: { manifestTrust, policyTrust }, waiver, baseline: waiver, boundWaiverDigest: waiver.payloadDigest, previousReleaseHead: "", waiverTrust };
    const common = { sourceRoot: packageRoot, packageRoot, profile: "local-development" as const, capabilityBlueprint: capabilityBlueprintFixture(), releaseEpoch: 7n, context: { trustedNowMs: 15n }, authority, providerDescriptorDigest: digest("c6"), lineage: { sequence: 0n, predecessorClosureDigest: "" }, security: { trustedTime: "enforced" as const, signerRevocation: "unavailable" as const, rollbackProtection: "unavailable" as const, immutableArtifact: "unavailable" as const }, issuedAtMs: 15n, expiresAtMs: 20n, keyEpoch: 1n, signers: [new StubReleaseClosureSigner("release.closure", 1n, "release-closure-secret")] };
    const compiled = compileInstalledReleaseV2(common);
    assert.equal(compiled.artifactInventoryDigest, subjectDigest);
    assert.equal(compiled.bindings.artifactInventoryDigest, subjectDigest);
    assert.equal(compiled.bindings.scannerToolDigest, scannerToolDigest);
    assert.equal(compiled.artifactGraphDigest, scan.graphDigest);
    assert.ok(compiled.graph.nodes.some((node) => node.id === "credential.ambient-environment" && node.domain === "D1"));
    assert.ok(compiled.graph.nodes.some((node) => node.kind === "raw-sink" && node.module === "node_modules/pkg/index.js" && node.domain === "D1"));
    assert.ok(compiled.graph.nodes.some((node) => node.kind === "raw-sink" && node.module === "tools/invoked.mjs" && node.domain === "D1"));
    for (const module of ["tools/helper", "tools/run.py", "libpayload.so", "tools/payload", "tools/payload.txt", "payload.dat"]) { const node = compiled.graph.nodes.find((row) => row.kind === "raw-sink" && row.module === module); assert.ok(node && node.moduleDigest.length === 64 && node.domain === "D1"); assert.ok(compiled.graph.edges.some((edge) => edge.to === node.id && edge.kind === "can-use")); }
    for (const module of ["tools/helper", "tools/run.py", "libpayload.so", "tools/payload", "tools/payload.txt", "payload.dat"]) { const path = join(packageRoot, module); const original = readFileSync(path); writeFileSync(path, Buffer.concat([original, Buffer.from([0x0a])])); const moved = compileInstalledReleaseV2(common); assert.notEqual(moved.artifactInventoryDigest, compiled.artifactInventoryDigest); assert.notEqual(moved.graph.nodes.find((row) => row.kind === "raw-sink" && row.module === module)?.moduleDigest, compiled.graph.nodes.find((row) => row.kind === "raw-sink" && row.module === module)?.moduleDigest); writeFileSync(path, original); if (module === "tools/helper") chmodSync(path, 0o755); }
    assert.equal(compiled.waivedSites, waiver.payload.entries.length);
    const verification = { closure: compiled.closure, graph: compiled.graph, world: compiled.world, context: { trustedNowMs: 16n }, bindings: compiled.bindings, trust: { threshold: 1, anchors: [{ keyId: "release.closure", algorithm: "stub-sha256" as const, verifyKey: "release-closure-secret", keyEpoch: 1n, validFromMs: 1n, validUntilMs: 30n, revokedAtMs: null }] }, lineage: { sequence: 0n, predecessorClosureDigest: "" }, expectedProfile: "local-development" as const, observedSecurity: common.security, bootNonce: "boot.compiler" };
    const encodedBundle = encodeReleaseBootBundle({ verification, authority }); const trustRoot = { releaseTrust: verification.trust, manifestTrust, policyTrust, waiverTrust }; const decodedBundle = decodeReleaseBootBundle(encodedBundle, trustRoot);
    const rootRoundTrip = decodeReleaseTrustRoot(encodeReleaseTrustRoot(trustRoot)); assert.equal(rootRoundTrip.releaseTrust.anchors[0]?.keyId, "release.closure");
    assert.equal(Buffer.from(encodedBundle).includes(Buffer.from("release-closure-secret")), false, "the untrusted carrier must not embed its authenticating trust material");
    const attackerTrustRoot = { ...trustRoot, releaseTrust: { threshold: 1, anchors: [{ ...verification.trust.anchors[0]!, verifyKey: "attacker-controlled-key" }] } };
    const attackerDecoded = decodeReleaseBootBundle(encodedBundle, attackerTrustRoot);
    assert.throws(() => verifyInstalledReleaseAtBoot({ installedRoot: packageRoot, verification: attackerDecoded.verification, authority: attackerDecoded.authority, providerDescriptorDigest: common.providerDescriptorDigest, trustedNowMs: () => 16n }), /signature threshold not met/);
    assert.throws(() => verifyInstalledReleaseAtBoot({ installedRoot: packageRoot, verification: decodedBundle.verification, authority: decodedBundle.authority, providerDescriptorDigest: common.providerDescriptorDigest, trustedNowMs: () => 16n }), /requires a production\/restricted Load-bearing closure/);
    assert.throws(() => decodeReleaseBootBundle(encodedBundle.slice(0, -1), trustRoot), /non-canonical/);
    const poisonedCarrier = decodeCanonical(encodedBundle) as Record<string, CanonicalValue>; poisonedCarrier.verification = { $keepType: "map", value: [["__proto__", { $keepType: "map", value: [] }]] };
    assert.throws(() => decodeReleaseBootBundle(encodeCanonical(poisonedCarrier), trustRoot), /packed map entries are invalid/);
    assert.throws(() => verifyInstalledReleaseAtBoot({ installedRoot: packageRoot, verification, authority, providerDescriptorDigest: common.providerDescriptorDigest, trustedNowMs: () => 16n }), /requires a production\/restricted Load-bearing closure/);
    let proxyTraps = 0; const hostileAuthority = new Proxy(authority, { getPrototypeOf() { proxyTraps++; return Object.prototype; }, ownKeys() { proxyTraps++; return Reflect.ownKeys(authority); }, getOwnPropertyDescriptor(target, key) { proxyTraps++; return Reflect.getOwnPropertyDescriptor(target, key); }, get(target, key, receiver) { proxyTraps++; return Reflect.get(target, key, receiver); } });
    assert.throws(() => verifyInstalledReleaseAtBoot({ installedRoot: packageRoot, verification, authority: hostileAuthority, providerDescriptorDigest: common.providerDescriptorDigest, trustedNowMs: () => 16n }), /authority must be plain inert data/);
    assert.equal(proxyTraps, 0, "Proxy rejection must occur before any authority trap executes");
    let bindingTraps = 0; const hostileBindings = new Proxy(verification.bindings, { getPrototypeOf() { bindingTraps++; return Object.prototype; }, ownKeys() { bindingTraps++; return Reflect.ownKeys(verification.bindings); }, getOwnPropertyDescriptor(target, key) { bindingTraps++; return Reflect.getOwnPropertyDescriptor(target, key); }, get(target, key, receiver) { bindingTraps++; return Reflect.get(target, key, receiver); } });
    assert.throws(() => verifyInstalledReleaseAtBoot({ installedRoot: packageRoot, verification: { ...verification, bindings: hostileBindings }, authority, providerDescriptorDigest: common.providerDescriptorDigest, trustedNowMs: () => 16n }), /bindings must be a plain object/);
    assert.equal(bindingTraps, 0, "Proxy binding rejection must occur before any trap or post-verification reread");
    let verificationTraps = 0; const hostileVerification = new Proxy(verification, { getPrototypeOf() { verificationTraps++; return Object.prototype; }, ownKeys() { verificationTraps++; return Reflect.ownKeys(verification); }, getOwnPropertyDescriptor(target, key) { verificationTraps++; return Reflect.getOwnPropertyDescriptor(target, key); }, get(target, key, receiver) { verificationTraps++; return Reflect.get(target, key, receiver); } });
    assert.throws(() => verifyInstalledReleaseAtBoot({ installedRoot: packageRoot, verification: hostileVerification, authority, providerDescriptorDigest: common.providerDescriptorDigest, trustedNowMs: () => 16n }), /verification must be plain inert data/);
    assert.equal(verificationTraps, 0, "verification envelope Proxy must be rejected before expectedProfile or spread traps");
    assert.throws(() => compileInstalledReleaseV2({ ...common, sourceRoot: join(packageRoot, "src") }), /sourceRoot must equal packageRoot/);
    let blueprintTraps = 0; const hostileBlueprint = new Proxy(common.capabilityBlueprint, { getPrototypeOf() { blueprintTraps++; return Object.prototype; }, ownKeys() { blueprintTraps++; return Reflect.ownKeys(common.capabilityBlueprint); }, getOwnPropertyDescriptor(target, key) { blueprintTraps++; return Reflect.getOwnPropertyDescriptor(target, key); }, get(target, key, receiver) { blueprintTraps++; return Reflect.get(target, key, receiver); } });
    assert.throws(() => compileInstalledReleaseV2({ ...common, capabilityBlueprint: hostileBlueprint }), /blueprint is not bounded inert canonical data/); assert.equal(blueprintTraps, 0);
    assert.throws(() => compileInstalledReleaseV2({ ...common, profile: "production", security: { trustedTime: "enforced", signerRevocation: "enforced", rollbackProtection: "enforced", immutableArtifact: "enforced" } }), /mechanically observed read-only mount/);

    writeFileSync(join(packageRoot, "src/hidden_sink.ts"), "import { request } from 'node:http'; export const hidden = request;\n");
    assert.throws(() => compileInstalledReleaseV2(common), /module closure differs.*hidden_sink/);
    rmSync(join(packageRoot, "src/hidden_sink.ts"));
    writeFileSync(join(packageRoot, "addon.wasm"), new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0])); const wasmBlueprint = structuredClone(common.capabilityBlueprint); (wasmBlueprint.nodes as unknown as Array<Record<string, unknown>>).push({ id: "component.native-addon", kind: "component", domain: "D1", module: "addon.wasm", evidenceIds: [], declaredAssurance: "unknown" });
    const wasmCompiled = compileInstalledReleaseV2({ ...common, capabilityBlueprint: wasmBlueprint });
    assert.ok(wasmCompiled.graph.nodes.some((node) => node.kind === "raw-sink" && node.module === "addon.wasm")); rmSync(join(packageRoot, "addon.wasm"));
    writeFileSync(join(packageRoot, "src/cli.ts"), "export const cli = false;\n");
    assert.throws(() => compileInstalledReleaseV2(common), /authority closure refused|artifact mismatch/);
  } finally {
    rmSync(packageRoot, { recursive: true, force: true });
  }
});

test("A4 release snapshot is closed-world across ignored, dist and dependency bytes and refuses links", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-release-snapshot-test-"));
  const snap = (): string => { const value = captureReleaseSnapshot(root); try { return value.digest; } finally { value.dispose(); } };
  try {
    mkdirSync(join(root, "dist")); mkdirSync(join(root, "node_modules/pkg"), { recursive: true });
    writeFileSync(join(root, ".gitignore"), "ignored.js\ndist\nnode_modules\n");
    writeFileSync(join(root, "ignored.js"), "export const ignored = 1;\n");
    writeFileSync(join(root, "dist/runtime.js"), "export const runtime = 1;\n");
    writeFileSync(join(root, "node_modules/pkg/index.js"), "export const dependency = 1;\n");
    const dense = captureReleaseSnapshot(root); assert.equal(dense.entries.length, 4); assert.equal(dense.entries.every((entry) => entry !== undefined && entry.path.length > 0), true); dense.dispose();
    const initial = snap();
    writeFileSync(join(root, "ignored.js"), "export const ignored = 2;\n"); assert.notEqual(snap(), initial);
    const afterIgnored = snap(); writeFileSync(join(root, "dist/runtime.js"), "export const runtime = 2;\n"); assert.notEqual(snap(), afterIgnored);
    const afterDist = snap(); writeFileSync(join(root, "node_modules/pkg/index.js"), "export const dependency = 2;\n"); assert.notEqual(snap(), afterDist);
    symlinkSync("ignored.js", join(root, "runtime-link.js")); assert.throws(() => captureReleaseSnapshot(root), /symbolic links are not admitted/);
    rmSync(join(root, "runtime-link.js"));
    if (process.platform !== "win32") { execFileSync("mkfifo", [join(root, "runtime.pipe")]); assert.throws(() => captureReleaseSnapshot(root), /special filesystem entry is not admitted/); }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("A4 executing-root binding refuses an admission minted for a different read-only artifact", { skip: process.env.KEEP_ASSURANCE_PROFILE === "portable" ? "requires designated Linux user/mount namespace host" : false }, async () => {
  if (process.env.KEEP_A4_RO_CHILD !== "1") {
    if (process.platform !== "linux") return;
    const { NODE_TEST_CONTEXT: _testContext, ...childEnv } = process.env;
    execFileSync("unshare", ["-Urnm", process.execPath, "--test", "--test-name-pattern", "A4 executing-root binding", fileURLToPath(import.meta.url)], { env: { ...childEnv, KEEP_A4_RO_CHILD: "1" }, stdio: "pipe", timeout: 30_000 });
    return;
  }
  const packageRoot = mkdtempSync(join(tmpdir(), "keep-a4-installed-")); const dataDir = mkdtempSync(join(tmpdir(), "keep-a4-data-")); let mounted = false; let server: Server | undefined;
  try {
    mkdirSync(join(packageRoot, "src/effect"), { recursive: true }); mkdirSync(join(packageRoot, "src/gateway"), { recursive: true });
    writeFileSync(join(packageRoot, "src/cli.ts"), "export const cli = true;\n"); writeFileSync(join(packageRoot, "src/effect/broker.ts"), "export const broker = true;\n"); writeFileSync(join(packageRoot, "src/gateway/http_provider.ts"), "export const provider = true;\n");
    const { graph, world, subjectDigest } = bindGraphToPackage(packageRoot);
    const policySigner: CompilerSigner = { signer: new StubSigner("installed-policy-secret", "installed.policy"), keyid: "installed.policy", verifyKey: "installed-policy-secret" }; const policyTrust: TrustPolicy = { trustedKeys: new Map([["installed.policy", "installed-policy-secret"]]), threshold: 1 };
    const policy: JsonValue = { version: 1n, combiningAlgorithm: "deny-overrides", principals: [{ name: "agent", labels: [] }], effects: [{ id: "e-net", effectType: "http.post", resourceSelector: "*" }], guards: [], rules: [{ id: "allow-net", decision: "permit", subjects: ["agent"], entryPoints: ["egress.net"], effect: "e-net" }] };
    const policyBundle = compilePolicy(policy, [policySigner]); const owners = new Map<EffectFamily, string>([["net", "src/gateway/http_provider.ts"]]); const scan = scanEffects({ root: packageRoot, owners });
    const effectSigner: EffectManifestSigner = { signer: new StubSigner("installed-effect-secret", "installed.effect"), keyid: "installed.effect", verifyKey: "installed-effect-secret" }; const manifestTrust: TrustPolicy = { trustedKeys: new Map([["installed.effect", "installed-effect-secret"]]), threshold: 1 }; const scannerToolDigest = scannerRuntimeDigest();
    const manifest = compileEffectManifest([validateEffectDecl({ family: "net", owner: "src/gateway/http_provider.ts" })], policyBundle, { artifactGraphDigest: scan.graphDigest, scannerToolDigest }, [effectSigner]);
    const waiverSigner: WaiverSigner = { signer: new StubSigner("installed-waiver-secret", "installed.waiver"), keyid: "installed.waiver", verifyKey: "installed-waiver-secret" }; const waiverTrust: TrustPolicy = { trustedKeys: new Map([["installed.waiver", "installed-waiver-secret"]]), threshold: 1 }; const waiver = compileWaiver({ generation: 0, predecessorDigest: "" }, [], [waiverSigner]);
    const authority = { manifest, policyBundle, trust: { manifestTrust, policyTrust }, waiver, baseline: waiver, boundWaiverDigest: waiver.payloadDigest, previousReleaseHead: "", waiverTrust };
    const remoteProvider = { mode: "openai-compatible" as const, baseUrl: "http://127.0.0.1:1", model: "installed", apiKey: "secret" };
    const bindings = { artifactInventoryDigest: subjectDigest, effectManifestDigest: manifest.payloadDigest, policyBundleDigest: policyBundle.payloadDigest, scannerToolDigest, authorityWaiverDigest: waiver.payloadDigest, providerDescriptorDigest: remoteProviderIdentityDigest(remoteProvider) };
    const keys = generateKeyPairSync("ed25519"); const privatePem = keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString(); const publicPem = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
    const security = { trustedTime: "enforced" as const, signerRevocation: "enforced" as const, rollbackProtection: "enforced" as const, immutableArtifact: "enforced" as const };
    const closure = compileReleaseClosureV2({ profile: "production", graph, world, context: { trustedNowMs: 15n }, bindings, lineage: { sequence: 0n, predecessorClosureDigest: "" }, security, issuedAtMs: 15n, expiresAtMs: 20n, keyEpoch: 1n, signers: [new Ed25519ReleaseClosureSigner("release.prod", 1n, privatePem)] });
    execFileSync("mount", ["--bind", packageRoot, packageRoot]); execFileSync("mount", ["-o", "remount,bind,ro", packageRoot]); mounted = true;
    let now = 16n; let calls = 0;
    server = createServer((req, res) => { let body = ""; req.on("data", (chunk) => { body += String(chunk); }); req.on("end", () => { calls++; assert.match(body, /hello/); res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ model: "installed", choices: [{ message: { content: "ok:hello" }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1 } })); }); });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve)); const address = server.address() as AddressInfo;
    const verification = { closure, graph, world, context: { trustedNowMs: 16n }, bindings, trust: { threshold: 1, anchors: [{ keyId: "release.prod", algorithm: "ed25519" as const, verifyKey: publicPem, keyEpoch: 1n, validFromMs: 1n, validUntilMs: 30n, revokedAtMs: null }] }, lineage: { sequence: 0n, predecessorClosureDigest: "" }, expectedProfile: "production" as const, observedSecurity: security, bootNonce: "boot.installed" };
    const liveRemoteProvider = { ...remoteProvider, baseUrl: `http://127.0.0.1:${address.port}` };
    const liveBindings = { ...bindings, providerDescriptorDigest: remoteProviderIdentityDigest(liveRemoteProvider) };
    const liveClosure = compileReleaseClosureV2({ profile: "production", graph, world, context: { trustedNowMs: 15n }, bindings: liveBindings, lineage: { sequence: 0n, predecessorClosureDigest: "" }, security, issuedAtMs: 15n, expiresAtMs: 20n, keyEpoch: 1n, signers: [new Ed25519ReleaseClosureSigner("release.prod", 1n, privatePem)] });
    const liveVerification = { ...verification, closure: liveClosure, bindings: liveBindings };
    assert.throws(() => composeKeep({ dataDir, remoteProvider: { ...liveRemoteProvider, model: "substituted" }, release: { installedRoot: packageRoot, verification: liveVerification, authority, trustedNowMs: (() => { let t = 16n; return () => t++; })() } }), /runtime authority\/provider artifacts are not exactly/);
    assert.equal(calls, 0, "descriptor substitution must refuse before provider construction or endpoint contact");
    let probeNow = 16n; const probeBoot = verifyInstalledReleaseAtBoot({ installedRoot: packageRoot, verification: liveVerification, authority, providerDescriptorDigest: liveBindings.providerDescriptorDigest, trustedNowMs: () => probeNow++ });
    const providerB = constructCapturedRemoteProvider({ ...liveRemoteProvider, model: "alternate-valid-provider" });
    assert.throws(() => buildDefaultBrokeredEgress(providerB, { write() {} }, { transportClass: "remote", releaseRuntime: probeBoot.runtime }), /does not match the signed built-in descriptor identity/);
    assert.equal(calls, 0, "a genuine runtime for descriptor A cannot be paired with built-in provider B");
    assert.throws(() => composeKeep({ dataDir, remoteProvider: liveRemoteProvider, release: { installedRoot: packageRoot, verification: liveVerification, authority, trustedNowMs: () => now++ } }), /belongs to a different executing root/);
    assert.equal(calls, 0);
    assert.throws(() => writeFileSync(join(packageRoot, "src/cli.ts"), "tamper\n"));
  } finally {
    if (server !== undefined) await new Promise<void>((resolve) => server!.close(() => resolve()));
    if (mounted) try { execFileSync("umount", [packageRoot]); } catch { /* child namespace exits anyway */ }
    rmSync(packageRoot, { recursive: true, force: true }); rmSync(dataDir, { recursive: true, force: true });
  }
});

test("A4 installed CLI admits only the signed immutable artifact and refuses corrupt, expired, attacker-root, and root-mismatched boots before state", { skip: process.env.KEEP_ASSURANCE_PROFILE === "portable" ? "requires designated Linux user/mount namespace host" : false }, async () => {
  if (process.env.KEEP_A4_CLI_CHILD !== "1") {
    if (process.platform !== "linux") return;
    const { NODE_TEST_CONTEXT: _testContext, ...childEnv } = process.env;
    const childEvidence = execFileSync("unshare", ["-Urm", process.execPath, "--test", "--test-name-pattern", "A4 installed CLI admits", fileURLToPath(import.meta.url)], { env: { ...childEnv, KEEP_A4_CLI_CHILD: "1" }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 60_000 });
    assert.match(childEvidence, /A4 installed CLI admits[\s\S]*duration_ms: [1-9][0-9]{3,}/, "the namespace child must execute the non-vacuous installed matrix");
    return;
  }
  const sourceRoot = process.cwd(); const scratch = mkdtempSync(join(tmpdir(), "keep-a4-cli-")); const packageRoot = join(scratch, "installed"); mkdirSync(packageRoot); for (const name of ["dist", "src", "tools", "node_modules", "package.json", "package-lock.json", "tsconfig.json", "README.md", "LICENSE"]) if (existsSync(join(sourceRoot, name))) execFileSync("cp", ["-a", join(sourceRoot, name), packageRoot]); rmSync(join(packageRoot, "node_modules/.bin"), { recursive: true, force: true }); let server: Server | undefined; let rootMounted = false; let sourceMounted = false;
  try {
    let hits = 0; server = createServer((req, res) => { let body = ""; req.on("data", (chunk) => { body += String(chunk); }); req.on("end", () => { hits++; assert.match(body, /hello/); res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ model: "installed", choices: [{ message: { content: '{"reply":"installed-ok"}' }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1 } })); }); });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve)); const address = server.address() as AddressInfo;
    const remoteProvider = { mode: "openai-compatible" as const, baseUrl: `http://127.0.0.1:${address.port}`, model: "installed", apiKey: "secret" };
    const issuedAtMs = BigInt(Date.now()); const expiresAtMs = issuedAtMs + 60_000n;
    const { graph, world, subjectDigest } = bindGraphToPackage(packageRoot, issuedAtMs, expiresAtMs);
    const policySigner: CompilerSigner = { signer: new StubSigner("cli-policy-secret", "cli.policy"), keyid: "cli.policy", verifyKey: "cli-policy-secret" }; const policyTrust: TrustPolicy = { trustedKeys: new Map([["cli.policy", "cli-policy-secret"]]), threshold: 1 };
    const policy: JsonValue = { version: 1n, combiningAlgorithm: "deny-overrides", principals: [{ name: "agent", labels: [] }], effects: [{ id: "e-net", effectType: "http.post", resourceSelector: "*" }], guards: [], rules: [{ id: "allow-net", decision: "permit", subjects: ["agent"], entryPoints: ["egress.net"], effect: "e-net" }] };
    const policyBundle = compilePolicy(policy, [policySigner]); const owners = new Map<EffectFamily, string>([["net", "src/gateway/http_provider.ts"]]); const scan = scanEffects({ root: packageRoot, owners });
    const effectSigner: EffectManifestSigner = { signer: new StubSigner("cli-effect-secret", "cli.effect"), keyid: "cli.effect", verifyKey: "cli-effect-secret" }; const manifestTrust: TrustPolicy = { trustedKeys: new Map([["cli.effect", "cli-effect-secret"]]), threshold: 1 }; const scannerToolDigest = scannerRuntimeDigest();
    const manifest = compileEffectManifest([validateEffectDecl({ family: "net", owner: "src/gateway/http_provider.ts" })], policyBundle, { artifactGraphDigest: scan.graphDigest, scannerToolDigest }, [effectSigner]);
    const waiverSigner: WaiverSigner = { signer: new StubSigner("cli-waiver-secret", "cli.waiver"), keyid: "cli.waiver", verifyKey: "cli-waiver-secret" }; const waiverTrust: TrustPolicy = { trustedKeys: new Map([["cli.waiver", "cli-waiver-secret"]]), threshold: 1 };
    const counts = new Map<string, { file: string; family: string; construct: string; count: number; reason: string }>(); for (const finding of scan.findings) { const key = `${finding.file}\0${finding.family}\0${finding.construct}`; const prior = counts.get(key); counts.set(key, { file: finding.file, family: finding.family, construct: finding.construct, count: (prior?.count ?? 0) + 1, reason: "A4 exact installed baseline; residualized by the capability graph" }); }
    const waiver = compileWaiver({ generation: 0, predecessorDigest: "" }, [...counts.values()], [waiverSigner]); const authority = { manifest, policyBundle, trust: { manifestTrust, policyTrust }, waiver, baseline: waiver, boundWaiverDigest: waiver.payloadDigest, previousReleaseHead: "", waiverTrust };
    const keys = generateKeyPairSync("ed25519"); const privatePem = keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString(); const publicPem = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
    const bindings = { artifactInventoryDigest: subjectDigest, effectManifestDigest: manifest.payloadDigest, policyBundleDigest: policyBundle.payloadDigest, scannerToolDigest, authorityWaiverDigest: waiver.payloadDigest, providerDescriptorDigest: remoteProviderIdentityDigest(remoteProvider) }; const security = { trustedTime: "enforced" as const, signerRevocation: "enforced" as const, rollbackProtection: "enforced" as const, immutableArtifact: "enforced" as const };
    const makeVerification = (expiry: bigint) => { const closure = compileReleaseClosureV2({ profile: "production", graph, world, context: { trustedNowMs: issuedAtMs }, bindings, lineage: { sequence: 0n, predecessorClosureDigest: "" }, security, issuedAtMs, expiresAtMs: expiry, keyEpoch: 1n, signers: [new Ed25519ReleaseClosureSigner("release.cli", 1n, privatePem)] }); return { closure, graph, world, context: { trustedNowMs: issuedAtMs }, bindings, trust: { threshold: 1, anchors: [{ keyId: "release.cli", algorithm: "ed25519" as const, verifyKey: publicPem, keyEpoch: 1n, validFromMs: issuedAtMs - 1_000n, validUntilMs: expiresAtMs + 1_000n, revokedAtMs: null }] }, lineage: { sequence: 0n, predecessorClosureDigest: "" }, expectedProfile: "production" as const, observedSecurity: security, bootNonce: "boot.cli.installed" }; };
    const verification = makeVerification(expiresAtMs); const trustRoot = { releaseTrust: verification.trust, manifestTrust, policyTrust, waiverTrust }; const bundlePath = join(scratch, "release.cbor"); writeFileSync(bundlePath, encodeReleaseBootBundle({ verification, authority }));
    execFileSync("mount", ["-t", "tmpfs", "tmpfs", "/etc"]);
    // This child has its own user/mount namespace. Preserve a synthetic account
    // in its otherwise empty /etc so normal profile-path discovery can run even
    // when the test service does not export a home-directory environment value.
    const account = join(scratch, "account"); mkdirSync(account);
    writeFileSync("/etc/passwd", `root:x:0:0:Synthetic CLI fixture:${account}:/bin/sh\n`);
    mkdirSync("/etc/keep", { recursive: true }); writeFileSync("/etc/keep/release-root.cbor", encodeReleaseTrustRoot(trustRoot)); execFileSync("mount", ["--bind", "/etc/keep", "/etc/keep"]); execFileSync("mount", ["-o", "remount,bind,ro", "/etc/keep"]);
    execFileSync("mount", ["--bind", packageRoot, packageRoot]); execFileSync("mount", ["-o", "remount,bind,ro", packageRoot]); rootMounted = true;
    execFileSync("mount", ["--bind", sourceRoot, sourceRoot]); execFileSync("mount", ["-o", "remount,bind,ro", sourceRoot]); sourceMounted = true;
    const repository = join(scratch, "repo"); mkdirSync(repository); execFileSync("git", ["init", "--quiet", repository]);
    const run = async (entryRoot: string, selectedBundle: string, dataName: string) => { const dataDir = join(scratch, dataName); const inherited = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("KEEP_"))); const child = spawn(process.execPath, [join(entryRoot, "dist/src/main.js"), "provider-check", "hello"], { cwd: entryRoot, env: { ...inherited, KEEP_PROVIDER: remoteProvider.mode, KEEP_PROVIDER_BASE_URL: remoteProvider.baseUrl, KEEP_PROVIDER_MODEL: remoteProvider.model, KEEP_PROVIDER_API_KEY: remoteProvider.apiKey, KEEP_REMOTE_PROCESSING_PURPOSE: "installed-verification", KEEP_REMOTE_PROCESSING_REGION: "local", KEEP_REPOSITORY: repository, KEEP_WORKSPACE: repository, KEEP_DATA_DIR: dataDir, KEEP_RELEASE_BUNDLE: selectedBundle }, stdio: ["ignore", "pipe", "pipe"] }); let stdout = "", stderr = ""; child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8"); child.stdout.on("data", (v) => { stdout += String(v); }); child.stderr.on("data", (v) => { stderr += String(v); }); const code = await new Promise<number | null>((resolve, reject) => { const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error(`CLI timeout: ${stderr}`)); }, 15_000); child.once("error", reject); child.once("close", (value) => { clearTimeout(timer); resolve(value); }); }); return { code, stdout, stderr, dataDir }; };
    const success = await run(packageRoot, bundlePath, "data-success"); assert.equal(success.code, 0, `stdout:\n${success.stdout}\nstderr:\n${success.stderr}`); assert.equal(hits, 1); assert.match(success.stdout, /installed-ok/); assert.equal(existsSync(success.dataDir), true);
    const corruptPath = join(scratch, "corrupt.cbor"); writeFileSync(corruptPath, Buffer.concat([readFileSync(bundlePath), Buffer.from([0])])); const corrupt = await run(packageRoot, corruptPath, "data-corrupt"); assert.notEqual(corrupt.code, 0); assert.equal(hits, 1); assert.equal(existsSync(corrupt.dataDir), false);
    const expiredPath = join(scratch, "expired.cbor"); writeFileSync(expiredPath, encodeReleaseBootBundle({ verification: makeVerification(issuedAtMs + 1n), authority })); const expired = await run(packageRoot, expiredPath, "data-expired"); assert.notEqual(expired.code, 0); assert.equal(hits, 1); assert.equal(existsSync(expired.dataDir), false);
    const attackerRoot = { ...trustRoot, releaseTrust: { threshold: 1, anchors: [{ ...verification.trust.anchors[0]!, verifyKey: generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString() }] } }; execFileSync("mount", ["-o", "remount,bind,rw", "/etc/keep"]); writeFileSync("/etc/keep/release-root.cbor", encodeReleaseTrustRoot(attackerRoot)); execFileSync("mount", ["-o", "remount,bind,ro", "/etc/keep"]); const attacker = await run(packageRoot, bundlePath, "data-attacker"); assert.notEqual(attacker.code, 0); assert.equal(hits, 1); assert.equal(existsSync(attacker.dataDir), false);
    const revokedRoot = { ...trustRoot, releaseTrust: { threshold: 1, anchors: [{ ...verification.trust.anchors[0]!, revokedAtMs: issuedAtMs }] } }; execFileSync("mount", ["-o", "remount,bind,rw", "/etc/keep"]); writeFileSync("/etc/keep/release-root.cbor", encodeReleaseTrustRoot(revokedRoot)); execFileSync("mount", ["-o", "remount,bind,ro", "/etc/keep"]); const revoked = await run(packageRoot, bundlePath, "data-revoked"); assert.notEqual(revoked.code, 0); assert.equal(hits, 1); assert.equal(existsSync(revoked.dataDir), false);
    execFileSync("mount", ["-o", "remount,bind,rw", "/etc/keep"]); writeFileSync("/etc/keep/release-root.cbor", encodeReleaseTrustRoot(trustRoot)); execFileSync("mount", ["-o", "remount,bind,ro", "/etc/keep"]); const alternate = join(scratch, "alternate"); mkdirSync(alternate); execFileSync("cp", ["-a", join(packageRoot, "dist"), join(packageRoot, "package.json"), alternate]); const mismatch = await run(alternate, bundlePath, "data-mismatch"); assert.notEqual(mismatch.code, 0); assert.equal(hits, 1); assert.equal(existsSync(mismatch.dataDir), false);
  } finally { if (server !== undefined) await new Promise<void>((resolve) => server!.close(() => resolve())); if (sourceMounted) try { execFileSync("umount", [sourceRoot]); } catch { /* namespace exits */ } if (rootMounted) try { execFileSync("umount", [packageRoot]); } catch { /* namespace exits */ } rmSync(scratch, { recursive: true, force: true }); }
});
