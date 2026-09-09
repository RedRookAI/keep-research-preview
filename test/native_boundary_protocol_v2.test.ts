import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  decodeCanonical,
  encodeCanonical,
  isCanonical,
  type CanonicalValue,
} from "../src/eir/canonical.js";
import {
  captureNativeBoundaryV2Request,
  captureNativeBoundaryV2Response,
  captureNativeV2Schema,
  decodeNativeV2Canonical,
  NATIVE_V2_DIGEST_REGISTRY,
  NATIVE_V2_MEASUREMENT_FIELDS,
  nativeDeploymentBaseDigest,
  nativeBoundaryV2RequestDigest,
  nativeReleaseClosureBaseDigest,
  validateNativeV2DigestRegistry,
  validateNativeBoundaryV2Exchange,
} from "../src/platform/native_boundary_protocol_v2.js";

const D = "ab".repeat(32);
const E = "cd".repeat(32);
const sigs = [
  {
    keyId: "development.release.1",
    algorithm: "ed25519",
    keyEpoch: 1n,
    signature: new Uint8Array(64).fill(1),
  },
];
const launch = {
  protocol: "keep.native-boundary",
  version: 2n,
  kind: "launch",
  requestId: "req.1",
  deploymentId: "deploy.1",
  bootId: "boot.1",
  manifestDigest: D,
  nonce: "nonce.1",
  sequence: 0n,
  deadlineMs: 100n,
  roles: [
    {
      roleId: "net.d3",
      roleClass: "D3",
      principalId: "keep-net",
      artifactDigest: D,
      credentialDomains: ["provider.test"],
      allowedChannelIds: ["d2-net"],
    },
  ],
};
const response = {
  protocol: "keep.native-boundary",
  version: 2n,
  requestId: "req.1",
  requestDigest: nativeBoundaryV2RequestDigest(launch),
  deploymentId: "deploy.1",
  bootId: "boot.1",
  nonce: "nonce.1",
  sequence: 0n,
  helperArtifactDigest: D,
  helperBuildId: "development.build.1",
  kernelBootId: "kernel.boot.1",
  status: "ok",
  roleHandles: [
    {
      roleId: "net.d3",
      roleClass: "D3",
      handleId: "handle.1",
      incarnationDigest: E,
      artifactDigest: D,
      principalId: "keep-net",
    },
  ],
  measurements: NATIVE_V2_MEASUREMENT_FIELDS.map((field, index) => ({
    measurementId: `measurement.${index.toString().padStart(2, "0")}`,
    roleHandleId: "handle.1",
    field,
    state: "inconclusive" as const,
    transcriptDigest: E,
  })),
  failureCode: "",
  evidenceBundleDigest: E,
};
const envelope = (payload: CanonicalValue) => ({
  payload,
  payloadDigest: createHash("sha256")
    .update(encodeCanonical(payload))
    .digest("hex"),
  signatures: sigs,
});
const deploymentPayload = {
  schema: "keep.native-deployment",
  version: 1n,
  trustClass: "development",
  deploymentId: "deploy.1",
  deploymentEpoch: 1n,
  deploymentBaseDigest: D,
  predecessorDigest: D,
  bootPolicy: {
    maxLaunchMs: 1000n,
    maxResponseMs: 1000n,
    maxAttestationAge: 10n,
    maxCleanupMs: 1000n,
    maxConcurrentTransactions: 1n,
    kernelCells: [
      {
        cellId: "linux.6.8",
        minimumKernel: "6.8",
        maximumKernel: "6.x",
        requiredFeatures: ["cgroup.kill", "landlock", "pidfd", "seccomp"],
      },
    ],
  },
  protocol: {
    name: "keep.native-boundary",
    version: 2n,
    maxFrameBytes: 1048576n,
    maxRoles: 32n,
    maxChannels: 128n,
    maxMeasurements: 1024n,
    maxDepth: 16n,
    maxItems: 65536n,
    maxTextBytes: 4096n,
  },
  artifacts: [
    {
      artifactId: "helper",
      digest: D,
      kind: "helper",
      targetTriple: "x86_64-unknown-linux-musl",
      variant: "static-pie",
      executableMode: 365n,
      releaseMember: true,
    },
    {
      artifactId: "prober",
      digest: D,
      kind: "prober",
      targetTriple: "x86_64-unknown-linux-musl",
      variant: "static-pie",
      executableMode: 365n,
      releaseMember: true,
    },
    {
      artifactId: "provisioner.net",
      digest: D,
      kind: "provisioner",
      targetTriple: "x86_64-unknown-linux-musl",
      variant: "static-pie",
      executableMode: 365n,
      releaseMember: true,
    },
    {
      artifactId: "role.net",
      digest: D,
      kind: "role",
      targetTriple: "x86_64-unknown-linux-musl",
      variant: "static-pie",
      executableMode: 365n,
      releaseMember: true,
    },
    {
      artifactId: "trampoline",
      digest: D,
      kind: "trampoline",
      targetTriple: "x86_64-unknown-linux-musl",
      variant: "static-pie",
      executableMode: 365n,
      releaseMember: true,
    },
  ],
  roles: [
    {
      roleId: "net.d3",
      roleClass: "D3",
      principalId: "keep-net",
      artifactId: "role.net",
      artifactDigest: D,
      credentialDomains: ["provider.test"],
      allowedChannelIds: ["d3.provision"],
      uid: 1001n,
      gid: 1001n,
      supplementaryGroups: [],
      namespaces: {
        user: true,
        pid: true,
        mount: true,
        network: true,
        ipc: true,
        cgroup: true,
      },
      mounts: [
        {
          sourceArtifactId: "role.net",
          target: "/keep/role",
          readOnly: true,
          nodev: true,
          nosuid: true,
          noexec: false,
        },
      ],
      cgroup: {
        pathId: "keep.net",
        memoryMax: 1048576n,
        pidsMax: 1n,
        cpuMaxMicros: 100000n,
        ioMaxDigest: D,
      },
      rlimits: {
        nofile: 16n,
        nproc: 1n,
        core: 0n,
        fsize: 0n,
        addressSpace: 67108864n,
      },
      capabilitiesEmpty: true,
      dumpable: false,
      launchSeccompDigest: D,
      steadySeccompDigest: D,
      landlockDigest: D,
      environmentAllowlist: [],
      inheritedFdSlots: [3n],
      requiredMeasurementFields: NATIVE_V2_MEASUREMENT_FIELDS,
    },
  ],
  channels: [
    {
      channelId: "b3.auth",
      fromEndpoint: "supervisor:keep",
      toEndpoint: "b3:b3.1",
      socketType: "seqpacket",
      direction: "request-response",
      maxFrameBytes: 4096n,
      maxDescriptors: 0n,
      peerCredentialPolicy: "exact-principal",
      oneShot: false,
    },
    {
      channelId: "d3.provision",
      fromEndpoint: "provisioner:provisioner.net",
      toEndpoint: "role:net.d3",
      socketType: "seqpacket",
      direction: "one-way",
      maxFrameBytes: 4096n,
      maxDescriptors: 1n,
      peerCredentialPolicy: "exact-principal",
      oneShot: true,
    },
    {
      channelId: "prober.observe",
      fromEndpoint: "prober:prober.1",
      toEndpoint: "supervisor:keep",
      socketType: "seqpacket",
      direction: "request-response",
      maxFrameBytes: 4096n,
      maxDescriptors: 0n,
      peerCredentialPolicy: "exact-principal",
      oneShot: false,
    },
  ],
  probers: [
    {
      proberId: "prober.1",
      artifactId: "prober",
      principalId: "keep-prober",
      signingKeyId: "development.prober.1",
      keyEpoch: 1n,
      channelId: "prober.observe",
      observationGrants: ["cgroup", "landlock", "namespaces", "seccomp"],
      requiredNegativeProbes: ["network.denied"],
    },
  ],
  provisioners: [
    {
      provisionerId: "provisioner.net",
      domain: "provider.test",
      principalId: "keep-provisioner-net",
      artifactId: "provisioner.net",
      targetRoleId: "net.d3",
      channelId: "d3.provision",
      descriptorType: "sealed-memfd",
      requiredSeals: [
        "F_SEAL_GROW",
        "F_SEAL_SEAL",
        "F_SEAL_SHRINK",
        "F_SEAL_WRITE",
      ],
      descriptorCount: 1n,
      destructionDeadlineMs: 100n,
    },
  ],
  b3: {
    authorityId: "b3.1",
    genesisBaseDigest: D,
    b3ProfileEnvelopeDigest: D,
    keyEpoch: 1n,
    assurance: "load-bearing",
    channelId: "b3.auth",
  },
  release: {
    buildId: "development.build.1",
    artifactVersion: 1n,
    targetTriple: "x86_64-unknown-linux-musl",
    variant: "static-pie",
    releaseKeyEpoch: 1n,
    timestampKeyEpoch: 1n,
  },
  revocation: {
    authorityId: "development.revocation",
    keyEpoch: 1n,
    namespace: "keep",
    scope: "native",
    genesisCheckpointEnvelopeDigest: D,
    minimumSequence: 1n,
    maxStalenessCounters: 10n,
    compromiseSemantics: "fail-stop-quarantine",
  },
  rollback: {
    deploymentEpoch: 1n,
    minimumArtifactVersion: 1n,
    predecessorDigest: D,
    authorizedRollbackEnvelopeDigest: D,
  },
  evidence: {
    schema: "keep.native-evidence",
    sinkId: "native.evidence",
    maxBundleBytes: 8388608n,
    algorithm: "ed25519",
    keyId: "development.prober.1",
    keyEpoch: 1n,
    appendPolicy: "create-exclusive-fsync",
    witnessPolicy: "external-prober",
  },
} as unknown as Record<string, CanonicalValue>;
deploymentPayload.deploymentBaseDigest = nativeDeploymentBaseDigest(deploymentPayload);
const deployment = envelope(deploymentPayload);
const closurePayload = {
  schema: "keep.native-release-closure",
  version: 1n,
  trustClass: "development",
  a4ReleaseBaseDigest: D,
  a4ArtifactInventoryDigest: D,
  nativeArtifactInventoryDigest: D,
  nativeDeploymentPayloadDigest: D,
  nativeDeploymentEnvelopeDigest: D,
  nativePackagePayloadDigest: D,
  nativeClosureBaseDigest: D,
  helperArtifactDigest: D,
  trampolineArtifactDigest: D,
  proberArtifactDigest: D,
  provisionerArtifactDigests: [],
  protocolDigest: D,
  evidenceSchemaDigest: D,
  targetTriple: "x86_64-unknown-linux-musl",
  variant: "static-pie",
  artifactVersion: 1n,
  buildId: "development.build.1",
  releaseKeyEpoch: 1n,
  timestampKeyEpoch: 1n,
  timestampRecordEnvelopeDigest: D,
  sbomEnvelopeDigest: D,
  provenanceEnvelopeDigests: [],
  reproducibilityRecordEnvelopeDigest: D,
  toolchainClosureEnvelopeDigest: D,
  releaseTimeRevocationCheckpointEnvelopeDigest: D,
  releaseTimeRevocationSequence: 1n,
  deploymentEpoch: 1n,
  minimumArtifactVersion: 1n,
  predecessorDigest: D,
  authorizedRollbackEnvelopeDigest: D,
  b0RootEnvelopeDigest: D,
  b3ProfileEnvelopeDigest: D,
} as unknown as Record<string, CanonicalValue>;
closurePayload.nativeClosureBaseDigest =
  nativeReleaseClosureBaseDigest(closurePayload);
const closure = envelope(closurePayload);
const index = envelope({
  schema: "keep.native-release-index",
  version: 1n,
  a4ReleaseBaseDigest: D,
  deploymentEnvelopeDigest: D,
  nativeClosureEnvelopeDigest: D,
  b0RootEnvelopeDigest: D,
  releaseKeyEpoch: 1n,
  trustClass: "development",
});
const revocation = envelope({
  schema: "keep.native-revocation",
  version: 1n,
  authorityId: "development.revocation",
  namespace: "keep",
  scope: "native",
  keyEpoch: 1n,
  sequence: 1n,
  previousEnvelopeDigest: D,
  issuedCounter: 1n,
  expiresCounter: 2n,
  revokedKeys: [],
  revokedArtifacts: [D],
  rotationCutoffs: [],
  compromiseSemantics: "development",
});
function measurementValue(field: string): CanonicalValue {
  if (field.startsWith("identity.uid.") || field.startsWith("identity.gid."))
    return { type: "uint64", value: 1001n };
  if (field === "identity.groups") return { type: "uint64-set", values: [] };
  if (field.startsWith("security.capabilities."))
    return { type: "identifier-set", values: [] };
  if (field === "security.dumpable") return { type: "boolean", value: false };
  if (field === "security.no-new-privileges")
    return { type: "boolean", value: true };
  if (field === "loader.executable") return { type: "digest", value: D };
  if (field === "loader.shared-libraries")
    return { type: "digest-set", values: [D] };
  if (field === "namespaces.inodes")
    return {
      type: "namespace-inodes",
      user: 1n,
      pid: 2n,
      mount: 3n,
      network: 4n,
      ipc: 5n,
      cgroup: 6n,
    };
  if (field === "cgroup.limits")
    return {
      type: "cgroup-limits",
      memoryMax: 1048576n,
      pidsMax: 1n,
      cpuMaxMicros: 100000n,
      ioMaxDigest: D,
    };
  if (field === "seccomp.launch" || field === "seccomp.steady")
    return {
      type: "seccomp-policy",
      architecture: "x86_64",
      defaultAction: "kill-process",
      allowedActions: ["allow"],
      filterDigest: D,
      noNewPrivileges: true,
    };
  if (field === "landlock.policy")
    return {
      type: "landlock-policy",
      abi: 10n,
      handledRights: ["fs.execute", "fs.read-file"],
      scopedRights: ["abstract-unix-socket", "signal"],
      rulesetDigest: D,
    };
  if (field === "mount.topology")
    return {
      type: "mount-topology",
      entries: [
        {
          target: "/keep/role",
          sourceDigest: D,
          readOnly: true,
          nodev: true,
          nosuid: true,
          noexec: false,
        },
      ],
    };
  if (field === "network.topology")
    return {
      type: "network-topology",
      interfaces: ["lo"],
      routes: ["loopback-only"],
      addressFamilies: ["AF_UNIX"],
    };
  if (field === "fd.inventory")
    return {
      type: "descriptor-inventory",
      entries: [
        {
          slot: 3n,
          purpose: "credential",
          flagsDigest: E,
          seals: ["F_SEAL_SEAL", "F_SEAL_WRITE"],
          credentialDomain: "provider.test",
        },
      ],
    };
  if (field === "credential.state")
    return {
      type: "credential-state",
      domains: ["provider.test"],
      deliveredAfterAttestation: true,
      descriptorCount: 1n,
    };
  if (field === "incarnation")
    return {
      type: "incarnation",
      pidfdDigest: E,
      startCounter: 1n,
      expiresCounter: 2n,
    };
  if (field === "capture.window")
    return { type: "counter-window", capturedCounter: 1n, expiresCounter: 2n };
  throw new Error(`unhandled measurement field ${field}`);
}
const evidence = {
  schema: "keep.native-evidence",
  version: 1n,
  deploymentId: "deploy.1",
  deploymentEpoch: 1n,
  bootId: "boot.1",
  kernelBootId: "kernel.boot.1",
  manifestDigest: D,
  nativeClosureEnvelopeDigest: D,
  helperArtifactDigest: D,
  helperBuildId: "development.build.1",
  helperIncarnation: D,
  protocolDigest: D,
  requestId: "req.1",
  requestDigest: D,
  requestNonce: "nonce.1",
  requestSequence: 0n,
  challengeNonce: "challenge.1",
  b3ProfileEnvelopeDigest: D,
  b3LeaseReceiptEnvelopeDigest: D,
  b3Counter: 1n,
  capturedCounter: 1n,
  expiresCounter: 2n,
  proberId: "prober.1",
  proberPrincipal: "keep-prober",
  proberArtifactDigest: D,
  proberIncarnation: D,
  proberKeyEpoch: 1n,
  revocationEnvelopeDigest: D,
  roles: [
    {
      roleId: "net.d3",
      roleClass: "D3",
      principalId: "keep-net",
      artifactDigest: D,
      incarnationDigest: E,
      uid: 1001n,
      gid: 1001n,
      groups: [],
      namespaceInodes: {
        user: 1n,
        pid: 2n,
        mount: 3n,
        network: 4n,
        ipc: 5n,
        cgroup: 6n,
      },
      cgroupId: "keep.net",
    },
  ],
  measurements: NATIVE_V2_MEASUREMENT_FIELDS.map((field, index) => ({
    measurementId: `measurement.${index.toString().padStart(2, "0")}`,
    roleId: "net.d3",
    field,
    value: measurementValue(field),
    mechanism: "procfs",
    mechanismVersion: "1",
    abi: "linux.6.8",
    source: "external-prober",
    transcriptDigest: E,
    state: "active",
    reasonCode: "observed",
  })),
  negativeProbes: [
    {
      probeId: "network.denied",
      roleId: "net.d3",
      target: "loopback.denied",
      action: "connect",
      expectedField: "network.topology",
      observedDenial: true,
      errno: "ECONNREFUSED",
      signal: "none",
      controlDigest: E,
    },
  ],
  inheritedFdInventory: [
    {
      roleId: "net.d3",
      slot: 3n,
      purpose: "credential",
      flagsDigest: E,
      peerPrincipalId: "keep-provisioner-net",
    },
  ],
  cleanup: {
    state: "not-required",
    killedRoleIds: [],
    reapedRoleIds: [],
    closedFdCount: 0n,
    revokedCredentialDomains: [],
    journalDigest: E,
    recoveryRequired: false,
  },
  previousEvidenceDigest: D,
  signature: {
    keyId: "development.prober.1",
    algorithm: "ed25519",
    keyEpoch: 1n,
    signature: new Uint8Array(64).fill(2),
  },
};

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}
function oracle(
  rows: readonly Uint8Array[],
  valueOnly = false,
): readonly string[] {
  const path = fileURLToPath(
    new URL(
      "../../native/target/x86_64-unknown-linux-musl/debug/keep-native-protocol-oracle",
      import.meta.url,
    ),
  );
  const result = spawnSync(path, {
    input:
      rows.map((row) => (valueOnly ? "VALUE:" : "") + hex(row)).join("\n") +
      "\n",
    encoding: "utf8",
    env: {},
  });
  assert.equal(
    result.status,
    0,
    `${result.error?.message ?? ""} ${result.stderr}`,
  );
  return result.stdout.trimEnd().split("\n");
}
function schemaEnvelope(
  payload: Record<string, CanonicalValue>,
): CanonicalValue {
  return envelope(payload as CanonicalValue) as CanonicalValue;
}
function mutateEnvelope(
  source: CanonicalValue,
  mutate: (payload: Record<string, CanonicalValue>) => void,
): CanonicalValue {
  const copy = structuredClone(source) as Record<string, CanonicalValue>;
  const payload = copy.payload as Record<string, CanonicalValue>;
  mutate(payload);
  return schemaEnvelope(payload);
}
function tsAccept(value: CanonicalValue): boolean {
  try {
    const row = value as Record<string, CanonicalValue>;
    if (row.protocol === "keep.native-boundary") {
      if ("kind" in row) captureNativeBoundaryV2Request(value);
      else captureNativeBoundaryV2Response(value);
      return true;
    }
    const schema = (row.schema ??
      (row.payload as Record<string, CanonicalValue>)?.schema) as string;
    if (schema === "keep.native-deployment")
      captureNativeV2Schema(value, "deployment", "development");
    else if (schema === "keep.native-release-closure")
      captureNativeV2Schema(value, "native-closure", "development");
    else if (schema === "keep.native-release-index")
      captureNativeV2Schema(value, "native-index", "development");
    else if (schema === "keep.native-revocation")
      captureNativeV2Schema(value, "revocation", "development");
    else if (schema === "keep.native-evidence")
      captureNativeV2Schema(value, "evidence", "development");
    else return false;
    return true;
  } catch {
    return false;
  }
}
function structuralMutants(source: CanonicalValue): CanonicalValue[] {
  const out: CanonicalValue[] = [];
  const visit = (value: CanonicalValue, path: (string | number)[]) => {
    if (
      value === null ||
      typeof value !== "object" ||
      value instanceof Uint8Array
    )
      return;
    if (Array.isArray(value)) {
      if (value.length) visit(value[0]!, [...path, 0]);
      return;
    }
    for (const key of Object.keys(value)) {
      const mutate = (replacement: "delete" | CanonicalValue) => {
        const copy = structuredClone(source) as any;
        let target = copy;
        for (const part of path) target = target[part];
        if (replacement === "delete") delete target[key];
        else target[key] = replacement;
        if (copy.payload && path[0] === "payload" && key !== "payloadDigest")
          copy.payloadDigest = createHash("sha256")
            .update(encodeCanonical(copy.payload))
            .digest("hex");
        out.push(copy as CanonicalValue);
      };
      mutate("delete");
      if (key !== "value") mutate(null);
      visit((value as Record<string, CanonicalValue>)[key]!, [...path, key]);
    }
    const extra = structuredClone(source) as any;
    let target = extra;
    for (const part of path) target = target[part];
    target["unexpectedField"] = true;
    if (extra.payload && path[0] === "payload")
      extra.payloadDigest = createHash("sha256")
        .update(encodeCanonical(extra.payload))
        .digest("hex");
    out.push(extra as CanonicalValue);
  };
  visit(source, []);
  return out;
}

test("A6 P1 protocol 2 exact request/response semantics refuse downgrade and evidence ambiguity", () => {
  assert.equal(captureNativeBoundaryV2Request(launch).version, 2n);
  assert.equal(
    captureNativeBoundaryV2Response(response).evidenceBundleDigest,
    E,
  );
  assert.throws(
    () => captureNativeBoundaryV2Request({ ...launch, version: 1n }),
    /unsupported/,
  );
  assert.throws(
    () =>
      captureNativeBoundaryV2Response({
        ...response,
        evidenceBundleDigest: null,
      }),
    /lacks evidence/,
  );
  assert.throws(
    () =>
      captureNativeBoundaryV2Response({
        ...response,
        status: "failed",
        failureCode: "failure.test",
        roleHandles: [],
        measurements: [],
        evidenceBundleDigest: null,
      }),
    /(unavailable|biconditional)/,
  );
  assert.doesNotThrow(() =>
    captureNativeBoundaryV2Response({
      ...response,
      status: "failed",
      failureCode: "evidence.unavailable.pre-prober",
      roleHandles: [],
      measurements: [],
      evidenceBundleDigest: null,
    }),
  );
});

test("A6 P1 request-aware reconciliation admits complete probe evidence without minting handles", () => {
  const probe = {
    protocol: "keep.native-boundary",
    version: 2n,
    kind: "probe",
    requestId: "req.probe",
    deploymentId: "deploy.1",
    bootId: "boot.1",
    manifestDigest: D,
    nonce: "nonce.probe",
    sequence: 1n,
    deadlineMs: 100n,
    roleHandleIds: ["handle.1"],
    challengeNonce: "challenge.probe",
  } as const;
  const probeResponse = {
    ...response,
    requestId: probe.requestId,
    requestDigest: nativeBoundaryV2RequestDigest(probe),
    nonce: probe.nonce,
    sequence: probe.sequence,
    roleHandles: [],
  };
  assert.doesNotThrow(() =>
    validateNativeBoundaryV2Exchange(probe, probeResponse),
  );
  assert.equal(
    oracle([
      encodeCanonical(probeResponse as unknown as CanonicalValue),
    ])[0]?.split("\t")[0],
    "OK",
  );
  assert.throws(
    () =>
      validateNativeBoundaryV2Exchange(probe, {
        ...probeResponse,
        measurements: probeResponse.measurements.slice(1),
      }),
    /closure incomplete/,
  );
  assert.throws(
    () => validateNativeBoundaryV2Exchange(launch, probeResponse),
    /(bind request|launch)/,
  );
});

test("A6 P1 response binding refuses wrong boot, nonce, and sequence", () => {
  const request = launch;
  for (const mutant of [
    { ...response, bootId: "boot.substituted" },
    { ...response, nonce: "nonce.substituted" },
    { ...response, sequence: response.sequence + 1n },
  ]) {
    assert.throws(
      () => validateNativeBoundaryV2Exchange(request, mutant),
      /response envelope does not bind request/,
    );
  }
});

test("A6 P1 evidence supports the advertised 32 roles times 27 exact fields", () => {
  const roles = Array.from({ length: 32 }, (_, index) => ({
    ...structuredClone(evidence.roles[0]!),
    roleId: `role.${index.toString().padStart(2, "0")}`,
    principalId: `principal.${index.toString().padStart(2, "0")}`,
  }));
  let measurementIndex = 0;
  const measurements = roles.flatMap((role) =>
    NATIVE_V2_MEASUREMENT_FIELDS.map((field) => ({
      ...structuredClone(evidence.measurements[0]!),
      measurementId: `measurement.${(measurementIndex++).toString().padStart(4, "0")}`,
      roleId: role.roleId,
      field,
      value: measurementValue(field),
    })),
  );
  const boundary = {
    ...evidence,
    roles,
    measurements,
    negativeProbes: [],
    inheritedFdInventory: [],
  } as unknown as CanonicalValue;
  assert.doesNotThrow(() =>
    captureNativeV2Schema(boundary, "evidence", "development"),
  );
  assert.equal(oracle([encodeCanonical(boundary)])[0]?.split("\t")[0], "OK");
  const oversized = {
    ...structuredClone(boundary as any),
    measurements: [...measurements, ...measurements.slice(0, 161)],
  } as CanonicalValue;
  assert.throws(
    () => captureNativeV2Schema(oversized, "evidence", "development"),
    /(oversized|duplicate|collection|bounded)/,
  );
  assert.equal(oracle([encodeCanonical(oversized)])[0]?.split("\t")[0], "ERR");
});

test("A6 P1 TS and safe Rust accept identical canonical schema corpus bytes and SHA-256", () => {
  const fixtures: readonly [string, CanonicalValue][] = [
    ["Request", launch as unknown as CanonicalValue],
    ["Response", response as unknown as CanonicalValue],
    ["Deployment", deployment as CanonicalValue],
    ["NativeClosure", closure as CanonicalValue],
    ["NativeIndex", index as CanonicalValue],
    ["Evidence", evidence as CanonicalValue],
    ["Revocation", revocation as CanonicalValue],
  ];
  captureNativeV2Schema(deployment, "deployment", "development");
  captureNativeV2Schema(closure, "native-closure", "development");
  captureNativeV2Schema(index, "native-index", "development");
  captureNativeV2Schema(evidence, "evidence", "development");
  captureNativeV2Schema(revocation, "revocation", "development");
  const bytes = fixtures.map(([, value]) => encodeCanonical(value));
  const outputs = oracle(bytes);
  assert.equal(outputs.length, fixtures.length);
  outputs.forEach((output, index) => {
    const [status, schema, digest, canonicalHex] = output.split("\t");
    assert.equal(
      status,
      "OK",
      `${fixtures[index]![0]} (${bytes[index]!.byteLength} bytes): ${output}`,
    );
    assert.equal(schema, fixtures[index]![0]);
    assert.equal(canonicalHex, hex(bytes[index]!));
    assert.equal(
      digest,
      createHash("sha256").update(bytes[index]!).digest("hex"),
    );
  });
});

test("A6 P1 migration rejects every legacy and mixed digest spelling in both families", () => {
  type Mutation = {
    schema: "deployment" | "native-closure" | "native-index" | "evidence";
    source: CanonicalValue;
    path: readonly string[];
    oldKey: string;
    newKey: string;
  };
  const mutations: Mutation[] = [
    { schema: "deployment", source: deployment, path: [], oldKey: "deploymentDigest", newKey: "deploymentBaseDigest" },
    { schema: "deployment", source: deployment, path: ["b3"], oldKey: "genesisDigest", newKey: "genesisBaseDigest" },
    { schema: "deployment", source: deployment, path: ["b3"], oldKey: "b3AuthorityDigest", newKey: "b3ProfileEnvelopeDigest" },
    { schema: "deployment", source: deployment, path: ["revocation"], oldKey: "genesisCheckpointDigest", newKey: "genesisCheckpointEnvelopeDigest" },
    { schema: "deployment", source: deployment, path: ["rollback"], oldKey: "authorizedRollbackDigest", newKey: "authorizedRollbackEnvelopeDigest" },
    { schema: "native-closure", source: closure, path: [], oldKey: "artifactInventoryDigest", newKey: "a4ArtifactInventoryDigest" },
    { schema: "native-closure", source: closure, path: [], oldKey: "nativePackageDigest", newKey: "nativePackagePayloadDigest" },
    { schema: "native-closure", source: closure, path: [], oldKey: "timestampRecordDigest", newKey: "timestampRecordEnvelopeDigest" },
    { schema: "native-closure", source: closure, path: [], oldKey: "sbomDigest", newKey: "sbomEnvelopeDigest" },
    { schema: "native-closure", source: closure, path: [], oldKey: "provenanceDigests", newKey: "provenanceEnvelopeDigests" },
    { schema: "native-closure", source: closure, path: [], oldKey: "reproducibilityRecordDigest", newKey: "reproducibilityRecordEnvelopeDigest" },
    { schema: "native-closure", source: closure, path: [], oldKey: "toolchainClosureDigest", newKey: "toolchainClosureEnvelopeDigest" },
    { schema: "native-closure", source: closure, path: [], oldKey: "releaseTimeRevocationCheckpointDigest", newKey: "releaseTimeRevocationCheckpointEnvelopeDigest" },
    { schema: "native-closure", source: closure, path: [], oldKey: "authorizedRollbackDigest", newKey: "authorizedRollbackEnvelopeDigest" },
    { schema: "native-closure", source: closure, path: [], oldKey: "b0RootDigest", newKey: "b0RootEnvelopeDigest" },
    { schema: "native-closure", source: closure, path: [], oldKey: "b3AuthorityDigest", newKey: "b3ProfileEnvelopeDigest" },
    { schema: "native-index", source: index, path: [], oldKey: "b0RootDigest", newKey: "b0RootEnvelopeDigest" },
    { schema: "evidence", source: evidence, path: [], oldKey: "nativeClosureDigest", newKey: "nativeClosureEnvelopeDigest" },
    { schema: "evidence", source: evidence, path: [], oldKey: "b3AuthorityDigest", newKey: "b3ProfileEnvelopeDigest" },
    { schema: "evidence", source: evidence, path: [], oldKey: "revocationDigest", newKey: "revocationEnvelopeDigest" },
  ];
  for (const mutation of mutations) {
    for (const mixed of [false, true]) {
      const original = structuredClone(mutation.source as any);
      const payload = original.payload ?? original;
      let target = payload;
      for (const segment of mutation.path) target = target[segment];
      target[mutation.oldKey] = structuredClone(target[mutation.newKey]);
      if (!mixed) delete target[mutation.newKey];
      const candidate = original.payload
        ? envelope(payload as CanonicalValue)
        : (payload as CanonicalValue);
      assert.throws(
        () => captureNativeV2Schema(candidate, mutation.schema, "development"),
        /exact|fields/,
        `${mutation.schema}:${mutation.oldKey}:${mixed ? "mixed" : "legacy"}`,
      );
      assert.equal(
        oracle([encodeCanonical(candidate)])[0]?.split("\t")[0],
        "ERR",
        `${mutation.schema}:${mutation.oldKey}:${mixed ? "mixed" : "legacy"}`,
      );
    }
  }
});

test("A6 P1 base digests bind their exact acyclic projections in both families", () => {
  const changed = (value: any): any => {
    if (typeof value === "string") return value === D ? E : `${value}.changed`;
    if (typeof value === "bigint") return value + 1n;
    if (typeof value === "boolean") return !value;
    if (value instanceof Uint8Array) {
      const copy = value.slice();
      copy[0] = (copy[0] ?? 0) ^ 1;
      return copy;
    }
    if (Array.isArray(value)) return [...value, null];
    return { ...value, migrationProbe: true };
  };
  const deploymentBase = nativeDeploymentBaseDigest(deploymentPayload);
  for (const key of Object.keys(deploymentPayload)) {
    if (key === "deploymentBaseDigest" || key === "rollback") continue;
    const mutant = structuredClone(deploymentPayload as any);
    mutant[key] = changed(mutant[key]);
    assert.notEqual(nativeDeploymentBaseDigest(mutant), deploymentBase, key);
  }
  for (const key of Object.keys(deploymentPayload.rollback as object)) {
    if (key === "authorizedRollbackEnvelopeDigest") continue;
    const mutant = structuredClone(deploymentPayload as any);
    mutant.rollback[key] = changed(mutant.rollback[key]);
    assert.notEqual(nativeDeploymentBaseDigest(mutant), deploymentBase, `rollback.${key}`);
  }
  const deploymentExcluded = structuredClone(deploymentPayload as any);
  deploymentExcluded.deploymentBaseDigest = E;
  deploymentExcluded.rollback.authorizedRollbackEnvelopeDigest = E;
  assert.equal(nativeDeploymentBaseDigest(deploymentExcluded), deploymentBase);

  const closureBase = nativeReleaseClosureBaseDigest(closurePayload);
  for (const key of Object.keys(closurePayload)) {
    if (key === "nativeClosureBaseDigest" || key === "timestampRecordEnvelopeDigest") continue;
    const mutant = structuredClone(closurePayload as any);
    mutant[key] = changed(mutant[key]);
    assert.notEqual(nativeReleaseClosureBaseDigest(mutant), closureBase, key);
  }
  const closureExcluded = structuredClone(closurePayload as any);
  closureExcluded.nativeClosureBaseDigest = E;
  closureExcluded.timestampRecordEnvelopeDigest = E;
  assert.equal(nativeReleaseClosureBaseDigest(closureExcluded), closureBase);

  const staleDeployment = structuredClone(deploymentPayload as any);
  staleDeployment.b3.b3ProfileEnvelopeDigest = E;
  const staleClosure = structuredClone(closurePayload as any);
  staleClosure.nativePackagePayloadDigest = E;
  for (const [schema, candidate] of [
    ["deployment", envelope(staleDeployment)],
    ["native-closure", envelope(staleClosure)],
  ] as const) {
    assert.throws(
      () => captureNativeV2Schema(candidate, schema, "development"),
      /base digest mismatch/,
    );
    assert.equal(oracle([encodeCanonical(candidate)])[0]?.split("\t")[0], "ERR");
  }
});

test("A6 P1 exported base builders reject hostile objects before executing traps or accessors", () => {
  for (const builder of [nativeDeploymentBaseDigest, nativeReleaseClosureBaseDigest]) {
    let traps = 0;
    const proxy = new Proxy({}, {
      getPrototypeOf() { traps += 1; return Object.prototype; },
      ownKeys() { traps += 1; return []; },
      getOwnPropertyDescriptor() { traps += 1; return undefined; },
      get() { traps += 1; return undefined; },
    });
    assert.throws(() => builder(proxy as any), /inert canonical/);
    assert.equal(traps, 0);
    let getterRuns = 0;
    const accessor = Object.create(null);
    Object.defineProperty(accessor, "schema", {
      enumerable: true,
      get() { getterRuns += 1; return "keep.hostile"; },
    });
    assert.throws(() => builder(accessor), /accessor/);
    assert.equal(getterRuns, 0);
    const symbol = Object.create(null);
    Object.defineProperty(symbol, Symbol("hidden"), { enumerable: true, value: D });
    assert.throws(() => builder(symbol), /symbol/);
    const nested = Object.create(null);
    nested.safe = proxy;
    assert.throws(() => builder(nested), /inert canonical/);
    assert.equal(traps, 0);
  }
});

test("A6 P1 digest registry has zero schema coverage gaps and an acyclic construction order", () => {
  const observed = new Set<string>();
  const visit = (value: any, path: string): void => {
    if (value === null || typeof value !== "object" || value instanceof Uint8Array)
      return;
    if (Array.isArray(value)) {
      value.forEach((entry) => visit(entry, `${path}[]`));
      return;
    }
    if (value.type === "digest") observed.add(`${path}.value`);
    if (value.type === "digest-set") observed.add(`${path}.values[]`);
    for (const [key, child] of Object.entries(value)) {
      const childPath = `${path}.${key}`;
      if (/Digests?$/.test(key) || key === "digest" || key === "helperIncarnation" || key === "proberIncarnation" || key === "revokedArtifacts") {
        if (Array.isArray(child)) observed.add(`${childPath}[]`);
        else observed.add(childPath);
      }
      visit(child, childPath);
    }
  };
  for (const [name, fixture] of [
    ["request", launch], ["response", response], ["deployment", deployment],
    ["closure", closure], ["index", index], ["revocation", revocation],
    ["evidence", evidence],
  ] as const) visit(fixture, name);
  const registered = new Set(NATIVE_V2_DIGEST_REGISTRY.map((row) => row.path));
  assert.deepEqual([...registered].sort(), [...observed].sort());
  assert.equal(registered.size, NATIVE_V2_DIGEST_REGISTRY.length);
  const deploymentDependencies = [...observed].filter(
    (path) =>
      path.startsWith("deployment.payload.") &&
      path !== "deployment.payload.deploymentBaseDigest" &&
      path !== "deployment.payload.rollback.authorizedRollbackEnvelopeDigest",
  );
  const closureDependencies = [...observed].filter(
    (path) =>
      path.startsWith("closure.payload.") &&
      path !== "closure.payload.nativeClosureBaseDigest" &&
      path !== "closure.payload.timestampRecordEnvelopeDigest",
  );
  assert.deepEqual(
    [...NATIVE_V2_DIGEST_REGISTRY.find((row) => row.path === "deployment.payload.deploymentBaseDigest")!.dependsOn].sort(),
    deploymentDependencies.sort(),
  );
  assert.deepEqual(
    [...NATIVE_V2_DIGEST_REGISTRY.find((row) => row.path === "closure.payload.nativeClosureBaseDigest")!.dependsOn].sort(),
    closureDependencies.sort(),
  );
  const evidenceDependencies = [...observed].filter((path) => path.startsWith("evidence."));
  assert.deepEqual(
    [...NATIVE_V2_DIGEST_REGISTRY.find((row) => row.path === "response.evidenceBundleDigest")!.dependsOn].sort(),
    evidenceDependencies.sort(),
  );
  assert.deepEqual(
    [...NATIVE_V2_DIGEST_REGISTRY.find((row) => row.path === "revocation.payloadDigest")!.dependsOn].sort(),
    ["revocation.payload.previousEnvelopeDigest", "revocation.payload.revokedArtifacts[]"],
  );
  assert.deepEqual(
    [...NATIVE_V2_DIGEST_REGISTRY.find((row) => row.path === "deployment.payloadDigest")!.dependsOn].sort(),
    [...deploymentDependencies, "deployment.payload.deploymentBaseDigest", "deployment.payload.rollback.authorizedRollbackEnvelopeDigest"].sort(),
  );
  assert.deepEqual(
    [...NATIVE_V2_DIGEST_REGISTRY.find((row) => row.path === "closure.payloadDigest")!.dependsOn].sort(),
    [...closureDependencies, "closure.payload.nativeClosureBaseDigest", "closure.payload.timestampRecordEnvelopeDigest"].sort(),
  );
  const ranks = new Map(NATIVE_V2_DIGEST_REGISTRY.map((row) => [row.path, row.rank]));
  for (const row of NATIVE_V2_DIGEST_REGISTRY)
    for (const dependency of row.dependsOn) {
      assert.ok(registered.has(dependency), `${row.path} has unknown dependency ${dependency}`);
      assert.ok(
        (ranks.get(dependency) ?? -1) < row.rank,
        `${row.path} reverse/cyclic edge to ${dependency}`,
      );
    }
  const reversed = NATIVE_V2_DIGEST_REGISTRY.map((row) => ({
    ...row,
    dependsOn:
      row.path === "deployment.payload.deploymentBaseDigest"
        ? ["index.payload.nativeClosureEnvelopeDigest"]
        : row.dependsOn,
  }));
  assert.throws(
    () => validateNativeV2DigestRegistry(reversed),
    /reverse or cyclic/,
  );
  const missingEdge = NATIVE_V2_DIGEST_REGISTRY.map((row) => ({
    ...row,
    dependsOn:
      row.path === "closure.payloadDigest" ? row.dependsOn.slice(1) : row.dependsOn,
  }));
  assert.throws(
    () => validateNativeV2DigestRegistry(missingEdge),
    /required edges are incomplete/,
  );
  const loweredRank = NATIVE_V2_DIGEST_REGISTRY.map((row) => ({
    ...row,
    rank: row.path === "index.payloadDigest" ? 8 : row.rank,
  }));
  assert.throws(
    () => validateNativeV2DigestRegistry(loweredRank),
    /reverse or cyclic/,
  );
});

test("A6 P1 hostile CBOR corpus is rejected by both codecs without a favorable parse", () => {
  const hostile = [
    "1800",
    "9fff",
    "c0f6",
    "f90000",
    "61ff",
    "a2616100616101",
    "63" + Buffer.from("e\u0301").toString("hex"),
    "81".repeat(18) + "f6",
  ];
  for (const value of hostile.slice(0, -1))
    assert.equal(
      isCanonical(Buffer.from(value, "hex")),
      false,
      `TS accepted ${value}`,
    );
  assert.throws(
    () =>
      captureNativeV2Schema(
        decodeCanonical(Buffer.from(hostile.at(-1)!, "hex")),
        "evidence",
        "development",
      ),
    /depth exceeds/,
  );
  for (const output of oracle(
    hostile.map((value) => Buffer.from(value, "hex")),
  ))
    assert.match(output, /^ERR\t/);
});

test("A6 P1 deterministic differential parser fuzz corpus has identical bounded accept/refuse decisions", () => {
  let state = 0xd1ff3e2n;
  const rows: Uint8Array[] = [];
  for (let caseIndex = 0; caseIndex < 1024; caseIndex++) {
    state = (state * 2862933555777941757n + 3037000493n) & 0xffffffffffffffffn;
    const length = 1 + Number(state % 64n);
    const row = new Uint8Array(length);
    for (let index = 0; index < length; index++) {
      state =
        (state * 2862933555777941757n + 3037000493n) & 0xffffffffffffffffn;
      row[index] = Number(state & 255n);
    }
    rows.push(row);
  }
  rows.push(
    ...[null, true, 0n, 23n, 24n, "ascii", [1n, 2n], { a: 1n }].map(
      encodeCanonical,
    ),
  );
  const rust = oracle(rows, true);
  for (const [index, row] of rows.entries()) {
    let ts = false;
    try {
      decodeNativeV2Canonical(row);
      ts = true;
    } catch {}
    const rustAccepted = rust[index]!.startsWith("OK\t");
    assert.equal(
      rustAccepted,
      ts,
      `parser divergence ${index}: ${hex(row)} => ${rust[index]}`,
    );
  }
});

test("A6 P1 development trust objects are categorically refused by production capture", () => {
  for (const [schema, value] of [
    ["deployment", deployment],
    ["native-closure", closure],
    ["native-index", index],
  ] as const)
    assert.throws(
      () => captureNativeV2Schema(value, schema, "production"),
      /(trust class|development signature key) refused/,
    );
});

test("A6 P1 deterministic differential property corpus stays byte-identical across TS and Rust", () => {
  let state = 0x12345678n;
  const values: CanonicalValue[] = [];
  for (let index = 0; index < 512; index++) {
    state ^= state << 13n;
    state ^= state >> 7n;
    state ^= state << 17n;
    state &= 0xffffffffffffffffn;
    switch (index % 6) {
      case 0:
        values.push(state);
        break;
      case 1:
        values.push((state & 1n) === 1n);
        break;
      case 2:
        values.push(`case.${state.toString(16).padStart(16, "0")}`);
        break;
      case 3:
        values.push(
          new Uint8Array(
            Buffer.from(state.toString(16).padStart(16, "0"), "hex"),
          ),
        );
        break;
      case 4:
        values.push([state & 0xffffn, null]);
        break;
      default:
        values.push({ id: state, ok: true });
    }
  }
  const bytes = values.map(encodeCanonical);
  const outputs = oracle(bytes, true);
  assert.equal(outputs.length, bytes.length);
  outputs.forEach((output, index) => {
    const [status, schema, digest, encoded] = output.split("\t");
    assert.equal(status, "OK", output);
    assert.equal(schema, "Value");
    assert.equal(encoded, hex(bytes[index]!));
    assert.equal(
      digest,
      createHash("sha256").update(bytes[index]!).digest("hex"),
    );
  });
});

test("A6 P1 semantic differential corpus rejects identical one-mutation-invalid schemas", () => {
  const invalid: CanonicalValue[] = [];
  invalid.push(
    { ...launch, manifestDigest: "x" } as unknown as CanonicalValue,
    { ...launch, roles: [] } as unknown as CanonicalValue,
    {
      ...launch,
      roles: [{ ...launch.roles[0]!, roleClass: "D1" }],
    } as unknown as CanonicalValue,
    {
      ...response,
      status: "failed",
      failureCode: "",
      roleHandles: [],
      measurements: [],
    } as unknown as CanonicalValue,
  );
  invalid.push(
    {
      ...response,
      measurements: response.measurements.map((row, index) =>
        index === 0 ? { ...row, field: "unknown.field" } : row,
      ),
    } as unknown as CanonicalValue,
    {
      ...response,
      measurements: response.measurements.map((row, index) =>
        index === 1 ? { ...row, field: response.measurements[0]!.field } : row,
      ),
    } as unknown as CanonicalValue,
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      p.artifacts = (p.artifacts as any[]).filter(
        (row) => row.kind !== "helper",
      ) as CanonicalValue;
    }),
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.artifacts as any[]).push({
        ...(p.artifacts as any[]).find((row) => row.kind === "helper"),
        artifactId: "helper.z",
      });
      (p.artifacts as any[]).sort((a, b) =>
        a.artifactId.localeCompare(b.artifactId),
      );
    }),
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.roles as any[])[0].requiredMeasurementFields = [
        NATIVE_V2_MEASUREMENT_FIELDS[0],
      ];
    }),
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.roles as any[])[0].allowedChannelIds = [];
    }),
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.channels as any[]).push({
        ...(p.channels as any[])[0],
        channelId: "unused.extra",
      });
      (p.channels as any[]).sort((a, b) =>
        a.channelId.localeCompare(b.channelId),
      );
    }),
    {
      ...evidence,
      roles: [{ ...evidence.roles[0]!, uid: 0n }],
    } as unknown as CanonicalValue,
    {
      ...evidence,
      roles: [{ ...evidence.roles[0]!, groups: [1001n] }],
    } as unknown as CanonicalValue,
    {
      ...evidence,
      roles: [{ ...evidence.roles[0]!, incarnationDigest: D }],
    } as unknown as CanonicalValue,
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (
        p.bootPolicy as Record<string, CanonicalValue>
      ).maxConcurrentTransactions = 2n;
    }),
  );
  for (const [index] of NATIVE_V2_MEASUREMENT_FIELDS.entries()) {
    const wrong = structuredClone(evidence) as any;
    wrong.measurements[index].value = null;
    invalid.push(wrong);
    const omitted = structuredClone(evidence) as any;
    omitted.measurements.splice(index, 1);
    invalid.push(omitted);
  }
  const unknownMeasurement = structuredClone(evidence) as any;
  unknownMeasurement.measurements[0].field = "unknown.field";
  invalid.push(unknownMeasurement);
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.protocol as Record<string, CanonicalValue>).maxFrameBytes = 1n;
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.artifacts as CanonicalValue[]).push(
        structuredClone((p.artifacts as CanonicalValue[])[0]!),
      );
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.roles as Record<string, CanonicalValue>[])[0]!.capabilitiesEmpty =
        false;
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.roles as Record<string, CanonicalValue>[])[0]!.allowedChannelIds = [
        "missing",
      ];
    }),
  );
  invalid.push(
    mutateEnvelope(closure as CanonicalValue, (p) => {
      p.helperArtifactDigest = "x";
    }),
  );
  invalid.push(
    mutateEnvelope(closure as CanonicalValue, (p) => {
      p.provenanceEnvelopeDigests = [D, D];
    }),
  );
  invalid.push(
    mutateEnvelope(revocation as CanonicalValue, (p) => {
      p.expiresCounter = 1n;
    }),
  );
  invalid.push(
    { ...evidence, expiresCounter: 0n } as unknown as CanonicalValue,
    {
      ...evidence,
      measurements: [{ ...evidence.measurements[0]!, roleId: "missing" }],
    } as unknown as CanonicalValue,
    {
      ...evidence,
      signature: "development.signature",
    } as unknown as CanonicalValue,
  );
  invalid.push(
    { ...deployment, signatures: [] } as CanonicalValue,
    {
      ...deployment,
      signatures: [{ ...sigs[0]!, keyId: "production.release.1" }],
    } as CanonicalValue,
    {
      ...deployment,
      signatures: [{ ...sigs[0]!, signature: 1n }],
    } as unknown as CanonicalValue,
  );
  invalid.push(
    {
      ...evidence,
      signature: { ...evidence.signature, keyId: "production.prober.1" },
    } as unknown as CanonicalValue,
    {
      ...revocation,
      signatures: [{ ...sigs[0]!, keyId: "production.revocation.1" }],
    } as CanonicalValue,
  );
  invalid.push(
    {
      ...response,
      roleHandles: [
        response.roleHandles[0]!,
        {
          ...response.roleHandles[0]!,
          handleId: "handle.2",
          incarnationDigest: D,
        },
      ],
      measurements: [],
    } as unknown as CanonicalValue,
    {
      ...response,
      status: "failed",
      failureCode: "evidence.unavailable.sink",
      roleHandles: [],
      measurements: [],
      evidenceBundleDigest: E,
    } as unknown as CanonicalValue,
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.roles as any[])[0].mounts[0].target = "/keep/role name";
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.probers as any[])[0].principalId = "keep-net";
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.roles as any[])[0].artifactDigest = E;
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.artifacts as any[]).find((row) => row.artifactId === "role.net").kind =
        "helper";
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.artifacts as any[]).find((row) => row.artifactId === "prober").kind =
        "role";
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.provisioners as any[]).push(
        structuredClone((p.provisioners as any[])[0]),
      );
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.provisioners as any[])[0].principalId = "keep-net";
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.provisioners as any[])[0].domain = "wrong.domain";
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.provisioners as any[])[0].descriptorCount = 0n;
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.channels as any[])[0].maxFrameBytes = 1048577n;
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      const channel = (p.channels as any[]).find(
        (row) => row.channelId === "d3.provision",
      );
      channel.fromEndpoint = "role:net.d3";
      channel.toEndpoint = "role:net.d3";
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      p.channels = (p.channels as any[]).filter(
        (row) => row.channelId !== "b3.auth",
      );
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      const channel = (p.channels as any[]).find(
        (row) => row.channelId === "d3.provision",
      );
      channel.fromEndpoint = "prober:prober.1";
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      const channel = (p.channels as any[]).find(
        (row) => row.channelId === "prober.observe",
      );
      channel.toEndpoint = "role:undeclared";
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      const channel = (p.channels as any[]).find(
        (row) => row.channelId === "d3.provision",
      );
      channel.direction = "request-response";
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.rollback as any).deploymentEpoch = 2n;
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.rollback as any).minimumArtifactVersion = 2n;
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.release as any).targetTriple = "wrong-target";
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.evidence as any).maxBundleBytes = 0n;
    }),
  );
  invalid.push(
    mutateEnvelope(deployment as CanonicalValue, (p) => {
      (p.evidence as any).keyId = "development.wrong";
    }),
  );
  assert.ok(invalid.length >= 15);
  for (const [index, value] of invalid.entries())
    assert.equal(tsAccept(value), false, `TS accepted mutant ${index}`);
  const results = oracle(invalid.map(encodeCanonical));
  results.forEach((result, index) =>
    assert.match(result, /^ERR\t/, `Rust accepted mutant ${index}: ${result}`),
  );
});

test("A6 P1 every frozen schema map rejects missing, null-typed, and extra-field structural mutants in both families", () => {
  const valid = [
    launch as unknown as CanonicalValue,
    response as unknown as CanonicalValue,
    deployment as CanonicalValue,
    closure as CanonicalValue,
    index as CanonicalValue,
    revocation as CanonicalValue,
    evidence as CanonicalValue,
  ];
  const mutants = valid.flatMap(structuralMutants);
  assert.ok(mutants.length > 300, `only ${mutants.length} mutants`);
  for (const [index, value] of mutants.entries())
    assert.equal(
      tsAccept(value),
      false,
      `TS accepted structural mutant ${index}`,
    );
  const outputs = oracle(mutants.map(encodeCanonical));
  outputs.forEach((output, index) =>
    assert.match(
      output,
      /^ERR\t/,
      `Rust accepted structural mutant ${index}: ${output}`,
    ),
  );
});

test("A6 P1 bounded byte decoder and Rust encoder enforce exact hostile limits", () => {
  const valid = encodeCanonical(launch as unknown as CanonicalValue);
  assert.deepEqual(decodeNativeV2Canonical(valid), decodeCanonical(valid));
  assert.throws(
    () => decodeNativeV2Canonical(new Uint8Array(1_048_577)),
    /bound/,
  );
  assert.throws(
    () => decodeNativeV2Canonical(new Proxy(valid, {})),
    /Uint8Array/,
  );
  const deep = encodeCanonical(
    Array.from({ length: 18 }).reduce<CanonicalValue>((value) => [value], null),
  );
  assert.throws(() => decodeNativeV2Canonical(deep), /depth/);
  const longText = encodeCanonical("x".repeat(4097));
  assert.throws(() => decodeNativeV2Canonical(longText), /text/);
  const tooMany = encodeCanonical(Array.from({ length: 1025 }, () => null));
  assert.throws(() => decodeNativeV2Canonical(tooMany), /collection/);
  for (const bytes of [
    encodeCanonical("x".repeat(4096)),
    encodeCanonical(Array.from({ length: 1024 }, () => null)),
  ])
    assert.doesNotThrow(() => decodeNativeV2Canonical(bytes));
});

test("A6 P1 object constructors preflight bounds and accessors before canonical encoding", () => {
  const huge = Array.from({ length: 1025 }, () => null);
  assert.throws(() => captureNativeBoundaryV2Request(huge), /dense\/bounded/);
  let reads = 0;
  const accessor = Object.create(null);
  Object.defineProperty(accessor, "protocol", {
    enumerable: true,
    get() {
      reads++;
      return "keep.native-boundary";
    },
  });
  assert.throws(() => captureNativeBoundaryV2Request(accessor), /accessor/);
  assert.equal(reads, 0);
  const nestedProxy = new Proxy(
    {},
    {
      ownKeys() {
        reads++;
        return [];
      },
    },
  );
  assert.throws(
    () => captureNativeBoundaryV2Request({ nested: nestedProxy }),
    /inert canonical/,
  );
  assert.equal(reads, 0);
  let nested: unknown = null;
  for (let index = 0; index < 18; index++) nested = [nested];
  assert.throws(() => captureNativeBoundaryV2Request(nested), /depth/);
  const cumulative = Array.from({ length: 256 }, () => new Uint8Array(4096));
  assert.throws(
    () => captureNativeBoundaryV2Request(cumulative),
    /cumulative encoded bytes/,
  );
});

test("A6 P1 SHA-256 implementation agrees with Node across padding, random, and schema maxima", () => {
  const lengths = [
    0,
    1,
    55,
    56,
    63,
    64,
    65,
    127,
    128,
    129,
    1000,
    4096,
    65536,
    4 * 1024 * 1024,
    8 * 1024 * 1024,
  ];
  let state = 0x51f15en;
  const rows = lengths.map((length) => {
    const bytes = new Uint8Array(length);
    for (let index = 0; index < length; index++) {
      state =
        (state * 6364136223846793005n + 1442695040888963407n) &
        0xffffffffffffffffn;
      bytes[index] = Number(state & 255n);
    }
    return bytes;
  });
  const path = fileURLToPath(
    new URL(
      "../../native/target/x86_64-unknown-linux-musl/debug/keep-native-protocol-oracle",
      import.meta.url,
    ),
  );
  const result = spawnSync(path, {
    input: rows.map((row) => `SHA:${hex(row)}`).join("\n") + "\n",
    encoding: "utf8",
    env: {},
    maxBuffer: 32 * 1024 * 1024,
  });
  assert.equal(
    result.status,
    0,
    `${result.error?.message ?? ""} ${result.stderr}`,
  );
  const outputs = result.stdout.trimEnd().split("\n");
  assert.equal(outputs.length, rows.length);
  outputs.forEach((output, index) =>
    assert.equal(
      output,
      `SHA\t${createHash("sha256").update(rows[index]!).digest("hex")}`,
      `length ${lengths[index]}`,
    ),
  );
});
