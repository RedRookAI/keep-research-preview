import { createHash } from "node:crypto";
import { encodeCanonical, type CanonicalValue } from "../../src/eir/canonical.js";
import { NATIVE_V2_MEASUREMENT_FIELDS, nativeDeploymentBaseDigest } from "../../src/platform/native_boundary_protocol_v2.js";

const D = "ab".repeat(32);
const baseDeploymentPayload = {
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
baseDeploymentPayload.deploymentBaseDigest = nativeDeploymentBaseDigest(baseDeploymentPayload);


export interface ProductionExecutableDigests {
  readonly helper: string;
  readonly trampoline: string;
  readonly prober: string;
  readonly provisioner: string;
  readonly role: string;
}

export function productionDeploymentFixture(digests: ProductionExecutableDigests): CanonicalValue {
  const payload = structuredClone(baseDeploymentPayload);
  payload.trustClass = "production";
  (payload.evidence as Record<string, CanonicalValue>).keyId = "production.prober.1";
  ((payload.probers as Array<Record<string, CanonicalValue>>)[0]!).signingKeyId = "production.prober.1";
  for (const artifact of payload.artifacts as Array<Record<string, CanonicalValue>>) {
    const kind = String(artifact.kind);
    if (kind === "helper" || kind === "trampoline" || kind === "prober" || kind === "provisioner" || kind === "role") artifact.digest = digests[kind];
  }
  for (const role of payload.roles as Array<Record<string, CanonicalValue>>) {
    const artifact = (payload.artifacts as Array<Record<string, CanonicalValue>>)
      .find((candidate) => candidate.artifactId === role.artifactId);
    if (artifact && typeof artifact.digest === "string") role.artifactDigest = artifact.digest;
  }
  payload.deploymentBaseDigest = nativeDeploymentBaseDigest(payload);
  return {
    payload,
    payloadDigest: createHash("sha256").update(encodeCanonical(payload)).digest("hex"),
    signatures: [{ keyId: "production.release.1", algorithm: "ed25519", keyEpoch: 1n, signature: new Uint8Array(64).fill(1) }],
  };
}
