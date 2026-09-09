/** Schema-valid development-only A6 deployment fixture for the refusal transport probe. */
import { createHash, randomBytes } from "node:crypto";
import { encodeCanonical, type CanonicalValue } from "../eir/canonical.js";
import {
  NATIVE_V2_MEASUREMENT_FIELDS,
  captureNativeV2Schema,
  nativeDeploymentBaseDigest,
  type NativeBoundaryV2Request,
} from "./native_boundary_protocol_v2.js";

const D = "ab".repeat(32);

export interface NativeTransportDevelopmentFixture {
  readonly deployment: CanonicalValue;
  readonly manifestDigest: string;
  readonly deploymentId: string;
  readonly channelId: string;
  readonly channelMaxFrameBytes: 65_536;
}

export interface NativeTransportDevelopmentProbeInput {
  readonly bootId: string;
  readonly deadlineMs: bigint;
  readonly sequence?: bigint;
}

export function buildNativeTransportDevelopmentProbe(
  fixture: NativeTransportDevelopmentFixture,
  input: NativeTransportDevelopmentProbeInput,
): NativeBoundaryV2Request {
  const token = randomBytes(16).toString("hex");
  return Object.freeze({
    protocol: "keep.native-boundary",
    version: 2n,
    kind: "cancel",
    requestId: `transport.probe.${token}`,
    deploymentId: fixture.deploymentId,
    bootId: input.bootId,
    manifestDigest: fixture.manifestDigest,
    nonce: `transport.nonce.${token}`,
    sequence: input.sequence ?? 0n,
    deadlineMs: input.deadlineMs,
    targetRequestId: "transport.probe",
  });
}

export function buildNativeTransportDevelopmentFixture(): NativeTransportDevelopmentFixture {
  const payload = {
    schema: "keep.native-deployment",
    version: 1n,
    trustClass: "development",
    deploymentId: "development.transport",
    deploymentEpoch: 1n,
    deploymentBaseDigest: D,
    predecessorDigest: D,
    bootPolicy: {
      maxLaunchMs: 1000n,
      maxResponseMs: 2000n,
      maxAttestationAge: 10n,
      maxCleanupMs: 1000n,
      maxConcurrentTransactions: 1n,
      kernelCells: [{
        cellId: "linux.6.8",
        minimumKernel: "6.8",
        maximumKernel: "6.x",
        requiredFeatures: ["cgroup.kill", "landlock", "pidfd", "seccomp"],
      }],
    },
    protocol: {
      name: "keep.native-boundary",
      version: 2n,
      maxFrameBytes: 1_048_576n,
      maxRoles: 32n,
      maxChannels: 128n,
      maxMeasurements: 1024n,
      maxDepth: 16n,
      maxItems: 65_536n,
      maxTextBytes: 4096n,
    },
    artifacts: [
      { artifactId: "helper", digest: D, kind: "helper", targetTriple: "x86_64-unknown-linux-musl", variant: "static-pie", executableMode: 365n, releaseMember: true },
      { artifactId: "prober", digest: D, kind: "prober", targetTriple: "x86_64-unknown-linux-musl", variant: "static-pie", executableMode: 365n, releaseMember: true },
      { artifactId: "provisioner.net", digest: D, kind: "provisioner", targetTriple: "x86_64-unknown-linux-musl", variant: "static-pie", executableMode: 365n, releaseMember: true },
      { artifactId: "role.net", digest: D, kind: "role", targetTriple: "x86_64-unknown-linux-musl", variant: "static-pie", executableMode: 365n, releaseMember: true },
      { artifactId: "trampoline", digest: D, kind: "trampoline", targetTriple: "x86_64-unknown-linux-musl", variant: "static-pie", executableMode: 365n, releaseMember: true },
    ],
    roles: [{
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
      namespaces: { user: true, pid: true, mount: true, network: true, ipc: true, cgroup: true },
      mounts: [{ sourceArtifactId: "role.net", target: "/keep/role", readOnly: true, nodev: true, nosuid: true, noexec: false }],
      cgroup: { pathId: "keep.net", memoryMax: 1_048_576n, pidsMax: 1n, cpuMaxMicros: 100_000n, ioMaxDigest: D },
      rlimits: { nofile: 16n, nproc: 1n, core: 0n, fsize: 0n, addressSpace: 67_108_864n },
      capabilitiesEmpty: true,
      dumpable: false,
      launchSeccompDigest: D,
      steadySeccompDigest: D,
      landlockDigest: D,
      environmentAllowlist: [],
      inheritedFdSlots: [3n],
      requiredMeasurementFields: NATIVE_V2_MEASUREMENT_FIELDS,
    }],
    channels: [
      { channelId: "b3.auth", fromEndpoint: "supervisor:keep", toEndpoint: "b3:b3.1", socketType: "seqpacket", direction: "request-response", maxFrameBytes: 4096n, maxDescriptors: 0n, peerCredentialPolicy: "exact-principal", oneShot: false },
      { channelId: "d3.provision", fromEndpoint: "provisioner:provisioner.net", toEndpoint: "role:net.d3", socketType: "seqpacket", direction: "one-way", maxFrameBytes: 4096n, maxDescriptors: 1n, peerCredentialPolicy: "exact-principal", oneShot: true },
      { channelId: "transport.observe", fromEndpoint: "prober:transport.prober", toEndpoint: "supervisor:keep", socketType: "seqpacket", direction: "request-response", maxFrameBytes: 65_536n, maxDescriptors: 0n, peerCredentialPolicy: "exact-principal", oneShot: false },
    ],
    probers: [{
      proberId: "transport.prober",
      artifactId: "prober",
      principalId: "keep-prober",
      signingKeyId: "development.prober.1",
      keyEpoch: 1n,
      channelId: "transport.observe",
      observationGrants: ["cgroup", "landlock", "namespaces", "seccomp"],
      requiredNegativeProbes: ["network.denied"],
    }],
    provisioners: [{
      provisionerId: "provisioner.net",
      domain: "provider.test",
      principalId: "keep-provisioner-net",
      artifactId: "provisioner.net",
      targetRoleId: "net.d3",
      channelId: "d3.provision",
      descriptorType: "sealed-memfd",
      requiredSeals: ["F_SEAL_GROW", "F_SEAL_SEAL", "F_SEAL_SHRINK", "F_SEAL_WRITE"],
      descriptorCount: 1n,
      destructionDeadlineMs: 100n,
    }],
    b3: { authorityId: "b3.1", genesisBaseDigest: D, b3ProfileEnvelopeDigest: D, keyEpoch: 1n, assurance: "load-bearing", channelId: "b3.auth" },
    release: { buildId: "development.transport.v1", artifactVersion: 1n, targetTriple: "x86_64-unknown-linux-musl", variant: "static-pie", releaseKeyEpoch: 1n, timestampKeyEpoch: 1n },
    revocation: { authorityId: "development.revocation", keyEpoch: 1n, namespace: "keep", scope: "native", genesisCheckpointEnvelopeDigest: D, minimumSequence: 1n, maxStalenessCounters: 10n, compromiseSemantics: "fail-stop-quarantine" },
    rollback: { deploymentEpoch: 1n, minimumArtifactVersion: 1n, predecessorDigest: D, authorizedRollbackEnvelopeDigest: D },
    evidence: { schema: "keep.native-evidence", sinkId: "native.evidence", maxBundleBytes: 8_388_608n, algorithm: "ed25519", keyId: "development.prober.1", keyEpoch: 1n, appendPolicy: "create-exclusive-fsync", witnessPolicy: "external-prober" },
  } as unknown as Record<string, CanonicalValue>;
  payload.deploymentBaseDigest = nativeDeploymentBaseDigest(payload);
  const payloadDigest = createHash("sha256").update(encodeCanonical(payload)).digest("hex");
  const deployment = {
    payload,
    payloadDigest,
    signatures: [{
      keyId: "development.release.1",
      algorithm: "ed25519",
      keyEpoch: 1n,
      signature: new Uint8Array(64).fill(1),
    }],
  } as unknown as CanonicalValue;
  const captured = captureNativeV2Schema(deployment, "deployment", "development");
  const manifestDigest = createHash("sha256").update(encodeCanonical(deployment)).digest("hex");
  if (captured.contentDigest !== manifestDigest)
    throw new Error("native development fixture capture digest mismatch");
  return Object.freeze({
    deployment,
    manifestDigest,
    deploymentId: "development.transport",
    channelId: "transport.observe",
    channelMaxFrameBytes: 65_536,
  });
}
