/**
 * A6 P2-S1: dependency-free, non-authorizing native authority schemas.
 *
 * This module only captures canonical data and builds typed hashes/preimages. It deliberately
 * contains no signature verification, filesystem access, B3 transport, production brand, or effect.
 */
import { createHash } from "node:crypto";
import { types } from "node:util";
import {
  decodeCanonical,
  encodeCanonical,
  isCanonical,
  type CanonicalValue,
} from "../eir/canonical.js";
import {
  captureNativeV2Schema,
  NATIVE_V2_DIGEST_REGISTRY,
  type NativeV2Schema,
  type NativeV2TrustClass,
} from "./native_boundary_protocol_v2.js";
import { NATIVE_P2_RELATIVE_PATH } from "./native_p2_path.js";
import {
  captureNativePatchOverlayV1,
  type ValidatedPatchOverlayPlan,
} from "./native_p2_d2_overlay.js";
import {
  captureNativePatchByteCarrierSetV1,
  joinValidatedPatchApplicationInputs,
  type ValidatedPatchApplicationInputs,
} from "./native_p2_d2_carriers.js";
import {
  validateNativeResultTreeApplicationV1,
  type CapturedNativeArchiveV1,
  type ValidatedNativeResultTreePlan,
} from "./native_p2_d2_application.js";

export class NativeAuthoritySchemaError extends Error {
  constructor(message: string) {
    super(`native authority schema: ${message}`);
    this.name = "NativeAuthoritySchemaError";
  }
}

export const P2_S1_LIMITS = Object.freeze({
  envelopeBytes: 4 * 1024 * 1024,
  evidenceBytes: 8 * 1024 * 1024,
  depth: 16,
  totalItems: 65_536,
  textBytes: 4_096,
  byteStringBytes: 1024 * 1024,
} as const);

// Frozen P1 identifier grammar: 1..128 ASCII bytes, alphanumeric first, then ._:@/-.
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const ABSOLUTE_PATH = /^(?!.*(?:^|\/)\.\.?(?:\/|$))\/(?:[A-Za-z0-9._+-]+(?:\/[A-Za-z0-9._+-]+)*)?$/;
const URI = /^(?:keep-artifact:|keep-source:|oci:)[A-Za-z0-9._:/+@-]+$/;
const ENDPOINT_IDENTITY = /^[A-Za-z0-9][A-Za-z0-9._+@-]{0,4095}$/;

export type P2DigestSemantic = string & { readonly __p2DigestSemantic: unique symbol };
export interface P2DigestValue<S extends string = string> {
  readonly semantic: S;
  readonly bytes: Uint8Array;
  readonly hex: string;
}

type ScalarSpec =
  | { readonly type: "identifier"; readonly enum?: readonly string[] }
  | { readonly type: "text"; readonly enum?: readonly string[]; readonly pattern?: RegExp }
  | { readonly type: "uint"; readonly min?: bigint; readonly max?: bigint }
  | { readonly type: "bool" }
  | { readonly type: "digest"; readonly semantic: string }
  | { readonly type: "bytes"; readonly exact?: number; readonly max?: number };
type Spec =
  | ScalarSpec
  | { readonly type: "oneOf"; readonly variants: readonly Spec[] }
  | { readonly type: "nullable"; readonly inner: Spec }
  | { readonly type: "record"; readonly fields: Readonly<Record<string, Spec>> }
  | {
      readonly type: "array";
      readonly item: Spec;
      readonly min: number;
      readonly max: number;
      readonly sortedScalar?: boolean;
      readonly sortBy?: readonly string[];
      readonly uniqueBy?: readonly string[];
    }
  | {
      readonly type: "tagged";
      readonly tag: string;
      readonly variants: Readonly<Record<string, Spec>>;
    };

const id = (values?: readonly string[]): Spec => values === undefined ? { type: "identifier" } : { type: "identifier", enum: values };
const text = (values?: readonly string[], pattern?: RegExp): Spec => ({
  type: "text",
  ...(values === undefined ? {} : { enum: values }),
  ...(pattern === undefined ? {} : { pattern }),
});
const uint = (min = 0n, max = (1n << 64n) - 1n): Spec => ({ type: "uint", min, max });
const bool: Spec = { type: "bool" };
const digest = (semantic: string): Spec => ({ type: "digest", semantic: semantic.endsWith("Digest") ? semantic : `${semantic}Digest` });
const bytes = (exact?: number, max?: number): Spec => ({
  type: "bytes",
  ...(exact === undefined ? {} : { exact }),
  ...(max === undefined ? {} : { max }),
});
const nullable = (inner: Spec): Spec => ({ type: "nullable", inner });
const record = (fields: Readonly<Record<string, Spec>>): Spec => ({ type: "record", fields });
const array = (
  item: Spec,
  max: number,
  options: { min?: number; sortedScalar?: boolean; sortBy?: readonly string[]; uniqueBy?: readonly string[] } = {},
): Spec => ({
  type: "array",
  item,
  min: options.min ?? 0,
  max,
  ...(options.sortedScalar === undefined ? {} : { sortedScalar: options.sortedScalar }),
  ...(options.sortBy === undefined ? {} : { sortBy: options.sortBy }),
  ...(options.uniqueBy === undefined ? {} : { uniqueBy: options.uniqueBy }),
});
const tagged = (tag: string, variants: Readonly<Record<string, Spec>>): Spec => ({ type: "tagged", tag, variants });
const oneOf = (...variants: readonly Spec[]): Spec => ({ type: "oneOf", variants });

function asRecord(value: CanonicalValue, path: string): Record<string, CanonicalValue> {
  if (value === null || Array.isArray(value) || value instanceof Uint8Array || typeof value !== "object")
    throw new NativeAuthoritySchemaError(`${path} is not a record`);
  return value as Record<string, CanonicalValue>;
}

function compareKey(row: Record<string, CanonicalValue>, keys: readonly string[]): string {
  return keys.map((key) => {
    const value = row[key];
    return typeof value === "bigint" ? value.toString().padStart(20, "0") : String(value);
  }).join("\0");
}

function validate(value: CanonicalValue, spec: Spec, path: string): void {
  if (spec.type === "oneOf") {
    for (const variant of spec.variants) {
      try { validate(value, variant, path); return; } catch { /* exact alternatives */ }
    }
    throw new NativeAuthoritySchemaError(`${path} matches no exact variant`);
  }
  if (spec.type === "nullable") {
    if (value !== null) validate(value, spec.inner, path);
    return;
  }
  if (spec.type === "identifier" || spec.type === "text") {
    if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > P2_S1_LIMITS.textBytes)
      throw new NativeAuthoritySchemaError(`${path} is not bounded text`);
    if (!/^[\x20-\x7e\n]*$/.test(value))
      throw new NativeAuthoritySchemaError(`${path} is outside the native ASCII profile`);
    if (spec.type === "identifier" && !IDENTIFIER.test(value))
      throw new NativeAuthoritySchemaError(`${path} is outside identifier grammar`);
    if (spec.enum && !spec.enum.includes(value))
      throw new NativeAuthoritySchemaError(`${path} is outside closed enum`);
    if (spec.type === "text" && spec.pattern && !spec.pattern.test(value))
      throw new NativeAuthoritySchemaError(`${path} is outside text grammar`);
    return;
  }
  if (spec.type === "uint") {
    if (typeof value !== "bigint" || value < (spec.min ?? 0n) || value > (spec.max ?? (1n << 64n) - 1n))
      throw new NativeAuthoritySchemaError(`${path} is outside uint64 bound`);
    return;
  }
  if (spec.type === "bool") {
    if (typeof value !== "boolean") throw new NativeAuthoritySchemaError(`${path} is not boolean`);
    return;
  }
  if (spec.type === "digest") {
    if (typeof value !== "string" || !HEX64.test(value) || value === "00".repeat(32))
      throw new NativeAuthoritySchemaError(`${path} is not a nonzero SHA-256`);
    return;
  }
  if (spec.type === "bytes") {
    if (!(value instanceof Uint8Array) ||
      (spec.exact !== undefined && value.byteLength !== spec.exact) ||
      value.byteLength > (spec.max ?? P2_S1_LIMITS.byteStringBytes))
      throw new NativeAuthoritySchemaError(`${path} is outside byte-string bound`);
    return;
  }
  if (spec.type === "record") {
    const row = asRecord(value, path);
    const actual = Object.keys(row).sort();
    const expected = Object.keys(spec.fields).sort();
    if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index]))
      throw new NativeAuthoritySchemaError(`${path} fields are not exact`);
    for (const [key, child] of Object.entries(spec.fields)) validate(row[key]!, child, `${path}.${key}`);
    return;
  }
  if (spec.type === "array") {
    if (!Array.isArray(value) || value.length < spec.min || value.length > spec.max)
      throw new NativeAuthoritySchemaError(`${path} collection bound violated`);
    let previous: string | undefined;
    const seen = new Set<string>();
    value.forEach((entry, index) => {
      validate(entry, spec.item, `${path}[${index}]`);
      if (spec.sortBy || spec.uniqueBy) {
        const row = asRecord(entry, `${path}[${index}]`);
        const order = spec.sortBy ? compareKey(row, spec.sortBy) : undefined;
        const identity = compareKey(row, spec.uniqueBy ?? spec.sortBy!);
        if (order !== undefined && previous !== undefined && !(previous < order))
          throw new NativeAuthoritySchemaError(`${path} is not strictly sorted`);
        if (seen.has(identity)) throw new NativeAuthoritySchemaError(`${path} is not unique`);
        previous = order;
        seen.add(identity);
      } else if (spec.sortedScalar && typeof entry === "string") {
        if (previous !== undefined && !(previous < entry))
          throw new NativeAuthoritySchemaError(`${path} is not sorted unique`);
        previous = entry;
      }
    });
    return;
  }
  const row = asRecord(value, path);
  const tagValue = row[spec.tag];
  if (typeof tagValue !== "string" || !Object.hasOwn(spec.variants, tagValue))
    throw new NativeAuthoritySchemaError(`${path} has unknown tagged variant`);
  validate(value, spec.variants[tagValue]!, path);
}

function boundedCanonical(bytesInput: unknown, maximum: number): CanonicalValue {
  if (bytesInput === null || typeof bytesInput !== "object" || types.isProxy(bytesInput) || !(bytesInput instanceof Uint8Array))
    throw new NativeAuthoritySchemaError("input is not an owned byte string");
  if (bytesInput.byteLength === 0 || bytesInput.byteLength > maximum)
    throw new NativeAuthoritySchemaError("encoded-size bound violated");
  const owned = Uint8Array.from(bytesInput);
  if (!isCanonical(owned)) throw new NativeAuthoritySchemaError("CBOR is not canonical");
  const value = decodeCanonical(owned);
  let items = 0;
  const walk = (entry: CanonicalValue, depth: number): void => {
    if (depth > P2_S1_LIMITS.depth || ++items > P2_S1_LIMITS.totalItems)
      throw new NativeAuthoritySchemaError("aggregate depth/item bound violated");
    if (typeof entry === "string" && Buffer.byteLength(entry, "utf8") > P2_S1_LIMITS.textBytes)
      throw new NativeAuthoritySchemaError("text bound violated");
    if (entry instanceof Uint8Array && entry.byteLength > P2_S1_LIMITS.byteStringBytes)
      throw new NativeAuthoritySchemaError("byte-string bound violated");
    if (Array.isArray(entry)) entry.forEach((child) => walk(child, depth + 1));
    else if (entry !== null && typeof entry === "object" && !(entry instanceof Uint8Array))
      Object.entries(entry).forEach(([key, child]) => { walk(key, depth + 1); walk(child, depth + 1); });
  };
  walk(value, 0);
  return value;
}

const scopeKey = record({ authorityId: id(), namespace: id(), scope: id(), genesisRootDigest: digest("GenesisRootEnvelope") });
const authorization = tagged("kind", {
  "root-update": record({ kind: id(["root-update"]), authorizationEnvelopeDigest: digest("RootEnvelope") }),
  revocation: record({ kind: id(["revocation"]), authorizationEnvelopeDigest: digest("RevocationEnvelope") }),
  rollback: record({ kind: id(["rollback"]), authorizationEnvelopeDigest: digest("RollbackAuthorizationEnvelope") }),
  recovery: record({ kind: id(["recovery"]), authorizationEnvelopeDigest: digest("RevocationRecoveryEnvelope") }),
  deployment: record({ kind: id(["deployment"]), authorizationEnvelopeDigest: digest("DeploymentEnvelope") }),
});
const callerPurpose = tagged("purpose", {
  "root-update": record({ purpose: id(["root-update"]), authorization }),
  "revocation-advance": record({ purpose: id(["revocation-advance"]), authorization }),
  rollback: record({ purpose: id(["rollback"]), authorization }),
  recovery: record({ purpose: id(["recovery"]), authorization }),
  "deployment-advance": record({ purpose: id(["deployment-advance"]), authorization }),
});

const operationCommon = { schema: id(["keep.native-b3-operation"]), version: uint(1n, 1n) } as const;
const P2_OPERATION_SPECS = Object.freeze({
  "b3-genesis-operation": record({ ...operationCommon, operationKind: id(["genesis"]), genesisBaseDigest: digest("GenesisBase"), b0RootEnvelopeDigest: digest("RootEnvelope"), b3ProfileEnvelopeDigest: digest("B3ProfileEnvelope"), derivedGenesisStateDigest: digest("B3State"), requestNonce: bytes(32) }),
  "b3-read-operation": record({ ...operationCommon, operationKind: id(["read"]), scopeKey, requestNonce: bytes(32) }),
  "b3-cas-operation": record({ ...operationCommon, operationKind: id(["compare-and-advance"]), scopeKey, expectedStateDigest: digest("B3State"), newStateDigest: digest("B3State"), callerPurpose, requestNonce: bytes(32) }),
  "b3-lease-operation": record({ ...operationCommon, operationKind: id(["validate-lease"]), scopeKey, generation: uint(), headEnvelopeDigest: digest("RevocationEnvelope"), b3CounterCeiling: uint(), requestNonce: bytes(32) }),
  "b3-subscribe-operation": record({ ...operationCommon, operationKind: id(["subscribe-invalidation"]), scopeKey, generation: uint(), sessionId: id(), requestNonce: bytes(32) }),
} as const);

const fact = tagged("valueType", {
  identifier: record({ factId: id(), valueType: id(["identifier"]), value: id() }),
  uint64: record({ factId: id(), valueType: id(["uint64"]), value: uint() }),
  boolean: record({ factId: id(), valueType: id(["boolean"]), value: bool }),
});
const auxiliarySpecs = Object.freeze({
  "observation-result": record({ schema: id(["keep.native-observation-result"]), version: uint(1n, 1n), resultCode: id(["pass", "fail", "inconclusive"]), facts: array(fact, 1024, { sortBy: ["factId"], uniqueBy: ["factId"] }) }),
  "control-policy": record({ schema: id(["keep.native-control-policy"]), version: uint(1n, 1n), controlId: id(), decisionClass: id(["permit", "deny", "measure-only"]), requirements: array(id(["signature-valid", "threshold-met", "content-address-match", "subject-match", "fresh", "not-revoked", "floor-satisfied", "lease-active", "isolation-measured"]), 256, { sortedScalar: true }) }),
  "journal-entries": record({ schema: id(["keep.native-journal-entries"]), version: uint(1n, 1n), entries: array(record({ sequence: uint(), eventCode: id(), subjectDigest: digest("JournalSubject"), counter: uint() }), 4096, { sortBy: ["sequence"], uniqueBy: ["sequence"] }) }),
  "peer-policy": record({ schema: id(["keep.native-peer-policy"]), version: uint(1n, 1n), requiredUid: nullable(uint()), requiredGid: nullable(uint()), requiredSecurityLabel: nullable(id()) }),
  "build-command": record({ schema: id(["keep.native-build-command"]), version: uint(1n, 1n), executableDigest: digest("BuildTool"), arguments: array(text(), 256) }),
  transcript: record({ schema: id(["keep.native-transcript"]), version: uint(1n, 1n), subjectDigest: digest("Subject"), mechanism: id(), mechanismVersion: id(), capturedCounter: uint(), resultDigest: digest("ObservationResult") }),
  control: record({ schema: id(["keep.native-control"]), version: uint(1n, 1n), controlId: id(), subjectDigest: digest("Subject"), policyDigest: digest("ControlPolicy") }),
  journal: record({ schema: id(["keep.native-journal"]), version: uint(1n, 1n), deploymentId: id(), bootId: id(), sequence: uint(), previousJournalDigest: digest("Journal"), entriesDigest: digest("JournalEntries") }),
  "fd-flags": record({ schema: id(["keep.native-fd-flags"]), version: uint(1n, 1n), flags: array(id(["O_RDONLY", "O_CLOEXEC", "O_NOFOLLOW", "O_PATH", "O_DIRECTORY"]), 5, { sortedScalar: true }), closeOnExec: bool, seals: array(id(["F_SEAL_WRITE", "F_SEAL_SHRINK", "F_SEAL_GROW", "F_SEAL_EXEC", "F_SEAL_SEAL"]), 5, { sortedScalar: true }) }),
  "transport-identity": record({ schema: id(["keep.native-transport-identity"]), version: uint(1n, 1n), transportKind: id(["unix-seqpacket", "vsock"]), endpointIdentity: text(undefined, ENDPOINT_IDENTITY), peerPolicyDigest: digest("PeerPolicy") }),
  invocation: record({ schema: id(["keep.native-invocation"]), version: uint(1n, 1n), buildId: id(), commandDigest: digest("BuildCommand"), environmentPolicyDigest: digest("EnvironmentPolicy"), inputs: array(record({ uri: text(undefined, URI), artifactDigest: digest("InvocationInputArtifact") }), 4096, { sortBy: ["uri"], uniqueBy: ["uri"] }) }),
  "environment-policy": record({ schema: id(["keep.native-environment-policy"]), version: uint(1n, 1n), allowedVariables: array(id(), 256, { sortedScalar: true }), workingDirectoryPolicy: id(["empty", "fixed-source-root"]), networkPolicy: id(["denied", "builder-isolated"]) }),
  comparison: record({ schema: id(["keep.native-comparison"]), version: uint(1n, 1n), algorithm: id(["sha256-byte-for-byte/v1"]), leftSubjectDigest: digest("Subject"), rightSubjectDigest: digest("Subject"), disagreementsDigest: digest("Disagreements") }),
} as const);

const ioLimit = nullable(uint());
const ioRow = record({ deviceMajor: uint(), deviceMinor: uint(), readBytesPerSecond: ioLimit, writeBytesPerSecond: ioLimit, readIops: ioLimit, writeIops: ioLimit });
const LANDLOCK_FILESYSTEM_RIGHTS = ["execute", "write-file", "read-file", "read-dir", "remove-dir", "remove-file", "make-char", "make-dir", "make-reg", "make-sock", "make-fifo", "make-block", "make-sym", "refer", "truncate", "ioctl-dev"] as const;
const LANDLOCK_NETWORK_RIGHTS = ["bind-tcp", "connect-tcp"] as const;
const LANDLOCK_SCOPE_RIGHTS = ["signal", "abstract-unix-socket"] as const;
const landlockPathRule = record({ kind: id(["path-beneath"]), path: text(undefined, ABSOLUTE_PATH), accessRights: array(id(LANDLOCK_FILESYSTEM_RIGHTS), 16, { sortedScalar: true }) });
const landlockPortRule = record({ kind: id(["tcp-port"]), port: uint(1n, 65535n), accessRights: array(id(LANDLOCK_NETWORK_RIGHTS), 2, { sortedScalar: true }) });
const LANDLOCK_V2_FILESYSTEM_RIGHTS = [...LANDLOCK_FILESYSTEM_RIGHTS, "resolve-unix"] as const;
const LANDLOCK_V2_NETWORK_RIGHTS = [...LANDLOCK_NETWORK_RIGHTS, "bind-udp", "connect-send-udp"] as const;
const LANDLOCK_V2_TCP_RIGHTS = ["bind-tcp", "connect-tcp"] as const;
const LANDLOCK_V2_UDP_RIGHTS = ["bind-udp", "connect-send-udp"] as const;
const landlockV2PathRule = record({ kind: id(["path-beneath"]), path: text(undefined, ABSOLUTE_PATH), accessRights: array(id(LANDLOCK_V2_FILESYSTEM_RIGHTS), 17, { sortedScalar: true }) });
const landlockV2TcpRule = record({ kind: id(["tcp-port"]), port: uint(1n, 65535n), accessRights: array(id(LANDLOCK_V2_TCP_RIGHTS), 2, { sortedScalar: true }) });
const landlockV2UdpRule = record({ kind: id(["udp-port"]), port: uint(0n, 65535n), accessRights: array(id(LANDLOCK_V2_UDP_RIGHTS), 2, { sortedScalar: true }) });
const seccompArgument = record({ index: uint(0n, 5n), operator: id(["eq", "ne", "lt", "le", "gt", "ge", "masked-eq"]), value: uint(), mask: nullable(uint()) });
const policySpecs = Object.freeze({
  "io-max": record({ schema: id(["keep.native-io-max"]), version: uint(1n, 1n), defaultPolicy: id(["deny-unlisted"]), rows: array(ioRow, 128, { sortBy: ["deviceMajor", "deviceMinor"], uniqueBy: ["deviceMajor", "deviceMinor"] }) }),
  landlock: record({ schema: id(["keep.native-landlock-policy"]), version: uint(1n, 1n), minimumAbi: uint(1n, 255n), handledFilesystemRights: array(id(LANDLOCK_FILESYSTEM_RIGHTS), 16, { sortedScalar: true }), handledNetworkRights: array(id(LANDLOCK_NETWORK_RIGHTS), 2, { sortedScalar: true }), handledScopeRights: array(id(LANDLOCK_SCOPE_RIGHTS), 2, { sortedScalar: true }), rules: array(tagged("kind", { "path-beneath": landlockPathRule, "tcp-port": landlockPortRule }), 256) }),
  "landlock-v2": record({ schema: id(["keep.native-landlock-policy"]), version: uint(2n, 2n), minimumAbi: uint(4n, 10n), effectiveAbi: uint(4n, 10n), reviewedMaximumAbi: uint(10n, 10n), handledFilesystemRights: array(id(LANDLOCK_V2_FILESYSTEM_RIGHTS), 17, { sortedScalar: true }), handledNetworkRights: array(id(LANDLOCK_V2_NETWORK_RIGHTS), 4, { sortedScalar: true }), handledScopeRights: array(id(LANDLOCK_SCOPE_RIGHTS), 2, { sortedScalar: true }), rules: array(tagged("kind", { "path-beneath": landlockV2PathRule, "tcp-port": landlockV2TcpRule, "udp-port": landlockV2UdpRule }), 256) }),
  seccomp: record({ schema: id(["keep.native-seccomp-policy"]), version: uint(1n, 1n), architecture: id(["x86_64", "aarch64"]), defaultAction: id(["kill-process"]), rules: array(record({ syscall: id(), action: id(["allow", "kill-process", "errno"]), errno: nullable(uint()), arguments: array(seccompArgument, 6, { sortBy: ["index"], uniqueBy: ["index"] }) }), 512, { sortBy: ["syscall"], uniqueBy: ["syscall"] }) }),
} as const);

const signature = record({ keyId: id(), algorithm: id(["ed25519"]), keyEpoch: uint(), signature: bytes(64) });
const rootSignature = record({ keyId: id(), algorithm: id(["ed25519"]), keyEpoch: uint(), authorizationRole: id(["root", "recovery"]), signature: bytes(64) });
const envelope = (payload: Spec, root = false): Spec => record({
  payload,
  payloadDigest: digest("PayloadDigest"),
  signatures: array(root ? oneOf(signature, rootSignature) : signature, 64, { min: 1, sortBy: ["keyId"], uniqueBy: ["keyId"] }),
});
const trustClass = id(["production", "development"]);
const keyRow = record({ keyId: id(), algorithm: id(["ed25519"]), publicKey: bytes(32), keyEpoch: uint(), validFromCounter: uint(), validUntilCounter: uint() });
const rootRoles = ["root", "release", "timestamp", "revocation", "recovery", "b3", "builder", "comparer"] as const;
const threshold = record(Object.fromEntries(rootRoles.map((role) => [role, uint(1n, 32n)])) as Record<string, Spec>);
const keyEpochRow = record({ role: id(rootRoles), minimumEpoch: uint() });
const fullB3State = record({ scopeKey, generation: uint(), rootEpoch: uint(), rootEnvelopeDigest: digest("RootEnvelope"), b3ProfileEnvelopeDigest: digest("B3ProfileEnvelope"), headSequence: uint(), headEnvelopeDigest: digest("RevocationEnvelope"), deploymentEpoch: uint(), artifactFloor: uint(), counter: uint(), quarantined: bool, quarantineDigest: digest("Quarantine"), consumedAuthorization: nullable(tagged("kind", {
  rollback: record({ kind: id(["rollback"]), authorizationEnvelopeDigest: digest("RollbackAuthorizationEnvelope") }),
  recovery: record({ kind: id(["recovery"]), authorizationEnvelopeDigest: digest("RevocationRecoveryEnvelope") }),
})) });
const proposedB3StateProjection = record({ scopeKey, rootEpoch: uint(), rootEnvelopeDigest: digest("RootEnvelope"), b3ProfileEnvelopeDigest: digest("B3ProfileEnvelope"), headSequence: uint(), headEnvelopeDigest: digest("RevocationEnvelope"), deploymentEpoch: uint(), artifactFloor: uint(), counter: uint(), quarantined: bool, quarantineDigest: digest("Quarantine") });
const artifactRow = record({ artifactId: id(), kind: id(["helper", "trampoline", "role", "prober", "provisioner", "policy", "evidence-schema"]), digest: digest("ArtifactFile"), size: uint(), mode: id(["0444", "0555"]), targetTriple: id(), variant: id(), releaseMember: bool });
const packageMember = record({ installRoot: id(["artifacts", "policy", "evidence-schema", "inventory", "toolchain"]), relativePath: text(undefined, NATIVE_P2_RELATIVE_PATH), digest: digest("PackageMember"), size: uint(), mode: id(["0444", "0555"]), ownerUid: uint(), ownerGid: uint(), objectType: id(["regular-executable", "regular-data"]) });
const toolchainEntry = record({ path: text(undefined, NATIVE_P2_RELATIVE_PATH), size: uint(), digest: digest("ToolchainEntry"), kind: id(["compiler", "rustlib", "linker", "sysroot", "vendor-source", "container-manifest", "build-tool"]) });
const uriDigestRow = record({ uri: text(undefined, URI), digestType: id(["ArtifactDigest", "SourceDigest", "OciBlobDigest", "SubjectDigest"]), digest: digest("Material") });
const sbomPackage = record({ purl: text(), name: id(), version: text(), license: text(), sourceDigest: digest("Source"), checksumAlgorithm: id(["sha256"]), checksum: digest("SbomChecksum") });
const disagreement = record({ path: text(undefined, NATIVE_P2_RELATIVE_PATH), leftBuilderId: id(), rightBuilderId: id(), leftDigest: digest("ComparedArtifact"), rightDigest: digest("ComparedArtifact"), reasonCode: id() });

const authoritySpecs = Object.freeze({
  "genesis-epoch": record({ schema: id(["keep.native-genesis-epoch"]), version: uint(1n, 1n), trustClass, rootId: id(), rootKeys: array(keyRow, 32, { min: 1, sortBy: ["keyId"], uniqueBy: ["keyId"] }), rootThreshold: uint(1n, 32n), participantIds: array(id(), 64, { min: 1, sortedScalar: true }), minimumParticipants: uint(1n, 64n), requiredOffline: bool, requiredWitnesses: uint(), issuedCounter: uint(), nonce: bytes(32) }),
  root: envelope(record({ schema: id(["keep.native-root"]), version: uint(1n, 1n), trustClass, rootId: id(), rootEpoch: uint(), genesisEpochDigest: digest("GenesisEpoch"), predecessorRootEnvelopeDigest: nullable(digest("RootEnvelope")), issuedCounter: uint(), threshold, rootKeys: array(keyRow, 32, { min: 1, sortBy: ["keyId"], uniqueBy: ["keyId"] }), releaseKeys: array(keyRow, 32, { min: 1, sortBy: ["keyId"], uniqueBy: ["keyId"] }), timestampKeys: array(keyRow, 32, { min: 1, sortBy: ["keyId"], uniqueBy: ["keyId"] }), revocationKeys: array(keyRow, 32, { min: 1, sortBy: ["keyId"], uniqueBy: ["keyId"] }), recoveryKeys: array(keyRow, 32, { min: 1, sortBy: ["keyId"], uniqueBy: ["keyId"] }), b3Keys: array(keyRow, 32, { min: 1, sortBy: ["keyId"], uniqueBy: ["keyId"] }), builderKeys: array(keyRow, 32, { min: 1, sortBy: ["keyId"], uniqueBy: ["keyId"] }), comparerKeys: array(keyRow, 32, { min: 1, sortBy: ["keyId"], uniqueBy: ["keyId"] }), keyEpochs: array(keyEpochRow, 8, { min: 8, sortBy: ["role"], uniqueBy: ["role"] }) }), true),
  ceremony: envelope(record({ schema: id(["keep.native-root-ceremony"]), version: uint(1n, 1n), trustClass, ceremonyId: id(), rootEnvelopeDigest: digest("RootEnvelope"), genesisCarrierDigest: digest("GenesisCarrier"), participantKeyIds: array(id(), 64, { min: 1, sortedScalar: true }), requestDigest: digest("CeremonyRequest"), transcriptDigest: digest("Transcript"), issuedCounter: uint() })),
  timestamp: envelope(record({ schema: id(["keep.native-timestamp"]), version: uint(1n, 1n), trustClass, nativeClosureBaseDigest: digest("ReleaseClosureBase"), artifactVersion: uint(), deploymentEpoch: uint(), releaseKeyEpoch: uint(), timestampKeyEpoch: uint(), issuedCounter: uint(), expiresCounter: uint(), revocationCheckpointEnvelopeDigest: digest("RevocationEnvelope"), revocationSequence: uint() })),
  rollback: envelope(record({ schema: id(["keep.native-rollback"]), version: uint(1n, 1n), trustClass, authorizationId: id(), fromDeploymentEnvelopeDigest: digest("DeploymentEnvelope"), fromDeploymentEpoch: uint(), fromArtifactVersion: uint(), toDeploymentBaseDigest: digest("DeploymentBase"), toDeploymentEpoch: uint(), toArtifactVersion: uint(), minimumArtifactVersion: uint(), predecessorDigest: digest("RollbackAuthorizationEnvelope"), issuedCounter: uint(), expiresCounter: uint(), nonce: bytes(32) })),
  recovery: envelope(record({ schema: id(["keep.native-revocation-recovery"]), version: uint(1n, 1n), trustClass, recoveryId: id(), authorityId: id(), namespace: id(), scope: id(), expectedB3State: fullB3State, proposedB3StateProjection, quarantinedHeadEnvelopeDigests: array(digest("RevocationEnvelope"), 4096, { min: 1, sortedScalar: true }), selectedHeadEnvelopeDigest: digest("RevocationEnvelope"), selectedSequence: uint(), issuedCounter: uint(), expiresCounter: uint(), reasonCode: id(), transcriptDigest: digest("Transcript") })),
  "b3-genesis-base": record({ schema: id(["keep.native-b3-genesis-base"]), version: uint(1n, 1n), trustClass, authorityId: id(), namespace: id(), scope: id(), headSequence: uint(), headEnvelopeDigest: digest("RevocationEnvelope"), deploymentEpoch: uint(), artifactFloor: uint(), counter: uint() }),
  "b3-state": fullB3State,
  "b3-profile": envelope(record({ schema: id(["keep.native-b3-profile"]), version: uint(1n, 1n), trustClass, authorityId: id(), b0RootEnvelopeDigest: digest("RootEnvelope"), genesisBaseDigest: digest("GenesisBase"), predecessorProfileEnvelopeDigest: nullable(digest("B3ProfileEnvelope")), algorithm: id(["ed25519"]), keyId: id(), keyEpoch: uint(), publicKey: bytes(32), validFromCounter: uint(), validUntilCounter: uint(), transportIdentityDigest: digest("TransportIdentity"), maxHeartbeatIntervalMs: uint(1n, 1000n) })),
  "b3-receipt": envelope(record({ schema: id(["keep.native-b3-receipt"]), version: uint(1n, 1n), operationKind: id(["genesis", "read", "compare-and-advance", "validate-lease", "subscribe-invalidation"]), authorityId: id(), b3ProfileEnvelopeDigest: digest("B3ProfileEnvelope"), scopeKey, priorStateDigest: digest("B3State"), newStateDigest: digest("B3State"), operationDigest: digest("B3Operation"), requestNonce: bytes(32), generation: uint(), counter: uint(), committed: bool, keyId: id(), keyEpoch: uint() })),
  "b3-invalidation": envelope(record({ schema: id(["keep.native-b3-invalidation"]), version: uint(1n, 1n), authorityId: id(), b3ProfileEnvelopeDigest: digest("B3ProfileEnvelope"), scopeKey, sessionId: id(), frameKind: id(["heartbeat", "invalidated"]), sequence: uint(1n), priorGeneration: uint(), newGeneration: uint(), newStateDigest: digest("B3State"), counter: uint(), requestNonce: bytes(32), priorAckDigest: nullable(digest("B3InvalidationAck")) })),
  "b3-invalidation-ack": record({ schema: id(["keep.native-b3-invalidation-ack"]), version: uint(1n, 1n), sessionId: id(), sequence: uint(1n), frameEnvelopeDigest: digest("B3InvalidationFrameEnvelope"), requestNonce: bytes(32) }),
  "build-identity": envelope(record({ schema: id(["keep.native-build-identity"]), version: uint(1n, 1n), trustClass, identityKind: id(["builder", "comparer"]), identityId: id(), administrativeDomain: id(), toolchainLineageDigest: digest("ToolchainLineage"), keyId: id(), keyEpoch: uint(), publicKey: bytes(32), validFromCounter: uint(), validUntilCounter: uint() })),
  "artifact-inventory": record({ schema: id(["keep.native-artifact-inventory"]), version: uint(1n, 1n), buildId: id(), targetTriple: id(), variant: id(), rows: array(artifactRow, 256, { sortBy: ["artifactId"], uniqueBy: ["artifactId"] }) }),
  "package-payload": record({ schema: id(["keep.native-package-payload"]), version: uint(1n, 1n), buildId: id(), targetTriple: id(), variant: id(), nativeArtifactInventoryDigest: digest("NativeArtifactInventory"), members: array(packageMember, 4096, { sortBy: ["installRoot", "relativePath"], uniqueBy: ["installRoot", "relativePath"] }) }),
  toolchain: envelope(record({ schema: id(["keep.native-toolchain"]), version: uint(1n, 1n), toolchainId: id(), targetTriple: id(), variant: id(), compilerDigest: digest("Compiler"), sysrootDigest: digest("Sysroot"), linkerDigest: digest("Linker"), vendorDigest: digest("Vendor"), containerDigest: digest("Container"), environmentPolicyDigest: digest("EnvironmentPolicy"), entries: array(toolchainEntry, 8192, { sortBy: ["path"], uniqueBy: ["path"] }) })),
  sbom: envelope(record({ schema: id(["keep.native-sbom"]), version: uint(1n, 1n), buildId: id(), targetTriple: id(), variant: id(), nativeArtifactInventoryDigest: digest("NativeArtifactInventory"), packages: array(sbomPackage, 4096, { sortBy: ["purl"], uniqueBy: ["purl"] }) })),
  provenance: envelope(record({ schema: id(["keep.native-provenance"]), version: uint(1n, 1n), builderId: id(), builderIdentityEnvelopeDigest: digest("BuilderIdentityEnvelope"), buildType: id(), buildId: id(), targetTriple: id(), variant: id(), nativeArtifactInventoryDigest: digest("NativeArtifactInventory"), nativePackagePayloadDigest: digest("NativePackagePayload"), toolchainClosureEnvelopeDigest: digest("ToolchainClosureEnvelope"), invocationDigest: digest("Invocation"), materials: array(uriDigestRow, 8192, { sortBy: ["uri"], uniqueBy: ["uri"] }), subjects: array(uriDigestRow, 4096, { sortBy: ["uri"], uniqueBy: ["uri"] }), startedCounter: uint(), finishedCounter: uint() })),
  reproducibility: envelope(record({ schema: id(["keep.native-repro"]), version: uint(1n, 1n), comparerIdentityEnvelopeDigest: digest("ComparerIdentityEnvelope"), buildId: id(), targetTriple: id(), variant: id(), nativeArtifactInventoryDigest: digest("NativeArtifactInventory"), nativePackagePayloadDigest: digest("NativePackagePayload"), toolchainClosureEnvelopeDigest: digest("ToolchainClosureEnvelope"), builderProvenanceEnvelopeDigests: array(digest("ProvenanceEnvelope"), 8, { min: 2, sortedScalar: true }), comparisonAlgorithm: id(["sha256-byte-for-byte/v1"]), comparisonDigest: digest("Comparison"), disagreements: array(disagreement, 1024, { sortBy: ["path", "leftBuilderId", "rightBuilderId"], uniqueBy: ["path", "leftBuilderId", "rightBuilderId"] }) })),
  "root-locator": record({ schema: id(["keep.native-root-locator"]), version: uint(1n, 1n), rootEpoch: uint(), rootEnvelopeDigest: digest("RootEnvelope") }),
  "revocation-locator": record({ schema: id(["keep.native-revocation-locator"]), version: uint(1n, 1n), sequence: uint(), revocationEnvelopeDigest: digest("RevocationEnvelope") }),
} as const);

export type P2S1SchemaName = keyof typeof P2_OPERATION_SPECS | keyof typeof auxiliarySpecs | keyof typeof policySpecs | keyof typeof authoritySpecs;
const P2_S1_SPECS: Readonly<Record<P2S1SchemaName, Spec>> = Object.freeze({ ...P2_OPERATION_SPECS, ...auxiliarySpecs, ...policySpecs, ...authoritySpecs });
export const P2_S1_RUST_SCHEMA_NAMES: Readonly<Record<P2S1SchemaName, string>> = Object.freeze({
  "b3-genesis-operation": "B3GenesisOperationV1", "b3-read-operation": "B3ReadOperationV1", "b3-cas-operation": "B3CasOperationV1", "b3-lease-operation": "B3LeaseOperationV1", "b3-subscribe-operation": "B3SubscribeOperationV1",
  "observation-result": "NativeObservationResultV1", "control-policy": "NativeControlPolicyV1", "journal-entries": "NativeJournalEntriesV1", "peer-policy": "NativePeerPolicyV1", "build-command": "NativeBuildCommandV1",
  transcript: "NativeTranscriptV1", control: "NativeControlV1", journal: "NativeJournalV1", "fd-flags": "NativeFdFlagsV1", "transport-identity": "NativeTransportIdentityV1", invocation: "NativeInvocationV1", "environment-policy": "NativeEnvironmentPolicyV1", comparison: "NativeComparisonV1",
  "io-max": "NativeIoMaxV1", landlock: "NativeLandlockPolicyV1", "landlock-v2": "NativeLandlockPolicyV2", seccomp: "NativeSeccompPolicyV1",
  "genesis-epoch": "NativeGenesisEpochV1", root: "NativeRootV1", ceremony: "NativeRootCeremonyRecordV1", timestamp: "NativeTimestampV1", rollback: "NativeRollbackAuthorizationV1", recovery: "NativeRevocationRecoveryV1",
  "b3-genesis-base": "NativeB3GenesisBaseV1", "b3-state": "B3StateV1", "b3-profile": "NativeB3ProfileV1", "b3-receipt": "B3ReceiptV1", "b3-invalidation": "B3InvalidationFrameV1", "b3-invalidation-ack": "B3InvalidationAckV1", "build-identity": "NativeBuildIdentityV1",
  "artifact-inventory": "NativeArtifactInventoryV1", "package-payload": "NativePackagePayloadV1", toolchain: "NativeToolchainClosureV1", sbom: "NativeSbomV1", provenance: "NativeProvenanceV1", reproducibility: "NativeReproducibilityRecordV1", "root-locator": "NativeRootLocatorV1", "revocation-locator": "NativeRevocationLocatorV1",
});

export interface P2S1SchemaInventoryEntry {
  readonly name: string;
  readonly shape: "Unsigned" | "Envelope" | "RootEnvelope";
  readonly fields: readonly string[];
}
export const P2_S1_SCHEMA_INVENTORY: readonly P2S1SchemaInventoryEntry[] = Object.freeze(
  Object.entries(P2_S1_SPECS).map(([schema, spec]) => {
    if (spec.type !== "record") throw new NativeAuthoritySchemaError("top-level schema is not a record");
    const envelopeShape = Object.hasOwn(spec.fields, "payload");
    return Object.freeze({
      name: P2_S1_RUST_SCHEMA_NAMES[schema as P2S1SchemaName],
      shape: envelopeShape ? (schema === "root" ? "RootEnvelope" : "Envelope") : "Unsigned",
      fields: Object.freeze(Object.keys(envelopeShape ? (spec.fields.payload as Extract<Spec, { type: "record" }>).fields : spec.fields)),
    });
  }).sort((left, right) => left.name.localeCompare(right.name)),
);

function describeSpec(spec: Spec): CanonicalValue {
  switch (spec.type) {
    case "identifier": return { kind: "identifier", enum: spec.enum === undefined ? null : [...spec.enum] };
    case "text": return { kind: "text", enum: spec.enum === undefined ? null : [...spec.enum], pattern: spec.pattern?.source ?? null };
    case "uint": return { kind: "uint", min: spec.min ?? 0n, max: spec.max ?? ((1n << 64n) - 1n) };
    case "bool": return { kind: "bool" };
    case "digest": return { kind: "digest", semantic: spec.semantic };
    case "bytes": return { kind: "bytes", exact: spec.exact === undefined ? null : BigInt(spec.exact), max: spec.max === undefined ? null : BigInt(spec.max) };
    case "nullable": return { kind: "nullable", inner: describeSpec(spec.inner) };
    case "oneOf": return { kind: "one-of", variants: spec.variants.map(describeSpec) };
    case "record": return { kind: "record", fields: Object.entries(spec.fields).map(([name, child]) => ({ name, spec: describeSpec(child) })) };
    case "array": return { kind: "array", item: describeSpec(spec.item), min: BigInt(spec.min), max: BigInt(spec.max), sortedScalar: spec.sortedScalar ?? false, sortBy: spec.sortBy === undefined ? [] : [...spec.sortBy], uniqueBy: spec.uniqueBy === undefined ? [] : [...spec.uniqueBy] };
    case "tagged": return { kind: "tagged", tag: spec.tag, variants: Object.entries(spec.variants).map(([name, child]) => ({ name, spec: describeSpec(child) })) };
  }
}

export const P2_S1_RECURSIVE_SCHEMA_METADATA: Uint8Array = encodeCanonical(
  Object.entries(P2_S1_SPECS).map(([schema, spec]) => ({
    name: P2_S1_RUST_SCHEMA_NAMES[schema as P2S1SchemaName],
    spec: describeSpec(spec),
  })).sort((left, right) => left.name.localeCompare(right.name)),
);

export interface CapturedP2S1Document {
  readonly schema: P2S1SchemaName | NativeV2Schema;
  readonly canonicalBytes: Uint8Array;
}

export interface P2S1DigestRegistryEntry {
  readonly path: string;
  readonly semanticType: string;
  readonly rank: number;
  readonly dependsOn: readonly string[];
}

function digestLeaves(spec: Spec, path: string, output: P2S1DigestRegistryEntry[]): void {
  if (spec.type === "digest") {
    output.push({ path, semanticType: spec.semantic, rank: 0, dependsOn: [] });
    return;
  }
  if (spec.type === "nullable") return digestLeaves(spec.inner, path, output);
  if (spec.type === "oneOf") {
    spec.variants.forEach((variant) => digestLeaves(variant, path, output));
    return;
  }
  if (spec.type === "record") {
    for (const [field, child] of Object.entries(spec.fields)) digestLeaves(child, `${path}.${field}`, output);
    return;
  }
  if (spec.type === "array") return digestLeaves(spec.item, spec.item.type === "digest" ? path : `${path}[]`, output);
  if (spec.type === "tagged")
    for (const child of Object.values(spec.variants)) digestLeaves(child, path, output);
}

const p2S1Registry: P2S1DigestRegistryEntry[] = [];
const asciiCompare = (left: string, right: string): number => left < right ? -1 : left > right ? 1 : 0;
const semanticRank = (semantic: string, path: string): number => {
  if (path.endsWith("scopeKey.genesisRootDigest")) return 2;
  if (semantic === "ConsumedAuthorizationEnvelopeDigest") return 4;
  if (semantic === "CallerAuthorizationEnvelopeDigest") return 2;
  if (path.startsWith("NativeRevocationRecoveryV1.") &&
    (path.endsWith("rootEnvelopeDigest") || path.endsWith("b3ProfileEnvelopeDigest"))) return 2;
  if (path.startsWith("NativeRevocationRecoveryV1.") &&
    (path.endsWith("headEnvelopeDigest") || path.endsWith("quarantineDigest"))) return 1;
  if (semantic === "DeploymentBaseDigest") return 3;
  if (semantic === "DeploymentEnvelopeDigest") return 5;
  if (semantic === "ReleaseClosureBaseDigest") return 6;
  if (semantic === "ReleaseClosureEnvelopeDigest") return 8;
  if (semantic === "ReleaseIndexEnvelopeDigest") return 9;
  if (path === "NativeReproducibilityRecordV1.toolchainClosureEnvelopeDigest") return 3;
  if (["NativePackagePayloadDigest", "ToolchainClosureEnvelopeDigest", "ProvenanceEnvelopeDigest"].includes(semantic)) return 2;
  if (semantic === "NativeArtifactInventoryDigest") return 1;
  return 0;
};
for (const [schema, spec] of Object.entries(P2_S1_SPECS)) {
  const name = P2_S1_RUST_SCHEMA_NAMES[schema as P2S1SchemaName];
  const inputs: P2S1DigestRegistryEntry[] = [];
  const isEnvelope = spec.type === "record" && Object.hasOwn(spec.fields, "payload");
  digestLeaves(isEnvelope ? (spec.fields.payload as Spec) : spec, name, inputs);
  const uniqueInputs = [...new Map(inputs.map((entry) => {
    const normalized = entry.path.endsWith("authorizationEnvelopeDigest")
      ? { ...entry, semanticType: entry.path.includes("B3State") || entry.path.includes("proposedB3State") || entry.path.includes("expectedB3State")
        ? "ConsumedAuthorizationEnvelopeDigest" : "CallerAuthorizationEnvelopeDigest" }
      : entry.path === "NativeProvenanceV1.subjects[].digest"
        ? { ...entry, semanticType: "SubjectDigest" }
        : entry;
    return [entry.path, { ...normalized, rank: semanticRank(normalized.semanticType, normalized.path) }];
  })).values()];
  const nextRank = Math.max(0, ...uniqueInputs.map((entry) => entry.rank)) + 1;
  p2S1Registry.push(...uniqueInputs);
  if (isEnvelope) {
    const payloadPath = `${name}.$payloadDigest`;
    p2S1Registry.push({ path: payloadPath, semanticType: `${name}PayloadDigest`, rank: nextRank, dependsOn: uniqueInputs.map((entry) => entry.path) },
      { path: `${name}.$envelopeDigest`, semanticType: `${name}EnvelopeDigest`, rank: nextRank + 1, dependsOn: [payloadPath] });
    continue;
  }
  p2S1Registry.push({
    path: `${name}.$contentDigest`,
    semanticType: `${name}ContentDigest`,
    rank: nextRank,
    dependsOn: uniqueInputs.map((entry) => entry.path),
  });
}
const crossSchemaEdges = [
  ["NativeProvenanceV1.toolchainClosureEnvelopeDigest", "NativeToolchainClosureV1.$envelopeDigest", 3],
  ["NativeProvenanceV1.invocationDigest", "NativeInvocationV1.$contentDigest", 2],
  ["NativeProvenanceV1.nativePackagePayloadDigest", "NativePackagePayloadV1.nativeArtifactInventoryDigest", 2],
  ["NativeReproducibilityRecordV1.builderProvenanceEnvelopeDigests", "NativeProvenanceV1.$envelopeDigest", 6],
  ["NativeReproducibilityRecordV1.comparisonDigest", "NativeComparisonV1.$contentDigest", 2],
  ["NativeReproducibilityRecordV1.nativePackagePayloadDigest", "NativePackagePayloadV1.nativeArtifactInventoryDigest", 2],
] as const;
for (const [consumer, producer, rank] of crossSchemaEdges) {
  const index = p2S1Registry.findIndex((entry) => entry.path === consumer);
  if (index < 0) throw new NativeAuthoritySchemaError("cross-schema digest consumer is absent");
  p2S1Registry[index] = { ...p2S1Registry[index]!, rank, dependsOn: [producer] };
}
for (const [schema, payloadRank, envelopeRank] of [["NativeProvenanceV1", 4, 5], ["NativeReproducibilityRecordV1", 7, 8]] as const) {
  const payloadIndex = p2S1Registry.findIndex((entry) => entry.path === `${schema}.$payloadDigest`);
  const envelopeIndex = p2S1Registry.findIndex((entry) => entry.path === `${schema}.$envelopeDigest`);
  p2S1Registry[payloadIndex] = { ...p2S1Registry[payloadIndex]!, rank: payloadRank };
  p2S1Registry[envelopeIndex] = { ...p2S1Registry[envelopeIndex]!, rank: envelopeRank };
}
export const P2_S1_DIGEST_REGISTRY: readonly P2S1DigestRegistryEntry[] = Object.freeze(
  p2S1Registry.sort((left, right) => asciiCompare(left.path, right.path)).map((entry) => Object.freeze({
    ...entry,
    dependsOn: Object.freeze([...entry.dependsOn]),
  })),
);

export function validateP2S1DigestRegistry(entries: readonly P2S1DigestRegistryEntry[]): void {
  const byPath = new Map(entries.map((entry) => [entry.path, entry]));
  if (byPath.size !== entries.length) throw new NativeAuthoritySchemaError("digest registry path is duplicated");
  if (entries.length !== P2_S1_DIGEST_REGISTRY.length ||
    P2_S1_DIGEST_REGISTRY.some((expected) => !byPath.has(expected.path)))
    throw new NativeAuthoritySchemaError("digest registry coverage is incomplete");
  for (const entry of entries) {
    if (!entry.path || !entry.semanticType || !Number.isInteger(entry.rank) || entry.rank < 0)
      throw new NativeAuthoritySchemaError("digest registry row is malformed");
    for (const dependency of entry.dependsOn) {
      const ancestor = byPath.get(dependency);
      if (!ancestor) throw new NativeAuthoritySchemaError("digest registry dependency is unknown");
      if (ancestor.rank >= entry.rank) throw new NativeAuthoritySchemaError("digest registry edge is reverse or cyclic");
    }
    const expected = P2_S1_DIGEST_REGISTRY.find((candidate) => candidate.path === entry.path)!;
    if (entry.semanticType !== expected.semanticType || entry.rank !== expected.rank ||
      [...entry.dependsOn].sort().join("\0") !== [...expected.dependsOn].sort().join("\0"))
      throw new NativeAuthoritySchemaError("digest registry row differs from frozen metadata");
  }
  for (const schema of Object.keys(P2_OPERATION_SPECS)) {
    const name = P2_S1_RUST_SCHEMA_NAMES[schema as P2S1SchemaName];
    const derived = byPath.get(`${name}.$contentDigest`);
    const exactInputs = entries
      .filter((entry) => entry.path.startsWith(`${name}.`) && !entry.path.includes(".$"))
      .map((entry) => entry.path)
      .sort();
    if (!derived || [...derived.dependsOn].sort().join("\0") !== exactInputs.join("\0"))
      throw new NativeAuthoritySchemaError("operation digest registry closure is incomplete");
  }
}
validateP2S1DigestRegistry(P2_S1_DIGEST_REGISTRY);

export const P2_S1_COMBINED_DIGEST_REGISTRY: readonly P2S1DigestRegistryEntry[] = Object.freeze([
  ...NATIVE_V2_DIGEST_REGISTRY.map((entry) => Object.freeze({
    path: entry.path,
    semanticType: entry.semanticType,
    rank: entry.rank,
    dependsOn: Object.freeze([...entry.dependsOn]),
  })),
  ...P2_S1_DIGEST_REGISTRY,
].sort((left, right) => asciiCompare(left.path, right.path)));

export function validateP2S1CombinedDigestRegistry(entries: readonly P2S1DigestRegistryEntry[]): void {
  const expected = new Map(P2_S1_COMBINED_DIGEST_REGISTRY.map((entry) => [entry.path, entry]));
  const actual = new Map(entries.map((entry) => [entry.path, entry]));
  if (actual.size !== entries.length || actual.size !== expected.size || [...expected.keys()].some((path) => !actual.has(path)))
    throw new NativeAuthoritySchemaError("combined digest registry coverage is incomplete or duplicated");
  for (const entry of entries) {
    const frozen = expected.get(entry.path)!;
    if (entry.rank !== frozen.rank || entry.semanticType !== frozen.semanticType ||
      [...entry.dependsOn].sort().join("\0") !== [...frozen.dependsOn].sort().join("\0"))
      throw new NativeAuthoritySchemaError("combined digest registry row differs from frozen metadata");
    for (const dependency of entry.dependsOn) {
      const producer = actual.get(dependency);
      if (!producer || producer.rank >= entry.rank)
        throw new NativeAuthoritySchemaError("combined digest registry has a missing or reverse edge");
    }
  }
}
validateP2S1CombinedDigestRegistry(P2_S1_COMBINED_DIGEST_REGISTRY);

export function captureP2S1Authority(
  bytesInput: unknown,
  schema: P2S1SchemaName | NativeV2Schema,
  admittedTrust: NativeV2TrustClass = "development",
): CapturedP2S1Document {
  if (typeof schema === "string" && Object.hasOwn(P2_S1_SPECS, schema))
    return captureP2S1Canonical(bytesInput, schema as P2S1SchemaName);
  if (!["deployment", "native-closure", "native-index", "revocation", "evidence"].includes(String(schema)))
    throw new NativeAuthoritySchemaError("schema is not frozen");
  const value = boundedCanonical(bytesInput, schema === "evidence" ? P2_S1_LIMITS.evidenceBytes : P2_S1_LIMITS.envelopeBytes);
  captureNativeV2Schema(value, schema as NativeV2Schema, admittedTrust);
  const canonicalBytes = encodeCanonical(value);
  return Object.freeze({ schema, canonicalBytes });
}

export function captureP2S1Canonical(bytesInput: unknown, schema: P2S1SchemaName): CapturedP2S1Document {
  if (typeof schema !== "string" || !Object.hasOwn(P2_S1_SPECS, schema))
    throw new NativeAuthoritySchemaError("schema is not frozen");
  const value = boundedCanonical(bytesInput, P2_S1_LIMITS.envelopeBytes);
  validate(value, P2_S1_SPECS[schema], schema);
  validateSemantics(value, schema);
  const canonicalBytes = encodeCanonical(value);
  return Object.freeze({ schema, canonicalBytes: Uint8Array.from(canonicalBytes) });
}

function validateSemantics(value: CanonicalValue, schema: P2S1SchemaName): void {
  const row = asRecord(value, schema);
  if (Object.hasOwn(row, "payload")) {
    const payload = asRecord(row.payload!, `${schema}.payload`);
    const computed = createHash("sha256").update(encodeCanonical(payload)).digest("hex");
    if (row.payloadDigest !== computed) throw new NativeAuthoritySchemaError("envelope payload digest mismatch");
    if (Object.hasOwn(payload, "trustClass")) {
      const development = payload.trustClass === "development";
      for (const signature of row.signatures as CanonicalValue[]) {
        const keyId = String(asRecord(signature, `${schema} signature`).keyId);
        if (development !== keyId.startsWith("development."))
          throw new NativeAuthoritySchemaError("signature key namespace does not match trust class");
      }
    }
    if (schema === "root") {
      const successor = payload.predecessorRootEnvelopeDigest !== null;
      for (const entry of row.signatures as CanonicalValue[]) {
        const keys = Object.keys(asRecord(entry, "root signature")).sort().join("\0");
        const expected = (successor
          ? ["algorithm", "authorizationRole", "keyEpoch", "keyId", "signature"]
          : ["algorithm", "keyEpoch", "keyId", "signature"]).sort().join("\0");
        if (keys !== expected) throw new NativeAuthoritySchemaError("root signature mode mismatch");
      }
      const allKeyIds = new Set<string>();
      if (payload.trustClass !== "production") throw new NativeAuthoritySchemaError("production root trust class required");
      if (((payload.rootEpoch as bigint) === 0n) !== (payload.predecessorRootEnvelopeDigest === null))
        throw new NativeAuthoritySchemaError("root epoch/predecessor equation failed");
      const thresholds = asRecord(payload.threshold!, "root thresholds");
      for (const role of rootRoles) {
        const keyField = `${role}Keys`;
        const keysForRole = payload[keyField] as CanonicalValue[];
        if ((thresholds[role] as bigint) > BigInt(keysForRole.length))
          throw new NativeAuthoritySchemaError("root threshold exceeds eligible keys");
        for (const value of keysForRole) {
          const key = asRecord(value, `${keyField} key`);
          if ((key.validUntilCounter as bigint) < (key.validFromCounter as bigint))
            throw new NativeAuthoritySchemaError("root key validity interval is empty");
          if (String(key.keyId).startsWith("development."))
            throw new NativeAuthoritySchemaError("development root key refused");
          if (allKeyIds.has(String(key.keyId))) throw new NativeAuthoritySchemaError("root key ID is reused across roles");
          allKeyIds.add(String(key.keyId));
        }
      }
    }
  }
  if (schema === "b3-cas-operation") {
    const purpose = asRecord(row.callerPurpose!, "callerPurpose");
    const auth = asRecord(purpose.authorization!, "authorization");
    const expected: Record<string, string> = { "root-update": "root-update", "revocation-advance": "revocation", rollback: "rollback", recovery: "recovery", "deployment-advance": "deployment" };
    if (auth.kind !== expected[String(purpose.purpose)]) throw new NativeAuthoritySchemaError("caller purpose/authorization mismatch");
  }
  if (schema === "peer-policy" && row.requiredUid === null && row.requiredGid === null && row.requiredSecurityLabel === null)
    throw new NativeAuthoritySchemaError("peer policy has no constraint");
  if (schema === "fd-flags" && row.closeOnExec !== (row.flags as CanonicalValue[]).includes("O_CLOEXEC"))
    throw new NativeAuthoritySchemaError("FD CLOEXEC state mismatch");
  if (schema === "io-max") for (const entry of row.rows as CanonicalValue[]) {
    const io = asRecord(entry, "io row");
    if ([io.readBytesPerSecond, io.writeBytesPerSecond, io.readIops, io.writeIops].every((item) => item === null))
      throw new NativeAuthoritySchemaError("I/O row has no limit");
  }
  if (schema === "journal-entries") {
    const entries = row.entries as CanonicalValue[];
    for (let index = 1; index < entries.length; index++) {
      const prior = asRecord(entries[index - 1]!, "prior journal entry").sequence as bigint;
      const current = asRecord(entries[index]!, "journal entry").sequence as bigint;
      if (current !== prior + 1n) throw new NativeAuthoritySchemaError("journal sequence is not consecutive");
    }
  }
  if (schema === "comparison" && row.leftSubjectDigest === row.rightSubjectDigest)
    throw new NativeAuthoritySchemaError("comparison subjects are identical");
  if (schema === "landlock" || schema === "landlock-v2") {
    const filesystem = new Set(row.handledFilesystemRights as string[]);
    const network = new Set(row.handledNetworkRights as string[]);
    if (schema === "landlock-v2") {
      const abi = Number(row.effectiveAbi);
      if (BigInt(abi) < (row.minimumAbi as bigint)) throw new NativeAuthoritySchemaError("Landlock effective ABI is below minimum");
      const fullFs = ["execute", "ioctl-dev", "make-block", "make-char", "make-dir", "make-fifo", "make-reg", "make-sock", "make-sym", "read-dir", "read-file", "refer", "remove-dir", "remove-file", "resolve-unix", "truncate", "write-file"];
      const expectedFs = fullFs.filter((right) => right !== "resolve-unix" && (right !== "ioctl-dev" || abi >= 5) || (right === "resolve-unix" && abi >= 9));
      const expectedNet = abi >= 10 ? ["bind-tcp", "bind-udp", "connect-send-udp", "connect-tcp"] : ["bind-tcp", "connect-tcp"];
      const expectedScope = abi >= 6 ? ["abstract-unix-socket", "signal"] : [];
      if (JSON.stringify([...filesystem]) !== JSON.stringify(expectedFs) || JSON.stringify([...network]) !== JSON.stringify(expectedNet) || JSON.stringify(row.handledScopeRights) !== JSON.stringify(expectedScope))
        throw new NativeAuthoritySchemaError("Landlock handled rights do not exactly match effective ABI");
    }
    let previous = "";
    for (const entry of row.rules as CanonicalValue[]) {
      const rule = asRecord(entry, "landlock rule");
      const key = rule.kind === "path-beneath"
        ? `path-beneath\0${String(rule.path)}`
        : `${String(rule.kind)}\0${String(rule.port).padStart(5, "0")}`;
      if (previous !== "" && !(previous < key)) throw new NativeAuthoritySchemaError("landlock rules are not sorted unique");
      previous = key;
      const handled = rule.kind === "path-beneath" ? filesystem : network;
      if ((rule.accessRights as string[]).some((right) => !handled.has(right)))
        throw new NativeAuthoritySchemaError("landlock rule uses an unhandled right");
    }
  }
  if (schema === "seccomp") for (const entry of row.rules as CanonicalValue[]) {
    const rule = asRecord(entry, "seccomp rule");
    if ((rule.action === "errno") !== (rule.errno !== null)) throw new NativeAuthoritySchemaError("seccomp errno/action mismatch");
    for (const argument of rule.arguments as CanonicalValue[]) {
      const arg = asRecord(argument, "seccomp argument");
      if ((arg.operator === "masked-eq") !== (arg.mask !== null)) throw new NativeAuthoritySchemaError("seccomp mask/operator mismatch");
    }
  }
  if (schema === "timestamp" || schema === "rollback" || schema === "recovery") {
    const payload = asRecord(row.payload!, `${schema}.payload`);
    if ((payload.expiresCounter as bigint) <= (payload.issuedCounter as bigint))
      throw new NativeAuthoritySchemaError("authority validity interval is empty");
  }
  if (schema === "genesis-epoch") {
    if (row.trustClass !== "production" || (row.rootKeys as CanonicalValue[]).some((entry) => String(asRecord(entry, "genesis key").keyId).startsWith("development.")))
      throw new NativeAuthoritySchemaError("production genesis trust/key namespace required");
    if ((row.rootThreshold as bigint) > BigInt((row.rootKeys as CanonicalValue[]).length) ||
      (row.minimumParticipants as bigint) > BigInt((row.participantIds as CanonicalValue[]).length) ||
      (row.requiredWitnesses as bigint) > BigInt((row.participantIds as CanonicalValue[]).length))
      throw new NativeAuthoritySchemaError("genesis threshold exceeds participants or keys");
  }
  if (schema === "b3-profile") {
    const payload = asRecord(row.payload!, "b3 profile payload");
    if ((payload.validUntilCounter as bigint) < (payload.validFromCounter as bigint))
      throw new NativeAuthoritySchemaError("B3 profile validity interval is empty");
  }
  if (schema === "rollback") {
    const payload = asRecord(row.payload!, "rollback payload");
    if ((payload.toDeploymentEpoch as bigint) <= (payload.fromDeploymentEpoch as bigint) ||
      (payload.toArtifactVersion as bigint) < (payload.minimumArtifactVersion as bigint))
      throw new NativeAuthoritySchemaError("rollback epoch or artifact floor equation failed");
  }
  if (schema === "recovery") {
    const payload = asRecord(row.payload!, "recovery payload");
    const expected = asRecord(payload.expectedB3State!, "expected B3 state");
    if ((payload.selectedSequence as bigint) <= (expected.headSequence as bigint))
      throw new NativeAuthoritySchemaError("recovery sequence does not advance");
  }
  if (schema === "b3-receipt") {
    const payload = asRecord(row.payload!, "B3 receipt payload");
    const cas = payload.operationKind === "compare-and-advance";
    if ((payload.committed as boolean) !== cas || (!cas && payload.priorStateDigest !== payload.newStateDigest))
      throw new NativeAuthoritySchemaError("B3 receipt state/commit equation failed");
  }
  if (schema === "b3-invalidation") {
    const payload = asRecord(row.payload!, "B3 invalidation payload");
    const prior = payload.priorGeneration as bigint;
    const next = payload.newGeneration as bigint;
    if (!((payload.frameKind === "heartbeat" && next === prior) || (payload.frameKind === "invalidated" && next > prior)))
      throw new NativeAuthoritySchemaError("B3 invalidation generation equation failed");
    if (((payload.sequence as bigint) === 1n) !== (payload.priorAckDigest === null))
      throw new NativeAuthoritySchemaError("B3 invalidation ACK chain equation failed");
  }
  if (schema === "build-identity") {
    const payload = asRecord(row.payload!, "build identity payload");
    if ((payload.validUntilCounter as bigint) < (payload.validFromCounter as bigint))
      throw new NativeAuthoritySchemaError("build identity validity interval is empty");
  }
  if (schema === "provenance") {
    const payload = asRecord(row.payload!, "provenance payload");
    if ((payload.finishedCounter as bigint) < (payload.startedCounter as bigint))
      throw new NativeAuthoritySchemaError("provenance counter interval is inverted");
    for (const [field, subject] of [["materials", false], ["subjects", true]] as const) {
      for (const value of payload[field] as CanonicalValue[]) {
        const typed = asRecord(value, `provenance ${field} row`);
        const scheme = String(typed.uri).split(":", 1)[0];
        const expected = subject ? "SubjectDigest" : ({ "keep-artifact": "ArtifactDigest", "keep-source": "SourceDigest", oci: "OciBlobDigest" } as const)[scheme as "keep-artifact" | "keep-source" | "oci"];
        if (typed.digestType !== expected) throw new NativeAuthoritySchemaError("provenance URI/digest type mismatch");
      }
    }
  }
  if (schema === "reproducibility") {
    const payload = asRecord(row.payload!, "reproducibility payload");
    if ((payload.disagreements as CanonicalValue[]).length !== 0)
      throw new NativeAuthoritySchemaError("official reproducibility record contains disagreements");
  }
}

const OPERATION_DOMAINS: Readonly<Record<keyof typeof P2_OPERATION_SPECS, string>> = Object.freeze({
  "b3-genesis-operation": "keep.native-b3-genesis-operation/v1\0",
  "b3-read-operation": "keep.native-b3-read/v1\0",
  "b3-cas-operation": "keep.native-b3-cas/v1\0",
  "b3-lease-operation": "keep.native-b3-lease/v1\0",
  "b3-subscribe-operation": "keep.native-b3-subscribe/v1\0",
});

const SIGNATURE_DOMAINS = Object.freeze({
  root: Object.freeze({ initial: "keep.native-root-genesis/v1\0", successor: "keep.native-root-update/v1\0" }),
  ceremony: "keep.native-root-ceremony/v1\0",
  timestamp: "keep.native-timestamp/v1\0",
  rollback: "keep.native-rollback/v1\0",
  recovery: "keep.native-revocation-recovery/v1\0",
  "b3-profile": "keep.native-b3-profile/v1\0",
  "b3-receipt": "keep.native-b3-receipt/v1\0",
  "b3-invalidation": "keep.native-b3-invalidation/v1\0",
  "build-identity": "keep.native-build-identity/v1\0",
  toolchain: "keep.native-toolchain/v1\0",
  sbom: "keep.native-sbom/v1\0",
  provenance: "keep.native-provenance/v1\0",
  reproducibility: "keep.native-repro/v1\0",
} as const);
export type P2S1SignedSchema = keyof typeof SIGNATURE_DOMAINS;

export function p2S1SignaturePreimage(bytesInput: unknown, schema: P2S1SignedSchema): Uint8Array {
  if (!Object.hasOwn(SIGNATURE_DOMAINS, schema)) throw new NativeAuthoritySchemaError("signed schema is not frozen");
  const captured = captureP2S1Canonical(bytesInput, schema);
  const envelopeValue = decodeCanonical(captured.canonicalBytes);
  const payload = asRecord(envelopeValue, `${schema} envelope`).payload!;
  const domain = schema === "root"
    ? (asRecord(payload, "root payload").predecessorRootEnvelopeDigest === null ? SIGNATURE_DOMAINS.root.initial : SIGNATURE_DOMAINS.root.successor)
    : SIGNATURE_DOMAINS[schema];
  return Uint8Array.from(createHash("sha512").update(domain, "utf8").update(encodeCanonical(payload)).digest());
}

const DERIVED_DOMAINS = Object.freeze({
  "genesis-epoch": "keep.native-genesis-epoch/v1\0",
  "b3-genesis-base": "keep.native-b3-genesis-base/v1\0",
  "b3-state": "keep.native-b3-state/v1\0",
  "observation-result": "keep.native-observation-result/v1\0",
  "control-policy": "keep.native-control-policy/v1\0",
  "journal-entries": "keep.native-journal-entries/v1\0",
  "peer-policy": "keep.native-peer-policy/v1\0",
  "build-command": "keep.native-build-command/v1\0",
  "io-max": "keep.native-io-max/v1\0",
  landlock: "keep.native-landlock-policy/v1\0",
  "landlock-v2": "keep.native-landlock-policy/v2\0",
  seccomp: "keep.native-seccomp-policy/v1\0",
} as const);
export type P2S1DerivedSchema = keyof typeof DERIVED_DOMAINS;

export function p2S1DerivedDigest(
  bytesInput: unknown,
  schema: P2S1DerivedSchema,
  seccompUse?: "launch" | "steady",
): P2DigestValue {
  if (!Object.hasOwn(DERIVED_DOMAINS, schema)) throw new NativeAuthoritySchemaError("derived schema is not frozen");
  if ((schema === "seccomp") !== (seccompUse !== undefined))
    throw new NativeAuthoritySchemaError("seccomp digest use must be explicit");
  const captured = captureP2S1Canonical(bytesInput, schema);
  const result = createHash("sha256").update(DERIVED_DOMAINS[schema], "utf8").update(captured.canonicalBytes).digest();
  const semantic = schema === "seccomp" ? `SeccompPolicyDigest:${seccompUse}` : `${schema}:DerivedDigest`;
  return Object.freeze({ semantic: semantic as P2DigestSemantic, bytes: Uint8Array.from(result), hex: result.toString("hex") });
}

export function p2S1EnvelopeDigest(bytesInput: unknown, schema: P2S1SignedSchema): P2DigestValue {
  const captured = captureP2S1Canonical(bytesInput, schema);
  const result = createHash("sha256").update(captured.canonicalBytes).digest();
  return Object.freeze({ semantic: `${schema}:EnvelopeDigest` as P2DigestSemantic, bytes: Uint8Array.from(result), hex: result.toString("hex") });
}

export function p2S1OperationDigest(bytesInput: unknown, schema: keyof typeof P2_OPERATION_SPECS): P2DigestValue {
  const captured = captureP2S1Canonical(bytesInput, schema);
  const bytesValue = createHash("sha256").update(OPERATION_DOMAINS[schema], "utf8").update(captured.canonicalBytes).digest();
  return Object.freeze({ semantic: `${schema}:operation` as P2DigestSemantic, bytes: Uint8Array.from(bytesValue), hex: bytesValue.toString("hex") });
}

export const P2_S1_AUTHORITY_BOUNDARY = Object.freeze({
  dependencyFree: true,
  signatureVerification: false,
  filesystemAuthority: false,
  b3Authority: false,
  productionBrand: false,
  nativeExecution: false,
  credentialAuthority: false,
  networkAuthority: false,
} as const);

/** Byte-only, no-effect consumer for the separately non-authorizing D2 overlay capture. */
export function captureValidatedPatchOverlayPlan(bytes: Uint8Array): ValidatedPatchOverlayPlan {
  return captureNativePatchOverlayV1(bytes);
}

/** Byte-only exact overlay/carrier join; still grants no filesystem or build authority. */
export function captureValidatedPatchApplicationInputs(
  overlayBytes: Uint8Array,
  carrierBytes: Uint8Array,
): ValidatedPatchApplicationInputs {
  return joinValidatedPatchApplicationInputs(
    captureNativePatchOverlayV1(overlayBytes),
    captureNativePatchByteCarrierSetV1(carrierBytes),
  );
}

/** Pure archive-row application and result commitment check; performs no materialization. */
export function captureValidatedNativeResultTreePlan(
  overlayBytes: Uint8Array,
  carrierBytes: Uint8Array,
  archive: CapturedNativeArchiveV1,
): ValidatedNativeResultTreePlan {
  return validateNativeResultTreeApplicationV1(
    captureValidatedPatchApplicationInputs(overlayBytes, carrierBytes),
    archive,
  );
}
