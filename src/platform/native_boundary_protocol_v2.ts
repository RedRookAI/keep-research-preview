/** A6 P1: development-only protocol-2/schema codec. No transport, boot authority, or native execution. */
import { createHash } from "node:crypto";
import { types } from "node:util";
import {
  decodeCanonical,
  encodeCanonical,
  isCanonical,
  type CanonicalValue,
} from "../eir/canonical.js";

export const NATIVE_BOUNDARY_V2 = Object.freeze({
  name: "keep.native-boundary",
  version: 2n,
  maxFrameBytes: 1_048_576,
  maxDepth: 16,
  maxItems: 65536,
  maxCollectionItems: 1024,
  maxTextBytes: 4096,
} as const);
export type NativeV2TrustClass = "production" | "development";
export type NativeV2RoleClass = "D1" | "D2" | "D3" | "PROBER";
export interface NativeV2RoleSpec {
  readonly roleId: string;
  readonly roleClass: NativeV2RoleClass;
  readonly principalId: string;
  readonly artifactDigest: string;
  readonly credentialDomains: readonly string[];
  readonly allowedChannelIds: readonly string[];
}
interface RequestBase {
  readonly protocol: "keep.native-boundary";
  readonly version: 2n;
  readonly requestId: string;
  readonly deploymentId: string;
  readonly bootId: string;
  readonly manifestDigest: string;
  readonly nonce: string;
  readonly sequence: bigint;
  readonly deadlineMs: bigint;
}
export type NativeBoundaryV2Request =
  | (RequestBase & {
      readonly kind: "launch";
      readonly roles: readonly NativeV2RoleSpec[];
    })
  | (RequestBase & {
      readonly kind: "probe";
      readonly roleHandleIds: readonly string[];
      readonly challengeNonce: string;
    })
  | (RequestBase & {
      readonly kind: "cancel";
      readonly targetRequestId: string;
    });
export interface NativeV2RoleHandle {
  readonly roleId: string;
  readonly roleClass: NativeV2RoleClass;
  readonly handleId: string;
  readonly incarnationDigest: string;
  readonly artifactDigest: string;
  readonly principalId: string;
}
export interface NativeV2Measurement {
  readonly measurementId: string;
  readonly roleHandleId: string;
  readonly field: string;
  readonly state: "active" | "inactive" | "unsupported" | "inconclusive";
  readonly transcriptDigest: string;
}
export interface NativeBoundaryV2Response {
  readonly protocol: "keep.native-boundary";
  readonly version: 2n;
  readonly requestId: string;
  readonly requestDigest: string;
  readonly deploymentId: string;
  readonly bootId: string;
  readonly nonce: string;
  readonly sequence: bigint;
  readonly helperArtifactDigest: string;
  readonly helperBuildId: string;
  readonly kernelBootId: string;
  readonly status: "ok" | "refused" | "failed";
  readonly roleHandles: readonly NativeV2RoleHandle[];
  readonly measurements: readonly NativeV2Measurement[];
  readonly failureCode: string;
  readonly evidenceBundleDigest: string | null;
}
export class NativeBoundaryV2Error extends Error {
  constructor(message: string) {
    super(`native boundary v2: ${message}`);
    this.name = "NativeBoundaryV2Error";
  }
}

const HEX64 = /^[0-9a-f]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/;
export const NATIVE_V2_MEASUREMENT_FIELDS = Object.freeze([
  "capture.window",
  "cgroup.limits",
  "credential.state",
  "fd.inventory",
  "identity.gid.effective",
  "identity.gid.real",
  "identity.gid.saved",
  "identity.groups",
  "identity.uid.effective",
  "identity.uid.real",
  "identity.uid.saved",
  "incarnation",
  "landlock.policy",
  "loader.executable",
  "loader.shared-libraries",
  "mount.topology",
  "namespaces.inodes",
  "network.topology",
  "seccomp.launch",
  "seccomp.steady",
  "security.capabilities.ambient",
  "security.capabilities.bounding",
  "security.capabilities.effective",
  "security.capabilities.inheritable",
  "security.capabilities.permitted",
  "security.dumpable",
  "security.no-new-privileges",
] as const);
const MEASUREMENT_FIELDS = new Set<string>(NATIVE_V2_MEASUREMENT_FIELDS);
function nativeBounds(
  value: CanonicalValue,
  depth = 0,
  count = { value: 0 },
): void {
  if (depth > NATIVE_BOUNDARY_V2.maxDepth)
    throw new NativeBoundaryV2Error("canonical depth exceeds bound");
  if (++count.value > NATIVE_BOUNDARY_V2.maxItems)
    throw new NativeBoundaryV2Error("canonical item count exceeds bound");
  if (typeof value === "string") {
    if (Buffer.byteLength(value, "utf8") > NATIVE_BOUNDARY_V2.maxTextBytes)
      throw new NativeBoundaryV2Error("canonical text exceeds bound");
    if (!/^[\x20-\x7e\n]*$/.test(value))
      throw new NativeBoundaryV2Error(
        "canonical text is outside the native ASCII profile",
      );
  }
  if (Array.isArray(value)) {
    if (value.length > NATIVE_BOUNDARY_V2.maxCollectionItems)
      throw new NativeBoundaryV2Error("canonical collection exceeds bound");
    for (const entry of value) nativeBounds(entry, depth + 1, count);
  } else if (
    value !== null &&
    typeof value === "object" &&
    !(value instanceof Uint8Array)
  ) {
    const entries = Object.entries(value);
    if (entries.length > NATIVE_BOUNDARY_V2.maxCollectionItems)
      throw new NativeBoundaryV2Error("canonical collection exceeds bound");
    for (const [key, entry] of entries) {
      nativeBounds(key, depth + 1, count);
      nativeBounds(entry, depth + 1, count);
    }
  }
}
export function decodeNativeV2Canonical(
  bytes: unknown,
  maximum: number = NATIVE_BOUNDARY_V2.maxFrameBytes,
): CanonicalValue {
  if (
    bytes === null ||
    typeof bytes !== "object" ||
    types.isProxy(bytes) ||
    !(bytes instanceof Uint8Array)
  )
    throw new NativeBoundaryV2Error("wire bytes are not an owned Uint8Array");
  if (bytes.byteLength === 0 || bytes.byteLength > maximum)
    throw new NativeBoundaryV2Error("wire bytes exceed bound");
  const ownedBytes = Uint8Array.from(bytes);
  if (!isCanonical(ownedBytes))
    throw new NativeBoundaryV2Error("wire bytes are not canonical CBOR");
  const owned = decodeCanonical(ownedBytes);
  nativeBounds(owned);
  return owned;
}
function preflightObject(input: unknown, label: string, maximum: number): void {
  const seen = new Set<object>();
  const count = { value: 0 };
  const walk = (value: unknown, depth: number): void => {
    if (depth > NATIVE_BOUNDARY_V2.maxDepth)
      throw new NativeBoundaryV2Error(`${label} depth exceeds bound`);
    if (++count.value > NATIVE_BOUNDARY_V2.maxItems)
      throw new NativeBoundaryV2Error(`${label} item count exceeds bound`);
    if (
      value === null ||
      typeof value === "boolean" ||
      typeof value === "bigint"
    )
      return;
    if (typeof value === "string") {
      if (
        Buffer.byteLength(value) > NATIVE_BOUNDARY_V2.maxTextBytes ||
        !/^[\x20-\x7e\n]*$/.test(value)
      )
        throw new NativeBoundaryV2Error(`${label} text exceeds profile`);
      return;
    }
    if (typeof value !== "object" || types.isProxy(value))
      throw new NativeBoundaryV2Error(`${label} is not inert canonical data`);
    if (seen.has(value)) throw new NativeBoundaryV2Error(`${label} is cyclic`);
    seen.add(value);
    if (value instanceof Uint8Array) {
      if (
        Object.getPrototypeOf(value) !== Uint8Array.prototype ||
        !(value.buffer instanceof ArrayBuffer) ||
        Object.getOwnPropertySymbols(value).length !== 0 ||
        value.byteLength > maximum
      )
        throw new NativeBoundaryV2Error(
          `${label} byte string is not owned/bounded`,
        );
      return;
    }
    if (Array.isArray(value)) {
      if (
        Object.getPrototypeOf(value) !== Array.prototype ||
        Object.getOwnPropertySymbols(value).length !== 0 ||
        Object.getOwnPropertyNames(value).length !== value.length + 1 ||
        value.length > NATIVE_BOUNDARY_V2.maxCollectionItems
      )
        throw new NativeBoundaryV2Error(`${label} array is not dense/bounded`);
      const descriptors = Object.getOwnPropertyDescriptors(value);
      for (let index = 0; index < value.length; index++) {
        const descriptor = descriptors[String(index)];
        if (!descriptor || !("value" in descriptor))
          throw new NativeBoundaryV2Error(`${label} array accessor refused`);
        walk(descriptor.value, depth + 1);
      }
      return;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null)
      throw new NativeBoundaryV2Error(`${label} prototype refused`);
    if (Object.getOwnPropertySymbols(value).length !== 0)
      throw new NativeBoundaryV2Error(`${label} symbol key refused`);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Object.keys(descriptors);
    if (keys.length > NATIVE_BOUNDARY_V2.maxCollectionItems)
      throw new NativeBoundaryV2Error(`${label} map exceeds bound`);
    for (const key of keys) {
      const descriptor = descriptors[key]!;
      if (!descriptor.enumerable || !("value" in descriptor))
        throw new NativeBoundaryV2Error(
          `${label} accessor/non-enumerable refused`,
        );
      walk(key, depth + 1);
      walk(descriptor.value, depth + 1);
    }
  };
  walk(input, 0);
}
function canonicalHeadLength(value: bigint): number {
  return value < 24n
    ? 1
    : value <= 0xffn
      ? 2
      : value <= 0xffffn
        ? 3
        : value <= 0xffffffffn
          ? 5
          : 9;
}
function encodedLengthPreflight(
  input: unknown,
  maximum: number,
  label: string,
): number {
  const add = (left: number, right: number) => {
    const total = left + right;
    if (!Number.isSafeInteger(total) || total > maximum)
      throw new NativeBoundaryV2Error(
        `${label} cumulative encoded bytes exceed bound`,
      );
    return total;
  };
  const walk = (value: unknown): number => {
    if (value === null || typeof value === "boolean") return 1;
    if (typeof value === "bigint") {
      if (value < 0n || value > 0xffffffffffffffffn)
        throw new NativeBoundaryV2Error(`${label} integer outside uint64`);
      return canonicalHeadLength(value);
    }
    if (typeof value === "string") {
      const length = Buffer.byteLength(value);
      return add(canonicalHeadLength(BigInt(length)), length);
    }
    if (value instanceof Uint8Array)
      return add(
        canonicalHeadLength(BigInt(value.byteLength)),
        value.byteLength,
      );
    if (Array.isArray(value)) {
      let total = canonicalHeadLength(BigInt(value.length));
      for (const entry of value) total = add(total, walk(entry));
      return total;
    }
    const descriptors = Object.getOwnPropertyDescriptors(value as object);
    const keys = Object.keys(descriptors);
    let total = canonicalHeadLength(BigInt(keys.length));
    for (const key of keys) {
      total = add(total, walk(key));
      total = add(total, walk(descriptors[key]!.value));
    }
    return total;
  };
  return walk(input);
}
function inert(
  input: unknown,
  label: string,
  maximum: number = NATIVE_BOUNDARY_V2.maxFrameBytes,
): CanonicalValue {
  preflightObject(input, label, maximum);
  const expectedLength = encodedLengthPreflight(input, maximum, label);
  let bytes: Uint8Array;
  try {
    bytes = encodeCanonical(input as CanonicalValue);
  } catch {
    throw new NativeBoundaryV2Error(`${label} is not canonical data`);
  }
  if (
    bytes.byteLength !== expectedLength ||
    bytes.byteLength === 0 ||
    bytes.byteLength > maximum ||
    !isCanonical(bytes)
  )
    throw new NativeBoundaryV2Error(`${label} exceeds canonical bounds`);
  const owned = decodeCanonical(bytes);
  nativeBounds(owned);
  return owned;
}
function map(value: unknown, label: string): Record<string, CanonicalValue> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    value instanceof Uint8Array ||
    Object.getPrototypeOf(value) !== null
  )
    throw new NativeBoundaryV2Error(`${label} is not an owned canonical map`);
  return value as Record<string, CanonicalValue>;
}
function exact(
  row: Record<string, CanonicalValue>,
  keys: readonly string[],
  label: string,
): void {
  const actual = Object.keys(row).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  )
    throw new NativeBoundaryV2Error(`${label} fields are not exact`);
}
function text(value: unknown, label: string): string {
  if (typeof value !== "string" || !IDENTIFIER.test(value))
    throw new NativeBoundaryV2Error(`${label} is not a bounded identifier`);
  return value;
}
function digest(value: unknown, label: string): string {
  if (
    typeof value !== "string" ||
    !HEX64.test(value) ||
    value === "00".repeat(32)
  )
    throw new NativeBoundaryV2Error(
      `${label} is not a non-placeholder SHA-256`,
    );
  return value;
}
function signatureBytes(value: unknown, label: string): Uint8Array {
  if (
    !(value instanceof Uint8Array) ||
    types.isProxy(value) ||
    Object.getPrototypeOf(value) !== Uint8Array.prototype ||
    !(value.buffer instanceof ArrayBuffer) ||
    value.byteLength !== 64 ||
    value.every((byte) => byte === 0)
  )
    throw new NativeBoundaryV2Error(
      `${label} is not a non-placeholder Ed25519 signature`,
    );
  return Uint8Array.from(value);
}
function absolutePath(value: unknown, label: string): string {
  if (
    typeof value !== "string" ||
    value.length < 2 ||
    value.length > 4096 ||
    !value.startsWith("/") ||
    value.includes("//") ||
    value.split("/").some((part) => part === "." || part === "..") ||
    !/^\/[A-Za-z0-9._/@-]+$/.test(value)
  )
    throw new NativeBoundaryV2Error(
      `${label} is not a canonical absolute path`,
    );
  return value;
}
function uint(value: unknown, label: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > 0xffffffffffffffffn)
    throw new NativeBoundaryV2Error(`${label} is not uint64`);
  return value;
}
function list<T>(
  value: unknown,
  maximum: number,
  label: string,
  capture: (entry: unknown, index: number) => T,
): readonly T[] {
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    Object.getOwnPropertyNames(value).length !== value.length + 1 ||
    value.length > maximum
  )
    throw new NativeBoundaryV2Error(`${label} is not a dense bounded array`);
  return Object.freeze(value.map(capture));
}
function texts(
  value: unknown,
  maximum: number,
  label: string,
): readonly string[] {
  const result = list(value, maximum, label, (entry, index) =>
    text(entry, `${label}[${index}]`),
  );
  if (new Set(result).size !== result.length)
    throw new NativeBoundaryV2Error(`${label} duplicates`);
  return Object.freeze([...result].sort());
}
function roleClass(value: unknown): NativeV2RoleClass {
  if (value !== "D1" && value !== "D2" && value !== "D3" && value !== "PROBER")
    throw new NativeBoundaryV2Error("role class unsupported");
  return value;
}
function bool(value: unknown, label: string): boolean {
  if (typeof value !== "boolean")
    throw new NativeBoundaryV2Error(`${label} is not boolean`);
  return value;
}
function enumText<T extends string>(
  value: unknown,
  values: readonly T[],
  label: string,
): T {
  if (typeof value !== "string" || !values.includes(value as T))
    throw new NativeBoundaryV2Error(`${label} enum unsupported`);
  return value as T;
}
function mapField(
  row: Record<string, CanonicalValue>,
  key: string,
  label: string,
): Record<string, CanonicalValue> {
  return map(row[key], `${label}.${key}`);
}
function exactRecord(
  value: unknown,
  keys: readonly string[],
  label: string,
): Record<string, CanonicalValue> {
  const row = map(value, label);
  exact(row, keys, label);
  return row;
}
function uniqueSorted<T>(
  rows: readonly T[],
  key: (row: T) => string,
  label: string,
): void {
  const values = rows.map(key);
  if (
    new Set(values).size !== values.length ||
    values.some((value, index) => index > 0 && !(values[index - 1]! < value))
  )
    throw new NativeBoundaryV2Error(`${label} is not sorted unique`);
}
function validateDigests(value: unknown, maximum: number, label: string): void {
  const rows = list(value, maximum, label, (entry, index) =>
    digest(entry, `${label}[${index}]`),
  );
  if (
    new Set(rows).size !== rows.length ||
    rows.some((value, index) => index > 0 && !(rows[index - 1]! < value))
  )
    throw new NativeBoundaryV2Error(`${label} is not sorted unique`);
}
function validateIdentifiers(
  value: unknown,
  maximum: number,
  label: string,
): readonly string[] {
  const rows = list(value, maximum, label, (entry, index) =>
    text(entry, `${label}[${index}]`),
  );
  if (
    new Set(rows).size !== rows.length ||
    rows.some((value, index) => index > 0 && !(rows[index - 1]! < value))
  )
    throw new NativeBoundaryV2Error(`${label} is not sorted unique`);
  return rows;
}

export function captureNativeBoundaryV2Request(
  input: unknown,
): NativeBoundaryV2Request {
  const row = map(inert(input, "request"), "request");
  const kind = row.kind;
  const commonKeys = [
    "protocol",
    "version",
    "kind",
    "requestId",
    "deploymentId",
    "bootId",
    "manifestDigest",
    "nonce",
    "sequence",
    "deadlineMs",
  ];
  if (kind === "launch") exact(row, [...commonKeys, "roles"], "launch request");
  else if (kind === "probe")
    exact(
      row,
      [...commonKeys, "roleHandleIds", "challengeNonce"],
      "probe request",
    );
  else if (kind === "cancel")
    exact(row, [...commonKeys, "targetRequestId"], "cancel request");
  else throw new NativeBoundaryV2Error("request kind unsupported");
  if (
    row.protocol !== NATIVE_BOUNDARY_V2.name ||
    row.version !== NATIVE_BOUNDARY_V2.version
  )
    throw new NativeBoundaryV2Error("protocol/version unsupported");
  const common = {
    protocol: NATIVE_BOUNDARY_V2.name,
    version: NATIVE_BOUNDARY_V2.version,
    requestId: text(row.requestId, "requestId"),
    deploymentId: text(row.deploymentId, "deploymentId"),
    bootId: text(row.bootId, "bootId"),
    manifestDigest: digest(row.manifestDigest, "manifestDigest"),
    nonce: text(row.nonce, "nonce"),
    sequence: uint(row.sequence, "sequence"),
    deadlineMs: uint(row.deadlineMs, "deadlineMs"),
  };
  if (kind === "launch") {
    const roles = list(row.roles, 32, "roles", (entry, index) => {
      const role = map(entry, `roles[${index}]`);
      exact(
        role,
        [
          "roleId",
          "roleClass",
          "principalId",
          "artifactDigest",
          "credentialDomains",
          "allowedChannelIds",
        ],
        `roles[${index}]`,
      );
      const klass = roleClass(role.roleClass);
      const credentialDomains = texts(
        role.credentialDomains,
        1,
        "credentialDomains",
      );
      if (klass !== "D3" && credentialDomains.length !== 0)
        throw new NativeBoundaryV2Error("credentials outside D3");
      return Object.freeze({
        roleId: text(role.roleId, "roleId"),
        roleClass: klass,
        principalId: text(role.principalId, "principalId"),
        artifactDigest: digest(role.artifactDigest, "artifactDigest"),
        credentialDomains,
        allowedChannelIds: texts(
          role.allowedChannelIds,
          128,
          "allowedChannelIds",
        ),
      });
    });
    if (
      roles.length === 0 ||
      new Set(roles.map((role) => role.roleId)).size !== roles.length ||
      new Set(roles.map((role) => role.principalId)).size !== roles.length
    )
      throw new NativeBoundaryV2Error("roles empty or duplicated");
    return Object.freeze({ kind, ...common, roles });
  }
  if (kind === "probe") {
    const roleHandleIds = texts(row.roleHandleIds, 32, "roleHandleIds");
    if (roleHandleIds.length === 0)
      throw new NativeBoundaryV2Error("probe handles empty");
    return Object.freeze({
      kind,
      ...common,
      roleHandleIds,
      challengeNonce: text(row.challengeNonce, "challengeNonce"),
    });
  }
  return Object.freeze({
    kind,
    ...common,
    targetRequestId: text(row.targetRequestId, "targetRequestId"),
  });
}

export function nativeBoundaryV2RequestDigest(input: unknown): string {
  const request = captureNativeBoundaryV2Request(input);
  const hash = createHash("sha256");
  hash.update("keep.eir.v1.keep.native-boundary-request/v2\0");
  hash.update(encodeCanonical(request as unknown as CanonicalValue));
  return hash.digest("hex");
}

export function captureNativeBoundaryV2Response(
  input: unknown,
): NativeBoundaryV2Response {
  const row = map(inert(input, "response"), "response");
  exact(
    row,
    [
      "protocol",
      "version",
      "requestId",
      "requestDigest",
      "deploymentId",
      "bootId",
      "nonce",
      "sequence",
      "helperArtifactDigest",
      "helperBuildId",
      "kernelBootId",
      "status",
      "roleHandles",
      "measurements",
      "failureCode",
      "evidenceBundleDigest",
    ],
    "response",
  );
  if (
    row.protocol !== NATIVE_BOUNDARY_V2.name ||
    row.version !== NATIVE_BOUNDARY_V2.version
  )
    throw new NativeBoundaryV2Error("protocol/version unsupported");
  const status = row.status;
  if (status !== "ok" && status !== "refused" && status !== "failed")
    throw new NativeBoundaryV2Error("status unsupported");
  const handles = list(row.roleHandles, 32, "roleHandles", (entry, index) => {
    const value = map(entry, `roleHandles[${index}]`);
    exact(
      value,
      [
        "roleId",
        "roleClass",
        "handleId",
        "incarnationDigest",
        "artifactDigest",
        "principalId",
      ],
      `roleHandles[${index}]`,
    );
    return Object.freeze({
      roleId: text(value.roleId, "roleId"),
      roleClass: roleClass(value.roleClass),
      handleId: text(value.handleId, "handleId"),
      incarnationDigest: digest(value.incarnationDigest, "incarnationDigest"),
      artifactDigest: digest(value.artifactDigest, "artifactDigest"),
      principalId: text(value.principalId, "principalId"),
    });
  });
  const measurements = list(
    row.measurements,
    1024,
    "measurements",
    (entry, index) => {
      const value = map(entry, `measurements[${index}]`);
      exact(
        value,
        ["measurementId", "roleHandleId", "field", "state", "transcriptDigest"],
        `measurements[${index}]`,
      );
      const state = value.state;
      if (
        state !== "active" &&
        state !== "inactive" &&
        state !== "unsupported" &&
        state !== "inconclusive"
      )
        throw new NativeBoundaryV2Error("measurement state unsupported");
      return Object.freeze({
        measurementId: text(value.measurementId, "measurementId"),
        roleHandleId: text(value.roleHandleId, "roleHandleId"),
        field: (() => {
          const field = text(value.field, "field");
          if (!MEASUREMENT_FIELDS.has(field))
            throw new NativeBoundaryV2Error(
              "measurement field outside registry",
            );
          return field;
        })(),
        state,
        transcriptDigest: digest(value.transcriptDigest, "transcriptDigest"),
      });
    },
  );
  if (
    new Set(handles.map((value) => value.handleId)).size !== handles.length ||
    new Set(handles.map((value) => value.roleId)).size !== handles.length ||
    new Set(measurements.map((value) => value.measurementId)).size !==
      measurements.length ||
    new Set(measurements.map((value) => `${value.roleHandleId}:${value.field}`))
      .size !== measurements.length
  )
    throw new NativeBoundaryV2Error("duplicate response identity");
  const failureCode = row.failureCode;
  const evidenceBundleDigest =
    row.evidenceBundleDigest === null
      ? null
      : digest(row.evidenceBundleDigest, "evidenceBundleDigest");
  if (status === "ok") {
    if (failureCode !== "" || evidenceBundleDigest === null)
      throw new NativeBoundaryV2Error(
        "ok response lacks evidence or has failure",
      );
  } else {
    if (
      typeof failureCode !== "string" ||
      !IDENTIFIER.test(failureCode) ||
      handles.length !== 0 ||
      measurements.length !== 0
    )
      throw new NativeBoundaryV2Error(
        "failure response contains partial success",
      );
    const unavailable = failureCode.startsWith("evidence.unavailable.");
    if ((evidenceBundleDigest === null) !== unavailable)
      throw new NativeBoundaryV2Error(
        "failure evidence/code biconditional violated",
      );
  }
  return Object.freeze({
    protocol: NATIVE_BOUNDARY_V2.name,
    version: NATIVE_BOUNDARY_V2.version,
    requestId: text(row.requestId, "requestId"),
    requestDigest: digest(row.requestDigest, "requestDigest"),
    deploymentId: text(row.deploymentId, "deploymentId"),
    bootId: text(row.bootId, "bootId"),
    nonce: text(row.nonce, "nonce"),
    sequence: uint(row.sequence, "sequence"),
    helperArtifactDigest: digest(
      row.helperArtifactDigest,
      "helperArtifactDigest",
    ),
    helperBuildId: text(row.helperBuildId, "helperBuildId"),
    kernelBootId: text(row.kernelBootId, "kernelBootId"),
    status,
    roleHandles: handles,
    measurements,
    failureCode: failureCode as string,
    evidenceBundleDigest,
  });
}

export function validateNativeBoundaryV2Exchange(
  requestInput: unknown,
  responseInput: unknown,
): void {
  const request = captureNativeBoundaryV2Request(requestInput);
  const response = captureNativeBoundaryV2Response(responseInput);
  if (
    response.requestId !== request.requestId ||
    response.requestDigest !== nativeBoundaryV2RequestDigest(request) ||
    response.deploymentId !== request.deploymentId ||
    response.bootId !== request.bootId ||
    response.nonce !== request.nonce ||
    response.sequence !== request.sequence
  )
    throw new NativeBoundaryV2Error("response envelope does not bind request");
  if (response.status !== "ok") return;
  if (request.kind === "cancel") {
    if (response.roleHandles.length || response.measurements.length)
      throw new NativeBoundaryV2Error("cancel response carries authority");
    return;
  }
  const handles =
    request.kind === "launch"
      ? response.roleHandles.map((row) => row.handleId)
      : [...request.roleHandleIds];
  if (request.kind === "probe" && response.roleHandles.length)
    throw new NativeBoundaryV2Error("probe response minted handles");
  if (request.kind === "launch") {
    if (response.roleHandles.length !== request.roles.length)
      throw new NativeBoundaryV2Error("launch handle closure incomplete");
    const requested = new Map(request.roles.map((row) => [row.roleId, row]));
    for (const handle of response.roleHandles) {
      const role = requested.get(handle.roleId);
      if (
        !role ||
        role.roleClass !== handle.roleClass ||
        role.principalId !== handle.principalId ||
        role.artifactDigest !== handle.artifactDigest
      )
        throw new NativeBoundaryV2Error("launch role substitution");
    }
  }
  const expected = new Set(
    handles.flatMap((handle) =>
      NATIVE_V2_MEASUREMENT_FIELDS.map((field) => `${handle}:${field}`),
    ),
  );
  if (
    response.measurements.length !== expected.size ||
    response.measurements.some(
      (row) => !expected.has(`${row.roleHandleId}:${row.field}`),
    )
  )
    throw new NativeBoundaryV2Error(
      "request-aware measurement closure incomplete",
    );
}

const ENVELOPE_KEYS = ["payload", "payloadDigest", "signatures"] as const;
const DEPLOYMENT_KEYS = [
  "schema",
  "version",
  "trustClass",
  "deploymentId",
  "deploymentEpoch",
  "deploymentBaseDigest",
  "predecessorDigest",
  "bootPolicy",
  "protocol",
  "artifacts",
  "roles",
  "channels",
  "probers",
  "provisioners",
  "b3",
  "release",
  "revocation",
  "rollback",
  "evidence",
] as const;
const CLOSURE_KEYS = [
  "schema",
  "version",
  "trustClass",
  "a4ReleaseBaseDigest",
  "a4ArtifactInventoryDigest",
  "nativeArtifactInventoryDigest",
  "nativeDeploymentPayloadDigest",
  "nativeDeploymentEnvelopeDigest",
  "nativePackagePayloadDigest",
  "nativeClosureBaseDigest",
  "helperArtifactDigest",
  "trampolineArtifactDigest",
  "proberArtifactDigest",
  "provisionerArtifactDigests",
  "protocolDigest",
  "evidenceSchemaDigest",
  "targetTriple",
  "variant",
  "artifactVersion",
  "buildId",
  "releaseKeyEpoch",
  "timestampKeyEpoch",
  "timestampRecordEnvelopeDigest",
  "sbomEnvelopeDigest",
  "provenanceEnvelopeDigests",
  "reproducibilityRecordEnvelopeDigest",
  "toolchainClosureEnvelopeDigest",
  "releaseTimeRevocationCheckpointEnvelopeDigest",
  "releaseTimeRevocationSequence",
  "deploymentEpoch",
  "minimumArtifactVersion",
  "predecessorDigest",
  "authorizedRollbackEnvelopeDigest",
  "b0RootEnvelopeDigest",
  "b3ProfileEnvelopeDigest",
] as const;
const INDEX_KEYS = [
  "schema",
  "version",
  "a4ReleaseBaseDigest",
  "deploymentEnvelopeDigest",
  "nativeClosureEnvelopeDigest",
  "b0RootEnvelopeDigest",
  "releaseKeyEpoch",
  "trustClass",
] as const;
const REVOCATION_KEYS = [
  "schema",
  "version",
  "authorityId",
  "namespace",
  "scope",
  "keyEpoch",
  "sequence",
  "previousEnvelopeDigest",
  "issuedCounter",
  "expiresCounter",
  "revokedKeys",
  "revokedArtifacts",
  "rotationCutoffs",
  "compromiseSemantics",
] as const;
const EVIDENCE_KEYS = [
  "schema",
  "version",
  "deploymentId",
  "deploymentEpoch",
  "bootId",
  "kernelBootId",
  "manifestDigest",
  "nativeClosureEnvelopeDigest",
  "helperArtifactDigest",
  "helperBuildId",
  "helperIncarnation",
  "protocolDigest",
  "requestId",
  "requestDigest",
  "requestNonce",
  "requestSequence",
  "challengeNonce",
  "b3ProfileEnvelopeDigest",
  "b3LeaseReceiptEnvelopeDigest",
  "b3Counter",
  "capturedCounter",
  "expiresCounter",
  "proberId",
  "proberPrincipal",
  "proberArtifactDigest",
  "proberIncarnation",
  "proberKeyEpoch",
  "revocationEnvelopeDigest",
  "roles",
  "measurements",
  "negativeProbes",
  "inheritedFdInventory",
  "cleanup",
  "previousEvidenceDigest",
  "signature",
] as const;

export interface NativeV2DigestRegistryEntry {
  readonly path: string;
  readonly field: string;
  readonly semanticType: string;
  readonly rank: number;
  readonly dependsOn: readonly string[];
}

const leaf = (path: string, semanticType = path): NativeV2DigestRegistryEntry => {
  if (
    semanticType === path &&
    (path === "request.manifestDigest" ||
      path === "evidence.manifestDigest" ||
      path.endsWith("deploymentEnvelopeDigest") ||
      path.endsWith("nativeDeploymentEnvelopeDigest"))
  )
    semanticType = "native-deployment-envelope-v1";
  if (semanticType === path && path.endsWith("nativeClosureEnvelopeDigest"))
    semanticType = "native-release-closure-envelope-v1";
  let rank = 0;
  let dependsOn: readonly string[] = [];
  if (path === "revocation.payloadDigest") {
    rank = 1;
    dependsOn = ["revocation.payload.previousEnvelopeDigest"];
  } else if (path.endsWith("authorizedRollbackEnvelopeDigest")) {
    rank = 4;
    dependsOn = ["deployment.payload.deploymentBaseDigest"];
  } else if (
    path === "request.manifestDigest" ||
    path === "evidence.manifestDigest" ||
    path.endsWith("deploymentEnvelopeDigest") ||
    path.endsWith("nativeDeploymentEnvelopeDigest")
  ) {
    rank = 6;
    dependsOn = ["deployment.payloadDigest"];
  } else if (path.endsWith("timestampRecordEnvelopeDigest")) {
    rank = 8;
    dependsOn = ["closure.payload.nativeClosureBaseDigest"];
  } else if (path.endsWith("nativeClosureEnvelopeDigest")) {
    rank = 10;
    dependsOn = ["closure.payloadDigest"];
  }
  return {
    path,
    field: path.slice(path.lastIndexOf(".") + 1).replace("[]", ""),
    semanticType,
    rank,
    dependsOn,
  };
};
const DEPLOYMENT_BASE_INPUTS = [
  "deployment.payload.predecessorDigest",
  "deployment.payload.artifacts[].digest",
  "deployment.payload.roles[].artifactDigest",
  "deployment.payload.roles[].cgroup.ioMaxDigest",
  "deployment.payload.roles[].launchSeccompDigest",
  "deployment.payload.roles[].steadySeccompDigest",
  "deployment.payload.roles[].landlockDigest",
  "deployment.payload.b3.genesisBaseDigest",
  "deployment.payload.b3.b3ProfileEnvelopeDigest",
  "deployment.payload.revocation.genesisCheckpointEnvelopeDigest",
  "deployment.payload.rollback.predecessorDigest",
] as const;
const CLOSURE_BASE_INPUTS = [
  "closure.payload.a4ReleaseBaseDigest", "closure.payload.a4ArtifactInventoryDigest",
  "closure.payload.nativeArtifactInventoryDigest", "closure.payload.nativeDeploymentPayloadDigest",
  "closure.payload.nativeDeploymentEnvelopeDigest", "closure.payload.nativePackagePayloadDigest",
  "closure.payload.helperArtifactDigest", "closure.payload.trampolineArtifactDigest",
  "closure.payload.proberArtifactDigest", "closure.payload.provisionerArtifactDigests[]",
  "closure.payload.protocolDigest", "closure.payload.evidenceSchemaDigest",
  "closure.payload.sbomEnvelopeDigest", "closure.payload.provenanceEnvelopeDigests[]",
  "closure.payload.reproducibilityRecordEnvelopeDigest", "closure.payload.toolchainClosureEnvelopeDigest",
  "closure.payload.releaseTimeRevocationCheckpointEnvelopeDigest", "closure.payload.predecessorDigest",
  "closure.payload.authorizedRollbackEnvelopeDigest", "closure.payload.b0RootEnvelopeDigest",
  "closure.payload.b3ProfileEnvelopeDigest",
] as const;
const DEPLOYMENT_PAYLOAD_INPUTS = [
  ...DEPLOYMENT_BASE_INPUTS,
  "deployment.payload.deploymentBaseDigest",
  "deployment.payload.rollback.authorizedRollbackEnvelopeDigest",
] as const;
const CLOSURE_PAYLOAD_INPUTS = [
  ...CLOSURE_BASE_INPUTS,
  "closure.payload.nativeClosureBaseDigest",
  "closure.payload.timestampRecordEnvelopeDigest",
] as const;
const INDEX_PAYLOAD_INPUTS = [
  "index.payload.a4ReleaseBaseDigest",
  "index.payload.deploymentEnvelopeDigest",
  "index.payload.nativeClosureEnvelopeDigest",
  "index.payload.b0RootEnvelopeDigest",
] as const;
const OTHER_DIGEST_PATHS = [
  "request.manifestDigest", "request.roles[].artifactDigest", "response.requestDigest",
  "response.helperArtifactDigest", "response.roleHandles[].incarnationDigest",
  "response.roleHandles[].artifactDigest", "response.measurements[].transcriptDigest",
  "response.evidenceBundleDigest", "deployment.payloadDigest", "closure.payloadDigest",
  "index.payloadDigest", "index.payload.a4ReleaseBaseDigest", "index.payload.deploymentEnvelopeDigest",
  "index.payload.nativeClosureEnvelopeDigest", "index.payload.b0RootEnvelopeDigest",
  "revocation.payloadDigest", "revocation.payload.previousEnvelopeDigest",
  "evidence.manifestDigest", "evidence.nativeClosureEnvelopeDigest",
  "evidence.helperArtifactDigest", "evidence.helperIncarnation", "evidence.protocolDigest",
  "evidence.requestDigest", "evidence.b3ProfileEnvelopeDigest",
  "evidence.b3LeaseReceiptEnvelopeDigest", "evidence.proberArtifactDigest",
  "evidence.proberIncarnation", "evidence.revocationEnvelopeDigest",
  "evidence.roles[].artifactDigest", "evidence.roles[].incarnationDigest",
  "evidence.measurements[].value.ioMaxDigest", "evidence.measurements[].value.filterDigest",
  "evidence.measurements[].value.rulesetDigest", "evidence.measurements[].value.entries[].sourceDigest",
  "evidence.measurements[].value.entries[].flagsDigest", "evidence.measurements[].value.pidfdDigest",
  "evidence.measurements[].value.value", "evidence.measurements[].value.values[]",
  "evidence.measurements[].transcriptDigest", "evidence.negativeProbes[].controlDigest",
  "evidence.inheritedFdInventory[].flagsDigest", "evidence.cleanup.journalDigest",
  "evidence.previousEvidenceDigest",
  "revocation.payload.revokedArtifacts[]",
] as const;
const EVIDENCE_BUNDLE_INPUTS = OTHER_DIGEST_PATHS.filter((path) =>
  path.startsWith("evidence."),
);
const REVOCATION_PAYLOAD_INPUTS = [
  "revocation.payload.previousEnvelopeDigest",
  "revocation.payload.revokedArtifacts[]",
] as const;
const central: NativeV2DigestRegistryEntry[] = [
  ...DEPLOYMENT_BASE_INPUTS.map((path) => leaf(path)),
  leaf("deployment.payload.rollback.authorizedRollbackEnvelopeDigest"),
  { path: "deployment.payload.deploymentBaseDigest", field: "deploymentBaseDigest", semanticType: "native-deployment-base-v1", rank: 3, dependsOn: DEPLOYMENT_BASE_INPUTS },
  ...CLOSURE_BASE_INPUTS.map((path) => leaf(path)),
  leaf("closure.payload.timestampRecordEnvelopeDigest"),
  { path: "closure.payload.nativeClosureBaseDigest", field: "nativeClosureBaseDigest", semanticType: "native-release-closure-base-v1", rank: 7, dependsOn: CLOSURE_BASE_INPUTS },
  ...OTHER_DIGEST_PATHS.map((path) => leaf(path, path === "request.manifestDigest" || path === "evidence.manifestDigest" ? "native-deployment-envelope-v1" : path)),
];
const derived = new Map<string, NativeV2DigestRegistryEntry>([
  ["deployment.payloadDigest", { path: "deployment.payloadDigest", field: "payloadDigest", semanticType: "native-deployment-payload-v1", rank: 5, dependsOn: DEPLOYMENT_PAYLOAD_INPUTS }],
  ["closure.payloadDigest", { path: "closure.payloadDigest", field: "payloadDigest", semanticType: "native-release-closure-payload-v1", rank: 9, dependsOn: CLOSURE_PAYLOAD_INPUTS }],
  ["index.payloadDigest", { path: "index.payloadDigest", field: "payloadDigest", semanticType: "native-release-index-payload-v1", rank: 11, dependsOn: INDEX_PAYLOAD_INPUTS }],
  ["revocation.payloadDigest", { path: "revocation.payloadDigest", field: "payloadDigest", semanticType: "native-revocation-payload-v1", rank: 1, dependsOn: REVOCATION_PAYLOAD_INPUTS }],
  ["response.evidenceBundleDigest", { path: "response.evidenceBundleDigest", field: "evidenceBundleDigest", semanticType: "native-evidence-bundle-v1", rank: 12, dependsOn: EVIDENCE_BUNDLE_INPUTS }],
]);
for (let index = 0; index < central.length; index++) {
  const replacement = derived.get(central[index]!.path);
  if (replacement) central[index] = replacement;
}
export const NATIVE_V2_DIGEST_REGISTRY: readonly NativeV2DigestRegistryEntry[] =
  Object.freeze(central.map((row) => Object.freeze({ ...row, dependsOn: Object.freeze([...row.dependsOn]) })));

const REQUIRED_DAG_EDGES = new Map<string, readonly string[]>([
  ["deployment.payload.deploymentBaseDigest", DEPLOYMENT_BASE_INPUTS],
  ["deployment.payload.rollback.authorizedRollbackEnvelopeDigest", ["deployment.payload.deploymentBaseDigest"]],
  ["deployment.payloadDigest", DEPLOYMENT_PAYLOAD_INPUTS],
  ["request.manifestDigest", ["deployment.payloadDigest"]],
  ["evidence.manifestDigest", ["deployment.payloadDigest"]],
  ["closure.payload.nativeDeploymentEnvelopeDigest", ["deployment.payloadDigest"]],
  ["index.payload.deploymentEnvelopeDigest", ["deployment.payloadDigest"]],
  ["closure.payload.nativeClosureBaseDigest", CLOSURE_BASE_INPUTS],
  ["closure.payload.timestampRecordEnvelopeDigest", ["closure.payload.nativeClosureBaseDigest"]],
  ["closure.payloadDigest", CLOSURE_PAYLOAD_INPUTS],
  ["index.payload.nativeClosureEnvelopeDigest", ["closure.payloadDigest"]],
  ["evidence.nativeClosureEnvelopeDigest", ["closure.payloadDigest"]],
  ["index.payloadDigest", INDEX_PAYLOAD_INPUTS],
  ["revocation.payloadDigest", REVOCATION_PAYLOAD_INPUTS],
  ["response.evidenceBundleDigest", EVIDENCE_BUNDLE_INPUTS],
]);

export function validateNativeV2DigestRegistry(
  entries: readonly NativeV2DigestRegistryEntry[],
): void {
  const byPath = new Map(entries.map((row) => [row.path, row]));
  if (byPath.size !== entries.length)
    throw new NativeBoundaryV2Error("digest registry path is duplicated");
  for (const row of entries) {
    if (!row.path || !row.field || !row.semanticType || !Number.isInteger(row.rank) || row.rank < 0)
      throw new NativeBoundaryV2Error("digest registry row is malformed");
    for (const dependency of row.dependsOn) {
      const ancestor = byPath.get(dependency);
      if (!ancestor)
        throw new NativeBoundaryV2Error("digest registry dependency is unknown");
      if (ancestor.rank >= row.rank)
        throw new NativeBoundaryV2Error("digest registry has a reverse or cyclic edge");
    }
    const required = REQUIRED_DAG_EDGES.get(row.path);
    if (
      required &&
      ([...required].sort().join("\0") !== [...row.dependsOn].sort().join("\0"))
    )
      throw new NativeBoundaryV2Error("digest registry required edges are incomplete");
  }
  for (const path of REQUIRED_DAG_EDGES.keys())
    if (!byPath.has(path))
      throw new NativeBoundaryV2Error("digest registry required node is missing");
}
validateNativeV2DigestRegistry(NATIVE_V2_DIGEST_REGISTRY);

function baseDigest(
  domain: string,
  projection: CanonicalValue,
): string {
  return createHash("sha256")
    .update(domain, "utf8")
    .update(encodeCanonical(projection))
    .digest("hex");
}

export function nativeDeploymentBaseDigest(
  payload: Readonly<Record<string, CanonicalValue>>,
): string {
  const owned = inert(payload, "native deployment base payload") as Record<
    string,
    CanonicalValue
  >;
  const projection: Record<string, CanonicalValue> = Object.create(null);
  for (const [key, value] of Object.entries(owned)) {
    if (key === "deploymentBaseDigest") continue;
    if (key === "rollback") {
      const rollback = value as Record<string, CanonicalValue>;
      const projectedRollback: Record<string, CanonicalValue> =
        Object.create(null);
      for (const [rollbackKey, rollbackValue] of Object.entries(rollback))
        if (rollbackKey !== "authorizedRollbackEnvelopeDigest")
          projectedRollback[rollbackKey] = rollbackValue;
      projection.rollback = projectedRollback;
    } else projection[key] = value;
  }
  return baseDigest("keep.native-deployment-base/v1\0", projection);
}

export function nativeReleaseClosureBaseDigest(
  payload: Readonly<Record<string, CanonicalValue>>,
): string {
  const owned = inert(payload, "native closure base payload") as Record<
    string,
    CanonicalValue
  >;
  const projection: Record<string, CanonicalValue> = Object.create(null);
  for (const [key, value] of Object.entries(owned))
    if (key !== "nativeClosureBaseDigest" && key !== "timestampRecordEnvelopeDigest")
      projection[key] = value;
  return baseDigest("keep.native-release-closure-base/v1\0", projection);
}

function validateDeployment(payload: Record<string, CanonicalValue>): void {
  text(payload.deploymentId, "deploymentId");
  uint(payload.deploymentEpoch, "deploymentEpoch");
  digest(payload.deploymentBaseDigest, "deploymentBaseDigest");
  digest(payload.predecessorDigest, "predecessorDigest");
  const boot = exactRecord(
    payload.bootPolicy,
    [
      "maxLaunchMs",
      "maxResponseMs",
      "maxAttestationAge",
      "maxCleanupMs",
      "maxConcurrentTransactions",
      "kernelCells",
    ],
    "bootPolicy",
  );
  for (const key of [
    "maxLaunchMs",
    "maxResponseMs",
    "maxAttestationAge",
    "maxCleanupMs",
    "maxConcurrentTransactions",
  ] as const)
    uint(boot[key], key);
  if (boot.maxConcurrentTransactions !== 1n)
    throw new NativeBoundaryV2Error("v1 concurrency must equal one");
  const kernelCells = list(
    boot.kernelCells,
    32,
    "kernelCells",
    (entry, index) => {
      const row = exactRecord(
        entry,
        ["cellId", "minimumKernel", "maximumKernel", "requiredFeatures"],
        `kernelCells[${index}]`,
      );
      text(row.cellId, "cellId");
      text(row.minimumKernel, "minimumKernel");
      text(row.maximumKernel, "maximumKernel");
      validateIdentifiers(row.requiredFeatures, 64, "requiredFeatures");
      return row;
    },
  );
  if (kernelCells.length === 0)
    throw new NativeBoundaryV2Error("kernelCells empty");
  uniqueSorted(kernelCells, (row) => row.cellId as string, "kernelCells");
  const protocol = exactRecord(
    payload.protocol,
    [
      "name",
      "version",
      "maxFrameBytes",
      "maxRoles",
      "maxChannels",
      "maxMeasurements",
      "maxDepth",
      "maxItems",
      "maxTextBytes",
    ],
    "protocol",
  );
  if (
    protocol.name !== NATIVE_BOUNDARY_V2.name ||
    protocol.version !== 2n ||
    protocol.maxFrameBytes !== BigInt(NATIVE_BOUNDARY_V2.maxFrameBytes) ||
    protocol.maxRoles !== 32n ||
    protocol.maxChannels !== 128n ||
    protocol.maxMeasurements !== 1024n ||
    protocol.maxDepth !== 16n ||
    protocol.maxItems !== 65536n ||
    protocol.maxTextBytes !== 4096n
  )
    throw new NativeBoundaryV2Error("protocol limits are not exact");
  const artifacts = list(
    payload.artifacts,
    128,
    "artifacts",
    (entry, index) => {
      const row = exactRecord(
        entry,
        [
          "artifactId",
          "digest",
          "kind",
          "targetTriple",
          "variant",
          "executableMode",
          "releaseMember",
        ],
        `artifacts[${index}]`,
      );
      text(row.artifactId, "artifactId");
      digest(row.digest, "artifact digest");
      enumText(
        row.kind,
        ["helper", "trampoline", "prober", "provisioner", "role"],
        "artifact kind",
      );
      text(row.targetTriple, "targetTriple");
      text(row.variant, "variant");
      const mode = uint(row.executableMode, "executableMode");
      if (mode !== 365n || bool(row.releaseMember, "releaseMember") !== true)
        throw new NativeBoundaryV2Error(
          "artifact is not an executable release member",
        );
      return row;
    },
  );
  if (artifacts.length === 0)
    throw new NativeBoundaryV2Error("artifacts empty");
  uniqueSorted(artifacts, (row) => row.artifactId as string, "artifacts");
  const artifactIds = new Set(artifacts.map((row) => row.artifactId));
  const artifactDigests = new Map(
    artifacts.map((row) => [row.artifactId, row.digest]),
  );
  const artifactKinds = new Map(
    artifacts.map((row) => [row.artifactId, row.kind]),
  );
  for (const kind of ["helper", "trampoline", "prober"])
    if (artifacts.filter((row) => row.kind === kind).length !== 1)
      throw new NativeBoundaryV2Error(`exactly one ${kind} artifact required`);
  const roles = list(payload.roles, 32, "deployment roles", (entry, index) => {
    const row = exactRecord(
      entry,
      [
        "roleId",
        "roleClass",
        "principalId",
        "artifactId",
        "artifactDigest",
        "credentialDomains",
        "allowedChannelIds",
        "uid",
        "gid",
        "supplementaryGroups",
        "namespaces",
        "mounts",
        "cgroup",
        "rlimits",
        "capabilitiesEmpty",
        "dumpable",
        "launchSeccompDigest",
        "steadySeccompDigest",
        "landlockDigest",
        "environmentAllowlist",
        "inheritedFdSlots",
        "requiredMeasurementFields",
      ],
      `deployment roles[${index}]`,
    );
    text(row.roleId, "roleId");
    const klass = roleClass(row.roleClass);
    text(row.principalId, "principalId");
    const artifactId = text(row.artifactId, "artifactId");
    if (
      !artifactIds.has(artifactId) ||
      artifactKinds.get(artifactId) !== "role"
    )
      throw new NativeBoundaryV2Error("role artifact missing/wrong kind");
    const artifactDigest = digest(row.artifactDigest, "artifactDigest");
    if (artifactDigests.get(artifactId) !== artifactDigest)
      throw new NativeBoundaryV2Error("role artifact digest mismatch");
    const credentials = validateIdentifiers(
      row.credentialDomains,
      1,
      "credentialDomains",
    );
    if (klass !== "D3" && credentials.length)
      throw new NativeBoundaryV2Error("credentials outside D3");
    validateIdentifiers(row.allowedChannelIds, 128, "allowedChannelIds");
    for (const key of ["uid", "gid"] as const) uint(row[key], key);
    list(row.supplementaryGroups, 32, "supplementaryGroups", (value) =>
      uint(value, "supplementaryGroup"),
    );
    const namespaces = exactRecord(
      row.namespaces,
      ["user", "pid", "mount", "network", "ipc", "cgroup"],
      "namespaces",
    );
    for (const key of Object.keys(namespaces))
      bool(namespaces[key], `namespaces.${key}`);
    list(row.mounts, 128, "mounts", (value, mountIndex) => {
      const mount = exactRecord(
        value,
        ["sourceArtifactId", "target", "readOnly", "nodev", "nosuid", "noexec"],
        `mounts[${mountIndex}]`,
      );
      if (!artifactIds.has(text(mount.sourceArtifactId, "sourceArtifactId")))
        throw new NativeBoundaryV2Error("mount artifact missing");
      absolutePath(mount.target, "mount target");
      for (const key of ["readOnly", "nodev", "nosuid", "noexec"] as const)
        bool(mount[key], key);
      return mount;
    });
    const cgroup = exactRecord(
      row.cgroup,
      ["pathId", "memoryMax", "pidsMax", "cpuMaxMicros", "ioMaxDigest"],
      "cgroup",
    );
    text(cgroup.pathId, "cgroup path");
    for (const key of ["memoryMax", "pidsMax", "cpuMaxMicros"] as const)
      uint(cgroup[key], key);
    digest(cgroup.ioMaxDigest, "ioMaxDigest");
    const rlimits = exactRecord(
      row.rlimits,
      ["nofile", "nproc", "core", "fsize", "addressSpace"],
      "rlimits",
    );
    for (const key of Object.keys(rlimits))
      uint(rlimits[key], `rlimits.${key}`);
    if (
      bool(row.capabilitiesEmpty, "capabilitiesEmpty") !== true ||
      bool(row.dumpable, "dumpable") !== false
    )
      throw new NativeBoundaryV2Error("role privilege booleans unsafe");
    for (const key of [
      "launchSeccompDigest",
      "steadySeccompDigest",
      "landlockDigest",
    ] as const)
      digest(row[key], key);
    validateIdentifiers(row.environmentAllowlist, 64, "environmentAllowlist");
    list(row.inheritedFdSlots, 64, "inheritedFdSlots", (value) =>
      uint(value, "inheritedFdSlot"),
    );
    const required = validateIdentifiers(
      row.requiredMeasurementFields,
      128,
      "requiredMeasurementFields",
    );
    if (
      required.length !== NATIVE_V2_MEASUREMENT_FIELDS.length ||
      required.some(
        (field, index) => field !== NATIVE_V2_MEASUREMENT_FIELDS[index],
      )
    )
      throw new NativeBoundaryV2Error("requiredMeasurementFields invalid");
    return row;
  });
  if (roles.length === 0)
    throw new NativeBoundaryV2Error("deployment roles empty");
  uniqueSorted(roles, (row) => row.roleId as string, "deployment roles");
  if (new Set(roles.map((row) => row.principalId)).size !== roles.length)
    throw new NativeBoundaryV2Error("role principals duplicate");
  const roleIds = new Set(roles.map((row) => row.roleId));
  const roleById = new Map(roles.map((row) => [row.roleId, row]));
  const channels = list(payload.channels, 128, "channels", (entry, index) => {
    const row = exactRecord(
      entry,
      [
        "channelId",
        "fromEndpoint",
        "toEndpoint",
        "socketType",
        "direction",
        "maxFrameBytes",
        "maxDescriptors",
        "peerCredentialPolicy",
        "oneShot",
      ],
      `channels[${index}]`,
    );
    text(row.channelId, "channelId");
    text(row.fromEndpoint, "fromEndpoint");
    text(row.toEndpoint, "toEndpoint");
    if (row.fromEndpoint === row.toEndpoint)
      throw new NativeBoundaryV2Error("channel self-loop refused");
    enumText(row.socketType, ["seqpacket"], "socketType");
    enumText(row.direction, ["one-way", "request-response"], "direction");
    const frame = uint(row.maxFrameBytes, "maxFrameBytes");
    const descriptors = uint(row.maxDescriptors, "maxDescriptors");
    if (
      frame === 0n ||
      frame > BigInt(NATIVE_BOUNDARY_V2.maxFrameBytes) ||
      descriptors > 64n
    )
      throw new NativeBoundaryV2Error("channel operational bounds invalid");
    enumText(
      row.peerCredentialPolicy,
      ["exact-principal"],
      "peerCredentialPolicy",
    );
    bool(row.oneShot, "oneShot");
    return row;
  });
  uniqueSorted(channels, (row) => row.channelId as string, "channels");
  const channelIds = new Set(channels.map((row) => row.channelId));
  const probers = list(payload.probers, 1, "probers", (entry) => {
    const row = exactRecord(
      entry,
      [
        "proberId",
        "artifactId",
        "principalId",
        "signingKeyId",
        "keyEpoch",
        "channelId",
        "observationGrants",
        "requiredNegativeProbes",
      ],
      "prober",
    );
    for (const key of [
      "proberId",
      "principalId",
      "signingKeyId",
      "channelId",
    ] as const)
      text(row[key], key);
    const artifactId = text(row.artifactId, "artifactId");
    if (
      !artifactIds.has(artifactId) ||
      artifactKinds.get(artifactId) !== "prober"
    )
      throw new NativeBoundaryV2Error("prober artifact missing/wrong kind");
    uint(row.keyEpoch, "keyEpoch");
    validateIdentifiers(row.observationGrants, 128, "observationGrants");
    validateIdentifiers(
      row.requiredNegativeProbes,
      128,
      "requiredNegativeProbes",
    );
    return row;
  });
  if (
    probers.length !== 1 ||
    roles.some((row) => row.principalId === probers[0]!.principalId)
  )
    throw new NativeBoundaryV2Error(
      "exactly one independently-principalled prober required",
    );
  const provisioners = list(
    payload.provisioners,
    32,
    "provisioners",
    (entry, index) => {
      const row = exactRecord(
        entry,
        [
          "provisionerId",
          "domain",
          "principalId",
          "artifactId",
          "targetRoleId",
          "channelId",
          "descriptorType",
          "requiredSeals",
          "descriptorCount",
          "destructionDeadlineMs",
        ],
        `provisioners[${index}]`,
      );
      for (const key of [
        "provisionerId",
        "domain",
        "principalId",
        "targetRoleId",
        "channelId",
        "descriptorType",
      ] as const)
        text(row[key], key);
      const artifactId = text(row.artifactId, "artifactId");
      const target = roleById.get(row.targetRoleId);
      const channel = channels.find(
        (channel) => channel.channelId === row.channelId,
      );
      if (
        !artifactIds.has(artifactId) ||
        artifactKinds.get(artifactId) !== "provisioner" ||
        !target ||
        target.roleClass !== "D3" ||
        !channel ||
        (channel.fromEndpoint !== `role:${row.targetRoleId}` &&
          channel.toEndpoint !== `role:${row.targetRoleId}`)
      )
        throw new NativeBoundaryV2Error("provisioner reference/kind missing");
      if (
        !Array.isArray(target.credentialDomains) ||
        target.credentialDomains.length !== 1 ||
        target.credentialDomains[0] !== row.domain
      )
        throw new NativeBoundaryV2Error(
          "provisioner domain does not exactly own target D3 credential",
        );
      validateIdentifiers(row.requiredSeals, 16, "requiredSeals");
      if (uint(row.descriptorCount, "descriptorCount") !== 1n)
        throw new NativeBoundaryV2Error("descriptorCount must equal one");
      uint(row.destructionDeadlineMs, "destructionDeadlineMs");
      return row;
    },
  );
  uniqueSorted(
    provisioners,
    (row) => row.provisionerId as string,
    "provisioners",
  );
  if (
    new Set(provisioners.map((row) => row.domain)).size !==
      provisioners.length ||
    new Set(provisioners.map((row) => row.principalId)).size !==
      provisioners.length ||
    provisioners.some(
      (row) =>
        roles.some((role) => role.principalId === row.principalId) ||
        row.principalId === probers[0]!.principalId,
    )
  )
    throw new NativeBoundaryV2Error("provisioner identity/domain aliases");
  const b3 = exactRecord(
    payload.b3,
    [
      "authorityId",
      "genesisBaseDigest",
      "b3ProfileEnvelopeDigest",
      "keyEpoch",
      "assurance",
      "channelId",
    ],
    "b3",
  );
  text(b3.authorityId, "authorityId");
  digest(b3.genesisBaseDigest, "genesisBaseDigest");
  digest(b3.b3ProfileEnvelopeDigest, "b3ProfileEnvelopeDigest");
  uint(b3.keyEpoch, "keyEpoch");
  enumText(b3.assurance, ["load-bearing"], "b3 assurance");
  text(b3.channelId, "channelId");
  const endpointIds = new Set<string>([
    "supervisor:keep",
    ...roles.map((row) => `role:${row.roleId}`),
    `prober:${probers[0]!.proberId}`,
    `b3:${b3.authorityId}`,
    ...provisioners.map((row) => `provisioner:${row.provisionerId}`),
  ]);
  for (const channel of channels)
    if (
      !endpointIds.has(channel.fromEndpoint as string) ||
      !endpointIds.has(channel.toEndpoint as string)
    )
      throw new NativeBoundaryV2Error(
        "channel endpoint outside typed topology",
      );
  for (const role of roles)
    for (const channelId of role.allowedChannelIds as string[]) {
      const channel = channels.find((row) => row.channelId === channelId);
      if (
        !channel ||
        (channel.fromEndpoint !== `role:${role.roleId}` &&
          channel.toEndpoint !== `role:${role.roleId}`)
      )
        throw new NativeBoundaryV2Error("role channel missing/unrelated");
    }
  const proberChannel = channels.find(
    (row) => row.channelId === probers[0]!.channelId,
  );
  if (
    !proberChannel ||
    proberChannel.fromEndpoint !== `prober:${probers[0]!.proberId}` ||
    proberChannel.toEndpoint !== "supervisor:keep" ||
    proberChannel.direction !== "request-response" ||
    proberChannel.maxDescriptors !== 0n ||
    proberChannel.oneShot !== false
  )
    throw new NativeBoundaryV2Error("prober channel topology mismatch");
  const b3Channel = channels.find((row) => row.channelId === b3.channelId);
  if (
    !b3Channel ||
    b3Channel.fromEndpoint !== "supervisor:keep" ||
    b3Channel.toEndpoint !== `b3:${b3.authorityId}` ||
    b3Channel.direction !== "request-response" ||
    b3Channel.maxDescriptors !== 0n ||
    b3Channel.oneShot !== false
  )
    throw new NativeBoundaryV2Error("B3 channel topology mismatch");
  for (const provisioner of provisioners) {
    const channel = channels.find(
      (row) => row.channelId === provisioner.channelId,
    );
    if (
      !channel ||
      channel.fromEndpoint !== `provisioner:${provisioner.provisionerId}` ||
      channel.toEndpoint !== `role:${provisioner.targetRoleId}` ||
      channel.direction !== "one-way" ||
      channel.maxDescriptors !== 1n ||
      channel.oneShot !== true
    )
      throw new NativeBoundaryV2Error("provisioner channel topology mismatch");
  }
  const authorityChannelIds = new Set<string>([
    probers[0]!.channelId as string,
    b3.channelId as string,
    ...provisioners.map((row) => row.channelId as string),
  ]);
  for (const channel of channels) {
    const participants = roles.filter(
      (role) =>
        channel.fromEndpoint === `role:${role.roleId}` ||
        channel.toEndpoint === `role:${role.roleId}`,
    );
    if (
      !authorityChannelIds.has(channel.channelId as string) &&
      participants.length === 0
    )
      throw new NativeBoundaryV2Error(
        "channel has no declared owner or authority purpose",
      );
    if (
      participants.some(
        (role) =>
          !(role.allowedChannelIds as string[]).includes(
            channel.channelId as string,
          ),
      )
    )
      throw new NativeBoundaryV2Error(
        "channel grants an undeclared role participant",
      );
  }
  const usedArtifacts = new Set<string>([
    artifacts.find((row) => row.kind === "helper")!.artifactId as string,
    artifacts.find((row) => row.kind === "trampoline")!.artifactId as string,
    probers[0]!.artifactId as string,
    ...roles.map((row) => row.artifactId as string),
    ...provisioners.map((row) => row.artifactId as string),
  ]);
  if (
    usedArtifacts.size !== artifacts.length ||
    artifacts.some((row) => !usedArtifacts.has(row.artifactId as string))
  )
    throw new NativeBoundaryV2Error(
      "orphan or multiply-purposed artifact refused",
    );
  const release = exactRecord(
    payload.release,
    [
      "buildId",
      "artifactVersion",
      "targetTriple",
      "variant",
      "releaseKeyEpoch",
      "timestampKeyEpoch",
    ],
    "release",
  );
  text(release.buildId, "buildId");
  const artifactVersion = uint(release.artifactVersion, "artifactVersion");
  const targetTriple = text(release.targetTriple, "targetTriple");
  const variant = text(release.variant, "variant");
  uint(release.releaseKeyEpoch, "releaseKeyEpoch");
  uint(release.timestampKeyEpoch, "timestampKeyEpoch");
  if (
    artifacts.some(
      (row) => row.targetTriple !== targetTriple || row.variant !== variant,
    )
  )
    throw new NativeBoundaryV2Error("release target/variant mismatch");
  const revocation = exactRecord(
    payload.revocation,
    [
      "authorityId",
      "keyEpoch",
      "namespace",
      "scope",
      "genesisCheckpointEnvelopeDigest",
      "minimumSequence",
      "maxStalenessCounters",
      "compromiseSemantics",
    ],
    "revocation",
  );
  for (const key of [
    "authorityId",
    "namespace",
    "scope",
    "compromiseSemantics",
  ] as const)
    text(revocation[key], key);
  uint(revocation.keyEpoch, "keyEpoch");
  digest(
    revocation.genesisCheckpointEnvelopeDigest,
    "genesisCheckpointEnvelopeDigest",
  );
  uint(revocation.minimumSequence, "minimumSequence");
  uint(revocation.maxStalenessCounters, "maxStalenessCounters");
  const rollback = exactRecord(
    payload.rollback,
    [
      "deploymentEpoch",
      "minimumArtifactVersion",
      "predecessorDigest",
      "authorizedRollbackEnvelopeDigest",
    ],
    "rollback",
  );
  if (
    uint(rollback.deploymentEpoch, "deploymentEpoch") !==
      payload.deploymentEpoch ||
    uint(rollback.minimumArtifactVersion, "minimumArtifactVersion") >
      artifactVersion
  )
    throw new NativeBoundaryV2Error("rollback epoch/version mismatch");
  digest(rollback.predecessorDigest, "predecessorDigest");
  digest(
    rollback.authorizedRollbackEnvelopeDigest,
    "authorizedRollbackEnvelopeDigest",
  );
  const evidence = exactRecord(
    payload.evidence,
    [
      "schema",
      "sinkId",
      "maxBundleBytes",
      "algorithm",
      "keyId",
      "keyEpoch",
      "appendPolicy",
      "witnessPolicy",
    ],
    "evidence",
  );
  if (
    evidence.schema !== "keep.native-evidence" ||
    evidence.algorithm !== "ed25519"
  )
    throw new NativeBoundaryV2Error("evidence schema/algorithm mismatch");
  text(evidence.sinkId, "sinkId");
  if (uint(evidence.maxBundleBytes, "maxBundleBytes") !== 8n * 1024n * 1024n)
    throw new NativeBoundaryV2Error("evidence bundle bound mismatch");
  if (
    text(evidence.keyId, "keyId") !== probers[0]!.signingKeyId ||
    uint(evidence.keyEpoch, "keyEpoch") !== probers[0]!.keyEpoch
  )
    throw new NativeBoundaryV2Error("evidence key/prober mismatch");
  enumText(evidence.appendPolicy, ["create-exclusive-fsync"], "appendPolicy");
  enumText(evidence.witnessPolicy, ["external-prober"], "witnessPolicy");
  if (payload.deploymentBaseDigest !== nativeDeploymentBaseDigest(payload))
    throw new NativeBoundaryV2Error("deployment base digest mismatch");
}

function validateScalarPayload(
  payload: Record<string, CanonicalValue>,
  schema: NativeV2Schema,
): void {
  const digestKeys =
    schema === "native-index"
      ? [
          "a4ReleaseBaseDigest",
          "deploymentEnvelopeDigest",
          "nativeClosureEnvelopeDigest",
          "b0RootEnvelopeDigest",
        ]
      : [
          "a4ReleaseBaseDigest",
          "a4ArtifactInventoryDigest",
          "nativeArtifactInventoryDigest",
          "nativeDeploymentPayloadDigest",
          "nativeDeploymentEnvelopeDigest",
          "nativePackagePayloadDigest",
          "nativeClosureBaseDigest",
          "helperArtifactDigest",
          "trampolineArtifactDigest",
          "proberArtifactDigest",
          "protocolDigest",
          "evidenceSchemaDigest",
          "timestampRecordEnvelopeDigest",
          "sbomEnvelopeDigest",
          "reproducibilityRecordEnvelopeDigest",
          "toolchainClosureEnvelopeDigest",
          "releaseTimeRevocationCheckpointEnvelopeDigest",
          "predecessorDigest",
          "authorizedRollbackEnvelopeDigest",
          "b0RootEnvelopeDigest",
          "b3ProfileEnvelopeDigest",
        ];
  for (const key of digestKeys) digest(payload[key], key);
  if (schema === "native-index") {
    uint(payload.releaseKeyEpoch, "releaseKeyEpoch");
    return;
  }
  validateDigests(
    payload.provisionerArtifactDigests,
    32,
    "provisionerArtifactDigests",
  );
  if (
    payload.nativeClosureBaseDigest !==
    nativeReleaseClosureBaseDigest(payload)
  )
    throw new NativeBoundaryV2Error("native closure base digest mismatch");
  validateDigests(
    payload.provenanceEnvelopeDigests,
    32,
    "provenanceEnvelopeDigests",
  );
  for (const key of ["targetTriple", "variant", "buildId"] as const)
    text(payload[key], key);
  for (const key of [
    "artifactVersion",
    "releaseKeyEpoch",
    "timestampKeyEpoch",
    "releaseTimeRevocationSequence",
    "deploymentEpoch",
    "minimumArtifactVersion",
  ] as const)
    uint(payload[key], key);
}

function validateRevocation(payload: Record<string, CanonicalValue>): void {
  for (const key of [
    "authorityId",
    "namespace",
    "scope",
    "compromiseSemantics",
  ] as const)
    text(payload[key], key);
  for (const key of [
    "keyEpoch",
    "sequence",
    "issuedCounter",
    "expiresCounter",
  ] as const)
    uint(payload[key], key);
  digest(payload.previousEnvelopeDigest, "previousEnvelopeDigest");
  validateIdentifiers(payload.revokedKeys, 256, "revokedKeys");
  validateDigests(payload.revokedArtifacts, 256, "revokedArtifacts");
  const cutoffs = list(
    payload.rotationCutoffs,
    1024,
    "rotationCutoffs",
    (entry, index) => {
      const row = exactRecord(
        entry,
        ["keyId", "minimumEpoch"],
        `rotationCutoffs[${index}]`,
      );
      text(row.keyId, "keyId");
      uint(row.minimumEpoch, "minimumEpoch");
      return row;
    },
  );
  uniqueSorted(cutoffs, (row) => row.keyId as string, "rotationCutoffs");
  if ((payload.expiresCounter as bigint) <= (payload.issuedCounter as bigint))
    throw new NativeBoundaryV2Error("revocation counter order invalid");
}

function validateMeasurementValue(field: string, value: unknown): void {
  const record = (type: string, keys: readonly string[]) => {
    const row = exactRecord(
      value,
      ["type", ...keys],
      `measurement.${field}.value`,
    );
    if (row.type !== type)
      throw new NativeBoundaryV2Error(
        `measurement ${field} value discriminator mismatch`,
      );
    return row;
  };
  if (field.startsWith("identity.uid.") || field.startsWith("identity.gid.")) {
    uint(record("uint64", ["value"]).value, "value");
    return;
  }
  if (field === "identity.groups") {
    const row = record("uint64-set", ["values"]);
    const values = list(row.values, 64, "values", (entry) =>
      uint(entry, "value"),
    );
    if (values.some((entry, index) => index > 0 && values[index - 1]! >= entry))
      throw new NativeBoundaryV2Error("uint64 set not sorted unique");
    return;
  }
  if (field.startsWith("security.capabilities.")) {
    validateIdentifiers(
      record("identifier-set", ["values"]).values,
      128,
      "capabilities",
    );
    return;
  }
  if (field === "security.dumpable" || field === "security.no-new-privileges") {
    bool(record("boolean", ["value"]).value, "value");
    return;
  }
  if (field === "loader.executable") {
    digest(record("digest", ["value"]).value, "value");
    return;
  }
  if (field === "loader.shared-libraries") {
    validateDigests(
      record("digest-set", ["values"]).values,
      256,
      "library digests",
    );
    return;
  }
  if (field === "namespaces.inodes") {
    const row = record("namespace-inodes", [
      "user",
      "pid",
      "mount",
      "network",
      "ipc",
      "cgroup",
    ]);
    for (const key of [
      "user",
      "pid",
      "mount",
      "network",
      "ipc",
      "cgroup",
    ] as const)
      uint(row[key], key);
    return;
  }
  if (field === "cgroup.limits") {
    const row = record("cgroup-limits", [
      "memoryMax",
      "pidsMax",
      "cpuMaxMicros",
      "ioMaxDigest",
    ]);
    for (const key of ["memoryMax", "pidsMax", "cpuMaxMicros"] as const)
      uint(row[key], key);
    digest(row.ioMaxDigest, "ioMaxDigest");
    return;
  }
  if (field === "seccomp.launch" || field === "seccomp.steady") {
    const row = record("seccomp-policy", [
      "architecture",
      "defaultAction",
      "allowedActions",
      "filterDigest",
      "noNewPrivileges",
    ]);
    text(row.architecture, "architecture");
    text(row.defaultAction, "defaultAction");
    validateIdentifiers(row.allowedActions, 256, "allowedActions");
    digest(row.filterDigest, "filterDigest");
    if (bool(row.noNewPrivileges, "noNewPrivileges") !== true)
      throw new NativeBoundaryV2Error("seccomp lacks no-new-privileges");
    return;
  }
  if (field === "landlock.policy") {
    const row = record("landlock-policy", [
      "abi",
      "handledRights",
      "scopedRights",
      "rulesetDigest",
    ]);
    uint(row.abi, "abi");
    validateIdentifiers(row.handledRights, 256, "handledRights");
    validateIdentifiers(row.scopedRights, 256, "scopedRights");
    digest(row.rulesetDigest, "rulesetDigest");
    return;
  }
  if (field === "mount.topology") {
    const row = record("mount-topology", ["entries"]);
    list(row.entries, 128, "mount entries", (entry, index) => {
      const mount = exactRecord(
        entry,
        ["target", "sourceDigest", "readOnly", "nodev", "nosuid", "noexec"],
        `mount entries[${index}]`,
      );
      absolutePath(mount.target, "target");
      digest(mount.sourceDigest, "sourceDigest");
      for (const key of ["readOnly", "nodev", "nosuid", "noexec"] as const)
        bool(mount[key], key);
      return mount;
    });
    return;
  }
  if (field === "network.topology") {
    const row = record("network-topology", [
      "interfaces",
      "routes",
      "addressFamilies",
    ]);
    validateIdentifiers(row.interfaces, 128, "interfaces");
    validateIdentifiers(row.routes, 256, "routes");
    validateIdentifiers(row.addressFamilies, 32, "addressFamilies");
    return;
  }
  if (field === "fd.inventory") {
    const row = record("descriptor-inventory", ["entries"]);
    list(row.entries, 256, "descriptor entries", (entry, index) => {
      const fd = exactRecord(
        entry,
        ["slot", "purpose", "flagsDigest", "seals", "credentialDomain"],
        `descriptor entries[${index}]`,
      );
      uint(fd.slot, "slot");
      text(fd.purpose, "purpose");
      digest(fd.flagsDigest, "flagsDigest");
      validateIdentifiers(fd.seals, 32, "seals");
      if (fd.credentialDomain !== null)
        text(fd.credentialDomain, "credentialDomain");
      return fd;
    });
    return;
  }
  if (field === "credential.state") {
    const row = record("credential-state", [
      "domains",
      "deliveredAfterAttestation",
      "descriptorCount",
    ]);
    validateIdentifiers(row.domains, 32, "domains");
    if (
      bool(row.deliveredAfterAttestation, "deliveredAfterAttestation") !== true
    )
      throw new NativeBoundaryV2Error(
        "credential delivered before attestation",
      );
    uint(row.descriptorCount, "descriptorCount");
    return;
  }
  if (field === "incarnation") {
    const row = record("incarnation", [
      "pidfdDigest",
      "startCounter",
      "expiresCounter",
    ]);
    digest(row.pidfdDigest, "pidfdDigest");
    if (
      uint(row.expiresCounter, "expiresCounter") <
      uint(row.startCounter, "startCounter")
    )
      throw new NativeBoundaryV2Error("incarnation counter order invalid");
    return;
  }
  if (field === "capture.window") {
    const row = record("counter-window", ["capturedCounter", "expiresCounter"]);
    if (
      uint(row.expiresCounter, "expiresCounter") <
      uint(row.capturedCounter, "capturedCounter")
    )
      throw new NativeBoundaryV2Error("capture window order invalid");
    return;
  }
  throw new NativeBoundaryV2Error("measurement field outside registry");
}

function validateEvidence(
  root: Record<string, CanonicalValue>,
  trust: NativeV2TrustClass,
): void {
  for (const key of [
    "deploymentId",
    "bootId",
    "kernelBootId",
    "helperBuildId",
    "requestId",
    "requestNonce",
    "challengeNonce",
    "proberId",
    "proberPrincipal",
  ] as const)
    text(root[key], key);
  for (const key of [
    "deploymentEpoch",
    "requestSequence",
    "b3Counter",
    "capturedCounter",
    "expiresCounter",
    "proberKeyEpoch",
  ] as const)
    uint(root[key], key);
  for (const key of [
    "manifestDigest",
    "nativeClosureEnvelopeDigest",
    "helperArtifactDigest",
    "helperIncarnation",
    "protocolDigest",
    "requestDigest",
    "b3ProfileEnvelopeDigest",
    "b3LeaseReceiptEnvelopeDigest",
    "proberArtifactDigest",
    "proberIncarnation",
    "revocationEnvelopeDigest",
    "previousEvidenceDigest",
  ] as const)
    digest(root[key], key);
  if (
    (root.expiresCounter as bigint) < (root.capturedCounter as bigint) ||
    (root.capturedCounter as bigint) < (root.b3Counter as bigint)
  )
    throw new NativeBoundaryV2Error("evidence counter order invalid");
  const roles = list(root.roles, 32, "evidence roles", (entry, index) => {
    const row = exactRecord(
      entry,
      [
        "roleId",
        "roleClass",
        "principalId",
        "artifactDigest",
        "incarnationDigest",
        "uid",
        "gid",
        "groups",
        "namespaceInodes",
        "cgroupId",
      ],
      `evidence roles[${index}]`,
    );
    text(row.roleId, "roleId");
    roleClass(row.roleClass);
    text(row.principalId, "principalId");
    digest(row.artifactDigest, "artifactDigest");
    digest(row.incarnationDigest, "incarnationDigest");
    uint(row.uid, "uid");
    uint(row.gid, "gid");
    list(row.groups, 32, "groups", (value) => uint(value, "group"));
    const namespaces = exactRecord(
      row.namespaceInodes,
      ["user", "pid", "mount", "network", "ipc", "cgroup"],
      "namespaceInodes",
    );
    for (const key of Object.keys(namespaces))
      uint(namespaces[key], `namespaceInodes.${key}`);
    text(row.cgroupId, "cgroupId");
    return row;
  });
  uniqueSorted(roles, (row) => row.roleId as string, "evidence roles");
  const roleIds = new Set(roles.map((row) => row.roleId));
  const measurements = list(
    root.measurements,
    1024,
    "evidence measurements",
    (entry, index) => {
      const row = exactRecord(
        entry,
        [
          "measurementId",
          "roleId",
          "field",
          "value",
          "mechanism",
          "mechanismVersion",
          "abi",
          "source",
          "transcriptDigest",
          "state",
          "reasonCode",
        ],
        `evidence measurements[${index}]`,
      );
      text(row.measurementId, "measurementId");
      if (!roleIds.has(text(row.roleId, "roleId")))
        throw new NativeBoundaryV2Error("measurement role absent");
      const field = text(row.field, "field");
      if (!MEASUREMENT_FIELDS.has(field))
        throw new NativeBoundaryV2Error("measurement field outside registry");
      for (const key of [
        "mechanism",
        "mechanismVersion",
        "abi",
        "source",
        "reasonCode",
      ] as const)
        text(row[key], key);
      validateMeasurementValue(field, row.value);
      digest(row.transcriptDigest, "transcriptDigest");
      enumText(
        row.state,
        ["active", "inactive", "unsupported", "inconclusive"],
        "measurement state",
      );
      return row;
    },
  );
  uniqueSorted(
    measurements,
    (row) => row.measurementId as string,
    "measurements",
  );
  const measurementPairs = new Set(
    measurements.map((row) => `${row.roleId}:${row.field}`),
  );
  if (
    roles.length === 0 ||
    measurementPairs.size !== measurements.length ||
    roles.some((role) =>
      NATIVE_V2_MEASUREMENT_FIELDS.some(
        (field) => !measurementPairs.has(`${role.roleId}:${field}`),
      ),
    )
  )
    throw new NativeBoundaryV2Error(
      "measurement registry coverage incomplete or duplicated",
    );
  const measured = new Map(
    measurements.map((row) => [
      `${row.roleId}:${row.field}`,
      row.value as Record<string, unknown>,
    ]),
  );
  for (const role of roles) {
    const value = (field: string) => measured.get(`${role.roleId}:${field}`)!;
    for (const field of [
      "identity.uid.real",
      "identity.uid.effective",
      "identity.uid.saved",
    ])
      if (value(field).value !== role.uid)
        throw new NativeBoundaryV2Error("UID evidence contradiction");
    for (const field of [
      "identity.gid.real",
      "identity.gid.effective",
      "identity.gid.saved",
    ])
      if (value(field).value !== role.gid)
        throw new NativeBoundaryV2Error("GID evidence contradiction");
    if (
      encodeCanonical(
        value("identity.groups").values as CanonicalValue,
      ).toString() !== encodeCanonical(role.groups as CanonicalValue).toString()
    )
      throw new NativeBoundaryV2Error("group evidence contradiction");
    const namespaceValue = value("namespaces.inodes");
    for (const key of ["user", "pid", "mount", "network", "ipc", "cgroup"])
      if (
        namespaceValue[key] !==
        (role.namespaceInodes as Record<string, unknown>)[key]
      )
        throw new NativeBoundaryV2Error("namespace evidence contradiction");
    if (value("incarnation").pidfdDigest !== role.incarnationDigest)
      throw new NativeBoundaryV2Error("incarnation evidence contradiction");
    if (value("loader.executable").value !== role.artifactDigest)
      throw new NativeBoundaryV2Error("executable evidence contradiction");
  }
  const probes = list(
    root.negativeProbes,
    256,
    "negativeProbes",
    (entry, index) => {
      const row = exactRecord(
        entry,
        [
          "probeId",
          "roleId",
          "target",
          "action",
          "expectedField",
          "observedDenial",
          "errno",
          "signal",
          "controlDigest",
        ],
        `negativeProbes[${index}]`,
      );
      text(row.probeId, "probeId");
      if (!roleIds.has(text(row.roleId, "roleId")))
        throw new NativeBoundaryV2Error("probe role absent");
      for (const key of ["target", "action", "errno", "signal"] as const)
        text(row[key], key);
      if (!MEASUREMENT_FIELDS.has(text(row.expectedField, "expectedField")))
        throw new NativeBoundaryV2Error("probe field outside registry");
      bool(row.observedDenial, "observedDenial");
      digest(row.controlDigest, "controlDigest");
      return row;
    },
  );
  uniqueSorted(probes, (row) => row.probeId as string, "negativeProbes");
  const fds = list(
    root.inheritedFdInventory,
    256,
    "inheritedFdInventory",
    (entry, index) => {
      const row = exactRecord(
        entry,
        ["roleId", "slot", "purpose", "flagsDigest", "peerPrincipalId"],
        `inheritedFdInventory[${index}]`,
      );
      if (!roleIds.has(text(row.roleId, "roleId")))
        throw new NativeBoundaryV2Error("fd role absent");
      uint(row.slot, "slot");
      text(row.purpose, "purpose");
      digest(row.flagsDigest, "flagsDigest");
      text(row.peerPrincipalId, "peerPrincipalId");
      return row;
    },
  );
  const fdKeys = fds.map((row) => `${row.roleId}:${row.slot}`);
  if (new Set(fdKeys).size !== fdKeys.length)
    throw new NativeBoundaryV2Error("fd inventory duplicates");
  const cleanup = exactRecord(
    root.cleanup,
    [
      "state",
      "killedRoleIds",
      "reapedRoleIds",
      "closedFdCount",
      "revokedCredentialDomains",
      "journalDigest",
      "recoveryRequired",
    ],
    "cleanup",
  );
  enumText(
    cleanup.state,
    ["not-required", "complete", "failed"],
    "cleanup state",
  );
  validateIdentifiers(cleanup.killedRoleIds, 32, "killedRoleIds");
  validateIdentifiers(cleanup.reapedRoleIds, 32, "reapedRoleIds");
  uint(cleanup.closedFdCount, "closedFdCount");
  validateIdentifiers(
    cleanup.revokedCredentialDomains,
    32,
    "revokedCredentialDomains",
  );
  digest(cleanup.journalDigest, "journalDigest");
  bool(cleanup.recoveryRequired, "recoveryRequired");
  const signature = exactRecord(
    root.signature,
    ["keyId", "algorithm", "keyEpoch", "signature"],
    "evidence signature",
  );
  const keyId = text(signature.keyId, "keyId");
  if (trust === "development" && !keyId.startsWith("development."))
    throw new NativeBoundaryV2Error(
      "development evidence key namespace required",
    );
  if (trust === "production" && keyId.startsWith("development."))
    throw new NativeBoundaryV2Error("development evidence key refused");
  if (signature.algorithm !== "ed25519")
    throw new NativeBoundaryV2Error("evidence signature algorithm unsupported");
  if (uint(signature.keyEpoch, "keyEpoch") !== root.proberKeyEpoch)
    throw new NativeBoundaryV2Error("evidence signature/prober epoch mismatch");
  signatureBytes(signature.signature, "signature");
}

export type NativeV2Schema =
  | "deployment"
  | "native-closure"
  | "native-index"
  | "revocation"
  | "evidence";
export interface CapturedNativeV2Document {
  readonly schema: NativeV2Schema;
  readonly admittedTrust: NativeV2TrustClass;
  readonly canonicalHex: string;
  readonly contentDigest: string;
}
function capturedDocument(
  owned: CanonicalValue,
  schema: NativeV2Schema,
  admittedTrust: NativeV2TrustClass,
): CapturedNativeV2Document {
  const bytes = encodeCanonical(owned);
  return Object.freeze({
    schema,
    admittedTrust,
    canonicalHex: Buffer.from(bytes).toString("hex"),
    contentDigest: createHash("sha256").update(bytes).digest("hex"),
  });
}
export function captureNativeV2Schema(
  input: unknown,
  schema: NativeV2Schema,
  admittedTrust: NativeV2TrustClass,
): CapturedNativeV2Document {
  const owned = inert(
    input,
    schema,
    schema === "evidence" ? 8 * 1024 * 1024 : 4 * 1024 * 1024,
  );
  const root = map(owned, schema);
  if (schema === "evidence") {
    exact(root, EVIDENCE_KEYS, schema);
    if (root.schema !== "keep.native-evidence" || root.version !== 1n)
      throw new NativeBoundaryV2Error("evidence schema/version mismatch");
    validateEvidence(root, admittedTrust);
    return capturedDocument(owned, schema, admittedTrust);
  }
  exact(root, ENVELOPE_KEYS, `${schema} envelope`);
  const payloadDigest = digest(root.payloadDigest, "payloadDigest");
  const payload = map(root.payload, `${schema} payload`);
  const computed = createHash("sha256")
    .update(encodeCanonical(payload))
    .digest("hex");
  if (payloadDigest !== computed)
    throw new NativeBoundaryV2Error(`${schema} payload digest mismatch`);
  const signatures = list(root.signatures, 32, "signatures", (entry, index) => {
    const signature = map(entry, `signatures[${index}]`);
    exact(
      signature,
      ["keyId", "algorithm", "keyEpoch", "signature"],
      `signatures[${index}]`,
    );
    const keyId = text(signature.keyId, "keyId");
    if (signature.algorithm !== "ed25519")
      throw new NativeBoundaryV2Error("signature algorithm unsupported");
    const keyEpoch = uint(signature.keyEpoch, "keyEpoch");
    signatureBytes(signature.signature, "signature");
    return { keyId, keyEpoch };
  });
  if (signatures.length === 0)
    throw new NativeBoundaryV2Error("signatures empty");
  if (
    admittedTrust === "development" &&
    signatures.some((row) => !row.keyId.startsWith("development."))
  )
    throw new NativeBoundaryV2Error(
      "development signature key namespace required",
    );
  if (
    admittedTrust === "production" &&
    signatures.some((row) => row.keyId.startsWith("development."))
  )
    throw new NativeBoundaryV2Error("development signature key refused");
  const definition =
    schema === "deployment"
      ? ([DEPLOYMENT_KEYS, "keep.native-deployment"] as const)
      : schema === "native-closure"
        ? ([CLOSURE_KEYS, "keep.native-release-closure"] as const)
        : schema === "native-index"
          ? ([INDEX_KEYS, "keep.native-release-index"] as const)
          : ([REVOCATION_KEYS, "keep.native-revocation"] as const);
  exact(payload, definition[0], `${schema} payload`);
  if (payload.schema !== definition[1] || payload.version !== 1n)
    throw new NativeBoundaryV2Error(`${schema} discriminator mismatch`);
  if (schema !== "revocation") {
    if (payload.trustClass !== admittedTrust)
      throw new NativeBoundaryV2Error(`${schema} trust class refused`);
    if (admittedTrust === "production" && payload.trustClass !== "production")
      throw new NativeBoundaryV2Error(
        "development object refused in production",
      );
  }
  if (schema === "deployment") validateDeployment(payload);
  else if (schema === "native-closure" || schema === "native-index")
    validateScalarPayload(payload, schema);
  else validateRevocation(payload);
  const expectedEpoch =
    schema === "deployment"
      ? uint(map(payload.release, "release").releaseKeyEpoch, "releaseKeyEpoch")
      : schema === "revocation"
        ? uint(payload.keyEpoch, "keyEpoch")
        : uint(payload.releaseKeyEpoch, "releaseKeyEpoch");
  if (signatures.some((row) => row.keyEpoch !== expectedEpoch))
    throw new NativeBoundaryV2Error("signature key epoch mismatch");
  return capturedDocument(owned, schema, admittedTrust);
}
