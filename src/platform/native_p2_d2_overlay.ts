/**
 * P2-D2 authenticated patch-overlay capture.
 *
 * This module validates already-owned canonical bytes. It has no filesystem, process,
 * network, signature, admission, overlay-application, build, or launch capability.
 */
import { createHash } from "node:crypto";
import { types } from "node:util";
import { decodeCanonical, encodeCanonical, type CanonicalValue } from "../eir/canonical.js";
import { isCanonicalNativeP2RelativePath } from "./native_p2_path.js";

export const P2_D2_OVERLAY_LIMITS = Object.freeze({
  encodedBytes: 1024 * 1024,
  depth: 16,
  totalItems: 65_536,
  textBytes: 4_096,
  operations: 256,
  newFileBytes: 16n * 1024n * 1024n,
  aggregateNewBytes: 128n * 1024n * 1024n,
} as const);

const SCHEMA = "keep.p2-d2-patch-overlay";
const PACKAGE_ID = "curve25519-dalek@5.0.0";
const DOMAIN = "keep.p2-d2-patch-overlay/v1\0";
const EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const HEX64 = /^[0-9a-f]{64}$/;
const ALL_ZERO = "0".repeat(64);
const ROOT_KEYS = ["schema", "version", "packageId", "baseArchiveDigest", "operations", "rationale", "resultTreeDigest", "auditPlanDigest"] as const;
const OPERATION_KEYS = ["operation", "path", "oldByteDigest", "newByteDigest", "newByteLength"] as const;

export class NativeP2D2OverlayError extends Error {
  constructor(message: string) {
    super(`native P2-D2 overlay: ${message}`);
    this.name = "NativeP2D2OverlayError";
  }
}

export type NativePatchOperationKindV1 = "add" | "delete" | "replace";
export interface NativePatchOperationV1 {
  readonly operation: NativePatchOperationKindV1;
  readonly path: string;
  readonly oldByteDigest: string | null;
  readonly newByteDigest: string | null;
  readonly newByteLength: bigint | null;
}
export interface NativePatchOverlayV1 {
  readonly schema: typeof SCHEMA;
  readonly version: 1n;
  readonly packageId: typeof PACKAGE_ID;
  readonly baseArchiveDigest: string;
  readonly operations: readonly NativePatchOperationV1[];
  readonly rationale: string;
  readonly resultTreeDigest: string;
  readonly auditPlanDigest: string;
}
export type PatchOverlayDigest = string & { readonly __patchOverlayDigest: unique symbol };
export interface ValidatedPatchOverlayPlan {
  readonly kind: "ValidatedPatchOverlayPlan";
  readonly overlay: NativePatchOverlayV1;
  readonly patchOverlayDigest: PatchOverlayDigest;
  canonicalBytes(): Uint8Array;
}

function record(value: CanonicalValue, path: string): Record<string, CanonicalValue> {
  if (value === null || Array.isArray(value) || value instanceof Uint8Array || typeof value !== "object")
    throw new NativeP2D2OverlayError(`${path} is not a record`);
  return value as Record<string, CanonicalValue>;
}

function exactKeys(row: Record<string, CanonicalValue>, expected: readonly string[], path: string): void {
  const actual = Object.keys(row).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index]))
    throw new NativeP2D2OverlayError(`${path} fields are not exact`);
}

function nativeProfile(value: CanonicalValue): void {
  let items = 0;
  const walk = (entry: CanonicalValue, depth: number): void => {
    if (depth > P2_D2_OVERLAY_LIMITS.depth || ++items > P2_D2_OVERLAY_LIMITS.totalItems)
      throw new NativeP2D2OverlayError("aggregate depth/item bound violated");
    if (typeof entry === "string") {
      if (Buffer.byteLength(entry, "utf8") > P2_D2_OVERLAY_LIMITS.textBytes)
        throw new NativeP2D2OverlayError("text bound violated");
      if (![...Buffer.from(entry, "utf8")].every((byte) => byte === 0x0a || (byte >= 0x20 && byte <= 0x7e)))
        throw new NativeP2D2OverlayError("text is outside the native ASCII profile");
    }
    if (Array.isArray(entry)) entry.forEach((child) => walk(child, depth + 1));
    else if (entry !== null && typeof entry === "object" && !(entry instanceof Uint8Array))
      Object.entries(entry).forEach(([key, child]) => { walk(key, depth + 1); walk(child, depth + 1); });
  };
  walk(value, 0);
}

function digest(value: CanonicalValue | undefined, path: string): string {
  if (typeof value !== "string" || !HEX64.test(value) || value === ALL_ZERO)
    throw new NativeP2D2OverlayError(`${path} is not a nonzero lowercase SHA-256 digest`);
  return value;
}

function nullableDigest(value: CanonicalValue | undefined, path: string): string | null {
  return value === null ? null : digest(value, path);
}

function nullableLength(value: CanonicalValue | undefined, path: string): bigint | null {
  if (value === null) return null;
  if (typeof value !== "bigint" || value < 0n || value > P2_D2_OVERLAY_LIMITS.newFileBytes)
    throw new NativeP2D2OverlayError(`${path} violates the uint64/file bound`);
  return value;
}

function validateNewBytes(length: bigint, digestValue: string, path: string): void {
  if ((length === 0n) !== (digestValue === EMPTY_SHA256))
    throw new NativeP2D2OverlayError(`${path} violates the empty-file digest equation`);
}

function operation(value: CanonicalValue, index: number): NativePatchOperationV1 {
  const path = `operations[${index}]`;
  const row = record(value, path);
  exactKeys(row, OPERATION_KEYS, path);
  if (row.operation !== "add" && row.operation !== "delete" && row.operation !== "replace")
    throw new NativeP2D2OverlayError(`${path}.operation is unknown`);
  if (typeof row.path !== "string" || Buffer.byteLength(row.path, "ascii") > P2_D2_OVERLAY_LIMITS.textBytes ||
      !isCanonicalNativeP2RelativePath(row.path) || row.path === ".cargo-checksum.json")
    throw new NativeP2D2OverlayError(`${path}.path is not an admitted regular-file path`);
  const oldByteDigest = nullableDigest(row.oldByteDigest, `${path}.oldByteDigest`);
  const newByteDigest = nullableDigest(row.newByteDigest, `${path}.newByteDigest`);
  const newByteLength = nullableLength(row.newByteLength, `${path}.newByteLength`);
  if (row.operation === "delete") {
    if (oldByteDigest === null || newByteDigest !== null || newByteLength !== null)
      throw new NativeP2D2OverlayError(`${path} violates the delete equation`);
  } else if (row.operation === "add") {
    if (oldByteDigest !== null || newByteDigest === null || newByteLength === null)
      throw new NativeP2D2OverlayError(`${path} violates the add equation`);
    validateNewBytes(newByteLength, newByteDigest, path);
  } else {
    if (oldByteDigest === null || newByteDigest === null || newByteLength === null)
      throw new NativeP2D2OverlayError(`${path} violates the replace equation`);
    if (oldByteDigest === newByteDigest)
      throw new NativeP2D2OverlayError(`${path} is a no-op replace`);
    validateNewBytes(newByteLength, newByteDigest, path);
  }
  return Object.freeze({ operation: row.operation, path: row.path, oldByteDigest, newByteDigest, newByteLength });
}

export function captureNativePatchOverlayV1(bytesInput: unknown): ValidatedPatchOverlayPlan {
  if (bytesInput === null || typeof bytesInput !== "object" || types.isProxy(bytesInput) || !(bytesInput instanceof Uint8Array))
    throw new NativeP2D2OverlayError("input is not an owned byte string");
  if (bytesInput.byteLength === 0 || bytesInput.byteLength > P2_D2_OVERLAY_LIMITS.encodedBytes)
    throw new NativeP2D2OverlayError("encoded-size bound violated");
  const value = decodeCanonical(bytesInput);
  nativeProfile(value);
  const row = record(value, "overlay");
  exactKeys(row, ROOT_KEYS, "overlay");
  if (row.schema !== SCHEMA || row.version !== 1n || row.packageId !== PACKAGE_ID)
    throw new NativeP2D2OverlayError("schema, version, or package identity is not frozen");
  if (!Array.isArray(row.operations) || row.operations.length < 1 || row.operations.length > P2_D2_OVERLAY_LIMITS.operations)
    throw new NativeP2D2OverlayError("operation count violates the bound");
  if (typeof row.rationale !== "string" || row.rationale.length === 0 || Buffer.byteLength(row.rationale, "utf8") > P2_D2_OVERLAY_LIMITS.textBytes)
    throw new NativeP2D2OverlayError("rationale violates the bound");
  const operations = row.operations.map(operation);
  let aggregate = 0n;
  for (let index = 0; index < operations.length; index += 1) {
    const current = operations[index]!;
    const prior = operations[index - 1];
    if (prior !== undefined && Buffer.compare(Buffer.from(prior.path, "ascii"), Buffer.from(current.path, "ascii")) >= 0)
      throw new NativeP2D2OverlayError("operations are not strictly path-sorted");
    if (operations.slice(0, index).some((entry) => entry.path.toLowerCase() === current.path.toLowerCase()))
      throw new NativeP2D2OverlayError("operation paths collide under ASCII case folding");
    aggregate += current.newByteLength ?? 0n;
    if (aggregate > P2_D2_OVERLAY_LIMITS.aggregateNewBytes)
      throw new NativeP2D2OverlayError("aggregate new bytes exceed the bound");
  }
  const canonical = encodeCanonical(value);
  if (canonical.byteLength !== bytesInput.byteLength)
    throw new NativeP2D2OverlayError("canonical byte identity changed");
  const overlay: NativePatchOverlayV1 = Object.freeze({
    schema: SCHEMA,
    version: 1n,
    packageId: PACKAGE_ID,
    baseArchiveDigest: digest(row.baseArchiveDigest, "baseArchiveDigest"),
    operations: Object.freeze(operations),
    rationale: row.rationale,
    resultTreeDigest: digest(row.resultTreeDigest, "resultTreeDigest"),
    auditPlanDigest: digest(row.auditPlanDigest, "auditPlanDigest"),
  });
  const patchOverlayDigest = createHash("sha256").update(DOMAIN, "ascii").update(canonical).digest("hex") as PatchOverlayDigest;
  const snapshot = Uint8Array.from(canonical);
  return Object.freeze({
    kind: "ValidatedPatchOverlayPlan" as const,
    overlay,
    patchOverlayDigest,
    canonicalBytes: () => Uint8Array.from(snapshot),
  });
}

export const P2_D2_OVERLAY_AUTHORITY_BOUNDARY = Object.freeze({
  filesystem: false,
  process: false,
  network: false,
  signatureVerification: false,
  overlayApplication: false,
  build: false,
  admission: false,
  authorityBrand: false,
  launch: false,
} as const);
