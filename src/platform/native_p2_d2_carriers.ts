/** Dependency-free, byte-only P2-D2 add/replace carrier capture and overlay join. */
import { createHash } from "node:crypto";
import { types } from "node:util";
import { CanonicalByteLimitError, decodeCanonicalSnapshot, type CanonicalValue } from "../eir/canonical.js";
import {
  P2_D2_OVERLAY_LIMITS,
  type NativePatchOperationKindV1,
  type ValidatedPatchOverlayPlan,
} from "./native_p2_d2_overlay.js";
import { isCanonicalNativeP2RelativePath } from "./native_p2_path.js";

const SCHEMA = "keep.p2-d2-patch-byte-carrier-set";
const PACKAGE_ID = "curve25519-dalek@5.0.0";
const DOMAIN = "keep.p2-d2-patch-byte-carrier-set/v1\0";
const MAX_ENCODED_BYTES = 130 * 1024 * 1024;
const ROOT_KEYS = ["schema", "version", "packageId", "entries"] as const;
const ENTRY_KEYS = ["path", "operation", "bytes"] as const;

export class NativeP2D2CarrierError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(`native P2-D2 patch byte carriers: ${message}`, options);
    this.name = "NativeP2D2CarrierError";
  }
}

export interface NativePatchByteCarrierV1 {
  readonly path: string;
  readonly operation: Exclude<NativePatchOperationKindV1, "delete">;
  bytes(): Uint8Array;
}
export type PatchByteCarrierSetDigest = string & { readonly __patchByteCarrierSetDigest: unique symbol };
export interface ValidatedPatchByteCarrierSet {
  readonly kind: "ValidatedPatchByteCarrierSet";
  readonly entries: readonly NativePatchByteCarrierV1[];
  readonly patchByteCarrierSetDigest: PatchByteCarrierSetDigest;
  canonicalBytes(): Uint8Array;
}
export interface ValidatedPatchApplicationInputs {
  readonly kind: "ValidatedPatchApplicationInputs";
  readonly overlayPlan: ValidatedPatchOverlayPlan;
  readonly carrierSet: ValidatedPatchByteCarrierSet;
  readonly filesystem: false;
  readonly build: false;
  readonly admission: false;
  readonly launch: false;
}

function record(value: CanonicalValue, path: string): Record<string, CanonicalValue> {
  if (value === null || Array.isArray(value) || value instanceof Uint8Array || typeof value !== "object")
    throw new NativeP2D2CarrierError(`${path} is not a record`);
  return value as Record<string, CanonicalValue>;
}
function exactKeys(row: Record<string, CanonicalValue>, expected: readonly string[], path: string): void {
  const actual = Object.keys(row).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index]))
    throw new NativeP2D2CarrierError(`${path} fields are not exact`);
}
function plainBytes(value: CanonicalValue | undefined, path: string): Uint8Array {
  if (!(value instanceof Uint8Array) || types.isProxy(value) || Object.getPrototypeOf(value) !== Uint8Array.prototype)
    throw new NativeP2D2CarrierError(`${path} is not an owned byte string`);
  if (value.byteLength > Number(P2_D2_OVERLAY_LIMITS.newFileBytes))
    throw new NativeP2D2CarrierError(`${path} exceeds the file bound`);
  return Uint8Array.from(value);
}

export function captureNativePatchByteCarrierSetV1(bytesInput: unknown): ValidatedPatchByteCarrierSet {
  if (bytesInput === null || typeof bytesInput !== "object" || types.isProxy(bytesInput) || !(bytesInput instanceof Uint8Array))
    throw new NativeP2D2CarrierError("input is not an owned byte string");
  // Bound the intrinsic input length before allocation, then retain the very
  // bytes that passed canonical verification. No second read of caller getters
  // and no caller-supplied decoded pair can confer this validation.
  let captured: ReturnType<typeof decodeCanonicalSnapshot>;
  try { captured = decodeCanonicalSnapshot(bytesInput, MAX_ENCODED_BYTES); }
  catch (cause) {
    if (cause instanceof CanonicalByteLimitError)
      throw new NativeP2D2CarrierError("encoded-size bound violated", { cause });
    throw cause; // Canonical-wire failures keep their existing distinct error type.
  }
  const { value, bytes: snapshot } = captured;
  const row = record(value, "carrierSet");
  exactKeys(row, ROOT_KEYS, "carrierSet");
  if (row.schema !== SCHEMA || row.version !== 1n || row.packageId !== PACKAGE_ID)
    throw new NativeP2D2CarrierError("schema, version, or package identity is not frozen");
  if (!Array.isArray(row.entries) || row.entries.length > P2_D2_OVERLAY_LIMITS.operations)
    throw new NativeP2D2CarrierError("entry count violates the bound");
  let aggregate = 0n;
  let prior: string | undefined;
  const folded = new Set<string>();
  const entries = row.entries.map((value, index): NativePatchByteCarrierV1 => {
    const path = `entries[${index}]`;
    const entry = record(value, path);
    exactKeys(entry, ENTRY_KEYS, path);
    if (entry.operation !== "add" && entry.operation !== "replace")
      throw new NativeP2D2CarrierError(`${path}.operation is not add/replace`);
    if (typeof entry.path !== "string" || Buffer.byteLength(entry.path, "ascii") > P2_D2_OVERLAY_LIMITS.textBytes ||
        !isCanonicalNativeP2RelativePath(entry.path) || entry.path === ".cargo-checksum.json")
      throw new NativeP2D2CarrierError(`${path}.path is not admitted`);
    if (prior !== undefined && Buffer.compare(Buffer.from(prior, "ascii"), Buffer.from(entry.path, "ascii")) >= 0)
      throw new NativeP2D2CarrierError("entries are not strictly path-sorted");
    prior = entry.path;
    const foldedPath = entry.path.toLowerCase();
    if (folded.has(foldedPath)) throw new NativeP2D2CarrierError("entry paths collide under ASCII case folding");
    folded.add(foldedPath);
    const payload = plainBytes(entry.bytes, `${path}.bytes`);
    aggregate += BigInt(payload.byteLength);
    if (aggregate > P2_D2_OVERLAY_LIMITS.aggregateNewBytes)
      throw new NativeP2D2CarrierError("aggregate carrier bytes exceed the bound");
    return Object.freeze({
      path: entry.path,
      operation: entry.operation,
      bytes: () => Uint8Array.from(payload),
    });
  });
  const patchByteCarrierSetDigest = createHash("sha256").update(DOMAIN, "ascii").update(snapshot).digest("hex") as PatchByteCarrierSetDigest;
  return Object.freeze({
    kind: "ValidatedPatchByteCarrierSet" as const,
    entries: Object.freeze(entries),
    patchByteCarrierSetDigest,
    canonicalBytes: () => Uint8Array.from(snapshot),
  });
}

export function joinValidatedPatchApplicationInputs(
  overlayPlan: ValidatedPatchOverlayPlan,
  carrierSet: ValidatedPatchByteCarrierSet,
): ValidatedPatchApplicationInputs {
  const expected = overlayPlan.overlay.operations.filter((operation) => operation.operation !== "delete");
  if (expected.length !== carrierSet.entries.length)
    throw new NativeP2D2CarrierError("carrier/overlay cardinality mismatch");
  for (let index = 0; index < expected.length; index += 1) {
    const operation = expected[index]!;
    const carrier = carrierSet.entries[index]!;
    const bytes = carrier.bytes();
    if (carrier.path !== operation.path || carrier.operation !== operation.operation)
      throw new NativeP2D2CarrierError("carrier/overlay path or operation mismatch");
    if (BigInt(bytes.byteLength) !== operation.newByteLength ||
        createHash("sha256").update(bytes).digest("hex") !== operation.newByteDigest)
      throw new NativeP2D2CarrierError("carrier bytes do not reproduce the overlay equation");
  }
  return Object.freeze({
    kind: "ValidatedPatchApplicationInputs" as const,
    overlayPlan,
    carrierSet,
    filesystem: false as const,
    build: false as const,
    admission: false as const,
    launch: false as const,
  });
}
