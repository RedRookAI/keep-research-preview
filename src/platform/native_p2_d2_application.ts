/** Pure P2-D2 carrier + overlay application into immutable ResultTreeV1 evidence. */
import { createHash } from "node:crypto";
import { types } from "node:util";
import { decodeCanonicalSnapshot, encodeCanonical, type CanonicalValue } from "../eir/canonical.js";
import { P2_D2_OVERLAY_LIMITS, type NativePatchOperationV1 } from "./native_p2_d2_overlay.js";
import { captureNativePatchDescriptorV1, captureNativePatchByteCarrierSetV1, joinValidatedPatchApplicationInputs, type ValidatedPatchApplicationInputs } from "./native_p2_d2_carriers.js";
import { captureNativePatchOverlayV1 } from "./native_p2_d2_overlay.js";
import { captureAuditPlanV1 } from "./native_p2_d2_audit_plan.js";
import { isCanonicalNativeP2RelativePath } from "./native_p2_path.js";

const RESULT_SCHEMA = "keep.p2-d2-result-tree";
const PACKAGE_ID = "curve25519-dalek@5.0.0";
const RESULT_DOMAIN = "keep.p2-d2-result-tree/v1\0";
const HEX64 = /^[0-9a-f]{64}$/u;
const ALL_ZERO = "0".repeat(64);

export class NativeP2D2ApplicationError extends Error {
  constructor(message: string) {
    super(`native P2-D2 application: ${message}`);
    this.name = "NativeP2D2ApplicationError";
  }
}

export interface CapturedNativeArchiveFileV1 { readonly path: string; readonly bytes: Uint8Array }
export interface CapturedNativeArchiveV1 {
  readonly packageId: typeof PACKAGE_ID;
  readonly baseArchiveDigest: string;
  readonly files: readonly CapturedNativeArchiveFileV1[];
}
export interface NativeResultTreeFileV1 {
  readonly path: string;
  readonly byteDigest: string;
  readonly byteLength: bigint;
}
export type ResultTreeDigest = string & { readonly __resultTreeDigest: unique symbol };
export interface NativeResultTreeCandidateV1 {
  readonly kind: "NativeResultTreeCandidateV1";
  readonly files: readonly NativeResultTreeFileV1[];
  readonly resultTreeDigest: ResultTreeDigest;
  canonicalBytes(): Uint8Array;
  fileBytes(path: string): Uint8Array;
}
export interface ValidatedNativeResultTreePlan extends Omit<NativeResultTreeCandidateV1, "kind"> {
  readonly kind: "ValidatedNativeResultTreePlan";
  readonly filesystem: false;
  readonly build: false;
  readonly admission: false;
  readonly launch: false;
}

const sha = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");
function validDigest(value: string): boolean { return HEX64.test(value) && value !== ALL_ZERO; }
function captureBytes(value: unknown, path: string): Uint8Array {
  if (!(value instanceof Uint8Array) || types.isProxy(value) || Object.getPrototypeOf(value) !== Uint8Array.prototype)
    throw new NativeP2D2ApplicationError(`${path} is not an owned byte string`);
  if (value.byteLength > Number(P2_D2_OVERLAY_LIMITS.newFileBytes))
    throw new NativeP2D2ApplicationError(`${path} exceeds the member bound`);
  return Uint8Array.from(value);
}

function captureBase(archive: CapturedNativeArchiveV1): Map<string, Uint8Array> {
  if (archive.packageId !== PACKAGE_ID || !validDigest(archive.baseArchiveDigest))
    throw new NativeP2D2ApplicationError("captured archive identity is malformed");
  if (!Array.isArray(archive.files) || archive.files.length > 4096)
    throw new NativeP2D2ApplicationError("captured archive file count violates the bound");
  const result = new Map<string, Uint8Array>();
  const folded = new Set<string>();
  let prior: string | undefined;
  let aggregate = 0n;
  for (let index = 0; index < archive.files.length; index += 1) {
    const row = archive.files[index]!;
    if (row === null || typeof row !== "object" || types.isProxy(row) ||
        Object.keys(row).sort().join("\0") !== "bytes\0path" || typeof row.path !== "string" ||
        Buffer.byteLength(row.path, "ascii") > P2_D2_OVERLAY_LIMITS.textBytes ||
        !isCanonicalNativeP2RelativePath(row.path) || row.path === ".cargo-checksum.json")
      throw new NativeP2D2ApplicationError(`captured archive row ${index} is malformed`);
    if (prior !== undefined && Buffer.compare(Buffer.from(prior, "ascii"), Buffer.from(row.path, "ascii")) >= 0)
      throw new NativeP2D2ApplicationError("captured archive paths are not strictly sorted");
    prior = row.path;
    const foldedPath = row.path.toLowerCase();
    if (folded.has(foldedPath)) throw new NativeP2D2ApplicationError("base tree collides under ASCII case folding");
    folded.add(foldedPath);
    const bytes = captureBytes(row.bytes, `files[${index}].bytes`);
    aggregate += BigInt(bytes.byteLength);
    if (aggregate > P2_D2_OVERLAY_LIMITS.aggregateNewBytes)
      throw new NativeP2D2ApplicationError("captured archive aggregate exceeds the bound");
    result.set(row.path, bytes);
  }
  return result;
}

function applyOperation(
  tree: Map<string, Uint8Array>,
  operation: NativePatchOperationV1,
  carrierBytes: Uint8Array | undefined,
): void {
  const exact = tree.get(operation.path);
  const foldedCollision = [...tree.keys()].find((path) => path.toLowerCase() === operation.path.toLowerCase() && path !== operation.path);
  if (foldedCollision !== undefined)
    throw new NativeP2D2ApplicationError(`operation case-collides with base member ${foldedCollision}`);
  if (operation.operation === "add") {
    if (exact !== undefined || carrierBytes === undefined)
      throw new NativeP2D2ApplicationError("add target exists or carrier is missing");
    tree.set(operation.path, carrierBytes);
    return;
  }
  if (exact === undefined || sha(exact) !== operation.oldByteDigest)
    throw new NativeP2D2ApplicationError("old-byte equation or target existence failed");
  if (operation.operation === "delete") {
    if (carrierBytes !== undefined) throw new NativeP2D2ApplicationError("delete unexpectedly has carrier bytes");
    tree.delete(operation.path);
  } else {
    if (carrierBytes === undefined) throw new NativeP2D2ApplicationError("replace carrier bytes are missing");
    tree.set(operation.path, carrierBytes);
  }
}

export function deriveNativeResultTreeCandidateV1(
  inputs: ValidatedPatchApplicationInputs,
  archive: CapturedNativeArchiveV1,
): NativeResultTreeCandidateV1 {
  if (archive.baseArchiveDigest !== inputs.overlayPlan.overlay.baseArchiveDigest)
    throw new NativeP2D2ApplicationError("overlay is bound to a different base archive");
  const tree = captureBase(archive);
  const carriers = new Map(inputs.carrierSet.entries.map((row) => [row.path, row.bytes()]));
  for (const operation of inputs.overlayPlan.overlay.operations)
    applyOperation(tree, operation, carriers.get(operation.path));
  const ordered = [...tree.entries()].sort(([left], [right]) => Buffer.compare(Buffer.from(left, "ascii"), Buffer.from(right, "ascii")));
  const finalFolded = new Set<string>();
  let aggregate = 0n;
  const files = ordered.map(([path, bytes]): NativeResultTreeFileV1 => {
    const folded = path.toLowerCase();
    if (finalFolded.has(folded)) throw new NativeP2D2ApplicationError("result tree collides under ASCII case folding");
    finalFolded.add(folded);
    aggregate += BigInt(bytes.byteLength);
    if (aggregate > P2_D2_OVERLAY_LIMITS.aggregateNewBytes)
      throw new NativeP2D2ApplicationError("result tree aggregate exceeds the bound");
    return Object.freeze({ path, byteDigest: sha(bytes), byteLength: BigInt(bytes.byteLength) });
  });
  const value: CanonicalValue = {
    schema: RESULT_SCHEMA,
    version: 1n,
    packageId: PACKAGE_ID,
    files: files.map((row) => ({ path: row.path, byteDigest: row.byteDigest, byteLength: row.byteLength })),
  };
  const canonical = encodeCanonical(value);
  const resultTreeDigest = createHash("sha256").update(RESULT_DOMAIN, "ascii").update(canonical).digest("hex") as ResultTreeDigest;
  const snapshot = Uint8Array.from(canonical);
  const byteMap = new Map(ordered.map(([path, bytes]) => [path, Uint8Array.from(bytes)]));
  return Object.freeze({
    kind: "NativeResultTreeCandidateV1" as const,
    files: Object.freeze(files),
    resultTreeDigest,
    canonicalBytes: () => Uint8Array.from(snapshot),
    fileBytes: (path: string) => {
      const bytes = byteMap.get(path);
      if (bytes === undefined) throw new NativeP2D2ApplicationError("result file path is absent");
      return Uint8Array.from(bytes);
    },
  });
}

export function validateNativeResultTreeApplicationV1(
  inputs: ValidatedPatchApplicationInputs,
  archive: CapturedNativeArchiveV1,
): ValidatedNativeResultTreePlan {
  const candidate = deriveNativeResultTreeCandidateV1(inputs, archive);
  if (candidate.resultTreeDigest !== inputs.overlayPlan.overlay.resultTreeDigest)
    throw new NativeP2D2ApplicationError("derived result tree does not match the overlay commitment");
  return Object.freeze({
    ...candidate,
    kind: "ValidatedNativeResultTreePlan" as const,
    filesystem: false as const,
    build: false as const,
    admission: false as const,
    launch: false as const,
  });
}

/** Review references are retained inputs; outcomes remain unverified. */
export function captureNativeReviewInputsV1(input: unknown): { bytes: Uint8Array; digest: string } {
  const { value, bytes } = decodeCanonicalSnapshot(input, 65_536);
  const keys = ["schema", "version", "toolchain", "unsafeCode", "license", "advisory", "reproducibility", "provenance"];
  if (value === null || typeof value !== "object" || Array.isArray(value) || value instanceof Uint8Array)
    throw new NativeP2D2ApplicationError("review inputs are not a record");
  const row = value as Record<string, CanonicalValue>;
  if (Object.keys(row).length !== keys.length || keys.some(key => !Object.hasOwn(row, key)) ||
      row.schema !== "keep.p2-d2-review-inputs" || row.version !== 1n ||
      keys.slice(2).some(key => row[key] !== null && (typeof row[key] !== "string" || !validDigest(row[key] as string))))
    throw new NativeP2D2ApplicationError("review input identities are malformed");
  return { bytes, digest: sha(bytes) };
}

export interface ValidatedNativePatchApplicationV1 {
  readonly kind: "ValidatedNativePatchApplicationV1";
  readonly evidenceDigest: string;
  readonly result: ValidatedNativeResultTreePlan;
  readonly auditPlanDigest: string;
  readonly reviewInputsDigest: string;
  readonly cargoChecksumArtifactDigest: string;
  readonly reviewStatus: "unverified";
  readonly admission: false;
  readonly launch: false;
  canonicalBytes(): Uint8Array;
  cargoChecksumBytes(): Uint8Array;
  auditPlanBytes(): Uint8Array;
  reviewInputBytes(): Uint8Array;
}

/** Apply one already captured snapshot, retaining its source and review identities. */
export function captureNativePatchApplicationV1(
  archive: CapturedNativeArchiveV1,
  overlayBytes: Uint8Array,
  carrierBytes: Uint8Array,
  auditBytes: Uint8Array,
  reviewBytes: Uint8Array,
  requestDigest: string,
  sourceRowDigest: string,
): ValidatedNativePatchApplicationV1 {
  if (!validDigest(requestDigest) || !validDigest(sourceRowDigest)) throw new NativeP2D2ApplicationError("snapshot identity malformed");
  const overlay = captureNativePatchOverlayV1(overlayBytes), carriers = captureNativePatchByteCarrierSetV1(carrierBytes);
  const descriptor = captureNativePatchDescriptorV1(overlayBytes, carrierBytes, archive.baseArchiveDigest);
  const audit = captureAuditPlanV1(auditBytes), review = captureNativeReviewInputsV1(reviewBytes);
  if (audit.auditPlanDigest !== overlay.overlay.auditPlanDigest) throw new NativeP2D2ApplicationError("audit plan commitment differs");
  const result = validateNativeResultTreeApplicationV1(joinValidatedPatchApplicationInputs(overlay, carriers), archive);
  const paths = new Set(result.files.map(row => row.path.toLowerCase()));
  for (const row of result.files) {
    const path = row.path.toLowerCase();
    if (path === ".cargo-checksum.json" || path.startsWith(".cargo-checksum.json/") ||
        path.split("/").slice(0, -1).some((_, index, parts) => paths.has(parts.slice(0, index + 1).join("/"))))
      throw new NativeP2D2ApplicationError("result namespace conflicts with a file or generated checksum");
  }
  const checksum = Buffer.from(`{"files":{${result.files.map(row => `${JSON.stringify(row.path)}:${JSON.stringify(row.byteDigest)}`).join(",")}},"package":null}\n`, "utf8");
  const cargoChecksumArtifactDigest = createHash("sha256").update("keep.p2-d2-cargo-checksum-artifact/v1\0", "ascii").update(checksum).digest("hex");
  const canonical = encodeCanonical({
    schema: "keep.p2-d2-patch-application", version: 1n, packageId: PACKAGE_ID,
    requestDigest, sourceRowDigest, baseArchiveDigest: archive.baseArchiveDigest,
    patchDescriptorDigest: descriptor.descriptorDigest, resultTreeDigest: result.resultTreeDigest,
    auditPlanDigest: audit.auditPlanDigest, reviewInputsDigest: review.digest,
    cargoChecksumArtifactDigest, reviewStatus: "unverified", admission: false, launch: false,
  });
  return Object.freeze({
    kind: "ValidatedNativePatchApplicationV1", result, auditPlanDigest: audit.auditPlanDigest,
    reviewInputsDigest: review.digest, cargoChecksumArtifactDigest, reviewStatus: "unverified", admission: false, launch: false,
    evidenceDigest: createHash("sha256").update("keep.p2-d2-patch-application/v1\0", "ascii").update(canonical).digest("hex"),
    canonicalBytes: () => Uint8Array.from(canonical), cargoChecksumBytes: () => Uint8Array.from(checksum),
    auditPlanBytes: () => audit.canonicalBytes(), reviewInputBytes: () => Uint8Array.from(review.bytes),
  });
}
