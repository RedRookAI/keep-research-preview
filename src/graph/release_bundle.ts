/** Canonical on-disk carrier for the signed A4 boot inputs. Secrets and clocks are deliberately absent. */
import { readFileSync, realpathSync, statSync } from "node:fs";
import { types } from "node:util";
import { decodeCanonical, encodeCanonical, isCanonical, type CanonicalValue } from "../eir/canonical.js";
import type { TrustPolicy } from "../bom/bom_signing.js";
import type { ReleaseClosureVerificationInput } from "./release_closure_v2.js";
import { releaseRootReadOnly, type AuthorityCompilerInputs } from "./release_compiler.js";
import type { ReleaseClosureTrustPolicy } from "./release_closure_v2.js";

export const RELEASE_BOOT_BUNDLE = Object.freeze({ name: "keep.release-boot-bundle", version: 1n } as const);
export const MAX_RELEASE_BOOT_BUNDLE_BYTES = 16 * 1024 * 1024;
export interface ReleaseBootBundle { readonly verification: ReleaseClosureVerificationInput; readonly authority: AuthorityCompilerInputs; }
export interface ReleaseTrustRoot { readonly releaseTrust: ReleaseClosureTrustPolicy; readonly manifestTrust: TrustPolicy; readonly policyTrust: TrustPolicy; readonly waiverTrust: TrustPolicy; }
export class ReleaseBundleError extends Error { constructor(message: string) { super(`release bundle: ${message}`); this.name = "ReleaseBundleError"; } }

const record = (value: unknown, keys: readonly string[], label: string): Record<string, CanonicalValue> => {
  if (value === null || typeof value !== "object" || Array.isArray(value) || value instanceof Uint8Array || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) throw new ReleaseBundleError(`${label} must be a map`);
  const row = value as Record<string, CanonicalValue>; const actual = Object.keys(row).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new ReleaseBundleError(`${label} keys are not exact`);
  return row;
};
const trustToCanonical = (trust: TrustPolicy): CanonicalValue => ({ threshold: BigInt(trust.threshold), trustedKeys: [...trust.trustedKeys].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([keyId, key]) => [keyId, key]) });
const trustFromCanonical = (value: unknown, label: string): TrustPolicy => {
  const row = record(value, ["threshold", "trustedKeys"], label); if (typeof row.threshold !== "bigint" || row.threshold < 1n || row.threshold > 32n || !Array.isArray(row.trustedKeys)) throw new ReleaseBundleError(`${label} is malformed`);
  const entries: [string, string][] = row.trustedKeys.map((entry, index) => { if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string" || typeof entry[1] !== "string") throw new ReleaseBundleError(`${label}.trustedKeys[${index}] is malformed`); return [entry[0], entry[1]]; });
  if (entries.some((entry, index) => index > 0 && entry[0] <= entries[index - 1]![0]) || BigInt(entries.length) < row.threshold) throw new ReleaseBundleError(`${label}.trustedKeys is not sorted, unique, or sufficient`);
  return Object.freeze({ threshold: Number(row.threshold), trustedKeys: new Map(entries) });
};
const releaseTrustToCanonical = (trust: ReleaseClosureTrustPolicy): CanonicalValue => ({ threshold: BigInt(trust.threshold), anchors: trust.anchors as unknown as CanonicalValue });
const releaseTrustFromCanonical = (value: unknown): ReleaseClosureTrustPolicy => { const row = record(value, ["threshold", "anchors"], "releaseTrust"); if (typeof row.threshold !== "bigint" || row.threshold < 1n || row.threshold > 32n || !Array.isArray(row.anchors)) throw new ReleaseBundleError("releaseTrust is malformed"); return Object.freeze({ threshold: Number(row.threshold), anchors: row.anchors as unknown as ReleaseClosureTrustPolicy["anchors"] }); };
/** Lossless typed envelope: unlike raw CBOR it preserves the intentional distinction between JS schema numbers and bigint epochs. */
function pack(value: unknown, depth = 0): CanonicalValue {
  if (depth > 64) throw new ReleaseBundleError("value exceeds depth bound");
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "bigint") return value;
  if (typeof value === "number") { if (!Number.isSafeInteger(value)) throw new ReleaseBundleError("number is not a safe integer"); return { $keepType: "number", value: BigInt(value) }; }
  if (typeof value !== "object" || types.isProxy(value)) throw new ReleaseBundleError("value is not inert serializable data");
  if (Array.isArray(value)) { if (Object.getPrototypeOf(value) !== Array.prototype || Object.getOwnPropertyNames(value).length !== value.length + 1) throw new ReleaseBundleError("array is sparse or extended"); return { $keepType: "array", value: value.map((entry) => pack(entry, depth + 1)) }; }
  if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) throw new ReleaseBundleError("value contains a non-plain object");
  if (Object.getOwnPropertySymbols(value).length !== 0) throw new ReleaseBundleError("value contains symbols");
  const entries: CanonicalValue[] = []; for (const key of Object.getOwnPropertyNames(value).sort()) { const descriptor = Object.getOwnPropertyDescriptor(value, key)!; if (!descriptor.enumerable || descriptor.get || descriptor.set || !("value" in descriptor)) throw new ReleaseBundleError("value contains an accessor/non-data property"); entries.push([key, pack(descriptor.value, depth + 1)]); }
  return { $keepType: "map", value: entries };
}
function unpack(value: CanonicalValue, depth = 0): unknown {
  if (depth > 64) throw new ReleaseBundleError("value exceeds depth bound");
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "bigint") return value;
  const row = record(value, ["$keepType", "value"], "typed value");
  if (row.$keepType === "number") { if (typeof row.value !== "bigint" || row.value < BigInt(Number.MIN_SAFE_INTEGER) || row.value > BigInt(Number.MAX_SAFE_INTEGER)) throw new ReleaseBundleError("packed number is invalid"); return Number(row.value); }
  if (row.$keepType === "array") { if (!Array.isArray(row.value)) throw new ReleaseBundleError("packed array is invalid"); return row.value.map((entry) => unpack(entry, depth + 1)); }
  if (row.$keepType === "map") { if (!Array.isArray(row.value)) throw new ReleaseBundleError("packed map is invalid"); const out: Record<string, unknown> = Object.create(null); let prior = ""; for (const [index, entry] of row.value.entries()) { if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string" || entry[0] === "__proto__" || entry[0] === "prototype" || entry[0] === "constructor" || (index > 0 && entry[0] <= prior)) throw new ReleaseBundleError("packed map entries are invalid"); prior = entry[0]; out[entry[0]] = unpack(entry[1]!, depth + 1); } return out; }
  throw new ReleaseBundleError("packed value tag is unsupported");
}

export function encodeReleaseBootBundle(bundle: ReleaseBootBundle): Uint8Array {
  const authority = bundle.authority;
  const verification = { closure: bundle.verification.closure, graph: bundle.verification.graph, world: bundle.verification.world, context: bundle.verification.context, bindings: bundle.verification.bindings, lineage: bundle.verification.lineage, expectedProfile: bundle.verification.expectedProfile, observedSecurity: bundle.verification.observedSecurity, bootNonce: bundle.verification.bootNonce };
  return encodeCanonical({ schema: RELEASE_BOOT_BUNDLE.name, version: RELEASE_BOOT_BUNDLE.version, verification: pack(verification), authority: pack({ manifest: authority.manifest, policyBundle: authority.policyBundle, waiver: authority.waiver, baseline: authority.baseline, boundWaiverDigest: authority.boundWaiverDigest, previousReleaseHead: authority.previousReleaseHead }) });
}

export function encodeReleaseTrustRoot(root: ReleaseTrustRoot): Uint8Array { return encodeCanonical({ schema: "keep.release-trust-root", version: 1n, releaseTrust: pack(releaseTrustToCanonical(root.releaseTrust)), manifestTrust: pack(trustToCanonical(root.manifestTrust)), policyTrust: pack(trustToCanonical(root.policyTrust)), waiverTrust: pack(trustToCanonical(root.waiverTrust)) }); }
export function decodeReleaseTrustRoot(bytes: Uint8Array): ReleaseTrustRoot { if (bytes.byteLength === 0 || bytes.byteLength > 1024 * 1024 || !isCanonical(bytes)) throw new ReleaseBundleError("trust root is empty, oversized, or non-canonical"); const root = record(decodeCanonical(bytes), ["schema", "version", "releaseTrust", "manifestTrust", "policyTrust", "waiverTrust"], "trust root"); if (root.schema !== "keep.release-trust-root" || root.version !== 1n) throw new ReleaseBundleError("trust root schema/version is unsupported"); return Object.freeze({ releaseTrust: releaseTrustFromCanonical(unpack(root.releaseTrust!)), manifestTrust: trustFromCanonical(unpack(root.manifestTrust!), "manifestTrust"), policyTrust: trustFromCanonical(unpack(root.policyTrust!), "policyTrust"), waiverTrust: trustFromCanonical(unpack(root.waiverTrust!), "waiverTrust") }); }

export function decodeReleaseBootBundle(bytes: Uint8Array, trustRoot: ReleaseTrustRoot): ReleaseBootBundle {
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_RELEASE_BOOT_BUNDLE_BYTES || !isCanonical(bytes)) throw new ReleaseBundleError("file is empty, oversized, or non-canonical CBOR");
  const root = record(decodeCanonical(bytes), ["schema", "version", "verification", "authority"], "bundle");
  if (root.schema !== RELEASE_BOOT_BUNDLE.name || root.version !== RELEASE_BOOT_BUNDLE.version) throw new ReleaseBundleError("schema/version is unsupported");
  const verification = unpack(root.verification!) as ReleaseClosureVerificationInput;
  const authority = record(unpack(root.authority!), ["manifest", "policyBundle", "waiver", "baseline", "boundWaiverDigest", "previousReleaseHead"], "authority");
  if (typeof authority.boundWaiverDigest !== "string" || typeof authority.previousReleaseHead !== "string") throw new ReleaseBundleError("authority release heads are malformed");
  return Object.freeze({ verification: Object.freeze({ ...verification, trust: trustRoot.releaseTrust }), authority: Object.freeze({ manifest: authority.manifest as unknown as AuthorityCompilerInputs["manifest"], policyBundle: authority.policyBundle as unknown as AuthorityCompilerInputs["policyBundle"], trust: Object.freeze({ manifestTrust: trustRoot.manifestTrust, policyTrust: trustRoot.policyTrust }), waiver: authority.waiver as unknown as AuthorityCompilerInputs["waiver"], baseline: authority.baseline as unknown as AuthorityCompilerInputs["baseline"], boundWaiverDigest: authority.boundWaiverDigest, previousReleaseHead: authority.previousReleaseHead, waiverTrust: trustRoot.waiverTrust }) });
}

export function readReleaseTrustRoot(path: string): ReleaseTrustRoot { let canonical: string; try { canonical = realpathSync(path); const stat = statSync(canonical); if (!stat.isFile() || stat.size <= 0 || stat.size > 1024 * 1024 || !releaseRootReadOnly(canonical)) throw new Error("not immutable bounded file"); } catch { throw new ReleaseBundleError("trust root is not a readable regular file on a read-only mount"); } return decodeReleaseTrustRoot(new Uint8Array(readFileSync(canonical))); }
export function readReleaseBootBundle(path: string, trustRoot: ReleaseTrustRoot): ReleaseBootBundle {
  let canonical: string; try { canonical = realpathSync(path); const stat = statSync(canonical); if (!stat.isFile() || stat.size <= 0 || stat.size > MAX_RELEASE_BOOT_BUNDLE_BYTES) throw new Error("not bounded regular file"); } catch { throw new ReleaseBundleError("path is not a readable bounded regular file"); }
  return decodeReleaseBootBundle(new Uint8Array(readFileSync(canonical)), trustRoot);
}
