/**
 * A4 signed release closure and boot-scoped admission.
 *
 * The closure signs only canonical, domain-separated bytes. Verification re-captures the capability graph, re-derives
 * its ledgers from an independently observed installed world, authenticates a threshold of release signers, checks
 * release lineage/time/revocation, and only then creates an opaque in-process admission token. Stub signing is
 * deliberately confined to sacrificial/local-development profiles and caps every claim at Specified.
 */
import { createHash, createPrivateKey, createPublicKey, sign as cryptoSign, timingSafeEqual, verify as cryptoVerify, type KeyObject } from "node:crypto";
import { types } from "node:util";
import { performance } from "node:perf_hooks";
import { eirDigest, isWellFormedText, type CanonicalValue } from "../eir/canonical.js";
import {
  captureCapabilityGraphV2,
  captureCapabilityGraphArgument,
  deriveCapabilityLedgers,
  type CapabilityLedgers,
  type CapabilityVerificationContext,
  type CapturedCapabilityGraphV2,
  type ObservedWorld,
} from "./capability_graph_v2.js";

export const RELEASE_CLOSURE_V2 = Object.freeze({ name: "keep.release-closure", version: 2 } as const);
export const MAX_RELEASE_CLOSURE_LIFETIME_MS = 86_400_000n;
export const MAX_RELEASE_CLOSURE_VERIFICATION_MS = 15_000;

export type ReleaseProfile = "sacrificial" | "local-development" | "production" | "restricted";
export type ClosureSignatureAlgorithm = "ed25519" | "stub-sha256";
export type ClosureMechanismStatus = "enforced" | "unavailable";

export interface ReleaseSecurityPosture {
  readonly trustedTime: ClosureMechanismStatus;
  readonly signerRevocation: ClosureMechanismStatus;
  readonly rollbackProtection: ClosureMechanismStatus;
  readonly immutableArtifact: ClosureMechanismStatus;
}

export interface ReleaseClosurePayloadV2 {
  readonly version: 2;
  readonly profile: ReleaseProfile;
  readonly subjectDigest: string;
  readonly releaseEpoch: bigint;
  readonly sequence: bigint;
  readonly predecessorClosureDigest: string;
  readonly graphDigest: string;
  readonly ledgersDigest: string;
  readonly observedWorldDigest: string;
  readonly artifactInventoryDigest: string;
  readonly effectManifestDigest: string;
  readonly policyBundleDigest: string;
  readonly scannerToolDigest: string;
  readonly authorityWaiverDigest: string;
  readonly providerDescriptorDigest: string;
  readonly issuedAtMs: bigint;
  readonly expiresAtMs: bigint;
  readonly keyEpoch: bigint;
  readonly security: ReleaseSecurityPosture;
  readonly claimCeiling: "Specified" | "Load-bearing";
}

export interface ReleaseClosureSignatureV2 {
  readonly keyId: string;
  readonly algorithm: ClosureSignatureAlgorithm;
  readonly keyEpoch: bigint;
  readonly signature: string;
}

export interface SignedReleaseClosureV2 {
  readonly payload: ReleaseClosurePayloadV2;
  readonly payloadDigest: string;
  readonly signatures: readonly ReleaseClosureSignatureV2[];
}

export interface ReleaseClosureSigner {
  readonly keyId: string;
  readonly algorithm: ClosureSignatureAlgorithm;
  readonly keyEpoch: bigint;
  sign(preimageDigest: string): string;
}

export interface ReleaseClosureTrustAnchor {
  readonly keyId: string;
  readonly algorithm: ClosureSignatureAlgorithm;
  readonly verifyKey: string;
  readonly keyEpoch: bigint;
  readonly validFromMs: bigint;
  readonly validUntilMs: bigint;
  readonly revokedAtMs: bigint | null;
}

export interface ReleaseClosureTrustPolicy {
  readonly threshold: number;
  readonly anchors: readonly ReleaseClosureTrustAnchor[];
}

export interface ReleaseClosureBindings {
  readonly artifactInventoryDigest: string;
  readonly effectManifestDigest: string;
  readonly policyBundleDigest: string;
  readonly scannerToolDigest: string;
  readonly authorityWaiverDigest: string;
  readonly providerDescriptorDigest: string;
}

export interface ReleaseLineageExpectation {
  readonly sequence: bigint;
  readonly predecessorClosureDigest: string;
}

export interface ReleaseAdmissionToken {
  readonly closureDigest: string;
  readonly graphDigest: string;
  readonly subjectDigest: string;
  readonly releaseEpoch: bigint;
  readonly profile: ReleaseProfile;
  readonly claimCeiling: "Specified" | "Load-bearing";
  readonly bootNonce: string;
  readonly issuedAtMs: bigint;
  readonly expiresAtMs: bigint;
}

export interface EffectiveCapabilityLedgers extends Omit<CapabilityLedgers, "claims" | "digest"> {
  readonly claims: CapabilityLedgers["claims"];
  readonly sourceLedgerDigest: string;
  readonly digest: string;
}

export type ReleaseClosureVerdict =
  | { readonly valid: true; readonly closure: SignedReleaseClosureV2; readonly graph: CapturedCapabilityGraphV2; readonly effectiveLedgers: EffectiveCapabilityLedgers; readonly admission: ReleaseAdmissionToken }
  | { readonly valid: false; readonly reason: string };

export interface ReleaseClosureVerificationInput {
  readonly closure: unknown; readonly graph: unknown; readonly world: unknown; readonly context: unknown; readonly bindings: ReleaseClosureBindings;
  readonly trust: ReleaseClosureTrustPolicy; readonly lineage: ReleaseLineageExpectation; readonly expectedProfile: ReleaseProfile; readonly observedSecurity: ReleaseSecurityPosture; readonly bootNonce: string;
}

export class ReleaseClosureError extends Error {
  constructor(message: string) { super(`release closure v2: ${message}`); this.name = "ReleaseClosureError"; }
}

function captureSigners(input: readonly ReleaseClosureSigner[]): readonly ReleaseClosureSigner[] {
  if (!Array.isArray(input) || Object.getPrototypeOf(input) !== Array.prototype || input.length === 0 || input.length > 32) throw new ReleaseClosureError("signers must be a bounded dense plain array");
  const keys = Reflect.ownKeys(input); if (keys.length !== input.length + 1 || !keys.includes("length")) throw new ReleaseClosureError("signers must be a bounded dense plain array");
  const seen = new Set<string>(); const out: ReleaseClosureSigner[] = [];
  for (let index = 0; index < input.length; index++) {
    if (!Object.prototype.hasOwnProperty.call(input, index)) throw new ReleaseClosureError("signers must be a bounded dense plain array");
    const signer = input[index]; if (signer === null || (typeof signer !== "object" && typeof signer !== "function")) throw new ReleaseClosureError(`signers[${index}] is malformed`);
    let keyId: string, algorithm: ClosureSignatureAlgorithm, keyEpoch: bigint, signFn: (digest: string) => string;
    try { keyId = id(signer.keyId, `signers[${index}].keyId`); algorithm = enumValue(signer.algorithm, ALGORITHMS, `signers[${index}].algorithm`); keyEpoch = epoch(signer.keyEpoch, `signers[${index}].keyEpoch`); if (typeof signer.sign !== "function") throw new Error("missing sign"); signFn = signer.sign.bind(signer); }
    catch (error) { throw new ReleaseClosureError(`signers[${index}] capture failed:${safeMessage(error)}`); }
    if (seen.has(keyId)) throw new ReleaseClosureError("compiler has duplicate signer key ids"); seen.add(keyId);
    out.push(Object.freeze({ keyId, algorithm, keyEpoch, sign: signFn }));
  }
  return Object.freeze(out);
}

const HEX64 = /^[0-9a-f]{64}$/;
const ID = /^[a-z0-9][a-z0-9._/-]{0,127}$/;
const BASE64URL = /^[A-Za-z0-9_-]{43,4096}$/;
const PROFILES = new Set<ReleaseProfile>(["sacrificial", "local-development", "production", "restricted"]);
const ALGORITHMS = new Set<ClosureSignatureAlgorithm>(["ed25519", "stub-sha256"]);
const STATUSES = new Set<ClosureMechanismStatus>(["enforced", "unavailable"]);
const admissionTokens = new WeakSet<object>();

const sha256 = (value: string): string => createHash("sha256").update(value, "utf8").digest("hex");
const safeMessage = (error: unknown): string => { try { return String((error as { message?: unknown })?.message ?? error).slice(0, 300); } catch { return "unknown"; } };
const exact = (value: unknown, keys: readonly string[], label: string): Record<string, unknown> => {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value) || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) throw new ReleaseClosureError(`${label} must be a plain object`);
  if (Object.getOwnPropertySymbols(value).length !== 0) throw new ReleaseClosureError(`${label} has symbol keys`);
  const out: Record<string, unknown> = Object.create(null);
  for (const key of Object.getOwnPropertyNames(value)) { const d = Object.getOwnPropertyDescriptor(value, key)!; if (!d.enumerable || d.get || d.set || !("value" in d)) throw new ReleaseClosureError(`${label}.${key} is not a plain value`); out[key] = d.value; }
  const actual = Object.keys(out).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new ReleaseClosureError(`${label} keys must be exactly ${expected.join(",")}`);
  return out;
};
const exactArray = (value: unknown, limit: number, label: string): readonly unknown[] => {
  if (!Array.isArray(value) || types.isProxy(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > limit || Object.getOwnPropertySymbols(value).length !== 0 || Object.getOwnPropertyNames(value).length !== value.length + 1) throw new ReleaseClosureError(`${label} must be a bounded plain dense array`);
  const out: unknown[] = [];
  for (let index = 0; index < value.length; index++) { const descriptor = Object.getOwnPropertyDescriptor(value, index); if (descriptor === undefined || !descriptor.enumerable || descriptor.get || descriptor.set || !("value" in descriptor)) throw new ReleaseClosureError(`${label}[${index}] is not a plain value`); out.push(descriptor.value); }
  return Object.freeze(out);
};
const text = (value: unknown, label: string): string => { if (typeof value !== "string" || value.length === 0 || value.length > 8192 || !isWellFormedText(value) || value.normalize("NFC") !== value) throw new ReleaseClosureError(`${label} is not bounded NFC text`); return value; };
const id = (value: unknown, label: string): string => { const result = text(value, label); if (!ID.test(result)) throw new ReleaseClosureError(`${label} is not a stable id`); return result; };
const digest = (value: unknown, label: string, empty = false): string => { if (empty && value === "") return ""; const result = text(value, label); if (!HEX64.test(result) || result === sha256("") || /^([0-9a-f])\1{63}$/.test(result)) throw new ReleaseClosureError(`${label} is not a non-placeholder digest`); return result; };
const epoch = (value: unknown, label: string): bigint => { if (typeof value !== "bigint" || value < 0n || value > 0xffffffffffffffffn) throw new ReleaseClosureError(`${label} is not a bounded epoch`); return value; };
const enumValue = <T extends string>(value: unknown, allowed: ReadonlySet<T>, label: string): T => { if (typeof value !== "string" || !allowed.has(value as T)) throw new ReleaseClosureError(`${label} is unsupported`); return value as T; };

function securityCanonical(value: ReleaseSecurityPosture): CanonicalValue {
  return { trustedTime: value.trustedTime, signerRevocation: value.signerRevocation, rollbackProtection: value.rollbackProtection, immutableArtifact: value.immutableArtifact };
}

function payloadCanonical(value: ReleaseClosurePayloadV2): CanonicalValue {
  return {
    schema: RELEASE_CLOSURE_V2.name, version: BigInt(value.version), profile: value.profile,
    subjectDigest: value.subjectDigest, releaseEpoch: value.releaseEpoch, sequence: value.sequence,
    predecessorClosureDigest: value.predecessorClosureDigest, graphDigest: value.graphDigest,
    ledgersDigest: value.ledgersDigest, observedWorldDigest: value.observedWorldDigest,
    artifactInventoryDigest: value.artifactInventoryDigest, effectManifestDigest: value.effectManifestDigest,
    policyBundleDigest: value.policyBundleDigest, scannerToolDigest: value.scannerToolDigest,
    authorityWaiverDigest: value.authorityWaiverDigest, providerDescriptorDigest: value.providerDescriptorDigest,
    issuedAtMs: value.issuedAtMs, expiresAtMs: value.expiresAtMs,
    keyEpoch: value.keyEpoch, security: securityCanonical(value.security), claimCeiling: value.claimCeiling,
  };
}

export const releaseClosurePayloadDigest = (payload: ReleaseClosurePayloadV2): string => eirDigest("keep.release-closure.payload/v2", payloadCanonical(payload));
const signaturePreimage = (payloadDigest: string): string => eirDigest("keep.release-closure.signature-preimage/v2", { payloadDigest });

export class Ed25519ReleaseClosureSigner implements ReleaseClosureSigner {
  readonly algorithm = "ed25519" as const;
  readonly #key: KeyObject;
  constructor(readonly keyId: string, readonly keyEpoch: bigint, privateKeyPem: string) { id(keyId, "signer.keyId"); epoch(keyEpoch, "signer.keyEpoch"); this.#key = createPrivateKey(privateKeyPem); if (this.#key.asymmetricKeyType !== "ed25519") throw new ReleaseClosureError("signer key is not Ed25519"); }
  sign(preimageDigest: string): string { return cryptoSign(null, Buffer.from(digest(preimageDigest, "preimageDigest"), "hex"), this.#key).toString("base64url"); }
}

export class StubReleaseClosureSigner implements ReleaseClosureSigner {
  readonly algorithm = "stub-sha256" as const;
  constructor(readonly keyId: string, readonly keyEpoch: bigint, private readonly key: string) { id(keyId, "signer.keyId"); epoch(keyEpoch, "signer.keyEpoch"); text(key, "signer.key"); }
  sign(preimageDigest: string): string { return Buffer.from(sha256(`${this.key}\0${preimageDigest}`), "hex").toString("base64url"); }
}

function captureSecurity(input: unknown): ReleaseSecurityPosture {
  const row = exact(input, ["trustedTime", "signerRevocation", "rollbackProtection", "immutableArtifact"], "payload.security");
  return Object.freeze({ trustedTime: enumValue(row.trustedTime, STATUSES, "security.trustedTime"), signerRevocation: enumValue(row.signerRevocation, STATUSES, "security.signerRevocation"), rollbackProtection: enumValue(row.rollbackProtection, STATUSES, "security.rollbackProtection"), immutableArtifact: enumValue(row.immutableArtifact, STATUSES, "security.immutableArtifact") });
}

function capturePayload(input: unknown): ReleaseClosurePayloadV2 {
  const keys = ["version", "profile", "subjectDigest", "releaseEpoch", "sequence", "predecessorClosureDigest", "graphDigest", "ledgersDigest", "observedWorldDigest", "artifactInventoryDigest", "effectManifestDigest", "policyBundleDigest", "scannerToolDigest", "authorityWaiverDigest", "providerDescriptorDigest", "issuedAtMs", "expiresAtMs", "keyEpoch", "security", "claimCeiling"];
  const row = exact(input, keys, "payload"); if (row.version !== 2) throw new ReleaseClosureError("unsupported payload version");
  const issuedAtMs = epoch(row.issuedAtMs, "payload.issuedAtMs"); const expiresAtMs = epoch(row.expiresAtMs, "payload.expiresAtMs");
  if (expiresAtMs <= issuedAtMs || expiresAtMs - issuedAtMs > MAX_RELEASE_CLOSURE_LIFETIME_MS) throw new ReleaseClosureError("payload lifetime is invalid");
  const profile = enumValue(row.profile, PROFILES, "payload.profile"); const security = captureSecurity(row.security);
  const payload = Object.freeze({ version: 2 as const, profile, subjectDigest: digest(row.subjectDigest, "payload.subjectDigest"), releaseEpoch: epoch(row.releaseEpoch, "payload.releaseEpoch"), sequence: epoch(row.sequence, "payload.sequence"), predecessorClosureDigest: digest(row.predecessorClosureDigest, "payload.predecessorClosureDigest", true), graphDigest: digest(row.graphDigest, "payload.graphDigest"), ledgersDigest: digest(row.ledgersDigest, "payload.ledgersDigest"), observedWorldDigest: digest(row.observedWorldDigest, "payload.observedWorldDigest"), artifactInventoryDigest: digest(row.artifactInventoryDigest, "payload.artifactInventoryDigest"), effectManifestDigest: digest(row.effectManifestDigest, "payload.effectManifestDigest"), policyBundleDigest: digest(row.policyBundleDigest, "payload.policyBundleDigest"), scannerToolDigest: digest(row.scannerToolDigest, "payload.scannerToolDigest"), authorityWaiverDigest: digest(row.authorityWaiverDigest, "payload.authorityWaiverDigest"), providerDescriptorDigest: digest(row.providerDescriptorDigest, "payload.providerDescriptorDigest"), issuedAtMs, expiresAtMs, keyEpoch: epoch(row.keyEpoch, "payload.keyEpoch"), security, claimCeiling: row.claimCeiling === "Specified" || row.claimCeiling === "Load-bearing" ? row.claimCeiling : (() => { throw new ReleaseClosureError("payload.claimCeiling is unsupported"); })() });
  const fullyEnforced = Object.values(security).every((status) => status === "enforced");
  if ((profile === "production" || profile === "restricted") && (!fullyEnforced || payload.claimCeiling !== "Load-bearing")) throw new ReleaseClosureError("production/restricted closure requires every security mechanism enforced and Load-bearing ceiling");
  if ((profile === "sacrificial" || profile === "local-development") && payload.claimCeiling !== "Specified") throw new ReleaseClosureError("development closure claim ceiling must be Specified");
  return payload;
}

function captureClosure(input: unknown): SignedReleaseClosureV2 {
  const row = exact(input, ["payload", "payloadDigest", "signatures"], "closure"); const payload = capturePayload(row.payload); const payloadDigest = digest(row.payloadDigest, "closure.payloadDigest");
  const signatureInput = exactArray(row.signatures, 32, "closure.signatures"); if (signatureInput.length === 0) throw new ReleaseClosureError("closure.signatures must not be empty");
  const signatures = Object.freeze(signatureInput.map((value, index) => { const entry = exact(value, ["keyId", "algorithm", "keyEpoch", "signature"], `signatures[${index}]`); const signature = text(entry.signature, `signatures[${index}].signature`); if (!BASE64URL.test(signature)) throw new ReleaseClosureError(`signatures[${index}].signature is malformed`); return Object.freeze({ keyId: id(entry.keyId, `signatures[${index}].keyId`), algorithm: enumValue(entry.algorithm, ALGORITHMS, `signatures[${index}].algorithm`), keyEpoch: epoch(entry.keyEpoch, `signatures[${index}].keyEpoch`), signature }); }).sort((a, b) => a.keyId < b.keyId ? -1 : a.keyId > b.keyId ? 1 : 0));
  if (signatures.some((entry, index) => index > 0 && entry.keyId === signatures[index - 1]!.keyId)) throw new ReleaseClosureError("closure has duplicate signer key ids");
  return Object.freeze({ payload, payloadDigest, signatures });
}

function validateBindings(input: unknown): ReleaseClosureBindings {
  const row = exact(input, ["artifactInventoryDigest", "effectManifestDigest", "policyBundleDigest", "scannerToolDigest", "authorityWaiverDigest", "providerDescriptorDigest"], "bindings");
  return Object.freeze({ artifactInventoryDigest: digest(row.artifactInventoryDigest, "bindings.artifactInventoryDigest"), effectManifestDigest: digest(row.effectManifestDigest, "bindings.effectManifestDigest"), policyBundleDigest: digest(row.policyBundleDigest, "bindings.policyBundleDigest"), scannerToolDigest: digest(row.scannerToolDigest, "bindings.scannerToolDigest"), authorityWaiverDigest: digest(row.authorityWaiverDigest, "bindings.authorityWaiverDigest"), providerDescriptorDigest: digest(row.providerDescriptorDigest, "bindings.providerDescriptorDigest") });
}

export function compileReleaseClosureV2(input: {
  readonly profile: ReleaseProfile; readonly graph: unknown; readonly world: unknown; readonly context: unknown;
  readonly bindings: ReleaseClosureBindings; readonly lineage: ReleaseLineageExpectation; readonly security: ReleaseSecurityPosture;
  readonly issuedAtMs: bigint; readonly expiresAtMs: bigint; readonly keyEpoch: bigint; readonly signers: readonly ReleaseClosureSigner[]; readonly threshold?: number;
}): SignedReleaseClosureV2 {
  const graph = captureCapabilityGraphV2(input.graph); const ledgers = deriveCapabilityLedgers(graph, input.world, input.context);
  if (!ledgers.inventory.valid || ledgers.verifiedAtMs === null) throw new ReleaseClosureError("cannot sign an unreconciled capability world");
  const bindings = validateBindings(input.bindings); const profile = enumValue(input.profile, PROFILES, "profile"); const keyEpoch = epoch(input.keyEpoch, "keyEpoch");
  if (bindings.artifactInventoryDigest !== graph.subjectDigest) throw new ReleaseClosureError("artifact inventory digest must equal capability graph subject digest");
  const signers = captureSigners(input.signers);
  const threshold = input.threshold ?? signers.length; if (!Number.isInteger(threshold) || threshold < 1 || threshold > signers.length) throw new ReleaseClosureError("signature threshold is invalid");
  const claimCeiling = profile === "production" || profile === "restricted" ? "Load-bearing" as const : "Specified" as const;
  if (input.issuedAtMs !== ledgers.verifiedAtMs || ledgers.verifiedAtMs >= input.expiresAtMs) throw new ReleaseClosureError("compiler context must use the exact issuedAtMs and precede expiry");
  if ((input.lineage.sequence === 0n) !== (input.lineage.predecessorClosureDigest === "")) throw new ReleaseClosureError("genesis lineage requires sequence 0 and empty predecessor exactly");
  const payload = capturePayload({ version: 2, profile, subjectDigest: graph.subjectDigest, releaseEpoch: graph.releaseEpoch, sequence: input.lineage.sequence, predecessorClosureDigest: input.lineage.predecessorClosureDigest, graphDigest: graph.digest, ledgersDigest: ledgers.digest, observedWorldDigest: ledgers.inventory.observedWorldDigest, ...bindings, issuedAtMs: input.issuedAtMs, expiresAtMs: input.expiresAtMs, keyEpoch, security: input.security, claimCeiling });
  if ((profile === "production" || profile === "restricted") && signers.some((signer) => signer.algorithm !== "ed25519")) throw new ReleaseClosureError("production/restricted closure refuses stub signers");
  for (const signer of signers) if (signer.keyEpoch !== keyEpoch) throw new ReleaseClosureError("signer key epoch differs from closure key epoch");
  const payloadDigest = releaseClosurePayloadDigest(payload); const preimage = signaturePreimage(payloadDigest);
  const signingDeadline = performance.now() + MAX_RELEASE_CLOSURE_VERIFICATION_MS;
  const signatures = signers.map((signer) => { if (performance.now() > signingDeadline) throw new ReleaseClosureError("signing budget exceeded"); const signature = text(signer.sign(preimage), `signer ${signer.keyId} signature`); if (performance.now() > signingDeadline) throw new ReleaseClosureError("signing budget exceeded"); return Object.freeze({ keyId: signer.keyId, algorithm: signer.algorithm, keyEpoch: signer.keyEpoch, signature }); }).sort((a, b) => a.keyId < b.keyId ? -1 : a.keyId > b.keyId ? 1 : 0);
  const closure = captureClosure({ payload, payloadDigest, signatures });
  if (closure.signatures.length < threshold) throw new ReleaseClosureError("compiler signer threshold cannot be met");
  return closure;
}

function signatureValid(signature: ReleaseClosureSignatureV2, anchor: ReleaseClosureTrustAnchor, preimage: string): boolean {
  try {
    const bytes = Buffer.from(signature.signature, "base64url");
    if (signature.algorithm === "ed25519") { const key = createPublicKey(anchor.verifyKey); return key.asymmetricKeyType === "ed25519" && cryptoVerify(null, Buffer.from(preimage, "hex"), key, bytes); }
    const expected = Buffer.from(sha256(`${anchor.verifyKey}\0${preimage}`), "hex"); return bytes.length === expected.length && timingSafeEqual(bytes, expected);
  } catch { return false; }
}

function effectiveLedgersOf(ledgers: CapabilityLedgers, claimCeiling: "Specified" | "Load-bearing"): EffectiveCapabilityLedgers {
  if (claimCeiling === "Load-bearing") return Object.freeze({ ...ledgers, sourceLedgerDigest: ledgers.digest });
  const claims = Object.freeze(ledgers.claims.map((claim) => Object.freeze({ ...claim, assurance: "unknown" as const, taxonomyCeiling: "Specified" as const, supported: false, reasons: Object.freeze([...claim.reasons, "release profile mechanically caps claims at Specified"]) })));
  const deployment = Object.freeze(ledgers.deployment.map((row) => Object.freeze({ ...row, assurance: "unknown" as const })));
  const authority = Object.freeze(ledgers.authority.map((row) => Object.freeze({ ...row, assurance: "unknown" as const })));
  const residuals = Object.freeze(ledgers.residuals.map((row) => Object.freeze({ ...row, assurance: "unknown" as const })));
  const compatibility = Object.freeze(ledgers.compatibility.map((row) => Object.freeze({ ...row, assurance: "unknown" as const })));
  const evidence = Object.freeze(ledgers.evidence.map((row) => Object.freeze({ ...row, assurance: "unknown" as const })));
  const digestValue = eirDigest("keep.release-closure.effective-ledgers/v2", { sourceLedgerDigest: ledgers.digest, claimCeiling, claims: claims.map((claim) => ({ id: claim.id, assurance: claim.assurance, taxonomyCeiling: claim.taxonomyCeiling, supported: claim.supported, reasons: claim.reasons })) });
  return Object.freeze({ ...ledgers, deployment, authority, residuals, compatibility, evidence, claims, sourceLedgerDigest: ledgers.digest, digest: digestValue });
}

function trustKeyIdentity(algorithm: ClosureSignatureAlgorithm, verifyKey: string): string {
  if (algorithm === "stub-sha256") return eirDigest("keep.release-closure.stub-trust-key/v2", { verifyKey });
  try { const key = createPublicKey(verifyKey); if (key.asymmetricKeyType !== "ed25519") throw new ReleaseClosureError("trust key is not Ed25519"); return createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex"); }
  catch (error) { throw new ReleaseClosureError(`invalid Ed25519 trust key:${safeMessage(error)}`); }
}

export function verifyReleaseClosureV2(input: ReleaseClosureVerificationInput): ReleaseClosureVerdict {
  try {
    const deadline = performance.now() + MAX_RELEASE_CLOSURE_VERIFICATION_MS; const checkBudget = (): void => { if (performance.now() > deadline) throw new ReleaseClosureError("verification budget exceeded"); };
    const closure = captureClosure(input.closure); if (releaseClosurePayloadDigest(closure.payload) !== closure.payloadDigest) return { valid: false, reason: "payload digest mismatch" };
    const graph = captureCapabilityGraphArgument(input.graph); checkBudget();
    const compiledLedgers = deriveCapabilityLedgers(graph, input.world, { trustedNowMs: closure.payload.issuedAtMs }); checkBudget();
    if (!compiledLedgers.inventory.valid || compiledLedgers.verifiedAtMs !== closure.payload.issuedAtMs || compiledLedgers.digest !== closure.payload.ledgersDigest) return { valid: false, reason: "signed compile-time ledger snapshot does not reconstruct" };
    const currentLedgers = deriveCapabilityLedgers(graph, input.world, input.context); checkBudget(); const bindings = validateBindings(input.bindings);
    if (!currentLedgers.inventory.valid || currentLedgers.verifiedAtMs === null) return { valid: false, reason: "installed capability world does not reconcile at verifier time" };
    const now = currentLedgers.verifiedAtMs; const payload = closure.payload;
    const expectedProfile = enumValue(input.expectedProfile, PROFILES, "expectedProfile"); if (payload.profile !== expectedProfile) return { valid: false, reason: "closure profile differs from boot expectation" };
    if (!(payload.issuedAtMs <= now && now < payload.expiresAtMs)) return { valid: false, reason: "closure is not current at verifier time" };
    if (payload.subjectDigest !== graph.subjectDigest || payload.artifactInventoryDigest !== graph.subjectDigest || payload.releaseEpoch !== graph.releaseEpoch || payload.graphDigest !== graph.digest || payload.observedWorldDigest !== currentLedgers.inventory.observedWorldDigest) return { valid: false, reason: "closure artifact/graph/world lineage mismatch" };
    for (const key of Object.keys(bindings) as Array<keyof ReleaseClosureBindings>) if (payload[key] !== bindings[key]) return { valid: false, reason: `closure ${key} binding mismatch` };
    if (payload.sequence !== input.lineage.sequence || payload.predecessorClosureDigest !== input.lineage.predecessorClosureDigest || ((payload.sequence === 0n) !== (payload.predecessorClosureDigest === ""))) return { valid: false, reason: "closure rollback lineage mismatch" };
    const observedSecurity = captureSecurity(input.observedSecurity); for (const key of Object.keys(observedSecurity) as Array<keyof ReleaseSecurityPosture>) if (payload.security[key] !== observedSecurity[key]) return { valid: false, reason: `closure security posture mismatch:${key}` };
    if ((payload.profile === "production" || payload.profile === "restricted") && Object.values(observedSecurity).some((status) => status !== "enforced")) return { valid: false, reason: "production/restricted environment lacks an enforced security mechanism" };
    const bootNonce = id(input.bootNonce, "bootNonce"); const threshold = input.trust?.threshold; if (!Number.isInteger(threshold) || threshold < 1 || threshold > 32) return { valid: false, reason: "invalid trust threshold" };
    const anchorInput = exactArray(input.trust?.anchors, 32, "trust.anchors");
    const anchors = new Map<string, ReleaseClosureTrustAnchor>(); const keyMaterials = new Set<string>();
    for (const [index, value] of anchorInput.entries()) {
      const row = exact(value, ["keyId", "algorithm", "verifyKey", "keyEpoch", "validFromMs", "validUntilMs", "revokedAtMs"], `trust.anchors[${index}]`);
      const anchor = Object.freeze({ keyId: id(row.keyId, `trust.anchors[${index}].keyId`), algorithm: enumValue(row.algorithm, ALGORITHMS, `trust.anchors[${index}].algorithm`), verifyKey: text(row.verifyKey, `trust.anchors[${index}].verifyKey`), keyEpoch: epoch(row.keyEpoch, `trust.anchors[${index}].keyEpoch`), validFromMs: epoch(row.validFromMs, `trust.anchors[${index}].validFromMs`), validUntilMs: epoch(row.validUntilMs, `trust.anchors[${index}].validUntilMs`), revokedAtMs: row.revokedAtMs === null ? null : epoch(row.revokedAtMs, `trust.anchors[${index}].revokedAtMs`) });
      if (anchor.validUntilMs <= anchor.validFromMs || (anchor.revokedAtMs !== null && anchor.revokedAtMs < anchor.validFromMs)) return { valid: false, reason: "trust anchor validity/revocation interval is invalid" };
      const material = trustKeyIdentity(anchor.algorithm, anchor.verifyKey); if (keyMaterials.has(material)) return { valid: false, reason: "duplicate trust key material cannot count twice toward quorum" }; keyMaterials.add(material);
      if (anchors.has(anchor.keyId)) return { valid: false, reason: "duplicate trust anchor" }; anchors.set(anchor.keyId, anchor);
    }
    const preimage = signaturePreimage(closure.payloadDigest); let valid = 0; const seen = new Set<string>();
    for (const signature of closure.signatures) {
      const anchor = anchors.get(signature.keyId); if (anchor === undefined || seen.has(signature.keyId) || anchor.algorithm !== signature.algorithm || anchor.keyEpoch !== signature.keyEpoch || signature.keyEpoch !== payload.keyEpoch) continue;
      if (!(anchor.validFromMs <= now && now < anchor.validUntilMs) || (anchor.revokedAtMs !== null && anchor.revokedAtMs <= now)) continue;
      if ((payload.profile === "production" || payload.profile === "restricted") && signature.algorithm !== "ed25519") continue;
      if (signatureValid(signature, anchor, preimage)) { seen.add(signature.keyId); valid++; }
    }
    if (valid < threshold) return { valid: false, reason: `signature threshold not met:${valid}<${threshold}` };
    const effectiveLedgers = effectiveLedgersOf(currentLedgers, payload.claimCeiling);
    const admission = Object.freeze({ closureDigest: closure.payloadDigest, graphDigest: graph.digest, subjectDigest: graph.subjectDigest, releaseEpoch: graph.releaseEpoch, profile: payload.profile, claimCeiling: payload.claimCeiling, bootNonce, issuedAtMs: payload.issuedAtMs, expiresAtMs: payload.expiresAtMs }); admissionTokens.add(admission);
    return { valid: true, closure, graph, effectiveLedgers, admission };
  } catch (error) { return { valid: false, reason: safeMessage(error) }; }
}

export function verifyReleaseAdmissionToken(token: unknown, expected: { readonly closureDigest: string; readonly graphDigest: string; readonly subjectDigest: string; readonly releaseEpoch: bigint; readonly profile: ReleaseProfile; readonly claimCeiling: "Specified" | "Load-bearing"; readonly bootNonce: string; readonly issuedAtMs: bigint; readonly nowMs: bigint }): token is ReleaseAdmissionToken {
  if (token === null || typeof token !== "object" || !admissionTokens.has(token as object)) return false;
  const row = token as ReleaseAdmissionToken;
  return row.closureDigest === expected.closureDigest && row.graphDigest === expected.graphDigest && row.subjectDigest === expected.subjectDigest && row.releaseEpoch === expected.releaseEpoch && row.profile === expected.profile && row.claimCeiling === expected.claimCeiling && row.bootNonce === expected.bootNonce && row.issuedAtMs === expected.issuedAtMs && row.issuedAtMs <= expected.nowMs && expected.nowMs < row.expiresAtMs;
}
