/** Pure, non-authorizing AuditPlanV1 capture. No I/O, signing, review, or status capability. */
import { createHash } from "node:crypto";
import { types } from "node:util";
import { decodeCanonical, encodeCanonical, type CanonicalValue } from "../eir/canonical.js";

const DOMAIN = "keep.p2-d2-audit-plan/v1\0";
const PLAN_SCHEMA = "keep.p2-d2-audit-plan";
const REGISTRY_SCHEMA = "keep.p2-d2-native-reviewer-registry";
const CLAIM_SCHEMA = "keep.p2-d2-evidence/v1";
const ROLES = ["advisory", "build-policy", "correctness", "license", "unsafe-contract"] as const;
const HEX64 = /^[0-9a-f]{64}$/u;
const IDENTIFIER = /^[a-z0-9](?:[a-z0-9._:/@-]{0,254}[a-z0-9])?$/u;
const ZERO = "0".repeat(64);
const PLAN_KEYS = ["schema", "version", "planId", "claimSchema", "reviewerRegistry", "producerKeyDigests", "validatorKeyDigests", "requiredClaims", "separationPolicy"] as const;
const REGISTRY_KEYS = ["schema", "version", "registryId", "revocationListDigest", "reviewers"] as const;
const REVIEWER_KEYS = ["principal", "reviewerFamily", "custodianFamily", "mechanism", "publicKeyAlgorithm", "publicKeyOrTrustRoot", "issuer", "subject", "repository", "workflow", "allowedRoles", "validFromCounter", "validThroughCounter", "revocationIdentity"] as const;
const CLAIM_KEYS = ["role", "minimumReviewers", "minimumReviewerFamilies", "minimumCustodianFamilies"] as const;
const SEPARATION_KEYS = ["distinctPrincipals", "distinctReviewerFamilies", "distinctCustodianFamilies", "producerReviewerDisjoint", "validatorReviewerDisjoint", "keysOffCollectorHost"] as const;

export class NativeP2D2AuditPlanError extends Error {
  constructor(message: string) { super(`native P2-D2 audit plan: ${message}`); this.name = "NativeP2D2AuditPlanError"; }
}

export interface ValidatedAuditPlanV1 {
  readonly kind: "ValidatedAuditPlanV1";
  readonly auditPlanDigest: string;
  canonicalBytes(): Uint8Array;
}

function record(value: CanonicalValue, path: string): Record<string, CanonicalValue> {
  if (value === null || Array.isArray(value) || value instanceof Uint8Array || typeof value !== "object")
    throw new NativeP2D2AuditPlanError(`${path} is not a record`);
  return value as Record<string, CanonicalValue>;
}
function exact(row: Record<string, CanonicalValue>, keys: readonly string[], path: string): void {
  const actual = Object.keys(row).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index]))
    throw new NativeP2D2AuditPlanError(`${path} fields are not exact`);
}
function identifier(value: CanonicalValue | undefined, path: string): string {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) throw new NativeP2D2AuditPlanError(`${path} is malformed`);
  return value;
}
function digest(value: CanonicalValue | undefined, path: string): string {
  if (typeof value !== "string" || !HEX64.test(value) || value === ZERO)
    throw new NativeP2D2AuditPlanError(`${path} is not a nonzero SHA-256`);
  return value;
}
function boundedText(value: CanonicalValue | undefined, path: string): string {
  if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value, "utf8") > 512 ||
      ![...Buffer.from(value, "utf8")].every((byte) => byte >= 0x20 && byte <= 0x7e))
    throw new NativeP2D2AuditPlanError(`${path} is not bounded native text`);
  return value;
}
function nullableText(value: CanonicalValue | undefined, path: string): string | null {
  if (value === null) return null;
  return boundedText(value, path);
}
function uint(value: CanonicalValue | undefined, path: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > 0xffff_ffff_ffff_ffffn)
    throw new NativeP2D2AuditPlanError(`${path} is not uint64`);
  return value;
}
function sortedUniqueText(value: CanonicalValue | undefined, path: string, exactSet?: readonly string[]): string[] {
  if (!Array.isArray(value) || value.length === 0) throw new NativeP2D2AuditPlanError(`${path} is empty or not an array`);
  const rows = value.map((entry, index) => identifier(entry, `${path}[${index}]`));
  if (rows.some((entry, index) => index > 0 && entry <= rows[index - 1]!))
    throw new NativeP2D2AuditPlanError(`${path} is not strictly ordered and unique`);
  if (exactSet !== undefined && (rows.length !== exactSet.length || rows.some((entry, index) => entry !== exactSet[index])))
    throw new NativeP2D2AuditPlanError(`${path} differs from the frozen role set`);
  return rows;
}
function sortedUniqueDigests(value: CanonicalValue | undefined, path: string): string[] {
  if (!Array.isArray(value) || value.length === 0) throw new NativeP2D2AuditPlanError(`${path} is empty or not an array`);
  const rows = value.map((entry, index) => digest(entry, `${path}[${index}]`));
  if (rows.some((entry, index) => index > 0 && entry <= rows[index - 1]!))
    throw new NativeP2D2AuditPlanError(`${path} is not strictly ordered and unique`);
  return rows;
}

export function captureAuditPlanV1(input: unknown): ValidatedAuditPlanV1 {
  if (input === null || typeof input !== "object" || types.isProxy(input) || !(input instanceof Uint8Array) || input.byteLength === 0 || input.byteLength > 1024 * 1024)
    throw new NativeP2D2AuditPlanError("input is not an owned bounded byte string");
  const decoded = decodeCanonical(input);
  const canonical = encodeCanonical(decoded);
  if (!Buffer.from(canonical).equals(Buffer.from(input))) throw new NativeP2D2AuditPlanError("encoding is noncanonical");
  const plan = record(decoded, "plan"); exact(plan, PLAN_KEYS, "plan");
  if (plan.schema !== PLAN_SCHEMA || plan.version !== 1n || plan.claimSchema !== CLAIM_SCHEMA)
    throw new NativeP2D2AuditPlanError("plan schema/version/claim schema disagreed");
  identifier(plan.planId, "plan.planId");
  const producer = sortedUniqueDigests(plan.producerKeyDigests, "plan.producerKeyDigests");
  const validator = sortedUniqueDigests(plan.validatorKeyDigests, "plan.validatorKeyDigests");
  if (producer.some((key) => validator.includes(key))) throw new NativeP2D2AuditPlanError("producer and validator keys overlap");

  const registry = record(plan.reviewerRegistry!, "registry"); exact(registry, REGISTRY_KEYS, "registry");
  if (registry.schema !== REGISTRY_SCHEMA || registry.version !== 1n) throw new NativeP2D2AuditPlanError("registry schema/version disagreed");
  identifier(registry.registryId, "registry.registryId"); digest(registry.revocationListDigest, "registry.revocationListDigest");
  if (!Array.isArray(registry.reviewers) || registry.reviewers.length < 2 || registry.reviewers.length > 16)
    throw new NativeP2D2AuditPlanError("registry reviewer count violates the threshold bound");
  const principals = new Set<string>(), reviewerFamilies = new Set<string>(), custodianFamilies = new Set<string>();
  const verificationKeys = new Set<string>(), revocations = new Set<string>(); let previousPrincipal = "";
  for (const [index, value] of registry.reviewers.entries()) {
    const row = record(value, `reviewers[${index}]`); exact(row, REVIEWER_KEYS, `reviewers[${index}]`);
    const principal = identifier(row.principal, `reviewers[${index}].principal`);
    if (principal <= previousPrincipal || principals.has(principal)) throw new NativeP2D2AuditPlanError("reviewers are not principal-ordered and unique");
    previousPrincipal = principal; principals.add(principal);
    reviewerFamilies.add(identifier(row.reviewerFamily, `reviewers[${index}].reviewerFamily`));
    custodianFamilies.add(identifier(row.custodianFamily, `reviewers[${index}].custodianFamily`));
    const key = digest(row.publicKeyOrTrustRoot, `reviewers[${index}].publicKeyOrTrustRoot`);
    const revocation = digest(row.revocationIdentity, `reviewers[${index}].revocationIdentity`);
    if (verificationKeys.has(key) || revocations.has(revocation) || producer.includes(key) || validator.includes(key))
      throw new NativeP2D2AuditPlanError("reviewer key/revocation identity duplicates or overlaps authority keys");
    verificationKeys.add(key); revocations.add(revocation);
    sortedUniqueText(row.allowedRoles, `reviewers[${index}].allowedRoles`, ROLES);
    const from = uint(row.validFromCounter, `reviewers[${index}].validFromCounter`);
    const through = uint(row.validThroughCounter, `reviewers[${index}].validThroughCounter`);
    if (from > through) throw new NativeP2D2AuditPlanError("reviewer validity interval is inverted");
    const mechanism = row.mechanism, algorithm = row.publicKeyAlgorithm;
    const identityFields = [row.issuer, row.subject, row.repository, row.workflow];
    if (mechanism === "ed25519-service") {
      if (algorithm !== "ed25519" || identityFields.some((entry) => entry !== null))
        throw new NativeP2D2AuditPlanError("Ed25519 mechanism fields disagree");
    } else if (mechanism === "sigstore-keyless") {
      if (algorithm !== "sigstore-fulcio-ecdsa-p256" || identityFields.some((entry, fieldIndex) => nullableText(entry, `reviewers[${index}].identity[${fieldIndex}]`) === null))
        throw new NativeP2D2AuditPlanError("Sigstore mechanism fields disagree");
    } else throw new NativeP2D2AuditPlanError("reviewer mechanism is unknown");
  }
  if (reviewerFamilies.size < 2 || custodianFamilies.size < 2) throw new NativeP2D2AuditPlanError("registry lacks two independent families");

  if (!Array.isArray(plan.requiredClaims) || plan.requiredClaims.length !== ROLES.length)
    throw new NativeP2D2AuditPlanError("required claim set is incomplete");
  plan.requiredClaims.forEach((value, index) => {
    const row = record(value, `requiredClaims[${index}]`); exact(row, CLAIM_KEYS, `requiredClaims[${index}]`);
    if (row.role !== ROLES[index] || row.minimumReviewers !== 2n || row.minimumReviewerFamilies !== 2n || row.minimumCustodianFamilies !== 2n)
      throw new NativeP2D2AuditPlanError("required claim threshold differs from the frozen policy");
  });
  const separation = record(plan.separationPolicy!, "separationPolicy"); exact(separation, SEPARATION_KEYS, "separationPolicy");
  if (SEPARATION_KEYS.some((key) => separation[key] !== true)) throw new NativeP2D2AuditPlanError("a separation invariant is disabled");
  const bytes = Uint8Array.from(input);
  const auditPlanDigest = createHash("sha256").update(DOMAIN, "ascii").update(bytes).digest("hex");
  return Object.freeze({ kind: "ValidatedAuditPlanV1", auditPlanDigest, canonicalBytes: () => Uint8Array.from(bytes) });
}
