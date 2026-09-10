import { eirDigest, type CanonicalValue } from "../eir/canonical.js";
import { ENFORCEMENT_FIELDS, ENFORCEMENT_STATUSES, type EnforcementField, type EnforcementStatus } from "./enforcement_profile.js";

export interface ProfileMeasurement {
  readonly field: EnforcementField;
  readonly value: EnforcementStatus;
  readonly evidenceDigest: string;
  readonly deploymentIdentity: string;
  readonly bootIdentity: string;
  readonly nonce: string;
  readonly measuredAtMs: bigint;
  readonly expiresAtMs: bigint;
  readonly proberPrincipal: string;
  readonly keyEpoch: bigint;
}

export interface ProfileAttestation {
  readonly measurement: ProfileMeasurement;
  readonly digest: string;
  readonly keyid: string;
  readonly signature: string;
}

export interface ProfileAttestationSigner {
  readonly keyid: string;
  sign(digest: string): string;
}

export interface ProfileAttestationVerifier {
  verify(keyid: string, digest: string, signature: string): boolean;
}

export interface ProberTrustPin {
  readonly principal: string;
  readonly keyid: string;
  readonly keyEpoch: bigint;
  /** Every role/principal the prober must be distinct from for this deployment. */
  readonly forbiddenPrincipals: ReadonlySet<string>;
}

const HEX64 = /^[0-9a-f]{64}$/;
const text = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length <= 512;
const FIELD_SET: ReadonlySet<string> = new Set(ENFORCEMENT_FIELDS);
const STATUS_SET: ReadonlySet<string> = new Set(ENFORCEMENT_STATUSES);

export function profileMeasurementDigest(m: ProfileMeasurement): string {
  const content: CanonicalValue = {
    field: m.field, value: m.value, evidenceDigest: m.evidenceDigest,
    deploymentIdentity: m.deploymentIdentity, bootIdentity: m.bootIdentity, nonce: m.nonce,
    measuredAtMs: m.measuredAtMs, expiresAtMs: m.expiresAtMs,
    proberPrincipal: m.proberPrincipal, keyEpoch: m.keyEpoch,
  };
  return eirDigest("keep.profile-attestation/measurement/v1", content);
}

export function signProfileMeasurement(measurement: ProfileMeasurement, signer: ProfileAttestationSigner): ProfileAttestation {
  const digest = profileMeasurementDigest(measurement);
  return Object.freeze({ measurement: Object.freeze({ ...measurement }), digest, keyid: signer.keyid, signature: signer.sign(digest) });
}

export type AttestationVerdict =
  | { readonly valid: true; readonly digest: string }
  | { readonly valid: false; readonly reason: string };

export interface AttestationExpectation {
  readonly deploymentIdentity: string;
  readonly bootIdentity: string;
  readonly nonce: string;
  readonly nowMs: bigint;
  readonly maxTtlMs: bigint;
}

/** Process-local replay fence: a nonce is consumed only after schema, binding,
 * lifetime and signature checks succeed. This is not persistent replay storage
 * or evidence that a signed assertion describes an actually enforced control. */
export class ProfileAttestationGate {
  readonly #used = new Set<string>();
  readonly #pin: ProberTrustPin;
  readonly #verifier: ProfileAttestationVerifier;
  constructor(pin: ProberTrustPin, verifier: ProfileAttestationVerifier) { this.#pin = pin; this.#verifier = verifier; }

  verify(attestation: ProfileAttestation, expected: AttestationExpectation): AttestationVerdict {
    try {
      if (attestation === null || typeof attestation !== "object" || Array.isArray(attestation)) return { valid: false, reason: "malformed-attestation" };
      const raw = attestation.measurement;
      if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return { valid: false, reason: "malformed-schema" };
      // Capture the declared signed fields once. The caller-supplied verifier may
      // mutate its original objects; it must not change what this call consumes.
      const m: ProfileMeasurement = {
        field: raw.field, value: raw.value, evidenceDigest: raw.evidenceDigest,
        deploymentIdentity: raw.deploymentIdentity, bootIdentity: raw.bootIdentity, nonce: raw.nonce,
        measuredAtMs: raw.measuredAtMs, expiresAtMs: raw.expiresAtMs,
        proberPrincipal: raw.proberPrincipal, keyEpoch: raw.keyEpoch,
      };
      const { digest: suppliedDigest, keyid, signature } = attestation;
      if (typeof m.field !== "string" || !FIELD_SET.has(m.field) || typeof m.value !== "string" || !STATUS_SET.has(m.value)) return { valid: false, reason: "malformed-schema" };
      if (typeof m.measuredAtMs !== "bigint" || typeof m.expiresAtMs !== "bigint" || typeof m.keyEpoch !== "bigint"
        || typeof expected.nowMs !== "bigint" || typeof expected.maxTtlMs !== "bigint") return { valid: false, reason: "malformed-time-or-epoch" };
      if (!text(m.deploymentIdentity) || !text(m.bootIdentity) || !text(m.nonce) || !text(m.proberPrincipal)) return { valid: false, reason: "malformed-binding" };
      if (typeof m.evidenceDigest !== "string" || !HEX64.test(m.evidenceDigest) || typeof suppliedDigest !== "string" || !HEX64.test(suppliedDigest)) return { valid: false, reason: "malformed-digest" };
      if (typeof keyid !== "string" || typeof signature !== "string") return { valid: false, reason: "malformed-signature-envelope" };
      const nonce = m.nonce;
      if (m.deploymentIdentity !== expected.deploymentIdentity || m.bootIdentity !== expected.bootIdentity) return { valid: false, reason: "cross-deployment-or-boot" };
      if (nonce !== expected.nonce || this.#used.has(nonce)) return { valid: false, reason: "nonce-mismatch-or-replay" };
      if (m.proberPrincipal !== this.#pin.principal || keyid !== this.#pin.keyid || m.keyEpoch !== this.#pin.keyEpoch) return { valid: false, reason: "untrusted-prober-or-key-epoch" };
      if (this.#pin.forbiddenPrincipals.has(m.proberPrincipal)) return { valid: false, reason: "prober-not-independent" };
      if (m.measuredAtMs > expected.nowMs || m.expiresAtMs < expected.nowMs || m.expiresAtMs < m.measuredAtMs || m.expiresAtMs - m.measuredAtMs > expected.maxTtlMs) return { valid: false, reason: "stale-or-invalid-lifetime" };
      const digest = profileMeasurementDigest(m);
      // This port is synchronous and boolean. A promise/object is not a verified
      // signature, even if a JavaScript caller bypassed the declared port type.
      if (digest !== suppliedDigest || this.#verifier.verify(keyid, digest, signature) !== true) return { valid: false, reason: "bad-signature-or-content" };
      // A synchronous verifier may reenter this gate. Only one call can consume
      // the challenge, even if both calls passed their initial replay checks.
      if (this.#used.has(nonce)) return { valid: false, reason: "nonce-mismatch-or-replay" };
      this.#used.add(nonce);
      return { valid: true, digest };
    } catch { return { valid: false, reason: "malformed-attestation" }; }
  }
}
