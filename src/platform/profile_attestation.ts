import { eirDigest, type CanonicalValue } from "../eir/canonical.js";
import type { EnforcementField, EnforcementStatus } from "./enforcement_profile.js";

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

/** Stateful replay fence: a nonce is consumed only after every binding and signature check succeeds. */
export class ProfileAttestationGate {
  readonly #used = new Set<string>();
  readonly #pin: ProberTrustPin;
  readonly #verifier: ProfileAttestationVerifier;
  constructor(pin: ProberTrustPin, verifier: ProfileAttestationVerifier) { this.#pin = pin; this.#verifier = verifier; }

  verify(attestation: ProfileAttestation, expected: AttestationExpectation): AttestationVerdict {
    try {
      const m = attestation.measurement;
      if (!text(m.deploymentIdentity) || !text(m.bootIdentity) || !text(m.nonce) || !text(m.proberPrincipal)) return { valid: false, reason: "malformed-binding" };
      if (!HEX64.test(m.evidenceDigest) || !HEX64.test(attestation.digest)) return { valid: false, reason: "malformed-digest" };
      if (m.deploymentIdentity !== expected.deploymentIdentity || m.bootIdentity !== expected.bootIdentity) return { valid: false, reason: "cross-deployment-or-boot" };
      if (m.nonce !== expected.nonce || this.#used.has(m.nonce)) return { valid: false, reason: "nonce-mismatch-or-replay" };
      if (m.proberPrincipal !== this.#pin.principal || attestation.keyid !== this.#pin.keyid || m.keyEpoch !== this.#pin.keyEpoch) return { valid: false, reason: "untrusted-prober-or-key-epoch" };
      if (this.#pin.forbiddenPrincipals.has(m.proberPrincipal)) return { valid: false, reason: "prober-not-independent" };
      if (m.measuredAtMs > expected.nowMs || m.expiresAtMs < expected.nowMs || m.expiresAtMs < m.measuredAtMs || m.expiresAtMs - m.measuredAtMs > expected.maxTtlMs) return { valid: false, reason: "stale-or-invalid-lifetime" };
      const digest = profileMeasurementDigest(m);
      if (digest !== attestation.digest || !this.#verifier.verify(attestation.keyid, digest, attestation.signature)) return { valid: false, reason: "bad-signature-or-content" };
      this.#used.add(m.nonce);
      return { valid: true, digest };
    } catch { return { valid: false, reason: "malformed-attestation" }; }
  }
}
