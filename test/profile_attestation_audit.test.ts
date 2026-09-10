import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, verify } from "node:crypto";
import { ProfileAttestationGate, signProfileMeasurement, type ProfileMeasurement, type ProfileAttestation } from "../src/platform/profile_attestation.js";
import { ENFORCEMENT_FIELDS } from "../src/platform/enforcement_profile.js";

// Genuine synthetic signatures from a configured trusted prober, not a public
// gateway exploit, deployed measurement, or independent institutional attestation.
const keys = generateKeyPairSync("ed25519");
const signer = { keyid: "synthetic-k1", sign: (digest: string) => sign(null, Buffer.from(digest), keys.privateKey).toString("base64") };
const verifier = { verify: (keyid: string, digest: string, signature: string) => keyid === signer.keyid && verify(null, Buffer.from(digest), keys.publicKey, Buffer.from(signature, "base64")) };
const pin = { principal: "prober", keyid: signer.keyid, keyEpoch: 1n, forbiddenPrincipals: new Set(["operator"]) };
function input(deploymentIdentity = "personal") {
  const measurement: ProfileMeasurement = { field: "networkMediation", value: "enforced", evidenceDigest: "a".repeat(64),
    deploymentIdentity, bootIdentity: "boot1", nonce: "nonce1", measuredAtMs: 10n, expiresAtMs: 20n, proberPrincipal: pin.principal, keyEpoch: 1n };
  const expected = { deploymentIdentity, bootIdentity: "boot1", nonce: "nonce1", nowMs: 15n, maxTtlMs: 20n };
  return { measurement, expected };
}

for (const deployment of ["personal", "tenant-alpha"]) {
  for (const mutation of [{ field: "not-a-control" }, { value: "certified-safe" }]) {
    test(`KEEP-11C-001: signed unsupported ${Object.keys(mutation)[0]} preserves ${deployment} nonce`, () => {
      const { measurement, expected } = input(deployment);
      const gate = new ProfileAttestationGate(pin, verifier);
      const invalid = signProfileMeasurement({ ...measurement, ...mutation } as ProfileMeasurement, signer);
      assert.equal(verifier.verify(invalid.keyid, invalid.digest, invalid.signature), true, "signature is genuinely valid");
      assert.equal(gate.verify(invalid, expected).valid, false);
      const corrected = signProfileMeasurement(measurement, signer);
      assert.equal(gate.verify(corrected, expected).valid, true, "rejected schema did not consume nonce");
      assert.deepEqual(gate.verify(corrected, expected), { valid: false, reason: "nonce-mismatch-or-replay" });
    });
  }
}

test("profile schema: every supported field/status remains usable with real signatures", () => {
  for (const field of ENFORCEMENT_FIELDS) for (const value of ["enforced", "detected-only", "unavailable", "unknown"] as const) {
    const { measurement, expected } = input();
    const gate = new ProfileAttestationGate(pin, verifier);
    assert.equal(gate.verify(signProfileMeasurement({ ...measurement, field, value }, signer), expected).valid, true, `${field}/${value}`);
  }
});

test("profile schema: signed string time fields cannot bypass declared bigint lifetime checks", () => {
  for (const mutation of [{ measuredAtMs: "10", expiresAtMs: "20" }, { measuredAtMs: "10" }, { expiresAtMs: "20" }]) {
    const { measurement, expected } = input();
    const gate = new ProfileAttestationGate(pin, verifier);
    const invalid = signProfileMeasurement({ ...measurement, ...mutation } as unknown as ProfileMeasurement, signer);
    assert.equal(verifier.verify(invalid.keyid, invalid.digest, invalid.signature), true);
    assert.equal(gate.verify(invalid, expected).valid, false);
    assert.equal(gate.verify(signProfileMeasurement(measurement, signer), expected).valid, true);
  }
});

test("profile schema: malformed structures and enum shapes never consume the valid challenge", () => {
  const { measurement, expected } = input();
  const correct = signProfileMeasurement(measurement, signer);
  const malformed: unknown[] = [null, {}, { measurement: null }, { ...correct, measurement: [] }];
  // EIR already refuses signing JS numbers; exercise malformed raw input without
  // pretending that an otherwise invalid canonical preimage has a genuine signature.
  malformed.push({ ...correct, measurement: { ...measurement, measuredAtMs: 10, expiresAtMs: 20 } });
  for (const value of ["constructor", "__proto__", "", null, 3, true, []]) {
    malformed.push({ ...correct, measurement: { ...measurement, value } });
    malformed.push({ ...correct, measurement: { ...measurement, field: value } });
  }
  for (const candidate of malformed) {
    const gate = new ProfileAttestationGate(pin, verifier);
    assert.equal(gate.verify(candidate as ProfileAttestation, expected).valid, false);
    assert.equal(gate.verify(correct, expected).valid, true);
  }
});

test("profile signatures, bindings, lifetime and prober checks retain same-nonce recovery after refusal", () => {
  const { measurement, expected } = input();
  const correct = signProfileMeasurement(measurement, signer);
  const candidates = [
    { ...correct, signature: Buffer.alloc(64).toString("base64") },
    { ...correct, digest: "b".repeat(64) },
    signProfileMeasurement({ ...measurement, value: "unknown" }, signer),
    signProfileMeasurement({ ...measurement, deploymentIdentity: "tenant-beta" }, signer),
    signProfileMeasurement({ ...measurement, bootIdentity: "boot2" }, signer),
    signProfileMeasurement({ ...measurement, nonce: "nonce2" }, signer),
    signProfileMeasurement({ ...measurement, proberPrincipal: "operator" }, signer),
    signProfileMeasurement({ ...measurement, keyEpoch: 2n }, signer),
    signProfileMeasurement({ ...measurement, measuredAtMs: 16n }, signer),
    signProfileMeasurement({ ...measurement, expiresAtMs: 14n }, signer),
    signProfileMeasurement({ ...measurement, expiresAtMs: 40n }, signer),
  ];
  // A correctly re-signed supported status is valid. Tampering it without resigning is not.
  assert.equal(new ProfileAttestationGate(pin, verifier).verify(candidates[2]!, expected).valid, true);
  candidates[2] = { ...correct, measurement: { ...measurement, value: "unknown" } };
  for (const candidate of candidates) {
    const gate = new ProfileAttestationGate(pin, verifier);
    assert.equal(gate.verify(candidate, expected).valid, false);
    assert.equal(gate.verify(correct, expected).valid, true);
  }
  const gate = new ProfileAttestationGate({ ...pin, forbiddenPrincipals: new Set([pin.principal]) }, verifier);
  assert.deepEqual(gate.verify(correct, expected), { valid: false, reason: "prober-not-independent" });
});

test("profile nonce: verifier callback mutation cannot leave the checked nonce reusable", () => {
  const { measurement, expected } = input();
  const mutable = { ...signProfileMeasurement(measurement, signer), measurement: { ...measurement } };
  const gate = new ProfileAttestationGate(pin, { verify(keyid, digest, signature) {
    const valid = verifier.verify(keyid, digest, signature);
    mutable.measurement.nonce = "not-the-checked-nonce";
    return valid;
  } });
  assert.equal(gate.verify(mutable, expected).valid, true);
  assert.deepEqual(gate.verify(signProfileMeasurement(measurement, signer), expected), { valid: false, reason: "nonce-mismatch-or-replay" });
});

test("profile nonce: synchronous verifier reentry cannot return two acceptances for one challenge", () => {
  const { measurement, expected } = input();
  const attestation = signProfileMeasurement(measurement, signer);
  let entered = false;
  let nestedAccepted = false;
  const gate = new ProfileAttestationGate(pin, { verify(keyid, digest, signature) {
    if (!entered) { entered = true; nestedAccepted = gate.verify(attestation, expected).valid; }
    return verifier.verify(keyid, digest, signature);
  } });
  assert.deepEqual(gate.verify(attestation, expected), { valid: false, reason: "nonce-mismatch-or-replay" });
  assert.equal(nestedAccepted, true);
});

test("profile lifetime: inclusive endpoints and exact TTL remain valid; untyped expectations preserve nonce", () => {
  const { measurement, expected } = input();
  const attestation = signProfileMeasurement(measurement, signer);
  for (const nowMs of [10n, 20n]) {
    assert.equal(new ProfileAttestationGate(pin, verifier).verify(attestation, { ...expected, nowMs, maxTtlMs: 10n }).valid, true);
  }
  for (const mutation of [{ nowMs: "15" }, { nowMs: 15 }, { maxTtlMs: "20" }, { maxTtlMs: 20 }]) {
    const gate = new ProfileAttestationGate(pin, verifier);
    assert.equal(gate.verify(attestation, { ...expected, ...mutation } as unknown as typeof expected).valid, false);
    assert.equal(gate.verify(attestation, expected).valid, true);
  }
});

test("profile signature port requires synchronous true, not a truthy promise or object", () => {
  const { measurement, expected } = input();
  const attestation = signProfileMeasurement(measurement, signer);
  for (const invalid of [undefined, {}, { valid: false }, Promise.resolve(false)]) {
    let misconfigured = true;
    const gate = new ProfileAttestationGate(pin, { verify(keyid, digest, signature) {
      return misconfigured ? invalid as unknown as boolean : verifier.verify(keyid, digest, signature);
    } });
    assert.deepEqual(gate.verify(attestation, expected), { valid: false, reason: "bad-signature-or-content" });
    misconfigured = false;
    assert.equal(gate.verify(attestation, expected).valid, true);
  }
});
