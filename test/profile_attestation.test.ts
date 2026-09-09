import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { ProfileAttestationGate, signProfileMeasurement, type ProfileAttestationSigner } from "../src/platform/profile_attestation.js";

const key = "test-profile-key";
const mac = (digest: string): string => createHmac("sha256", key).update(digest).digest("hex");
const signer: ProfileAttestationSigner = { keyid: "probe-k1", sign: mac };
const verifier = { verify: (keyid: string, digest: string, signature: string) => keyid === "probe-k1" && mac(digest) === signature };
const pin = { principal: "prober-1", keyid: "probe-k1", keyEpoch: 4n, forbiddenPrincipals: new Set(["d1", "d2", "d3", "d4"]) };
const measurement = { field: "networkMediation" as const, value: "enforced" as const, evidenceDigest: "a".repeat(64), deploymentIdentity: "deploy-a", bootIdentity: "boot-a", nonce: "challenge-1", measuredAtMs: 100n, expiresAtMs: 120n, proberPrincipal: "prober-1", keyEpoch: 4n };
const expected = { deploymentIdentity: "deploy-a", bootIdentity: "boot-a", nonce: "challenge-1", nowMs: 110n, maxTtlMs: 30n };

test("a fresh signed, pinned, boot-bound measurement verifies once", () => {
  const gate = new ProfileAttestationGate(pin, verifier);
  const attestation = signProfileMeasurement(measurement, signer);
  assert.equal(gate.verify(attestation, expected).valid, true);
  assert.deepEqual(gate.verify(attestation, expected), { valid: false, reason: "nonce-mismatch-or-replay" });
});

test("tamper, stale evidence, cross-boot evidence, and wrong key epoch fail closed", () => {
  const attestation = signProfileMeasurement(measurement, signer);
  const cases = [
    { ...attestation, measurement: { ...measurement, value: "detected-only" as const } },
    signProfileMeasurement({ ...measurement, expiresAtMs: 109n }, signer),
    signProfileMeasurement({ ...measurement, bootIdentity: "boot-b" }, signer),
    signProfileMeasurement({ ...measurement, keyEpoch: 3n }, signer),
  ];
  for (const candidate of cases) assert.equal(new ProfileAttestationGate(pin, verifier).verify(candidate, expected).valid, false);
});

test("a prober collocated with a forbidden role is rejected even with a valid signature", () => {
  const badPin = { ...pin, principal: "d2" };
  const attestation = signProfileMeasurement({ ...measurement, proberPrincipal: "d2" }, signer);
  assert.deepEqual(new ProfileAttestationGate(badPin, verifier).verify(attestation, expected), { valid: false, reason: "prober-not-independent" });
});

