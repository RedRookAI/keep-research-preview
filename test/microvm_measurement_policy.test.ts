import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import {
  loadVerifiedMicrovmMeasurementPolicyAuthority,
  microvmMeasurementPolicySignaturePreimage,
  trustedMicrovmMeasurementPolicyDigest,
  verifySignedMicrovmMeasurementPolicy,
  verifiedMicrovmMeasurementPolicyAuthorityDigest,
  type MicrovmMeasurementPolicyTrustRoot,
  type SignedMicrovmMeasurementPolicy,
  type TrustedMicrovmMeasurements,
} from "../src/infra/microvm_boundary.js";
import { chmodSync, lstatSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const policy: TrustedMicrovmMeasurements = {
  schema: "keep.trusted-microvm-measurements/v1",
  vmmSha256: "1".repeat(64), jailerSha256: "2".repeat(64), kernelSha256: "3".repeat(64),
  baseRootfsSha256: "4".repeat(64), guestSupervisorSha256: "5".repeat(64),
  debugfsSha256: "6".repeat(64), mke2fsSha256: "7".repeat(64), e2fsckSha256: "8".repeat(64),
};

function fixture(): { signed: SignedMicrovmMeasurementPolicy; trust: MicrovmMeasurementPolicyTrustRoot } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const keyId = "test.microvm.policy.1";
  return {
    signed: {
      schema: "keep.signed-microvm-measurement-policy/v1", keyId, policy,
      signature: sign(null, microvmMeasurementPolicySignaturePreimage(policy), privateKey).toString("base64"),
    },
    trust: {
      schema: "keep.microvm-measurement-policy-trust-root/v1", keyId,
      publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    },
  };
}

test("signed microVM policy is independently verified before appraisal", () => {
  const { signed, trust } = fixture();
  assert.equal(verifySignedMicrovmMeasurementPolicy(signed, trust), trustedMicrovmMeasurementPolicyDigest(policy));
});

test("policy mutation, foreign trust, and unknown policy fields refuse", () => {
  const { signed, trust } = fixture();
  assert.throws(() => verifySignedMicrovmMeasurementPolicy({ ...signed, policy: { ...policy, kernelSha256: "9".repeat(64) } }, trust), /signature/);
  assert.throws(() => verifySignedMicrovmMeasurementPolicy(signed, { ...fixture().trust, keyId: trust.keyId }), /signature/);
  assert.throws(() => trustedMicrovmMeasurementPolicyDigest({ ...policy, extra: "untrusted" } as TrustedMicrovmMeasurements), /fields are not exact/);
});

function hasTrustedRootOwnedChain(path: string): boolean {
  const file = lstatSync(path);
  if (!file.isFile() || file.isSymbolicLink() || file.uid !== 0 || (file.mode & 0o022) !== 0) return false;
  for (let cursor = dirname(realpathSync(path)); ; cursor = dirname(cursor)) {
    const ancestor = lstatSync(cursor);
    if (!ancestor.isDirectory() || ancestor.isSymbolicLink() || ancestor.uid !== 0 || (ancestor.mode & 0o022) !== 0) return false;
    if (cursor === dirname(cursor)) return true;
  }
}

test("synthetic signed policy respects the actual host ownership boundary without private release records", () => {
  // A source checkout may be root-owned on a designated host or user-owned on a
  // contributor's machine. Do not turn the latter into policy authority or skip it.
  // Only the public key and a signed synthetic policy reach disk; never a private key.
  const root = mkdtempSync(join(process.cwd(), ".keep-policy-fixture-"));
  const signedPath = join(root, "policy.json");
  const trustPath = join(root, "trust.json");
  try {
    const { signed, trust } = fixture();
    writeFileSync(signedPath, JSON.stringify(signed), { mode: 0o600 });
    writeFileSync(trustPath, JSON.stringify(trust), { mode: 0o600 });
    if (hasTrustedRootOwnedChain(signedPath) && hasTrustedRootOwnedChain(trustPath)) {
      const authority = loadVerifiedMicrovmMeasurementPolicyAuthority(signedPath, trustPath);
      assert.equal(verifiedMicrovmMeasurementPolicyAuthorityDigest(authority), trustedMicrovmMeasurementPolicyDigest(policy));
    } else {
      assert.throws(
        () => loadVerifiedMicrovmMeasurementPolicyAuthority(signedPath, trustPath),
        /root-owned|non-writable/,
        "an untrusted ownership chain must refuse rather than mint authority",
      );
    }
    // Even on a trusted host, a writable policy cannot establish authority.
    chmodSync(signedPath, 0o666);
    assert.throws(() => loadVerifiedMicrovmMeasurementPolicyAuthority(signedPath, trustPath), /root-owned|non-writable/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
