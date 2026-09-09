/**
 * R34 — AI-BOM signing (signer-interface seam + in-env verify-side authenticity logic).
 *
 * The AI-BOM (`ai_bom.ts`) is TAMPER-EVIDENT via the hash-chain: recompute the digest and compare. But
 * a bad actor can forge a FRESH well-formed manifest — tamper-evidence proves "not silently altered
 * after recording," not "only a trusted party could have produced it." R34 adds AUTHENTICITY: sign the
 * BOM digest with a key the AGENT CANNOT REACH, so a forged manifest fails signature verification.
 *
 * DISCIPLINE (research, 2026-08-09):
 *  - DSSE / in-toto envelope: `{ payload, payloadType, signatures:[{keyid, sig}] }` — the statement +
 *    its signature(s) in one envelope. Signing upgrades SLSA L1 (unsigned) to L2/L3.
 *  - SLSA L3 control/data-plane split: "separate user-defined build steps (data plane) from provenance
 *    generation (control plane); the signing key must be UNREACHABLE by user-defined steps." The agent
 *    (untrusted, data plane) cannot sign its own BOM; only the control-plane signer (HSM/KMS/TEE) can.
 *  - Signatures answer "WHO + that it wasn't changed"; provenance answers "how + from what." Signing is
 *    the "who."
 *  - Transparency log (Rekor): an append-only record of signing events complements the signature —
 *    Keep's SPINE is the Rekor analog (the signed digest is staged to the tamper-evident chain).
 *  - Threshold / fleet cosign (R25): DSSE allows multiple signatures; a k-of-n quorum of fleet signers.
 *
 * BUILT vs SEAM: BUILT + proven in-env is the VERIFY side — recompute the digest, verify each signature
 * against the TRUSTED public keys, require a threshold, and fail safe (absent/tampered/untrusted-key/
 * quorum-not-met → unverifiable → the existing `bomVerified=false` gate veto). The real HSM/KMS/TEE KEY
 * CUSTODY — the private key that never leaves the boundary and the agent cannot reach — is the SEAM
 * (R34), the key-custody family of R25/R37. In-env "signing" is a keyed-hash stub; the sandbox has no HSM.
 *
 * WHAT WOULD CHANGE IT: keyless signing (Sigstore Fulcio ephemeral cert + OIDC) or a real asymmetric
 * KMS key replaces the stub; a transparency-log inclusion proof strengthens auditability. Neither lets
 * a forged manifest or an untrusted-key signature verify.
 */

import { bomDigest, type AiBom } from "./ai_bom.js";
import { createHash } from "node:crypto";

function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

export interface Signature {
  readonly keyid: string;
  readonly sig: string;
}

/** DSSE-style envelope: the BOM payload (+ the attested measurement, R37) and its signatures. */
export interface SignedBom {
  readonly payload: AiBom;
  /** The R37 attested running-measurement, bound into the signed content (authenticity + integrity). */
  readonly attestedMeasurement?: string | undefined;
  readonly signatures: readonly Signature[];
}

/** The signer SEAM — a real deployment holds the private key in an HSM/KMS/TEE. */
export interface Signer {
  sign(digest: string): Signature;
}

/** The verifier's trust policy: which keyids are trusted (keyid → verify key) and the quorum size. */
export interface TrustPolicy {
  readonly trustedKeys: ReadonlyMap<string, string>;
  readonly threshold: number; // k-of-n cosign (R25); 1 for a single trusted signer
}

export type SigVerification =
  | { readonly verified: true; readonly signerCount: number }
  | { readonly verified: false; readonly reason: string };

/** The content that is signed: the BOM digest bound to the attested measurement. */
export function signedContent(payload: AiBom, attestedMeasurement?: string): string {
  return `${bomDigest(payload)}|${attestedMeasurement ?? ""}`;
}

/** The stub signature (stands in for the HSM/KMS signature — the SEAM). */
export function stubSign(privateKey: string, keyid: string, content: string): Signature {
  return { keyid, sig: sha256Hex(`${privateKey}|${content}`) };
}

/**
 * Verify a signed BOM. Total + fail-safe. Recompute the signed content, count signatures that are BOTH
 * from a TRUSTED key AND valid over the content, and require the threshold. Any shortfall ⇒ unverifiable.
 */
export function verifySignedBom(env: SignedBom | undefined, policy: TrustPolicy): SigVerification {
  if (env === undefined) return { verified: false, reason: "no-signed-bom" }; // absent → deny
  if (env.signatures.length === 0) return { verified: false, reason: "no-signatures" };
  const content = signedContent(env.payload, env.attestedMeasurement);
  let valid = 0;
  const seen = new Set<string>();
  for (const s of env.signatures) {
    const key = policy.trustedKeys.get(s.keyid);
    if (key === undefined) continue; // UNTRUSTED key → does not count (the agent's own key is not trusted)
    const expected = stubSign(key, s.keyid, content).sig;
    if (s.sig === expected && !seen.has(s.keyid)) {
      seen.add(s.keyid);
      valid++; // valid signature from a distinct trusted key
    }
  }
  if (valid < policy.threshold) {
    return { verified: false, reason: `threshold-not-met:${valid}<${policy.threshold}` };
  }
  return { verified: true, signerCount: valid };
}

/** A failed/absent/forged signature → bomVerified=false → the existing gate veto. */
export function signedBomVerified(v: SigVerification): boolean {
  return v.verified === true;
}

/** In-env stub signer: signs with a fixed private key + keyid. Not an HSM — it only exercises verify. */
export class StubSigner implements Signer {
  constructor(private readonly privateKey: string, private readonly keyid: string) {}
  sign(content: string): Signature {
    return stubSign(this.privateKey, this.keyid, content);
  }
}
