/**
 * Reference signing and verification for AI-BOM records.
 * The signed content binds a BOM digest to an optional running measurement. Verification counts
 * valid results from distinct configured keys and compares that count with the trust threshold.
 *
 * The envelope follows the payload/signature separation used by DSSE and in-toto. This implementation
 * uses a keyed SHA-256 stub: verification requires the same secret as signing. It exercises the
 * binding and threshold rules without providing public-key verification or independent key custody.
 * Production asymmetric signing requires a matching verifier and protected key storage.
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

/** BOM payload, optional running measurement and detached signatures. */
export interface SignedBom {
  readonly payload: AiBom;
  /** Optional running measurement bound into the signed content. */
  readonly attestedMeasurement?: string | undefined;
  readonly signatures: readonly Signature[];
}

/** Injected signing interface; key custody belongs to its implementation. */
export interface Signer {
  sign(digest: string): Signature;
}

/** The verifier's trust policy: which keyids are trusted (keyid → verify key) and the quorum size. */
export interface TrustPolicy {
  readonly trustedKeys: ReadonlyMap<string, string>;
  readonly threshold: number; // Required number of distinct trusted signers.
}

export type SigVerification =
  | { readonly verified: true; readonly signerCount: number }
  | { readonly verified: false; readonly reason: string };

/** The content that is signed: the BOM digest bound to the attested measurement. */
export function signedContent(payload: AiBom, attestedMeasurement?: string): string {
  return `${bomDigest(payload)}|${attestedMeasurement ?? ""}`;
}

/** Keyed-hash reference primitive; signing and verification share the same secret. */
export function stubSign(privateKey: string, keyid: string, content: string): Signature {
  return { keyid, sig: sha256Hex(`${privateKey}|${content}`) };
}

/**
 * Recompute the signed content and count valid results from distinct configured keys.
 * Reject absent signatures or a count below the policy threshold.
 */
export function verifySignedBom(env: SignedBom | undefined, policy: TrustPolicy): SigVerification {
  if (env === undefined) return { verified: false, reason: "no-signed-bom" }; // absent → deny
  if (env.signatures.length === 0) return { verified: false, reason: "no-signatures" };
  const content = signedContent(env.payload, env.attestedMeasurement);
  let valid = 0;
  const seen = new Set<string>();
  for (const s of env.signatures) {
    const key = policy.trustedKeys.get(s.keyid);
    if (key === undefined) continue; // Only configured keys count toward the threshold.
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

/** Project the verification result into the gate's bomVerified input. */
export function signedBomVerified(v: SigVerification): boolean {
  return v.verified === true;
}

/** Reference signer using an injected shared secret and key identifier. */
export class StubSigner implements Signer {
  constructor(private readonly privateKey: string, private readonly keyid: string) {}
  sign(content: string): Signature {
    return stubSign(this.privateKey, this.keyid, content);
  }
}
