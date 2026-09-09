/**
 * R37 — running-binary attestation (attester-interface seam + in-env verifier logic).
 *
 * verify-minimal-TCB (`verify_tcb.ts`) hashes the trusted-core SOURCE files: it proves the source on
 * disk is exactly the enumerated minimal set, unaltered. It does NOT prove the code ACTUALLY EXECUTING
 * is that code — a tampered running process, or a swapped in-memory image, passes a source check. R37
 * closes that gap with attestation: measure the LOADED code and produce a signed QUOTE a verifier
 * appraises against the pinned manifest.
 *
 * DISCIPLINE (research, 2026-08-09 — RFC 9683 / TPM remote attestation, TEE reports):
 *  - Measurement chain: boot (CRTM → firmware → bootloader → kernel → runtime) extends PCRs; the loaded
 *    TCB modules are measured (IMA-style) into a PCR. The digest of that measurement is the evidence.
 *  - Quote: the TPM/TEE signs (measurement ‖ verifier-nonce) with an Attestation Key held in hardware
 *    (the SEAM). "Any change to the quote — in the device or in the path — invalidates the signature,"
 *    because the signing key is unreachable by a tampered process.
 *  - Verifier appraisal (RFC 9683 "SHOULD NOT be trusted" conditions, each a reject here):
 *    signature not correct → deny; nonce mismatch → deny (replay); measurement ≠ known-good → deny;
 *    stale/absent → deny. Freshness comes from a fresh per-challenge nonce echoed in the signed quote.
 *  - Binding to R34: the attested measurement digest anchors the AI-BOM's code hash, so "what produced
 *    this decision" is provably "what actually ran," not merely "what was on disk."
 *
 * BUILT vs SEAM: BUILT + proven in-env is the VERIFIER side — appraisal (measurement match), freshness
 * (nonce), signature check, and fail-safe (absent/stale/tampered → deny), plus `attestedTcbIntact`
 * feeding the existing `tcbIntact` gate veto (a tampered running TCB is a tcb-drift-class deny signal).
 * The real TPM/TEE QUOTE over the loaded binary — the unforgeable hardware-signed measurement — is the
 * SEAM (R37), the key-custody family of R25/R34. In-env the "signature" is a keyed hash stub exercising
 * the verifier logic; the sandbox has no TPM/TEE.
 *
 * WHAT WOULD CHANGE IT: DICE layered measurement or a TEE report format extends the evidence; a real AK
 * signature replaces the stub. Neither lets a tampered measurement or stale nonce verify.
 */

import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

// ── Restoration-authorization signing (BUILD-ORDER 8.44A / 8.44A-FIX — SIGNER VERIFICATION) ────────
//
// A restoration attestation authorizes a history FORK: an append-only reversing-entry that supersedes
// a witnessed head (see spine/witness_reconcile.ts). The authority that matters is "did the key-holder
// sign THIS restore, to THIS content?" — so the signature must be VERIFIED against the enrolled key over
// the canonical restore bytes, and those bytes must BIND the restored content, not merely the seq. It is
// bound to a fresh nonce so a captured valid signature cannot be REPLAYED to authorize a LATER fork.
// Presence-of-a-signature is not verification-of-a-signature: a signature you do not check is decoration
// (the JWT `alg:none` / "signature not actually verified" CVE class).
//
// 8.44A-FIX (cross-family veto, GPT-5.6): the first 8.44A signed only {restoredToSeq, priorWitnessedHash,
// nonce} — NOT the restored CONTENT — so a single valid authorization transferred to ANY fork sharing that
// seq + superseded witness hash (the classic "signature covers less than it authorizes" / signature-
// wrapping flaw class). This round adds `contentDigest` to the SIGNED bytes and verifies it against the
// supplied blocks in reconcile, so an authorization minted for restore A does NOT verify for fork B.
//
// KEY DISCIPLINE — the same primitive as isolation_attestation.ts: HMAC-SHA256 over canonical bytes
// with the ENROLLED run key, constant-time compared. This is TRUE on-box today (the symmetric run key
// IS enrolled). It is NECESSARY but NOT SUFFICIENT against a compromised BOX: a box compromised enough to
// read the same-box symmetric key can mint a correctly-bound authorization. Asymmetric OPERATOR-KEY custody
// OFF-BOX — so the box that verifies cannot also mint authorizations — is the LOAD-BEARING 8.R0 human-root
// SEAM, not optional hardening. Swapping this HMAC for `crypto.verify` over an Ed25519 operator public key
// is a drop-in behind the same `RestorationSignedFields` shape.

export interface RestorationSignedFields {
  readonly restoredToSeq: number;
  readonly priorWitnessedHash: string;
  /**
   * BINDS the restored content (8.44A-FIX): a digest of the ACTUAL restored blocks (see
   * hashchain.restoredContentDigest). Signed WITH the seq so the authorization cannot transfer to a
   * different fork that merely shares the seq + superseded witness hash.
   */
  readonly contentDigest: string;
  /** Anti-replay binding: a per-authorization nonce, signed WITH the rest so it cannot be swapped. */
  readonly nonce: string;
}

/** Deterministic bytes over EVERY authorization-bearing field — change the target seq, the superseded
 *  hash, the restored CONTENT DIGEST, or the nonce and the signature no longer verifies. */
export function canonicalRestorationBytes(f: RestorationSignedFields): string {
  // DOMAIN SEPARATION (BUILD-ORDER 8.44A-FIX9, Fable): a fixed, versioned tag makes it STRUCTURALLY impossible for
  // any other HMAC signer of a (disclosed-seam) shared key to ever be a signing oracle for restoration bytes —
  // rather than relying on the accidental fact that other signers canonicalize with SORTED keys while these use a
  // fixed insertion order. The tag is the first thing signed, so no untagged message can collide with a tagged one.
  return JSON.stringify({
    _domain: "keep.spine.restoration-authorization.v1",
    restoredToSeq: f.restoredToSeq,
    priorWitnessedHash: f.priorWitnessedHash,
    contentDigest: f.contentDigest,
    nonce: f.nonce,
  });
}

/** HMAC-SHA256 over the canonical restore bytes with the enrolled key (hex). The zero-dep signing
 *  primitive; a real deployment swaps in the asymmetric operator signature (8.R0 SEAM). */
export function signRestoration(key: Buffer, f: RestorationSignedFields): string {
  return createHmac("sha256", key).update(canonicalRestorationBytes(f)).digest("hex");
}

/** A strict, full-length lowercase-or-uppercase hex string of exactly `hexLen` characters. */
const isStrictHex = (s: string, hexLen: number): boolean =>
  s.length === hexLen && s.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(s);

/**
 * Constant-time verification of a restoration signature against the enrolled key. A tampered field, a
 * signature from a DIFFERENT key, a length mismatch, or a non-hex signature → false. Never throws.
 *
 * STRICT HEX (8.44A-FIX): `Buffer.from(sig,"hex")` silently DECODES a valid hex PREFIX and DROPS trailing
 * garbage — so "<valid-64-hex>ZZ" decodes to the same 32 bytes and would slip a mutated signature past the
 * decoded-length check as if it were the clean one (measured: Buffer.from("deadbeefZZ","hex") === deadbeef).
 * We therefore validate the signature is STRICT, FULL-LENGTH hex BEFORE decoding and reject otherwise.
 */
export function restorationSignatureValid(key: Buffer, f: RestorationSignedFields, signature: string): boolean {
  const expectedHex = signRestoration(key, f);
  if (typeof signature !== "string" || !isStrictHex(signature, expectedHex.length)) return false;
  const expected = Buffer.from(expectedHex, "hex");
  const actual = Buffer.from(signature, "hex");
  if (actual.length !== expected.length || expected.length === 0) return false;
  return timingSafeEqual(actual, expected);
}

/** A signed attestation quote over the loaded measurement + the verifier's nonce. */
export interface Quote {
  /** Digest of the measured LOADED TCB (the running-binary analog of the pinned manifest digest). */
  readonly measurementDigest: string;
  /** The verifier's fresh challenge nonce, echoed so the verifier can check freshness. */
  readonly nonce: string;
  /** The signature over (measurementDigest ‖ nonce). In-env a keyed-hash stub; real = AK/TEE signature. */
  readonly signature: string;
}

/** The attester SEAM — a real deployment issues a TPM2_Quote / TEE report. */
export interface Attester {
  quote(nonce: string): Quote;
}

export type QuoteVerification =
  | { readonly verified: true; readonly measurementDigest: string }
  | { readonly verified: false; readonly reason: string };

/** The stub signature (stands in for the hardware AK signature — the SEAM). */
export function stubSign(key: string, measurementDigest: string, nonce: string): string {
  return sha256Hex(`${key}|${measurementDigest}|${nonce}`);
}

export interface Appraisal {
  /** The known-good measurement (e.g. `tcbManifestDigest` of the pinned nine-module TCB). */
  readonly expectedDigest: string;
  /** The fresh nonce the verifier issued for THIS challenge. */
  readonly challengeNonce: string;
  /** The public/verify key for the attestation signature (real = AK public key). */
  readonly verifyKey: string;
}

/**
 * Appraise a quote. Total + fail-safe. Order isolates each reject: absent → signature → freshness →
 * measurement. A tampered running process cannot produce a valid signature over the expected nonce
 * with the genuine key, and a replayed old quote fails the freshness (nonce) check.
 */
export function verifyQuote(quote: Quote | undefined, appraisal: Appraisal): QuoteVerification {
  if (quote === undefined) return { verified: false, reason: "no-quote" }; // absent → deny (fail-safe)
  const expectedSig = stubSign(appraisal.verifyKey, quote.measurementDigest, quote.nonce);
  if (quote.signature !== expectedSig) return { verified: false, reason: "bad-signature" };
  if (quote.nonce !== appraisal.challengeNonce) return { verified: false, reason: "stale-nonce" }; // replay
  if (quote.measurementDigest !== appraisal.expectedDigest) return { verified: false, reason: "measurement-mismatch" }; // drift
  return { verified: true, measurementDigest: quote.measurementDigest };
}

/** A failed/absent attestation → tcbIntact=false → the existing gate veto (tcb-drift class). */
export function attestedTcbIntact(v: QuoteVerification): boolean {
  return v.verified === true;
}

/**
 * In-env stub attester: signs over a configured measurement (which a test may TAMPER) with a key. Not
 * a real TPM — it cannot provide the unforgeable property; it only exercises the verifier logic.
 */
export class StubAttester implements Attester {
  constructor(private readonly measurementDigest: string, private readonly key: string) {}
  quote(nonce: string): Quote {
    return { measurementDigest: this.measurementDigest, nonce, signature: stubSign(this.key, this.measurementDigest, nonce) };
  }
}
