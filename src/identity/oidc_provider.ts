/**
 * OidcJwksProvider (Increment 3.2) — retires the identity-provider OIDC/JWKS seam with a REAL asymmetric verifier.
 *
 * HmacAssertionProvider proved the login→session→RBAC flow with a symmetric shared secret. This is the real thing: it
 * verifies an OIDC ID token's RS256 signature against a JWKS (a set of public keys keyed by `kid`) using node:crypto,
 * then validates iss / aud / exp / nbf / nonce. Zero runtime deps. The ONLY remaining external piece is fetching a real
 * IdP's JWKS document over HTTPS (a third-party network call) — supply those keys (or a fetch hook) at deployment; the
 * verification logic below is fully built and proven here against a locally-generated keypair.
 *
 * SOTA basis (2026-08-08 — CVE-2026-22817 & the alg-confusion class): the algorithm is PINNED server-side to an
 * allowlist (default ["RS256"]) and NEVER derived from the token — this defeats both `alg:none` and the RS256→HS256
 * confusion attack (where the RSA public key is abused as an HMAC secret). Order: pin alg → resolve key by kid → verify
 * signature → check iss (exact) / aud (must contain) / exp / nbf with a tight ±leeway. Any failure returns null
 * (fail-closed — a verifier never throws-to-allow). What would change it: ES256/EdDSA can be added to the allowlist with
 * their own key handling; a live JWKS-endpoint fetch (with kid-miss refresh for key rotation) is the deployment swap.
 */

import { createPublicKey, createVerify, timingSafeEqual, type JsonWebKey } from "node:crypto";
import type { IdentityProviderPort, VerifiedIdentity } from "./identity_provider.js";
import { parsePolicyJson, type JsonValue } from "../policy/json.js";

/** A JSON Web Key (RSA public key material as published in a JWKS). */
export interface Jwk {
  readonly kty: string;
  readonly kid?: string;
  readonly alg?: string;
  readonly use?: string;
  readonly n?: string;
  readonly e?: string;
  readonly [k: string]: unknown;
}
export interface Jwks { readonly keys: readonly Jwk[]; }
export interface VerifiedCodeFlowIdentity extends VerifiedIdentity { readonly validUntil: number; }

export interface OidcConfig {
  /** The provider's public keys (a JWKS). In prod, fetched from the IdP's jwks_uri. */
  readonly jwks: Jwks;
  /** Expected issuer — must match the token's `iss` EXACTLY (no wildcards/substrings). */
  readonly issuer: string;
  /** Expected audience — the token's `aud` must CONTAIN this (prevents cross-service replay). */
  readonly audience: string;
  /** Allowed signing algorithms. Default ["RS256"]. NEVER derived from the token header. */
  readonly allowedAlgs?: readonly string[];
  /** Finite nonnegative clock-skew leeway in seconds for exp/nbf. Default 60. */
  readonly leewaySec?: number;
  /** If set, the token's `nonce` claim must match this exactly. */
  readonly expectedNonce?: string;
}

const RS_ALG_TO_HASH: Record<string, string> = { RS256: "RSA-SHA256", RS384: "RSA-SHA384", RS512: "RSA-SHA512" };

export class OidcJwksProvider implements IdentityProviderPort {
  private readonly allowed: ReadonlySet<string>;
  private readonly leewaySec: number;
  constructor(private readonly cfg: OidcConfig) {
    this.allowed = new Set(cfg.allowedAlgs ?? ["RS256"]);
    this.leewaySec = cfg.leewaySec ?? 60;
    if (!Number.isFinite(this.leewaySec) || this.leewaySec < 0) {
      throw new Error("OIDC leewaySec must be finite and nonnegative");
    }
  }

  /** Restricted code-flow profile: integer NumericDates, unique JSON keys and per-transaction nonce. */
  async verifyCodeFlow(assertion: string, now: number, transaction: { readonly nonce: string; readonly issuedAt: number; readonly expiresAt: number }): Promise<VerifiedCodeFlowIdentity | null> {
    try {
      if (!Number.isFinite(now) || !Number.isFinite(transaction.issuedAt) || !Number.isFinite(transaction.expiresAt) || now < transaction.issuedAt || now >= transaction.expiresAt
        || !transaction.nonce || typeof assertion !== "string" || assertion.length > 16384) return null;
      const parts = assertion.split(".");
      if (parts.length !== 3 || parts.some(part => !/^[A-Za-z0-9_-]+$/u.test(part) || Buffer.from(part, "base64url").toString("base64url") !== part)) return null;
      const header = strictOidcObject(Buffer.from(parts[0]!, "base64url")), claims = strictOidcObject(Buffer.from(parts[1]!, "base64url"));
      if (header.alg !== "RS256" || typeof header.kid !== "string" || !header.kid || header.kid.length > 256 || header.crit !== undefined || header.b64 !== undefined || header.jku !== undefined || header.jwk !== undefined || header.x5u !== undefined) return null;
      const keys = this.cfg.jwks.keys;
      if (!Array.isArray(keys) || keys.length < 1 || keys.length > 64 || keys.some(key => typeof key.kid !== "string" || !key.kid)
        || new Set(keys.map(key => key.kid)).size !== keys.length) return null;
      const key = keys.find(row => row.kid === header.kid);
      if (!key || key.kty !== "RSA" || (key.alg !== undefined && key.alg !== "RS256") || (key.use !== undefined && key.use !== "sig")
        || ["d", "p", "q", "dp", "dq", "qi", "oth", "k"].some(field => Object.hasOwn(key, field))
        || (key.key_ops !== undefined && (!Array.isArray(key.key_ops) || key.key_ops.length !== 1 || key.key_ops[0] !== "verify"))) return null;
      const imported = createPublicKey({ key: key as JsonWebKey, format: "jwk" });
      if ((imported.asymmetricKeyDetails?.modulusLength ?? 0) < 2048 || !createVerify("RSA-SHA256").update(`${parts[0]}.${parts[1]}`).end().verify(imported, Buffer.from(parts[2]!, "base64url"))) return null;
      const date = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
      if (claims.iss !== this.cfg.issuer || !(claims.aud === this.cfg.audience || (Array.isArray(claims.aud) && claims.aud.length === 1 && claims.aud[0] === this.cfg.audience))
        || (claims.azp !== undefined && claims.azp !== this.cfg.audience) || !date(claims.iat) || !date(claims.exp) || claims.exp <= claims.iat
        || claims.iat * 1000 > now + this.leewaySec * 1000 || claims.iat * 1000 < transaction.issuedAt - this.leewaySec * 1000
        || now >= (claims.exp + this.leewaySec) * 1000 || (claims.nbf !== undefined && (!date(claims.nbf) || now < (claims.nbf - this.leewaySec) * 1000))
        || typeof claims.nonce !== "string" || !constantTimeEqual(claims.nonce, transaction.nonce)
        || typeof claims.sub !== "string" || !claims.sub || claims.sub.length > 255 || /[^\x21-\x7e]/u.test(claims.sub)) return null;
      return { subject: claims.sub, validUntil: (claims.exp + this.leewaySec) * 1000 };
    } catch { return null; }
  }

  async verify(assertion: string, now: number): Promise<VerifiedIdentity | null> {
    const nowSec = now / 1000;
    const parts = assertion.split(".");
    if (parts.length !== 3) return null;
    const [h, p, s] = parts as [string, string, string];

    const header = decodeJson(h);
    const payload = decodeJson(p);
    if (!header || !payload) return null;

    // 1) PIN the algorithm — reject anything not on the allowlist (defeats alg:none + RS256→HS256 confusion).
    const alg = typeof header["alg"] === "string" ? (header["alg"] as string) : "";
    if (!this.allowed.has(alg) || !(alg in RS_ALG_TO_HASH)) return null;

    // 2) Resolve the verification key from the JWKS by kid (exact). No kid match → reject (caller may refresh + retry).
    const kid = typeof header["kid"] === "string" ? (header["kid"] as string) : undefined;
    const jwk = this.cfg.jwks.keys.find((k) => (kid ? k.kid === kid : true) && (k.kty === "RSA"));
    if (!jwk) return null;
    if (jwk.alg && jwk.alg !== alg) return null; // a key that declares a different alg must not verify this token

    // 3) Verify the signature over `header.payload` with the pinned algorithm.
    let ok = false;
    try {
      const key = createPublicKey({ key: jwk as unknown as JsonWebKey, format: "jwk" });
      const sig = Buffer.from(s, "base64url");
      ok = createVerify(RS_ALG_TO_HASH[alg]!).update(`${h}.${p}`).end().verify(key, sig);
    } catch { return null; }
    if (!ok) return null;

    // 4) Claims: exact iss, aud must contain, exp/nbf within leeway, optional nonce.
    if (payload["iss"] !== this.cfg.issuer) return null;
    if (!audienceContains(payload["aud"], this.cfg.audience)) return null;
    const exp = numClaim(payload["exp"]);
    if (exp === undefined || nowSec >= exp + this.leewaySec) return null;
    const nbf = numClaim(payload["nbf"]);
    if (Object.hasOwn(payload, "nbf") && nbf === undefined) return null;
    if (nbf !== undefined && nowSec < nbf - this.leewaySec) return null;
    if (this.cfg.expectedNonce !== undefined) {
      const nonce = typeof payload["nonce"] === "string" ? (payload["nonce"] as string) : "";
      if (!constantTimeEqual(nonce, this.cfg.expectedNonce)) return null;
    }
    const sub = payload["sub"];
    if (typeof sub !== "string" || sub.length === 0) return null;

    return {
      subject: sub,
      ...(typeof payload["email"] === "string" ? { email: payload["email"] as string } : {}),
      ...(typeof payload["name"] === "string" ? { displayName: payload["name"] as string } : {}),
    };
  }
}

/** Existing strict parser supplies duplicate-key/Unicode/depth refusal; this profile admits integers only. */
export function strictOidcObject(input: Uint8Array): Record<string, unknown> {
  if (input[0] === 0xef && input[1] === 0xbb && input[2] === 0xbf) throw new Error("invalid OIDC JSON");
  const convert = (value: JsonValue): unknown => {
    if (typeof value === "bigint") { const n = Number(value); if (!Number.isSafeInteger(n)) throw new Error("invalid OIDC JSON"); return n; }
    if (Array.isArray(value)) return value.map(convert);
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, convert(item)]));
    return value;
  };
  const value = convert(parsePolicyJson(input));
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid OIDC JSON");
  return value as Record<string, unknown>;
}

function decodeJson(b64url: string): Record<string, unknown> | null {
  try {
    const obj = JSON.parse(Buffer.from(b64url, "base64url").toString("utf8")) as unknown;
    return obj && typeof obj === "object" ? (obj as Record<string, unknown>) : null;
  } catch { return null; }
}
function numClaim(v: unknown): number | undefined { return typeof v === "number" && Number.isFinite(v) ? v : undefined; }
function audienceContains(aud: unknown, expected: string): boolean {
  if (typeof aud === "string") return aud === expected;
  if (Array.isArray(aud)) return aud.some((a) => a === expected);
  return false;
}
function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a), bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
