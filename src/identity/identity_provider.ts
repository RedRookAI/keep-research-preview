/**
 * Identity provider port + registry (Increment X1).
 *
 * The port is the seam a real IdP plugs into: an OIDC adapter verifies an ID token's signature against the
 * provider's JWKS (RS256), checks iss/aud/exp/nonce, and returns the verified claims. Swapping that adapter in
 * requires no change to the web UI or the session layer.
 *
 * `HmacAssertionProvider` is a concrete, dependency-free provider that verifies an HMAC-signed identity assertion.
 * It models the SAME trust relationship — the IdP signs an assertion of "who this is"; the relying party verifies
 * the signature and expiry before trusting it — so the whole login→session→RBAC flow is provable end-to-end here,
 * with a shared secret standing in for the IdP's signing key. What would change it: production federation replaces
 * the shared secret with asymmetric JWKS verification (the OIDC adapter) behind this same port.
 *
 * The registry maps a verified identity to a Keep principal (role). Deny-by-default: an identity with no mapping
 * gets NO access — there is no implicit role.
 *
 * SOTA basis (2026-08-06): verify the identity assertion's signature + expiry before trust (OIDC ID-token
 * verification); least privilege + explicit assignment, no default grant (Microsoft Entra; CSA). Zero deps.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import type { Principal, Role } from "./rbac.js";

export interface VerifiedIdentity {
  readonly subject: string;
  readonly email?: string;
  readonly displayName?: string;
}

export interface IdentityProviderPort {
  /** Verify an authentication assertion and return the identity, or null if invalid/expired. */
  verify(assertion: string, now: number): Promise<VerifiedIdentity | null>;
}

interface AssertionPayload {
  readonly sub: string;
  readonly email?: string;
  readonly name?: string;
  readonly exp: number; // ms epoch
}

/** Concrete provider: verifies `base64url(payload).hmacHex`. Models an IdP-signed assertion (see file header). */
export class HmacAssertionProvider implements IdentityProviderPort {
  constructor(private readonly secret: string) {
    if (!secret) throw new Error("HmacAssertionProvider requires a signing secret");
  }

  /** Build a signed assertion (used by a dev login form and by tests; a real IdP does this on its side). */
  sign(payload: AssertionPayload): string {
    const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
    return `${encoded}.${this.mac(encoded)}`;
  }

  async verify(assertion: string, now: number): Promise<VerifiedIdentity | null> {
    const dot = assertion.lastIndexOf(".");
    if (dot <= 0) return null;
    const encoded = assertion.slice(0, dot);
    const sig = assertion.slice(dot + 1);
    const expected = this.mac(encoded);
    if (!this.constantEq(sig, expected)) return null;
    let payload: AssertionPayload;
    try {
      payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as AssertionPayload;
    } catch {
      return null;
    }
    if (typeof payload.sub !== "string" || !payload.sub) return null;
    if (typeof payload.exp !== "number" || payload.exp <= now) return null; // expired or missing expiry
    return {
      subject: payload.sub,
      ...(payload.email ? { email: payload.email } : {}),
      ...(payload.name ? { displayName: payload.name } : {}),
    };
  }

  private mac(encoded: string): string {
    return createHmac("sha256", this.secret).update(encoded).digest("hex");
  }
  private constantEq(a: string, b: string): boolean {
    const ab = Buffer.from(a), bb = Buffer.from(b);
    if (ab.length !== bb.length) return false;
    return timingSafeEqual(ab, bb);
  }
}

export interface PrincipalMapping {
  /** Match by IdP subject (preferred — stable) and/or email. */
  readonly subject?: string;
  readonly email?: string;
  readonly role: Role;
  /** Enterprise tenant boundary. Omit only for the n=1/single-tenant review surface. */
  readonly tenant?: string;
  /** Optional explicit principal id; defaults to the verified subject. */
  readonly id?: string;
  readonly displayName?: string;
}

/** Maps a verified identity → a Keep principal. Deny-by-default: no mapping → null (no access). */
export class PrincipalRegistry {
  constructor(private readonly mappings: readonly PrincipalMapping[]) {}

  /** Resolve an already authenticated durable subject against current configuration.
   * Email-only mappings without an explicit id cannot recover a stable subject. */
  resolveReference(id: string, tenant?: string): Principal | undefined {
    const matches = this.mappings.filter(m => (m.id ?? m.subject) === id && m.tenant === tenant);
    if (matches.length !== 1) return undefined;
    const m = matches[0]!;
    return { id, kind: "human", role: m.role, ...(tenant === undefined ? {} : { tenant }) };
  }

  resolve(identity: VerifiedIdentity): Principal | null {
    for (const m of this.mappings) {
      const bySub = m.subject !== undefined && m.subject === identity.subject;
      const byEmail = m.email !== undefined && identity.email !== undefined && m.email.toLowerCase() === identity.email.toLowerCase();
      if (bySub || byEmail) {
        const displayName = m.displayName ?? identity.displayName;
        return { id: m.id ?? identity.subject, kind: "human", role: m.role, ...(displayName ? { displayName } : {}), ...(m.tenant ? { tenant: m.tenant } : {}) };
      }
    }
    return null;
  }
}
