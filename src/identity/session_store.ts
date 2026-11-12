/**
 * Session store — opaque, server-side sessions for the web review UI's multi-user mode.
 *
 * Research references (2026-08-06): for SESSION tokens, opaque server-side state beats JWTs because revocation must be
 * real-time — a JWT can't be un-issued without a revocation list, which negates the point (CIAM Compass; WorkOS).
 * Enforce BOTH a sliding idle timeout and an absolute cap (loginradius, OWASP); rotate the session id on login to
 * prevent fixation; and destroy the server-side record on logout, not just the cookie (JustAppSec). Session ids are
 * 32 random bytes. Each session carries its own CSRF token.
 *
 * Extension considerations: a multi-node deployment moves this map behind a shared store (Redis) with the same TTL
 * semantics; the interface is unchanged.
 */

import { randomBytes } from "node:crypto";
import type { Principal } from "./rbac.js";
export interface SessionAuthorityRef {
  readonly bootId: string; readonly authorityId: string;
  readonly issuer: string; readonly subject: string; readonly tenantId: string;
}
export function captureSessionAuthorityRef(value: unknown): SessionAuthorityRef {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== "authorityId,bootId,issuer,subject,tenantId") throw new Error("invalid session authority reference");
  const row = value as SessionAuthorityRef;
  if (!/^[a-f0-9]{32}$/u.test(row.bootId) || !/^[a-f0-9]{64}$/u.test(row.authorityId) || [row.issuer, row.subject, row.tenantId].some(s => typeof s !== "string" || !s || s.length > 8192 || /[\u0000-\u001f\u007f]/u.test(s))) throw new Error("invalid session authority reference");
  return Object.freeze({ bootId: row.bootId, authorityId: row.authorityId, issuer: row.issuer, subject: row.subject, tenantId: row.tenantId });
}

export interface Session {
  readonly authority?: SessionAuthorityRef;
  readonly authentication?: { readonly issuer: string; readonly subject: string; readonly tenantId: string };
  readonly id: string;
  readonly principal: Principal;
  readonly csrfToken: string;
  readonly createdAt: number;
  lastSeen: number;
}

export interface SessionStoreConfig {
  /** Idle timeout — a session unused for this long expires (sliding). Default 30 min. */
  readonly idleMs?: number;
  /** Absolute cap — a session older than this expires regardless of activity. Default 8 h. */
  readonly absoluteMs?: number;
  /** Global live sessions plus provisional slots. Finite positive integer; engineering default 10,000. */
  readonly maxSessions?: number;
}

export class SessionCapacityError extends Error {
  readonly code = "session-capacity";
  constructor() { super("Session capacity reached"); }
}

/** A counted, one-shot slot. Release unused slots in finally around asynchronous authority effects. */
export interface SessionReservation {
  create(principal: Principal, now: number, authentication?: Session["authentication"]): Session;
  release(): void;
}

export class SessionStore {
  private readonly sessions = new Map<string, Session>();
  private readonly bootId = randomBytes(16).toString("hex");
  private readonly authorities = new Map<string, Session>();
  private readonly idleMs: number;
  private readonly absoluteMs: number;
  private readonly maxSessions: number;
  private readonly reservations = new Set<symbol>();

  constructor(cfg: SessionStoreConfig = {}) {
    this.idleMs = cfg.idleMs ?? 30 * 60_000;
    this.absoluteMs = cfg.absoluteMs ?? 8 * 60 * 60_000;
    this.maxSessions = cfg.maxSessions ?? 10_000;
    if (!Number.isSafeInteger(this.maxSessions) || this.maxSessions < 1) {
      throw new Error("SessionStore maxSessions must be a finite positive safe integer");
    }
  }

  /** Mint a fresh session for a just-authenticated principal (new id → rotation, anti-fixation). */
  create(principal: Principal, now: number): Session {
    const slot = this.reserve(now);
    try { return slot.create(principal, now); }
    finally { slot.release(); }
  }

  /** Reserve before awaiting effects. A reservation cannot expire or be taken by another login. */
  reserve(now: number): SessionReservation {
    this.purgeExpired(now);
    if (this.sessions.size + this.reservations.size >= this.maxSessions) throw new SessionCapacityError();
    const token = Symbol("session slot");
    this.reservations.add(token);
    return Object.freeze({
      create: (principal: Principal, createdAt: number, authentication?: Session["authentication"]): Session => {
        if (!this.reservations.has(token)) throw new Error("Session reservation is no longer available");
        const authority = authentication === undefined ? undefined : captureSessionAuthorityRef({ bootId: this.bootId, authorityId: randomBytes(32).toString("hex"), ...authentication });
        const session: Session = { id: randomBytes(32).toString("hex"), principal, ...(authentication ? { authentication: Object.freeze({ ...authentication }), authority: authority! } : {}),
          csrfToken: randomBytes(32).toString("hex"), createdAt, lastSeen: createdAt };
        // No await or external callback between releasing this slot and adding its session.
        this.reservations.delete(token);
        this.sessions.set(session.id, session);
        if (authority) this.authorities.set(authority.authorityId, session);
        return session;
      },
      release: () => { this.reservations.delete(token); },
    });
  }

  /** Resolve a live session, enforcing idle + absolute timeouts. Expired sessions are destroyed and return null. */
  get(id: string | undefined, now: number): Session | null {
    if (!id) return null;
    const s = this.sessions.get(id);
    if (!s) return null;
    if (this.isExpired(s, now)) {
      this.revoke(id); // expired — destroy server-side and its admission reference
      return null;
    }
    s.lastSeen = now; // sliding extension on activity
    return s;
  }

  /** Destroy a session server-side (logout / admin revocation). Idempotent. */
  revoke(id: string): void {
    const session = this.sessions.get(id);
    if (session?.authority) this.authorities.delete(session.authority.authorityId);
    this.sessions.delete(id);
  }

  /** Non-bearer dispatch check; does not count as browser activity or extend idle expiry. */
  assertAuthority(input: SessionAuthorityRef | undefined, principal: Principal, now: number): void {
    if (!input || !Number.isFinite(now)) throw new Error("session authority unavailable");
    const ref = captureSessionAuthorityRef(input), session = this.authorities.get(ref.authorityId);
    if (ref.bootId !== this.bootId || !session || this.isExpired(session, now) || now < session.createdAt || session.principal.kind !== "human"
      || principal.kind !== "human" || ref.tenantId !== principal.tenant || session.principal.id !== principal.id || session.principal.tenant !== principal.tenant || !session.authority
      || JSON.stringify(session.authority) !== JSON.stringify(ref)) throw new Error("session authority unavailable");
  }

  /** Rotates credentials without replenishing the absolute authentication lifetime. */
  rotate(id: string, now: number): Session {
    const previous = this.get(id, now);
    if (!previous?.authentication || !previous.authority) throw new Error("session rotation unavailable");
    this.revoke(id);
    const slot = this.reserve(now);
    try { const rotated = slot.create(previous.principal, previous.createdAt, previous.authentication); rotated.lastSeen = now; return rotated; }
    finally { slot.release(); }
  }

  /** Destroy every session for a principal (e.g., role changed or user removed — instant, real-time). */
  revokeAllFor(principalId: string): number {
    let n = 0;
    for (const [id, s] of this.sessions) if (s.principal.id === principalId) { this.revoke(id); n++; }
    return n;
  }

  /** Count live sessions at the same clock used by create/get; reclaim untouched expired entries. */
  activeCount(now: number = Date.now()): number {
    this.purgeExpired(now);
    return this.sessions.size;
  }

  private isExpired(session: Session, now: number): boolean {
    return now - session.createdAt > this.absoluteMs || now - session.lastSeen > this.idleMs;
  }

  private purgeExpired(now: number): void {
    for (const [id, session] of this.sessions) {
      if (this.isExpired(session, now)) this.revoke(id);
    }
  }
}
