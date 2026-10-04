/**
 * Session store (Increment X1) — opaque, server-side sessions for the web review UI's multi-user mode.
 *
 * SOTA basis (2026-08-06): for SESSION tokens, opaque server-side state beats JWTs because revocation must be
 * real-time — a JWT can't be un-issued without a revocation list, which negates the point (CIAM Compass; WorkOS).
 * Enforce BOTH a sliding idle timeout and an absolute cap (loginradius, OWASP); rotate the session id on login to
 * prevent fixation; and destroy the server-side record on logout, not just the cookie (JustAppSec). Session ids are
 * 32 random bytes. Each session carries its own CSRF token. Zero deps (node:crypto).
 *
 * What would change it: a multi-node deployment moves this map behind a shared store (Redis) with the same TTL
 * semantics; the interface is unchanged.
 */

import { randomBytes } from "node:crypto";
import type { Principal } from "./rbac.js";

export interface Session {
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
  create(principal: Principal, now: number): Session;
  release(): void;
}

export class SessionStore {
  private readonly sessions = new Map<string, Session>();
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
      create: (principal: Principal, createdAt: number): Session => {
        if (!this.reservations.has(token)) throw new Error("Session reservation is no longer available");
        const session: Session = { id: randomBytes(32).toString("hex"), principal,
          csrfToken: randomBytes(32).toString("hex"), createdAt, lastSeen: createdAt };
        // No await or external callback between releasing this slot and adding its session.
        this.reservations.delete(token);
        this.sessions.set(session.id, session);
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
      this.sessions.delete(id); // expired — destroy server-side, don't just let the cookie linger
      return null;
    }
    s.lastSeen = now; // sliding extension on activity
    return s;
  }

  /** Destroy a session server-side (logout / admin revocation). Idempotent. */
  revoke(id: string): void {
    this.sessions.delete(id);
  }

  /** Destroy every session for a principal (e.g., role changed or user removed — instant, real-time). */
  revokeAllFor(principalId: string): number {
    let n = 0;
    for (const [id, s] of this.sessions) if (s.principal.id === principalId) { this.sessions.delete(id); n++; }
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
      if (this.isExpired(session, now)) this.sessions.delete(id);
    }
  }
}
