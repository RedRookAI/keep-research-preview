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
}

export class SessionStore {
  private readonly sessions = new Map<string, Session>();
  private readonly idleMs: number;
  private readonly absoluteMs: number;

  constructor(cfg: SessionStoreConfig = {}) {
    this.idleMs = cfg.idleMs ?? 30 * 60_000;
    this.absoluteMs = cfg.absoluteMs ?? 8 * 60 * 60_000;
  }

  /** Mint a fresh session for a just-authenticated principal (new id → rotation, anti-fixation). */
  create(principal: Principal, now: number): Session {
    const session: Session = {
      id: randomBytes(32).toString("hex"),
      principal,
      csrfToken: randomBytes(32).toString("hex"),
      createdAt: now,
      lastSeen: now,
    };
    this.sessions.set(session.id, session);
    return session;
  }

  /** Resolve a live session, enforcing idle + absolute timeouts. Expired sessions are destroyed and return null. */
  get(id: string | undefined, now: number): Session | null {
    if (!id) return null;
    const s = this.sessions.get(id);
    if (!s) return null;
    if (now - s.createdAt > this.absoluteMs || now - s.lastSeen > this.idleMs) {
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

  activeCount(): number {
    return this.sessions.size;
  }
}
