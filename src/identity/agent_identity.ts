/**
 * Per-agent identity + kill switch (Core Addition C).
 *
 * Every agent/sub-agent gets an UNFORGEABLE identity — a capability TOKEN, not a claimed name — bound
 * to a narrow scope. All its effects carry that identity; a kill switch revokes an identity so its
 * subsequent effects are refused. A killed, unknown, forged, or out-of-scope identity fails safe to
 * REFUSE.
 *
 * DISCIPLINE (research, 2026-08-09):
 *  - Capability, not a name (SPIFFE/agent-identity): "a JWT anyone who intercepts can replay is a
 *    credential problem pretending to be an identity." So identity is a secret token; presenting the
 *    id (the name) without the matching token is refused — you must HOLD the capability.
 *  - Narrow, per-task scope + ATTENUATING delegation (SPIFFE aud guidance: wide scope "opens
 *    impersonation if one service is compromised"; RFC 8693 delegation ≠ impersonation): a delegated
 *    sub-identity's scope is the INTERSECTION with its parent — it can only narrow, never widen.
 *  - Revocable / short-lived (the kill discipline): "a token that outlives its workload may continue
 *    to be accepted even after the workload has ceased to exist." Kill is immediate and MONOTONE — a
 *    killed identity stays killed; its effects are refused thereafter.
 *  - Attribution (audit names the run, not the bot): every mint/kill records to the spine.
 *
 * BUILT vs SEAM: BUILT is the in-env identity model + registry + kill + fail-safe authorization + the
 * gate binding (a killed/unknown identity is a deny-capable gate input). A real OS-level enforcement —
 * a process-group / cgroup kill that terminates a revoked agent's PROCESS so it cannot emit effects
 * out of band, and cross-process credential attestation (SPIFFE/SVID-class) — is a SEAM (R35), the
 * same OS-enforcement family as R3/R27.
 *
 * WHAT WOULD CHANGE IT: short-lived expiry (an exp claim) would add time-bounded refusal; proof-of-
 * possession (DPoP/X509-SVID) would harden the token against replay. Neither lets a killed or
 * out-of-scope identity proceed.
 */

import { randomBytes } from "node:crypto";
import { withinScope } from "../authz/path_scope.js";
import type { Spine } from "../spine/spine.js";

/**
 * ROUND 35 — the named handles an operator revokes with. A kill switch you cannot address is
 * not a kill switch, so the ids the production paths mint are exported rather than inlined.
 */
export const DEFAULT_SOLVER_IDENTITY_ID = "keep-default-solver";

/** An unforgeable agent identity: a public id + a secret capability token + a narrow scope. */
export interface AgentIdentity {
  readonly id: string;
  /** The unforgeable capability — holding this string IS the identity. Never logged in full. */
  readonly token: string;
  /** Allowed path prefixes. An effect's path must be under one of these. */
  readonly scope: readonly string[];
}

interface Registered {
  readonly token: string;
  readonly scope: readonly string[];
}

export type AuthzResult =
  | { readonly authorized: true }
  | { readonly authorized: false; readonly reason: string };

/**
 * Is `path` within one of the scope prefixes?
 *
 * ROUND 38: the predicate MOVED to `../authz/path_scope.js` and is now shared with the
 * structural floor's write-set allowlist. Round 37 refused to wire a second path-authority
 * mechanism into the write path; writing a second one for the floor would have been the same
 * mistake facing the other way. One predicate, two callers.
 *
 * Compares CANONICAL forms on both sides; the stored scope strings are left untouched, so a
 * delegated identity still reports the scope it was granted verbatim.
 */
const inScope = withinScope;

/** Attenuate: the child scope is the subset of `requested` that is within the parent scope. */
function attenuate(parentScope: readonly string[], requested: readonly string[]): string[] {
  return requested.filter((r) => inScope(parentScope, r) || (parentScope.includes("*") ));
}

/** The identity registry: mints unforgeable identities, records kills, and authorizes effects. */
export class IdentityRegistry {
  private readonly registered = new Map<string, Registered>();
  private readonly revoked = new Set<string>();

  constructor(private readonly spine?: Spine) {}

  /** Mint a root identity with a fresh unforgeable token and a narrow scope. */
  mint(id: string, scope: readonly string[]): AgentIdentity {
    const token = randomBytes(32).toString("hex");
    this.registered.set(id, { token, scope: [...scope] });
    this.spine?.stage({ type: "identity.created", actor: "agent-identity", payload: { event: "agent.minted", id, scope } });
    return { id, token, scope: [...scope] };
  }

  /**
   * Delegate a sub-identity from a LIVE parent. The child scope is ATTENUATED — the intersection of
   * the requested scope with the parent's. A killed/forged parent cannot delegate.
   */
  delegate(parent: AgentIdentity, childId: string, requestedScope: readonly string[]): AgentIdentity | undefined {
    if (this.authorize(parent).authorized !== true) return undefined; // dead/forged parent can't delegate
    const childScope = attenuate(parent.scope, requestedScope);
    const token = randomBytes(32).toString("hex");
    this.registered.set(childId, { token, scope: childScope });
    this.spine?.stage({ type: "identity.created", actor: "agent-identity", payload: { event: "agent.delegated", id: childId, parent: parent.id, scope: childScope } });
    return { id: childId, token, scope: childScope };
  }

  /** Kill an identity — monotone, recorded to the spine. Its subsequent effects are refused. */
  kill(id: string, reason = "revoked"): void {
    this.revoked.add(id);
    this.spine?.stage({ type: "identity.action", actor: "agent-identity", payload: { event: "agent.killed", id, reason } });
  }

  isKilled(id: string): boolean {
    return this.revoked.has(id);
  }

  /** Is this identity LIVE — known, token matches (unforgeable), and not killed? Fail-safe. */
  authorize(identity: AgentIdentity | undefined): AuthzResult {
    if (identity === undefined) return { authorized: false, reason: "no-identity" };
    const reg = this.registered.get(identity.id);
    if (reg === undefined) return { authorized: false, reason: "unknown-identity" };
    if (reg.token !== identity.token) return { authorized: false, reason: "forged-token" }; // claimed the name, lacks the capability
    if (this.revoked.has(identity.id)) return { authorized: false, reason: "killed-identity" };
    return { authorized: true };
  }

  /** Authorize a specific EFFECT: the identity must be live AND the path within its (attenuated) scope. */
  authorizeEffect(identity: AgentIdentity | undefined, path: string): AuthzResult {
    const live = this.authorize(identity);
    if (live.authorized !== true) return live;
    const reg = this.registered.get(identity!.id)!;
    if (!inScope(reg.scope, path)) return { authorized: false, reason: `out-of-scope:${path}` };
    return { authorized: true };
  }
}
