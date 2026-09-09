/**
 * AUTHORIZATION SPINE — Teams/Enterprise arc, T1. The resource-scoped `may(principal, action, resource)` check
 * that gates the personalization surfaces (memory / vault / lens / connector) at a scope/subject.
 *
 * Authorization is "the missing layer," and the models COMPOSE, not replace: RBAC (coarse roles — reused from
 * `rbac.ts`, whose `AuthorizationPort` is the documented enterprise swap point) → ReBAC/Zanzibar (resource-level
 * via a relationship graph; a superset of RBAC) → PBAC (a later round). This module adds the resource-scoped
 * check + the ReBAC track + agent delegation.
 *
 * STANDING PRINCIPLE — both-and, never collapse to N=1: ONE interface (`may`), TWO tracks behind it —
 *   - `ownerResolver` (the N=1 FLOOR): the sole owner may do everything; everyone else default-deny. Zero
 *     ceremony; a solo self-hosted instance is fully functional with no org setup.
 *   - `rebacResolver` (the org CEILING): RBAC coarse roles composed with ReBAC relationship tuples
 *     (owner-of / member-of / viewer-of), walked as a graph for fine-grained, per-resource, user-driven sharing.
 * Neither is amputated to serve the other; the floor is never dropped and the ceiling is never walled off.
 *
 * FRONTIER (Keep's differentiator): Zanzibar was built for HUMAN principals over STATIC resources — it does not
 * address AI AGENTS acting on a user's behalf. Here an agent's authority is DELEGATED FROM and BOUNDED BY its
 * principal: an agent's decision is the intersection of its own (attenuated) grant and its principal-user's
 * `may(...)` — it can NEVER exceed the human it acts for (RFC 8693: delegation ≠ impersonation).
 *
 * Fail-closed: a missing/unknown envelope element ⇒ default-DENY.
 *
 * BUILT + proven in-env: the `may()` check + the two resolvers + delegation-bounding + default-deny. SEAM: the
 * relationship-tuple store (a deployment uses SpiceDB/OpenFGA) and the OIDC identity provider.
 */

import type { Principal } from "../identity/rbac.js";

export type AuthzAction = "read" | "write" | "promote" | "share" | "configure";
export type Surface = "memory" | "vault" | "lens" | "connector";
export type Scope = "user" | "project" | "team" | "global";

const ACTIONS: ReadonlySet<string> = new Set<AuthzAction>(["read", "write", "promote", "share", "configure"]);
const SURFACES: ReadonlySet<string> = new Set<Surface>(["memory", "vault", "lens", "connector"]);
const SCOPES: ReadonlySet<string> = new Set<Scope>(["user", "project", "team", "global"]);

/** A gated resource: a personalization surface at a scope, optionally a specific object / information-subject. */
export interface Resource {
  readonly surface: Surface;
  readonly scope: Scope;
  readonly id?: string | undefined; // e.g. project id / team id — the ReBAC object
  readonly subject?: string | undefined; // the information-subject (vault/memory)
}

export interface Decision {
  readonly allow: boolean;
  readonly reason: string;
}

/** A principal in a `may` call — possibly an agent acting FOR a user (delegation). */
export interface AuthzPrincipal {
  readonly principal: Principal; // reuse rbac.ts's Principal (id, kind, role)
  readonly actingFor?: AuthzPrincipal | undefined; // if an agent: the principal it is delegated from
  readonly ownGrant?: ReadonlySet<AuthzAction> | undefined; // an agent's own (attenuated) grant
}

/** One interface; a resolver decides for a non-agent principal. Owner (N=1) and ReBAC (org) both implement it. */
export interface AuthzResolver {
  resolve(who: AuthzPrincipal, action: AuthzAction, resource: Resource): Decision;
}

// ---- Track 1: the N=1 owner resolver (the floor) ----

/** The sole owner may do everything; everyone else is default-denied. Zero org ceremony. */
export function ownerResolver(ownerId: string): AuthzResolver {
  return {
    resolve(who: AuthzPrincipal): Decision {
      if (who.principal.id === ownerId && who.principal.role === "owner") {
        return { allow: true, reason: "sole owner (N=1 floor)" };
      }
      return { allow: false, reason: "not the owner (default-deny)" };
    },
  };
}

// ---- Track 2: the org ReBAC resolver (the ceiling) ----

export type Relation = "owner-of" | "member-of" | "viewer-of";
/** A Zanzibar-style relationship tuple: subject —relation→ object (object = "project:x", "team:eng", "global:"). */
export interface Tuple {
  readonly subject: string;
  readonly relation: Relation;
  readonly object: string;
}

function objectOf(resource: Resource): string {
  return `${resource.scope}:${resource.id ?? ""}`;
}

/**
 * The org resolver: RBAC coarse roles composed with ReBAC relationships. A principal may act on a resource iff a
 * relationship path connects them to the resource's object — owner-of (direct), member-of a team that owns it
 * (2-hop graph walk), or viewer-of. `read` is allowed to any relation; `write/promote/share/configure` require
 * owner-of or member-of (a viewer cannot mutate). No relationship ⇒ default-deny.
 */
export function rebacResolver(tuples: readonly Tuple[]): AuthzResolver {
  const has = (subject: string, relation: Relation, object: string): boolean =>
    tuples.some((t) => t.subject === subject && t.relation === relation && t.object === object);

  return {
    resolve(who: AuthzPrincipal, action: AuthzAction, resource: Resource): Decision {
      const uid = who.principal.id;
      const obj = objectOf(resource);
      const ownerOf = has(uid, "owner-of", obj);
      // 2-hop: uid member-of some team T, and T owner-of obj
      const memberOfOwningTeam = tuples.some(
        (t) => t.subject === uid && t.relation === "member-of" && has(t.object, "owner-of", obj),
      );
      const viewerOf = has(uid, "viewer-of", obj);

      const mutating = action !== "read";
      const canMutate = ownerOf || memberOfOwningTeam;
      const related = ownerOf || memberOfOwningTeam || viewerOf;

      if (mutating) {
        return canMutate
          ? { allow: true, reason: `${ownerOf ? "owner-of" : "member-of owning team"} ${obj}` }
          : { allow: false, reason: `no write relationship to ${obj} (viewer or none)` };
      }
      return related
        ? { allow: true, reason: `related (${ownerOf ? "owner" : memberOfOwningTeam ? "member" : "viewer"}) to ${obj}` }
        : { allow: false, reason: `no relationship to ${obj}` };
    },
  };
}

// ---- The one interface ----

function envelopeComplete(who: AuthzPrincipal, action: AuthzAction, resource: Resource): boolean {
  if (who === undefined || who.principal === undefined || !who.principal.id) return false;
  if (!ACTIONS.has(action)) return false;
  if (resource === undefined || !SURFACES.has(resource.surface) || !SCOPES.has(resource.scope)) return false;
  return true;
}

/**
 * The ONE authorization interface. Serves both tracks (pass `ownerResolver` for N=1, `rebacResolver` for org).
 *   - Fail-closed: an incomplete/unknown envelope ⇒ default-DENY.
 *   - Delegation: an agent acting-for a user is bounded by BOTH its own grant AND its principal's `may(...)` — the
 *     intersection; it can never exceed the human it acts for.
 */
export function may(who: AuthzPrincipal, action: AuthzAction, resource: Resource, resolver: AuthzResolver): Decision {
  if (!envelopeComplete(who, action, resource)) {
    return { allow: false, reason: "incomplete authorization envelope (default-deny)" };
  }

  if (who.actingFor !== undefined) {
    // bounded by the principal it acts for (never exceeds it)
    const principalDecision = may(who.actingFor, action, resource, resolver);
    if (!principalDecision.allow) {
      return { allow: false, reason: `agent bounded by principal: ${principalDecision.reason}` };
    }
    // and bounded by its own attenuated grant
    if (who.ownGrant !== undefined && !who.ownGrant.has(action)) {
      return { allow: false, reason: `agent's own grant excludes '${action}'` };
    }
    return { allow: true, reason: `agent within its principal's authority for '${action}'` };
  }

  return resolver.resolve(who, action, resource);
}
