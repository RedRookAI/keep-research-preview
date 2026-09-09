/**
 * Open RBAC (Increment X0) — the authorization core that lets a TEAM share a Keep instance, without ever degrading
 * the single operator. It is deliberately the open, self-hostable core: a small roles→permissions model behind a
 * port, so an enterprise can swap in ABAC / ReBAC / a policy engine (Cedar, OPA) later (X1) without changing the
 * call sites.
 *
 * N=1 is untouched: when no team is configured, the implicit principal is the OWNER with every permission and there
 * is no login. RBAC only engages when principals are explicitly configured. (On the host, the CLI acts as owner —
 * shell access to the Keep box is ownership; RBAC's job is to govern the shared web surface where many people connect.)
 *
 * SOTA basis (2026-08-06):
 *  - Treat the agent as a FIRST-CLASS identity with a least-privilege role; "never let an agent call
 *    permission-management APIs or approve its own actions" (Microsoft Entra Agent ID; cowork.ink; CSA). Here the
 *    `agent` role has `change.solve` and NOTHING else — it can propose, but structurally cannot approve, decline,
 *    or change roles. That is Keep's human merge gate (I6) expressed as an access-control invariant (I9).
 *  - Design roles around discrete units of work, least privilege, and per-request enforcement ("never trust,
 *    always verify") — permissions here are discrete actions, checked at each decision point, not once at login.
 *  - RBAC is the foundational boundary; agents strain the stable-subject assumption, so keep it behind a port and
 *    layer relationship/attribute checks later (Zuplo, Avatier, hymalaia). What would change it: a deployment that
 *    needs per-resource / on-behalf-of scoping swaps the AuthorizationPort for a ReBAC store — call sites unchanged.
 */

export type Permission =
  | "review.view"
  | "review.approve"
  | "review.decline"
  | "change.solve"
  | "config.write"
  | "calibration.authorize"
  | "serve"
  | "audit.view"
  | "audit.export"
  | "rbac.admin"
  | "skill.publish"
  | "skill.install"
  | "memory.read"
  | "memory.write"
  | "memory.forget"
  | "audience.read"
  | "audience.import"
  | "audience.erase"
  | "audience.reset"
  | "adaptation.read"
  | "adaptation.manage"
  | "adaptation.observe";

export const ALL_PERMISSIONS: readonly Permission[] = [
  "review.view", "review.approve", "review.decline", "change.solve",
  "config.write", "calibration.authorize", "serve", "audit.view", "audit.export", "rbac.admin", "skill.publish", "skill.install", "memory.read", "memory.write", "memory.forget", "audience.read", "audience.import", "audience.erase", "audience.reset", "adaptation.read", "adaptation.manage", "adaptation.observe",
];

export type Role = "owner" | "maintainer" | "reviewer" | "operator" | "viewer" | "agent";

export type PrincipalKind = "human" | "agent" | "service";

export interface Principal {
  readonly id: string;
  readonly kind: PrincipalKind;
  readonly role: Role;
  readonly displayName?: string;
  /** P-7: the tenant this principal belongs to. Absent = single-tenant (n=1) — sees the full trail. */
  readonly tenant?: string;
}

/** Roles as least-privilege bundles of discrete permissions. The agent gets ONLY `change.solve`. */
export const ROLE_PERMISSIONS: Readonly<Record<Role, ReadonlySet<Permission>>> = {
  owner: new Set<Permission>(ALL_PERMISSIONS),
  maintainer: new Set<Permission>(["review.view", "review.approve", "review.decline", "change.solve", "config.write", "calibration.authorize", "serve", "audit.view", "audit.export", "skill.publish", "skill.install", "memory.read", "memory.write", "memory.forget", "audience.read", "audience.import", "audience.erase", "audience.reset", "adaptation.read", "adaptation.manage", "adaptation.observe"]),
  reviewer: new Set<Permission>(["review.view", "review.approve", "review.decline", "audit.view", "memory.read", "audience.read", "adaptation.read"]),
  operator: new Set<Permission>(["change.solve", "serve", "review.view", "audit.view", "skill.install", "memory.read", "memory.write", "audience.read", "audience.import", "audience.erase", "adaptation.read", "adaptation.manage", "adaptation.observe"]),
  viewer: new Set<Permission>(["review.view", "audit.view", "memory.read", "audience.read", "adaptation.read"]),
  agent: new Set<Permission>(["change.solve"]), // proposes changes; NEVER approves its own work, never admins RBAC
};

export interface AuthzDecision {
  readonly allow: boolean;
  readonly reason: string;
}

/** The swap point: a deployment can replace this with an ABAC/ReBAC/policy-engine authorizer (X1/enterprise). */
export interface AuthorizationPort {
  authorize(principal: Principal, action: Permission): AuthzDecision;
}

/** Default authorizer: pure roles→permissions. Deny-by-default (unknown role/permission → deny). */
export class RbacAuthorizer implements AuthorizationPort {
  authorize(principal: Principal, action: Permission): AuthzDecision {
    const perms = ROLE_PERMISSIONS[principal.role];
    if (perms && perms.has(action)) return { allow: true, reason: `role '${principal.role}' permits '${action}'` };
    return { allow: false, reason: `role '${principal.role}' does not permit '${action}'` };
  }
}

/** The implicit single-operator principal — full access, no configuration (N=1 default). */
export const OWNER: Principal = { id: "owner", kind: "human", role: "owner", displayName: "Owner" };

/** The agent's own identity. Least-privilege by construction: it can propose changes and nothing else. */
export const AGENT: Principal = { id: "keep-agent", kind: "agent", role: "agent", displayName: "Keep (agent)" };

/** Convenience: does this principal hold this permission? */
export function can(auth: AuthorizationPort, principal: Principal, action: Permission): boolean {
  return auth.authorize(principal, action).allow;
}
