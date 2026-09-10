import { randomUUID } from "node:crypto";
import type { Spine } from "../spine/spine.js";
import { ALL_PERMISSIONS, ROLE_PERMISSIONS, type AuthorizationPort, type AuthzDecision, type Permission, type Principal, type Role } from "./rbac.js";

export interface DelegatedAgentPrincipal extends Principal {
  readonly kind: "agent";
  readonly role: "agent";
  readonly delegatedBy: string;
  readonly grantId: string;
}
export type DelegationParentResolver = (id: string, tenant?: string) => Principal | undefined;

interface DurableGrant {
  readonly grantId: string;
  readonly agentId: string;
  readonly parent: { readonly id: string; readonly role: Role; readonly tenant?: string };
  readonly permissions: readonly Permission[];
  readonly issuedAt: number;
  readonly expiresAt: number;
}
interface DelegationProjection {
  readonly grants: ReadonlyMap<string, DurableGrant>;
  readonly revoked: ReadonlySet<string>;
}

const PROHIBITED = new Set<Permission>(["rbac.admin", "review.approve", "review.decline", "calibration.authorize", "audience.import", "audience.erase", "audience.reset", "adaptation.manage"]);
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

/**
 * Issued delegation is an append-only projection of the canonical Spine. The base authorizer remains
 * the policy source of truth and is rechecked on every use, so parent revocation or policy tightening
 * attenuates an already-issued grant immediately. Effect-level target authority remains owned by the
 * existing effect boundary; this registry cannot mint it.
 */
export class DelegationRegistry implements AuthorizationPort {
  constructor(
    private readonly base: AuthorizationPort,
    private readonly spine: Spine,
    private readonly resolveParent: DelegationParentResolver,
    private readonly clock: () => number = () => Date.now(),
  ) {
    if (!spine.verify().ok) throw new Error("delegation Spine is not verifiable");
    this.project();
  }

  async issue(
    parent: Principal,
    agentId: string,
    requested: readonly Permission[],
    expiresAt: number,
    issuedAt = this.clock(),
    grantId: string = randomUUID(),
  ): Promise<DelegatedAgentPrincipal> {
    if (!this.spine.durableStorage()) throw new Error("delegation issuance requires an fsync-durable Spine");
    const requestedParent = captureParent(parent);
    const currentParent = this.resolveParent(requestedParent.id, requestedParent.tenant);
    if (currentParent === undefined || currentParent.kind !== "human" || currentParent.role === "agent" || currentParent.id !== requestedParent.id || currentParent.tenant !== requestedParent.tenant) throw new Error("delegation parent is not present in the live human directory");
    const capturedParent = captureParent(currentParent);
    if (!SAFE_ID.test(agentId) || !SAFE_ID.test(grantId)) throw new Error("delegation requires safe non-empty agent and grant ids");
    if (!Number.isSafeInteger(issuedAt) || !Number.isSafeInteger(expiresAt) || expiresAt <= issuedAt) throw new Error("delegation expiry must be a future safe-integer timestamp");
    if (!Array.isArray(requested) || requested.length > ALL_PERMISSIONS.length || requested.some((permission) => !ALL_PERMISSIONS.includes(permission))) throw new Error("delegation requested an unknown or unbounded permission set");
    return this.spine.withCoordinationLock("identity.delegation", async () => {
      const projection = this.project();
      if (projection.grants.has(grantId) || projection.revoked.has(grantId)) throw new Error("delegation grant id already exists or was revoked");
      const permissions = [...new Set(requested)].filter((permission) => !PROHIBITED.has(permission) && this.base.authorize(currentParent, permission).allow).sort();
      const grant = captureGrant({ grantId, agentId, parent: capturedParent, permissions, issuedAt, expiresAt });
      this.spine.stage({ type: "identity.action", actor: "delegation", payload: { event: "delegation.issued", ...grant } });
      await this.spine.seal();
      try {
        if (!this.spine.verify().ok || !this.project().grants.has(grantId)) throw new Error("delegation issuance could not be verified after sealing");
      } catch (error) {
        await this.compensateFailedIssue(grantId, error);
      }
      return principalFor(grant);
    });
  }

  /** Trusted host-administrator operation. Request handlers must use revokeFor. */
  async revoke(grantId: string): Promise<boolean> {
    return this.revokeMatching(grantId);
  }

  /** Revoke only within the authenticated human manager's tenant. Unknown/foreign IDs are no-ops. */
  async revokeFor(caller: Principal, grantId: string): Promise<boolean> {
    // Capture identity before awaiting coordination; never keep a mutable caller reference.
    if (caller.kind !== "human" || caller.role === "agent") return false;
    let captured: DurableGrant["parent"];
    try { captured = captureParent(caller); } catch { return false; }
    return this.revokeMatching(grantId, captured);
  }

  private async revokeMatching(grantId: string, caller?: DurableGrant["parent"]): Promise<boolean> {
    if (!this.spine.durableStorage()) throw new Error("delegation revocation requires an fsync-durable Spine");
    if (!SAFE_ID.test(grantId)) return false;
    return this.spine.withCoordinationLock("identity.delegation", async () => {
      if (caller !== undefined) {
        // Recheck live authority under the same lock as target lookup and mutation.
        const current = this.resolveParent(caller.id, caller.tenant);
        if (current === undefined || current.kind !== "human" || current.role === "agent" || current.id !== caller.id || current.tenant !== caller.tenant || !this.base.authorize(current, "rbac.admin").allow) return false;
      }
      const grant = this.project().grants.get(grantId);
      if (grant === undefined || (caller !== undefined && grant.parent.tenant !== caller.tenant)) return false;
      this.spine.stage({ type: "identity.action", actor: "delegation", payload: { event: "delegation.revoked", grantId } });
      await this.spine.seal();
      if (!this.spine.verify().ok || this.project().grants.has(grantId)) throw new Error("delegation revocation could not be verified after sealing");
      return true;
    });
  }

  authorize(principal: Principal, action: Permission): AuthzDecision {
    if (principal.kind === "human" && principal.role !== "agent") return this.base.authorize(principal, action);
    if (principal.kind !== "agent") return { allow: false, reason: "non-human principal has no valid issued delegation" };
    let grant: DurableGrant | undefined;
    try { grant = this.resolve(principal, this.project().grants); }
    catch { return { allow: false, reason: "delegation evidence is not verifiable" }; }
    if (grant === undefined) return { allow: false, reason: "agent has no valid issued delegation" };
    if (this.clock() >= grant.expiresAt) return { allow: false, reason: "delegated grant expired" };
    if (!grant.permissions.includes(action)) return { allow: false, reason: "delegated grant excludes action" };
    const parent = this.liveParent(grant);
    if (parent === undefined || !this.base.authorize(parent, action).allow) return { allow: false, reason: "human parent no longer holds delegated authority" };
    return { allow: true, reason: `human ${grant.parent.id} delegated '${action}' under ${grant.grantId}` };
  }

  attribution(principal: Principal): { readonly humanPrincipalId: string; readonly agentPrincipalId?: string; readonly grantId?: string } | undefined {
    if (principal.kind === "human" && principal.role !== "agent") return { humanPrincipalId: principal.id };
    if (principal.kind !== "agent") return undefined;
    let grant: DurableGrant | undefined;
    try { grant = this.resolve(principal, this.project().grants); } catch { return undefined; }
    if (grant === undefined || this.clock() >= grant.expiresAt) return undefined;
    return Object.freeze({ humanPrincipalId: grant.parent.id, agentPrincipalId: grant.agentId, grantId: grant.grantId });
  }

  restorePrincipal(grantId: string): DelegatedAgentPrincipal | undefined {
    let grant: DurableGrant | undefined;
    try { grant = this.project().grants.get(grantId); } catch { return undefined; }
    return grant === undefined || this.clock() >= grant.expiresAt ? undefined : principalFor(grant);
  }

  private resolve(principal: Principal, grants: ReadonlyMap<string, DurableGrant>): DurableGrant | undefined {
    const grantId = (principal as Partial<DelegatedAgentPrincipal>).grantId;
    const delegatedBy = (principal as Partial<DelegatedAgentPrincipal>).delegatedBy;
    if (typeof grantId !== "string" || typeof delegatedBy !== "string") return undefined;
    const grant = grants.get(grantId);
    return grant !== undefined && grant.agentId === principal.id && grant.parent.id === delegatedBy && grant.parent.tenant === principal.tenant && principal.role === "agent" ? grant : undefined;
  }

  private liveParent(grant: DurableGrant): Principal | undefined {
    const parent = this.resolveParent(grant.parent.id, grant.parent.tenant);
    return parent !== undefined && parent.kind === "human" && parent.role !== "agent" && parent.id === grant.parent.id && parent.tenant === grant.parent.tenant ? parent : undefined;
  }

  private async compensateFailedIssue(grantId: string, cause: unknown): Promise<never> {
    try {
      this.spine.stage({ type: "identity.action", actor: "delegation", payload: { event: "delegation.revoked", grantId } });
      await this.spine.seal();
      if (!this.spine.verify().ok) throw new Error("compensating revocation is not verifiable");
      const projection = this.project();
      if (projection.grants.has(grantId) || !projection.revoked.has(grantId)) throw new Error("compensating revocation is not effective");
    } catch (compensationError) {
      throw new Error(`delegation issuance is indeterminate for grant ${grantId}; explicit revocation is required`, { cause: { issuance: cause, compensation: compensationError } });
    }
    throw cause;
  }

  private project(): DelegationProjection {
    if (!this.spine.verify().ok) throw new Error("delegation Spine is not verifiable");
    const grants = new Map<string, DurableGrant>();
    const revoked = new Set<string>();
    for (const row of this.spine.replay()) {
      const payload = row.payload as Record<string, unknown>;
      if (row.type !== "identity.action" || row.actor !== "delegation" || (payload["event"] !== "delegation.issued" && payload["event"] !== "delegation.revoked")) continue;
      if (payload["event"] === "delegation.revoked") {
        if (Object.keys(payload).sort().join(",") !== "event,grantId" || typeof payload["grantId"] !== "string" || !SAFE_ID.test(payload["grantId"])) continue;
        revoked.add(payload["grantId"]); grants.delete(payload["grantId"]); continue;
      }
      const { event: _event, ...candidate } = payload;
      try {
        const grant = captureGrant(candidate);
        if (grants.has(grant.grantId) || revoked.has(grant.grantId)) { grants.delete(grant.grantId); revoked.add(grant.grantId); continue; }
        grants.set(grant.grantId, grant);
      } catch {
        const grantId = candidate["grantId"];
        if (typeof grantId === "string" && SAFE_ID.test(grantId)) { grants.delete(grantId); revoked.add(grantId); }
      }
    }
    return Object.freeze({ grants, revoked });
  }
}

function captureParent(parent: Principal): DurableGrant["parent"] {
  if (parent.kind !== "human" || typeof parent.id !== "string" || !SAFE_ID.test(parent.id) || !(parent.role in ROLE_PERMISSIONS) || (parent.tenant !== undefined && (typeof parent.tenant !== "string" || !SAFE_ID.test(parent.tenant)))) throw new Error("delegation requires a valid human parent");
  return Object.freeze({ id: parent.id, role: parent.role, ...(parent.tenant === undefined ? {} : { tenant: parent.tenant }) });
}

function captureGrant(value: unknown): DurableGrant {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid delegation grant");
  const row = value as Record<string, unknown>;
  if (Object.keys(row).sort().join(",") !== "agentId,expiresAt,grantId,issuedAt,parent,permissions") throw new Error("invalid delegation grant schema");
  const parent = captureDurableParent(row["parent"]);
  const permissions = row["permissions"];
  if (typeof row["grantId"] !== "string" || !SAFE_ID.test(row["grantId"]) || typeof row["agentId"] !== "string" || !SAFE_ID.test(row["agentId"])
    || !Array.isArray(permissions) || permissions.length > ALL_PERMISSIONS.length || new Set(permissions).size !== permissions.length
    || permissions.some((permission) => !ALL_PERMISSIONS.includes(permission as Permission) || PROHIBITED.has(permission as Permission))
    || !Number.isSafeInteger(row["issuedAt"]) || !Number.isSafeInteger(row["expiresAt"]) || Number(row["expiresAt"]) <= Number(row["issuedAt"])) throw new Error("invalid delegation grant");
  return Object.freeze({ grantId: row["grantId"], agentId: row["agentId"], parent, permissions: Object.freeze([...(permissions as Permission[])]), issuedAt: Number(row["issuedAt"]), expiresAt: Number(row["expiresAt"]) });
}

function captureDurableParent(value: unknown): DurableGrant["parent"] {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid delegation parent");
  const row = value as Record<string, unknown>;
  const keys = Object.keys(row).sort().join(",");
  if (keys !== "id,role" && keys !== "id,role,tenant") throw new Error("invalid delegation parent schema");
  if (typeof row["id"] !== "string" || !SAFE_ID.test(row["id"])
    || typeof row["role"] !== "string" || !(row["role"] in ROLE_PERMISSIONS)
    || (row["tenant"] !== undefined && (typeof row["tenant"] !== "string" || !SAFE_ID.test(row["tenant"])))) throw new Error("invalid delegation parent");
  return Object.freeze({ id: row["id"], role: row["role"] as Role, ...(row["tenant"] === undefined ? {} : { tenant: row["tenant"] as string }) });
}

function principalFor(grant: DurableGrant): DelegatedAgentPrincipal {
  return Object.freeze({ id: grant.agentId, kind: "agent", role: "agent", delegatedBy: grant.parent.id, grantId: grant.grantId, ...(grant.parent.tenant === undefined ? {} : { tenant: grant.parent.tenant }) });
}
function parentPrincipal(grant: DurableGrant): Principal { return { id: grant.parent.id, kind: "human", role: grant.parent.role, ...(grant.parent.tenant === undefined ? {} : { tenant: grant.parent.tenant }) }; }
