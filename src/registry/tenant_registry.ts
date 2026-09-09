/**
 * P-7 — MULTI-TENANT SKILL REGISTRY ISOLATION (first slice). The R1 KeepHub registry is a single shared store: a
 * skill published by one tenant is visible + installable by every other. In a multi-tenant deployment that is a
 * cross-tenant leak. This wraps the registry in per-tenant STRUCTURAL isolation — each tenant gets its own sub-store,
 * so one tenant's `list`/`get` never reaches another's skills (not a filter that a stray call can bypass) — with the
 * existing `CrossProjectAccessError` as a deterministic guard on any explicit cross-tenant reach (defense in depth).
 *
 * Composes the R1 `InMemoryRegistryStore` + the `ProjectRegistry`'s tenant boundary; mirrors M2's per-subject memory
 * partition for the tenant dimension. n=1 uses a single default tenant view — frictionless, behavior unchanged.
 */

import { InMemoryRegistryStore, type RegistryStore } from "./skill_registry.js";
import { DataClassifier } from "../ingest/data_classifier.js";

/** The default tenant for a single-tenant (n=1) deployment. One tenant → the isolation dimension is invisible. */
export const DEFAULT_TENANT = "keep.n1.default"; // reserved single-tenant sentinel
const SAFE_TENANT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
export class CrossTenantRegistryAccessError extends Error {
  constructor(readonly ownerTenant: string, readonly attemptedTenant: string) {
    super(`cross-tenant registry access denied: ${attemptedTenant} cannot read ${ownerTenant}`);
    this.name = "CrossTenantRegistryAccessError";
  }
}

export class TenantRegistryStore {
  /** Per-tenant sub-stores. A tenant's skills live ONLY in its own store — structural isolation, not a filter. */
  private readonly byTenant = new Map<string, InMemoryRegistryStore>();

  /** An isolated registry view for one tenant. Tenant B's view is a different store than tenant A's — no crossover. */
  forTenant(tenantId: string = DEFAULT_TENANT): RegistryStore {
    if (!SAFE_TENANT.test(tenantId)) throw new Error("tenant registry requires a safe tenant id");
    let store = this.byTenant.get(tenantId);
    if (store === undefined) {
      store = new InMemoryRegistryStore();
      this.byTenant.set(tenantId, store);
    }
    return store;
  }

  /**
   * Fetch a skill on behalf of `caller` from `owner`'s tenant. Same-tenant → the skill (or undefined); cross-tenant →
   * a deterministic CrossProjectAccessError (never a silent read across the boundary). The guard is defense-in-depth:
   * the structural partition already prevents accidental crossover; this rejects an EXPLICIT cross-tenant attempt.
   */
  getFor(caller: string, owner: string, skillId: string) {
    if (caller !== owner) throw new CrossTenantRegistryAccessError(owner, caller);
    return this.forTenant(owner).get(skillId);
  }

  /** Tenants currently holding at least one skill (for admin/ops; never exposes cross-tenant skill contents). */
  tenants(): readonly string[] {
    return [...this.byTenant.keys()];
  }
}

/**
 * GLOBAL-SCOPE DISCIPLINE guard (P-7-REVET). GLOBAL scope is visible to every tenant, so tenant-IDENTIFYING content
 * must never be ingested there — it must be PROJECT-scoped. This composes the DataClassifier (no new detector) to flag
 * identifying content that would leak across tenants if stored globally. It is a lint/warning, not a hard block: the
 * caller decides, but it can never say it wasn't told.
 */
export interface GlobalScopeCheck {
  readonly flagged: boolean;
  readonly reason?: string;
}

export function globalScopeDisciplineCheck(content: string, scope: string, classifier: DataClassifier = new DataClassifier()): GlobalScopeCheck {
  if (scope !== "global") return { flagged: false };
  const cls = classifier.classify(content);
  // Flag on DETECTED identifying content only — not the ever-present "unstructured PII possible" caveat, which would
  // over-flag every global lesson (the over-block failure mode). The caveat is noted when findings exist.
  if (cls.findings.length === 0) return { flagged: false };
  const caveat = cls.unstructuredPiiPossible ? " (a NER pass may surface more)" : "";
  return { flagged: true, reason: `tenant-identifying content (${cls.findings.length} finding(s))${caveat} must be project-scoped, not global — global scope is visible to all tenants` };
}
