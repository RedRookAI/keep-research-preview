/**
 * ProjectRegistry (Increment 3.5a) — the cryptographic-namespacing enforcer.
 *
 * SOTA basis (re-verified 2026-08-14): the winning multi-tenant isolation pattern is
 * tiered defense-in-depth with **per-tenant encryption keys** as the gold standard
 * (Claire AI, Blaxel 2026 — both VERIFIED): "each tenant's data encrypted with their own
 * key; if one key is compromised, only one is affected." Isolation must be DETERMINISTIC
 * and enforced in code below the model — "relying on LLMs for access control is an
 * architectural anti-pattern". Crypto-shred (destroy the per-project key) gives the
 * clean-delete property (Blaxel: "destroying the KEK renders tenant data cryptographically
 * inaccessible").
 *
 * PERSISTENT-SEAM REQUIREMENT (honest, S-11): this in-memory cryptographic namespacing is the
 * APP-LAYER control. It is necessary but NOT sufficient for a persistent backing store: per
 * Blaxel, "for agent workloads where queries are LLM-generated, database-level RLS is
 * mandatory — application-layer filtering can't guarantee every dynamic query includes the
 * correct tenant filter." So the persistent tenant store MUST add DB-level ROW-LEVEL SECURITY
 * (RLS, force-enabled so even the table owner can't bypass) + per-tenant KEK envelope
 * encryption. GLOBAL-SCOPE DISCIPLINE: tenant-identifying content must be PROJECT-scoped, never
 * ingested at GLOBAL scope (global is visible to all tenants) — see globalScopeDisciplineCheck.
 *
 * This registry is the single place that:
 *   - records which projects exist (id, name, lifecycle, timestamps);
 *   - guarantees each project has its own encryption key (via CryptoShredKeyStore);
 *   - hands out a NAMESPACER that binds every derived key to one ProjectId, so a
 *     cross-project access is impossible to express without throwing;
 *   - performs clean offboarding = crypto-shred the project's key.
 *
 * It NEVER asks a model anything. Zero deps beyond the existing keystore.
 */

import { CryptoShredKeyStore, type Ciphertext } from "../keystore/keystore.js";
import { mintProjectId, asProjectId, type ProjectId } from "./project_id.js";
import type { ProjectRecordStore } from "./project_record_store.js";

/** Lifecycle of a project. active/background can run; archived is read-only; deleted is shredded. */
export type ProjectLifecycle = "active" | "background" | "archived" | "deleted";

/** Immutable-ish record of a project (name + lifecycle are mutable; id + createdAt are not). */
export interface ProjectRecord {
  readonly id: ProjectId;
  /** Owning enterprise tenant. Absent is the zero-configuration personal deployment. */
  readonly tenant?: string;
  name: string;
  lifecycle: ProjectLifecycle;
  readonly createdAt: number;
  updatedAt: number;
}

/**
 * A namespacer bound to exactly ONE project. Every storage/cache/log key in the system
 * goes through `key()`, which prefixes with the ProjectId — so two projects can never
 * collide on a cache key or a store key (a named 2026 leakage vector: cache-key collisions).
 * `encrypt`/`decrypt` use the project's OWN key, so data at rest is cryptographically siloed.
 */
export interface ProjectNamespace {
  readonly projectId: ProjectId;
  /** Namespace an arbitrary logical key under this project. Deterministic, collision-free. */
  key(logicalKey: string): string;
  /** Encrypt plaintext under THIS project's key (per-project encryption). */
  encrypt(plaintext: string): Ciphertext;
  /** Decrypt ciphertext under THIS project's key. Throws if the project was crypto-shredded. */
  decrypt(c: Ciphertext): string;
  /** Domain-separated pseudonym that becomes unlinkable when this project's key is shredded. */
  pseudonym(domain: string, value: string): string;
}

/** Thrown when code attempts to cross a project boundary. Deterministic, not model-mediated. */
export class CrossProjectAccessError extends Error {
  constructor(
    readonly ownerProject: ProjectId,
    readonly attemptedProject: ProjectId,
  ) {
    super(
      `cross-project access denied: a namespace for ${ownerProject} was used to touch ${attemptedProject}`,
    );
    this.name = "CrossProjectAccessError";
  }
}

export class ProjectRegistry {
  private readonly records = new Map<ProjectId, ProjectRecord>();
  private revision: number | undefined;

  /**
   * @param keys the shared CryptoShredKeyStore; each ProjectId becomes a key SUBJECT, so
   *             per-project keys + crypto-shred delete come for free and stay auditable.
   */
  constructor(
    private readonly keys: CryptoShredKeyStore,
    private readonly store?: ProjectRecordStore,
  ) {
    const snapshot = store?.load() ?? { revision: 0, records: [] };
    this.revision = snapshot.revision;
    const durableRecords = snapshot.records;
    // The durable tombstone is the deletion commit point. Finish an interrupted crypto-shred
    // before exposing any registry operation in this process.
    for (const record of durableRecords) {
      if (record.lifecycle === "deleted") this.keys.shred(record.id);
    }
    for (const record of durableRecords) {
      this.records.set(record.id, { ...record });
      if (record.lifecycle !== "deleted") this.keys.ensureKey(record.id);
    }
  }

  private persist(replacement: Map<ProjectId, ProjectRecord>): void {
    if (this.store !== undefined) this.revision = this.store.save([...replacement.values()].map((record) => ({ ...record })), this.revision);
  }

  private refresh(): void {
    if (this.store === undefined) return;
    const snapshot = this.store.load();
    if (snapshot.revision === this.revision) return;
    this.keys.refresh();
    // A sibling may have committed a tombstone and then failed before destroying its wrapped
    // key. Finish that transaction before publishing the new revision in memory; if destruction
    // fails, the next refresh must retry rather than short-circuiting on a consumed revision.
    for (const record of snapshot.records) if (record.lifecycle === "deleted") this.keys.shred(record.id);
    this.records.clear();
    for (const record of snapshot.records) this.records.set(record.id, { ...record });
    this.revision = snapshot.revision;
  }

  private replace(record: ProjectRecord): void {
    const replacement = new Map(this.records);
    replacement.set(record.id, { ...record });
    this.persist(replacement);
    this.records.clear();
    for (const [id, value] of replacement) this.records.set(id, value);
  }

  /** Prepare required state before publishing the record. The callback has no live namespace yet. */
  create(name: string, lifecycle: Exclude<ProjectLifecycle, "deleted"> = "active", tenant?: string,
    prepare?: (record: Readonly<ProjectRecord>) => void): ProjectRecord {
    if (typeof name !== "string" || name.length === 0 || Buffer.byteLength(name, "utf8") > 4_096 || /[\u0000-\u001f\u007f]/u.test(name)) {
      throw new Error("invalid project name");
    }
    if (tenant !== undefined && (typeof tenant !== "string" || tenant.length === 0 || Buffer.byteLength(tenant, "utf8") > 256 || /[\u0000-\u001f\u007f]/u.test(tenant))) throw new Error("invalid project tenant");
    const id = mintProjectId();
    this.keys.ensureKey(id); // per-project encryption key (SubjectId = ProjectId)
    const now = Date.now();
    const rec: ProjectRecord = { id, name, lifecycle, createdAt: now, updatedAt: now, ...(tenant === undefined ? {} : { tenant }) };
    const expectedRevision = this.revision;
    try {
      prepare?.({ ...rec });
      lifecycle === "active" ? this.commitForeground(rec) : this.replace(rec);
    }
    catch (error) {
      // A save error can follow a committed rename. Never compensate by destroying
      // a key while the corresponding project may already be visible to another reader.
      let confirmedAbsent = this.store === undefined && !this.records.has(id);
      if (this.store !== undefined) {
        try {
          const observed = this.store.load();
          confirmedAbsent = observed.revision === expectedRevision && !observed.records.some(record => record.id === id);
        } catch { /* unavailable reconciliation is unknown, not authority to shred */ }
      }
      if (confirmedAbsent) {
        try { this.keys.shred(id); }
        catch (cleanupError) { throw new AggregateError([error, cleanupError], "project creation and key cleanup could not be confirmed"); }
      }
      throw error;
    }
    return { ...rec };
  }

  /** List all non-deleted projects (deleted ones are shredded and hidden). */
  list(): readonly ProjectRecord[] {
    this.refresh();
    return [...this.records.values()].filter((r) => r.lifecycle !== "deleted").map((record) => ({ ...record }));
  }

  /** Fetch a project record or throw (unknown/foreign id must never silently pass). */
  get(id: ProjectId): ProjectRecord {
    this.refresh();
    const rec = this.records.get(asProjectId(id));
    if (!rec || rec.lifecycle === "deleted") throw new Error(`no such project: ${id}`);
    return { ...rec };
  }

  has(id: ProjectId): boolean {
    this.refresh();
    const rec = this.records.get(id);
    return !!rec && rec.lifecycle !== "deleted";
  }

  /** Durable lifecycle, including hidden deletion tombstones used for restart reconciliation. */
  lifecycle(id: ProjectId): ProjectLifecycle | undefined {
    this.refresh();
    return this.records.get(id)?.lifecycle;
  }

  /** Rename (label change only; the ProjectId is immutable). */
  rename(id: ProjectId, name: string): void {
    const rec = this.get(id);
    if (typeof name !== "string" || name.length === 0 || Buffer.byteLength(name, "utf8") > 4_096 || /[\u0000-\u001f\u007f]/u.test(name)) {
      throw new Error("invalid project name");
    }
    this.replace({ ...rec, name, updatedAt: Date.now() });
  }

  /** Promote through tenant selection or park/archive. Archived state cannot be reactivated here. */
  setLifecycle(id: ProjectId, lifecycle: Exclude<ProjectLifecycle, "deleted">): void {
    if (lifecycle === "active") { this.setForeground(id); return; }
    const rec = this.get(id);
    if (rec.lifecycle === "archived" && lifecycle === "background") throw new Error(`project ${id} is archived and read-only`);
    this.replace({ ...rec, lifecycle, updatedAt: Date.now() });
  }

  /** Select within the target's tenant, committing sibling demotion and promotion together. */
  setForeground(id: ProjectId): { outgoing?: ProjectId; incoming: ProjectId } {
    const target = this.get(id);
    if (target.lifecycle === "archived") throw new Error(`project ${id} is archived and read-only`);
    return this.commitForeground(target);
  }

  /** Both creation and later promotion use the same complete-record commit. */
  private commitForeground(target: ProjectRecord): { outgoing?: ProjectId; incoming: ProjectId } {
    const active = [...this.records.values()].filter(record => record.tenant === target.tenant && record.lifecycle === "active");
    const outgoing = active[0]?.id;
    if (active.length === 1 && outgoing === target.id) return { incoming: target.id };
    const replacement = new Map(this.records);
    const now = Date.now();
    for (const record of active) {
      if (record.id !== target.id) replacement.set(record.id, { ...record, lifecycle: "background", updatedAt: now });
    }
    replacement.set(target.id, target.lifecycle === "active" ? { ...target } : { ...target, lifecycle: "active", updatedAt: now });
    // No session callbacks or separate demotion writes in this revision-checked commit.
    this.persist(replacement);
    this.records.clear();
    for (const [projectId, record] of replacement) this.records.set(projectId, record);
    return outgoing !== undefined && outgoing !== target.id ? { outgoing, incoming: target.id } : { incoming: target.id };
  }

  /**
   * Return a namespacer bound to this project. This is the ONLY sanctioned way to derive
   * storage/cache/log keys or encrypt/decrypt project data — so isolation is enforced by
   * construction rather than by discipline.
   */
  namespace(id: ProjectId): ProjectNamespace {
    const rec = this.get(id); // throws if unknown/deleted
    const projectId = rec.id;
    const keys = this.keys;
    const registry = this;
    return {
      projectId,
      key(logicalKey: string): string {
        return `${projectId}::${logicalKey}`;
      },
      encrypt(plaintext: string): Ciphertext {
        registry.get(projectId);
        return keys.encrypt(projectId, plaintext);
      },
      decrypt(c: Ciphertext): string {
        registry.get(projectId);
        return keys.decrypt(projectId, c);
      },
      pseudonym(domain: string, value: string): string {
        registry.get(projectId);
        return keys.pseudonym(projectId, domain, value);
      },
    };
  }

  /**
   * Assert that a namespaced key belongs to `owner`. Any storage layer can call this to
   * make a cross-project access throw deterministically (defense in depth on top of the
   * namespacer). Parses the ProjectId prefix off a namespaced key and compares.
   */
  assertOwnership(owner: ProjectId, namespacedKey: string): void {
    const sep = namespacedKey.indexOf("::");
    const keyProject = sep >= 0 ? namespacedKey.slice(0, sep) : "";
    if (keyProject !== owner) {
      throw new CrossProjectAccessError(owner, (keyProject || "<none>") as ProjectId);
    }
  }

  /**
   * Clean offboarding = crypto-shred the project's key. Data encrypted under it becomes
   * cryptographically unrecoverable (the SOTA-praised clean-delete property), WITHOUT
   * needing to locate and scrub every byte. The audit trail (spine) survives via the
   * keystore's two-phase erasure auditor. Other projects are bit-identical afterward.
   */
  remove(id: ProjectId): void {
    this.refresh();
    const rec = this.records.get(asProjectId(id));
    if (!rec) throw new Error(`no such project: ${id}`);
    // Persist the tombstone before the irreversible effect. Restart completes a shred that
    // was interrupted after this durable point. Repeating remove on that tombstone retries only
    // the shred and cannot rewrite or weaken the already-committed deletion authority.
    if (rec.lifecycle !== "deleted") this.replace({ ...rec, name: "<erased>", lifecycle: "deleted", updatedAt: Date.now() });
    this.keys.shred(rec.id); // irreversible; audited by the keystore
  }
}
