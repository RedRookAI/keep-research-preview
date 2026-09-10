/**
 * Owns project sessions and tenant-local foreground selection. Selection changes
 * presentation/lifecycle only: it does not execute, resume, summarize history, or
 * grant authority/budget. Checkpoints remain bound to their original runs.
 *
 * Registry selection is one revision-checked record replacement. Session compaction
 * is an explicit, separate operation; it is not atomic with foreground selection.
 * Transport callers must authenticate and authorize the selected project separately.
 */

import { ProjectRegistry, type ProjectRecord } from "./project_registry.js";
import { ProjectSession, ProjectSessionUnavailableError, type BudgetEnvelope, type Compactor } from "./project_session.js";
import type { ProjectId } from "./project_id.js";
import { ProjectSessionConflictError, ProjectSessionReadError, validateProjectBudget, type ProjectSessionPersistence } from "./project_session_persistence.js";
import type { ProjectCheckpointStore } from "../autonomy/project_checkpoint_store.js";

/** Options when creating a project. */
export interface CreateOptions {
  readonly name: string;
  readonly budget?: BudgetEnvelope;
  readonly tenant?: string;
}

/** A default typed-note compactor: keeps role/seq structure, drops filler. Swappable. */
export const defaultCompactor: Compactor = (entries) => {
  const upToSeq = entries.length ? entries[entries.length - 1]!.seq : -1;
  const keptFacts = entries
    .filter((e) => e.role === "user" || e.role === "assistant" || e.role === "tool" || e.role === "event")
    .map((e) => `[${e.role}#${e.seq}] ${e.text.slice(0, 200)}`);
  return {
    upToSeq,
    at: Date.now(),
    summary: `Compacted ${entries.length} entries (seq 0..${upToSeq}).`,
    keptFacts,
  };
};

export class ProjectSessionManager {
  private readonly sessions = new Map<ProjectId, ProjectSession>();
  private readonly quarantined = new Map<ProjectId, Error>();

  /**
   * @param registry the cryptographic-namespacing registry (owns identity + per-project keys)
   * @param compactor used only by explicit compact(), never implicitly by switch()
   */
  constructor(
    private readonly registry: ProjectRegistry,
    private readonly compactor: Compactor = defaultCompactor,
    private readonly persistenceForProject?: (id: ProjectId) => ProjectSessionPersistence | undefined,
    private readonly checkpoints?: ProjectCheckpointStore,
  ) {
    const records = registry.list();
    for (const record of records) this.restore(record.id);
    // Loading does not rewrite tenant selections, including legacy duplicate active rows.
    // An explicit switch normalizes the selected tenant; quarantine remains inspectable.
  }

  /** Commit initial state and identity, without activation. A failed local restore is quarantined. */
  create(opts: CreateOptions): ProjectRecord {
    // A newly durable project is parked first. A crash before switch cannot create two
    // authoritative foreground records.
    const budget = validateProjectBudget(opts.budget ?? { spentTokensToday: 0 });
    let persistence: ProjectSessionPersistence | undefined;
    const rec = this.registry.create(opts.name, "background", opts.tenant, record => {
      persistence = this.persistenceForProject?.(record.id);
      // No namespace is available until record publication. Empty state contains no
      // ciphertext; use the existing validated snapshot writer before that publication.
      persistence?.save({ schemaVersion: 1, storageRevision: 0, projectId: record.id,
        history: [], secrets: [], compactions: [], nextSeq: 0, budget }, undefined);
    });
    try {
      const ns = this.registry.namespace(rec.id);
      this.sessions.set(rec.id, new ProjectSession(ns, budget, persistence, this.checkpoints,
        () => ["active", "background"].includes(this.registry.lifecycle(rec.id) ?? ""), persistence !== undefined));
    } catch (error) {
      // The registry commit already succeeded. Return its identity for inspection,
      // while retaining the load failure as a hold on session access/execution.
      this.quarantined.set(rec.id, error instanceof Error ? error : new Error("created project session restore failed"));
    }
    return rec;
  }

  /** Restore a current object; a superseded prior reference stays fenced, never rebased. */
  private restore(id: ProjectId): void {
    const cached = this.sessions.get(id);
    if (cached !== undefined) {
      try { cached.assertCurrent(); return; }
      catch (error) {
        this.sessions.delete(id);
        if (!(error instanceof ProjectSessionConflictError)) {
          this.quarantined.set(id, error instanceof Error ? error : new Error("project session currentness check failed"));
          // Hold this lookup. Only a later lookup may reload after an I/O failure;
          // never retry here or revive the fenced cached object.
          return;
        }
      }
    }
    const previous = this.quarantined.get(id);
    if (previous !== undefined && !(previous instanceof ProjectSessionUnavailableError) && !(previous instanceof ProjectSessionReadError)) return;
    try {
      const persistence = this.persistenceForProject?.(id);
      this.sessions.set(id, new ProjectSession(this.registry.namespace(id), undefined,
        persistence, this.checkpoints,
        () => ["active", "background"].includes(this.registry.lifecycle(id) ?? ""), persistence !== undefined));
      this.quarantined.delete(id);
    } catch (error) {
      // Missing/unreadable state may later recover. Malformed/authentication failures
      // stay quarantined until reconstruction; no failure grants default state.
      this.quarantined.set(id, error instanceof Error ? error : new Error("project session restore failed"));
    }
  }

  /** All non-deleted projects. */
  list(): readonly ProjectRecord[] {
    return this.registry.list();
  }

  /** The session for a project (throws if unknown/deleted — never silently wrong-namespace). */
  session(id: ProjectId): ProjectSession {
    const projectId = this.registry.get(id).id;
    this.restore(projectId);
    const quarantined = this.quarantined.get(projectId);
    if (quarantined instanceof ProjectSessionUnavailableError) throw quarantined;
    if (quarantined instanceof ProjectSessionReadError) throw quarantined;
    if (quarantined !== undefined) throw new Error(`project ${projectId} is quarantined: ${quarantined.message}`, { cause: quarantined });
    const s = this.sessions.get(projectId);
    if (!s) throw new Error(`no live session for project ${id}`);
    return s;
  }

  /** Archived projects remain inspectable but cannot be admitted for execution. */
  runnableSession(id: ProjectId): ProjectSession {
    const record = this.registry.get(id);
    if (record.lifecycle === "archived") throw new Error(`project ${id} is archived and read-only`);
    return this.session(record.id);
  }

  lifecycle(id: ProjectId): import("./project_registry.js").ProjectLifecycle | undefined { return this.registry.lifecycle(id); }
  /** Includes unavailable snapshots so metadata consumers never assume a live session. */
  quarantine(id: ProjectId): string | undefined {
    this.registry.get(id);
    this.restore(id);
    return this.quarantined.get(id)?.message;
  }

  /** First healthy active row in durable order, scoped explicitly; undefined means personal. */
  active(tenant: string | undefined): ProjectId | undefined {
    return this.registry.list().find(record => {
      if (record.tenant !== tenant || record.lifecycle !== "active") return false;
      try { return this.quarantine(record.id) === undefined; }
      catch (error) {
        // Selection reads are not locked against a sibling deletion. A vanished
        // row cannot be selected; an unrelated store failure must still surface.
        if (!this.registry.has(record.id)) return false;
        throw error;
      }
    })?.id;
  }

  /**
   * Switch foreground within the target's tenant. History and execution stay untouched.
   * Re-selecting the unique active project is a no-op; legacy siblings are normalized.
   */
  switch(id: ProjectId): {
    outgoing?: ProjectId;
    incoming: ProjectId;
  } {
    const incoming = this.runnableSession(id).projectId;
    return this.registry.setForeground(incoming);
  }

  /** Explicit history summarization. May discard detail; never implied by project selection. */
  compact(id: ProjectId, count: number): ReturnType<ProjectSession["compactOldest"]> {
    if (!Number.isSafeInteger(count) || count < 0) throw new Error("explicit nonnegative compaction count required");
    const session = this.runnableSession(id);
    return session.compactOldest(count, this.compactor);
  }

  /** Move a project to the background (keeps its session + checkpoint; may run in-envelope). */
  background(id: ProjectId): void {
    const projectId = this.runnableSession(id).projectId;
    this.registry.setLifecycle(projectId, "background");
  }

  /** Archive a project (read-only; session retained but not runnable). */
  archive(id: ProjectId): void {
    const rec = this.registry.get(id);
    this.registry.setLifecycle(rec.id, "archived");
  }

  /**
   * Delete a project: crypto-shred its key (registry) and drop its session. Data encrypted
   * under that key becomes unrecoverable; OTHER projects are unaffected (bit-identical).
   */
  delete(id: ProjectId): void {
    const lifecycle = this.registry.lifecycle(id);
    if (lifecycle === undefined) throw new Error(`no such project: ${id}`);
    this.registry.remove(id); // crypto-shred + mark deleted (audited); retries tombstoned shreds.
    this.sessions.delete(id);
    this.quarantined.delete(id);
  }
}
