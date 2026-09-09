/**
 * ProjectSessionManager (Increment 3.5c) — the outer runtime.
 *
 * SOTA basis (2026-08-04): "the outer runtime owns approvals/tracing/resume; the session
 * owns its files/commands/state" (Edge of Context 2026). Switching is a CHECKPOINT RESTORE,
 * not a chat replay: "define the state machine, persist the checkpoints, sleep through the
 * idle time, and wake up exactly where you left off" (Google ADK, Aug 2026). One
 * workspace/session per project (Augment Code): "pause, switch contexts, or hand off
 * instantly."
 *
 * Responsibilities:
 *   - create / list / switch / archive / delete projects (delete = crypto-shred via registry);
 *   - hold which project is ACTIVE (foreground) vs BACKGROUND (may keep running in-envelope);
 *   - switch(): compact + checkpoint the outgoing session (never lose state), keep it running
 *     in the background if it had an active envelope, restore the incoming from its checkpoint.
 *
 * Isolation is inherited: every ProjectSession is built from the registry's per-project
 * ProjectNamespace, so the manager cannot hand one project a handle into another. Zero deps.
 */

import { ProjectRegistry, type ProjectRecord } from "./project_registry.js";
import { ProjectSession, type BudgetEnvelope, type Compactor } from "./project_session.js";
import type { ProjectId } from "./project_id.js";
import type { ProjectSessionPersistence } from "./project_session_persistence.js";
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
    .filter((e) => e.role === "assistant" || e.role === "tool" || e.role === "event")
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
  private activeId: ProjectId | undefined = undefined;

  /**
   * @param registry the cryptographic-namespacing registry (owns identity + per-project keys)
   * @param compactor how outgoing history is compacted on switch (injected; defaults provided)
   */
  constructor(
    private readonly registry: ProjectRegistry,
    private readonly compactor: Compactor = defaultCompactor,
    private readonly persistenceForProject?: (id: ProjectId) => ProjectSessionPersistence | undefined,
    private readonly checkpoints?: ProjectCheckpointStore,
  ) {
    const records = registry.list();
    const active = records.filter((record) => record.lifecycle === "active");
    for (const record of records) {
      try {
        this.sessions.set(record.id, new ProjectSession(
          this.registry.namespace(record.id),
          undefined,
          this.persistenceForProject?.(record.id),
          this.checkpoints,
          () => ["active", "background"].includes(this.registry.lifecycle(record.id) ?? ""),
        ));
      } catch (error) {
        this.quarantined.set(record.id, error instanceof Error ? error : new Error("project session restore failed"));
      }
    }
    const selected = active.find((record) => !this.quarantined.has(record.id));
    for (const record of active) if (record.id !== selected?.id) this.registry.setLifecycle(record.id, "background");
    this.activeId = selected?.id;
  }

  /** Create a project (registry mints id + key) and its isolated session. Does NOT auto-activate. */
  create(opts: CreateOptions): ProjectRecord {
    // A newly durable project is parked first. A crash before switch cannot create two
    // authoritative foreground records.
    const rec = this.registry.create(opts.name, "background", opts.tenant);
    const ns = this.registry.namespace(rec.id);
    this.sessions.set(rec.id, new ProjectSession(ns, opts.budget, this.persistenceForProject?.(rec.id), this.checkpoints, () => ["active", "background"].includes(this.registry.lifecycle(rec.id) ?? "")));
    return rec;
  }

  /** All non-deleted projects. */
  list(): readonly ProjectRecord[] {
    return this.registry.list();
  }

  /** The session for a project (throws if unknown/deleted — never silently wrong-namespace). */
  session(id: ProjectId): ProjectSession {
    const projectId = this.registry.get(id).id;
    const quarantined = this.quarantined.get(projectId);
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
  quarantine(id: ProjectId): string | undefined { return this.quarantined.get(id)?.message; }

  /** The currently-active (foreground) project id, if any. */
  active(): ProjectId | undefined {
    return this.activeId;
  }

  /**
   * Switch the foreground to `id`.
   *  1. Compact + checkpoint the OUTGOING session (nothing lost). If it had an active
   *     envelope it becomes BACKGROUND (keeps running autonomously); else it stays put.
   *  2. Restore the INCOMING from its last checkpoint (a state restore, sub-second).
   * @param compactOutgoingOver only compact if the outgoing session has more than this many
   *        live entries (avoid churning tiny sessions). Default 0 = always compact something.
   */
  switch(id: ProjectId, opts: { keepOutgoingInBackground?: boolean; compactOutgoingOver?: number } = {}): {
    outgoing?: ProjectId;
    incoming: ProjectId;
  } {
    const record = this.registry.get(id);
    if (record.lifecycle === "archived") throw new Error(`project ${id} is archived and read-only`);
    const incoming = record.id;
    const outgoing = this.activeId;

    // Durable state outranks this process's cached foreground pointer. This also repairs an
    // active record whose session was quarantined during a prior boot.
    for (const candidate of this.registry.list()) {
      if (candidate.id !== incoming && candidate.lifecycle === "active") this.registry.setLifecycle(candidate.id, "background");
    }

    if (outgoing && outgoing !== incoming) {
      const out = this.sessions.get(outgoing);
      if (out) {
        const threshold = opts.compactOutgoingOver ?? 0;
        if (out.liveCount() > threshold) {
          out.compactOldest(out.liveCount(), this.compactor);
        }
        // Outgoing keeps its checkpoint (already saved by the loop); mark background if requested.
        this.registry.setLifecycle(
          outgoing,
          "background",
        );
        this.activeId = undefined;
      }
    }

    // Restore incoming: bring it to foreground. Its ProjectSession already holds the last
    // checkpoint; nothing to replay. (The loop resumes FROM session.lastCheckpoint().)
    this.registry.setLifecycle(incoming, "active");
    this.activeId = incoming;
    return outgoing && outgoing !== incoming ? { outgoing, incoming } : { incoming };
  }

  /** Move a project to the background (keeps its session + checkpoint; may run in-envelope). */
  background(id: ProjectId): void {
    const rec = this.registry.get(id);
    this.registry.setLifecycle(rec.id, "background");
    if (this.activeId === rec.id) this.activeId = undefined;
  }

  /** Archive a project (read-only; session retained but not runnable). */
  archive(id: ProjectId): void {
    const rec = this.registry.get(id);
    this.registry.setLifecycle(rec.id, "archived");
    if (this.activeId === rec.id) this.activeId = undefined;
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
    if (this.activeId === id) this.activeId = undefined;
  }
}
