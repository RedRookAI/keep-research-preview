/**
 * ProjectSession (Increment 3.5b) — the isolated per-project workspace.
 *
 * SOTA basis (2026-08-04):
 *  - Durable, per-project history you can scroll/resume is the assistant-grade UX
 *    (OpenAI/Claude/Gemini pattern); continuity comes from the stable ProjectId, not memory.
 *  - Long-horizon context uses COMPACTION + TYPED NOTES (Anthropic recommendation; arXiv
 *    2602.21351): compress old history into a structured summary that "preserves variable
 *    names, file paths, intermediate results while discarding filler" — cheap resume without
 *    replaying everything.
 *  - Conversation history at rest is "encrypted with a per-tenant key" (Claire AI 2026);
 *    here every history entry is encrypted under the project's OWN key via ProjectNamespace.
 *
 * Everything this session owns is bound to one ProjectId through its ProjectNamespace, so
 * two sessions are non-overlapping by construction — a cross-project read is not expressible
 * without throwing. Zero deps.
 */

import type { ProjectNamespace } from "./project_registry.js";
import type { ProjectId } from "./project_id.js";
import type { Ciphertext } from "../keystore/keystore.js";
import type { ProjectState } from "../autonomy/project_loop.js";
import { projectCheckpointIdentity, type ProjectCheckpointStore } from "../autonomy/project_checkpoint_store.js";
import { ProjectSessionConflictError, type PersistedCompaction, type PersistedProjectSecret, type ProjectSessionPersistence, type ProjectSessionSnapshot } from "./project_session_persistence.js";
import type { EngineeringStatusProjectionV1 } from "../spine/engineering_status_projection_v1.js";

/** Roles for a history entry — mirrors assistant transcripts + system/tool events. */
export type HistoryRole = "user" | "assistant" | "system" | "tool" | "event";

/** A single, durable history entry (stored ENCRYPTED under the project key). */
export interface HistoryEntry {
  readonly seq: number;
  readonly role: HistoryRole;
  readonly at: number;
  /** Plaintext is returned on read; at rest it is ciphertext (see StoredEntry). */
  readonly text: string;
}

/** What is actually retained at rest: metadata in the clear, PAYLOAD encrypted. */
interface StoredEntry {
  readonly seq: number;
  readonly role: HistoryRole;
  readonly at: number;
  readonly cipher: Ciphertext;
}

/**
 * A typed compaction note — the structured summary that replaces a run of old entries.
 * Preserves the load-bearing facts (paths, names, decisions, results) per the SOTA.
 */
export interface CompactionNote {
  readonly upToSeq: number;
  readonly at: number;
  readonly summary: string;
  /** Load-bearing facts extracted for cheap resume (file paths, decisions, results). */
  readonly keptFacts: readonly string[];
}

/** A function that compacts a batch of entries into a typed note (injected seam). */
export type Compactor = (entries: readonly HistoryEntry[]) => CompactionNote;

/** Budget envelope for one project (its own caps; § scheduled autonomy). */
export interface BudgetEnvelope {
  readonly dailyTokenCap?: number;
  readonly perRunStepCap?: number;
  spentTokensToday: number;
  /** Durable watermark used to reconcile append-only metering without double counting. */
  meteredTraceTokens?: number;
}
export interface ProjectDocumentValue { readonly value: string | undefined; readonly revision: number; }

const DOCUMENT_PREFIX = "keep.document.";
const MAX_DOCUMENT_BEARING_SESSION_BYTES = 32 * 1024 * 1024;

export class ProjectSession {
  readonly projectId: ProjectId;
  private readonly ns: ProjectNamespace;

  /** History at rest: encrypted payloads + a running sequence. */
  private readonly stored: StoredEntry[] = [];
  private nextSeq = 0;
  /** Typed-note compactions of older history (kept in the clear; they're already summaries). */
  private readonly notes: CompactionNote[] = [];
  private readonly persistedNotes: PersistedCompaction[] = [];
  private readonly secrets = new Map<string, Ciphertext>();

  /** The current checkpoint (which stage, artifacts, budget left) — set by the ProjectLoop. */
  private ephemeralState: ProjectState | undefined;
  private runId: string | undefined;
  private checkpointRef: import("./project_session_persistence.js").ProjectCheckpointReference | undefined;
  private persistenceRevision = 0;
  private persistenceSuperseded = false;

  /** The project's budget envelope. */
  readonly budget: BudgetEnvelope;

  constructor(
    ns: ProjectNamespace,
    budget: BudgetEnvelope = { spentTokensToday: 0 },
    private readonly persistence?: ProjectSessionPersistence,
    private readonly checkpoints?: ProjectCheckpointStore,
    private readonly writable: () => boolean = () => true,
  ) {
    this.ns = ns;
    const documentMethods = [persistence?.loadDocument, persistence?.saveDocument, persistence?.deleteDocument].filter((method) => method !== undefined).length;
    if (documentMethods !== 0 && documentMethods !== 3) throw new Error("project document persistence methods must be configured together");
    this.projectId = ns.projectId;
    const restored = persistence?.load();
    if (restored !== undefined && restored.projectId !== this.projectId) throw new Error(`project session store belongs to ${restored.projectId}, not ${this.projectId}`);
    this.budget = { ...(restored?.budget ?? budget) };
    if (restored) {
      this.persistenceRevision = restored.storageRevision;
      this.stored.push(...restored.history.map((entry) => ({ ...entry, cipher: { ...entry.cipher } })));
      for (const secret of restored.secrets) this.secrets.set(secret.name, { ...secret.cipher });
      this.persistedNotes.push(...restored.compactions.map((entry) => ({ ...entry, cipher: { ...entry.cipher } })));
      this.notes.push(...restored.compactions.map((entry) => this.decryptCompaction(entry)));
      this.nextSeq = restored.nextSeq;
      this.runId = restored.runId ?? restored.checkpointRef?.runId;
      this.checkpointRef = restored.checkpointRef;
    }
  }

  private snapshot(overrides: Partial<ProjectSessionSnapshot> = {}): ProjectSessionSnapshot {
    return {
      schemaVersion: 1,
      storageRevision: this.persistenceRevision,
      projectId: this.projectId,
      history: this.stored,
      secrets: [...this.secrets.entries()].map(([name, cipher]): PersistedProjectSecret => ({ name, cipher })),
      compactions: this.persistedNotes,
      nextSeq: this.nextSeq,
      budget: this.budget,
      ...(this.runId ? { runId: this.runId } : {}),
      ...(this.checkpointRef ? { checkpointRef: this.checkpointRef } : {}),
      ...overrides,
    };
  }

  private persist(snapshot: ProjectSessionSnapshot): void {
    if (this.persistenceSuperseded) throw new Error(`project session ${this.projectId} was superseded by a newer process and is read-only`);
    if (this.persistence !== undefined) {
      try { this.persistenceRevision = this.persistence.save(snapshot, this.persistenceRevision); }
      catch (error) {
        if (error instanceof ProjectSessionConflictError) this.persistenceSuperseded = true;
        throw error;
      }
    }
  }

  private assertWritable(): void {
    if (!this.writable()) throw new Error(`project ${this.projectId} is not writable (archived, deleted, or unavailable)`);
  }

  private assertCurrentForRead(): void {
    if (this.persistenceSuperseded) throw new Error(`project session ${this.projectId} was superseded by a newer process and cannot serve stale data`);
    const durable = this.persistence?.load();
    if (durable !== undefined && durable.storageRevision !== this.persistenceRevision) {
      this.persistenceSuperseded = true;
      throw new Error(`project session ${this.projectId} was superseded by a newer process and cannot serve stale data`);
    }
  }

  /** Persist the immutable project→run ownership edge before any project callback can execute. */
  bindRun(runId: string): void {
    this.assertWritable();
    if (typeof runId !== "string" || runId.length === 0 || Buffer.byteLength(runId, "utf8") > 1024 || /[\u0000-\u001f\u007f]/u.test(runId)) throw new Error("invalid project run binding");
    if (this.runId !== undefined && this.runId !== runId) throw new Error(`project ${this.projectId} is already bound to run ${this.runId}`);
    if (this.runId === runId) return;
    this.persist(this.snapshot({ runId }));
    this.runId = runId;
  }

  boundRunId(): string | undefined { return this.runId; }

  private decryptCompaction(entry: PersistedCompaction): CompactionNote {
    let value: unknown;
    try { value = JSON.parse(this.ns.decrypt(entry.cipher)); } catch (cause) { throw new Error("cannot authenticate persisted compaction", { cause }); }
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("invalid persisted compaction plaintext");
    const row = value as Record<string, unknown>;
    if (typeof row.summary !== "string" || Buffer.byteLength(row.summary, "utf8") > 1_000_000 || !Array.isArray(row.keptFacts)
      || row.keptFacts.length > 10_000 || row.keptFacts.some((fact) => typeof fact !== "string" || Buffer.byteLength(fact, "utf8") > 16_384)) throw new Error("invalid persisted compaction plaintext");
    return { upToSeq: entry.upToSeq, at: entry.at, summary: row.summary, keptFacts: [...row.keptFacts] as string[] };
  }

  /** Append a history entry; the payload is encrypted under the project key at rest. */
  append(role: HistoryRole, text: string, at: number = Date.now()): HistoryEntry {
    this.assertWritable();
    if (!["user", "assistant", "system", "tool", "event"].includes(role)) throw new Error("invalid history role");
    if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > 16 * 1024 * 1024) throw new RangeError("history text is oversized");
    if (!Number.isSafeInteger(at) || at < 0) throw new Error("invalid history timestamp");
    const seq = this.nextSeq;
    const entry = { seq, role, at, cipher: this.ns.encrypt(text) };
    this.persist(this.snapshot({ history: [...this.stored, entry], nextSeq: seq + 1 }));
    this.nextSeq++;
    this.stored.push(entry);
    return { seq, role, at, text };
  }

  /** Store one named project secret encrypted under this project's key. */
  putSecret(name: string, value: string): void {
    if (name.startsWith(DOCUMENT_PREFIX)) throw new Error("project document namespace is reserved");
    this.putEncryptedValue(name, value, 1024 * 1024, "project secret");
  }

  /** Store one bounded encrypted project document atomically with the rest of the session. */
  putDocument(name: string, value: string): void {
    const current = this.resolveDocumentVersioned(name);
    this.putDocumentVersioned(name, value, current.revision);
  }

  putDocumentVersioned(name: string, value: string, expectedRevision: number): number {
    this.assertWritable();
    if (!/^[A-Za-z0-9._-]{1,128}$/u.test(name) || typeof value !== "string" || value.length === 0 || Buffer.byteLength(value, "utf8") > 8 * 1024 * 1024 || !Number.isSafeInteger(expectedRevision) || expectedRevision < 0) throw new Error("invalid project document value");
    if (this.persistence?.saveDocument !== undefined && this.persistence.loadDocument !== undefined) {
      return this.persistence.saveDocument(name, this.ns.encrypt(value), expectedRevision);
    }
    if (expectedRevision !== this.persistenceRevision) throw new ProjectSessionConflictError(`project document conflict: expected ${expectedRevision}, found ${this.persistenceRevision}`);
    this.putEncryptedValue(`${DOCUMENT_PREFIX}${name}`, value, 8 * 1024 * 1024, "project document");
    return this.persistenceRevision;
  }

  private putEncryptedValue(name: string, value: string, maxBytes: number, label: string): void {
    this.assertWritable();
    if (!/^[A-Za-z0-9._-]{1,128}$/u.test(name)) throw new Error("invalid project secret name");
    if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value, "utf8") > maxBytes) throw new Error(`invalid ${label} value`);
    const next = new Map(this.secrets); next.set(name, this.ns.encrypt(value));
    const rows = [...next.entries()].map(([secretName, cipher]): PersistedProjectSecret => ({ name: secretName, cipher }));
    const nextSnapshot = this.snapshot({ secrets: rows });
    if (label === "project document" && Buffer.byteLength(JSON.stringify(nextSnapshot), "utf8") > MAX_DOCUMENT_BEARING_SESSION_BYTES) throw new Error("project document would leave insufficient durable session headroom");
    this.persist(nextSnapshot);
    this.secrets.clear(); for (const [secretName, cipher] of next) this.secrets.set(secretName, cipher);
  }

  resolveSecret(name: string): string | undefined {
    this.assertCurrentForRead();
    if (name.startsWith(DOCUMENT_PREFIX)) return undefined;
    const value = this.secrets.get(name); return value ? this.ns.decrypt(value) : undefined;
  }
  resolveDocument(name: string): string | undefined {
    return this.resolveDocumentVersioned(name).value;
  }
  resolveDocumentVersioned(name: string): ProjectDocumentValue {
    if (!/^[A-Za-z0-9._-]{1,128}$/u.test(name)) throw new Error("invalid project document name");
    if (this.persistence?.loadDocument !== undefined) {
      const document = this.persistence.loadDocument(name);
      if (document === undefined) return { value: undefined, revision: 0 };
      return { value: document.deleted ? undefined : this.ns.decrypt(document.cipher!), revision: document.storageRevision };
    }
    this.assertCurrentForRead();
    const value = this.secrets.get(`${DOCUMENT_PREFIX}${name}`); return { value: value ? this.ns.decrypt(value) : undefined, revision: this.persistenceRevision };
  }
  listSecrets(): readonly string[] { return [...this.secrets.keys()].filter((name) => !name.startsWith(DOCUMENT_PREFIX)).sort(); }
  forgetDocument(name: string): boolean {
    const current = this.resolveDocumentVersioned(name);
    return this.forgetDocumentVersioned(name, current.revision);
  }
  forgetDocumentVersioned(name: string, expectedRevision: number): boolean {
    this.assertWritable();
    if (this.persistence?.deleteDocument !== undefined && this.persistence.loadDocument !== undefined) {
      return this.persistence.deleteDocument(name, expectedRevision);
    }
    if (expectedRevision !== this.persistenceRevision) throw new ProjectSessionConflictError(`project document conflict: expected ${expectedRevision}, found ${this.persistenceRevision}`);
    const internalName = `${DOCUMENT_PREFIX}${name}`;
    if (!this.secrets.has(internalName)) return false;
    const next = new Map(this.secrets); next.delete(internalName);
    this.persist(this.snapshot({ secrets: [...next.entries()].map(([secretName, cipher]) => ({ name: secretName, cipher })) }));
    this.secrets.delete(internalName); return true;
  }
  forgetSecret(name: string): boolean {
    this.assertWritable();
    if (!this.secrets.has(name)) return false;
    const next = new Map(this.secrets); next.delete(name);
    this.persist(this.snapshot({ secrets: [...next.entries()].map(([secretName, cipher]) => ({ name: secretName, cipher })) }));
    this.secrets.delete(name); return true;
  }

  /** Read full history (decrypts each entry under the project key). Chronological. */
  history(): HistoryEntry[] {
    return this.stored.map((s) => ({
      seq: s.seq,
      role: s.role,
      at: s.at,
      text: this.ns.decrypt(s.cipher),
    }));
  }

  /** The typed-note compactions produced so far (already summaries; no decryption needed). */
  compactions(): readonly CompactionNote[] {
    return this.notes.map((note) => ({ ...note, keptFacts: [...note.keptFacts] }));
  }

  /** Number of live (un-compacted) entries currently retained. */
  liveCount(): number {
    return this.stored.length;
  }

  /**
   * Compact the oldest `count` entries into one typed note, then drop them from live
   * history. Keeps resume cheap on long projects while preserving load-bearing facts.
   * Returns the note. No-op-safe: compacting 0 or more-than-present is bounded.
   */
  compactOldest(count: number, compactor: Compactor): CompactionNote | undefined {
    this.assertWritable();
    const n = Math.min(Math.max(count, 0), this.stored.length);
    if (n === 0) return undefined;
    const batch = this.stored.slice(0, n).map((s) => ({
      seq: s.seq,
      role: s.role,
      at: s.at,
      text: this.ns.decrypt(s.cipher),
    }));
    const note = compactor(batch);
    if (!note || note.upToSeq !== batch[batch.length - 1]!.seq || !Number.isSafeInteger(note.at) || note.at < 0
      || typeof note.summary !== "string" || !Array.isArray(note.keptFacts)) throw new Error("invalid compaction result");
    const persisted = { upToSeq: note.upToSeq, at: note.at, cipher: this.ns.encrypt(JSON.stringify({ summary: note.summary, keptFacts: note.keptFacts })) };
    this.persist(this.snapshot({ history: this.stored.slice(n), compactions: [...this.persistedNotes, persisted] }));
    this.notes.push({ ...note, keptFacts: [...note.keptFacts] });
    this.persistedNotes.push(persisted);
    this.stored.splice(0, n); // drop the compacted originals from live history
    return note;
  }

  /** Save the current checkpoint (called by the ProjectLoop on each transition). */
  checkpoint(state: ProjectState, engineeringStatus?:EngineeringStatusProjectionV1): void {
    this.assertWritable();
    if (this.runId !== undefined && this.runId !== state.runId) throw new Error(`project ${this.projectId} does not own run ${state.runId}`);
    if (this.persistence !== undefined) {
      if (this.checkpoints === undefined) throw new Error("persistent sessions require the canonical checkpoint store");
      if(engineeringStatus!==undefined&&(engineeringStatus.project_id!==this.projectId||engineeringStatus.run_id!==state.runId||engineeringStatus.authoritative!==false))throw new Error("engineering status projection does not match project checkpoint");
      const expected = {...projectCheckpointIdentity(state),...(engineeringStatus?{engineeringStatusProjectionDigest:engineeringStatus.projection_digest}:{})};
      const durable = this.checkpoints.load(expected.runId);
      if (durable === undefined || !checkpointIdentityMatches(projectCheckpointIdentity(durable),expected)) throw new Error("session checkpoint does not match canonical durable state");
      try { this.persist(this.snapshot({ runId: state.runId, checkpointRef: expected })); }
      catch (error) {
        if (!(error instanceof ProjectSessionConflictError)) throw error;
        const winner = this.persistence.load();
        if (winner === undefined || winner.projectId !== this.projectId || winner.runId !== state.runId || winner.checkpointRef === undefined
          || winner.checkpointRef.revision < expected.revision || winner.checkpointRef.runId !== expected.runId) throw error;
        const winnerState = this.checkpoints.load(winner.checkpointRef.runId);
        if (winnerState === undefined || !checkpointIdentityMatches(projectCheckpointIdentity(winnerState),winner.checkpointRef)) throw error;
        this.persistenceRevision = winner.storageRevision; this.persistenceSuperseded = true;
      }
      this.runId = state.runId;
      this.checkpointRef = this.persistenceSuperseded ? this.persistence.load()?.checkpointRef ?? expected : expected;
      this.ephemeralState = undefined;
      return;
    }
    this.runId = state.runId;
    this.ephemeralState = state;
  }

  /** Restore the last checkpoint (used on switch-back — a state restore, not a replay). */
  lastCheckpoint(): ProjectState | undefined {
    if (this.checkpointRef !== undefined) {
      if (this.checkpoints === undefined) throw new Error("canonical checkpoint resolver is unavailable");
      const durable = this.checkpoints.load(this.checkpointRef.runId);
      if (durable === undefined || durable.revision < this.checkpointRef.revision) throw new Error("canonical checkpoint reference is stale or corrupt");
      if (durable.revision === this.checkpointRef.revision && !checkpointIdentityMatches(projectCheckpointIdentity(durable),this.checkpointRef)) throw new Error("canonical checkpoint reference is stale or corrupt");
      return durable;
    }
    return this.ephemeralState;
  }

  /** Record token spend against the daily cap (returns whether still within budget). */
  spend(tokens: number): boolean {
    this.assertWritable();
    if (!Number.isSafeInteger(tokens)) throw new Error("token spend must be an integer");
    const spentTokensToday = this.budget.spentTokensToday + Math.max(0, tokens);
    if (!Number.isSafeInteger(spentTokensToday)) throw new RangeError("token spend overflow");
    this.persist(this.snapshot({ budget: { ...this.budget, spentTokensToday } }));
    this.budget.spentTokensToday = spentTokensToday;
    return (
      this.budget.dailyTokenCap === undefined ||
      this.budget.spentTokensToday <= this.budget.dailyTokenCap
    );
  }

  reconcileMeteredTokens(total: number): boolean {
    this.assertWritable();
    if (!Number.isSafeInteger(total) || total < 0) throw new Error("metered token total must be a nonnegative integer");
    const prior = this.budget.meteredTraceTokens ?? 0;
    if (total <= prior) return this.withinBudget();
    const spentTokensToday = this.budget.spentTokensToday + total - prior;
    if (!Number.isSafeInteger(spentTokensToday)) throw new RangeError("token spend overflow");
    const budget = { ...this.budget, spentTokensToday, meteredTraceTokens: total };
    this.persist(this.snapshot({ budget }));
    this.budget.spentTokensToday = spentTokensToday;
    this.budget.meteredTraceTokens = total;
    return this.withinBudget();
  }

  /** True if the project is within its daily token budget. */
  withinBudget(): boolean {
    return (
      this.budget.dailyTokenCap === undefined ||
      this.budget.spentTokensToday <= this.budget.dailyTokenCap
    );
  }
}

function checkpointIdentityMatches(actual:{readonly runId:string;readonly revision:number;readonly sha256:string},expected:{readonly runId:string;readonly revision:number;readonly sha256:string}):boolean{return actual.runId===expected.runId&&actual.revision===expected.revision&&actual.sha256===expected.sha256;}
