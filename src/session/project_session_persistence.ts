import { closeSync, existsSync, fsyncSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";

import type { Ciphertext } from "../keystore/keystore.js";
import { ensureDurableDir, fsyncDir, NODE_IO } from "../spine/durable_fs.js";
import { withSyncFileMutationLock } from "../spine/sync_file_mutation_lock.js";
import { asProjectId, type ProjectId } from "./project_id.js";
import type { BudgetEnvelope, HistoryRole } from "./project_session.js";

export interface PersistedSessionEntry { readonly seq: number; readonly role: HistoryRole; readonly at: number; readonly cipher: Ciphertext; }
export interface PersistedProjectSecret { readonly name: string; readonly cipher: Ciphertext; }
export interface PersistedCompaction { readonly upToSeq: number; readonly at: number; readonly cipher: Ciphertext; }
export interface ProjectCheckpointReference { readonly runId: string; readonly revision: number; readonly sha256: string; readonly engineeringStatusProjectionDigest?: string; }
export interface ProjectSessionSnapshot {
  readonly schemaVersion: 1;
  readonly storageRevision: number;
  readonly projectId: ProjectId;
  readonly history: readonly PersistedSessionEntry[];
  readonly secrets: readonly PersistedProjectSecret[];
  readonly compactions: readonly PersistedCompaction[];
  readonly nextSeq: number;
  readonly budget: BudgetEnvelope;
  /** Stable ownership link only; checkpoint content remains exclusively in ProjectCheckpointStore. */
  readonly runId?: string;
  readonly checkpointRef?: ProjectCheckpointReference;
}
export interface PersistedProjectDocument { readonly schemaVersion: 1; readonly storageRevision: number; readonly name: string; readonly deleted: boolean; readonly cipher?: Ciphertext; }
export interface ProjectSessionPersistence {
  load(): ProjectSessionSnapshot | undefined;
  save(snapshot: ProjectSessionSnapshot, expectedRevision: number): number;
  loadDocument?(name: string): PersistedProjectDocument | undefined;
  saveDocument?(name: string, value: Ciphertext, expectedRevision: number): number;
  deleteDocument?(name: string, expectedRevision: number): boolean;
}
export class ProjectSessionConflictError extends Error { override readonly name = "ProjectSessionConflictError"; }

const roles = new Set<HistoryRole>(["user", "assistant", "system", "tool", "event"]);
const MAX_SESSION_BYTES = 64 * 1024 * 1024;
const MAX_DOCUMENT_BYTES = 20 * 1024 * 1024;
const MAX_ENTRIES = 100_000;

function object(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`invalid ${label}`);
  return value as Record<string, unknown>;
}
function exact(value: Record<string, unknown>, required: readonly string[], optional: readonly string[], label: string): void {
  const allowed = new Set([...required, ...optional]);
  if (required.some((key) => !(key in value)) || Object.keys(value).some((key) => !allowed.has(key))) throw new Error(`invalid ${label} fields`);
}
function uint(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new Error(`invalid ${label}`);
  return value as number;
}
function cipher(value: unknown): Ciphertext {
  const row = object(value, "session ciphertext");
  exact(row, ["iv", "authTag", "data"], [], "session ciphertext");
  if (typeof row.iv !== "string" || !/^[0-9a-f]{24}$/iu.test(row.iv)
    || typeof row.authTag !== "string" || !/^[0-9a-f]{32}$/iu.test(row.authTag)
    || typeof row.data !== "string" || !/^[0-9a-f]*$/iu.test(row.data)) throw new Error("invalid session ciphertext encoding");
  return row as unknown as Ciphertext;
}

function persistedCipher(value: Ciphertext): Ciphertext {
  return { iv: value.iv, authTag: value.authTag, data: value.data };
}
function budget(value: unknown): BudgetEnvelope {
  const row = object(value, "session budget");
  exact(row, ["spentTokensToday"], ["dailyTokenCap", "perRunStepCap", "meteredTraceTokens"], "session budget");
  return {
    spentTokensToday: uint(row.spentTokensToday, "spentTokensToday"),
    ...(Object.hasOwn(row, "dailyTokenCap") ? { dailyTokenCap: uint(row.dailyTokenCap, "dailyTokenCap") } : {}),
    ...(Object.hasOwn(row, "perRunStepCap") ? { perRunStepCap: uint(row.perRunStepCap, "perRunStepCap") } : {}),
    ...(Object.hasOwn(row, "meteredTraceTokens") ? { meteredTraceTokens: uint(row.meteredTraceTokens, "meteredTraceTokens") } : {}),
  };
}

export function validateProjectSessionSnapshot(value: unknown): ProjectSessionSnapshot {
  const root = object(value, "project session snapshot");
  exact(root, ["schemaVersion", "projectId", "history", "secrets", "compactions", "nextSeq", "budget"], ["storageRevision", "runId", "checkpointRef"], "project session snapshot");
  if (root.schemaVersion !== 1) throw new Error("unsupported project session schema");
  const projectId = asProjectId(String(root.projectId));
  const nextSeq = uint(root.nextSeq, "session nextSeq");
  if (!Array.isArray(root.history) || root.history.length > MAX_ENTRIES) throw new Error("invalid session history");
  let previous = -1;
  const history = root.history.map((value, index): PersistedSessionEntry => {
    const row = object(value, `history entry ${index}`); exact(row, ["seq", "role", "at", "cipher"], [], `history entry ${index}`);
    const seq = uint(row.seq, `history sequence ${index}`);
    if (seq <= previous || seq >= nextSeq) throw new Error("invalid session history sequence");
    previous = seq;
    if (!roles.has(row.role as HistoryRole)) throw new Error("invalid session history role");
    return { seq, role: row.role as HistoryRole, at: uint(row.at, "history timestamp"), cipher: cipher(row.cipher) };
  });
  if (!Array.isArray(root.secrets) || root.secrets.length > MAX_ENTRIES) throw new Error("invalid project secrets");
  const names = new Set<string>();
  const secrets = root.secrets.map((value, index): PersistedProjectSecret => {
    const row = object(value, `project secret ${index}`); exact(row, ["name", "cipher"], [], `project secret ${index}`);
    if (typeof row.name !== "string" || !/^[A-Za-z0-9._-]{1,128}$/u.test(row.name) || names.has(row.name)) throw new Error("invalid project secret name");
    names.add(row.name); return { name: row.name, cipher: cipher(row.cipher) };
  });
  if (!Array.isArray(root.compactions) || root.compactions.length > MAX_ENTRIES) throw new Error("invalid session compactions");
  const compactions = root.compactions.map((value, index): PersistedCompaction => {
    const row = object(value, `compaction ${index}`); exact(row, ["upToSeq", "at", "cipher"], [], `compaction ${index}`);
    const upToSeq = uint(row.upToSeq, "compaction sequence");
    if (upToSeq >= nextSeq) throw new Error("invalid compaction sequence");
    return { upToSeq, at: uint(row.at, "compaction timestamp"), cipher: cipher(row.cipher) };
  });
  let checkpointRef: ProjectCheckpointReference | undefined;
  if ("checkpointRef" in root) {
    const row = object(root.checkpointRef, "checkpoint reference"); exact(row, ["runId", "revision", "sha256"], ["engineeringStatusProjectionDigest"], "checkpoint reference");
    if (typeof row.runId !== "string" || row.runId.length === 0 || Buffer.byteLength(row.runId, "utf8") > 1024 || typeof row.sha256 !== "string" || !/^[0-9a-f]{64}$/u.test(row.sha256)) throw new Error("invalid checkpoint reference");
    if(row.engineeringStatusProjectionDigest!==undefined&&(typeof row.engineeringStatusProjectionDigest!=="string"||! /^[0-9a-f]{64}$/u.test(row.engineeringStatusProjectionDigest)))throw new Error("invalid engineering status projection reference");
    checkpointRef = { runId: row.runId, revision: uint(row.revision, "checkpoint revision"), sha256: row.sha256, ...(typeof row.engineeringStatusProjectionDigest==="string"?{engineeringStatusProjectionDigest:row.engineeringStatusProjectionDigest}:{}) };
  }
  let runId: string | undefined;
  if ("runId" in root) {
    if (typeof root.runId !== "string" || root.runId.length === 0 || Buffer.byteLength(root.runId, "utf8") > 1024 || /[\u0000-\u001f\u007f]/u.test(root.runId)) throw new Error("invalid session run binding");
    runId = root.runId;
  }
  if (runId !== undefined && checkpointRef !== undefined && runId !== checkpointRef.runId) throw new Error("session run binding disagrees with checkpoint reference");
  const storageRevision = "storageRevision" in root ? uint(root.storageRevision, "session storage revision") : 0;
  return { schemaVersion: 1, storageRevision, projectId, history, secrets, compactions, nextSeq, budget: budget(root.budget), ...(runId ? { runId } : {}), ...(checkpointRef ? { checkpointRef } : {}) };
}

export class FileProjectSessionPersistence implements ProjectSessionPersistence {
  constructor(private readonly path: string) {}
  load(): ProjectSessionSnapshot | undefined {
    if (!existsSync(this.path)) return undefined;
    if (!statSync(this.path).isFile() || statSync(this.path).size > MAX_SESSION_BYTES) throw new Error(`invalid project session store ${this.path}`);
    try { return validateProjectSessionSnapshot(JSON.parse(readFileSync(this.path, "utf8"))); }
    catch (cause) { throw new Error(`invalid project session store ${this.path}`, { cause }); }
  }
  save(snapshot: ProjectSessionSnapshot, expectedRevision: number): number {
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) throw new Error("invalid expected session revision");
    // A raw SHA-256 of secret plaintext is a post-shred dictionary oracle. AES-GCM already
    // authenticates the ciphertext; persist only its cryptographic envelope.
    const sanitized: ProjectSessionSnapshot = {
      ...snapshot,
      history: snapshot.history.map((entry) => ({ ...entry, cipher: persistedCipher(entry.cipher) })),
      secrets: snapshot.secrets.map((entry) => ({ ...entry, cipher: persistedCipher(entry.cipher) })),
      compactions: snapshot.compactions.map((entry) => ({ ...entry, cipher: persistedCipher(entry.cipher) })),
    };
    validateProjectSessionSnapshot(sanitized);
    return withSyncFileMutationLock(this.path, () => {
      const current = this.load(); const actual = current?.storageRevision ?? 0;
      if (actual !== expectedRevision) throw new ProjectSessionConflictError(`project session conflict: expected ${expectedRevision}, found ${actual}`);
      const nextRevision = expectedRevision + 1;
      const validated = validateProjectSessionSnapshot({ ...sanitized, storageRevision: nextRevision });
      const bytes = Buffer.from(`${JSON.stringify(validated)}\n`, "utf8");
      if (bytes.byteLength > MAX_SESSION_BYTES) throw new Error(`project session store exceeds ${MAX_SESSION_BYTES} bytes`);
      const dir = dirname(this.path); ensureDurableDir(NODE_IO, dir);
      const temp = `${this.path}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      let fd: number | undefined;
      try {
        fd = openSync(temp, "wx", 0o600);
        for (let offset = 0; offset < bytes.length;) { const written = writeSync(fd, bytes, offset, bytes.length - offset); if (written <= 0) throw new Error("session write made no progress"); offset += written; }
        fsyncSync(fd); closeSync(fd); fd = undefined; renameSync(temp, this.path); fsyncDir(NODE_IO, dir);
      } catch (error) {
        if (fd !== undefined) { try { closeSync(fd); } catch { /* preserve original */ } }
        try { unlinkSync(temp); } catch { /* absent or renamed */ } throw error;
      }
      return nextRevision;
    });
  }

  private documentPath(name: string): string {
    if (!/^[A-Za-z0-9._-]{1,128}$/u.test(name)) throw new Error("invalid project document name");
    return join(`${this.path}.documents`, `${name}.json`);
  }

  loadDocument(name: string): PersistedProjectDocument | undefined {
    const path = this.documentPath(name);
    if (!existsSync(path)) return undefined;
    if (!statSync(path).isFile() || statSync(path).size > MAX_DOCUMENT_BYTES) throw new Error(`invalid project document store ${path}`);
    try {
      const row = object(JSON.parse(readFileSync(path, "utf8")), "project document");
      exact(row, ["schemaVersion", "storageRevision", "name"], ["deleted", "cipher"], "project document");
      if (row.schemaVersion !== 1 || row.name !== name) throw new Error("invalid project document identity");
      if (row.deleted !== undefined && typeof row.deleted !== "boolean") throw new Error("invalid project document tombstone");
      const deleted = row.deleted === true;
      if (deleted === (row.cipher !== undefined)) throw new Error("project document must contain either ciphertext or a tombstone");
      return { schemaVersion: 1, storageRevision: uint(row.storageRevision, "project document revision"), name, deleted, ...(deleted ? {} : { cipher: cipher(row.cipher) }) };
    } catch (cause) { throw new Error(`invalid project document store ${path}`, { cause }); }
  }

  saveDocument(name: string, value: Ciphertext, expectedRevision: number): number {
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) throw new Error("invalid expected project document revision");
    const path = this.documentPath(name);
    return withSyncFileMutationLock(path, () => {
      const actual = this.loadDocument(name)?.storageRevision ?? 0;
      if (actual !== expectedRevision) throw new ProjectSessionConflictError(`project document conflict: expected ${expectedRevision}, found ${actual}`);
      const nextRevision = expectedRevision + 1;
      const bytes = Buffer.from(`${JSON.stringify({ schemaVersion: 1, storageRevision: nextRevision, name, deleted: false, cipher: persistedCipher(value) })}\n`, "utf8");
      if (bytes.byteLength > MAX_DOCUMENT_BYTES) throw new Error(`project document store exceeds ${MAX_DOCUMENT_BYTES} bytes`);
      const dir = dirname(path); ensureDurableDir(NODE_IO, dir);
      const temp = `${path}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      let fd: number | undefined;
      try {
        fd = openSync(temp, "wx", 0o600);
        for (let offset = 0; offset < bytes.length;) { const written = writeSync(fd, bytes, offset, bytes.length - offset); if (written <= 0) throw new Error("document write made no progress"); offset += written; }
        fsyncSync(fd); closeSync(fd); fd = undefined; renameSync(temp, path); fsyncDir(NODE_IO, dir);
      } catch (error) {
        if (fd !== undefined) { try { closeSync(fd); } catch { /* preserve original */ } }
        try { unlinkSync(temp); } catch { /* absent or renamed */ } throw error;
      }
      return nextRevision;
    });
  }

  deleteDocument(name: string, expectedRevision: number): boolean {
    const path = this.documentPath(name);
    return withSyncFileMutationLock(path, () => {
      const current = this.loadDocument(name);
      const actual = current?.storageRevision ?? 0;
      if (actual !== expectedRevision) throw new ProjectSessionConflictError(`project document conflict: expected ${expectedRevision}, found ${actual}`);
      if (current?.deleted === true || current === undefined) return false;
      const bytes = Buffer.from(`${JSON.stringify({ schemaVersion: 1, storageRevision: expectedRevision + 1, name, deleted: true })}\n`, "utf8");
      const dir = dirname(path); ensureDurableDir(NODE_IO, dir);
      const temp = `${path}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      let fd: number | undefined;
      try {
        fd = openSync(temp, "wx", 0o600); writeSync(fd, bytes); fsyncSync(fd); closeSync(fd); fd = undefined; renameSync(temp, path); fsyncDir(NODE_IO, dir);
      } catch (error) {
        if (fd !== undefined) { try { closeSync(fd); } catch { /* preserve original */ } }
        try { unlinkSync(temp); } catch { /* absent or renamed */ } throw error;
      }
      return true;
    });
  }
}
