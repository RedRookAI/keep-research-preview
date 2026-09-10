import {
  closeSync,
  existsSync,
  fsyncSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname } from "node:path";

import { ensureDurableDir, fsyncDir, NODE_IO } from "../spine/durable_fs.js";
import { withSyncFileMutationLock } from "../spine/sync_file_mutation_lock.js";
import { asProjectId } from "./project_id.js";
import type { ProjectLifecycle, ProjectRecord } from "./project_registry.js";

/** Atomic persistence boundary for the registry's complete project record set. */
export interface ProjectRecordStore {
  load(): ProjectRecordSnapshot;
  save(records: readonly ProjectRecord[], expectedRevision: number | undefined): number;
}
/** An absent carrier has undefined revision; an existing legacy array has revision zero. */
export interface ProjectRecordSnapshot { readonly revision: number | undefined; readonly records: readonly ProjectRecord[]; }

const lifecycles = new Set<ProjectLifecycle>(["active", "background", "archived", "deleted"]);
const MAX_PROJECT_RECORDS = 100_000;
const MAX_PROJECT_NAME_BYTES = 4_096;
const MAX_PROJECT_RECORD_STORE_BYTES = 64 * 1024 * 1024;

function validateName(value: unknown, id: string): string {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > MAX_PROJECT_NAME_BYTES) {
    throw new Error(`invalid project name for ${id}`);
  }
  if (value.length === 0 || /[\u0000-\u001f\u007f]/u.test(value)) throw new Error(`invalid project name for ${id}`);
  return value;
}

function validateRecord(value: unknown, index: number): ProjectRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`invalid project record at index ${index}`);
  }
  const record = value as Record<string, unknown>;
  const fields = Object.keys(record).sort().join(",");
  if (fields !== "createdAt,id,lifecycle,name,updatedAt" && fields !== "createdAt,id,lifecycle,name,tenant,updatedAt") {
    throw new Error(`invalid project record fields at index ${index}`);
  }
  const id = asProjectId(String(record.id));
  const name = validateName(record.name, id);
  if (record.tenant !== undefined && (typeof record.tenant !== "string" || record.tenant.length === 0 || Buffer.byteLength(record.tenant, "utf8") > 256 || /[\u0000-\u001f\u007f]/u.test(record.tenant))) throw new Error(`invalid project tenant for ${id}`);
  if (!lifecycles.has(record.lifecycle as ProjectLifecycle)) throw new Error(`invalid project lifecycle for ${id}`);
  if (!Number.isSafeInteger(record.createdAt) || (record.createdAt as number) < 0) throw new Error(`invalid createdAt for ${id}`);
  if (!Number.isSafeInteger(record.updatedAt) || (record.updatedAt as number) < (record.createdAt as number)) {
    throw new Error(`invalid updatedAt for ${id}`);
  }
  return {
    id,
    name,
    lifecycle: record.lifecycle as ProjectLifecycle,
    createdAt: record.createdAt as number,
    updatedAt: record.updatedAt as number,
    ...(typeof record.tenant === "string" ? { tenant: record.tenant } : {}),
  };
}

function validateRecords(value: unknown): ProjectRecord[] {
  if (!Array.isArray(value) || value.length > MAX_PROJECT_RECORDS) {
    throw new Error("project record store must contain a bounded array");
  }
  const records = value.map(validateRecord);
  const ids = new Set(records.map((record) => record.id));
  if (ids.size !== records.length) throw new Error("project record store contains duplicate ids");
  return records;
}

/** A single private JSON file replaced only after its complete contents and directory entry are durable. */
export class FileProjectRecordStore implements ProjectRecordStore {
  constructor(private readonly path: string) {}

  load(): ProjectRecordSnapshot {
    if (!existsSync(this.path)) return { revision: undefined, records: [] };
    let bytes: Buffer;
    try { bytes = readFileSync(this.path); }
    catch (error) { throw new Error(`cannot read project record store ${this.path}`, { cause: error }); }
    if (bytes.byteLength > MAX_PROJECT_RECORD_STORE_BYTES) throw new Error(`project record store exceeds ${MAX_PROJECT_RECORD_STORE_BYTES} bytes`);
    try {
      const parsed = JSON.parse(bytes.toString("utf8")) as unknown;
      if (Array.isArray(parsed)) return { revision: 0, records: validateRecords(parsed) };
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error("invalid project record document");
      const row = parsed as Record<string, unknown>;
      if (Object.keys(row).sort().join(",") !== "records,revision" || !Number.isSafeInteger(row.revision) || (row.revision as number) < 1) throw new Error("invalid project record document");
      return { revision: row.revision as number, records: validateRecords(row.records) };
    }
    catch (error) { throw new Error(`invalid project record store ${this.path}`, { cause: error }); }
  }

  save(records: readonly ProjectRecord[], expectedRevision: number | undefined): number {
    const validated = validateRecords(records);
    if (expectedRevision !== undefined && (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0)) throw new Error("invalid expected project record revision");
    const nextRevision = (expectedRevision ?? 0) + 1;
    return withSyncFileMutationLock(this.path, () => {
      const current = this.load();
      if (current.revision !== expectedRevision) throw new ProjectRecordConflictError(`project record conflict: expected ${expectedRevision}, found ${current.revision}`);
      const bytes = Buffer.from(`${JSON.stringify({ revision: nextRevision, records: validated })}\n`, "utf8");
      if (bytes.byteLength > MAX_PROJECT_RECORD_STORE_BYTES) throw new Error(`project record store exceeds ${MAX_PROJECT_RECORD_STORE_BYTES} bytes`);
      const dir = dirname(this.path);
      ensureDurableDir(NODE_IO, dir);
      const temp = `${this.path}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      let fd: number | undefined;
      try {
        fd = openSync(temp, "wx", 0o600);
        for (let offset = 0; offset < bytes.length;) {
          const written = writeSync(fd, bytes, offset, bytes.length - offset);
          if (written <= 0) throw new Error("project record store write made no progress");
          offset += written;
        }
        fsyncSync(fd); closeSync(fd); fd = undefined; renameSync(temp, this.path); fsyncDir(NODE_IO, dir);
      } catch (error) {
        if (fd !== undefined) { try { closeSync(fd); } catch { /* preserve the original failure */ } }
        try { unlinkSync(temp); } catch { /* absent or already renamed */ }
        throw error;
      }
      return nextRevision;
    });
  }
}

export class ProjectRecordConflictError extends Error { override readonly name = "ProjectRecordConflictError"; }
