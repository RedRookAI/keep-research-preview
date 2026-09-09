import { createHash, randomUUID } from "node:crypto";
import { closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { CryptoShredKeyStore, type Ciphertext } from "../keystore/keystore.js";
import { FileWrappedKeyPersistence } from "../keystore/file_wrapped_key_persistence.js";
import { fsyncDir, NODE_IO } from "../spine/durable_fs.js";
import { SyncFileMutationBusyError, withSyncFileMutationLock } from "../spine/sync_file_mutation_lock.js";
import { memoryCurrentWithSourcesAt, memorySourceClosure, type Lesson, type MemoryScope } from "./model.js";

/** Trusted internal custody coordinates, NOT proof of caller authorization. */
export interface MemoryPartitionScope {
  readonly ownerId: string;
  readonly kind: MemoryScope;
  readonly tenantId?: string;
  readonly projectId?: string;
  readonly agentId?: string;
}

export interface PersistedMemoryEntry {
  readonly lesson: Lesson;
  readonly embedding?: readonly number[];
  readonly access: { readonly count: number; readonly lastAccessedTs: number };
}

export interface MemoryPartitionView {
  readonly revision: number;
  readonly scope: MemoryPartitionScope;
  readonly entries: readonly PersistedMemoryEntry[];
  readonly erasures?: readonly { readonly id: string; readonly operationId: string; readonly local: "revocation-pending" | "key-revoked" }[];
}

export type MemoryControlCommand =
  | { readonly action: "erase"; readonly id: string }
  | { readonly action: "hold"; readonly id: string; readonly holdId: string; readonly active: boolean };
export interface MemoryControlActor { readonly actorId: string; readonly actorKind: string; readonly role: string; readonly permission: string }

/** Content-free admission outbox, committed with the memory mutation. */
export interface MemoryAdmissionEvent {
  readonly id: string;
  readonly payload: Readonly<Record<string, unknown>>;
}
export interface MemoryCommandRecord {
  readonly requestDigest: string;
  readonly result: unknown;
  readonly events: readonly MemoryAdmissionEvent[];
}
export type MemoryCommandLookup =
  | { readonly disposition: "absent" }
  | { readonly disposition: "committed"; readonly revision: number; readonly command: MemoryCommandRecord }
  | { readonly disposition: "rejected" }
  | { readonly disposition: "withheld"; readonly revision: number; readonly reason: "receipt-erased" }
  | { readonly disposition: "held" };

export type MemoryCommitResult =
  | { readonly disposition: "committed"; readonly operationId: string; readonly revision: number; readonly reconciled: boolean }
  | { readonly disposition: "conflict"; readonly operationId: string; readonly revision: number }
  | { readonly disposition: "withheld"; readonly operationId: string; readonly revision: number; readonly reason: "receipt-erased" }
  | { readonly disposition: "rejected"; readonly operationId: string; readonly reason: "unauthorized" | "invalid-request" | "operation-reused" | "erasure-required" | "immutable-version" | "not-found" | "legal-hold" | "control-unavailable" | "erasure-started" }
  | { readonly disposition: "held"; readonly operationId: string; readonly publication: "not-attempted" | "unknown"; readonly reason: "busy" | "unavailable" | "commit-uncertain" };

export interface FileMemoryPartitionOptions {
  readonly directory: string;
  readonly scope: MemoryPartitionScope;
  readonly keyAuthority: { readonly masterKeyPath: string; readonly wrappedKeysPath: string };
  /** Trusted host time, injectable for deterministic tests, never command input. */
  readonly clock?: () => number;
  /** Fault injection for offline qualification, never an operator command parameter. */
  readonly fault?: (point: "before-write" | "before-rename" | "after-rename" | "after-directory-sync" | "before-control-write" | "before-control-rename" | "after-control-rename" | "after-control-sync" | "after-key-revocation") => void;
}

interface ControlOperation {
  readonly id: string;
  readonly kind: "hold" | "erase";
  readonly itemId: string;
  readonly revision: number;
  readonly command: MemoryCommandRecord;
  readonly targets?: readonly { readonly id: string; readonly key: string }[];
  readonly receipts?: readonly ReceiptReservation[];
  readonly phase?: "revocation-pending" | "key-revoked";
  readonly holdId?: string;
  readonly active?: boolean;
}
interface Control {
  readonly schema: "keep.memory.control/v1" | "keep.memory.control/v2";
  readonly scope: MemoryPartitionScope;
  readonly partitionKey: string;
  readonly operations: readonly ControlOperation[];
}

interface SealedEntry { readonly id: string; readonly key: string; readonly payload: Ciphertext }
interface Operation { readonly id: string; readonly requestDigest: string; readonly revision: number; readonly command?: MemoryCommandRecord }
interface ReceiptReservation { readonly id: string; readonly revision: number; readonly key?: string }
interface SealedOperation {
  readonly id: string; readonly revision: number;
  readonly receipt: { readonly key: string; readonly dependencies: readonly string[]; readonly payload: Ciphertext };
}
interface Snapshot {
  readonly schema: "keep.memory.partition/v1" | "keep.memory.partition/v2";
  readonly scope: MemoryPartitionScope;
  readonly revision: number;
  readonly operations: readonly (Operation | SealedOperation)[];
  readonly entries: readonly SealedEntry[];
}
interface Envelope { readonly schema: "keep.memory.envelope/v1"; readonly key: string; readonly payload: Ciphertext }
const MAX_BYTES = 64 * 1024 * 1024;
const PARTITION_KEY = /^keep\.memory\.partition\.v1:[0-9a-f-]{36}$/u;
const ITEM_KEY = /^keep\.memory\.item\.v1:[0-9a-f-]{36}$/u;
const RECEIPT_KEY = /^keep\.memory\.receipt\.v1:[0-9a-f-]{36}$/u;

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid memory record");
  return value as Record<string, unknown>;
}
function fields(value: Record<string, unknown>, required: string[], optional: string[] = []): void {
  if (required.some(key => !(key in value)) || Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) throw new Error("invalid memory fields");
}
function identifier(value: unknown): asserts value is string {
  if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value) > 4096 || /[\u0000-\u001f\u007f]/u.test(value)) throw new Error("invalid memory identifier");
}
function finite(value: unknown): asserts value is number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new Error("invalid memory number");
}
function revision(value: unknown): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new Error("invalid memory revision");
}
function scopeOf(value: unknown): MemoryPartitionScope {
  const row = record(value);
  fields(row, ["ownerId", "kind"], ["tenantId", "projectId", "agentId"]);
  identifier(row.ownerId);
  if (!["user", "project", "global", "agent"].includes(String(row.kind))) throw new Error("invalid memory scope");
  for (const key of ["tenantId", "projectId", "agentId"]) if (key in row) identifier(row[key]);
  if (row.kind === "project" && row.projectId === undefined) throw new Error("project scope requires project identity");
  if (row.kind === "agent" && row.agentId === undefined) throw new Error("agent scope requires agent identity");
  return row as unknown as MemoryPartitionScope;
}
function entryOf(value: unknown, scope: MemoryPartitionScope): PersistedMemoryEntry {
  const row = record(value); fields(row, ["lesson", "access"], ["embedding"]);
  const lesson = record(row.lesson);
  fields(lesson, ["id", "content", "tier", "origin", "provenanceEventId", "scope", "kind", "importance", "evidence", "createdTs", "validFrom"], ["modelDependency", "citation", "validTo", "custody"]);
  identifier(lesson.id); identifier(lesson.provenanceEventId);
  if (typeof lesson.content !== "string" || !["candidate", "probation", "confirmed", "retired"].includes(String(lesson.tier))
    || !["self", "external", "seeded"].includes(String(lesson.origin)) || lesson.scope !== scope.kind
    || !["fact", "preference", "decision", "procedure"].includes(String(lesson.kind))) throw new Error("invalid memory lesson");
  for (const key of ["modelDependency", "citation"]) if (key in lesson && typeof lesson[key] !== "string") throw new Error("invalid memory annotation");
  finite(lesson.importance); finite(lesson.createdTs); finite(lesson.validFrom);
  if (lesson.importance < 0 || lesson.importance > 1) throw new Error("invalid memory importance");
  if ("validTo" in lesson) { finite(lesson.validTo); if (lesson.validTo < lesson.validFrom) throw new Error("invalid memory interval"); }
  if ("custody" in lesson) {
    const custody = record(lesson.custody);
    if (custody.schema === "keep.memory.derived-custody/v1") {
      fields(custody, ["schema", "scope", "source", "consentEventId", "purpose", "assertion", "uncertainty", "authority", "retention", "residency", "dependencies", "derivatives", "algorithm", "sources"]);
      if (canonical(scopeOf(custody.scope)) !== canonical(scope) || custody.purpose !== "source-preserving-memory"
        || custody.assertion !== "derived" || custody.uncertainty !== "unassessed" || custody.authority !== "none"
        || custody.algorithm !== "extractive-v1" || lesson.origin !== "self"
        || !["candidate", "retired"].includes(String(lesson.tier)) || canonical(lesson.evidence) !== "[]") throw new Error("invalid derived custody");
      identifier(custody.consentEventId);
      const source = record(custody.source); fields(source, ["kind", "operationId", "actorId", "actorKind"]);
      if (source.kind !== "host-extractive-command" || !["human", "agent", "service"].includes(String(source.actorKind))) throw new Error("invalid derived source");
      identifier(source.operationId); identifier(source.actorId);
      if (!Array.isArray(custody.sources) || custody.sources.length < 2 || custody.sources.length > 8) throw new Error("invalid derived sources");
      const ids = new Set<string>();
      for (const value of custody.sources) {
        const s = record(value); fields(s, ["itemId", "provenanceEventId", "startByte", "endByte"]);
        identifier(s.itemId); identifier(s.provenanceEventId); revision(s.startByte); revision(s.endByte);
        if (s.itemId === lesson.id || ids.has(s.itemId) || s.endByte <= s.startByte || s.endByte - s.startByte > 512) throw new Error("invalid derived span");
        ids.add(s.itemId);
      }
      const retention = record(custody.retention); fields(retention, ["useUntil", "expiryDisposition", "legalHoldAssessment"]);
      if (retention.useUntil !== null) { revision(retention.useUntil); if (retention.useUntil <= lesson.createdTs) throw new Error("expired derived admission"); }
      if (retention.expiryDisposition !== "withhold-pending-erasure" || retention.legalHoldAssessment !== "unassessed") throw new Error("invalid derived retention");
      if (canonical(custody.residency) !== canonical({ storage: "operator-host", region: "unverified", embeddingProcessing: "none" })
        || canonical(custody.dependencies) !== canonical({ embeddingProvider: null, embeddingModel: null })
        || canonical(custody.derivatives) !== canonical({ coEncrypted: ["sources", "access"], outsideCustody: "caller-provider-backup-copies-untracked" })) throw new Error("invalid derived inventory");
    } else {
      fields(custody, ["schema", "scope", "source", "consentEventId", "purpose", "assertion", "uncertainty", "authority", "retention", "residency", "dependencies", "derivatives", ...(custody.schema === "keep.memory.manual-custody/v3" ? ["privateSource"] : [])], ["supersedes"]);
      if (!["keep.memory.manual-custody/v1", "keep.memory.manual-custody/v2", "keep.memory.manual-custody/v3"].includes(String(custody.schema)) || canonical(scopeOf(custody.scope)) !== canonical(scope)
        || custody.purpose !== "explicit-manual-memory" || custody.assertion !== "asserted" || custody.uncertainty !== "unassessed" || custody.authority !== "none") throw new Error("invalid manual custody");
      identifier(custody.consentEventId);
      if (custody.schema === "keep.memory.manual-custody/v3") {
        const privateSource = record(custody.privateSource); fields(privateSource, ["representation", "purpose", "policyIdentity"]);
        if (privateSource.representation !== "keep.memory.private-source/v1" || typeof privateSource.purpose !== "string"
          || !/^[a-z][a-z0-9.-]{0,127}$/u.test(privateSource.purpose) || typeof privateSource.policyIdentity !== "string"
          || !/^[a-f0-9]{64}$/u.test(privateSource.policyIdentity)) throw new Error("invalid private source representation");
      }
      if ("supersedes" in custody) { identifier(custody.supersedes); if (custody.supersedes === lesson.id) throw new Error("self supersession"); }
      const source = record(custody.source); fields(source, ["kind", "operationId", "actorId", "actorKind"]);
      if (source.kind !== "authenticated-manual-command" || !["human", "agent", "service"].includes(String(source.actorKind))) throw new Error("invalid memory source");
      identifier(source.operationId); identifier(source.actorId);
      const retention = record(custody.retention); fields(retention, ["useUntil", "expiryDisposition", "legalHoldAssessment"]);
      if (retention.useUntil !== null) { revision(retention.useUntil); if (retention.useUntil <= lesson.createdTs) throw new Error("expired memory admission"); }
      if (retention.expiryDisposition !== "withhold-pending-erasure" || retention.legalHoldAssessment !== "unassessed") throw new Error("invalid retention policy");
      const residency = record(custody.residency); fields(residency, ["storage", "region", "embeddingProcessing"]);
      const sourceOnly = ["keep.memory.manual-custody/v2", "keep.memory.manual-custody/v3"].includes(String(custody.schema));
      if (residency.storage !== "operator-host" || residency.region !== "unverified" || !(sourceOnly ? ["none"] : ["local", "external"]).includes(String(residency.embeddingProcessing))) throw new Error("invalid residency facts");
      const dependencies = record(custody.dependencies); fields(dependencies, ["embeddingProvider", "embeddingModel"]);
      if (sourceOnly) { if (dependencies.embeddingProvider !== null) throw new Error("source-only provider must be absent"); }
      else identifier(dependencies.embeddingProvider);
      if (dependencies.embeddingModel !== null) throw new Error("unmeasured embedding model");
      const derivatives = record(custody.derivatives); fields(derivatives, ["coEncrypted", "outsideCustody"]);
      if (canonical(derivatives.coEncrypted) !== (sourceOnly ? '["access"]' : '["embedding","access"]') || derivatives.outsideCustody !== "caller-provider-backup-copies-untracked") throw new Error("invalid derivative inventory");
    }
  }
  if (!Array.isArray(lesson.evidence)) throw new Error("invalid memory evidence");
  for (const value of lesson.evidence) {
    const evidence = record(value); fields(evidence, ["spineEventId", "cleanResolved", "context", "ts"]);
    identifier(evidence.spineEventId); identifier(evidence.context); finite(evidence.ts);
    if (typeof evidence.cleanResolved !== "boolean") throw new Error("invalid memory outcome");
  }
  if (["keep.memory.derived-custody/v1", "keep.memory.manual-custody/v2", "keep.memory.manual-custody/v3"].includes((lesson.custody as Lesson["custody"])?.schema ?? "")) {
    if ("embedding" in row) throw new Error("source-only item cannot invent an embedding");
  } else {
    if (!Array.isArray(row.embedding) || row.embedding.length === 0) throw new Error("invalid memory embedding");
    row.embedding.forEach(finite);
  }
  const access = record(row.access); fields(access, ["count", "lastAccessedTs"]); revision(access.count); finite(access.lastAccessedTs);
  return row as unknown as PersistedMemoryEntry;
}
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const row = value as Record<string, unknown>;
    return `{${Object.keys(row).sort().map(key => `${JSON.stringify(key)}:${canonical(row[key])}`).join(",")}}`;
  }
  const result = JSON.stringify(value);
  if (result === undefined) throw new Error("non-JSON memory value");
  return result;
}
function freeze<T>(value: T): T {
  if (value !== null && typeof value === "object") { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}
function preservesVersion(prior: Lesson, next: Lesson): boolean {
  if (canonical(prior.custody ?? null) !== canonical(next.custody ?? null)) return false;
  // Content/provenance corrections append a successor, never rewrite admitted history.
  for (const key of ["id", "content", "origin", "provenanceEventId", "scope", "kind", "createdTs", "validFrom", "citation", "modelDependency"] as const) {
    if (prior[key] !== next[key]) return false;
  }
  if (prior.validTo !== undefined && prior.validTo !== next.validTo) return false;
  return next.evidence.length >= prior.evidence.length
    && prior.evidence.every((evidence, index) => canonical(evidence) === canonical(next.evidence[index]));
}
function ciphertext(value: unknown): Ciphertext {
  const row = record(value); fields(row, ["iv", "authTag", "data"]);
  if (typeof row.iv !== "string" || !/^[0-9a-f]{24}$/u.test(row.iv) || typeof row.authTag !== "string" || !/^[0-9a-f]{32}$/u.test(row.authTag)
    || typeof row.data !== "string" || !/^(?:[0-9a-f]{2})+$/u.test(row.data)) throw new Error("invalid memory ciphertext");
  return row as unknown as Ciphertext;
}
function commandOf(value: unknown): MemoryCommandRecord {
  const row = record(value); fields(row, ["requestDigest", "result", "events"]);
  if (typeof row.requestDigest !== "string" || !/^[0-9a-f]{64}$/u.test(row.requestDigest) || !Array.isArray(row.events)) throw new Error("invalid memory command receipt");
  canonical(row.result);
  const ids = new Set<string>();
  for (const value of row.events) {
    const event = record(value); fields(event, ["id", "payload"]); identifier(event.id); record(event.payload);
    if (ids.has(event.id) || Buffer.byteLength(canonical(event.payload)) > 1024 * 1024) throw new Error("invalid memory admission event");
    ids.add(event.id);
  }
  return row as unknown as MemoryCommandRecord;
}
function operationOf(value: unknown): Operation {
  const operation = record(value); fields(operation, ["id", "requestDigest", "revision"], ["command"]);
  identifier(operation.id); revision(operation.revision);
  if (typeof operation.requestDigest !== "string" || !/^[0-9a-f]{64}$/u.test(operation.requestDigest)) throw new Error("invalid memory operation fingerprint");
  if (operation.command !== undefined) commandOf(operation.command);
  return operation as unknown as Operation;
}
function seal(keys: CryptoShredKeyStore, key: string, value: unknown): Ciphertext {
  const { iv, authTag, data } = keys.encrypt(key, canonical(value));
  return { iv, authTag, data }; // Never persist the primitive's plaintext hash.
}

/**
 * Explicit private-directory snapshot custody. No default runtime exposure, caller
 * authentication, rollback-resistance to restored key authority, or erasure claim.
 * All cooperating writers use this lock; a stale carrier requires reconciliation.
 * Parent directories and key authority must be trusted (not an adversarial filesystem).
 */
export class FileMemoryPartition {
  private readonly options: FileMemoryPartitionOptions;
  readonly snapshotPath: string;
  readonly controlPath: string;

  constructor(options: FileMemoryPartitionOptions) {
    const scope = freeze(scopeOf(structuredClone(options.scope)));
    const directory = resolve(options.directory);
    const masterKeyPath = resolve(options.keyAuthority.masterKeyPath);
    const wrappedKeysPath = resolve(options.keyAuthority.wrappedKeysPath);
    if (masterKeyPath === wrappedKeysPath || [masterKeyPath, wrappedKeysPath].some(path => path === directory || path.startsWith(`${directory}${sep}`))) throw new Error("memory data and key authority must be separate");
    this.options = { directory, scope, keyAuthority: { masterKeyPath, wrappedKeysPath }, ...(options.fault ? { fault: options.fault } : {}),
      ...(options.clock === undefined ? {} : { clock: options.clock }) };
    this.snapshotPath = join(directory, "partition.json.enc");
    this.controlPath = join(dirname(wrappedKeysPath), `memory-control-${createHash("sha256").update(canonical(scope)).digest("hex")}.enc`);
  }

  /** Only a new directory is eligible. A partial initialization is held, not reset. */
  initialize(): void {
    if (existsSync(this.controlPath)) throw new Error("existing control requires reconciliation");
    const keys = this.keys(); // Missing established master never creates a directory.
    mkdirSync(this.options.directory, { mode: 0o700 });
    fsyncDir(NODE_IO, dirname(this.options.directory));
    withSyncFileMutationLock(this.snapshotPath, () => {
      const key = `keep.memory.partition.v1:${randomUUID()}`;
      keys.ensureKey(key);
      this.createControl(keys, key);
      this.publish(keys, key, { schema: "keep.memory.partition/v2", scope: this.options.scope, revision: 0, operations: [], entries: [] }, () => {});
    }, { allowStaleTakeover: false });
  }

  read(confirmDurability = false): MemoryPartitionView {
    this.checkDirectory();
    return withSyncFileMutationLock(this.snapshotPath, () => {
      const keys = this.keys(); const { snapshot, entries, control } = this.load(keys);
      if (confirmDurability) { this.readBytes(true); fsyncDir(NODE_IO, this.options.directory); }
      const erasures = control?.operations.filter(operation => operation.kind === "erase").flatMap(operation => operation.targets!.map(target => ({ id: target.id, operationId: operation.id,
        local: keys.hasKey(target.key) ? "revocation-pending" as const : operation.phase! }))) ?? [];
      return freeze({ revision: snapshot.revision, scope: structuredClone(snapshot.scope), entries, ...(erasures.length === 0 ? {} : { erasures }) });
    }, { allowStaleTakeover: false });
  }

  /** Explicit initialization/migration only. A missing established control never becomes empty. */
  initializeControl(): void {
    this.checkDirectory();
    withSyncFileMutationLock(this.snapshotPath, () => {
      const keys = this.keys(); const { key, control } = this.load(keys);
      if (control === undefined) this.createControl(keys, key);
      else this.readPrivateBytes(this.controlPath, true);
      fsyncDir(NODE_IO, dirname(this.controlPath));
    }, { allowStaleTakeover: false });
  }

  /** Reconcile the original command before any provider preparation or new effect. */
  lookupCommand(operationId: string, requestDigest: string): MemoryCommandLookup {
    try {
      identifier(operationId); this.checkDirectory();
      return withSyncFileMutationLock(this.snapshotPath, (): MemoryCommandLookup => {
        const keys = this.keys(); const { operations, control } = this.load(keys);
        const reserved = this.receiptReservations(control).get(operationId);
        if (reserved) return { disposition: "withheld", revision: reserved.revision, reason: "receipt-erased" };
        const controlled = control?.operations.find(operation => operation.id === operationId);
        if (controlled) {
          if (controlled.command.requestDigest !== requestDigest) return { disposition: "rejected" };
          if (controlled.kind === "erase" && (controlled.phase !== "key-revoked" || [...controlled.targets!.map(target => target.key), ...(controlled.receipts ?? []).flatMap(receipt => receipt.key === undefined ? [] : [receipt.key])].some(key => keys.hasKey(key)))) return { disposition: "held" };
          this.readPrivateBytes(this.controlPath, true); fsyncDir(NODE_IO, dirname(this.controlPath));
          return freeze({ disposition: "committed", revision: controlled.revision, command: structuredClone(controlled.command) });
        }
        const prior = operations.find(operation => operation.id === operationId);
        if (!prior) return { disposition: "absent" };
        if (prior.command?.requestDigest !== requestDigest) return { disposition: "rejected" };
        this.readBytes(true); fsyncDir(NODE_IO, this.options.directory);
        return freeze({ disposition: "committed", revision: prior.revision, command: structuredClone(prior.command) });
      }, { allowStaleTakeover: false });
    } catch { return { disposition: "held" }; }
  }

  /** The complete selected partition's outbox, not only this process's cached writes. */
  admissionEvents(): readonly MemoryAdmissionEvent[] {
    this.checkDirectory();
    return withSyncFileMutationLock(this.snapshotPath, () => {
      const { operations, control } = this.load(this.keys());
      return freeze(structuredClone([...operations.flatMap(operation => operation.command?.events ?? []), ...(control?.operations.flatMap(operation => operation.command.events) ?? [])]));
    }, { allowStaleTakeover: false });
  }

  commit(operationId: string, expectedRevision: number, nextEntries: readonly PersistedMemoryEntry[], command?: MemoryCommandRecord, beforePublish?: () => boolean): MemoryCommitResult {
    let entries: PersistedMemoryEntry[];
    let requestDigest: string;
    let capturedCommand: MemoryCommandRecord | undefined;
    try {
      identifier(operationId); revision(expectedRevision);
      const copy: unknown = structuredClone(nextEntries);
      if (!Array.isArray(copy)) throw new Error("invalid memory entries");
      entries = copy.map(value => entryOf(value, this.options.scope));
      if (new Set(entries.map(entry => entry.lesson.id)).size !== entries.length) throw new Error("duplicate memory id");
      capturedCommand = command === undefined ? undefined : commandOf(structuredClone(command));
      const request = canonical({ expectedRevision, entries, ...(capturedCommand === undefined ? {} : { command: capturedCommand }) });
      if (Buffer.byteLength(request) > MAX_BYTES) throw new Error("memory request is oversized");
      requestDigest = createHash("sha256").update(request).digest("hex");
    } catch { return { disposition: "rejected", operationId, reason: "invalid-request" }; }
    let published = false;
    try {
      this.checkDirectory();
      return withSyncFileMutationLock(this.snapshotPath, (): MemoryCommitResult => {
        const keys = this.keys();
        const { key, snapshot, operations, entries: priorEntries, control } = this.load(keys);
        const reserved = this.receiptReservations(control).get(operationId);
        if (reserved) return { disposition: "withheld", operationId, revision: reserved.revision, reason: "receipt-erased" };
        if (control?.operations.some(operation => operation.id === operationId)) return { disposition: "rejected", operationId, reason: "operation-reused" };
        const priorOperation = operations.find(operation => operation.id === operationId);
        if (priorOperation) {
          if (priorOperation.requestDigest !== requestDigest) return { disposition: "rejected", operationId, reason: "operation-reused" };
          published = true;
          // Reconcile visibility after a prior ambiguous rename by syncing this state.
          this.readBytes(true); fsyncDir(NODE_IO, this.options.directory);
          return { disposition: "committed", operationId, revision: priorOperation.revision, reconciled: true };
        }
        if (snapshot.revision !== expectedRevision) return { disposition: "conflict", operationId, revision: snapshot.revision };
        const nextIds = new Set(entries.map(entry => entry.lesson.id));
        const erasedIds = new Set(control?.operations.filter(operation => operation.kind === "erase").flatMap(operation => operation.targets!.map(target => target.id)));
        const lineage = this.lineage(operations, control);
        if (priorEntries.some(entry => !nextIds.has(entry.lesson.id)) || entries.some(entry => erasedIds.has(entry.lesson.id) || this.parentsOf(entry.lesson, lineage).some(id => erasedIds.has(id)))) return { disposition: "rejected", operationId, reason: "erasure-required" };
        const nextRevision = snapshot.revision + 1; revision(nextRevision);
        const sealedById = new Map(snapshot.entries.map(entry => [entry.id, entry]));
        const priorById = new Map(priorEntries.map(entry => [entry.lesson.id, { entry, sealed: sealedById.get(entry.lesson.id)! }]));
        if (entries.some(entry => { const prior = priorById.get(entry.lesson.id); return prior !== undefined && !preservesVersion(prior.entry.lesson, entry.lesson); })) {
          return { disposition: "rejected", operationId, reason: "immutable-version" };
        }
        const priorLessons = new Map(priorEntries.map(entry => [entry.lesson.id, entry.lesson]));
        const nextLessons = new Map(entries.map(entry => [entry.lesson.id, entry.lesson]));
        const now = (this.options.clock ?? Date.now)();
        for (const { lesson } of entries) {
          if (lesson.custody?.schema !== "keep.memory.derived-custody/v1" || priorById.has(lesson.id)) continue;
          const c = lesson.custody;
          // Parents must already exist unchanged at this publication boundary; proposed rows
          // cannot supply their own evidence or retire a source in the same transaction.
          if (!Number.isFinite(now) || lesson.createdTs > now || lesson.validFrom !== lesson.createdTs
            || c.source.operationId !== operationId
            || c.sources.some(s => !priorLessons.has(s.itemId) || canonical(priorLessons.get(s.itemId)) !== canonical(nextLessons.get(s.itemId)))
            || !memoryCurrentWithSourcesAt(lesson, now, priorLessons)) return { disposition: "rejected", operationId, reason: "invalid-request" };
          const closure = memorySourceClosure(lesson, priorLessons)!;
          if (closure.some(parent => parent.id !== lesson.id && (parent.createdTs > lesson.createdTs
            || (parent.validTo !== undefined && (lesson.validTo === undefined || lesson.validTo > parent.validTo))
            || (parent.custody?.retention.useUntil != null && (c.retention.useUntil === null || c.retention.useUntil > parent.custody.retention.useUntil))))) {
            return { disposition: "rejected", operationId, reason: "invalid-request" };
          }
        }
        // A host capability, not serialized request data. Derived commands re-resolve
        // their read/write intersection after loading/checking the locked parent state.
        if (beforePublish !== undefined && beforePublish() !== true) return { disposition: "rejected", operationId, reason: "unauthorized" };
        const sealed = entries.map(entry => {
          const prior = priorById.get(entry.lesson.id);
          if (prior && canonical(prior.entry) === canonical(entry)) return prior.sealed;
          const itemKey = prior?.sealed.key ?? `keep.memory.item.v1:${randomUUID()}`;
          if (!prior) keys.ensureKey(itemKey);
          return { id: entry.lesson.id, key: itemKey, payload: seal(keys, itemKey, { schema: "keep.memory.item/v1", scope: this.options.scope, entry }) };
        });
        const receiptKey = `keep.memory.receipt.v1:${randomUUID()}`; keys.ensureKey(receiptKey);
        const dependencies = entries.map(entry => entry.lesson.id);
        const operation: Operation = { id: operationId, requestDigest, revision: nextRevision, ...(capturedCommand === undefined ? {} : { command: capturedCommand }) };
        const stored: SealedOperation = { id: operationId, revision: nextRevision, receipt: { key: receiptKey, dependencies,
          payload: seal(keys, receiptKey, { schema: "keep.memory.operation-receipt/v1", scope: this.options.scope, partitionKey: key, operation, dependencies }) } };
        this.publish(keys, key, { ...snapshot, schema: "keep.memory.partition/v2", revision: nextRevision, entries: [...sealed, ...snapshot.entries.filter(entry => erasedIds.has(entry.id))], operations: [...snapshot.operations, stored] }, () => { published = true; });
        return { disposition: "committed", operationId, revision: nextRevision, reconciled: false };
      }, { allowStaleTakeover: false });
    } catch (error) {
      return { disposition: "held", operationId, publication: published ? "unknown" : "not-attempted",
        reason: published ? "commit-uncertain" : error instanceof SyncFileMutationBusyError ? "busy" : "unavailable" };
    }
  }

  /** Trusted synchronous control command; the gateway supplies actual actor and resource authority. */
  controlCommand(operationId: string, input: MemoryControlCommand, actor: MemoryControlActor): MemoryCommitResult {
    let command: MemoryControlCommand; let admission: MemoryControlActor; let digest: string;
    try {
      identifier(operationId); command = structuredClone(input); admission = structuredClone(actor);
      fields(record(admission), ["actorId", "actorKind", "role", "permission"]);
      const row = record(command); fields(row, command.action === "erase" ? ["action", "id"] : ["action", "id", "holdId", "active"]);
      identifier(command.id);
      if (command.action !== "erase" && command.action !== "hold") throw new Error("invalid control action");
      if (command.action === "hold") { identifier(command.holdId); if (typeof command.active !== "boolean") throw new Error("invalid hold"); }
      for (const value of Object.values(admission)) identifier(value);
      digest = createHash("sha256").update(canonical(command)).digest("hex");
    } catch { return { disposition: "rejected", operationId, reason: "invalid-request" }; }
    let published = false;
    try {
      this.checkDirectory();
      return withSyncFileMutationLock(this.snapshotPath, (): MemoryCommitResult => {
        const keys = this.keys(); const { snapshot, control, entries, operations } = this.load(keys);
        if (!control) return { disposition: "rejected", operationId, reason: "control-unavailable" };
        const reservations = this.receiptReservations(control);
        const reserved = reservations.get(operationId);
        if (reserved) return { disposition: "withheld", operationId, revision: reserved.revision, reason: "receipt-erased" };
        let operation = control.operations.find(value => value.id === operationId);
        if (operation && operation.command.requestDigest !== digest || snapshot.operations.some(value => value.id === operationId)) return { disposition: "rejected", operationId, reason: "operation-reused" };
        const reconciled = operation !== undefined;
        const event = (name: string, disposition: string): MemoryAdmissionEvent => ({ id: `memory-admission:${randomUUID()}`,
          payload: { event: name, ...admission, scope: structuredClone(this.options.scope), operationId, itemId: command.id, terminalDisposition: disposition,
            ...(command.action === "hold" ? { holdId: command.holdId, active: command.active } : {}) } });
        let current = control;
        if (!operation) {
          if (control.operations.some(value => value.kind === "erase" && value.targets!.some(target => target.id === command.id))) return { disposition: "rejected", operationId, reason: "erasure-started" };
          if (!entries.some(entry => entry.lesson.id === command.id)) return { disposition: "rejected", operationId, reason: "not-found" };
          const targetIds = new Set([command.id]);
          if (command.action === "erase") {
            // Corrections are known derivatives, including retired intermediate versions.
            const children = new Map<string, string[]>();
            const lineage = this.lineage(operations, control);
            for (const entry of entries) for (const parent of this.parentsOf(entry.lesson, lineage)) children.set(parent, [...(children.get(parent) ?? []), entry.lesson.id]);
            const queue = [command.id];
            for (let i = 0; i < queue.length; i++) for (const child of children.get(queue[i]!) ?? []) if (!targetIds.has(child)) { targetIds.add(child); queue.push(child); }
            const holds = new Map<string, boolean>();
            for (const row of control.operations) if (row.kind === "hold" && targetIds.has(row.itemId)) holds.set(canonical([row.itemId, row.holdId]), row.active!);
            if ([...holds.values()].some(Boolean)) return { disposition: "rejected", operationId, reason: "legal-hold" };
          }
          const receipts: ReceiptReservation[] = command.action === "hold" ? [] : snapshot.operations.flatMap(value => {
            if (reservations.has(value.id)) return [];
            if ("receipt" in value) return value.receipt.dependencies.some(id => targetIds.has(id)) ? [{ id: value.id, revision: value.revision, key: value.receipt.key }] : [];
            // Legacy raw publication fingerprints have no trustworthy per-item inventory.
            // Preserve the known content-free opt-in receipt so survivors remain accessible.
            return value.id === "keep.memory.initialize/v1" ? [] : [{ id: value.id, revision: value.revision }];
          });
          const reservedIds = new Set(receipts.map(receipt => receipt.id));
          const retainedEvents = operations.filter(value => reservedIds.has(value.id)).flatMap(value => value.command?.events ?? []);
          operation = command.action === "hold"
            ? { id: operationId, kind: "hold", itemId: command.id, revision: snapshot.revision, holdId: command.holdId, active: command.active,
              command: { requestDigest: digest, result: { id: command.id, holdId: command.holdId, active: command.active }, events: [event("memory.hold.changed", "committed")] } }
            : { id: operationId, kind: "erase", itemId: command.id, revision: snapshot.revision, targets: snapshot.entries.filter(row => targetIds.has(row.id)).map(({ id, key }) => ({ id, key })), receipts, phase: "revocation-pending",
              command: { requestDigest: digest, result: { id: command.id, ids: [...targetIds], local: "revocation-pending", metadataErasure: "receipt-revocation-pending", outsideCopies: "pending", mediaSanitization: "unproven" }, events: [...retainedEvents, event("memory.erasure.requested", "accepted")] } };
          current = { ...control, schema: "keep.memory.control/v2", operations: [...control.operations, operation] };
          this.publishControl(keys, current, () => { published = true; });
        } else {
          published = true;
          this.readPrivateBytes(this.controlPath, true); fsyncDir(NODE_IO, dirname(this.controlPath));
        }
        if (operation.kind === "erase") {
          // Also re-establish absence durably on a retry after an ambiguous key-map rename.
          const persistence = new FileWrappedKeyPersistence({ ...this.options.keyAuthority, requireExistingMasterKey: true, allowStaleTakeover: false });
          const revoke = [...operation.targets!.map(target => target.key), ...(operation.receipts ?? []).flatMap(receipt => receipt.key === undefined ? [] : [receipt.key])];
          persistence.deleteMany(revoke); keys.refresh();
          if (revoke.some(key => keys.hasKey(key))) throw new Error("erased key remains in current authority");
          this.options.fault?.("after-key-revocation");
          if (operation.phase !== "key-revoked") {
            const finished: ControlOperation = { ...operation, phase: "key-revoked", command: { ...operation.command,
              result: { id: command.id, ids: operation.targets!.map(target => target.id), local: "key-revoked",
                metadataErasure: operation.receipts === undefined || operation.receipts.some(receipt => receipt.key === undefined) ? "legacy-fingerprints-and-provenance-pending" : "receipt-fingerprints-revoked-provenance-pending", outsideCopies: "pending", mediaSanitization: "unproven" },
              events: [...operation.command.events, event("memory.erasure.key-revoked", "local-key-revoked-outside-copies-pending")] } };
            current = { ...current, operations: current.operations.map(value => value.id === operationId ? finished : value) };
            this.publishControl(keys, current, () => { published = true; });
          }
        }
        return { disposition: "committed", operationId, revision: operation.revision, reconciled };
      }, { allowStaleTakeover: false });
    } catch (error) {
      return { disposition: "held", operationId, publication: published ? "unknown" : "not-attempted",
        reason: published ? "commit-uncertain" : error instanceof SyncFileMutationBusyError ? "busy" : "unavailable" };
    }
  }

  private receiptReservations(control?: Control): ReadonlyMap<string, ReceiptReservation> {
    return new Map(control?.operations.flatMap(operation => (operation.receipts ?? []).map(receipt => [receipt.id, receipt] as const)));
  }
  private lineage(operations: readonly Operation[], control?: Control): ReadonlyMap<string, { id: string; parent: string }> {
    const result = new Map<string, { id: string; parent: string }>();
    for (const operation of [...operations, ...(control?.operations ?? [])]) for (const event of operation.command?.events ?? []) {
      const payload = event.payload;
      if (payload["event"] === "lesson_corrected" && typeof payload["lessonId"] === "string" && typeof payload["supersedes"] === "string") result.set(event.id, { id: payload["lessonId"], parent: payload["supersedes"] });
    }
    return result;
  }
  private parentsOf(lesson: Lesson, lineage: ReadonlyMap<string, { id: string; parent: string }>): readonly string[] {
    const admitted = lineage.get(lesson.provenanceEventId);
    const supersedes = lesson.custody?.supersedes ?? (admitted?.id === lesson.id ? admitted.parent : undefined);
    return [...new Set([...(supersedes === undefined ? [] : [supersedes]),
      ...(lesson.custody?.schema === "keep.memory.derived-custody/v1" ? lesson.custody.sources.map(s => s.itemId) : [])])];
  }

  private controlKey(partitionKey: string): string { return partitionKey.replace("keep.memory.partition.v1:", "keep.memory.control.v1:"); }
  private createControl(keys: CryptoShredKeyStore, partitionKey: string): void {
    const key = this.controlKey(partitionKey);
    if (existsSync(this.controlPath) || keys.hasKey(key)) throw new Error("existing control requires reconciliation");
    keys.ensureKey(key);
    this.publishControl(keys, { schema: "keep.memory.control/v2", scope: this.options.scope, partitionKey, operations: [] }, () => {});
  }
  private loadControl(keys: CryptoShredKeyStore, partitionKey: string): Control | undefined {
    const key = this.controlKey(partitionKey);
    if (!existsSync(this.controlPath)) {
      if (keys.hasKey(key)) throw new Error("established memory control is missing");
      return undefined; // Legacy partition: control is created only by explicit initialization.
    }
    const row = record(JSON.parse(keys.decrypt(key, ciphertext(JSON.parse(this.readPrivateBytes(this.controlPath))))));
    fields(row, ["schema", "scope", "partitionKey", "operations"]);
    if (!["keep.memory.control/v1", "keep.memory.control/v2"].includes(String(row.schema)) || row.partitionKey !== partitionKey || canonical(scopeOf(row.scope)) !== canonical(this.options.scope) || !Array.isArray(row.operations)) throw new Error("invalid memory control");
    const ids = new Set<string>(), erased = new Set<string>();
    const reserved = new Set<string>(), receiptKeys = new Set<string>();
    for (const value of row.operations) {
      const op = record(value); fields(op, op.kind === "erase" ? ["id", "kind", "itemId", "revision", "command", "targets", "phase"] : ["id", "kind", "itemId", "revision", "command", "holdId", "active"], op.kind === "erase" ? ["receipts"] : []);
      identifier(op.id); identifier(op.itemId); revision(op.revision); commandOf(op.command);
      if (ids.has(op.id)) throw new Error("duplicate memory control operation"); ids.add(op.id);
      if (op.kind === "erase") {
        if (!Array.isArray(op.targets) || op.targets.length === 0 || !["revocation-pending", "key-revoked"].includes(String(op.phase))) throw new Error("invalid memory erasure");
        const targetKeys = new Set<string>();
        for (const targetValue of op.targets) {
          const target = record(targetValue); fields(target, ["id", "key"]); identifier(target.id);
          if (typeof target.key !== "string" || !ITEM_KEY.test(target.key) || erased.has(target.id) || targetKeys.has(target.key)) throw new Error("invalid memory erasure target");
          erased.add(target.id); targetKeys.add(target.key);
        }
        if (!op.targets.some(value => record(value).id === op.itemId)) throw new Error("missing erasure root");
        if ("receipts" in op) {
          if (!Array.isArray(op.receipts)) throw new Error("invalid receipt reservations");
          for (const value of op.receipts) {
            const receipt = record(value); fields(receipt, ["id", "revision"], ["key"]); identifier(receipt.id); revision(receipt.revision);
            if (reserved.has(receipt.id)) throw new Error("duplicate receipt reservation"); reserved.add(receipt.id);
            if ("key" in receipt) {
              if (typeof receipt.key !== "string" || !RECEIPT_KEY.test(receipt.key) || receiptKeys.has(receipt.key)) throw new Error("invalid receipt key reservation");
              receiptKeys.add(receipt.key);
            }
          }
        }
      } else if (op.kind === "hold") { identifier(op.holdId); if (typeof op.active !== "boolean" || erased.has(op.itemId)) throw new Error("invalid memory hold"); }
      else throw new Error("invalid memory control operation");
    }
    if ([...reserved].some(id => ids.has(id))) throw new Error("control and memory operation identity conflict");
    return row as unknown as Control;
  }
  private publishControl(keys: CryptoShredKeyStore, control: Control, onRename: () => void): void {
    const bytes = Buffer.from(JSON.stringify(seal(keys, this.controlKey(control.partitionKey), control)));
    if (bytes.length > MAX_BYTES) throw new Error("memory control is oversized");
    this.writeDocument(this.controlPath, bytes, onRename, true);
  }

  private keys(): CryptoShredKeyStore {
    return new CryptoShredKeyStore(new FileWrappedKeyPersistence({ ...this.options.keyAuthority, requireExistingMasterKey: true, allowStaleTakeover: false }));
  }
  private checkDirectory(): void {
    const stat = lstatSync(this.options.directory);
    if (!stat.isDirectory() || (stat.mode & 0o077) !== 0) throw new Error("memory partition requires an established private directory");
  }
  private readBytes(sync = false): string {
    return this.readPrivateBytes(this.snapshotPath, sync);
  }
  private readPrivateBytes(path: string, sync = false): string {
    const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const stat = fstatSync(fd);
      if (!stat.isFile() || stat.size > MAX_BYTES || (stat.mode & 0o077) !== 0) throw new Error("invalid memory snapshot file");
      const bytes = readFileSync(fd);
      if (bytes.length !== stat.size || bytes.length > MAX_BYTES) throw new Error("memory snapshot changed during read");
      if (sync) fsyncSync(fd);
      return bytes.toString("utf8");
    } finally { closeSync(fd); }
  }
  private load(keys: CryptoShredKeyStore): { key: string; snapshot: Snapshot; operations: Operation[]; entries: PersistedMemoryEntry[]; control?: Control } {
    const envelope = record(JSON.parse(this.readBytes())); fields(envelope, ["schema", "key", "payload"]);
    if (envelope.schema !== "keep.memory.envelope/v1" || typeof envelope.key !== "string" || !PARTITION_KEY.test(envelope.key)) throw new Error("invalid memory envelope");
    const row = record(JSON.parse(keys.decrypt(envelope.key, ciphertext(envelope.payload))));
    fields(row, ["schema", "scope", "revision", "operations", "entries"]);
    if (!["keep.memory.partition/v1", "keep.memory.partition/v2"].includes(String(row.schema)) || canonical(scopeOf(row.scope)) !== canonical(this.options.scope)) throw new Error("memory partition scope mismatch");
    revision(row.revision);
    if (!Array.isArray(row.operations) || !Array.isArray(row.entries) || row.operations.length !== row.revision) throw new Error("invalid memory snapshot");
    const control = this.loadControl(keys, envelope.key), reservations = this.receiptReservations(control);
    const operationIds = new Set<string>();
    const receiptHandles = new Set<string>(), operations: Operation[] = [];
    row.operations.forEach((value, index) => {
      const operation = record(value); identifier(operation.id);
      if (operation.revision !== index + 1 || operationIds.has(operation.id)) throw new Error("invalid memory operation history");
      operationIds.add(operation.id);
      const reserved = reservations.get(operation.id);
      if (reserved && reserved.revision !== operation.revision) throw new Error("receipt reservation revision mismatch");
      if ("receipt" in operation) {
        fields(operation, ["id", "revision", "receipt"]);
        const receipt = record(operation.receipt); fields(receipt, ["key", "dependencies", "payload"]);
        if (typeof receipt.key !== "string" || !RECEIPT_KEY.test(receipt.key) || receiptHandles.has(receipt.key) || !Array.isArray(receipt.dependencies)) throw new Error("invalid sealed receipt");
        receiptHandles.add(receipt.key); receipt.dependencies.forEach(identifier);
        if (new Set(receipt.dependencies).size !== receipt.dependencies.length) throw new Error("duplicate receipt dependency");
        const payload = ciphertext(receipt.payload);
        if (reserved) { if (reserved.key !== receipt.key) throw new Error("receipt reservation key mismatch"); return; }
        const opened = record(JSON.parse(keys.decrypt(receipt.key, payload))); fields(opened, ["schema", "scope", "partitionKey", "operation", "dependencies"]);
        if (opened.schema !== "keep.memory.operation-receipt/v1" || opened.partitionKey !== envelope.key || canonical(scopeOf(opened.scope)) !== canonical(this.options.scope)
          || canonical(opened.dependencies) !== canonical(receipt.dependencies)) throw new Error("receipt binding mismatch");
        const plain = operationOf(opened.operation);
        if (plain.id !== operation.id || plain.revision !== operation.revision) throw new Error("receipt operation identity mismatch");
        operations.push(plain);
      } else {
        const plain = operationOf(operation);
        if (reserved) { if (reserved.key !== undefined) throw new Error("sealed receipt replaced with legacy metadata"); return; }
        operations.push(plain);
      }
    });
    if (control?.operations.some(operation => operationIds.has(operation.id))) throw new Error("control and snapshot operation identity conflict");
    const ids = new Set<string>(); const handles = new Set<string>();
    const lineage = this.lineage(operations, control);
    const erased = new Map(control?.operations.filter(operation => operation.kind === "erase").flatMap(operation => operation.targets!.map(target => [target.id, target] as const)));
    const entries = row.entries.flatMap(value => {
      const sealed = record(value); fields(sealed, ["id", "key", "payload"]); identifier(sealed.id);
      if (typeof sealed.key !== "string" || !ITEM_KEY.test(sealed.key) || ids.has(sealed.id) || handles.has(sealed.key)) throw new Error("invalid memory item identity");
      ids.add(sealed.id); handles.add(sealed.key);
      const erasure = erased.get(sealed.id);
      if (erasure !== undefined) {
        if (erasure.key !== sealed.key) throw new Error("erasure item/key binding mismatch");
        ciphertext(sealed.payload); return [];
      }
      const item = record(JSON.parse(keys.decrypt(sealed.key, ciphertext(sealed.payload)))); fields(item, ["schema", "scope", "entry"]);
      if (item.schema !== "keep.memory.item/v1" || canonical(scopeOf(item.scope)) !== canonical(this.options.scope)) throw new Error("memory item scope mismatch");
      const entry = entryOf(item.entry, this.options.scope);
      if (entry.lesson.id !== sealed.id) throw new Error("memory item binding mismatch");
      if (this.parentsOf(entry.lesson, lineage).some(id => erased.has(id))) throw new Error("unreconciled derivative of erased memory");
      return [entry];
    });
    const byId = new Map(entries.map(entry => [entry.lesson.id, entry.lesson]));
    if (entries.some(entry => entry.lesson.custody?.schema === "keep.memory.derived-custody/v1"
      && memorySourceClosure(entry.lesson, byId) === undefined)) throw new Error("unreconciled memory source lineage");
    return { key: envelope.key, snapshot: row as unknown as Snapshot, operations, entries, ...(control === undefined ? {} : { control }) };
  }
  private publish(keys: CryptoShredKeyStore, key: string, snapshot: Snapshot, onRename: () => void): void {
    const envelope: Envelope = { schema: "keep.memory.envelope/v1", key, payload: seal(keys, key, snapshot) };
    const bytes = Buffer.from(JSON.stringify(envelope));
    if (bytes.length > MAX_BYTES) throw new Error("memory snapshot is oversized");
    this.writeDocument(this.snapshotPath, bytes, onRename);
  }
  private writeDocument(path: string, bytes: Buffer, onRename: () => void, control = false): void {
    const temporary = `${path}.${randomUUID()}.tmp`;
    let fd: number | undefined;
    try {
      this.options.fault?.(control ? "before-control-write" : "before-write");
      fd = openSync(temporary, "wx", 0o600);
      for (let offset = 0; offset < bytes.length;) {
        const written = writeSync(fd, bytes, offset, bytes.length - offset);
        if (written <= 0) throw new Error("memory write made no progress");
        offset += written;
      }
      fsyncSync(fd); closeSync(fd); fd = undefined;
      this.options.fault?.(control ? "before-control-rename" : "before-rename");
      renameSync(temporary, path); onRename();
      this.options.fault?.(control ? "after-control-rename" : "after-rename");
      fsyncDir(NODE_IO, dirname(path));
      this.options.fault?.(control ? "after-control-sync" : "after-directory-sync");
    } finally {
      if (fd !== undefined) { try { closeSync(fd); } catch { /* Preserve the original failure. */ } }
      try { unlinkSync(temporary); } catch { /* Absent after successful rename. */ }
    }
  }
}

/** Server-owned path selection. Each partition has separate established key authority.
 * Construction/open never creates custody; only explicit initialization may do so.
 * The caller must authenticate and resolve the complete scope before invoking this service. */
export class FileMemoryCustody {
  private readonly root: string;
  constructor(root: string) { this.root = resolve(root); }

  partition(scope: MemoryPartitionScope): FileMemoryPartition {
    const captured = scopeOf(structuredClone(scope));
    const locator = createHash("sha256").update(canonical(captured)).digest("hex");
    return new FileMemoryPartition({ directory: join(this.root, "data", locator), scope: captured,
      keyAuthority: { masterKeyPath: join(this.root, "keys", locator, "master.key"), wrappedKeysPath: join(this.root, "keys", locator, "wrapped.json") } });
  }

  initialize(scope: MemoryPartitionScope): MemoryPartitionView {
    const partition = this.partition(scope);
    const privateDirectory = (path: string): void => {
      if (!existsSync(path)) { mkdirSync(path, { mode: 0o700 }); fsyncDir(NODE_IO, dirname(path)); }
      const stat = lstatSync(path);
      if (!stat.isDirectory() || (stat.mode & 0o077) !== 0) throw new Error("memory custody requires a private directory");
    };
    privateDirectory(this.root); privateDirectory(join(this.root, "data")); privateDirectory(join(this.root, "keys"));
    const locator = createHash("sha256").update(canonical(scopeOf(structuredClone(scope)))).digest("hex");
    const keyDirectory = join(this.root, "keys", locator);
    return withSyncFileMutationLock(join(this.root, `${locator}.initialization`), () => {
      // An existing partial key/data pair is never replaced. A successful uncertain
      // initialization can instead be authenticated and fsync-confirmed on retry.
      if (existsSync(keyDirectory) || existsSync(dirname(partition.snapshotPath))) { partition.initializeControl(); return partition.read(true); }
      privateDirectory(keyDirectory);
      new FileWrappedKeyPersistence({ masterKeyPath: join(keyDirectory, "master.key"), wrappedKeysPath: join(keyDirectory, "wrapped.json") });
      partition.initialize();
      return partition.read(true);
    }, { allowStaleTakeover: false });
  }
}
