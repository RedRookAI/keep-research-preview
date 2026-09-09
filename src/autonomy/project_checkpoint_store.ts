import { createHash, randomBytes } from "node:crypto";
import { closeSync, constants, fsyncSync, linkSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { decodeProjectState, type ProjectState } from "./project_state.js";
import type { Ciphertext } from "../keystore/keystore.js";
import type { ProjectId } from "../session/project_id.js";
import { isEngineeringStatusProjectionV1, type EngineeringStatusProjectionStoreV1, type EngineeringStatusProjectionV1 } from "../spine/engineering_status_projection_v1.js";
import { ensureDurableDir, fsyncDir, NODE_IO } from "../spine/durable_fs.js";
import { withSyncFileMutationLock } from "../spine/sync_file_mutation_lock.js";
import { StaleWorkAttemptError, type WorkAttemptFenceV1 } from "../spine/work_attempt_authority_v1.js";

export const MAX_PROJECT_CHECKPOINT_BYTES = 16 * 1024 * 1024;

export class ProjectCheckpointConflictError extends Error {
  override readonly name = "ProjectCheckpointConflictError";
}

export interface SavedProjectCheckpoint {
  readonly state: ProjectState;
  readonly canonicalBytes: Uint8Array;
  readonly sha256: string;
}

export interface ProjectCheckpointStore {
  load(runId: string): ProjectState | undefined;
  save(next: ProjectState, expectedRevision: number | undefined): SavedProjectCheckpoint;
}
export interface AttemptFencedProjectCheckpointStore extends ProjectCheckpointStore {
  saveAttempt(next: ProjectState, expectedRevision: number | undefined, fence: WorkAttemptFenceV1): Promise<SavedProjectCheckpoint>;
}
export interface ProjectCheckpointCryptography {
  encrypt(projectId: ProjectId, plaintext: string): Ciphertext;
  decrypt(projectId: ProjectId, ciphertext: Ciphertext): string;
  /** Upgrade-only ownership resolver for checkpoints written before project binding was embedded. */
  projectIdForRun?(runId: string): ProjectId | undefined;
}

function canonicalSnapshot(state: ProjectState): Uint8Array {
  const decoded = decodeProjectState(state);
  const bytes = Buffer.from(JSON.stringify(sortJson(decoded)), "utf8");
  if (bytes.byteLength > MAX_PROJECT_CHECKPOINT_BYTES) throw new RangeError(`project checkpoint exceeds ${MAX_PROJECT_CHECKPOINT_BYTES} bytes`);
  return bytes;
}

function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortJson);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, entry]) => [key, sortJson(entry)]));
  }
  return value;
}

function saved(state: ProjectState): SavedProjectCheckpoint {
  const canonicalBytes = canonicalSnapshot(state);
  return { state, canonicalBytes, sha256: createHash("sha256").update(canonicalBytes).digest("hex") };
}

/** Content identity used by non-owning consumers that reference, but never duplicate, a checkpoint. */
export function projectCheckpointIdentity(state: ProjectState): { readonly runId: string; readonly revision: number; readonly sha256: string } {
  const result = saved(decodeProjectState(state));
  return { runId: result.state.runId, revision: result.state.revision, sha256: result.sha256 };
}

function assertRevision(next: ProjectState, expected: number | undefined, current: ProjectState | undefined): void {
  const actual = current?.revision;
  if (actual !== expected) throw new ProjectCheckpointConflictError(`checkpoint conflict: expected ${String(expected)}, found ${String(actual)}`);
  const required = expected === undefined ? 0 : expected + 1;
  if (next.revision !== required) throw new ProjectCheckpointConflictError(`next revision must be ${required}, got ${next.revision}`);
  if (current !== undefined && current.runId !== next.runId) throw new ProjectCheckpointConflictError("runId cannot change across revisions");
}

export class InMemoryProjectCheckpointStore implements ProjectCheckpointStore {
  readonly #states = new Map<string, ProjectState>();

  load(runId: string): ProjectState | undefined {
    const state = this.#states.get(runId);
    return state === undefined ? undefined : decodeProjectState(JSON.parse(JSON.stringify(state)) as unknown);
  }

  save(next: ProjectState, expectedRevision: number | undefined): SavedProjectCheckpoint {
    const validated = decodeProjectState(next);
    const decoded = decodeProjectState(JSON.parse(JSON.stringify(validated)) as unknown);
    const current = this.#states.get(decoded.runId);
    assertRevision(decoded, expectedRevision, current);
    const result = saved(decoded);
    this.#states.set(decoded.runId, decoded);
    return result;
  }
}

/** Atomic local adapter for n=1; enterprise adapters implement the identical CAS interface. */
export class FileProjectCheckpointStore implements AttemptFencedProjectCheckpointStore {
  constructor(readonly directory: string, private readonly cryptography?: ProjectCheckpointCryptography) {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
  }

  load(runId: string): ProjectState | undefined {
    const key = this.fileKey(runId);
    const candidates = readdirSync(this.directory)
      .filter((name) => name === `${key}.json` || (name.startsWith(`${key}.revision-`) && name.endsWith(".json")))
      .map((name) => {
        try { return this.readCandidate(join(this.directory, name)); }
        catch (error) {
          // Another successful writer may remove an obsolete revision marker after
          // readdir but before open. Only that disappearance is retryable; malformed,
          // unsafe, or unreadable carriers remain hard failures.
          if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
          throw error;
        }
      })
      .filter((candidate): candidate is ProjectState => candidate !== undefined);
    if (candidates.length === 0) return undefined;
    if (candidates.some((candidate) => candidate.runId !== runId)) throw new Error("checkpoint filename disagrees with its runId");
    candidates.sort((a, b) => b.revision - a.revision);
    const latest = candidates[0]!;
    for (const candidate of candidates) {
      if (candidate.revision === latest.revision && JSON.stringify(candidate) !== JSON.stringify(latest)) throw new Error(`conflicting checkpoint payloads at revision ${latest.revision}`);
    }
    return latest;
  }

  save(next: ProjectState, expectedRevision: number | undefined): SavedProjectCheckpoint {
    const decoded = decodeProjectState(next);
    const current = this.load(decoded.runId);
    assertRevision(decoded, expectedRevision, current);
    const result = saved(decoded);
    const destination = this.pathFor(decoded.runId);
    const key = this.fileKey(decoded.runId);
    const marker = join(this.directory, `${key}.revision-${decoded.revision}.json`);
    const temporary = join(this.directory, `.${key}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`);
    try {
      let fd: number | undefined;
      try {
        fd = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
        const bytes = this.cryptography === undefined ? result.canonicalBytes : (() => {
          if (decoded.projectId === undefined) throw new Error("encrypted checkpoint storage requires a projectId binding");
          const encrypted = this.cryptography!.encrypt(decoded.projectId, Buffer.from(result.canonicalBytes).toString("utf8"));
          return Buffer.from(JSON.stringify({
            schema: "keep.project-checkpoint-encrypted/v1", projectId: decoded.projectId, runId: decoded.runId, revision: decoded.revision,
            ciphertext: { iv: encrypted.iv, authTag: encrypted.authTag, data: encrypted.data },
          }), "utf8");
        })();
        writeFileSync(fd, bytes);
        fsyncSync(fd);
      } finally {
        if (fd !== undefined) closeSync(fd);
      }
      // link(2) is the cross-process CAS: exactly one writer can create this immutable revision name.
      try { linkSync(temporary, marker); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new ProjectCheckpointConflictError(`checkpoint revision ${decoded.revision} already committed for ${decoded.runId}`);
        throw error;
      }
      renameSync(temporary, destination);
      const dirFd = openSync(dirname(destination), constants.O_RDONLY);
      try { fsyncSync(dirFd); } finally { closeSync(dirFd); }
      if (expectedRevision !== undefined) {
        try { unlinkSync(join(this.directory, `${key}.revision-${expectedRevision}.json`)); } catch { /* current marker remains authoritative */ }
      }
      return result;
    } catch (error) {
      try { unlinkSync(temporary); } catch { /* best effort */ }
      // Once linked, the marker is a committed recovery record even if publishing the convenience
      // snapshot failed. If link returned EEXIST, the marker belongs to the winning writer; this
      // attempt must never unlink it. In either case marker cleanup is forbidden here.
      throw error;
    }
  }

  /** Validate attempt currency and retain that authority until the checkpoint CAS is durable. */
  async saveAttempt(next: ProjectState, expectedRevision: number | undefined, fence: WorkAttemptFenceV1): Promise<SavedProjectCheckpoint> {
    // The identity digest is stable across takeover generations, unlike attempt_id. This lets the
    // winning generation continue the same checkpoint lineage while the fence excludes stale writers.
    if(next.projectId!==fence.identity.project_id||next.runId!==fence.reference.identity_digest)throw new StaleWorkAttemptError("checkpoint project or work identity is substituted");
    return await fence.withCurrent(async () => this.save(next, expectedRevision));
  }

  private readCandidate(path: string): ProjectState {
    const bytes = readFileSync(path);
    if (bytes.byteLength > MAX_PROJECT_CHECKPOINT_BYTES * 3) throw new RangeError(`project checkpoint exceeds encrypted storage ceiling`);
    const parsed = JSON.parse(bytes.toString("utf8")) as unknown;
    if (this.cryptography === undefined) return decodeProjectState(parsed);
    // One-way compatibility for the pre-encryption format. Ownership comes from the durable
    // project->run binding, never from the legacy checkpoint. Its next CAS save is encrypted.
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) && (parsed as Record<string, unknown>)["schema"] !== "keep.project-checkpoint-encrypted/v1") {
      const legacy = decodeProjectState(parsed); const projectId = legacy.projectId ?? this.cryptography.projectIdForRun?.(legacy.runId);
      if (projectId === undefined || (legacy.projectId !== undefined && legacy.projectId !== projectId)) throw new Error("legacy checkpoint has no durable project ownership binding");
      return decodeProjectState({ ...legacy, projectId });
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error("invalid encrypted project checkpoint");
    const row = parsed as Record<string, unknown>;
    if (Object.keys(row).sort().join(",") !== "ciphertext,projectId,revision,runId,schema" || row.schema !== "keep.project-checkpoint-encrypted/v1"
      || typeof row.projectId !== "string" || !/^prj_[0-9a-f]{32}$/u.test(row.projectId) || typeof row.runId !== "string" || !Number.isSafeInteger(row.revision)
      || typeof row.ciphertext !== "object" || row.ciphertext === null || Array.isArray(row.ciphertext)) throw new Error("invalid encrypted project checkpoint");
    const cipher = row.ciphertext as Record<string, unknown>;
    if (Object.keys(cipher).sort().join(",") !== "authTag,data,iv" || typeof cipher.iv !== "string" || !/^[0-9a-f]{24}$/iu.test(cipher.iv)
      || typeof cipher.authTag !== "string" || !/^[0-9a-f]{32}$/iu.test(cipher.authTag) || typeof cipher.data !== "string" || !/^[0-9a-f]*$/iu.test(cipher.data)) throw new Error("invalid encrypted project checkpoint ciphertext");
    const plaintext = this.cryptography.decrypt(row.projectId as ProjectId, cipher as unknown as Ciphertext);
    const state = decodeProjectState(JSON.parse(plaintext) as unknown);
    if (state.projectId !== row.projectId || state.runId !== row.runId || state.revision !== row.revision) throw new Error("encrypted checkpoint envelope disagrees with authenticated state");
    return state;
  }

  private fileKey(runId: string): string {
    if (runId.length === 0 || Buffer.byteLength(runId, "utf8") > 1024) throw new RangeError("runId must be bounded non-empty text");
    return createHash("sha256").update("keep.project-checkpoint/v1\0").update(runId, "utf8").digest("hex");
  }

  private pathFor(runId: string): string {
    return join(this.directory, `${this.fileKey(runId)}.json`);
  }
}

/** Atomic cache for event-derived lifecycle status; absence never prevents checkpoint recovery. */
export class FileEngineeringStatusProjectionStoreV1 implements EngineeringStatusProjectionStoreV1 {
  constructor(readonly directory:string){ensureDurableDir(NODE_IO,directory);}
  load(projectId:string):EngineeringStatusProjectionV1|undefined{
    const path=this.pathFor(projectId);let bytes:Buffer;try{bytes=readFileSync(path);}catch(error){if((error as NodeJS.ErrnoException).code==="ENOENT")return undefined;throw error;}
    if(bytes.byteLength>MAX_PROJECT_CHECKPOINT_BYTES)throw new Error("engineering status projection exceeds storage ceiling");
    let value:unknown;try{value=JSON.parse(bytes.toString("utf8"));}catch{throw new Error("invalid engineering status projection");}
    if(!isEngineeringStatusProjectionV1(value)||value.project_id!==projectId)throw new Error("invalid engineering status projection");return value;
  }
  compareAndSave(projectId:string,expectedDigest:string|null,projection:EngineeringStatusProjectionV1):boolean{
    if(projection.project_id!==projectId||!isEngineeringStatusProjectionV1(projection))return false;const path=this.pathFor(projectId);
    return withSyncFileMutationLock(path,()=>{const current=this.load(projectId);if((current?.projection_digest??null)!==expectedDigest)return false;
      const bytes=Buffer.from(`${JSON.stringify(projection)}\n`,"utf8");if(bytes.byteLength>MAX_PROJECT_CHECKPOINT_BYTES)throw new Error("engineering status projection exceeds storage ceiling");
      const temporary=`${path}.tmp-${process.pid}-${randomBytes(8).toString("hex")}`;let fd:number|undefined;try{fd=openSync(temporary,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY,0o600);writeFileSync(fd,bytes);fsyncSync(fd);closeSync(fd);fd=undefined;renameSync(temporary,path);fsyncDir(NODE_IO,this.directory);return true;}catch(error){if(fd!==undefined)try{closeSync(fd);}catch{}try{unlinkSync(temporary);}catch{}throw error;}});
  }
  private pathFor(projectId:string):string{if(projectId.length===0||Buffer.byteLength(projectId,"utf8")>1024)throw new Error("invalid projection projectId");return join(this.directory,`${createHash("sha256").update("keep.engineering-status-projection/v1\0").update(projectId).digest("hex")}.json`);}
}
