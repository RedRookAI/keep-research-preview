import { createHash, randomBytes } from "node:crypto";
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { FileSystemLock, type DistributedLock } from "../lock/lock.js";

export const WORK_ATTEMPT_STAGES_V1 = [
  "RESEARCH_PENDING", "RESEARCH_COMPLETE", "VET_1_PASS", "IMPLEMENTING", "CANDIDATE_FROZEN",
  "FULL_TEST_PASS", "VET_2_PASS", "PACKAGE_VERIFIED", "REMOTE_READBACK_PASS", "COMPLETE",
] as const;
export type WorkAttemptStageV1 = typeof WORK_ATTEMPT_STAGES_V1[number];
export const WORK_ATTEMPT_NON_ADVANCING_OUTCOMES_V1 = [
  "FAILURE", "AMBIGUITY", "PROTECTED_WORKLOAD_IMPACT", "SCOPE_CONFLICT", "OWNER_RESERVED_EFFECT",
] as const;
export type WorkAttemptNonAdvancingOutcomeV1 = typeof WORK_ATTEMPT_NON_ADVANCING_OUTCOMES_V1[number];

export interface WorkAttemptFailureLessonV1 { readonly id: string; readonly digest: string }
export type WorkAttemptAuthorityV1 =
  | { readonly kind: "n1"; readonly owner_id: string; readonly custody_id: string; readonly organization_services: "ABSENT" }
  | { readonly kind: "enterprise"; readonly organization_id: string; readonly tenant_id: string; readonly actor_id: string; readonly role_id: string; readonly separation_policy_id: string; readonly custody_id: string; readonly isolation_id: string; readonly custody_evidence_digest: string; readonly isolation_evidence_digest: string; readonly local_owner_substitution: false };
export interface WorkAttemptIdentityV1 {
  readonly project_id: string;
  readonly goal_id: string;
  readonly subgoal_id: string;
  readonly ticket_id: string;
  readonly ticket_body: Readonly<Record<string, unknown>>;
  readonly ticket_body_digest: string;
  readonly failure_lessons: readonly WorkAttemptFailureLessonV1[];
  readonly track: "n1" | "enterprise";
  readonly authority: WorkAttemptAuthorityV1;
  readonly product_commit: string;
  readonly interpreter_identity: string;
}
export interface WorkAttemptReferenceV1 {
  readonly identity_digest: string;
  readonly attempt_id: string;
  readonly generation: number;
}
export interface WorkAttemptTransitionV1 {
  readonly index: number;
  readonly stage: WorkAttemptStageV1;
  readonly outcome: "ADVANCE" | WorkAttemptNonAdvancingOutcomeV1;
  readonly evidence_digest: string;
}
export interface WorkAttemptSnapshotV1 extends WorkAttemptReferenceV1 {
  readonly schema: "keep.work-attempt-authority/v1";
  readonly schema_version: 1;
  readonly identity: WorkAttemptIdentityV1;
  readonly transitions: readonly WorkAttemptTransitionV1[];
}
export interface WorkAttemptFenceV1 {
  readonly reference: WorkAttemptReferenceV1;
  readonly identity: WorkAttemptIdentityV1;
  withCurrent<T>(commit: () => Promise<T>): Promise<T>;
}

export class InvalidWorkAttemptError extends Error { override readonly name = "InvalidWorkAttemptError"; }
export class WorkAttemptConflictError extends Error { override readonly name = "WorkAttemptConflictError"; }
export class StaleWorkAttemptError extends Error { override readonly name = "StaleWorkAttemptError"; }

const HEX = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const ATTEMPT = /^[0-9a-f]{32}$/u;
const TICKET = /^(?:PG|SG)-[0-9]{2}-T[0-9]{3}[A-Z]?$/u;

function plain(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
function canonical(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (!plain(value)) throw new InvalidWorkAttemptError("attempt identity contains a non-JSON value");
  const keys = Object.keys(value).sort();
  if (keys.some((key) => key === "__proto__" || key === "prototype" || key === "constructor")) throw new InvalidWorkAttemptError("attempt identity contains an unsafe key");
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}
const digest = (value: unknown): string => createHash("sha256").update(canonical(value)).digest("hex");
const clone = <T>(value: T): T => JSON.parse(canonical(value)) as T;

function validText(value: unknown): value is string { return typeof value === "string" && value.trim() === value && value.length > 0 && Buffer.byteLength(value,"utf8") <= 1024 && !value.includes("\0"); }
function validateAuthority(track: WorkAttemptIdentityV1["track"], value: unknown): value is WorkAttemptAuthorityV1 {
  if (!plain(value) || value.kind !== track) return false;
  if (track === "n1") return Object.keys(value).sort().join(",") === "custody_id,kind,organization_services,owner_id" && validText(value.owner_id) && validText(value.custody_id) && value.organization_services === "ABSENT";
  return Object.keys(value).sort().join(",") === "actor_id,custody_evidence_digest,custody_id,isolation_evidence_digest,isolation_id,kind,local_owner_substitution,organization_id,role_id,separation_policy_id,tenant_id"
    && validText(value.organization_id) && validText(value.tenant_id) && validText(value.actor_id) && validText(value.role_id) && validText(value.separation_policy_id) && validText(value.custody_id) && validText(value.isolation_id)
    && typeof value.custody_evidence_digest === "string" && HEX.test(value.custody_evidence_digest)
    && typeof value.isolation_evidence_digest === "string" && HEX.test(value.isolation_evidence_digest) && value.local_owner_substitution === false;
}
function validateIdentity(value: unknown): WorkAttemptIdentityV1 {
  if (!plain(value) || Object.keys(value).sort().join(",") !== "authority,failure_lessons,goal_id,interpreter_identity,product_commit,project_id,subgoal_id,ticket_body,ticket_body_digest,ticket_id,track") throw new InvalidWorkAttemptError("attempt identity has an incomplete or unknown field");
  const candidate = value as unknown as WorkAttemptIdentityV1;
  if (![candidate.project_id, candidate.goal_id, candidate.subgoal_id, candidate.interpreter_identity].every(validText) || !TICKET.test(candidate.ticket_id) || !COMMIT.test(candidate.product_commit) || !["n1", "enterprise"].includes(candidate.track)) throw new InvalidWorkAttemptError("attempt identity has an invalid coordinate");
  if (!plain(candidate.ticket_body) || candidate.ticket_body.id !== candidate.ticket_id || !Array.isArray(candidate.ticket_body.requirements) || candidate.ticket_body.requirements.length === 0 || !Array.isArray(candidate.ticket_body.finish_conditions) || candidate.ticket_body.finish_conditions.length === 0 || !plain(candidate.ticket_body.research_contract) || !Array.isArray(candidate.ticket_body.mutation_surface) || candidate.ticket_body.mutation_surface.length === 0 || digest(candidate.ticket_body) !== candidate.ticket_body_digest) throw new InvalidWorkAttemptError("complete ticket body is missing or its digest disagrees");
  if (!Array.isArray(candidate.failure_lessons) || candidate.failure_lessons.length === 0 || candidate.failure_lessons.length > 1024 || candidate.failure_lessons.some((lesson) => !plain(lesson) || Object.keys(lesson).sort().join(",") !== "digest,id" || !validText(lesson.id) || typeof lesson.digest !== "string" || !HEX.test(lesson.digest)) || new Set(candidate.failure_lessons.map((lesson) => lesson.id)).size !== candidate.failure_lessons.length) throw new InvalidWorkAttemptError("failure lessons must be a nonempty unique digest-bound set");
  if (!validateAuthority(candidate.track, candidate.authority)) throw new InvalidWorkAttemptError("track authority is invalid or substituted");
  return clone(candidate);
}
function sameReference(actual: WorkAttemptSnapshotV1, expected: WorkAttemptReferenceV1): boolean {
  return actual.identity_digest === expected.identity_digest && actual.attempt_id === expected.attempt_id && actual.generation === expected.generation;
}
function decodeSnapshot(value: unknown): WorkAttemptSnapshotV1 {
  if (!plain(value) || Object.keys(value).sort().join(",") !== "attempt_id,generation,identity,identity_digest,schema,schema_version,transitions" || value.schema !== "keep.work-attempt-authority/v1" || value.schema_version !== 1 || !ATTEMPT.test(String(value.attempt_id)) || !Number.isSafeInteger(value.generation) || Number(value.generation) < 0 || !Array.isArray(value.transitions)) throw new InvalidWorkAttemptError("durable attempt record is malformed");
  const identity = validateIdentity(value.identity);
  if (value.identity_digest !== digest(identity)) throw new InvalidWorkAttemptError("durable attempt identity digest disagrees");
  const transitions = value.transitions.map((entry, index) => {
    if (!plain(entry) || Object.keys(entry).sort().join(",") !== "evidence_digest,index,outcome,stage" || entry.index !== index || !WORK_ATTEMPT_STAGES_V1.includes(entry.stage as WorkAttemptStageV1) || !(entry.outcome === "ADVANCE" || WORK_ATTEMPT_NON_ADVANCING_OUTCOMES_V1.includes(entry.outcome as WorkAttemptNonAdvancingOutcomeV1)) || !HEX.test(String(entry.evidence_digest))) throw new InvalidWorkAttemptError("durable attempt transition is malformed");
    return clone(entry) as unknown as WorkAttemptTransitionV1;
  });
  return clone({ ...value, identity, transitions } as unknown as WorkAttemptSnapshotV1);
}

export function replayWorkAttemptV1(transitions: readonly WorkAttemptTransitionV1[]): { readonly next_stage: WorkAttemptStageV1 | null; readonly advancing_count: number } {
  let advancing = 0;
  transitions.forEach((transition, index) => {
    if (transition.index !== index || transition.stage !== WORK_ATTEMPT_STAGES_V1[advancing]) throw new InvalidWorkAttemptError("transition history skips or reorders a stage");
    if (transition.outcome === "ADVANCE") advancing += 1;
  });
  return Object.freeze({ next_stage: WORK_ATTEMPT_STAGES_V1[advancing] ?? null, advancing_count: advancing });
}

export class FileWorkAttemptAuthorityV1 {
  readonly #path: string;
  readonly #lock: DistributedLock;
  constructor(readonly directory: string, lock?: DistributedLock) {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const stat = lstatSync(directory); const uid = typeof process.getuid === "function" ? process.getuid() : stat.uid;
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== uid || (stat.mode & 0o077) !== 0) throw new InvalidWorkAttemptError("attempt authority directory must be private and owner-controlled");
    this.#path = join(directory, "active-attempt.json");
    this.#lock = lock ?? new FileSystemLock(join(directory, ".locks"));
  }
  async admit(identityValue: unknown): Promise<WorkAttemptSnapshotV1> {
    const identity = validateIdentity(identityValue);
    return await this.#lock.withLock("active-ticket", async () => {
      if (this.#loadOptional() !== undefined) throw new WorkAttemptConflictError("one active ticket already exists");
      const snapshot: WorkAttemptSnapshotV1 = { schema: "keep.work-attempt-authority/v1", schema_version: 1, identity, identity_digest: digest(identity), attempt_id: randomBytes(16).toString("hex"), generation: 0, transitions: [] };
      this.#write(snapshot); return clone(snapshot);
    });
  }
  load(reference?: WorkAttemptReferenceV1): WorkAttemptSnapshotV1 {
    const snapshot = this.#loadOptional(); if (snapshot === undefined) throw new InvalidWorkAttemptError("durable attempt record is absent");
    if (reference !== undefined && !sameReference(snapshot, reference)) throw new StaleWorkAttemptError("attempt reference is stale or substituted");
    return snapshot;
  }
  async takeover(reference: WorkAttemptReferenceV1): Promise<WorkAttemptSnapshotV1> {
    return await this.#lock.withLock("active-ticket", async () => {
      const current = this.load(reference);
      const next = { ...current, attempt_id: randomBytes(16).toString("hex"), generation: current.generation + 1 };
      this.#write(next); return clone(next);
    });
  }
  fence(reference: WorkAttemptReferenceV1): WorkAttemptFenceV1 {
    const current=this.load(reference),frozen = Object.freeze(clone(reference)),identity=Object.freeze(clone(current.identity));
    return Object.freeze({ reference: frozen, identity, withCurrent: async <T>(commit: () => Promise<T>) => await this.withCurrent(frozen, commit) });
  }
  async withCurrent<T>(reference: WorkAttemptReferenceV1, commit: () => Promise<T>): Promise<T> {
    return await this.#lock.withLock("active-ticket", async () => { this.load(reference); return await commit(); });
  }
  async record(reference: WorkAttemptReferenceV1, stage: WorkAttemptStageV1, outcome: "ADVANCE" | WorkAttemptNonAdvancingOutcomeV1, evidenceDigest: string): Promise<WorkAttemptSnapshotV1> {
    if (!HEX.test(evidenceDigest)) throw new InvalidWorkAttemptError("transition evidence digest is invalid");
    return await this.#lock.withLock("active-ticket", async () => {
      const current = this.load(reference); const replay = replayWorkAttemptV1(current.transitions);
      if (replay.next_stage !== stage) throw new InvalidWorkAttemptError("transition does not target the first unmet stage");
      const transition: WorkAttemptTransitionV1 = { index: current.transitions.length, stage, outcome, evidence_digest: evidenceDigest };
      const next = { ...current, transitions: [...current.transitions, transition] }; replayWorkAttemptV1(next.transitions); this.#write(next); return clone(next);
    });
  }
  #loadOptional(): WorkAttemptSnapshotV1 | undefined {
    let fd: number | undefined; let bytes: Buffer;
    try { fd = openSync(this.#path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); const stat=fstatSync(fd);const uid=typeof process.getuid==="function"?process.getuid():stat.uid;if(!stat.isFile()||stat.uid!==uid||(stat.mode&0o077)!==0)throw new InvalidWorkAttemptError("durable attempt carrier must be private and owner-controlled");bytes=readFileSync(fd); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw error; }
    finally { if(fd!==undefined)closeSync(fd); }
    if (bytes.length > 16 * 1024 * 1024) throw new InvalidWorkAttemptError("durable attempt record exceeds size ceiling");
    return decodeSnapshot(JSON.parse(bytes.toString("utf8")) as unknown);
  }
  #write(snapshot: WorkAttemptSnapshotV1): void {
    const bytes = Buffer.from(`${canonical(decodeSnapshot(snapshot))}\n`, "utf8");
    if(bytes.length>16*1024*1024)throw new InvalidWorkAttemptError("durable attempt record exceeds size ceiling");
    const temporary = join(this.directory, `.active-attempt.${process.pid}.${randomBytes(8).toString("hex")}.tmp`);
    let fd: number | undefined;
    try { fd = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600); writeFileSync(fd, bytes); fsyncSync(fd); closeSync(fd); fd = undefined; renameSync(temporary, this.#path); const dir = openSync(dirname(this.#path), constants.O_RDONLY | constants.O_DIRECTORY); try { fsyncSync(dir); } finally { closeSync(dir); } }
    finally { if (fd !== undefined) closeSync(fd); try{unlinkSync(temporary);}catch{} }
  }
}
