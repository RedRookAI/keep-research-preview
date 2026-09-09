import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync, closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync,
  readFileSync, realpathSync, renameSync, rmSync, statSync, unlinkSync, writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

import type { GitAdapter } from "../infra/git_adapter.js";
import { appraiseGitMutationControlPlane, pinnedFetchOperand, pinnedPushOperand, resolvePinnedRemoteTransport } from "../git/pinned_remote.js";
import { FileSystemLock } from "../lock/lock.js";
import type { WorkAttemptFenceV1, WorkAttemptSnapshotV1 } from "../spine/work_attempt_authority_v1.js";
import type { YoloTicketCoordinatorInputV1, YoloTicketStepResultV1 } from "../autonomy/yolo_ticket_coordinator_v1.js";
import { YoloTicketCoordinatorV1 } from "../autonomy/yolo_ticket_coordinator_v1.js";

const HEX = /^[0-9a-f]{64}$/u;
const GIT_OID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const CREDENTIAL_COMPONENT = /^(?:\.env(?:\..+)?|credentials?(?:\..+)?|secrets?(?:\..+)?|id_(?:rsa|dsa|ecdsa|ed25519)|.*\.(?:pem|key|p12|pfx))$/i;
const RAW_CREDENTIAL = /(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bgh[opusr]_[A-Za-z0-9_]{20,}\b|\bsk-[A-Za-z0-9_-]{20,}\b)/;
const EXCLUDED_COMPONENT = /^(?:\.git|node_modules|vendor|dist|build|coverage|\.cache|cache|caches|target|scratch|tmp|temp)$/iu;
const ARCHIVE = /\.(?:tar|tar\.gz|tgz|zip|7z|rar)$/iu;

export interface HourlyWipFileV1 {
  readonly path: string;
  readonly dirty_status: string;
  readonly worktree: { readonly mode: number; readonly sha256: string; readonly content_base64: string } | null;
  readonly index: { readonly mode: number; readonly sha256: string; readonly content_base64: string } | null;
}

export interface HourlyWipSnapshotV1 {
  readonly schema: "keep.hourly-wip/v1";
  readonly schema_version: 1;
  readonly status: "WIP_UNVERIFIED";
  readonly job_id: string;
  readonly hour_bucket_utc: number;
  readonly base_commit: string;
  readonly recovery_ref: string;
  readonly attempt: {
    readonly identity_digest: string;
    readonly attempt_id: string;
    readonly generation: number;
    readonly track: "n1" | "enterprise";
    readonly authority: WorkAttemptSnapshotV1["identity"]["authority"];
    readonly product_commit: string;
    readonly interpreter_identity: string;
  };
  readonly allowlist: readonly string[];
  readonly files: readonly HourlyWipFileV1[];
  readonly excluded_ignored: readonly { readonly class: string; readonly count: number }[];
  readonly dirty: true;
  readonly last_result: string;
  readonly first_known_failure: string | null;
  readonly test_status: "NOT_RUN_WIP";
  readonly next_action: string;
  readonly recovery_set_complete: true;
  readonly manifest_sha256: string;
}

export interface CaptureHourlyWipRequestV1 {
  readonly project_root: string;
  readonly git: GitAdapter;
  readonly attempt: WorkAttemptSnapshotV1;
  readonly base_commit: string;
  readonly recovery_ref: string;
  readonly hour_bucket_utc: number;
  readonly allowlist: readonly string[];
  readonly last_result: string;
  readonly first_known_failure?: string | null;
  readonly next_action: string;
  readonly max_files?: number;
  readonly max_file_bytes?: number;
  readonly max_total_bytes?: number;
}

export interface PreparedWipPublicationV1 {
  readonly schema_version: 1;
  readonly job_id: string;
  readonly snapshot_sha256: string;
  readonly recovery_ref: string;
  readonly commit_oid: string;
  readonly expected_remote_oid: string | null;
  readonly repository_path: string;
}

export interface WipRemoteReadbackV1 {
  readonly commit_oid: string;
  readonly snapshot: HourlyWipSnapshotV1;
}

export interface WipRestoreExpectationV1 { readonly attempt: HourlyWipSnapshotV1["attempt"] }

/** The seam exists so C07 can deterministically inject outage/ambiguity without network. */
export interface WipPublicationPortV1 {
  prepare(snapshot: HourlyWipSnapshotV1): Promise<PreparedWipPublicationV1>;
  publish(prepared: PreparedWipPublicationV1): Promise<void>;
  readBack(prepared: PreparedWipPublicationV1): Promise<WipRemoteReadbackV1>;
  recover(recoveryRef: string, expected: WipRestoreExpectationV1): Promise<WipRemoteReadbackV1>;
  release(prepared: PreparedWipPublicationV1): Promise<void>;
  materialize(readback: WipRemoteReadbackV1, targetRoot: string, expected: WipRestoreExpectationV1): Promise<void>;
}

export type HourlyWipTickResultV1 =
  | { readonly status: "CLEAN" }
  | { readonly status: "COALESCED"; readonly job_id: string; readonly commit_oid: string }
  | { readonly status: "REMOTE_VERIFIED"; readonly job_id: string; readonly commit_oid: string; readonly snapshot_sha256: string }
  | { readonly status: "FAILED_VISIBLE"; readonly job_id: string; readonly first_failure: string; readonly next_action: "RETRY_SAME_JOB" };

interface JobRecordV1 {
  readonly schema_version: 1;
  readonly job_id: string;
  readonly status: "CAPTURED" | "PREPARED" | "FAILED_VISIBLE" | "REMOTE_VERIFIED";
  readonly snapshot: HourlyWipSnapshotV1 | null;
  readonly prepared: PreparedWipPublicationV1 | null;
  readonly first_failure: string | null;
  readonly commit_oid: string | null;
}

function decodeJobRecordV1(value: unknown, expectedId: string): JobRecordV1 {
  if (!plain(value) || !exactKeys(value, ["schema_version", "job_id", "status", "snapshot", "prepared", "first_failure", "commit_oid"]) || value.schema_version !== 1 || value.job_id !== expectedId || !["CAPTURED", "PREPARED", "FAILED_VISIBLE", "REMOTE_VERIFIED"].includes(String(value.status))) throw new Error("WIP durable job state is invalid");
  if (!(value.first_failure === null || typeof value.first_failure === "string") || !(value.commit_oid === null || typeof value.commit_oid === "string" && GIT_OID.test(value.commit_oid))) throw new Error("WIP durable job state is invalid");
  const snapshot = value.snapshot;
  if (!(snapshot === null || verifyHourlyWipSnapshotV1(snapshot as HourlyWipSnapshotV1))) throw new Error("WIP durable job state is invalid");
  if (snapshot !== null && (snapshot as HourlyWipSnapshotV1).job_id !== expectedId) throw new Error("WIP durable job state is invalid");
  const prepared = value.prepared;
  if (prepared !== null && (!plain(prepared) || !exactKeys(prepared, ["schema_version", "job_id", "snapshot_sha256", "recovery_ref", "commit_oid", "expected_remote_oid", "repository_path"]) || prepared.schema_version !== 1 || prepared.job_id !== expectedId || typeof prepared.snapshot_sha256 !== "string" || !HEX.test(prepared.snapshot_sha256) || typeof prepared.recovery_ref !== "string" || typeof prepared.commit_oid !== "string" || !GIT_OID.test(prepared.commit_oid) || !(prepared.expected_remote_oid === null || typeof prepared.expected_remote_oid === "string" && GIT_OID.test(prepared.expected_remote_oid)) || typeof prepared.repository_path !== "string" || !isAbsolute(prepared.repository_path))) throw new Error("WIP durable job state is invalid");
  if (prepared !== null && (snapshot === null || prepared.snapshot_sha256 !== (snapshot as HourlyWipSnapshotV1).manifest_sha256 || prepared.recovery_ref !== (snapshot as HourlyWipSnapshotV1).recovery_ref)) throw new Error("WIP durable job state is invalid");
  if (value.status === "CAPTURED" && (snapshot === null || prepared !== null || value.commit_oid !== null) || value.status === "PREPARED" && (snapshot === null || prepared === null || value.commit_oid !== null) || value.status === "FAILED_VISIBLE" && value.first_failure === null || value.status === "REMOTE_VERIFIED" && (snapshot !== null || prepared !== null || value.commit_oid === null)) throw new Error("WIP durable job state is invalid");
  return freeze(value as unknown as JobRecordV1);
}

const canonicalValue = (value: unknown): unknown => Array.isArray(value) ? value.map(canonicalValue)
  : value !== null && typeof value === "object" ? Object.fromEntries(Object.keys(value as Record<string, unknown>).sort().map((key) => [key, canonicalValue((value as Record<string, unknown>)[key])])) : value;
const canonical = (value: unknown): string => JSON.stringify(canonicalValue(value));
const sha256 = (value: string | Uint8Array): string => createHash("sha256").update(value).digest("hex");
const plain = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
const exactKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean => Object.keys(value).sort().join(",") === [...keys].sort().join(",");
const freeze = <T>(value: T): T => {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) freeze(child);
  }
  return value;
};
const text = (value: unknown, label: string, max = 4096): string => {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || value.includes("\0") || Buffer.byteLength(value, "utf8") > max) throw new Error(`${label} is invalid`);
  return value;
};
const safePath = (value: string): boolean => value !== "" && !isAbsolute(value) && !value.split("/").some((part) => part === "" || part === "." || part === ".." || part === ".git");
const under = (path: string, root: string): boolean => path === root || path.startsWith(`${root}/`);
const excludedClass = (path: string): string | null => {
  const component = path.split("/").find((part) => EXCLUDED_COMPONENT.test(part));
  if (component !== undefined) return component.toLowerCase();
  return ARCHIVE.test(path) ? "archive" : null;
};
const secretPath = (path: string): boolean => path.split("/").some((part) => CREDENTIAL_COMPONENT.test(part));
const jobId = (attempt: WorkAttemptSnapshotV1, hour: number): string => `wip_${sha256(canonical({ identity_digest: attempt.identity_digest, attempt_id: attempt.attempt_id, generation: attempt.generation, hour })).slice(0, 40)}`;
const recoveryRef = (attempt: WorkAttemptSnapshotV1): string => `refs/heads/keep-wip/${attempt.identity.track}/${attempt.identity_digest}`;
const RECOVERY_REF = /^refs\/heads\/keep-wip\/(?:n1|enterprise)\/[0-9a-f]{64}$/u;

function validatePrepared(value: PreparedWipPublicationV1): void {
  if (!plain(value) || !exactKeys(value, ["schema_version", "job_id", "snapshot_sha256", "recovery_ref", "commit_oid", "expected_remote_oid", "repository_path"]) || value.schema_version !== 1 || !/^wip_[0-9a-f]{40}$/u.test(value.job_id) || !HEX.test(value.snapshot_sha256) || !RECOVERY_REF.test(value.recovery_ref) || !GIT_OID.test(value.commit_oid) || !(value.expected_remote_oid === null || GIT_OID.test(value.expected_remote_oid)) || !isAbsolute(value.repository_path)) throw new Error("prepared WIP publication is invalid");
}

function stableFile(path: string, maxBytes: number): { readonly bytes: Buffer; readonly mode: number } {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.size > maxBytes || (before.mode & 0o7000) !== 0) throw new Error("WIP file kind, mode, or size refused");
    const bytes = readFileSync(fd);
    const after = fstatSync(fd);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mode !== after.mode || bytes.length !== before.size) throw new Error("WIP file changed during capture");
    return { bytes, mode: before.mode & 0o7777 };
  } finally { closeSync(fd); }
}

function requireDirectoryParents(root: string, path: string): void {
  const parts = path.split("/"); let current = root;
  for (const part of parts.slice(0, -1)) {
    current = join(current, part); if (!existsSync(current)) return;
    const stat = lstatSync(current); if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("WIP path parent is not a real directory");
  }
}

function parsePorcelain(bytes: Buffer): readonly { readonly status: string; readonly path: string }[] {
  const parts = bytes.toString("utf8").split("\0").filter(Boolean);
  return parts.map((entry) => {
    if (entry.length < 4 || entry[2] !== " ") throw new Error("Git status record is malformed or contains a rename");
    const status = entry.slice(0, 2); const rawPath = entry.slice(3); const path = rawPath.replace(/\/$/u, "");
    if (!safePath(path) || Buffer.from(path, "utf8").toString("utf8") !== path) throw new Error("Git status path is unsafe");
    return { status, path };
  });
}

async function indexEntry(git: GitAdapter, path: string, maxBytes: number): Promise<HourlyWipFileV1["index"]> {
  const listed = (await git.gitInput(["ls-files", "-s", "-z", "--", `:(literal)${path}`], { maxOutputBytes: 1024 * 1024 })).stdout.toString("utf8").split("\0").filter(Boolean);
  if (listed.length === 0) return null;
  if (listed.length !== 1) throw new Error("unmerged index state cannot be represented by WIP v1");
  const match = /^(\d{6}) ([0-9a-f]{40,64}) 0\t([^\0]+)$/u.exec(listed[0]!);
  if (match === null || match[3] !== path) throw new Error("index entry is malformed");
  const bytes = (await git.gitInput(["cat-file", "blob", match[2]!], { maxOutputBytes: maxBytes + 1 })).stdout;
  if (bytes.length > maxBytes) throw new Error("WIP index file exceeds maxFileBytes");
  return { mode: Number.parseInt(match[1]!, 8), sha256: sha256(bytes), content_base64: bytes.toString("base64") };
}

export async function captureHourlyWipV1(request: CaptureHourlyWipRequestV1): Promise<HourlyWipSnapshotV1 | null> {
  const root = realpathSync(request.project_root);
  if (realpathSync(request.git.workingDirectory()) !== root) throw new Error("WIP Git root differs from declared project root");
  if (!GIT_OID.test(request.base_commit) || request.attempt.identity.product_commit !== request.base_commit || (await request.git.git(["rev-parse", "--verify", "HEAD^{commit}"])).stdout.trim() !== request.base_commit) throw new Error("WIP base commit differs from attempt or canonical HEAD");
  if (!Number.isSafeInteger(request.hour_bucket_utc) || request.hour_bucket_utc < 0) throw new Error("WIP hour bucket is invalid");
  if (request.recovery_ref !== recoveryRef(request.attempt)) throw new Error("WIP recovery ref is not the closed attempt ref");
  const allowlist = [...new Set(request.allowlist.map((path) => text(path, "WIP allowlist path")))].sort();
  if (allowlist.length === 0 || allowlist.some((path) => !safePath(path) || excludedClass(path) !== null || secretPath(path))) throw new Error("WIP allowlist is empty or unsafe");
  const maxFiles = request.max_files ?? 10_000;
  const maxFileBytes = request.max_file_bytes ?? 4 * 1024 * 1024;
  const maxTotalBytes = request.max_total_bytes ?? 16 * 1024 * 1024;
  if (![maxFiles, maxFileBytes, maxTotalBytes].every((n) => Number.isSafeInteger(n) && n > 0)) throw new Error("WIP resource limit is invalid");
  const status = parsePorcelain((await request.git.gitInput(["status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames"], { maxOutputBytes: 16 * 1024 * 1024 })).stdout);
  if (status.length === 0) return null;
  if (new Set(status.map((entry) => entry.path)).size !== status.length) throw new Error("WIP changed path has multiple incompatible Git records");
  const ignored = parsePorcelain((await request.git.gitInput(["status", "--porcelain=v1", "-z", "--ignored=matching", "--untracked-files=normal", "--no-renames"], { maxOutputBytes: 16 * 1024 * 1024 })).stdout).filter((entry) => entry.status === "!!");
  if (ignored.length > maxFiles) throw new Error("WIP ignored-path summary exceeds maxFiles");
  const files: HourlyWipFileV1[] = [];
  let total = 0;
  for (const entry of status) {
    const excluded = excludedClass(entry.path);
    if (excluded !== null) throw new Error(`WIP changed path is excluded (${excluded})`);
    if (secretPath(entry.path)) throw new Error("WIP credential path refused");
    if (!allowlist.some((allowed) => under(entry.path, allowed))) throw new Error("WIP changed path falls outside the explicit allowlist");
    if (files.length >= maxFiles) throw new Error("WIP capture exceeds maxFiles");
    const absolute = resolve(root, ...entry.path.split("/"));
    const rel = relative(root, absolute);
    if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error("WIP path escapes project root");
    requireDirectoryParents(root, entry.path);
    let worktree: HourlyWipFileV1["worktree"] = null;
    if (!entry.status.includes("D") && !existsSync(absolute)) throw new Error("WIP non-delete path vanished during capture");
    if (!entry.status.includes("D")) {
      const read = stableFile(absolute, maxFileBytes);
      if (RAW_CREDENTIAL.test(read.bytes.toString("utf8"))) throw new Error("WIP credential content refused");
      total += read.bytes.length;
      worktree = { mode: read.mode, sha256: sha256(read.bytes), content_base64: read.bytes.toString("base64") };
    }
    const index = entry.status === "??" ? null : await indexEntry(request.git, entry.path, maxFileBytes);
    if (index !== null) {
      const bytes = Buffer.from(index.content_base64, "base64");
      if (RAW_CREDENTIAL.test(bytes.toString("utf8"))) throw new Error("WIP credential content refused");
      total += bytes.length;
    }
    if (total > maxTotalBytes) throw new Error("WIP capture exceeds maxTotalBytes");
    files.push(freeze({ path: entry.path, dirty_status: entry.status, worktree, index }));
  }
  const ignoredClasses = ignored.map((entry) => {
    const classification = excludedClass(entry.path);
    if (classification === null && allowlist.some((allowed) => under(entry.path.replace(/\/$/u, ""), allowed))) throw new Error("ignored content inside the WIP allowlist makes recovery incomplete");
    return secretPath(entry.path) ? "credential-path-redacted" : classification ?? "outside-allowlist";
  });
  const excludedIgnored = [...new Set(ignoredClasses)].sort().map((classification) => freeze({ class: classification, count: ignoredClasses.filter((value) => value === classification).length }));
  files.sort((a, b) => a.path.localeCompare(b.path));
  const attempt = request.attempt;
  const body = {
    schema: "keep.hourly-wip/v1" as const, schema_version: 1 as const, status: "WIP_UNVERIFIED" as const,
    job_id: jobId(attempt, request.hour_bucket_utc), hour_bucket_utc: request.hour_bucket_utc,
    base_commit: request.base_commit, recovery_ref: request.recovery_ref,
    attempt: { identity_digest: attempt.identity_digest, attempt_id: attempt.attempt_id, generation: attempt.generation,
      track: attempt.identity.track, authority: attempt.identity.authority, product_commit: attempt.identity.product_commit,
      interpreter_identity: attempt.identity.interpreter_identity },
    allowlist, files, excluded_ignored: excludedIgnored, dirty: true as const,
    last_result: text(request.last_result, "WIP last result"), first_known_failure: request.first_known_failure === undefined || request.first_known_failure === null ? null : text(request.first_known_failure, "WIP first failure"),
    test_status: "NOT_RUN_WIP" as const, next_action: text(request.next_action, "WIP next action"), recovery_set_complete: true as const,
  };
  return freeze({ ...body, manifest_sha256: sha256(canonical(body)) });
}

export function verifyHourlyWipSnapshotV1(value: HourlyWipSnapshotV1): boolean {
  try {
    if (!plain(value) || !exactKeys(value, ["schema", "schema_version", "status", "job_id", "hour_bucket_utc", "base_commit", "recovery_ref", "attempt", "allowlist", "files", "excluded_ignored", "dirty", "last_result", "first_known_failure", "test_status", "next_action", "recovery_set_complete", "manifest_sha256"])) return false;
    if (!plain(value.attempt) || !exactKeys(value.attempt, ["identity_digest", "attempt_id", "generation", "track", "authority", "product_commit", "interpreter_identity"])) return false;
    if (!HEX.test(value.attempt.identity_digest) || !/^[0-9a-f]{32}$/u.test(value.attempt.attempt_id) || !Number.isSafeInteger(value.attempt.generation) || value.attempt.generation < 0 || !["n1", "enterprise"].includes(value.attempt.track) || !GIT_OID.test(value.attempt.product_commit)) return false;
    const authority: Record<string, unknown> = value.attempt.authority;
    if (!plain(authority) || authority.kind !== value.attempt.track || (value.attempt.track === "n1"
      ? !exactKeys(authority, ["kind", "owner_id", "custody_id", "organization_services"]) || authority.organization_services !== "ABSENT"
      : !exactKeys(authority, ["kind", "organization_id", "tenant_id", "actor_id", "role_id", "separation_policy_id", "custody_id", "isolation_id", "custody_evidence_digest", "isolation_evidence_digest", "local_owner_substitution"]) || authority.local_owner_substitution !== false || !HEX.test(String(authority.custody_evidence_digest)) || !HEX.test(String(authority.isolation_evidence_digest)))) return false;
    if (Object.entries(authority).some(([key, item]) => key !== "local_owner_substitution" && (typeof item !== "string" || item.length === 0 || item.trim() !== item || item.includes("\0")))) return false;
    if (value.schema !== "keep.hourly-wip/v1" || value.schema_version !== 1 || value.status !== "WIP_UNVERIFIED" || !HEX.test(value.manifest_sha256) || !GIT_OID.test(value.base_commit) || value.base_commit !== value.attempt.product_commit || value.recovery_ref !== `refs/heads/keep-wip/${value.attempt.track}/${value.attempt.identity_digest}`) return false;
    const expectedJob = `wip_${sha256(canonical({ identity_digest: value.attempt.identity_digest, attempt_id: value.attempt.attempt_id, generation: value.attempt.generation, hour: value.hour_bucket_utc })).slice(0, 40)}`;
    if (value.job_id !== expectedJob || !Number.isSafeInteger(value.hour_bucket_utc) || value.hour_bucket_utc < 0 || !Array.isArray(value.allowlist) || value.allowlist.length === 0 || [...value.allowlist].sort().join("\0") !== value.allowlist.join("\0") || new Set(value.allowlist).size !== value.allowlist.length || value.allowlist.some((path) => typeof path !== "string" || !safePath(path) || excludedClass(path) !== null || secretPath(path))) return false;
    if (!Array.isArray(value.files) || !Array.isArray(value.excluded_ignored) || typeof value.last_result !== "string" || value.last_result.trim() !== value.last_result || value.last_result.length === 0 || typeof value.next_action !== "string" || value.next_action.trim() !== value.next_action || value.next_action.length === 0 || !(value.first_known_failure === null || typeof value.first_known_failure === "string" && value.first_known_failure.trim() === value.first_known_failure && value.first_known_failure.length > 0)) return false;
    const { manifest_sha256: _digest, ...body } = value;
    if (sha256(canonical(body)) !== value.manifest_sha256 || value.test_status !== "NOT_RUN_WIP" || value.recovery_set_complete !== true || value.dirty !== true) return false;
    const seen = new Set<string>();
    for (const file of value.files) {
      if (!plain(file) || !exactKeys(file, ["path", "dirty_status", "worktree", "index"]) || typeof file.path !== "string" || typeof file.dirty_status !== "string" || !/^(?:[ MADRCU?!]{2})$/u.test(file.dirty_status) || file.dirty_status === "  " || file.dirty_status === "!!" || !safePath(file.path) || seen.has(file.path) || excludedClass(file.path) !== null || secretPath(file.path)) return false;
      seen.add(file.path);
      for (const content of [file.worktree, file.index]) if (content !== null) {
        if (!plain(content)) return false;
        const encoded: Record<string, unknown> = content;
        if (!exactKeys(encoded, ["mode", "sha256", "content_base64"]) || !Number.isSafeInteger(encoded.mode) || Number(encoded.mode) < 0 || Number(encoded.mode) > 0o177777 || typeof encoded.sha256 !== "string" || !HEX.test(encoded.sha256) || typeof encoded.content_base64 !== "string") return false;
        const bytes = Buffer.from(encoded.content_base64, "base64");
        if (bytes.toString("base64") !== encoded.content_base64 || sha256(bytes) !== encoded.sha256 || RAW_CREDENTIAL.test(bytes.toString("utf8"))) return false;
      }
    }
    for (const entry of value.excluded_ignored) if (!plain(entry) || !exactKeys(entry, ["class", "count"]) || typeof entry.class !== "string" || entry.class.length === 0 || !Number.isSafeInteger(entry.count) || Number(entry.count) <= 0) return false;
    return value.files.length > 0 && [...value.files].map((file) => file.path).sort().join("\0") === value.files.map((file) => file.path).join("\0");
  } catch { return false; }
}

export interface GitWipPublicationOptionsV1 {
  readonly workspace_root: string;
  readonly remote: string;
  readonly fetch_url: string;
  readonly push_url: string;
  readonly fetch_url_sha256: string;
  readonly push_url_sha256: string;
  readonly git_factory: (root: string) => GitAdapter;
}

export class GitWipPublicationPortV1 implements WipPublicationPortV1 {
  readonly #root: string;
  constructor(readonly options: GitWipPublicationOptionsV1) {
    this.#root = resolve(options.workspace_root); mkdirSync(this.#root, { recursive: true, mode: 0o700 });
    const stat = lstatSync(this.#root); if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) throw new Error("WIP publication workspace must be private");
  }
  async prepare(snapshot: HourlyWipSnapshotV1): Promise<PreparedWipPublicationV1> {
    if (!verifyHourlyWipSnapshotV1(snapshot)) throw new Error("WIP snapshot verification failed before publication");
    const repository = join(this.#root, snapshot.job_id);
    if (existsSync(repository)) {
      const existing = lstatSync(repository); const real = realpathSync(repository); const rel = relative(this.#root, real);
      if (!existing.isDirectory() || existing.isSymbolicLink() || rel !== snapshot.job_id || (existing.mode & 0o077) !== 0) throw new Error("WIP prepared repository collision is unsafe");
      rmSync(real, { recursive: true, force: true });
    }
    mkdirSync(repository, { mode: 0o700 });
    const git = this.options.git_factory(repository);
    await git.git(["init"]); await git.git(["config", "--local", "user.name", "Keep WIP Recovery"]); await git.git(["config", "--local", "user.email", "keep-wip@invalid"]);
    await git.git(["remote", "add", this.options.remote, this.options.fetch_url]);
    await git.git(["remote", "set-url", "--push", this.options.remote, this.options.push_url]);
    const transport = await resolvePinnedRemoteTransport(git, this.options.remote, this.options.fetch_url_sha256, this.options.push_url_sha256);
    await appraiseGitMutationControlPlane(git, repository);
    const fetchUrl = pinnedFetchOperand(transport);
    await git.gitInput(["fetch", "--depth=1", "--no-tags", fetchUrl, snapshot.base_commit], { timeoutMs: 180_000, killProcessGroup: true });
    const base = (await git.git(["rev-parse", "--verify", "FETCH_HEAD^{commit}"])).stdout.trim();
    if (base !== snapshot.base_commit) throw new Error("WIP base fetch returned a substituted commit");
    const remote = await git.gitInput(["ls-remote", "--refs", fetchUrl, snapshot.recovery_ref], { timeoutMs: 180_000, killProcessGroup: true, maxOutputBytes: 64 * 1024 });
    const line = remote.stdout.toString("utf8").trim();
    let expected: string | null = null;
    if (line !== "") {
      const parts = line.split("\t"); if (parts.length !== 2 || parts[1] !== snapshot.recovery_ref || !GIT_OID.test(parts[0]!)) throw new Error("WIP remote observation is malformed");
      expected = parts[0]!; await git.gitInput(["fetch", "--depth=1", "--no-tags", fetchUrl, snapshot.recovery_ref], { timeoutMs: 180_000, killProcessGroup: true });
    }
    const snapshotBytes = Buffer.from(`${canonical(snapshot)}\n`, "utf8");
    const blob = (await git.gitInput(["hash-object", "-w", "--stdin"], { stdin: snapshotBytes })).stdout.toString("ascii").trim();
    const inner = (await git.gitInput(["mktree", "-z"], { stdin: Buffer.from(`100644 blob ${blob}\tsnapshot.json\0`) })).stdout.toString("ascii").trim();
    const baseTree = (await git.git(["rev-parse", `${snapshot.base_commit}^{tree}`])).stdout.trim();
    const rootEntries = (await git.gitInput(["ls-tree", "-z", baseTree])).stdout.toString("utf8").split("\0").filter(Boolean);
    if (rootEntries.some((entry) => entry.endsWith("\t.keep-wip"))) throw new Error("project uses reserved .keep-wip path");
    rootEntries.push(`040000 tree ${inner}\t.keep-wip`);
    const tree = (await git.gitInput(["mktree", "-z"], { stdin: Buffer.from(`${rootEntries.join("\0")}\0`) })).stdout.toString("ascii").trim();
    const parent = expected ?? snapshot.base_commit;
    const commit = (await git.gitInput(["commit-tree", tree, "-p", parent], { stdin: Buffer.from(`Keep WIP ${snapshot.job_id}\n`) })).stdout.toString("ascii").trim();
    if (!GIT_OID.test(commit)) throw new Error("WIP commit-tree returned an invalid object ID");
    return freeze({ schema_version: 1, job_id: snapshot.job_id, snapshot_sha256: snapshot.manifest_sha256, recovery_ref: snapshot.recovery_ref, commit_oid: commit, expected_remote_oid: expected, repository_path: repository });
  }
  async publish(prepared: PreparedWipPublicationV1): Promise<void> {
    validatePrepared(prepared);
    const git = this.#preparedGit(prepared); const transport = await resolvePinnedRemoteTransport(git, this.options.remote, this.options.fetch_url_sha256, this.options.push_url_sha256);
    await appraiseGitMutationControlPlane(git, prepared.repository_path);
    const expect = prepared.expected_remote_oid ?? "";
    await git.gitInput(["push", "--porcelain", `--force-with-lease=${prepared.recovery_ref}:${expect}`, pinnedPushOperand(transport), `${prepared.commit_oid}:${prepared.recovery_ref}`], { timeoutMs: 20_000, killProcessGroup: true, maxOutputBytes: 1024 * 1024 });
  }
  async readBack(prepared: PreparedWipPublicationV1): Promise<WipRemoteReadbackV1> {
    validatePrepared(prepared);
    return await this.#readRemote(prepared.recovery_ref, { commit_oid: prepared.commit_oid, job_id: prepared.job_id, snapshot_sha256: prepared.snapshot_sha256 });
  }
  async recover(recoveryRefValue: string, expected: WipRestoreExpectationV1): Promise<WipRemoteReadbackV1> {
    const expectedRef = `refs/heads/keep-wip/${expected.attempt.track}/${expected.attempt.identity_digest}`;
    if (!RECOVERY_REF.test(recoveryRefValue) || recoveryRefValue !== expectedRef) throw new Error("WIP recovery ref differs from expected attempt");
    return await this.#readRemote(recoveryRefValue, { attempt: expected.attempt });
  }
  async #readRemote(recoveryRefValue: string, expected: { readonly commit_oid?: string; readonly job_id?: string; readonly snapshot_sha256?: string; readonly attempt?: HourlyWipSnapshotV1["attempt"] }): Promise<WipRemoteReadbackV1> {
    if (!RECOVERY_REF.test(recoveryRefValue)) throw new Error("WIP recovery ref is invalid");
    const repository = join(this.#root, `readback-${randomBytes(12).toString("hex")}`); mkdirSync(repository, { mode: 0o700 });
    try {
      const git = this.options.git_factory(repository); await this.#configureRemote(git); await appraiseGitMutationControlPlane(git, repository);
      const transport = await resolvePinnedRemoteTransport(git, this.options.remote, this.options.fetch_url_sha256, this.options.push_url_sha256);
      await git.gitInput(["fetch", "--depth=1", "--no-tags", pinnedFetchOperand(transport), recoveryRefValue], { timeoutMs: 180_000, killProcessGroup: true });
      const commit = (await git.git(["rev-parse", "--verify", "FETCH_HEAD^{commit}"])).stdout.trim();
      if (expected.commit_oid !== undefined && commit !== expected.commit_oid) throw new Error("WIP remote ref differs from prepared commit");
      const bytes = (await git.gitInput(["show", `${commit}:.keep-wip/snapshot.json`], { maxOutputBytes: 32 * 1024 * 1024 })).stdout;
      const snapshot = JSON.parse(bytes.toString("utf8")) as HourlyWipSnapshotV1;
      if (!verifyHourlyWipSnapshotV1(snapshot) || snapshot.recovery_ref !== recoveryRefValue || expected.job_id !== undefined && snapshot.job_id !== expected.job_id || expected.snapshot_sha256 !== undefined && snapshot.manifest_sha256 !== expected.snapshot_sha256 || expected.attempt !== undefined && canonical(snapshot.attempt) !== canonical(expected.attempt)) throw new Error("WIP remote snapshot failed independent verification");
      await git.gitInput(["fetch", "--depth=1", "--no-tags", pinnedFetchOperand(transport), snapshot.base_commit], { timeoutMs: 180_000, killProcessGroup: true });
      if ((await git.git(["rev-parse", "--verify", "FETCH_HEAD^{commit}"])).stdout.trim() !== snapshot.base_commit) throw new Error("WIP remote base readback differs from the manifest");
      return freeze({ commit_oid: commit, snapshot });
    } finally { rmSync(repository, { recursive: true, force: true }); }
  }
  async release(prepared: PreparedWipPublicationV1): Promise<void> {
    validatePrepared(prepared); const declared = resolve(prepared.repository_path); if (declared !== join(this.#root, prepared.job_id)) throw new Error("prepared WIP repository escapes its workspace");
    if (!existsSync(declared)) return;
    const path = realpathSync(declared); const rel = relative(this.#root, path);
    if (rel !== prepared.job_id) throw new Error("prepared WIP repository escapes its workspace");
    rmSync(path, { recursive: true, force: true });
  }
  async materialize(readback: WipRemoteReadbackV1, targetRoot: string, expected: WipRestoreExpectationV1): Promise<void> {
    if (!isAbsolute(targetRoot) || existsSync(targetRoot) || !verifyHourlyWipSnapshotV1(readback.snapshot) || !GIT_OID.test(readback.commit_oid) || canonical(readback.snapshot.attempt) !== canonical(expected.attempt)) throw new Error("WIP restore requires an absent target, valid snapshot, and exact expected attempt");
    const parent = dirname(targetRoot); if (!existsSync(parent) || !statSync(parent).isDirectory()) throw new Error("WIP restore parent is absent");
    mkdirSync(targetRoot, { mode: 0o700 });
    try {
      const git = this.options.git_factory(targetRoot);
      await this.#configureRemote(git); await appraiseGitMutationControlPlane(git, targetRoot); const transport = await resolvePinnedRemoteTransport(git, this.options.remote, this.options.fetch_url_sha256, this.options.push_url_sha256);
      await git.gitInput(["fetch", "--depth=1", "--no-tags", pinnedFetchOperand(transport), readback.snapshot.recovery_ref], { timeoutMs: 180_000, killProcessGroup: true });
      if ((await git.git(["rev-parse", "--verify", "FETCH_HEAD^{commit}"])).stdout.trim() !== readback.commit_oid) throw new Error("WIP restore remote ref changed after readback");
      const remoteSnapshot = JSON.parse((await git.gitInput(["show", `${readback.commit_oid}:.keep-wip/snapshot.json`], { maxOutputBytes: 32 * 1024 * 1024 })).stdout.toString("utf8")) as HourlyWipSnapshotV1;
      if (!verifyHourlyWipSnapshotV1(remoteSnapshot) || canonical(remoteSnapshot) !== canonical(readback.snapshot)) throw new Error("WIP restore snapshot differs from remote commit");
      await git.gitInput(["fetch", "--depth=1", "--no-tags", pinnedFetchOperand(transport), readback.snapshot.base_commit], { timeoutMs: 180_000, killProcessGroup: true });
      if ((await git.git(["rev-parse", "--verify", "FETCH_HEAD^{commit}"])).stdout.trim() !== readback.snapshot.base_commit) throw new Error("WIP restore base differs from readback");
      await git.git(["checkout", "--detach", readback.snapshot.base_commit, "--"]);
      await restoreSnapshotDelta(git, targetRoot, readback.snapshot);
    } catch (error) { rmSync(targetRoot, { recursive: true, force: true }); throw error; }
  }
  async #configureRemote(git: GitAdapter): Promise<void> {
    await git.git(["init"]); await git.git(["config", "--local", "user.name", "Keep WIP Readback"]); await git.git(["config", "--local", "user.email", "keep-wip-readback@invalid"]);
    await git.git(["remote", "add", this.options.remote, this.options.fetch_url]); await git.git(["remote", "set-url", "--push", this.options.remote, this.options.push_url]);
  }
  #preparedGit(prepared: PreparedWipPublicationV1): GitAdapter {
    validatePrepared(prepared);
    const path = realpathSync(prepared.repository_path); const rel = relative(this.#root, path);
    if (rel.startsWith(`..${sep}`) || rel === ".." || isAbsolute(rel) || !under(rel.replaceAll(sep, "/"), prepared.job_id)) throw new Error("prepared WIP repository escapes its workspace");
    return this.options.git_factory(path);
  }
}

async function restoreSnapshotDelta(git: GitAdapter, root: string, snapshot: HourlyWipSnapshotV1): Promise<void> {
  for (const file of snapshot.files) {
    const path = join(root, ...file.path.split("/"));
    requireDirectoryParents(root, file.path);
    if (file.index === null) await git.git(["update-index", "--force-remove", "--", file.path]);
    else {
      const bytes = Buffer.from(file.index.content_base64, "base64"); const oid = (await git.gitInput(["hash-object", "-w", "--stdin"], { stdin: bytes })).stdout.toString("ascii").trim();
      await git.git(["update-index", "--add", "--cacheinfo", `${file.index.mode.toString(8)},${oid},${file.path}`]);
    }
    if (file.worktree === null) { if (existsSync(path)) rmSync(path, { force: true }); continue; }
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    writeFileSync(path, Buffer.from(file.worktree.content_base64, "base64"), { flag: "w", mode: file.worktree.mode }); chmodSync(path, file.worktree.mode);
  }
  const status = parsePorcelain((await git.gitInput(["status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames"], { maxOutputBytes: 16 * 1024 * 1024 })).stdout);
  const expected = new Map(snapshot.files.map((file) => [file.path, file]));
  if (status.length !== expected.size || status.some((entry) => expected.get(entry.path)?.dirty_status !== entry.status)) throw new Error("restored WIP status differs from remote snapshot");
  for (const file of snapshot.files) {
    const absolute = join(root, ...file.path.split("/"));
    const worktree = existsSync(absolute) ? stableFile(absolute, 4 * 1024 * 1024) : null;
    if ((worktree === null) !== (file.worktree === null) || (worktree !== null && (worktree.mode !== file.worktree!.mode || sha256(worktree.bytes) !== file.worktree!.sha256))) throw new Error("restored WIP worktree bytes differ from remote snapshot");
    const index = await indexEntry(git, file.path, 4 * 1024 * 1024);
    if ((index === null) !== (file.index === null) || (index !== null && (index.mode !== file.index!.mode || index.sha256 !== file.index!.sha256))) throw new Error("restored WIP index bytes differ from remote snapshot");
  }
}

export class HourlyWipSupervisorV1 {
  readonly #root: string; readonly #lock: FileSystemLock;
  constructor(readonly stateDirectory: string, readonly port: WipPublicationPortV1) {
    this.#root = resolve(stateDirectory); mkdirSync(this.#root, { recursive: true, mode: 0o700 }); this.#lock = new FileSystemLock(join(this.#root, ".locks"));
  }
  async tick(fence: WorkAttemptFenceV1, request: Omit<CaptureHourlyWipRequestV1, "attempt">): Promise<HourlyWipTickResultV1> {
    const id = `wip_${sha256(canonical({ ...fence.reference, hour: request.hour_bucket_utc })).slice(0, 40)}`;
    return await this.#lock.withLock(id, async () => {
      let record: JobRecordV1 | undefined;
      try { record = this.#load(id); }
      catch { return freeze({ status: "FAILED_VISIBLE", job_id: id, first_failure: "WIP durable job state is invalid", next_action: "RETRY_SAME_JOB" }); }
      if (record?.status === "REMOTE_VERIFIED" && record.commit_oid !== null) return freeze({ status: "COALESCED", job_id: id, commit_oid: record.commit_oid });
      try {
        if (record === undefined || record.snapshot === null || record.status === "FAILED_VISIBLE" && record.prepared === null) {
          const attempt = freeze({ schema: "keep.work-attempt-authority/v1", schema_version: 1, identity: fence.identity, identity_digest: fence.reference.identity_digest, attempt_id: fence.reference.attempt_id, generation: fence.reference.generation, transitions: [] }) as WorkAttemptSnapshotV1;
          const firstKnownFailure = request.first_known_failure ?? record?.first_failure ?? null;
          const snapshot = await captureHourlyWipV1({ ...request, first_known_failure: firstKnownFailure, attempt });
          if (snapshot === null) return freeze({ status: "CLEAN" });
          await fence.withCurrent(async () => { record = { schema_version: 1, job_id: id, status: "CAPTURED", snapshot, prepared: null, first_failure: record?.first_failure ?? null, commit_oid: null }; this.#write(record); });
        }
        if (record === undefined) throw new Error("WIP capture record is absent");
        if (record.snapshot === null) throw new Error("WIP retry has no completed capture");
        const snapshot = record.snapshot;
        if (record.prepared === null) { const prepared = await this.port.prepare(snapshot); await fence.withCurrent(async () => { record = { ...record!, status: "PREPARED", prepared }; this.#write(record); }); }
        const prepared = record.prepared;
        if (prepared === null) throw new Error("WIP publication preparation is absent");
        if (record.status !== "REMOTE_VERIFIED") {
          let reconciled: WipRemoteReadbackV1 | null = null;
          try { reconciled = await this.port.readBack(prepared); } catch { /* absent/unreadable desired remote object: retry the same prepared mutation */ }
          if (reconciled !== null && reconciled.commit_oid === prepared.commit_oid && reconciled.snapshot.manifest_sha256 === snapshot.manifest_sha256) {
            await this.port.release(prepared);
            await fence.withCurrent(async () => { record = { schema_version: 1, job_id: id, status: "REMOTE_VERIFIED", snapshot: null, prepared: null, first_failure: record!.first_failure, commit_oid: reconciled!.commit_oid }; this.#write(record); });
            return freeze({ status: "REMOTE_VERIFIED", job_id: id, commit_oid: reconciled.commit_oid, snapshot_sha256: snapshot.manifest_sha256 });
          }
        }
        await fence.withCurrent(async () => await this.port.publish(prepared));
        const readback = await this.port.readBack(prepared);
        if (readback.commit_oid !== prepared.commit_oid || readback.snapshot.manifest_sha256 !== snapshot.manifest_sha256) throw new Error("remote WIP readback differs from captured snapshot");
        await this.port.release(prepared);
        await fence.withCurrent(async () => { record = { schema_version: 1, job_id: id, status: "REMOTE_VERIFIED", snapshot: null, prepared: null, first_failure: record!.first_failure, commit_oid: readback.commit_oid }; this.#write(record); });
        return freeze({ status: "REMOTE_VERIFIED", job_id: id, commit_oid: readback.commit_oid, snapshot_sha256: snapshot.manifest_sha256 });
      } catch (error) {
        const first = record?.first_failure ?? sanitizeFailure(error);
        try { await fence.withCurrent(async () => { record = record === undefined
          ? { schema_version: 1, job_id: id, status: "FAILED_VISIBLE", snapshot: null, prepared: null, first_failure: first, commit_oid: null }
          : { ...record, status: "FAILED_VISIBLE", first_failure: first }; this.#write(record); }); } catch { /* stale attempts cannot mutate job authority */ }
        return freeze({ status: "FAILED_VISIBLE", job_id: id, first_failure: first, next_action: "RETRY_SAME_JOB" });
      }
    });
  }
  async tickCurrentHour(fence: WorkAttemptFenceV1, request: Omit<CaptureHourlyWipRequestV1, "attempt" | "base_commit" | "recovery_ref" | "hour_bucket_utc">, nowMs = Date.now()): Promise<HourlyWipTickResultV1> {
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new Error("WIP clock is invalid");
    const baseCommit = await request.git.head();
    return await this.tick(fence, { ...request, base_commit: baseCommit, recovery_ref: `refs/heads/keep-wip/${fence.identity.track}/${fence.reference.identity_digest}`, hour_bucket_utc: Math.floor(nowMs / 3_600_000) });
  }
  #path(id: string): string { return join(this.#root, `${id}.json`); }
  #load(id: string): JobRecordV1 | undefined { try { return decodeJobRecordV1(JSON.parse(readFileSync(this.#path(id), "utf8")) as unknown, id); } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw error; } }
  #write(record: JobRecordV1): void {
    const path = this.#path(record.job_id); const temporary = `${path}.${process.pid}.${randomBytes(5).toString("hex")}.tmp`; const bytes = Buffer.from(`${canonical(record)}\n`); let fd: number | undefined;
    try { fd = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600); writeFileSync(fd, bytes); fsyncSync(fd); closeSync(fd); fd = undefined; renameSync(temporary, path); const directory = openSync(this.#root, constants.O_RDONLY | constants.O_DIRECTORY); try { fsyncSync(directory); } finally { closeSync(directory); } }
    finally { if (fd !== undefined) closeSync(fd); try { unlinkSync(temporary); } catch {} }
  }
}

const sanitizeFailure = (error: unknown): string => error instanceof Error && /^[A-Za-z0-9 ()_-]{1,160}$/u.test(error.message) ? error.message : "WIP publication failed; inspect local diagnostics";

export async function runYoloTicketStepWithHourlyWipV1(input: {
  readonly coordinator: YoloTicketCoordinatorV1;
  readonly coordinator_input: YoloTicketCoordinatorInputV1;
  readonly supervisor: HourlyWipSupervisorV1;
  readonly wip_request: Omit<CaptureHourlyWipRequestV1, "attempt" | "base_commit" | "recovery_ref" | "hour_bucket_utc">;
  readonly now_ms?: number;
}): Promise<{ readonly step: YoloTicketStepResultV1; readonly wip: HourlyWipTickResultV1 | null; readonly combined_effects_performed: boolean }> {
  const step = await input.coordinator.step(input.coordinator_input);
  if (step.status.mode !== "autonomous" || (step.code !== "ADVANCED" && step.code !== "ACTION_FAILURE")) return freeze({ step, wip: null, combined_effects_performed: false });
  const wip = await input.supervisor.tickCurrentHour(input.coordinator_input.attempt_authority.fence(input.coordinator_input.attempt), input.wip_request, input.now_ms);
  return freeze({ step, wip, combined_effects_performed: wip.status === "REMOTE_VERIFIED" });
}
