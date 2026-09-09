import { constants, closeSync, fstatSync, lstatSync, openSync, readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { isAbsolute, join, relative, sep } from "node:path";

export type BackupScope = "product" | "state";
export interface BackupLimits { readonly maxFiles?: number; readonly maxFileBytes?: number; readonly maxTotalBytes?: number }

export interface BackupDirectoryEntry { readonly scope: BackupScope; readonly path: string; readonly mode: number }

export interface BackupFileEntry {
  readonly scope: BackupScope;
  readonly path: string;
  readonly size: number;
  readonly mode: number;
  readonly sha256: string;
  readonly contentBase64: string;
}

/** Credential material is never placed in a capture as plaintext. The protector's key lives outside the archive. */
export interface BackupCredentialProtector {
  readonly protectorId: string;
  seal(scope: BackupScope, path: string, plaintext: Buffer): Promise<{ readonly sealedBase64: string; readonly contentBinding: string }> | { readonly sealedBase64: string; readonly contentBinding: string };
}

export interface ProtectedBackupFileEntry {
  readonly scope: BackupScope;
  readonly path: string;
  readonly size: number;
  readonly mode: number;
  readonly protectorId: string;
  readonly sealedBase64: string;
  readonly sealedSha256: string;
  /** Keyed deterministic identity: supports content addressing without exposing a plaintext-secret hash. */
  readonly contentBinding: string;
}

export interface BackupExclusion {
  readonly scope: BackupScope;
  readonly path: string;
  readonly reason: "credential-path" | "credential-content" | "git-control" | "nested-repository" | "non-regular";
}

export interface InstalledBackupCapture {
  readonly schemaVersion: 1;
  readonly id: string;
  readonly takenAtMs: number;
  readonly files: readonly BackupFileEntry[];
  readonly protectedFiles: readonly ProtectedBackupFileEntry[];
  readonly directories: readonly BackupDirectoryEntry[];
  readonly exclusions: readonly BackupExclusion[];
  readonly inventoryDigest: string;
  readonly contentInventoryDigest: string;
  readonly totalBytes: number;
  /** Exactly one independent second read matched the captured inventory. */
  readonly verified: true;
  /** True only when no operationally necessary credential was omitted. */
  readonly operationalRecoveryComplete: boolean;
  readonly credentialProtection: "all-state" | "best-effort";
}

export interface InstalledBackupCaptureRequest extends BackupLimits {
  /** Exact installed package/release root. Absolute, real directory; never inferred from cwd. */
  readonly installedRoot: string;
  /** Exact Keep-owned durable-state root. User repositories must remain outside it. */
  readonly stateRoot: string;
  readonly nowMs?: number;
  readonly maxFiles?: number;
  readonly maxFileBytes?: number;
  readonly maxTotalBytes?: number;
  /** Optional n=1/enterprise-neutral seam: seal credential files under an externally held recovery authority. */
  readonly credentialProtector?: BackupCredentialProtector;
}

const DEFAULT_MAX_FILES = 100_000;
const DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024;
const CREDENTIAL_COMPONENT = /^(?:\.env(?:\..+)?|credentials?(?:\..+)?|secrets?(?:\..+)?|id_(?:rsa|dsa|ecdsa|ed25519)|.*\.(?:pem|key|p12|pfx))$/i;
const RAW_CREDENTIAL = /(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bgh[opusr]_[A-Za-z0-9_]{20,}\b|\bsk-[A-Za-z0-9_-]{20,}\b)/;

interface ScanResult {
  readonly files: readonly BackupFileEntry[];
  readonly protectedFiles: readonly ProtectedBackupFileEntry[];
  readonly directories: readonly BackupDirectoryEntry[];
  readonly exclusions: readonly BackupExclusion[];
  readonly inventoryDigest: string;
  readonly totalBytes: number;
  readonly sourceDigest: string;
  readonly contentInventoryDigest: string;
}

interface SourceIdentity { readonly scope: BackupScope; readonly path: string; readonly size: number; readonly mode: number; readonly sha256: string }

/** Capture once and perform exactly one independent reread; a changing or incomplete tree is refused. */
export async function captureInstalledBackup(request: InstalledBackupCaptureRequest): Promise<InstalledBackupCapture> {
  const limits = {
    maxFiles: positive(request.maxFiles, DEFAULT_MAX_FILES, "maxFiles"),
    maxFileBytes: positive(request.maxFileBytes, DEFAULT_MAX_FILE_BYTES, "maxFileBytes"),
    maxTotalBytes: positive(request.maxTotalBytes, DEFAULT_MAX_TOTAL_BYTES, "maxTotalBytes"),
  };
  const roots = resolveRoots(request.installedRoot, request.stateRoot);
  const first = await scan(roots, limits, request.credentialProtector);
  const verification = await scan(roots, limits, request.credentialProtector);
  if (first.sourceDigest !== verification.sourceDigest) throw new Error("backup capture changed during verification; no snapshot was produced");
  const takenAtMs = request.nowMs ?? Date.now();
  if (!Number.isSafeInteger(takenAtMs) || takenAtMs < 0) throw new Error("backup capture timestamp must be a non-negative safe integer");
  const credentialProtection = request.credentialProtector === undefined ? "best-effort" as const : "all-state" as const;
  const operationalRecoveryComplete = request.credentialProtector !== undefined && first.exclusions.every((entry) => entry.reason !== "credential-path" && entry.reason !== "credential-content");
  const inventoryDigest = boundInventoryDigest(first.inventoryDigest, takenAtMs, credentialProtection, operationalRecoveryComplete);
  return Object.freeze({
    schemaVersion: 1,
    id: `keep_backup_${first.contentInventoryDigest.slice(0, 32)}`,
    takenAtMs,
    files: Object.freeze(first.files),
    protectedFiles: Object.freeze(first.protectedFiles),
    directories: Object.freeze(first.directories),
    exclusions: Object.freeze(first.exclusions),
    inventoryDigest,
    contentInventoryDigest: first.contentInventoryDigest,
    totalBytes: first.totalBytes,
    verified: true,
    operationalRecoveryComplete,
    credentialProtection,
  });
}

/** Verify a transported capture without consulting its source paths. */
export function verifyInstalledBackup(capture: InstalledBackupCapture, requestedLimits: BackupLimits = {}): boolean {
  try {
    if (capture.schemaVersion !== 1 || capture.verified !== true || !Number.isSafeInteger(capture.takenAtMs) || capture.takenAtMs < 0) return false;
    const limits = { maxFiles: positive(requestedLimits.maxFiles, DEFAULT_MAX_FILES, "maxFiles"), maxFileBytes: positive(requestedLimits.maxFileBytes, DEFAULT_MAX_FILE_BYTES, "maxFileBytes"), maxTotalBytes: positive(requestedLimits.maxTotalBytes, DEFAULT_MAX_TOTAL_BYTES, "maxTotalBytes") };
    if (capture.files.length + (capture.protectedFiles?.length ?? 0) > limits.maxFiles || capture.totalBytes > limits.maxTotalBytes) return false;
    let totalBytes = 0;
    const seen = new Set<string>();
    for (const file of capture.files) {
      if (!safeRelative(file.path) || (file.scope !== "product" && file.scope !== "state")) return false;
      if (!validFileMetadata(file) || file.size > limits.maxFileBytes || base64DecodedUpperBound(file.contentBase64) > limits.maxFileBytes) return false;
      const identity = `${file.scope}:${file.path}`;
      if (seen.has(identity)) return false;
      seen.add(identity);
      const bytes = Buffer.from(file.contentBase64, "base64");
      if (bytes.toString("base64") !== file.contentBase64 || bytes.length !== file.size || digest(bytes) !== file.sha256) return false;
      totalBytes += bytes.length;
    }
    for (const file of capture.protectedFiles ?? []) {
      if (!safeRelative(file.path) || (file.scope !== "product" && file.scope !== "state") || !validProtectedMetadata(file) ||
          file.size > limits.maxFileBytes || typeof file.protectorId !== "string" || file.protectorId.trim() === "" || !/^[a-f0-9]{64}$/.test(file.sealedSha256) ||
          !/^[a-f0-9]{64}$/.test(file.contentBinding) || base64DecodedUpperBound(file.sealedBase64) > limits.maxFileBytes + 65_536) return false;
      const identity = `${file.scope}:${file.path}`;
      if (seen.has(identity)) return false;
      seen.add(identity);
      const sealed = Buffer.from(file.sealedBase64, "base64");
      if (sealed.toString("base64") !== file.sealedBase64 || digest(sealed) !== file.sealedSha256) return false;
      totalBytes += file.size;
    }
    for (const directory of capture.directories ?? []) {
      if (!safeRelative(directory.path) || (directory.scope !== "product" && directory.scope !== "state") || !validMode(directory.mode)) return false;
      const identity = `${directory.scope}:${directory.path}`; if (seen.has(identity)) return false; seen.add(identity);
    }
    const excluded = new Set<string>();
    for (const entry of capture.exclusions) {
      if (!safeRelative(entry.path) || (entry.scope !== "product" && entry.scope !== "state") ||
          !["credential-path", "credential-content", "git-control", "nested-repository", "non-regular"].includes(entry.reason)) return false;
      const identity = `${entry.scope}:${entry.path}`;
      if (seen.has(identity) || excluded.has(identity)) return false;
      excluded.add(identity);
    }
    if (totalBytes !== capture.totalBytes) return false;
    const payloadCalculated = inventoryDigest(capture.files, capture.protectedFiles ?? [], capture.directories ?? [], capture.exclusions);
    const contentCalculated = contentInventoryDigest(capture.files, capture.protectedFiles ?? [], capture.directories ?? [], capture.exclusions);
    if (capture.credentialProtection !== "all-state" && capture.credentialProtection !== "best-effort") return false;
    const complete = capture.credentialProtection === "all-state" && capture.exclusions.every((entry) => entry.reason !== "credential-path" && entry.reason !== "credential-content");
    const calculated = boundInventoryDigest(payloadCalculated, capture.takenAtMs, capture.credentialProtection, capture.operationalRecoveryComplete);
    return calculated === capture.inventoryDigest && contentCalculated === capture.contentInventoryDigest && capture.id === `keep_backup_${contentCalculated.slice(0, 32)}` && capture.operationalRecoveryComplete === complete;
  } catch { return false; }
}

async function scan(roots: Readonly<Record<BackupScope, string>>, limits: { maxFiles: number; maxFileBytes: number; maxTotalBytes: number }, credentialProtector?: BackupCredentialProtector): Promise<ScanResult> {
  const files: BackupFileEntry[] = [];
  const protectedFiles: ProtectedBackupFileEntry[] = [];
  const directories: BackupDirectoryEntry[] = [];
  const sourceIdentities: SourceIdentity[] = [];
  const exclusions: BackupExclusion[] = [];
  let totalBytes = 0;
  for (const scope of ["product", "state"] as const) await walk(scope, roots[scope], "", true);
  files.sort(compareRows); protectedFiles.sort(compareRows); directories.sort(compareRows); exclusions.sort(compareRows);
  const frozenExclusions = exclusions.map((entry) => Object.freeze(entry));
  return { files, protectedFiles, directories, exclusions: frozenExclusions, inventoryDigest: inventoryDigest(files, protectedFiles, directories, frozenExclusions), totalBytes,
    sourceDigest: digest(JSON.stringify(sourceIdentities.sort(compareRows))), contentInventoryDigest: contentInventoryDigest(files, protectedFiles, directories, frozenExclusions) };

  async function walk(scope: BackupScope, root: string, rel: string, isRoot: boolean): Promise<void> {
    const absolute = rel === "" ? root : join(root, ...rel.split("/"));
    const own = lstatSync(absolute);
    if (own.isSymbolicLink()) throw new Error(`backup refuses symbolic link: ${scope}:${rel || "."}`);
    if (!own.isDirectory()) throw new Error(`backup root/tree entry is not a directory: ${scope}:${rel || "."}`);
    if (!isRoot && hasGitMarker(absolute)) { exclusions.push({ scope, path: rel, reason: "nested-repository" }); return; }
    for (const dirent of readdirSync(absolute, { withFileTypes: true }).sort((a, b) => lexical(a.name, b.name))) {
      const childRel = rel === "" ? dirent.name : `${rel}/${dirent.name}`;
      if (dirent.name === ".git") { exclusions.push({ scope, path: childRel, reason: "git-control" }); continue; }
      const credentialByPath = credentialPath(childRel);
      if (credentialByPath && !credentialProtector) { exclusions.push({ scope, path: childRel, reason: "credential-path" }); continue; }
      const child = join(absolute, dirent.name);
      const meta = lstatSync(child);
      if (meta.isSymbolicLink()) throw new Error(`backup refuses symbolic link: ${scope}:${childRel}`);
      if (meta.isDirectory()) {
        if (hasGitMarker(child)) { exclusions.push({ scope, path: childRel, reason: "nested-repository" }); continue; }
        directories.push(Object.freeze({ scope, path: childRel, mode: meta.mode & 0o7777 })); await walk(scope, root, childRel, false); continue;
      }
      if (!meta.isFile()) { exclusions.push({ scope, path: childRel, reason: "non-regular" }); continue; }
      if (meta.size > limits.maxFileBytes) throw new Error(`backup file exceeds maxFileBytes: ${scope}:${childRel}`);
      const bytes = stableRead(child, meta.size);
      const credentialByContent = RAW_CREDENTIAL.test(bytes.toString("utf8"));
      if ((credentialByPath || credentialByContent) && !credentialProtector) { exclusions.push({ scope, path: childRel, reason: credentialByPath ? "credential-path" : "credential-content" }); continue; }
      totalBytes += bytes.length;
      if (totalBytes > limits.maxTotalBytes) throw new Error("backup capture exceeds maxTotalBytes");
      if (files.length + protectedFiles.length >= limits.maxFiles) throw new Error("backup capture exceeds maxFiles");
      const sourceIdentity = Object.freeze({ scope, path: childRel, size: bytes.length, mode: meta.mode & 0o7777, sha256: digest(bytes) });
      sourceIdentities.push(sourceIdentity);
      if (credentialProtector && (scope === "state" || credentialByPath || credentialByContent)) {
        const { sealedBase64, contentBinding } = await credentialProtector.seal(scope, childRel, bytes);
        const sealed = Buffer.from(sealedBase64, "base64");
        if (sealed.toString("base64") !== sealedBase64) throw new Error(`credential protector returned non-canonical data: ${scope}:${childRel}`);
        if (!/^[a-f0-9]{64}$/.test(contentBinding)) throw new Error(`credential protector returned an invalid content binding: ${scope}:${childRel}`);
        protectedFiles.push(Object.freeze({ scope, path: childRel, size: bytes.length, mode: meta.mode & 0o7777,
          protectorId: credentialProtector.protectorId, sealedBase64, sealedSha256: digest(sealed), contentBinding }));
      } else files.push(Object.freeze({ ...sourceIdentity, contentBase64: bytes.toString("base64") }));
    }
  }
}

function stableRead(path: string, expectedSize: number): Buffer {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.size !== expectedSize) throw new Error(`backup file changed before read: ${path}`);
    const bytes = readFileSync(fd);
    const after = fstatSync(fd);
    if (after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ino !== before.ino || after.dev !== before.dev)
      throw new Error(`backup file changed during read: ${path}`);
    return bytes;
  } finally { closeSync(fd); }
}

function resolveRoots(installedRoot: string, stateRoot: string): Readonly<Record<BackupScope, string>> {
  if (!isAbsolute(installedRoot) || !isAbsolute(stateRoot)) throw new Error("backup roots must be explicit absolute paths");
  for (const path of [installedRoot, stateRoot]) if (lstatSync(path).isSymbolicLink()) throw new Error("backup roots must not be symbolic links");
  const product = realpathSync(installedRoot), state = realpathSync(stateRoot);
  if (!statSync(product).isDirectory() || !statSync(state).isDirectory()) throw new Error("backup roots must be directories");
  if (product === state || within(product, state) || within(state, product)) throw new Error("installed and state roots must be disjoint");
  return Object.freeze({ product, state });
}

function hasGitMarker(path: string): boolean { try { lstatSync(join(path, ".git")); return true; } catch { return false; } }
function credentialPath(path: string): boolean { return path.split("/").some((component) => CREDENTIAL_COMPONENT.test(component)); }
function within(parent: string, child: string): boolean { const r = relative(parent, child); return r !== "" && !r.startsWith(`..${sep}`) && r !== ".." && !isAbsolute(r); }
function safeRelative(path: string): boolean { return path !== "" && !isAbsolute(path) && !path.split("/").some((part) => part === "" || part === "." || part === ".."); }
function digest(data: string | Buffer): string { return createHash("sha256").update(data).digest("hex"); }
function inventoryDigest(files: readonly BackupFileEntry[], protectedFiles: readonly ProtectedBackupFileEntry[], directories: readonly BackupDirectoryEntry[], exclusions: readonly BackupExclusion[]): string {
  const inventory = {
    files: [...files].sort(compareRows).map(({ contentBase64: _content, ...row }) => row),
    protectedFiles: [...protectedFiles].sort(compareRows),
    directories: [...directories].sort(compareRows),
    exclusions: [...exclusions].sort(compareRows),
  };
  return digest(JSON.stringify(inventory));
}
function contentInventoryDigest(files: readonly BackupFileEntry[], protectedFiles: readonly ProtectedBackupFileEntry[], directories: readonly BackupDirectoryEntry[], exclusions: readonly BackupExclusion[]): string {
  return digest(JSON.stringify({ files: [...files].sort(compareRows).map(({ contentBase64: _content, ...row }) => row),
    protectedFiles: [...protectedFiles].sort(compareRows).map(({ sealedBase64: _sealed, sealedSha256: _sealedDigest, ...row }) => row),
    directories: [...directories].sort(compareRows), exclusions: [...exclusions].sort(compareRows) }));
}
function boundInventoryDigest(payloadInventoryDigest: string, takenAtMs: number, credentialProtection: InstalledBackupCapture["credentialProtection"], operationalRecoveryComplete: boolean): string {
  return digest(JSON.stringify({ payloadInventoryDigest, takenAtMs, credentialProtection, operationalRecoveryComplete }));
}
function validFileMetadata(file: { size: number; mode: number; sha256: string }): boolean {
  return Number.isSafeInteger(file.size) && file.size >= 0 && validMode(file.mode) && /^[a-f0-9]{64}$/.test(file.sha256);
}
function validProtectedMetadata(file: { size: number; mode: number }): boolean {
  return Number.isSafeInteger(file.size) && file.size >= 0 && validMode(file.mode);
}
function validMode(mode: number): boolean { return Number.isSafeInteger(mode) && mode >= 0 && mode <= 0o7777; }
function base64DecodedUpperBound(value: unknown): number { return typeof value === "string" ? Math.ceil(value.length / 4) * 3 : Number.POSITIVE_INFINITY; }
function compareRows(a: { scope: BackupScope; path: string }, b: { scope: BackupScope; path: string }): number { return lexical(a.scope, b.scope) || lexical(a.path, b.path); }
function lexical(a: string, b: string): number { return a < b ? -1 : a > b ? 1 : 0; }
function positive(value: number | undefined, fallback: number, name: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved <= 0) throw new Error(`${name} must be a positive safe integer`);
  return resolved;
}
