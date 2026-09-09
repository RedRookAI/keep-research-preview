import { chmodSync, closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, isAbsolute, join, resolve } from "node:path";
import type { BackupPort, Hasher } from "./backup_port.js";
import { verifyInstalledBackup, type BackupLimits, type BackupScope, type InstalledBackupCapture } from "./installed_backup_capture.js";
import { verifyProtectedBackup, type ProtectedBackup, type SupplyChainTrust } from "./supply_chain_backup.js";
import type { BackupCredentialOpener } from "./backup_secret_protection.js";

export interface RestoreSigningInput {
  readonly protectedBackup: ProtectedBackup;
  readonly backup: BackupPort;
  readonly trust: SupplyChainTrust;
  readonly expectedDependencyLockDigest: string;
  readonly hasher: Hasher;
}

export type RestoreSigningReport =
  | { readonly status: "distinct-signing-keys-verified"; readonly producerKeyId: string; readonly witnessKeyId: string; readonly limitation: string }
  | { readonly status: "unsigned" | "verification-failed"; readonly limitation: string };

export interface InstalledBackupRestoreRequest {
  readonly capture: InstalledBackupCapture;
  /** Absolute absent directory; restored product/ and state/ are published beneath it by one rename. */
  readonly targetRoot: string;
  readonly signing?: RestoreSigningInput;
  /** Required when the capture contains protected credential material; the authority/key is external to the archive. */
  readonly credentialOpener?: BackupCredentialOpener;
  readonly limits?: BackupLimits;
}

export interface InstalledBackupRestoreReport {
  readonly restored: true;
  readonly captureId: string;
  readonly inventoryDigest: string;
  readonly productFiles: number;
  readonly stateFiles: number;
  /** Authenticity, not merely self-consistency. False for an explicitly unsigned restore. */
  readonly userDataVerified: boolean;
  readonly contentIntegrityVerified: true;
  readonly authenticityVerified: boolean;
  readonly operationalRecoveryComplete: boolean;
  readonly componentSetComplete: boolean;
  readonly protectedCredentialFiles: number;
  readonly productTarget: string;
  readonly stateTarget: string;
  readonly exclusions: InstalledBackupCapture["exclusions"];
  readonly signing: RestoreSigningReport;
}

/** Restore through fresh sibling staging directories, verify bytes and inventory, then publish by rename. */
export async function restoreInstalledBackup(request: InstalledBackupRestoreRequest): Promise<InstalledBackupRestoreReport> {
  const targetRoot = validateFreshTarget(request.targetRoot);
  const signing = await signingReport(request.capture, request.signing);
  if (signing.status === "verification-failed") throw new Error(signing.limitation);
  if (!verifyInstalledBackup(request.capture, request.limits)) throw new Error("installed backup archive failed verification or resource limits; restore refused");
  const privileged = [...request.capture.files, ...(request.capture.protectedFiles ?? []), ...(request.capture.directories ?? [])].some((entry) => (entry.mode & 0o7000) !== 0);
  if (privileged && signing.status !== "distinct-signing-keys-verified") throw new Error("unsigned restore cannot publish privileged file modes");
  if ((request.capture.protectedFiles?.length ?? 0) > 0 && request.credentialOpener === undefined)
    throw new Error("restore requires the external credential recovery authority for protected files");
  mkdirSync(targetRoot, { mode: 0o700 }); // exclusive reservation closes the absent-target rename race
  const stage = join(targetRoot, ".restore-in-progress");
  const productStage = join(stage, "product"), stateStage = join(stage, "state");
  try {
    mkdirSync(stage, { mode: 0o700 }); mkdirSync(productStage, { mode: 0o700 }); mkdirSync(stateStage, { mode: 0o700 });
    for (const directory of request.capture.directories ?? []) {
      const root = directory.scope === "product" ? productStage : stateStage;
      mkdirSync(join(root, ...directory.path.split("/")), { recursive: true, mode: 0o700 });
    }
    for (const file of request.capture.files) {
      const root = file.scope === "product" ? productStage : stateStage;
      const destination = join(root, ...file.path.split("/"));
      mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
      writeFileSync(destination, Buffer.from(file.contentBase64, "base64"), { flag: "wx", mode: file.mode });
      chmodSync(destination, file.mode);
    }
    for (const file of request.capture.protectedFiles ?? []) {
      if (request.credentialOpener!.protectorId !== file.protectorId) throw new Error(`credential recovery authority does not match ${file.scope}:${file.path}`);
      const bytes = await request.credentialOpener!.open(file.scope, file.path, file.sealedBase64, file.contentBinding);
      if (bytes.length !== file.size) throw new Error(`opened credential size differs from captured metadata: ${file.scope}:${file.path}`);
      const root = file.scope === "product" ? productStage : stateStage;
      const destination = join(root, ...file.path.split("/"));
      mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
      writeFileSync(destination, bytes, { flag: "wx", mode: file.mode }); chmodSync(destination, file.mode);
    }
    verifyTree(productStage, "product", request.capture);
    verifyTree(stateStage, "state", request.capture);
    flushTree(stage);
    renameSync(productStage, join(targetRoot, "product")); renameSync(stateStage, join(targetRoot, "state")); rmSync(stage, { recursive: true });
    const marker = join(targetRoot, "RESTORE_COMPLETE.json");
    writeFileSync(marker, JSON.stringify({ schemaVersion: 1, captureId: request.capture.id, inventoryDigest: request.capture.inventoryDigest }), { flag: "wx", mode: 0o600 });
    syncPath(marker); syncPath(targetRoot); syncPath(dirname(targetRoot));
  } catch (error) {
    if (existsSync(targetRoot)) rmSync(targetRoot, { recursive: true, force: true });
    throw error;
  }
  const productFiles = request.capture.files.filter((file) => file.scope === "product").length;
  const protectedProductFiles = (request.capture.protectedFiles ?? []).filter((file) => file.scope === "product").length;
  const protectedCredentialFiles = request.capture.protectedFiles?.length ?? 0;
  const stateFiles = request.capture.files.length - productFiles + protectedCredentialFiles - protectedProductFiles;
  return Object.freeze({ restored: true, captureId: request.capture.id, inventoryDigest: request.capture.inventoryDigest,
    productFiles: productFiles + protectedProductFiles, stateFiles, userDataVerified: signing.status === "distinct-signing-keys-verified",
    contentIntegrityVerified: true, authenticityVerified: signing.status === "distinct-signing-keys-verified",
    operationalRecoveryComplete: request.capture.operationalRecoveryComplete && signing.status === "distinct-signing-keys-verified",
    componentSetComplete: request.capture.operationalRecoveryComplete, protectedCredentialFiles,
    productTarget: join(targetRoot, "product"), stateTarget: join(targetRoot, "state"),
    exclusions: request.capture.exclusions, signing });
}

function validateFreshTarget(input: string): string {
  if (!isAbsolute(input)) throw new Error("restore target must be an explicit absolute path");
  const target = resolve(input);
  if (existsSync(target)) throw new Error(`restore target must be absent: ${target}`);
  const parent = dirname(target);
  if (!existsSync(parent) || lstatSync(parent).isSymbolicLink() || !lstatSync(parent).isDirectory()) throw new Error(`restore target parent must be an existing real directory: ${parent}`);
  return target;
}

function verifyTree(root: string, scope: BackupScope, capture: InstalledBackupCapture): void {
  const expected = [...capture.files, ...(capture.protectedFiles ?? [])].filter((file) => file.scope === scope);
  const actual: string[] = [];
  const actualDirectories: string[] = [];
  walk(root, "");
  const expectedPaths = expected.map((file) => file.path).sort(lexical);
  actual.sort(lexical);
  if (JSON.stringify(actual) !== JSON.stringify(expectedPaths)) throw new Error(`restored ${scope} inventory differs from backup`);
  const expectedDirectories = (capture.directories ?? []).filter((entry) => entry.scope === scope).map((entry) => entry.path).sort(lexical);
  actualDirectories.sort(lexical); if (JSON.stringify(actualDirectories) !== JSON.stringify(expectedDirectories)) throw new Error(`restored ${scope} directory inventory differs from backup`);
  for (const file of expected) {
    const path = join(root, ...file.path.split("/"));
    const meta = lstatSync(path);
    if (!meta.isFile() || meta.isSymbolicLink() || (meta.mode & 0o7777) !== file.mode) throw new Error(`restored metadata differs: ${scope}:${file.path}`);
    const bytes = readFileSync(path);
    if (bytes.length !== file.size || ("sha256" in file && digest(bytes) !== file.sha256)) throw new Error(`restored content differs: ${scope}:${file.path}`);
  }
  for (const directory of (capture.directories ?? []).filter((entry) => entry.scope === scope).sort((a, b) => b.path.length - a.path.length)) {
    const path = join(root, ...directory.path.split("/")); chmodSync(path, directory.mode);
    const meta = lstatSync(path); if (!meta.isDirectory() || meta.isSymbolicLink() || (meta.mode & 0o7777) !== directory.mode) throw new Error(`restored directory metadata differs: ${scope}:${directory.path}`);
  }

  function walk(directory: string, rel: string): void {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const childRel = rel === "" ? entry.name : `${rel}/${entry.name}`;
      const child = join(directory, entry.name);
      const meta = lstatSync(child);
      if (meta.isSymbolicLink()) throw new Error(`restored tree contains a symbolic link: ${scope}:${childRel}`);
      if (meta.isDirectory()) { actualDirectories.push(childRel); walk(child, childRel); }
      else if (meta.isFile()) actual.push(childRel);
      else throw new Error(`restored tree contains a non-regular entry: ${scope}:${childRel}`);
    }
  }
}

function flushTree(root: string): void {
  for (const entry of readdirSync(root, { withFileTypes: true })) { const path = join(root, entry.name); if (entry.isDirectory()) flushTree(path); else syncPath(path); }
  syncPath(root);
}
function syncPath(path: string): void { const fd = openSync(path, "r"); try { fsyncSync(fd); } finally { closeSync(fd); } }

async function signingReport(capture: InstalledBackupCapture, input: RestoreSigningInput | undefined): Promise<RestoreSigningReport> {
  if (!input) return Object.freeze({ status: "unsigned", limitation: "content hashes detect transport damage but provide no independently custodied authenticity" });
  const verdict = await verifyProtectedBackup({ protectedBackup: input.protectedBackup, backup: input.backup, trust: input.trust,
    expectedArtifactInventoryDigest: capture.inventoryDigest, expectedDependencyLockDigest: input.expectedDependencyLockDigest, hasher: input.hasher });
  if (!verdict.ok) return Object.freeze({ status: "verification-failed", limitation: `independent signing evidence did not verify: ${verdict.reason}` });
  return Object.freeze({ status: "distinct-signing-keys-verified", producerKeyId: input.protectedBackup.producerSignature.keyId,
    witnessKeyId: input.protectedBackup.witness.signature.keyId, limitation: "signature verification proves bound producer/witness keys, not that their real-world custody is organizationally independent" });
}

function digest(data: Buffer): string { return createHash("sha256").update(data).digest("hex"); }
function lexical(a: string, b: string): number { return a < b ? -1 : a > b ? 1 : 0; }
