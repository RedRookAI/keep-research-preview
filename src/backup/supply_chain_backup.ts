import { createHash, sign, verify, type KeyObject } from "node:crypto";

import { canonicalize } from "../spine/event.js";
import type { BackupPort, Hasher, Snapshot, SnapshotRef } from "./backup_port.js";
import { verifyRestore, type RestoreVerification } from "./verify_restore.js";

const HEX64 = /^[a-f0-9]{64}$/;

export interface SupplyChainStatement {
  readonly version: 1;
  readonly snapshotId: string;
  readonly contentRoot: string;
  readonly artifactInventoryDigest: string;
  readonly dependencyLockDigest: string;
  readonly createdAt: number;
}

export interface DetachedSignature {
  readonly keyId: string;
  readonly algorithm: "ed25519";
  readonly signature: string;
}

export interface WitnessReceipt {
  readonly statementDigest: string;
  readonly witnessedAt: number;
  readonly signature: DetachedSignature;
}

export interface ProtectedBackup {
  readonly ref: SnapshotRef;
  readonly statement: SupplyChainStatement;
  readonly producerSignature: DetachedSignature;
  readonly witness: WitnessReceipt;
}

export interface SupplyChainSigner {
  readonly keyId: string;
  sign(message: string): DetachedSignature;
}

export interface SupplyChainTrust {
  readonly producerKeys: ReadonlyMap<string, KeyObject>;
  readonly witnessKeys: ReadonlyMap<string, KeyObject>;
}

export type ProtectedBackupVerification =
  | { readonly ok: true; readonly restore: RestoreVerification; readonly snapshot: Snapshot }
  | { readonly ok: false; readonly reason: string; readonly restore?: RestoreVerification };

export function sha256Digest(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

export function statementDigest(statement: SupplyChainStatement): string {
  return sha256Digest(canonicalize(statement));
}

function witnessContent(statementDigestValue: string, witnessedAt: number): string {
  return canonicalize({ statementDigest: statementDigestValue, witnessedAt });
}

export class Ed25519SupplyChainSigner implements SupplyChainSigner {
  constructor(readonly keyId: string, private readonly privateKey: KeyObject) {}
  sign(message: string): DetachedSignature {
    return { keyId: this.keyId, algorithm: "ed25519", signature: sign(null, Buffer.from(message), this.privateKey).toString("base64") };
  }
}

function validSignature(signature: DetachedSignature, message: string, keys: ReadonlyMap<string, KeyObject>): boolean {
  if (signature.algorithm !== "ed25519") return false;
  const key = keys.get(signature.keyId);
  if (!key) return false;
  try { return verify(null, Buffer.from(message), key, Buffer.from(signature.signature, "base64")); }
  catch { return false; }
}

export async function createProtectedBackup(input: {
  readonly snapshot: Snapshot;
  readonly artifactInventoryDigest: string;
  readonly dependencyLockDigest: string;
  readonly producer: SupplyChainSigner;
  readonly witness: SupplyChainSigner;
  readonly backup: BackupPort;
  readonly now?: number;
}): Promise<ProtectedBackup> {
  if (!HEX64.test(input.artifactInventoryDigest) || !HEX64.test(input.dependencyLockDigest)) throw new Error("supply-chain digests must be lowercase SHA-256");
  if (input.producer.keyId === input.witness.keyId) throw new Error("backup producer and witness must be independent keys");
  const ref = await input.backup.put(input.snapshot);
  if (ref.id !== input.snapshot.id || ref.contentRoot !== input.snapshot.contentRoot) throw new Error("backup target acknowledgement does not match the supplied snapshot");
  const now = input.now ?? Date.now();
  const statement: SupplyChainStatement = Object.freeze({ version: 1, snapshotId: ref.id, contentRoot: ref.contentRoot, artifactInventoryDigest: input.artifactInventoryDigest, dependencyLockDigest: input.dependencyLockDigest, createdAt: now });
  const digest = statementDigest(statement);
  return Object.freeze({ ref, statement, producerSignature: input.producer.sign(digest), witness: Object.freeze({ statementDigest: digest, witnessedAt: now, signature: input.witness.sign(witnessContent(digest, now)) }) });
}

export async function verifyProtectedBackup(input: {
  readonly protectedBackup: ProtectedBackup;
  readonly backup: BackupPort;
  readonly trust: SupplyChainTrust;
  readonly expectedArtifactInventoryDigest: string;
  readonly expectedDependencyLockDigest: string;
  readonly hasher: Hasher;
}): Promise<ProtectedBackupVerification> {
  const p = input.protectedBackup;
  const digest = statementDigest(p.statement);
  if (p.statement.artifactInventoryDigest !== input.expectedArtifactInventoryDigest) return { ok: false, reason: "artifact inventory digest mismatch" };
  if (p.statement.dependencyLockDigest !== input.expectedDependencyLockDigest) return { ok: false, reason: "dependency lock digest mismatch" };
  if (p.ref.id !== p.statement.snapshotId || p.ref.contentRoot !== p.statement.contentRoot) return { ok: false, reason: "snapshot reference is not bound to the signed statement" };
  if (!validSignature(p.producerSignature, digest, input.trust.producerKeys)) return { ok: false, reason: "invalid or untrusted producer signature" };
  if (p.witness.statementDigest !== digest || !validSignature(p.witness.signature, witnessContent(digest, p.witness.witnessedAt), input.trust.witnessKeys)) return { ok: false, reason: "invalid or untrusted independent witness" };
  if (p.producerSignature.keyId === p.witness.signature.keyId) return { ok: false, reason: "producer and witness are not independent" };
  const snapshot = await input.backup.get(p.statement.snapshotId);
  if (!snapshot) return { ok: false, reason: "protected snapshot is missing from backup target" };
  const restore = verifyRestore(snapshot.blocks, p.statement.contentRoot, input.hasher);
  if (!restore.ok) return { ok: false, reason: `protected restore failed: ${restore.reason}`, restore };
  if (snapshot.id !== p.statement.snapshotId || snapshot.contentRoot !== p.statement.contentRoot) return { ok: false, reason: "fetched snapshot metadata is not bound to the signed statement", restore };
  return { ok: true, restore, snapshot };
}

