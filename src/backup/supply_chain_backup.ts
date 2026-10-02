import { createHash, createPublicKey, sign, verify, KeyObject } from "node:crypto";

import { canonicalize } from "../spine/event.js";
import { normalizePlainData } from "../spine/witness_reconcile.js";
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
  /** Required for protected creation; legacy custom signers without it fail before storage. */
  readonly publicKey?: KeyObject;
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
  readonly publicKey: KeyObject;
  constructor(readonly keyId: string, private readonly privateKey: KeyObject) { this.publicKey = createPublicKey(privateKey); }
  sign(message: string): DetachedSignature {
    return { keyId: this.keyId, algorithm: "ed25519", signature: sign(null, Buffer.from(message), this.privateKey).toString("base64") };
  }
}

function publicKeyBytes(key: KeyObject | undefined): Buffer | undefined {
  if (!(key instanceof KeyObject) || key.type !== "public" || key.asymmetricKeyType !== "ed25519") return undefined;
  try { return key.export({ format: "der", type: "spki" }); } catch { return undefined; }
}

function validSignature(signature: DetachedSignature, message: string, key: KeyObject | undefined): boolean {
  if (signature.algorithm !== "ed25519") return false;
  if (!key || !publicKeyBytes(key)) return false;
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
  const { artifactInventoryDigest, dependencyLockDigest, producer, witness, backup } = input;
  const snapshot = normalizePlainData(input.snapshot);
  if (!HEX64.test(artifactInventoryDigest) || !HEX64.test(dependencyLockDigest)) throw new Error("supply-chain digests must be lowercase SHA-256");
  const producerKey = producer.publicKey, witnessKey = witness.publicKey;
  const producerBytes = publicKeyBytes(producerKey), witnessBytes = publicKeyBytes(witnessKey);
  if (!producerBytes || !witnessBytes) throw new Error("backup signers must provide public Ed25519 keys for verification");
  const producerId = producer.keyId, witnessId = witness.keyId;
  if (producerId === witnessId || producerBytes.equals(witnessBytes)) throw new Error("backup producer and witness must be distinct independent keys; labels alone are insufficient");
  const now = input.now ?? Date.now();
  const statement: SupplyChainStatement = Object.freeze({ version: 1, snapshotId: snapshot.id, contentRoot: snapshot.contentRoot, artifactInventoryDigest, dependencyLockDigest, createdAt: now });
  const digest = statementDigest(statement);
  const producerSignature = Object.freeze({ ...producer.sign(digest) });
  const witnessSignature = Object.freeze({ ...witness.sign(witnessContent(digest, now)) });
  if (producerSignature.keyId !== producerId || witnessSignature.keyId !== witnessId ||
      !validSignature(producerSignature, digest, producerKey) || !validSignature(witnessSignature, witnessContent(digest, now), witnessKey))
    throw new Error("backup signer returned an invalid signature or mismatched public key");
  // Sign the retained identity before the target can mutate its detached argument.
  // An acknowledgement failure can leave an unreferenced object at an append-only target.
  const ref = Object.freeze({ ...await backup.put(normalizePlainData(snapshot)) });
  if (ref.id !== snapshot.id || ref.contentRoot !== snapshot.contentRoot || ref.blockCount !== snapshot.blockCount)
    throw new Error("backup target acknowledgement does not match the supplied snapshot");
  return Object.freeze({ ref, statement, producerSignature, witness: Object.freeze({ statementDigest: digest, witnessedAt: now, signature: witnessSignature }) });
}

export async function verifyProtectedBackup(input: {
  readonly protectedBackup: ProtectedBackup;
  readonly backup: BackupPort;
  readonly trust: SupplyChainTrust;
  readonly expectedArtifactInventoryDigest: string;
  readonly expectedDependencyLockDigest: string;
  readonly hasher: Hasher;
}): Promise<ProtectedBackupVerification> {
  try {
  const p = normalizePlainData(input.protectedBackup);
  const digest = statementDigest(p.statement);
  if (p.statement.artifactInventoryDigest !== input.expectedArtifactInventoryDigest) return { ok: false, reason: "artifact inventory digest mismatch" };
  if (p.statement.dependencyLockDigest !== input.expectedDependencyLockDigest) return { ok: false, reason: "dependency lock digest mismatch" };
  if (p.ref.id !== p.statement.snapshotId || p.ref.contentRoot !== p.statement.contentRoot) return { ok: false, reason: "snapshot reference is not bound to the signed statement" };
  const producerKey = input.trust.producerKeys.get(p.producerSignature.keyId), witnessKey = input.trust.witnessKeys.get(p.witness.signature.keyId);
  if (!validSignature(p.producerSignature, digest, producerKey)) return { ok: false, reason: "invalid or untrusted producer signature" };
  if (p.witness.statementDigest !== digest || !validSignature(p.witness.signature, witnessContent(digest, p.witness.witnessedAt), witnessKey)) return { ok: false, reason: "invalid or untrusted independent witness" };
  if (p.producerSignature.keyId === p.witness.signature.keyId || publicKeyBytes(producerKey)!.equals(publicKeyBytes(witnessKey)!)) return { ok: false, reason: "producer and witness are not distinct keys" };
  const fetched = await input.backup.get(p.statement.snapshotId);
  if (!fetched) return { ok: false, reason: "protected snapshot is missing from backup target" };
  const snapshot = normalizePlainData(fetched);
  const restore = verifyRestore(snapshot.blocks, p.statement.contentRoot, input.hasher);
  if (!restore.ok) return { ok: false, reason: `protected restore failed: ${restore.reason}`, restore };
  if (snapshot.id !== p.statement.snapshotId || snapshot.contentRoot !== p.statement.contentRoot) return { ok: false, reason: "fetched snapshot metadata is not bound to the signed statement", restore };
  if (snapshot.blockCount !== snapshot.blocks.length || snapshot.eventCount !== snapshot.blocks.reduce((n, b) => n + b.events.length, 0)) return { ok: false, reason: "fetched snapshot counts are inconsistent", restore };
  return { ok: true, restore, snapshot };
  } catch { return { ok: false, reason: "malformed protected backup or failed target read" }; }
}
