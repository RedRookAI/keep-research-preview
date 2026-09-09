import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";

import { LocalBackup, type Snapshot } from "../src/backup/backup_port.js";
import { createProtectedBackup, Ed25519SupplyChainSigner, sha256Digest, verifyProtectedBackup } from "../src/backup/supply_chain_backup.js";
import { composeLifecycle } from "../src/lifecycle/compose_lifecycle.js";

const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const empty: Snapshot = { id: `snap_${hash("0".repeat(64)).slice(0, 32)}`, contentRoot: "0".repeat(64), blocks: [], blockCount: 0, eventCount: 0, takenAt: 1 };

function fixture() {
  const producer = generateKeyPairSync("ed25519");
  const witness = generateKeyPairSync("ed25519");
  const backup = new LocalBackup();
  return {
    backup,
    producer: new Ed25519SupplyChainSigner("producer", producer.privateKey),
    witness: new Ed25519SupplyChainSigner("witness", witness.privateKey),
    trust: { producerKeys: new Map([["producer", producer.publicKey]]), witnessKeys: new Map([["witness", witness.publicKey]]) },
  };
}

test("G7: artifact inventory and dependency lock are independently signed and restore-verified", async () => {
  const f = fixture();
  const artifact = sha256Digest("installed-artifact-inventory");
  const lock = sha256Digest("package-lock bytes");
  const protectedBackup = await createProtectedBackup({ snapshot: empty, artifactInventoryDigest: artifact, dependencyLockDigest: lock, producer: f.producer, witness: f.witness, backup: f.backup, now: 10 });
  const verdict = await verifyProtectedBackup({ protectedBackup, backup: f.backup, trust: f.trust, expectedArtifactInventoryDigest: artifact, expectedDependencyLockDigest: lock, hasher: hash });
  assert.equal(verdict.ok, true);
  assert.equal(verdict.ok && verdict.restore.ok, true, "the fetched copy passes the ordinary restore predicate");
});

test("G7: tampering, dependency substitution, and a non-independent witness fail closed", async () => {
  const f = fixture();
  const artifact = sha256Digest("inventory");
  const lock = sha256Digest("lock");
  const p = await createProtectedBackup({ snapshot: empty, artifactInventoryDigest: artifact, dependencyLockDigest: lock, producer: f.producer, witness: f.witness, backup: f.backup });
  assert.equal((await verifyProtectedBackup({ protectedBackup: p, backup: f.backup, trust: f.trust, expectedArtifactInventoryDigest: artifact, expectedDependencyLockDigest: sha256Digest("other-lock"), hasher: hash })).ok, false);
  assert.equal((await verifyProtectedBackup({ protectedBackup: { ...p, statement: { ...p.statement, contentRoot: "f".repeat(64) } }, backup: f.backup, trust: f.trust, expectedArtifactInventoryDigest: artifact, expectedDependencyLockDigest: lock, hasher: hash })).ok, false);
  assert.equal((await verifyProtectedBackup({ protectedBackup: { ...p, witness: { ...p.witness, witnessedAt: p.witness.witnessedAt + 1 } }, backup: f.backup, trust: f.trust, expectedArtifactInventoryDigest: artifact, expectedDependencyLockDigest: lock, hasher: hash })).ok, false);
  await assert.rejects(() => createProtectedBackup({ snapshot: empty, artifactInventoryDigest: artifact, dependencyLockDigest: lock, producer: f.producer, witness: f.producer, backup: f.backup }), /independent keys/);
});

test("G7: the protected backup path is reachable through the lifecycle surface", () => {
  const lifecycle = composeLifecycle();
  assert.equal(lifecycle.createProtectedBackup, createProtectedBackup);
  assert.equal(lifecycle.verifyProtectedBackup, verifyProtectedBackup);
});

