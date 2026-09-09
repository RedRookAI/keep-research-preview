import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { captureInstalledBackup } from "../src/backup/installed_backup_capture.js";
import { restoreInstalledBackup } from "../src/backup/installed_backup_restore.js";
import { buildSnapshot, LocalBackup } from "../src/backup/backup_port.js";
import { createProtectedBackup, Ed25519SupplyChainSigner, sha256Digest } from "../src/backup/supply_chain_backup.js";
import { composeLifecycle } from "../src/lifecycle/compose_lifecycle.js";

const hash = (value: string) => createHash("sha256").update(value).digest("hex");
async function fixture() {
  const root = mkdtempSync(join(tmpdir(), "keep-restore-"));
  const product = join(root, "source-product"), state = join(root, "source-state");
  mkdirSync(product); mkdirSync(state); mkdirSync(join(state, "projects"));
  writeFileSync(join(product, "keep.js"), "product bytes", { mode: 0o755 });
  writeFileSync(join(state, "projects", "alice.json"), '{"goal":"keep my work"}', { mode: 0o600 });
  const capture = await captureInstalledBackup({ installedRoot: product, stateRoot: state, nowMs: 10 });
  return { root, capture, targetRoot: join(root, "restored") };
}

test("OPS-05 restores into fresh locations and verifies installed files plus user state", async () => {
  const f = await fixture();
  const report = await restoreInstalledBackup({ capture: f.capture, targetRoot: f.targetRoot });
  assert.equal(report.restored, true); assert.equal(report.userDataVerified, false, "unsigned self-consistency is not authenticity");
  assert.equal(report.contentIntegrityVerified, true);
  assert.equal(readFileSync(join(f.targetRoot, "product", "keep.js"), "utf8"), "product bytes");
  assert.equal(readFileSync(join(f.targetRoot, "state", "projects", "alice.json"), "utf8"), '{"goal":"keep my work"}');
  assert.equal(report.signing.status, "unsigned");
  assert.match(report.signing.limitation, /no independently custodied authenticity/);
  assert.equal(composeLifecycle().restoreInstalledBackup, restoreInstalledBackup, "restore is reachable through the existing lifecycle surface");
});

test("OPS-05 refuses tampered archives and existing targets before writing anything", async () => {
  const f = await fixture();
  const bad = { ...f.capture, files: f.capture.files.map((file, index) => index === 0 ? { ...file, contentBase64: Buffer.from("tamper").toString("base64") } : file) };
  await assert.rejects(restoreInstalledBackup({ capture: bad, targetRoot: f.targetRoot }), /failed verification/);
  assert.equal(existsSync(f.targetRoot), false);
  mkdirSync(f.targetRoot); writeFileSync(join(f.targetRoot, "keep.txt"), "do not overwrite");
  await assert.rejects(restoreInstalledBackup({ capture: f.capture, targetRoot: f.targetRoot }), /must be absent/);
  assert.equal(readFileSync(join(f.targetRoot, "keep.txt"), "utf8"), "do not overwrite");
});

test("OPS-05 reports distinct verified keys without overclaiming independent custody", async () => {
  const f = await fixture();
  const producer = generateKeyPairSync("ed25519"), witness = generateKeyPairSync("ed25519");
  const backup = new LocalBackup();
  const snapshot = buildSnapshot([], hash, 1);
  const dependencyLockDigest = sha256Digest("lock");
  const protectedBackup = await createProtectedBackup({ snapshot, artifactInventoryDigest: f.capture.inventoryDigest, dependencyLockDigest,
    producer: new Ed25519SupplyChainSigner("producer", producer.privateKey), witness: new Ed25519SupplyChainSigner("witness", witness.privateKey), backup, now: 10 });
  const signing = { protectedBackup, backup, trust: { producerKeys: new Map([["producer", producer.publicKey]]), witnessKeys: new Map([["witness", witness.publicKey]]) }, expectedDependencyLockDigest: dependencyLockDigest, hasher: hash };
  const report = await restoreInstalledBackup({ capture: f.capture, targetRoot: f.targetRoot, signing });
  assert.equal(report.signing.status, "distinct-signing-keys-verified");
  assert.match(report.signing.limitation, /not.*real-world custody|real-world custody.*not/);
  const forged = { ...f.capture, credentialProtection: "all-state" as const, operationalRecoveryComplete: true, takenAtMs: 999999 };
  await assert.rejects(restoreInstalledBackup({ capture: forged, targetRoot: join(f.root, "forged"), signing }), /failed verification/);
});
