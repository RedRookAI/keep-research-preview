import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { captureInstalledBackup, verifyInstalledBackup } from "../src/backup/installed_backup_capture.js";
import { PassphraseBackupCredentialProtector } from "../src/backup/backup_secret_protection.js";
import { restoreInstalledBackup } from "../src/backup/installed_backup_restore.js";
import { composeLifecycle } from "../src/lifecycle/compose_lifecycle.js";
const bindingSalt = Buffer.alloc(16, 9).toString("base64");

function roots() {
  const root = mkdtempSync(join(tmpdir(), "keep-secret-recovery-"));
  const product = join(root, "product"), state = join(root, "state");
  mkdirSync(product); mkdirSync(join(state, "projects"), { recursive: true });
  writeFileSync(join(product, "keep.js"), "product");
  writeFileSync(join(state, "projects", "records.json"), "encrypted-project-state", { mode: 0o600 });
  writeFileSync(join(state, "projects", "wrapped-keys.json"), "wrapped-subject-keys", { mode: 0o600 });
  writeFileSync(join(state, "projects", "master.key"), Buffer.alloc(32, 7), { mode: 0o600 });
  return { root, product, state };
}

test("installed recovery protects and restores the master-key root needed to decrypt project state", async () => {
  const f = roots();
  const protector = new PassphraseBackupCredentialProtector("personal-recovery-v1", "correct horse battery staple recovery secret", bindingSalt);
  const capture = await captureInstalledBackup({ installedRoot: f.product, stateRoot: f.state, credentialProtector: protector, nowMs: 1 });
  assert.equal(capture.operationalRecoveryComplete, true);
  assert.equal(capture.protectedFiles.length, 3, "all state is protected so unknown secret formats cannot escape in plaintext");
  assert.ok(capture.protectedFiles.some((file) => file.path === "projects/master.key"));
  assert.equal(verifyInstalledBackup(capture), true);
  assert.ok(!JSON.stringify(capture).includes(Buffer.alloc(32, 7).toString("base64")), "raw master key is absent from the archive");
  const targetRoot = join(f.root, "restore");
  const report = await restoreInstalledBackup({ capture, targetRoot, credentialOpener: protector });
  assert.equal(report.componentSetComplete, true);
  assert.equal(report.operationalRecoveryComplete, false, "unsigned recovery cannot claim trusted operational recovery");
  assert.equal(report.protectedCredentialFiles, 3);
  assert.deepEqual(readFileSync(join(targetRoot, "state", "projects", "master.key")), Buffer.alloc(32, 7));
  assert.equal(readFileSync(join(targetRoot, "state", "projects", "records.json"), "utf8"), "encrypted-project-state");
});

test("archive without credential recovery authority reports incomplete operational recovery", async () => {
  const f = roots();
  const capture = await captureInstalledBackup({ installedRoot: f.product, stateRoot: f.state });
  assert.equal(capture.operationalRecoveryComplete, false);
  assert.ok(capture.exclusions.some((entry) => entry.path === "projects/master.key" && entry.reason === "credential-path"));
  const report = await restoreInstalledBackup({ capture, targetRoot: join(f.root, "restore") });
  assert.equal(report.restored, true);
  assert.equal(report.operationalRecoveryComplete, false);
  assert.equal(existsSync(join(report.stateTarget, "projects", "master.key")), false);
});

test("wrong or absent recovery authority refuses before publishing a partial restore", async () => {
  const f = roots();
  const correct = new PassphraseBackupCredentialProtector("personal-recovery-v1", "correct horse battery staple recovery secret", bindingSalt);
  const capture = await captureInstalledBackup({ installedRoot: f.product, stateRoot: f.state, credentialProtector: correct });
  const absentTarget = join(f.root, "absent-authority");
  await assert.rejects(restoreInstalledBackup({ capture, targetRoot: absentTarget }), /requires the external credential recovery authority/);
  assert.equal(existsSync(absentTarget), false);
  const wrongTarget = join(f.root, "wrong-authority");
  const wrong = new PassphraseBackupCredentialProtector("personal-recovery-v1", "this is definitely the wrong recovery secret", bindingSalt);
  await assert.rejects(restoreInstalledBackup({ capture, targetRoot: wrongTarget, credentialOpener: wrong }), /could not be authenticated/);
  assert.equal(existsSync(wrongTarget), false);
});

test("credential ciphertext is bound to its exact scope and path", () => {
  const protector = new PassphraseBackupCredentialProtector("personal-recovery-v1", "correct horse battery staple recovery secret", bindingSalt);
  const sealed = protector.seal("state", "projects/master.key", Buffer.from("secret"));
  assert.throws(() => protector.open("state", "projects/other.key", sealed.sealedBase64), /could not be authenticated/);
  assert.equal(protector.open("state", "projects/master.key", sealed.sealedBase64).toString(), "secret");
  assert.equal(composeLifecycle().PassphraseBackupCredentialProtector, PassphraseBackupCredentialProtector);
});
