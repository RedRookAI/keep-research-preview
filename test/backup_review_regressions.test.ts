import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { captureInstalledBackup, verifyInstalledBackup } from "../src/backup/installed_backup_capture.js";
import { PassphraseBackupCredentialProtector } from "../src/backup/backup_secret_protection.js";
import { restoreInstalledBackup } from "../src/backup/installed_backup_restore.js";
import { renderUninstallSummary, uninstall, type RemovalPort } from "../src/backup/uninstall.js";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";

const secret = "correct horse battery staple recovery secret";
const bindingSalt = Buffer.alloc(16, 4).toString("base64");
function fixture() { const root = mkdtempSync(join(tmpdir(), "keep-backup-review-")), product = join(root, "product"), state = join(root, "state"); mkdirSync(product); mkdirSync(state); writeFileSync(join(product, "keep.js"), "product"); return { root, product, state }; }
function spine(root: string) { return new Spine(new FileSpineStore(join(root, "spine")), new InProcessLock(), new SchemaRegistry()); }

test("review F1/F8: empty directories and exact directory/file modes survive", async () => {
  const f = fixture(); mkdirSync(join(f.state, "sessions"), { mode: 0o750 }); writeFileSync(join(f.product, "helper"), "x", { mode: 0o755 });
  const protector = new PassphraseBackupCredentialProtector("recovery", secret, bindingSalt);
  const capture = await captureInstalledBackup({ installedRoot: f.product, stateRoot: f.state, credentialProtector: protector });
  const report = await restoreInstalledBackup({ capture, targetRoot: join(f.root, "restored"), credentialOpener: protector });
  assert.equal(existsSync(join(report.stateTarget, "sessions")), true); assert.equal(statSync(join(report.stateTarget, "sessions")).mode & 0o7777, 0o750);
});

test("review F2/F11: arbitrary state secrets are sealed and protected captures remain content-addressed", async () => {
  const f = fixture(); writeFileSync(join(f.state, "config.json"), JSON.stringify({ smtpPassword: "hunter2hunter2", slack: "xoxb-unknown-format" }));
  const protector = new PassphraseBackupCredentialProtector("recovery", secret, bindingSalt);
  const first = await captureInstalledBackup({ installedRoot: f.product, stateRoot: f.state, credentialProtector: protector, nowMs: 1 });
  const second = await captureInstalledBackup({ installedRoot: f.product, stateRoot: f.state, credentialProtector: protector, nowMs: 2 });
  assert.equal(first.id, second.id); assert.equal(first.operationalRecoveryComplete, true);
  assert.equal(first.files.some((file) => file.scope === "state"), false); assert.ok(!JSON.stringify(first).includes("hunter2hunter2"));
});

test("review F8: privileged mode is represented exactly and cannot be published unsigned", async () => {
  const f = fixture(); const helper = join(f.product, "helper"); writeFileSync(helper, "helper"); chmodSync(helper, 0o4755);
  const capture = await captureInstalledBackup({ installedRoot: f.product, stateRoot: f.state });
  assert.equal(capture.files.find((file) => file.path === "helper")?.mode, 0o4755);
  const targetRoot = join(f.root, "restore"); await assert.rejects(restoreInstalledBackup({ capture, targetRoot }), /privileged file modes/);
  assert.equal(existsSync(targetRoot), false);
});

test("review F3/F6: runtime artifacts are recorded exclusions and hostile archive limits fail before publication", async () => {
  const f = fixture(); const fifo = join(f.state, "keep.sock");
  // A FIFO exercises the same non-regular branch as a live Unix socket without asynchronous server cleanup.
  requireFifo(fifo);
  const capture = await captureInstalledBackup({ installedRoot: f.product, stateRoot: f.state });
  assert.ok(capture.exclusions.some((entry) => entry.path === "keep.sock" && entry.reason === "non-regular"));
  assert.equal(verifyInstalledBackup(capture, { maxFiles: 1, maxFileBytes: 1, maxTotalBytes: 1 }), false);
});

test("review F5: partial uninstall returns exact evidence and does not shred keys", async () => {
  const f = fixture(); const home = join(f.root, "home"), runfile = join(f.root, "run.sock"), registryParent = join(f.root, "registry");
  mkdirSync(home); writeFileSync(runfile, "run"); writeFileSync(registryParent, "not a directory"); const impossible = join(registryParent, "inst.json");
  const plan = { instanceHome: home, registryEntries: [impossible], runfiles: [runfile] }; const ownership = { ownedPaths: [home, impossible, runfile], preservedRepositories: [f.product] };
  const keys = new CryptoShredKeyStore(); keys.ensureKey("project");
  const removal: RemovalPort = { async plan() { return plan; }, async apply(_plan, progress) {
    for (const path of [runfile, home]) { progress({ phase: "attempting", path }); rmSync(path, { recursive: true }); progress({ phase: "removed", path }); }
    progress({ phase: "attempting", path: impossible }); progress({ phase: "failed", path: impossible, error: "deterministic failure" });
    return [{ path: runfile, status: "removed" }, { path: impossible, status: "failed", error: "deterministic failure" }, { path: home, status: "removed" }]; } };
  const report = await uninstall({ instanceId: "inst", keySubjects: ["project"] }, { spine: spine(f.root), keystore: keys,
    removal, ownership, finalBackup: async () => ({ id: "backup", inventoryDigest: "a".repeat(64), target: "offbox", verified: true }) });
  assert.equal(report.completed, false); assert.equal(report.removed.runfiles.length, 1); assert.equal(report.removalFailures?.[0]?.path, impossible);
  assert.equal(keys.hasKey("project"), true); assert.equal(existsSync(home), false, "independent owned paths continue to a known terminal disposition");
  assert.match(renderUninstallSummary(report), /Removed before failure: 2 exact owned path/);
});

test("review pass 2: incomplete adapter evidence cannot authorize key shredding", async () => {
  const f = fixture(); const home = join(f.root, "home"); mkdirSync(home); const plan = { instanceHome: home, registryEntries: [] as string[], runfiles: [] as string[] };
  const removal: RemovalPort = { async plan() { return plan; }, async apply() { return []; } };
  const keys = new CryptoShredKeyStore(); keys.ensureKey("project");
  const report = await uninstall({ instanceId: "inst", keySubjects: ["project"] }, { spine: spine(f.root), keystore: keys, removal,
    ownership: { ownedPaths: [home], preservedRepositories: [f.product] }, finalBackup: async () => ({ id: "backup", inventoryDigest: "b".repeat(64), target: "offbox", verified: true }) });
  assert.equal(report.completed, false); assert.match(report.abortedReason ?? "", /incomplete or invalid evidence/); assert.equal(keys.hasKey("project"), true); assert.equal(existsSync(home), true);
});

test("review pass 2: per-authority salts prevent global content-binding precomputation", () => {
  const a = new PassphraseBackupCredentialProtector("same-id", secret, Buffer.alloc(16, 1).toString("base64"));
  const b = new PassphraseBackupCredentialProtector("same-id", secret, Buffer.alloc(16, 2).toString("base64"));
  assert.notEqual(a.seal("state", "known.txt", Buffer.from("known")).contentBinding, b.seal("state", "known.txt", Buffer.from("known")).contentBinding);
});

test("review pass 2: asynchronous enterprise protector/opener uses the same recovery contract", async () => {
  const f = fixture(); writeFileSync(join(f.state, "state.json"), "state");
  const local = new PassphraseBackupCredentialProtector("kms-adapter", secret, bindingSalt);
  const asyncPort = { protectorId: local.protectorId, async seal(scope: "product" | "state", path: string, bytes: Buffer) { return local.seal(scope, path, bytes); },
    async open(scope: "product" | "state", path: string, sealed: string, binding?: string) { return local.open(scope, path, sealed, binding); } };
  const capture = await captureInstalledBackup({ installedRoot: f.product, stateRoot: f.state, credentialProtector: asyncPort });
  const report = await restoreInstalledBackup({ capture, targetRoot: join(f.root, "restore"), credentialOpener: asyncPort });
  assert.equal(report.componentSetComplete, true);
});

test("review F7: completed publication carries a durable completion marker", async () => {
  const f = fixture(); writeFileSync(join(f.state, "state.json"), "state"); const targetRoot = join(f.root, "restore");
  const capture = await captureInstalledBackup({ installedRoot: f.product, stateRoot: f.state }); await restoreInstalledBackup({ capture, targetRoot });
  const marker = JSON.parse(readFileSync(join(targetRoot, "RESTORE_COMPLETE.json"), "utf8")) as { captureId: string };
  assert.equal(marker.captureId, capture.id);
});

function requireFifo(path: string): void {
  const result = spawnSync("mkfifo", [path]);
  if (result.status !== 0) throw new Error(`mkfifo failed: ${String(result.stderr)}`);
}
