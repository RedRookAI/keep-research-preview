import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createPublicKey, generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, rmdirSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildSnapshot, LocalBackup, type BackupPort, type Snapshot, type SnapshotRef } from "../src/backup/backup_port.js";
import { OffboxShipDriver } from "../src/backup/offbox_ship.js";
import { verifyRestore } from "../src/backup/verify_restore.js";
import { captureInstalledBackup, verifyInstalledBackup } from "../src/backup/installed_backup_capture.js";
import { restoreInstalledBackup } from "../src/backup/installed_backup_restore.js";
import { PassphraseBackupCredentialProtector } from "../src/backup/backup_secret_protection.js";
import { createProtectedBackup, Ed25519SupplyChainSigner, statementDigest, verifyProtectedBackup, type ProtectedBackup } from "../src/backup/supply_chain_backup.js";
import { canonicalize } from "../src/spine/event.js";
import { sealBlock } from "../src/spine/hashchain.js";

const hash = (s: string) => createHash("sha256").update(s).digest("hex");
function history(marker = "original") {
  return [sealBlock(undefined, [{ id: "event", schemaVersion: 1, type: "generic", ts: 1, actor: "fixture", payload: { marker } }], 1)];
}
function ref(s: Snapshot): SnapshotRef { return { id: s.id, contentRoot: s.contentRoot, takenAt: s.takenAt, blockCount: s.blockCount }; }
function mutate(s: Snapshot) { (s.blocks[0]!.events[0]!.payload as Record<string, unknown>).marker = "changed"; }
function keys() {
  const p = generateKeyPairSync("ed25519"), w = generateKeyPairSync("ed25519");
  return { p, w, producer: new Ed25519SupplyChainSigner("producer", p.privateKey), witness: new Ed25519SupplyChainSigner("witness", w.privateKey),
    trust: { producerKeys: new Map([["producer", p.publicKey]]), witnessKeys: new Map([["witness", w.publicKey]]) } };
}
function fixture() {
  const root = mkdtempSync(join(tmpdir(), "keep-backup-13b-"));
  const installedRoot = join(root, "product"), stateRoot = join(root, "state");
  mkdirSync(installedRoot); mkdirSync(stateRoot); mkdirSync(join(stateRoot, "a-empty"), { mode: 0o750 });
  writeFileSync(join(installedRoot, "main.js"), "export const answer = 42;", { mode: 0o755 });
  writeFileSync(join(stateRoot, "record.json"), '{"record":"preserved"}');
  return { root, installedRoot, stateRoot };
}
const protector = () => new PassphraseBackupCredentialProtector("test-recovery", "synthetic recovery passphrase for backup tests", Buffer.alloc(16, 13).toString("base64"));

for (const kind of ["directories", "exclusions"] as const) {
  test(`13B inventory budget counts ${kind} during capture and before restore`, async () => {
    const f = fixture();
    try {
      // Three existing inventory entries plus one directory/exclusion, not a file.
      mkdirSync(join(f.stateRoot, kind === "directories" ? "second-empty" : ".git"));
      const capture = await captureInstalledBackup({ ...f, maxFiles: 4 });
      assert.equal(capture.files.length + capture.protectedFiles.length + capture.directories.length + capture.exclusions.length, 4);
      assert.equal(verifyInstalledBackup(capture, { maxFiles: 4 }), true);
      assert.equal(verifyInstalledBackup(capture, { maxFiles: 3 }), false);
      await assert.rejects(captureInstalledBackup({ ...f, maxFiles: 3 }), /maxFiles/);
      const targetRoot = join(f.root, "too-small");
      await assert.rejects(restoreInstalledBackup({ capture, targetRoot, limits: { maxFiles: 3 } }));
      assert.equal(existsSync(targetRoot), false);
      const restored = await restoreInstalledBackup({ capture, targetRoot: join(f.root, "allowed"), limits: { maxFiles: 4 } });
      assert.equal(readFileSync(join(restored.productTarget, "main.js"), "utf8"), "export const answer = 42;");
    } finally { rmSync(f.root, { recursive: true, force: true }); }
  });
}

test("13B snapshot ownership refuses shared-memory data before retaining or dispatching", async () => {
  const bytes = new Uint8Array(new SharedArrayBuffer(1)); bytes[0] = 7;
  const blocks = [sealBlock(undefined, [{ id: "shared", schemaVersion: 1, type: "generic", ts: 1, actor: "fixture", payload: { bytes } }], 1)];
  assert.throws(() => buildSnapshot(blocks, hash, 1), /non-plain/);
  const contentRoot = blocks[0]!.cumulativeRoot;
  const supplied: Snapshot = { blocks, contentRoot, blockCount: 1, eventCount: 1, takenAt: 1, id: `snap_${hash(contentRoot).slice(0, 32)}` };
  const local = new LocalBackup();
  await assert.rejects(local.put(supplied), /non-plain/);
  assert.deepEqual(await local.list(), []);
  let writes = 0;
  const target: BackupPort = { name: "counted", requiresAccount: false, async put(s) { writes++; return ref(s); }, async list() { return []; }, async get() { return supplied; } };
  const outcome = await new OffboxShipDriver(target, () => blocks, hash, 1).shipOnce(1);
  assert.equal(outcome.ok, false); assert.equal(outcome.health.verifiedShips, 0);
  await assert.rejects(createProtectedBackup({ snapshot: supplied, artifactInventoryDigest: hash("artifact"), dependencyLockDigest: hash("lock"), ...keys(), backup: target }), /non-plain/);
  assert.equal(writes, 0);
  bytes[0] = 9;
  assert.deepEqual(await local.list(), []);
});

for (const track of ["personal", "tenant-alpha"] as const) {
  test(`13B useful ${track}: protected capture, two-key restore and subsequent state write`, async () => {
    const f = fixture();
    try {
      writeFileSync(join(f.stateRoot, "owner.json"), JSON.stringify({ track }));
      const recovery = protector();
      const capture = await captureInstalledBackup({ ...f, credentialProtector: recovery, nowMs: 10 });
      assert.equal(verifyInstalledBackup(capture), true);
      const again = await captureInstalledBackup({ ...f, credentialProtector: recovery, nowMs: 20 });
      assert.equal(again.id, capture.id, "randomized encryption does not change content identity");
      assert.notEqual(again.protectedFiles[0]!.sealedBase64, capture.protectedFiles[0]!.sealedBase64);
      const k = keys(), backup = new LocalBackup(), snapshot = buildSnapshot(history(), hash, 1), lock = hash("lock");
      const signed = await createProtectedBackup({ snapshot, artifactInventoryDigest: capture.inventoryDigest, dependencyLockDigest: lock, ...k, backup, now: 10 });
      // JSON transport exercises the unchanged v1 wire representation.
      const report = await restoreInstalledBackup({ capture: JSON.parse(JSON.stringify(capture)), targetRoot: join(f.root, "restored"), credentialOpener: recovery,
        signing: { protectedBackup: JSON.parse(JSON.stringify(signed)), backup, trust: k.trust, expectedDependencyLockDigest: lock, hasher: hash } });
      assert.equal(report.authenticityVerified, true);
      assert.equal(report.operationalRecoveryComplete, true);
      assert.equal(readFileSync(join(report.stateTarget, "owner.json"), "utf8"), JSON.stringify({ track }));
      assert.equal(statSync(join(report.stateTarget, "a-empty")).mode & 0o7777, 0o750);
      assert.equal(statSync(join(report.productTarget, "main.js")).mode & 0o7777, 0o755);
      writeFileSync(join(report.stateTarget, "new-record"), "new useful work");
      assert.equal(readFileSync(join(report.stateTarget, "new-record"), "utf8"), "new useful work");
      assert.equal(existsSync(join(f.stateRoot, "new-record")), false);
    } finally { rmSync(f.root, { recursive: true, force: true }); }
  });
}

for (const change of ["add-directory", "remove-directory", "directory-mode", "add-exclusion", "file-content"] as const) {
  test(`KEEP-13B-001: reread refuses ${change}`, async () => {
    const f = fixture(), recovery = protector(); let changed = false;
    try {
      await assert.rejects(captureInstalledBackup({ ...f, credentialProtector: { protectorId: recovery.protectorId, async seal(scope, path, bytes) {
        const sealed = recovery.seal(scope, path, bytes);
        if (!changed) {
          changed = true;
          if (change === "add-directory") mkdirSync(join(f.stateRoot, "later-empty"));
          if (change === "remove-directory") rmdirSync(join(f.stateRoot, "a-empty"));
          if (change === "directory-mode") chmodSync(join(f.stateRoot, "a-empty"), 0o700);
          if (change === "add-exclusion") mkdirSync(join(f.stateRoot, ".git"));
          if (change === "file-content") writeFileSync(join(f.stateRoot, "record.json"), "later data");
        }
        return sealed;
      } } }), /changed during verification/);
      assert.equal(changed, true);
      assert.equal(readFileSync(join(f.installedRoot, "main.js"), "utf8"), "export const answer = 42;");
    } finally { rmSync(f.root, { recursive: true, force: true }); }
  });
}

test("KEEP-13B-002: creation rejects one key with two labels before writing", async () => {
  const k = keys(); let writes = 0;
  const backup: BackupPort = { name: "counting", requiresAccount: false, async put(s) { writes++; return ref(s); }, async list() { return []; }, async get() { return undefined; } };
  await assert.rejects(createProtectedBackup({ snapshot: buildSnapshot(history(), hash, 1), artifactInventoryDigest: hash("artifact"), dependencyLockDigest: hash("lock"),
    producer: k.producer, witness: new Ed25519SupplyChainSigner("alias", k.p.privateKey), backup }), /distinct|independent/);
  assert.equal(writes, 0);
});

test("KEEP-13B-002: legacy same-key alias signatures cannot satisfy verified restore", async () => {
  const f = fixture();
  try {
    const recovery = protector(), capture = await captureInstalledBackup({ ...f, credentialProtector: recovery });
    const k = keys(), snapshot = buildSnapshot(history(), hash, 1), backup = new LocalBackup(), lock = hash("lock");
    await backup.put(snapshot);
    const statement = { version: 1 as const, snapshotId: snapshot.id, contentRoot: snapshot.contentRoot, artifactInventoryDigest: capture.inventoryDigest, dependencyLockDigest: lock, createdAt: 1 };
    const digest = statementDigest(statement), alias = new Ed25519SupplyChainSigner("alias", k.p.privateKey);
    const signed: ProtectedBackup = { ref: ref(snapshot), statement, producerSignature: k.producer.sign(digest), witness: { statementDigest: digest, witnessedAt: 1, signature: alias.sign(canonicalize({ statementDigest: digest, witnessedAt: 1 })) } };
    // Reimport the same public key to rule out object-reference comparison.
    const aliasKey = createPublicKey(k.p.publicKey.export({ format: "pem", type: "spki" }));
    const trust = { producerKeys: k.trust.producerKeys, witnessKeys: new Map([["alias", aliasKey]]) };
    const verdict = await verifyProtectedBackup({ protectedBackup: signed, backup, trust, expectedArtifactInventoryDigest: capture.inventoryDigest, expectedDependencyLockDigest: lock, hasher: hash });
    assert.equal(verdict.ok, false);
    const targetRoot = join(f.root, "aliased-restore");
    await assert.rejects(restoreInstalledBackup({ capture, targetRoot, credentialOpener: recovery, signing: { protectedBackup: signed, backup, trust, expectedDependencyLockDigest: lock, hasher: hash } }));
    assert.equal(existsSync(targetRoot), false);
    assert.deepEqual(await backup.get(snapshot.id), snapshot, "refusal does not rewrite old data");
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("KEEP-13B-003: build and storage own nested snapshot data", async () => {
  const blocks = history(), snapshot = buildSnapshot(blocks, hash, 1), backup = new LocalBackup();
  const expected = structuredClone(snapshot);
  (blocks[0]!.events[0]!.payload as Record<string, unknown>).marker = "changed at source";
  assert.deepEqual(snapshot, expected);
  await backup.put(snapshot);
  mutate(snapshot);
  assert.deepEqual(await backup.get(snapshot.id), expected);
  const returned = (await backup.get(snapshot.id))!; mutate(returned);
  assert.deepEqual(await backup.get(snapshot.id), expected);
  assert.equal(verifyRestore((await backup.get(snapshot.id))!.blocks, expected.contentRoot, hash).ok, true);
  const repeated = await backup.put({ ...expected, takenAt: 200 });
  assert.equal(repeated.takenAt, 1, "same content keeps the first stored time");
  await assert.rejects(backup.put({ ...expected, contentRoot: "f".repeat(64) }));
  assert.equal(await new LocalBackup().get(snapshot.id), undefined, "adapter remains memory-only");
});

test("13B local storage refuses damaged contents or inconsistent counts", async () => {
  const snapshot = buildSnapshot(history(), hash, 1);
  for (const candidate of [{ ...snapshot, blockCount: 2 }, { ...snapshot, eventCount: 2 }, structuredClone(snapshot)]) {
    if (candidate.blockCount === 1 && candidate.eventCount === 1) mutate(candidate);
    const backup = new LocalBackup();
    await assert.rejects(backup.put(candidate)); assert.deepEqual(await backup.list(), []);
  }
});

test("KEEP-13B-003: put and get references independently cannot edit stored data", async () => {
  const snapshot = buildSnapshot(history(), hash, 1), backup = new LocalBackup(), expected = structuredClone(snapshot);
  await backup.put(snapshot); mutate(snapshot);
  assert.deepEqual(await backup.get(snapshot.id), expected);
  const fetched = (await backup.get(snapshot.id))!; mutate(fetched);
  assert.deepEqual(await backup.get(snapshot.id), expected);
});

test("13B: absent, private, or non-Ed25519 signer keys fail before writes", async () => {
  const k = keys(), rsa = generateKeyPairSync("ec", { namedCurve: "prime256v1" }); let writes = 0;
  const backup: BackupPort = { name: "counting", requiresAccount: false, async put(s) { writes++; return ref(s); }, async list() { return []; }, async get() { return undefined; } };
  for (const publicKey of [undefined, k.p.privateKey, rsa.publicKey, k.w.publicKey]) {
    const producer = { keyId: "producer", sign: k.producer.sign.bind(k.producer), ...(publicKey ? { publicKey } : {}) };
    await assert.rejects(createProtectedBackup({ snapshot: buildSnapshot(history(), hash, 1), artifactInventoryDigest: hash("artifact"), dependencyLockDigest: hash("lock"),
      producer, witness: k.witness, backup }));
  }
  assert.equal(writes, 0);
});

test("13B: malformed source/fetched data produce unhealthy results, not uncaught errors", async () => {
  for (const location of ["source", "get"] as const) {
    const backup: BackupPort = { name: "malformed", requiresAccount: false, async put(s) { return ref(s); }, async list() { return []; },
      async get() { return { ...buildSnapshot(history(), hash, 1), blocks: null } as unknown as Snapshot; } };
    const driver = new OffboxShipDriver(backup, () => { if (location === "source") throw Error("source unavailable"); return history(); }, hash, 1);
    const result = await driver.shipOnce(10);
    assert.equal(result.ok, false); assert.equal(result.health.healthy, false); assert.equal(result.health.verifiedShips, 0);
  }
});

test("13B: restore keeps the signed capture across target/opener callbacks", async () => {
  const f = fixture();
  try {
    const recovery = protector(), capture = await captureInstalledBackup({ ...f, credentialProtector: recovery });
    const k = keys(), backup = new LocalBackup(), snapshot = buildSnapshot(history(), hash, 1), lock = hash("lock");
    const signed = await createProtectedBackup({ snapshot, artifactInventoryDigest: capture.inventoryDigest, dependencyLockDigest: lock, ...k, backup });
    writeFileSync(join(f.installedRoot, "main.js"), "replacement not in signed capture");
    const other = await captureInstalledBackup({ ...f, credentialProtector: recovery });
    const originalDigest = capture.inventoryDigest;
    // Transported objects are intentionally mutable; the API must own what it verifies.
    const rawCapture = structuredClone(capture), rawSigned = structuredClone(signed);
    const mutating: BackupPort = { name: "mutable-input", requiresAccount: false, put: backup.put.bind(backup), list: backup.list.bind(backup), async get(id) {
      Object.assign(rawCapture, other); Object.assign(rawSigned.producerSignature, { keyId: "wrong-label" }); return backup.get(id);
    } };
    const report = await restoreInstalledBackup({ capture: rawCapture, targetRoot: join(f.root, "restore"), credentialOpener: recovery,
      signing: { protectedBackup: rawSigned, backup: mutating, trust: k.trust, expectedDependencyLockDigest: lock, hasher: hash } });
    assert.equal(report.inventoryDigest, originalDigest);
    assert.equal(readFileSync(join(report.productTarget, "main.js"), "utf8"), "export const answer = 42;");
    assert.equal(report.signing.status, "distinct-signing-keys-verified");
    assert.equal(report.signing.status === "distinct-signing-keys-verified" && report.signing.producerKeyId, "producer");
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

for (const variant of ["mutate-put", "wrong-ack", "wrong-fetched-count", "wrong-fetched-id", "mutate-ack-during-get"] as const) {
  test(`KEEP-13B-004: shipping pins source identity (${variant})`, async () => {
    const source = history(), original = structuredClone(source), replacement = buildSnapshot(history("other-valid-history"), hash, 1);
    let stored: Snapshot | undefined, acknowledgment: SnapshotRef | undefined;
    const backup: BackupPort = { name: "mutating-target", requiresAccount: false,
      async put(s) {
        if (variant === "mutate-put") {
          (s.blocks as typeof source).splice(0, s.blocks.length, ...replacement.blocks);
          Object.assign(s, replacement);
        }
        stored = structuredClone(s); acknowledgment = ref(s);
        return variant === "wrong-ack" ? { ...acknowledgment, contentRoot: replacement.contentRoot } : acknowledgment;
      }, async list() { return []; }, async get() {
        if (variant === "mutate-ack-during-get") Object.assign(acknowledgment!, { id: "changed-after-check" });
        if (variant === "wrong-fetched-count") return { ...stored!, eventCount: 999 };
        if (variant === "wrong-fetched-id") return { ...stored!, id: "wrong" };
        return stored;
      } };
    const driver = new OffboxShipDriver(backup, () => source, hash, 1);
    const outcome = await driver.shipOnce(10);
    assert.deepEqual(source, original);
    if (variant === "mutate-ack-during-get") {
      assert.equal(outcome.ok, true, "the fetched original is valid; caller-owned ref must remain stable");
      assert.equal(outcome.ref?.id, buildSnapshot(original, hash, 10).id);
      assert.equal(outcome.health.lastShippedId, outcome.ref?.id);
    } else {
      assert.equal(outcome.ok, false); assert.equal(outcome.health.healthy, false); assert.equal(outcome.health.verifiedShips, 0);
    }
  });
}

test("13B signed creation also rejects mutation of the submitted snapshot", async () => {
  const k = keys(), snapshot = buildSnapshot(history(), hash, 1), original = structuredClone(snapshot);
  const backup: BackupPort = { name: "mutating", requiresAccount: false, async put(s) { Object.assign(s, buildSnapshot(history("replacement"), hash, 1)); return ref(s); }, async list() { return []; }, async get() { return undefined; } };
  await assert.rejects(createProtectedBackup({ snapshot, artifactInventoryDigest: hash("artifact"), dependencyLockDigest: hash("lock"), ...k, backup }), /acknowledgement/);
  assert.deepEqual(snapshot, original);
});

test("KEEP-09A-001 extension: genuine signed root detects changed special own key", async () => {
  const k = keys(), backup = new LocalBackup();
  const blocks = history(); Object.assign(blocks[0]!.events[0]!, { payload: JSON.parse('{"ordinary":"ok","__proto__":{"marker":"original"}}') });
  const snapshot = buildSnapshot([sealBlock(undefined, blocks[0]!.events, 1)], hash, 1), artifact = hash("artifact"), lock = hash("lock");
  const signed = await createProtectedBackup({ snapshot, artifactInventoryDigest: artifact, dependencyLockDigest: lock, ...k, backup });
  const altered = structuredClone(snapshot);
  (altered.blocks[0]!.events[0]!.payload.__proto__ as Record<string, unknown>).marker = "altered";
  const verifyInput = { protectedBackup: signed, backup, trust: k.trust, expectedArtifactInventoryDigest: artifact, expectedDependencyLockDigest: lock, hasher: hash };
  assert.equal((await verifyProtectedBackup(verifyInput)).ok, true);
  assert.equal((await verifyProtectedBackup({ ...verifyInput, backup: { ...backup, name: "altered", requiresAccount: false, put: backup.put.bind(backup), list: backup.list.bind(backup), get: async () => altered } })).ok, false);
});
