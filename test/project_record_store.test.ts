import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import { FileWrappedKeyPersistence } from "../src/keystore/file_wrapped_key_persistence.js";
import { FileProjectRecordStore, type ProjectRecordStore } from "../src/session/project_record_store.js";
import { ProjectRegistry } from "../src/session/project_registry.js";
import { ProjectSessionManager } from "../src/session/project_session_manager.js";
import { withSyncFileMutationLock } from "../src/spine/sync_file_mutation_lock.js";

test("synchronous mutation lock rejects PID-reuse identity and reaps its stale carrier", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-sync-lock-stale-")); const target = join(dir, "records.json"); const lock = `${target}.mutation.lock`;
  writeFileSync(lock, `${JSON.stringify({ schema: "keep.sync-file-lock/v1", pid: process.pid, processStart: "not-this-process", token: "old" })}\n`, { mode: 0o600 });
  let ran = false; withSyncFileMutationLock(target, () => { ran = true; });
  assert.equal(ran, true); assert.equal(existsSync(lock), false); assert.equal(readdirSync(dir).some((name) => name.includes(".stale-")), false);
});

test("durable project identities, labels, and lifecycle records survive registry restart", () => {
  const path = join(mkdtempSync(join(tmpdir(), "keep-project-records-")), "projects.json");
  const first = new ProjectRegistry(new CryptoShredKeyStore(), new FileProjectRecordStore(path));
  const alpha = first.create("alpha software project");
  const beta = first.create("beta content project");
  first.setLifecycle(alpha.id, "background");
  first.rename(beta.id, "beta manuscript");
  const expected = [first.get(alpha.id), first.get(beta.id)];

  const reopened = new ProjectRegistry(new CryptoShredKeyStore(), new FileProjectRecordStore(path));
  assert.deepEqual(reopened.list(), expected);
  assert.notEqual(alpha.id, beta.id);
  assert.equal(statSync(path).mode & 0o777, 0o600);
});

test("malformed, duplicate, oversized, and non-project durable records fail closed", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-project-records-bad-"));
  const path = join(dir, "projects.json");
  const store = new FileProjectRecordStore(path);
  assert.throws(() => store.save([{ id: "../escape", name: "bad", lifecycle: "active", createdAt: 1, updatedAt: 1 } as never], 0), /project/i);
  writeFileSync(path, JSON.stringify([{ id: "prj_00000000000000000000000000000000", name: "x", lifecycle: "active", createdAt: 2, updatedAt: 1 }]));
  assert.throws(() => store.load(), /invalid project record store/u);
  writeFileSync(path, Buffer.alloc(64 * 1024 * 1024 + 1));
  assert.throws(() => store.load(), /exceeds/u);
});

test("registry publishes no in-memory mutation when durable save fails", () => {
  let durable: readonly import("../src/session/project_registry.js").ProjectRecord[] = [];
  let revision = 0;
  let fail = false;
  const store: ProjectRecordStore = {
    load: () => ({ revision, records: durable }),
    save: (records, expected) => { if (fail) throw new Error("disk unavailable"); assert.equal(expected, revision); durable = records.map((record) => ({ ...record })); return ++revision; },
  };
  const keys = new CryptoShredKeyStore();
  const registry = new ProjectRegistry(keys, store);
  const project = registry.create("survives failed rename");
  fail = true;
  assert.throws(() => registry.rename(project.id, "must not publish"), /disk unavailable/u);
  assert.equal(registry.get(project.id).name, "survives failed rename");
  assert.equal(JSON.parse(JSON.stringify(durable))[0].name, "survives failed rename");
});

test("durable deletion tombstone commits before crypto-shred and restart finishes interruption", () => {
  let durable: readonly import("../src/session/project_registry.js").ProjectRecord[] = [];
  let revision = 0;
  const store: ProjectRecordStore = {
    load: () => ({ revision, records: durable }),
    save: (records, expected) => { assert.equal(expected, revision); durable = records.map((record) => ({ ...record })); return ++revision; },
  };
  class InterruptingKeys extends CryptoShredKeyStore {
    interrupt = false;
    override shred(subject: string): boolean {
      if (this.interrupt) throw new Error("interrupted shred");
      return super.shred(subject);
    }
  }
  const keys = new InterruptingKeys();
  const first = new ProjectRegistry(keys, store);
  const removed = first.create("remove me");
  const retained = first.create("retain me");
  keys.interrupt = true;
  assert.throws(() => first.remove(removed.id), /interrupted shred/u);
  assert.equal(durable.find((record) => record.id === removed.id)?.lifecycle, "deleted");
  assert.equal(keys.hasKey(removed.id), true);

  keys.interrupt = false;
  const reopened = new ProjectRegistry(keys, store);
  assert.equal(reopened.has(removed.id), false);
  assert.equal(keys.hasKey(removed.id), false);
  assert.equal(reopened.has(retained.id), true);
});

test("real wrapped-key carriers retry interrupted shred and preserve a sibling across restarts", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-project-real-shred-"));
  const options = { masterKeyPath: join(dir, "master.key"), wrappedKeysPath: join(dir, "keys.json") };
  const recordsPath = join(dir, "projects.json");
  const real = new FileWrappedKeyPersistence(options);
  let interrupt = true;
  const faulting = {
    load: () => real.load(),
    save: (subject: string, key: Buffer) => real.save(subject, key),
    delete: (subject: string) => { if (interrupt) throw new Error("interrupted real shred"); real.delete(subject); },
  };
  const firstKeys = new CryptoShredKeyStore(faulting);
  const first = new ProjectRegistry(firstKeys, new FileProjectRecordStore(recordsPath));
  const removed = first.create("remove real key");
  const retained = first.create("retain real key");
  const removedCiphertext = first.namespace(removed.id).encrypt("removed secret");
  const retainedCiphertext = first.namespace(retained.id).encrypt("retained secret");
  assert.throws(() => first.remove(removed.id), /interrupted real shred/u);
  assert.equal(first.lifecycle(removed.id), "deleted");

  interrupt = false;
  first.remove(removed.id); // same-process retry must be possible after the tombstone commit.
  const reopenedKeys = new CryptoShredKeyStore(new FileWrappedKeyPersistence(options));
  const reopened = new ProjectRegistry(reopenedKeys, new FileProjectRecordStore(recordsPath));
  assert.equal(reopened.has(removed.id), false);
  assert.equal(reopenedKeys.hasKey(removed.id), false);
  assert.throws(() => reopenedKeys.decrypt(removed.id, removedCiphertext), /erased|shredded/u);
  assert.equal(reopenedKeys.decrypt(retained.id, retainedCiphertext), "retained secret");

  const secondRestart = new CryptoShredKeyStore(new FileWrappedKeyPersistence(options));
  assert.equal(secondRestart.hasKey(removed.id), false);
  assert.equal(secondRestart.decrypt(retained.id, retainedCiphertext), "retained secret");
});

test("refresh and manager deletion both retry a tombstoned shred without consuming the revision", () => {
  let durable: readonly import("../src/session/project_registry.js").ProjectRecord[] = []; let revision = 0;
  const store: ProjectRecordStore = { load: () => ({ revision, records: durable }), save: (records, expected) => { assert.equal(expected, revision); durable = records.map((row) => ({ ...row })); return ++revision; } };
  class FaultingKeys extends CryptoShredKeyStore { fail = false; override shred(subject: string): boolean { if (this.fail) throw new Error("shred unavailable"); return super.shred(subject); } }
  const writerKeys = new FaultingKeys(); const writer = new ProjectRegistry(writerKeys, store); const project = writer.create("retry deletion");
  const siblingKeys = new FaultingKeys(); const sibling = new ProjectRegistry(siblingKeys, store);
  writerKeys.fail = true; assert.throws(() => writer.remove(project.id), /shred unavailable/u);
  siblingKeys.fail = true; assert.throws(() => sibling.list(), /shred unavailable/u);
  siblingKeys.fail = false; assert.deepEqual(sibling.list(), []); assert.equal(siblingKeys.hasKey(project.id), false);

  const managerKeys = new FaultingKeys(); const managerRegistry = new ProjectRegistry(managerKeys); const manager = new ProjectSessionManager(managerRegistry);
  const managed = manager.create({ name: "manager retry" }); managerKeys.fail = true;
  assert.throws(() => manager.delete(managed.id), /shred unavailable/u);
  managerKeys.fail = false; manager.delete(managed.id); assert.equal(managerRegistry.lifecycle(managed.id), "deleted"); assert.equal(managerKeys.hasKey(managed.id), false);
});

test("returned records are detached and cannot mutate registry authority", () => {
  const registry = new ProjectRegistry(new CryptoShredKeyStore());
  const created = registry.create("immutable boundary");
  created.name = "forged";
  const listed = registry.list()[0]!;
  listed.lifecycle = "archived";
  assert.equal(registry.get(created.id).name, "immutable boundary");
  assert.equal(registry.get(created.id).lifecycle, "active");
});

test("a stale process cannot overwrite a deletion tombstone or resurrect its project", () => {
  const path = join(mkdtempSync(join(tmpdir(), "keep-project-record-cas-")), "projects.json");
  const first = new ProjectRegistry(new CryptoShredKeyStore(), new FileProjectRecordStore(path));
  const erased = first.create("sensitive project");
  const stale = new ProjectRegistry(new CryptoShredKeyStore(), new FileProjectRecordStore(path));
  first.remove(erased.id);
  assert.throws(() => stale.create("unrelated stale write"), /project record conflict/u);
  const reopened = new ProjectRegistry(new CryptoShredKeyStore(), new FileProjectRecordStore(path));
  assert.equal(reopened.has(erased.id), false);
  assert.equal(reopened.lifecycle(erased.id), "deleted");
  assert.doesNotMatch(readFileSync(path, "utf8"), /sensitive project/u, "erasure tombstone must not retain the project label");
});
