import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileWrappedKeyPersistence } from "../src/keystore/file_wrapped_key_persistence.js";
import { CryptoShredKeyStore, type KeyPersistence } from "../src/keystore/keystore.js";

function paths() {
  const dir = mkdtempSync(join(tmpdir(), "keep-wrapped-keys-"));
  return { masterKeyPath: join(dir, "master.key"), wrappedKeysPath: join(dir, "keys.json") };
}

test("project keys are authenticated ciphertext and restore independently after restart", () => {
  const options = paths();
  const first = new CryptoShredKeyStore(new FileWrappedKeyPersistence(options));
  first.ensureKey("project-a");
  first.ensureKey("project-b");
  const a = first.encrypt("project-a", "alpha secret");
  const b = first.encrypt("project-b", "beta secret");
  const atRest = readFileSync(options.wrappedKeysPath, "utf8");
  assert.doesNotMatch(atRest, /alpha secret|beta secret/u);
  assert.equal(statSync(options.masterKeyPath).mode & 0o777, 0o600);
  assert.equal(statSync(options.wrappedKeysPath).mode & 0o777, 0o600);

  const reopened = new CryptoShredKeyStore(new FileWrappedKeyPersistence(options));
  assert.equal(reopened.decrypt("project-a", a), "alpha secret");
  assert.equal(reopened.decrypt("project-b", b), "beta secret");
  assert.throws(() => reopened.decrypt("project-b", a));
});

test("corrupt wrapped keys and a wrong master key fail closed instead of regenerating", () => {
  const options = paths();
  const first = new CryptoShredKeyStore(new FileWrappedKeyPersistence(options));
  first.ensureKey("project-a");
  const parsed = JSON.parse(readFileSync(options.wrappedKeysPath, "utf8")) as { keys: Record<string, { ciphertext: string }> };
  const prior = parsed.keys["project-a"]!.ciphertext;
  parsed.keys["project-a"]!.ciphertext = `${prior[0] === "0" ? "1" : "0"}${prior.slice(1)}`;
  writeFileSync(options.wrappedKeysPath, JSON.stringify(parsed));
  assert.throws(() => new CryptoShredKeyStore(new FileWrappedKeyPersistence(options)), /authenticate persisted key/u);

  const clean = paths();
  const cleanStore = new CryptoShredKeyStore(new FileWrappedKeyPersistence(clean));
  cleanStore.ensureKey("project-clean");
  const other = paths();
  new FileWrappedKeyPersistence(other);
  writeFileSync(clean.masterKeyPath, readFileSync(other.masterKeyPath));
  chmodSync(clean.masterKeyPath, 0o600);
  assert.throws(() => new CryptoShredKeyStore(new FileWrappedKeyPersistence(clean)), /authenticate persisted key/u);
});

test("failed durable save or delete never changes live key authority", () => {
  const keys = new Map<string, Buffer>();
  let failSave = true;
  let failDelete = true;
  const persistence: KeyPersistence = {
    load: () => keys,
    save: (subject, key) => { if (failSave) throw new Error("save failed"); keys.set(subject, Buffer.from(key)); },
    delete: (subject) => { if (failDelete) throw new Error("delete failed"); keys.delete(subject); },
  };
  const store = new CryptoShredKeyStore(persistence);
  assert.throws(() => store.ensureKey("subject"), /save failed/u);
  assert.equal(store.hasKey("subject"), false);
  failSave = false;
  assert.equal(store.ensureKey("subject"), true);
  const cipher = store.encrypt("subject", "retained");
  assert.throws(() => store.shred("subject"), /delete failed/u);
  assert.equal(store.decrypt("subject", cipher), "retained");
  failDelete = false;
  assert.equal(store.shred("subject"), true);
  assert.throws(() => store.decrypt("subject", cipher), /erased/u);
});

test("independent live instances neither lose keys nor reverse a crypto-shred", () => {
  const options = paths();
  const first = new CryptoShredKeyStore(new FileWrappedKeyPersistence(options));
  const second = new CryptoShredKeyStore(new FileWrappedKeyPersistence(options));
  first.ensureKey("project-a");
  second.ensureKey("project-b");
  let reopened = new CryptoShredKeyStore(new FileWrappedKeyPersistence(options));
  assert.equal(reopened.hasKey("project-a"), true);
  assert.equal(reopened.hasKey("project-b"), true);

  first.shred("project-a");
  second.ensureKey("project-c");
  reopened = new CryptoShredKeyStore(new FileWrappedKeyPersistence(options));
  assert.equal(reopened.hasKey("project-a"), false, "a stale writer must never resurrect a shredded key");
  assert.equal(reopened.hasKey("project-b"), true);
  assert.equal(reopened.hasKey("project-c"), true);
});
