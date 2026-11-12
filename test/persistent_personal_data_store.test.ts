import test from "node:test";
import assert from "node:assert/strict";
import fs, { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import { PersistentPersonalDataStore } from "../src/privacy/persistent_personal_data_store.js";
import { composeKeep } from "../src/compose.js";
import { NODE_IO } from "../src/spine/durable_fs.js";

function fixture(enabled = true) {
  const keys = new CryptoShredKeyStore();
  const path = join(mkdtempSync(join(tmpdir(), "keep-personal-")), "personal.json");
  const options = { enabled, path, subject: "personal:alice", keys };
  return { keys, path, options, store: new PersistentPersonalDataStore(options) };
}

test("G6 requires opt-in and persists only encrypted surrogate/cue/preference values", () => {
  const disabled = fixture(false);
  assert.throws(() => disabled.store.put("cue", "hedging baseline", "0.25"), /not opted in/);

  const f = fixture();
  f.store.put("surrogate", "email#1", "alice@example.com", 1);
  f.store.put("cue", "hedging baseline", "0.25", 2);
  f.store.put("preference", "verbosity", "concise", 3);
  const disk = readFileSync(f.path, "utf8");
  assert.doesNotMatch(disk, /alice@example\.com|0\.25|concise|hedging baseline|verbosity|email#1/);
  assert.doesNotMatch(disk, /plaintextHash/);
  for (const value of ["email#1", "alice@example.com", "hedging baseline", "0.25", "verbosity", "concise"]) {
    assert.ok(!disk.includes(createHash("sha256").update(value).digest("hex")), "no private-value dictionary oracle");
  }

  const restarted = new PersistentPersonalDataStore(f.options);
  assert.deepEqual(restarted.list().map(({ kind, label, value }) => ({ kind, label, value })), [
    { kind: "surrogate", label: "email#1", value: "alice@example.com" },
    { kind: "cue", label: "hedging baseline", value: "0.25" },
    { kind: "preference", label: "verbosity", value: "concise" },
  ]);
});

test("G6 is absent without opt-in and the composed store survives a fresh process-equivalent restart", () => {
  const dataDir = mkdtempSync(join(tmpdir(), "keep-personal-compose-"));
  const withoutOptIn = composeKeep({ dataDir: join(dataDir, "disabled") });
  assert.equal(withoutOptIn.personalDataStore, undefined);
  assert.equal(existsSync(join(dataDir, "disabled", "personal-data")), false);

  const config = { dataDir, persistentPersonalData: { subject: "personal:alice" } } as const;
  const first = composeKeep(config);
  first.personalDataStore!.put("preference", "verbosity", "concise", 10);

  const reopened = composeKeep(config);
  assert.deepEqual(
    reopened.personalDataStore!.list().map(({ kind, label, value }) => ({ kind, label, value })),
    [{ kind: "preference", label: "verbosity", value: "concise" }],
  );
  for (const name of ["store.json", "wrapped-keys.json"]) {
    assert.doesNotMatch(readFileSync(join(dataDir, "personal-data", name), "utf8"), /verbosity|concise/);
  }
});

test("G6 exposes correction, plaintext export, selective erasure, and crypto-shred", () => {
  const f = fixture();
  const cue = f.store.put("cue", "hedging baseline", "0.25", 1);
  const pref = f.store.put("preference", "verbosity", "normal", 2);
  assert.equal(f.store.correct(pref.id, "detailed", 3).value, "detailed");
  assert.equal(f.store.export().items.find((item) => item.id === pref.id)?.value, "detailed");
  assert.ok(!readFileSync(f.path, "utf8").includes(createHash("sha256").update("detailed").digest("hex")));

  assert.equal(f.store.erase(cue.id), true);
  assert.equal(f.store.list().some((item) => item.id === cue.id), false);
  assert.equal(f.store.cryptoShred(), true);
  assert.equal(f.keys.hasKey(f.options.subject), false);
  assert.throws(() => new PersistentPersonalDataStore(f.options).list(), /erased|authenticate|Unsupported state/);
  assert.equal(f.keys.hasKey(f.options.subject), false, "restart never silently recreates a destroyed subject key");
});

function legacyFixture() {
  const f = fixture(), label = "verbosity", value = "concise";
  const legacy = (plain: string) => ({ ...f.keys.encrypt(f.options.subject, plain), plaintextHash: createHash("sha256").update(plain).digest("hex") });
  const original = JSON.stringify({ schema: "keep.personal-data/v2", subject: f.options.subject,
    items: [{ id: "existing-preference", kind: "preference", label: legacy(label), value: legacy(value), createdAt: 1 }] }) + "\n";
  writeFileSync(f.path, original, { mode: 0o600 });
  return { ...f, original, label, value };
}

test("new encryption omits plaintext fingerprints and still decrypts legacy ciphertext", () => {
  const f = fixture();
  const encrypted = f.keys.encrypt(f.options.subject, "yes");
  assert.equal(encrypted.plaintextHash, undefined);
  assert.equal(f.keys.decrypt(f.options.subject, { ...encrypted, plaintextHash: "legacy-unused-fingerprint" }), "yes");
});

test("legacy personal records migrate atomically to authenticated hash-free ciphertext without a legacy copy", () => {
  const f = legacyFixture();
  const migrated = new PersistentPersonalDataStore(f.options);
  assert.deepEqual(migrated.list(), [{ id: "existing-preference", kind: "preference", label: f.label, value: f.value, createdAt: 1 }]);
  const disk = readFileSync(f.path, "utf8");
  assert.equal(JSON.parse(disk).schema, "keep.personal-data/v3");
  assert.doesNotMatch(disk, /plaintextHash|verbosity|concise/);
  assert.deepEqual(readdirSync(dirname(f.path)), ["personal.json"]);
  assert.deepEqual(new PersistentPersonalDataStore(f.options).list(), migrated.list());
  const item = migrated.correct("existing-preference", "brief", 2);
  assert.equal(new PersistentPersonalDataStore(f.options).list()[0]?.value, item.value);
});

test("legacy migration refuses wrong subjects, wrong or missing keys and corrupted ciphertext without replacing recoverable bytes", () => {
  for (const fault of ["foreign", "wrong-key", "missing-key", "tampered"] as const) {
    const f = legacyFixture();
    let options = f.options;
    if (fault === "foreign") { f.keys.ensureKey("personal:bob"); options = { ...options, subject: "personal:bob" }; }
    if (fault === "wrong-key") { const keys = new CryptoShredKeyStore(); keys.ensureKey(f.options.subject); options = { ...options, keys }; }
    if (fault === "missing-key") { f.keys.shred(f.options.subject); }
    if (fault === "tampered") {
      const bad = JSON.parse(f.original), tag: string = bad.items[0].value.authTag;
      bad.items[0].value.authTag = (tag.startsWith("0") ? "1" : "0") + tag.slice(1);
      writeFileSync(f.path, JSON.stringify(bad));
    }
    const before = readFileSync(f.path, "utf8");
    assert.throws(() => new PersistentPersonalDataStore(options), /foreign|migration incomplete|erased/);
    assert.equal(readFileSync(f.path, "utf8"), before, fault);
    assert.deepEqual(readdirSync(dirname(f.path)), ["personal.json"]);
  }
});

test("disabled opt-in leaves a legacy file and its key authority untouched", () => {
  const f = legacyFixture();
  const disabled = new PersistentPersonalDataStore({ ...f.options, enabled: false });
  assert.throws(() => disabled.list(), /not opted in/);
  assert.equal(readFileSync(f.path, "utf8"), f.original);
  assert.equal(f.keys.hasKey(f.options.subject), true);
  assert.equal(existsSync(fixture(false).path), false);
});

test("failed migration before replacement preserves the original and removes its protected temporary file", t => {
  const f = legacyFixture();
  const failure = t.mock.method(fs, "renameSync", () => { throw new Error("simulated replacement failure"); });
  syncBuiltinESMExports();
  try {
    assert.throws(() => new PersistentPersonalDataStore(f.options), /migration incomplete/);
    assert.equal(readFileSync(f.path, "utf8"), f.original);
    assert.deepEqual(readdirSync(dirname(f.path)), ["personal.json"]);
  } finally { failure.mock.restore(); syncBuiltinESMExports(); }
  assert.equal(new PersistentPersonalDataStore(f.options).list()[0]?.value, f.value);
});

test("failed directory sync after migration retains a recoverable hash-free store and reports incomplete durability", t => {
  const f = legacyFixture();
  const failure = t.mock.method(NODE_IO, "fsyncSync", () => {
    throw Object.assign(new Error("simulated directory sync failure"), { code: "EIO" });
  });
  try {
    assert.throws(() => new PersistentPersonalDataStore(f.options), /migration incomplete/);
    const disk = readFileSync(f.path, "utf8");
    assert.equal(JSON.parse(disk).schema, "keep.personal-data/v3");
    assert.doesNotMatch(disk, /plaintextHash/);
    assert.deepEqual(readdirSync(dirname(f.path)), ["personal.json"]);
  } finally { failure.mock.restore(); }
  assert.equal(new PersistentPersonalDataStore(f.options).list()[0]?.value, f.value);
});

test("an interrupted correction preserves the durable value and fences stale in-memory continuation", t => {
  const f = fixture();
  const item = f.store.put("preference", "verbosity", "normal", 1);
  const original = readFileSync(f.path, "utf8");
  const failure = t.mock.method(fs, "renameSync", () => { throw new Error("simulated correction failure"); });
  syncBuiltinESMExports();
  try {
    assert.throws(() => f.store.correct(item.id, "brief", 2), /simulated correction failure/);
    assert.equal(readFileSync(f.path, "utf8"), original);
    assert.throws(() => f.store.put("cue", "other", "value"), /held after a failed write/);
    assert.throws(() => f.store.list(), /held after a failed write/);
  } finally { failure.mock.restore(); syncBuiltinESMExports(); }
  assert.equal(new PersistentPersonalDataStore(f.options).list()[0]?.value, "normal");
});

test("a failed write cannot prevent explicit key erasure", t => {
  const f = fixture();
  const item = f.store.put("preference", "verbosity", "normal", 1);
  const failure = t.mock.method(fs, "renameSync", () => { throw new Error("simulated write failure"); });
  syncBuiltinESMExports();
  try {
    assert.throws(() => f.store.correct(item.id, "brief", 2), /simulated write failure/);
    assert.equal(f.store.cryptoShred(), true);
    assert.equal(f.keys.hasKey(f.options.subject), false);
  } finally { failure.mock.restore(); syncBuiltinESMExports(); }
  assert.throws(() => new PersistentPersonalDataStore(f.options), /erased/);
});

