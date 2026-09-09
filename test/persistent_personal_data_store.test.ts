import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import { PersistentPersonalDataStore } from "../src/privacy/persistent_personal_data_store.js";
import { composeKeep } from "../src/compose.js";

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

  assert.equal(f.store.erase(cue.id), true);
  assert.equal(f.store.list().some((item) => item.id === cue.id), false);
  assert.equal(f.store.cryptoShred(), true);
  assert.equal(f.keys.hasKey(f.options.subject), false);
  assert.throws(() => new PersistentPersonalDataStore(f.options).list(), /erased|authenticate|Unsupported state/);
  assert.equal(f.keys.hasKey(f.options.subject), false, "restart never silently recreates a destroyed subject key");
});

