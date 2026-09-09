import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  putScopedPreference,
  scopedVersions,
  resolveScopedProfile,
  assertScopedRead,
  ownerOf,
} from "../src/personalize/scoped_preferences.js";
import { type PolicyBounds } from "../src/personalize/personalize.js";
import { RevisionStore } from "../src/frontdoor/revision_store.js";
import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { ProjectRegistry, CrossProjectAccessError } from "../src/session/project_registry.js";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import { asProjectId, isProjectId } from "../src/session/project_id.js";

// Red-team of the project-isolation boundary. Each attack is encoded as a PASSING (blocked) test whose specific
// defense, when neutered, reddens it. The boundary held on every axis; this suite locks that in.

function newStore(): RevisionStore {
  const dir = mkdtempSync(join(tmpdir(), "keep-rt-"));
  return new RevisionStore(new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry()));
}
function registry(): ProjectRegistry {
  return new ProjectRegistry(new CryptoShredKeyStore());
}
const BOUNDS: PolicyBounds = {
  reliabilityFloor: 0.7, autonomyBackstop: "collaborator", modelCeilingTier: 3,
  defaultPromptFormat: "markdown", defaultVerbosity: "normal",
};

test("ATTACK 1 — cross-project read is blocked by STRUCTURAL owner equality (not a prefix match)", () => {
  const store = newStore();
  const reg = registry();
  const a = reg.namespace(reg.create("A").id);
  const b = reg.namespace(reg.create("B").id);
  putScopedPreference(store, a, "verbosity", "detailed");
  assert.equal(scopedVersions(store, b).length, 0, "B's namespace owns none of A's preference versions");
  assert.equal(resolveScopedProfile(store, b, {}, BOUNDS).verbosity, "normal", "B resolves the default");
});

test("ATTACK 2 — a forged / unregistered ProjectId is rejected (branded, validated, not a bare cast)", () => {
  const reg = registry();
  assert.equal(isProjectId("prj_deadbeef"), false, "short/foreign id is not a valid ProjectId");
  assert.throws(() => asProjectId("prj_evil"), "asProjectId rejects a malformed id");
  // a well-formed but UNREGISTERED id cannot obtain a namespace (registry.get throws).
  const unregistered = asProjectId("prj_" + "0".repeat(32));
  assert.throws(() => reg.namespace(unregistered), "no namespace for an unregistered project");
});

test("ATTACK 3 — scope-string confusion stays within the writer's namespace (crafted @scope can't cross)", () => {
  const store = newStore();
  const reg = registry();
  const a = reg.namespace(reg.create("A").id);
  const b = reg.namespace(reg.create("B").id);
  // A crafts a scope containing '::' and B's-looking content — the key is still owned by A structurally.
  putScopedPreference(store, a, "verbosity", "detailed", "evil::prj_bbbb::pref:x");
  assert.equal(scopedVersions(store, b).length, 0, "the crafted scope does not leak to B");
  // and the owner of A's crafted key is A, by the field before the FIRST separator.
  const key = a.key("pref:verbosity@evil::prj_bbbb::pref:x");
  assert.equal(ownerOf(key), a.projectId, "owner is the first field, regardless of '::' later in the key");
});

test("ATTACK 4 — crypto-shred is complete: neither current NOR superseded history is readable afterwards", () => {
  const store = newStore();
  const reg = registry();
  const rec = reg.create("A");
  const a = reg.namespace(rec.id);
  putScopedPreference(store, a, "verbosity", "normal");
  putScopedPreference(store, a, "verbosity", "detailed"); // supersedes → a historical version now exists
  const key = a.key("pref:verbosity");
  assert.ok(store.history(key).length >= 2, "there is a superseded historical version in the append-only spine");
  reg.remove(rec.id); // crypto-shred
  // every version (current + historical) was encrypted under the destroyed key ⇒ nothing decrypts.
  assert.equal(resolveScopedProfile(store, a, {}, BOUNDS).verbosity, "normal", "no plaintext survives the shred");
  for (const v of store.history(key)) {
    assert.throws(() => a.decrypt(JSON.parse(v.content)), "each historical ciphertext is unreadable post-shred");
  }
});

test("ATTACK 5 — a tampered ciphertext fails CLOSED (GCM auth); it is excluded, never fail-open to a value", () => {
  const store = newStore();
  const reg = registry();
  const a = reg.namespace(reg.create("A").id);
  putScopedPreference(store, a, "promptFormat", "terse");
  const key = a.key("pref:promptFormat");
  const tampered = JSON.parse(store.current(key)!.content);
  // Flip the last ciphertext byte DETERMINISTICALLY (XOR 0xff) so the tamper is ALWAYS a real change.
  // (The old `slice(0,-2) + "ff"` was a no-op ~1/256 of runs — when the random-nonce ciphertext already
  //  ended in "ff" — so GCM auth passed and the test flaked; a fixed replacement byte is not a tamper.)
  const lastByte = parseInt(tampered.data.slice(-2), 16) ^ 0xff;
  tampered.data = tampered.data.slice(0, -2) + lastByte.toString(16).padStart(2, "0"); // edit the ciphertext body
  store.revise(key, JSON.stringify(tampered));
  assert.equal(resolveScopedProfile(store, a, {}, BOUNDS).promptFormat, "markdown", "tampered ⇒ excluded ⇒ safe default");
});

test("HARDENING — a malformed / unowned key fails CLOSED with CrossProjectAccessError (structural owner check)", () => {
  const reg = registry();
  const a = reg.namespace(reg.create("A").id);
  assert.equal(ownerOf("weird::stuff"), undefined, "a non-ProjectId owner field ⇒ owned by no project");
  assert.equal(ownerOf("noseparator"), undefined, "a key without the separator ⇒ owned by no project");
  assert.throws(() => assertScopedRead(a, "weird::stuff"), CrossProjectAccessError, "malformed owner ⇒ fail closed");
  assert.throws(() => assertScopedRead(a, a.key("pref:x").replace(a.projectId, reg.namespace(reg.create("B").id).projectId)), CrossProjectAccessError, "foreign owner ⇒ fail closed");
});
