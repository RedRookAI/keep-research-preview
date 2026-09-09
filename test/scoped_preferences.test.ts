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
} from "../src/personalize/scoped_preferences.js";
import { type PolicyBounds } from "../src/personalize/personalize.js";
import { RevisionStore } from "../src/frontdoor/revision_store.js";
import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { ProjectRegistry, CrossProjectAccessError } from "../src/session/project_registry.js";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";

// Cryptographic preference isolation — bind the preference spine through the ProjectNamespace. BUILT: the
// namespacing binding + default-deny + assertScopedRead. SEAM: the persistent per-project store. Verify by disproof.

function newStore(): RevisionStore {
  const dir = mkdtempSync(join(tmpdir(), "keep-pi-"));
  return new RevisionStore(new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry()));
}
function registry(): ProjectRegistry {
  return new ProjectRegistry(new CryptoShredKeyStore());
}
const BOUNDS: PolicyBounds = {
  reliabilityFloor: 0.7, autonomyBackstop: "collaborator", modelCeilingTier: 3,
  defaultPromptFormat: "markdown", defaultVerbosity: "normal",
};

test("cryptographic isolation: a preference written under project A is NOT visible under project B", () => {
  const store = newStore();
  const reg = registry();
  const a = reg.namespace(reg.create("A").id);
  const b = reg.namespace(reg.create("B").id);
  putScopedPreference(store, a, "verbosity", "detailed");

  assert.equal(scopedVersions(store, b).length, 0, "B's namespace sees NONE of A's preferences");
  assert.equal(resolveScopedProfile(store, b, {}, BOUNDS).verbosity, "normal", "B resolves the default, not A's value");
  assert.equal(resolveScopedProfile(store, a, {}, BOUNDS).verbosity, "detailed", "A sees its own preference");
});

test("default-deny: assertScopedRead throws CrossProjectAccessError on a cross-namespace key (isolated)", () => {
  const reg = registry();
  const a = reg.namespace(reg.create("A").id);
  const b = reg.namespace(reg.create("B").id);
  const aKey = a.key("pref:verbosity");
  assert.throws(() => assertScopedRead(b, aKey), CrossProjectAccessError, "B may not read A's key");
  assert.doesNotThrow(() => assertScopedRead(a, aKey), "A may read its own key");
});

test("no regression: within-project resolution matches the envelope (CP-net scope + clamp both hold)", () => {
  const store = newStore();
  const reg = registry();
  const a = reg.namespace(reg.create("A").id);
  // CP-net scope: a scoped pref applies only in its context.
  putScopedPreference(store, a, "verbosity", "detailed", "project:alpha");
  assert.equal(resolveScopedProfile(store, a, { scope: "project:alpha" }, BOUNDS).verbosity, "detailed", "in scope");
  assert.equal(resolveScopedProfile(store, a, { scope: "project:beta" }, BOUNDS).verbosity, "normal", "out of scope ⇒ default");
  // clamp: a preference can't relax the reliability floor.
  putScopedPreference(store, a, "minReliability", "0.3");
  assert.equal(resolveScopedProfile(store, a, {}, BOUNDS).minReliability, 0.7, "clamp still holds within the binding");
});

test("clean-delete: crypto-shredding project A makes its preferences inaccessible (default)", () => {
  const store = newStore();
  const reg = registry();
  const rec = reg.create("A");
  const a = reg.namespace(rec.id);
  putScopedPreference(store, a, "verbosity", "detailed");
  assert.equal(resolveScopedProfile(store, a, {}, BOUNDS).verbosity, "detailed", "readable before shred");
  reg.remove(rec.id); // crypto-shred: destroy A's key
  // the pre-shred namespace `a` can no longer decrypt ⇒ content is cryptographically inaccessible ⇒ default.
  assert.equal(resolveScopedProfile(store, a, {}, BOUNDS).verbosity, "normal", "unreadable after crypto-shred");
});

test("deterministic: the same store + namespace resolve identically", () => {
  const store = newStore();
  const reg = registry();
  const a = reg.namespace(reg.create("A").id);
  putScopedPreference(store, a, "promptFormat", "terse");
  assert.deepEqual(resolveScopedProfile(store, a, {}, BOUNDS), resolveScopedProfile(store, a, {}, BOUNDS));
});
