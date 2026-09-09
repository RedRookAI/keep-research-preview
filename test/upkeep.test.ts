import { test } from "node:test";
import assert from "node:assert/strict";

import { upkeep, prune, normalizedEqual, type UpkeepItem } from "../src/memory/upkeep.js";
import { SensitiveContextVault } from "../src/privacy/contextual_integrity.js";
import { ProjectRegistry } from "../src/session/project_registry.js";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";

// Autonomous upkeep: the self-maintaining second brain. BUILT: dedup/link/supersede/prune. SEAM: similarity +
// extraction. Reversible (supersede-not-delete + tombstones), inspectable, sensitive-through-the-vault. Disprove.

const item = (id: string, key: string, content: string, scope = "projA"): UpkeepItem => ({ id, key, content, scope });

test("dedup: a near-duplicate same-topic candidate is merged, not re-added", () => {
  const existing = [item("m1", "coffee", "prefers coffee in the morning")];
  const r = upkeep(existing, { content: "Prefers coffee in the morning", key: "coffee", scope: "projA" });
  assert.equal(r.action, "dedup", "a duplicate is deduped");
  assert.equal(r.dedupOf, "m1");
});

test("supersede: a same-topic candidate with different content supersedes the stale item (not a duplicate)", () => {
  const existing = [item("m1", "editor", "uses vim")];
  const r = upkeep(existing, { content: "uses emacs now", key: "editor", scope: "projA" });
  assert.equal(r.action, "supersede", "an update supersedes, does not duplicate");
  assert.equal(r.supersedes, "m1", "the stale item is the supersede target (its provenance is retained by the caller)");
});

test("link: existing items in the same scope on a different topic are linked", () => {
  const existing = [item("m1", "coffee", "likes coffee"), item("m2", "editor", "uses vim"), item("m3", "x", "y", "projB")];
  const r = upkeep(existing, { content: "likes tea too", key: "tea", scope: "projA" });
  assert.deepEqual([...r.links].sort(), ["m1", "m2"], "same-scope different-topic items are linked; other-scope is not");
});

test("prune leaves a tombstone with a reason — never a silent delete (reversible + inspectable)", () => {
  const items = [item("m1", "a", "keep me"), item("m2", "b", "prune me")];
  const r = prune(items, (i) => i.id === "m2", "superseded");
  assert.equal(r.kept.length, 1);
  assert.equal(r.tombstones.length, 1, "the pruned item leaves a tombstone, not a silent delete");
  assert.match(r.tombstones[0]!.reason, /superseded/);
  assert.equal(r.tombstones[0]!.id, "m2");
});

test("sensitive routing: a special-category candidate is captured in the CI vault (Round 1)", () => {
  const reg = new ProjectRegistry(new CryptoShredKeyStore());
  const vault = new SensitiveContextVault(reg.namespace(reg.create("P").id));
  const r = upkeep([], { content: "I was diagnosed with cancer", key: "health", scope: "user", subject: "alice" }, { vault });
  assert.equal(r.sensitive, true, "the disclosure is routed through the vault");
  assert.equal(vault.revealToSubject("alice").length, 1, "and it is captured there, subject-scoped");
});

test("inspectable: the upkeep decision exposes action + links + targets", () => {
  const r = upkeep([item("m1", "coffee", "likes coffee")], { content: "uses emacs", key: "editor", scope: "projA" });
  assert.ok(["add", "dedup", "supersede"].includes(r.action));
  assert.ok(Array.isArray(r.links), "links are legible");
});

test("deterministic: same existing + candidate ⇒ same decision", () => {
  const existing = [item("m1", "editor", "uses vim")];
  const c = { content: "uses emacs", key: "editor", scope: "projA" };
  assert.deepEqual(upkeep(existing, c), upkeep(existing, c));
  assert.equal(normalizedEqual("A  b", "a b"), true);
});
