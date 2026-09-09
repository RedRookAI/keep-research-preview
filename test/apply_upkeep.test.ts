import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { applyUpkeep, applyPrune } from "../src/memory/apply_upkeep.js";
import { upkeep, prune, type UpkeepItem, type Candidate } from "../src/memory/upkeep.js";
import { MemoryStore } from "../src/memory/store.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { SensitiveContextVault } from "../src/privacy/contextual_integrity.js";
import { ProjectRegistry } from "../src/session/project_registry.js";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";

// H1: the upkeep apply adapter — the pure decision (upkeep) wired to the real MemoryStore. Idempotent + supersede-
// not-delete via the retired tier + tombstones-not-silent-deletes + no double-capture. Verify by disproof.

function newStore(): MemoryStore {
  const dir = mkdtempSync(join(tmpdir(), "keep-h1-"));
  return new MemoryStore(new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry()), new ModelGateway(new LocalProvider()));
}
const liveCount = (s: MemoryStore): number => s.all().filter((l) => l.tier !== "retired").length;

test("add: an add result ingests once", async () => {
  const store = newStore();
  const c: Candidate = { content: "prefers vim", key: "editor", scope: "user" };
  const r = upkeep([], c);
  assert.equal(r.action, "add");
  await applyUpkeep(store, c, r);
  assert.equal(liveCount(store), 1, "the new lesson was ingested");
});

test("dedup: a near-duplicate is NOT re-added", async () => {
  const store = newStore();
  const first: Candidate = { content: "prefers vim", key: "editor", scope: "user" };
  await applyUpkeep(store, first, upkeep([], first));
  const existing: UpkeepItem[] = store.all().map((l) => ({ id: l.id, content: l.content, key: "editor", scope: "user" }));
  const dupCand: Candidate = { content: "Prefers  vim", key: "editor", scope: "user" }; // near-dup (case/space)
  const r = upkeep(existing, dupCand);
  assert.equal(r.action, "dedup");
  await applyUpkeep(store, dupCand, r);
  assert.equal(liveCount(store), 1, "no re-add on dedup");
});

test("supersede: retires the stale lesson (present for provenance) AND adds the new — not a duplicate", async () => {
  const store = newStore();
  const first: Candidate = { content: "uses vim", key: "editor", scope: "user" };
  const applied = await applyUpkeep(store, first, upkeep([], first));
  const staleId = applied.addedId!;
  const existing: UpkeepItem[] = [{ id: staleId, content: "uses vim", key: "editor", scope: "user" }];
  const update: Candidate = { content: "uses emacs now", key: "editor", scope: "user" };
  const r = upkeep(existing, update);
  assert.equal(r.action, "supersede");
  await applyUpkeep(store, update, r);
  assert.equal(store.get(staleId)!.tier, "retired", "the stale lesson is retired (supersede-not-delete), still present");
  assert.equal(liveCount(store), 1, "exactly one live lesson — the new one, not a duplicate");
});

test("applyPrune records a tombstone (retired) — never a silent delete", () => {
  const store = newStore();
  const items = [{ id: "x", content: "c", key: "k", scope: "user" }];
  // ingest a real lesson to prune
  return applyUpkeep(store, { content: "stale note", key: "k", scope: "user" }, upkeep([], { content: "stale note", key: "k", scope: "user" })).then(async (a) => {
    const id = a.addedId!;
    const { tombstones } = prune([{ id, content: "stale note", key: "k", scope: "user" }], () => true, "stale");
    const res = applyPrune(store, tombstones);
    assert.deepEqual(res.retired, [id]);
    assert.equal(store.get(id)!.tier, "retired", "the pruned lesson is a tombstone (retired + present), not silently deleted");
    void items;
  });
});

test("idempotence: applying the same supersede twice ≡ once (no double-retire, no duplicate)", async () => {
  const store = newStore();
  const first: Candidate = { content: "uses vim", key: "editor", scope: "user" };
  const applied = await applyUpkeep(store, first, upkeep([], first));
  const staleId = applied.addedId!;
  const existing: UpkeepItem[] = [{ id: staleId, content: "uses vim", key: "editor", scope: "user" }];
  const update: Candidate = { content: "uses emacs now", key: "editor", scope: "user" };
  const r = upkeep(existing, update);
  await applyUpkeep(store, update, r); // apply once
  const afterOnce = { total: store.all().length, live: liveCount(store) };
  const second = await applyUpkeep(store, update, r); // apply twice — same result
  const afterTwice = { total: store.all().length, live: liveCount(store) };
  assert.deepEqual(afterTwice, afterOnce, "apply-twice leaves the store identical to apply-once");
  assert.equal(second.noop, true, "the repeat apply is a no-op on state");
});

test("no double-capture: a sensitive candidate is vaulted once by upkeep; the adapter does not re-capture", async () => {
  const reg = new ProjectRegistry(new CryptoShredKeyStore());
  const vault = new SensitiveContextVault(reg.namespace(reg.create("P").id));
  const store = newStore();
  const c: Candidate = { content: "I was diagnosed with cancer", key: "health", scope: "user", subject: "alice" };
  const r = upkeep([], c, { vault }); // upkeep captures the sensitive disclosure ONCE
  assert.equal(vault.revealToSubject("alice").length, 1);
  await applyUpkeep(store, c, r); // the adapter has no vault surface — cannot double-capture
  assert.equal(vault.revealToSubject("alice").length, 1, "still exactly one vault entry after apply");
});

test("deterministic: same add applied to two fresh stores yields the same live count", async () => {
  const a = newStore();
  const b = newStore();
  const c: Candidate = { content: "x", key: "k", scope: "user" };
  await applyUpkeep(a, c, upkeep([], c));
  await applyUpkeep(b, c, upkeep([], c));
  assert.equal(liveCount(a), liveCount(b));
});
