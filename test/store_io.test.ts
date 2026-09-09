import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { assembleDerived, applyRestored, roundTrip, type DerivedSources } from "../src/portability/store_io.js";
import { exportAll, importAll } from "../src/portability/portability.js";
import { MemoryStore } from "../src/memory/store.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";

// H2: the portability store-I/O adapter — pure export/import wired to the real stores. Round-trip fidelity +
// metamorphic stability + import-at-probation + CI-scoping. Verify by disproof.

function newStore(): MemoryStore {
  const dir = mkdtempSync(join(tmpdir(), "keep-h2-"));
  return new MemoryStore(new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry()), new ModelGateway(new LocalProvider()));
}
const liveContents = (s: MemoryStore): string[] => s.all().filter((l) => l.tier !== "retired").map((l) => l.content).sort();

test("assembleDerived reflects the real store (+ pass-through categories)", async () => {
  const store = newStore();
  await store.ingest("prefers vim", { origin: "self", scope: "user" });
  const state = assembleDerived("alice", { memoryStore: store, preferences: [{ dimension: "verbosity", value: "terse" }] });
  assert.equal(state.memories.length, 1, "the store's memory is in the bundle");
  assert.equal(state.memories[0]!.content, "prefers vim");
  assert.equal(state.preferences.length, 1, "pass-through preferences are carried");
});

test("applyRestored applies imported memories to the real store at PROBATION", async () => {
  const src = newStore();
  await src.ingest("uses emacs", { origin: "self", scope: "user" }); // starts at candidate
  const bundle = exportAll("alice", assembleDerived("alice", { memoryStore: src }));
  const res = importAll(bundle);
  assert.ok(res.ok);
  const dst = newStore();
  if (res.ok) await applyRestored(res.restored, { memoryStore: dst });
  const applied = dst.all().find((l) => l.content === "uses emacs");
  assert.ok(applied, "the imported memory is in the destination store");
  assert.equal(applied!.tier, "probation", "imported memory lands at probation, not confirmed");
});

test("live round-trip reproduces the memory content across two stores", async () => {
  const src = newStore();
  await src.ingest("alpha note", { origin: "self", scope: "user" });
  await src.ingest("beta note", { origin: "self", scope: "project" });
  const dst = newStore();
  const res = await roundTrip("alice", { memoryStore: src }, { memoryStore: dst });
  assert.ok(res.ok);
  assert.deepEqual(liveContents(dst), liveContents(src), "every memory content survives the round-trip");
});

test("metamorphic stability: a second round-trip yields the same content as the first", async () => {
  const s1 = newStore();
  await s1.ingest("gamma note", { origin: "self", scope: "user" });
  const s2 = newStore();
  await roundTrip("alice", { memoryStore: s1 }, { memoryStore: s2 });
  const s3 = newStore();
  await roundTrip("alice", { memoryStore: s2 }, { memoryStore: s3 });
  assert.deepEqual(liveContents(s3), liveContents(s2), "export→import→export is stable (content-equivalent)");
});

test("CI-scoping on assembly: another subject's memory is filtered out of the bundle", async () => {
  const store = newStore();
  const alice = (await store.ingest("alice private", { origin: "self", scope: "user" }))!;
  await store.ingest("bob private", { origin: "self", scope: "user" });
  // subjectOf marks the second memory as bob's; assembleDerived tags per-subject; exportAll filters to alice.
  const sources: DerivedSources = { memoryStore: store, subjectOf: (l) => (l.id === alice.id ? "alice" : "bob") };
  const bundle = exportAll("alice", assembleDerived("alice", sources));
  const contents = bundle.state.memories.map((m) => m.content);
  assert.deepEqual(contents, ["alice private"], "only alice's memory is exported; bob's is filtered out");
});

test("deterministic: same store assembled twice ⇒ identical DerivedState", async () => {
  const store = newStore();
  await store.ingest("delta note", { origin: "self", scope: "user" });
  assert.deepEqual(assembleDerived("alice", { memoryStore: store }), assembleDerived("alice", { memoryStore: store }));
});
