import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { TemporalKnowledgeGraph } from "../src/memory/temporal_kg.js";
import { MemoryStore } from "../src/memory/store.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";

const store = () => new MemoryStore(
  new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-tkg-"))), new InProcessLock(), new SchemaRegistry()),
  new ModelGateway(new LocalProvider()),
);

test("TKG (a): an as-of query returns edges valid at T, excluding later ones", async () => {
  const g = new TemporalKnowledgeGraph(store(), () => 1000);
  await g.addEdge("alice", "livesIn", "Boston", 0);
  await g.addEdge("alice", "worksAt", "Acme", 500);
  const atT = g.edgesAt(200).map((e) => `${e.subject}-${e.relation}-${e.object}`);
  assert.ok(atT.includes("alice-livesIn-Boston"), "the edge valid at T=200 is present");
  assert.ok(!atT.includes("alice-worksAt-Acme"), "an edge that begins at 500 is NOT valid at T=200");
});

test("TKG (b): a contradicting edge invalidates the prior — current query returns only the new one", async () => {
  const g = new TemporalKnowledgeGraph(store(), () => 1000);
  await g.addEdge("alice", "livesIn", "Boston", 0);
  await g.addEdge("alice", "livesIn", "Denver", 100); // contradicts (same subj+rel, diff obj)
  const current = g.currentEdges().filter((e) => e.subject === "alice" && e.relation === "livesIn").map((e) => e.object);
  assert.deepEqual(current, ["Denver"], "only the current (new) value is live; the stale one was invalidated");
});

test("TKG (c): the invalidated edge is STILL visible in an as-of query BEFORE its close (supersede-not-delete)", async () => {
  const g = new TemporalKnowledgeGraph(store(), () => 1000);
  await g.addEdge("alice", "livesIn", "Boston", 0);
  await g.addEdge("alice", "livesIn", "Denver", 100);
  const before = g.edgesAt(50).map((e) => e.object);
  assert.ok(before.includes("Boston"), "at T=50 the Boston edge was still valid (history preserved, not deleted)");
  assert.ok(!before.includes("Denver"), "Denver was not yet valid at T=50");
});

test("TKG (d): typing is enforced — a malformed edge (empty relation/object) is rejected", async () => {
  const g = new TemporalKnowledgeGraph(store(), () => 1000);
  const bad = await g.addEdge("alice", "", "Boston", 0);
  assert.equal(bad, undefined, "an edge with no relation is rejected");
  const bad2 = await g.addEdge("", "livesIn", "Boston", 0);
  assert.equal(bad2, undefined, "an edge with no subject is rejected");
  assert.equal(g.edgesAt(10).length, 0, "no malformed edge was stored");
});

test("TKG (e): the derived-view / dilution caveat is surfaced honestly", async () => {
  const g = new TemporalKnowledgeGraph(store());
  assert.match(g.caveat, /derived view/i);
  assert.match(g.caveat, /misaligned recall|under-use/i);
});

test("TKG relationsOf: neighbours of an entity at a time", async () => {
  const g = new TemporalKnowledgeGraph(store(), () => 1000);
  await g.addEdge("alice", "livesIn", "Boston", 0);
  await g.addEdge("alice", "worksAt", "Acme", 0);
  await g.addEdge("bob", "livesIn", "Denver", 0);
  const rels = g.relationsOf("alice", 10).map((e) => e.relation).sort();
  assert.deepEqual(rels, ["livesIn", "worksAt"], "only alice's edges");
});
