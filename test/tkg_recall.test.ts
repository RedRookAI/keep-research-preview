import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { MemoryStore } from "../src/memory/store.js";
import { TemporalKnowledgeGraph } from "../src/memory/temporal_kg.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";

function store(clock: () => number = () => 1000): MemoryStore {
  return new MemoryStore(
    new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-recall-"))), new InProcessLock(), new SchemaRegistry()),
    new ModelGateway(new LocalProvider()),
    undefined,
    clock,
  );
}
// livesIn is functional (DEFAULT_CARDINALITY) → contradictions supersede
const graph = (s: MemoryStore, clock: () => number) => new TemporalKnowledgeGraph(s, clock);

test("TKG-RECALL (a): recallEntity returns an entity's current relations from the graph", async () => {
  const s = store();
  const g = graph(s, () => 1000);
  await g.addEdge("alice", "worksAt", "Acme", 0);
  await g.addEdge("alice", "speaks", "French", 0);
  const rels = s.recallEntity("alice").map((e) => `${e.relation}-${e.object}`).sort();
  assert.deepEqual(rels, ["speaks-French", "worksAt-Acme"], "graph-recall surfaces alice's current edges");
});

test("TKG-RECALL (b): an as-of recall returns the relations valid at T (not later ones)", async () => {
  const s = store();
  const g = graph(s, () => 1000);
  await g.addEdge("alice", "worksAt", "Acme", 0);
  await g.addEdge("alice", "livesIn", "Denver", 500); // begins at 500
  const atT = s.recallEntity("alice", 200).map((e) => e.object);
  assert.ok(atT.includes("Acme"), "worksAt valid at T=200");
  assert.ok(!atT.includes("Denver"), "livesIn begins at 500 — not recalled at T=200");
});

test("TKG-RECALL (c): a superseded relation is absent from CURRENT recall but present in an as-of recall before its close", async () => {
  const s = store(() => 1000);
  const g = graph(s, () => 1000);
  await g.addEdge("alice", "livesIn", "Boston", 0);   // functional
  await g.addEdge("alice", "livesIn", "Denver", 100); // supersedes Boston at 100
  const now = s.recallEntity("alice").filter((e) => e.relation === "livesIn").map((e) => e.object);
  assert.deepEqual(now, ["Denver"], "current recall shows only the live value");
  const past = s.recallEntity("alice", 50).filter((e) => e.relation === "livesIn").map((e) => e.object);
  assert.deepEqual(past, ["Boston"], "as-of recall before the close still shows the superseded value");
});

test("TKG-RECALL (d): graph-recall complements semantic retrieve (both reachable, distinct results)", async () => {
  const s = store();
  const g = graph(s, () => 1000);
  await g.addEdge("alice", "worksAt", "Acme", 0);
  await s.ingest("alice prefers dark roast coffee in the morning", { origin: "self" });
  // graph-recall: structured edge
  const graphHits = s.recallEntity("alice");
  assert.ok(graphHits.some((e) => e.object === "Acme"), "graph-recall returns the structured edge");
  // vector-recall: fuzzy semantic match on the free-text lesson
  const vecHits = await s.retrieve("coffee preference morning", 5);
  assert.ok(vecHits.some((h) => h.lesson.content.includes("dark roast")), "vector-recall returns the semantic lesson");
  // distinct shapes: graph edges vs retrieval hits
  assert.ok(graphHits[0] && "relation" in graphHits[0] && vecHits[0] && "similarity" in vecHits[0], "distinct result shapes");
});
