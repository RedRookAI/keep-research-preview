import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { contradicts, parseRelation, cardinalityOf, intervalsOverlap, DEFAULT_CARDINALITY, type EdgeFact } from "../src/memory/contradiction.js";
import { TemporalKnowledgeGraph } from "../src/memory/temporal_kg.js";
import { MemoryStore } from "../src/memory/store.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";

const store = () => new MemoryStore(
  new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-toki-"))), new InProcessLock(), new SchemaRegistry()),
  new ModelGateway(new LocalProvider()),
);
const E = (subject: string, relation: string, object: string, validFrom = 0, validTo?: number): EdgeFact =>
  ({ subject, relation, object, validFrom, ...(validTo !== undefined ? { validTo } : {}) });

test("TOKI (a): a FUNCTIONAL-relation conflict contradicts (new object supersedes)", () => {
  // livesIn is functional; same subject, different object, overlapping time → contradict
  assert.equal(contradicts(E("alice", "livesIn", "Denver", 100), E("alice", "livesIn", "Boston", 0)), true);
});

test("TOKI (b): a MULTI-VALUED relation does NOT contradict (additive — both retained)", () => {
  // speaks is multi-valued; different object is additive, not a conflict
  assert.equal(contradicts(E("alice", "speaks", "French", 100), E("alice", "speaks", "English", 0)), false);
});

test("TOKI (c): explicit NEGATION contradicts the affirmative (same base + object)", () => {
  assert.equal(contradicts(E("alice", "not:livesIn", "Boston", 100), E("alice", "livesIn", "Boston", 0)), true);
  // and the reverse direction
  assert.equal(contradicts(E("alice", "livesIn", "Boston", 100), E("alice", "not:livesIn", "Boston", 0)), true);
});

test("TOKI (d): NON-overlapping valid-time intervals do NOT conflict (sequential facts coexist)", () => {
  // existing [0,50), new starts at 100 → no overlap even though functional + different object
  assert.equal(contradicts(E("alice", "livesIn", "Denver", 100), E("alice", "livesIn", "Boston", 0, 50)), false);
  assert.equal(intervalsOverlap(100, undefined, 0, 50), false);
});

test("TOKI (e): an UNKNOWN relation defaults to multi-valued (no over-supersession)", () => {
  assert.equal(cardinalityOf("collaboratedWith", DEFAULT_CARDINALITY), "multi_valued");
  assert.equal(contradicts(E("alice", "collaboratedWith", "Bob", 100), E("alice", "collaboratedWith", "Carol", 0)), false);
});

test("TOKI parseRelation: strips the not: prefix", () => {
  assert.deepEqual(parseRelation("not:role"), { base: "role", negated: true });
  assert.deepEqual(parseRelation("role"), { base: "role", negated: false });
});

test("TOKI wired: TKG supersedes a functional conflict but keeps additive multi-valued edges", async () => {
  const g = new TemporalKnowledgeGraph(store(), () => 1000);
  await g.addEdge("alice", "livesIn", "Boston", 0);
  await g.addEdge("alice", "livesIn", "Denver", 100);        // functional → supersedes Boston
  await g.addEdge("alice", "speaks", "English", 0);
  await g.addEdge("alice", "speaks", "French", 50);          // multi-valued → both kept
  const now = g.currentEdges();
  const livesIn = now.filter((e) => e.relation === "livesIn").map((e) => e.object);
  const speaks = now.filter((e) => e.relation === "speaks").map((e) => e.object).sort();
  assert.deepEqual(livesIn, ["Denver"], "functional livesIn superseded to the current value");
  assert.deepEqual(speaks, ["English", "French"], "additive speaks kept both");
});

test("TOKI wired: negation supersedes the affirmative in the graph", async () => {
  const g = new TemporalKnowledgeGraph(store(), () => 1000);
  await g.addEdge("alice", "worksAt", "Acme", 0);
  await g.addEdge("alice", "not:worksAt", "Acme", 100);       // negation → supersedes the affirmative
  const worksAt = g.currentEdges().filter((e) => e.relation === "worksAt" && e.object === "Acme");
  assert.equal(worksAt.length, 0, "the affirmative worksAt was superseded by its negation");
});
