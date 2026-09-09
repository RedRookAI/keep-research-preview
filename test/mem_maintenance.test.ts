import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { MemoryStore } from "../src/memory/store.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";

// a store with a controllable clock
function storeWithClock(clock: () => number): MemoryStore {
  return new MemoryStore(
    new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-mm-"))), new InProcessLock(), new SchemaRegistry()),
    new ModelGateway(new LocalProvider()),
    undefined,
    clock,
  );
}

test("MEM-MAINTENANCE (a): a retrieved lesson gets its access signal recorded (ts + count bump)", async () => {
  let t = 1000;
  const s = storeWithClock(() => t);
  const l = await s.ingest("keep pinned deps for reproducible builds", { origin: "self" });
  assert.equal(s.accessOf(l!.id), undefined, "no access before retrieval");
  t = 2000;
  await s.retrieve("reproducible builds pinned deps", 5);
  const a1 = s.accessOf(l!.id);
  assert.ok(a1, "access recorded after retrieval");
  assert.equal(a1!.count, 1);
  assert.equal(a1!.lastAccessedTs, 2000);
  t = 3000;
  await s.retrieve("reproducible builds pinned deps", 5);
  assert.equal(s.accessOf(l!.id)!.count, 2, "count bumps on re-access");
  assert.equal(s.accessOf(l!.id)!.lastAccessedTs, 3000, "ts refreshes on re-access");
});

test("MEM-MAINTENANCE (b): runMaintenance retires a stale, un-accessed, low-value memory", async () => {
  const NOW = 1_000_000;
  const s = storeWithClock(() => NOW);
  const l = await s.ingest("transient scratch note", { origin: "self", importance: 0.1, validFrom: NOW - 5000 });
  (l as { createdTs: number }).createdTs = NOW - 5000; // old
  const decisions = s.runMaintenance({ staleAgeMs: 1000, importanceFloor: 0.7, lowImportanceCeil: 0.3 });
  const d = decisions.find((x) => x.lessonId === l!.id)!;
  assert.equal(d.retire, true, "stale + low-value + un-accessed → retired");
  assert.equal(s.get(l!.id)!.tier, "retired");
});

test("MEM-MAINTENANCE (c): a frequently-retrieved memory is protected end-to-end (recorded access reinforces)", async () => {
  const NOW = 1_000_000;
  let t = NOW - 5000;
  const s = storeWithClock(() => t);
  const l = await s.ingest("old but frequently used API base url", { origin: "self", importance: 0.1, validFrom: NOW - 5000 });
  (l as { createdTs: number }).createdTs = NOW - 5000; // ancient + low importance
  // the agent keeps retrieving it right up to NOW → access reinforcement should protect it
  t = NOW - 10;
  await s.retrieve("frequently used API base url", 5);
  t = NOW;
  const decisions = s.runMaintenance({ staleAgeMs: 1000, importanceFloor: 0.7, lowImportanceCeil: 0.3, recencyWindowMs: 1000 });
  const d = decisions.find((x) => x.lessonId === l!.id)!;
  assert.equal(d.retire, false, "recent recorded access protects the ancient low-importance memory");
  assert.match(d.reason, /recently accessed/);
  assert.notEqual(s.get(l!.id)!.tier, "retired");
});

test("MEM-MAINTENANCE (d): maintenance is explainable — returns the decisions", async () => {
  const NOW = 1_000_000;
  const s = storeWithClock(() => NOW);
  const keep = await s.ingest("critical invariant", { origin: "self", importance: 0.9, validFrom: NOW - 5000 });
  const drop = await s.ingest("noise", { origin: "self", importance: 0.1, validFrom: NOW - 5000 });
  (drop as { createdTs: number }).createdTs = NOW - 5000;
  const decisions = s.runMaintenance({ staleAgeMs: 1000 });
  assert.ok(decisions.length >= 2, "a decision per live lesson");
  const dk = decisions.find((x) => x.lessonId === keep!.id)!;
  const dd = decisions.find((x) => x.lessonId === drop!.id)!;
  assert.equal(dk.retire, false); assert.ok(dk.reason.length > 0 && typeof dk.priority === "number");
  assert.equal(dd.retire, true); assert.ok(dd.reason.length > 0);
});

test("MEM-MAINTENANCE (guardrail): a high-importance memory is never retired, however stale", async () => {
  const NOW = 1_000_000;
  const s = storeWithClock(() => NOW);
  const l = await s.ingest("user has a severe allergy", { origin: "self", importance: 0.95, validFrom: NOW - 9_000_000 });
  (l as { createdTs: number }).createdTs = NOW - 9_000_000;
  s.runMaintenance({ staleAgeMs: 1000 });
  assert.notEqual(s.get(l!.id)!.tier, "retired", "the guardrail holds through the wired path");
});
