import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { explainForgetting, applyForgetting, type AccessInfo, type ForgetConfig } from "../src/memory/forgetting.js";
import { MemoryStore } from "../src/memory/store.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";

const store = () => new MemoryStore(
  new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-decay-"))), new InProcessLock(), new SchemaRegistry()),
  new ModelGateway(new LocalProvider()),
);
const NOW = 1_000_000;
const cfg: ForgetConfig = { now: NOW, staleAgeMs: 1000, importanceFloor: 0.7, lowImportanceCeil: 0.3 };
const noAccess = (_id: string): AccessInfo | undefined => undefined;

// ingest a lesson at a chosen importance + createdTs by reaching into the stored lesson (deterministic test setup)
async function seed(s: MemoryStore, content: string, importance: number, createdTs: number, validTo?: number): Promise<string> {
  const l = await s.ingest(content, { origin: "self", importance, validFrom: createdTs });
  // set createdTs deterministically for the test (createdTs is readonly at runtime; cast for the fixture)
  (l as { createdTs: number }).createdTs = createdTs;
  if (validTo !== undefined) s.closeValidInterval(l!.id, validTo);
  return l!.id;
}

test("MEM-DECAY (a): a stale, low-importance, un-accessed memory is retired", async () => {
  const s = store();
  const id = await seed(s, "transient debug note", 0.2, NOW - 5000); // old + low importance
  const decisions = applyForgetting(s, noAccess, cfg);
  const d = decisions.find((x) => x.lessonId === id)!;
  assert.equal(d.retire, true, "stale + low-importance + un-accessed → retired");
  assert.equal(s.get(id)!.tier, "retired");
});

test("MEM-DECAY (b): a still-valid HIGH-IMPORTANCE memory is NEVER retired (the guardrail)", async () => {
  const s = store();
  const id = await seed(s, "user has a penicillin allergy", 0.9, NOW - 500000); // ancient but high-importance
  const decisions = applyForgetting(s, noAccess, cfg);
  const d = decisions.find((x) => x.lessonId === id)!;
  assert.equal(d.retire, false, "high-importance is never forgotten, however old");
  assert.notEqual(s.get(id)!.tier, "retired");
  assert.match(d.reason, /high-importance/);
});

test("MEM-DECAY (c): a recently-accessed memory is protected regardless of age", async () => {
  const s = store();
  const id = await seed(s, "old but frequently used glossary", 0.2, NOW - 500000); // ancient + low importance
  const access = (qid: string): AccessInfo | undefined => (qid === id ? { lastAccessedTs: NOW - 10, count: 9 } : undefined);
  const decisions = applyForgetting(s, access, cfg);
  const d = decisions.find((x) => x.lessonId === id)!;
  assert.equal(d.retire, false, "recent access protects even an ancient low-importance memory");
  assert.match(d.reason, /recently accessed/);
});

test("MEM-DECAY (d): retire is reversible/audited, NOT a delete — the memory + its as-of history survive", async () => {
  const s = store();
  const id = await seed(s, "stale fact valid over [t0,t1]", 0.1, NOW - 5000, NOW - 100); // expired
  applyForgetting(s, noAccess, cfg);
  assert.ok(s.get(id), "the lesson still EXISTS after retirement (not deleted)");
  assert.equal(s.get(id)!.tier, "retired");
  // as-of history survives: it was valid before its validTo, and validAt does not filter by tier
  const beforeClose = s.validAt(NOW - 5000).map((l) => l.id);
  assert.ok(beforeClose.includes(id), "as-of history is preserved — the retired memory is still visible in the past");
});

test("MEM-DECAY (e): the policy EXPLAINS what it would retire and why (no mutation)", async () => {
  const s = store();
  const keep = await seed(s, "critical constraint", 0.9, NOW - 5000);
  const drop = await seed(s, "old noise", 0.1, NOW - 5000);
  const report = explainForgetting(s.all(), noAccess, cfg);
  // explain does not mutate
  assert.notEqual(s.get(drop)!.tier, "retired", "explainForgetting is read-only");
  const dk = report.find((x) => x.lessonId === keep)!;
  const dd = report.find((x) => x.lessonId === drop)!;
  assert.equal(dk.retire, false); assert.ok(dk.reason.length > 0);
  assert.equal(dd.retire, true); assert.match(dd.reason, /stale.*low-importance/);
  assert.ok(typeof dd.priority === "number", "each decision carries a retention priority");
});
