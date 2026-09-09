import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runMemoryEval, SEEDED_MEM_SCENARIOS, type MemScenario } from "../src/eval/memory_eval.js";
import { MemoryStore } from "../src/memory/store.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";

const freshStore = () => new MemoryStore(
  new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-me-"))), new InProcessLock(), new SchemaRegistry()),
  new ModelGateway(new LocalProvider()),
);

test("MEM-EVAL runs the seeded set and every question type passes on the real store", async () => {
  const r = await runMemoryEval(SEEDED_MEM_SCENARIOS, { freshStore });
  assert.equal(r.overall.passed, r.overall.total, `all seeded scenarios should pass; got ${r.overall.passed}/${r.overall.total}`);
  // per-type present (not one aggregate)
  const types = r.perType.map((t) => t.type).sort();
  assert.deepEqual(types, ["abstention", "knowledge-update", "multi-session", "single-session-user", "temporal-reasoning"]);
});

test("MEM-EVAL (a) knowledge-update: the CURRENT value wins, the stale value is gone", async () => {
  const s = SEEDED_MEM_SCENARIOS.filter((x) => x.type === "knowledge-update");
  const r = await runMemoryEval(s, { freshStore });
  const ku = r.perType.find((t) => t.type === "knowledge-update")!;
  assert.equal(ku.passed, ku.total, "current-wins + stale-absent");
});

test("MEM-EVAL (b) temporal-reasoning: an as-of query returns the value valid THEN", async () => {
  const s = SEEDED_MEM_SCENARIOS.filter((x) => x.type === "temporal-reasoning");
  const r = await runMemoryEval(s, { freshStore });
  const tr = r.perType.find((t) => t.type === "temporal-reasoning")!;
  assert.equal(tr.passed, tr.total, "as-of returns the then-valid value, not the later one");
});

test("MEM-EVAL (c) abstention: a no-evidence query yields no confident hit", async () => {
  const s = SEEDED_MEM_SCENARIOS.filter((x) => x.type === "abstention");
  const r = await runMemoryEval(s, { freshStore });
  const abs = r.perType.find((t) => t.type === "abstention")!;
  assert.equal(abs.passed, abs.total, "the store correctly abstains on unknown info");
});

test("MEM-EVAL (d) reports per-type recall, not one aggregate", async () => {
  const r = await runMemoryEval(SEEDED_MEM_SCENARIOS, { freshStore });
  assert.ok(r.perType.length >= 5, "each type scored separately");
  for (const t of r.perType) assert.ok(typeof t.recallAtK === "number", `${t.type} has its own recall@k`);
});

test("MEM-EVAL (e) surfaces the post-filter-dilution caveat when temporal-reasoning is evaluated", async () => {
  const withTemporal = await runMemoryEval(SEEDED_MEM_SCENARIOS, { freshStore });
  assert.ok(withTemporal.caveats.some((c) => /post-filter dilution/i.test(c)), "dilution caveat surfaced");
  // and the honest seeded-proxy label is always present
  assert.match(withTemporal.seededProxyNote, /SEEDED in-repo proxy/);
});
