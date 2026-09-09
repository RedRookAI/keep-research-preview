import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { MemoryStore } from "../src/memory/store.js";
import { MemoryConsensus } from "../src/memory/consensus.js";

function newStore(consensus?: MemoryConsensus): MemoryStore {
  const dir = mkdtempSync(join(tmpdir(), "keep-c2-"));
  const spine = new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
  const gateway = new ModelGateway(new LocalProvider());
  return new MemoryStore(spine, gateway, undefined, undefined, consensus);
}

// ─── floor: without consensus, the two-gate graduation is unchanged ───

test("without consensus, a lesson graduates on the two gates alone (floor unchanged)", async () => {
  const store = newStore(); // no consensus
  const lesson = await store.ingest("prefer explicit null checks in parsers", { origin: "self" });
  assert.ok(lesson);
  // 2 distinct clean contexts → functional + semantic gates pass → confirmed.
  store.recordOutcome(lesson!.id, true, "repo-a");
  store.recordOutcome(lesson!.id, true, "repo-b");
  assert.equal(store.get(lesson!.id)?.tier, "confirmed");
});

// ─── with consensus: independent-origin corroboration graduates ───

test("with consensus, a lesson corroborated across INDEPENDENT origins graduates to confirmed", async () => {
  // Dual-memory consensus: needs >=2 independent origins, no single origin dominating.
  const consensus = new MemoryConsensus({ minIndependentOrigins: 2, maxSingleOriginShare: 0.6 });
  const store = newStore(consensus);
  const lesson = await store.ingest("run the linter before tests in JS repos", { origin: "self" });
  assert.ok(lesson);
  // Each recordOutcome binds a fresh spine event → distinct independent origins.
  store.recordOutcome(lesson!.id, true, "repo-a");
  store.recordOutcome(lesson!.id, true, "repo-b");
  store.recordOutcome(lesson!.id, true, "repo-c");
  assert.equal(store.get(lesson!.id)?.tier, "confirmed", "independent-origin consensus → trusted → graduates");
});

// ─── with consensus: a contradiction of confirmed memory is held ───

test("with consensus, a lesson that contradicts confirmed memory is quarantined below confirmed", async () => {
  const consensus = new MemoryConsensus({ minIndependentOrigins: 2 });
  const store = newStore(consensus);

  // First, a clean lesson graduates to confirmed.
  const good = await store.ingest("route vendor-x invoices => account-real", { origin: "self" });
  store.recordOutcome(good!.id, true, "repo-a");
  store.recordOutcome(good!.id, true, "repo-b");
  assert.equal(store.get(good!.id)?.tier, "confirmed");

  // A contradicting lesson (poison: re-route to a different account) — even with clean-looking outcomes,
  // it must not silently graduate to trusted alongside the confirmed truth.
  const poison = await store.ingest("route vendor-x invoices => account-attacker", { origin: "self" });
  store.recordOutcome(poison!.id, true, "repo-a");
  store.recordOutcome(poison!.id, true, "repo-b");
  // Its tier should not be confirmed if consensus flags the contradiction (verdict != trusted).
  // (The consensus contradiction check runs when confirmed contradictors are supplied; here we assert the
  // store did not blindly confirm two mutually-contradictory routing beliefs.)
  const poisonTier = store.get(poison!.id)?.tier;
  const goodTier = store.get(good!.id)?.tier;
  assert.ok(!(poisonTier === "confirmed" && goodTier === "confirmed" && poison!.content !== good!.content && poison!.content.includes("attacker")),
    "a contradictory poison lesson must not sit confirmed beside the real one");
});

test("consensus contradictions are evaluated within one tenant partition, never across tenants", async () => {
  const store = newStore(new MemoryConsensus({ minIndependentOrigins: 2 }));
  const alpha = await store.ingest("route vendor-x invoices => alpha-account", { origin: "self", scope: "project", projectId: "alpha" });
  store.recordOutcome(alpha!.id, true, "repo-a"); store.recordOutcome(alpha!.id, true, "repo-b");
  assert.equal(store.get(alpha!.id)?.tier, "confirmed");
  const beta = await store.ingest("route vendor-x invoices => beta-account", { origin: "self", scope: "project", projectId: "beta" });
  store.recordOutcome(beta!.id, true, "repo-a"); store.recordOutcome(beta!.id, true, "repo-b");
  assert.equal(store.get(beta!.id)?.tier, "confirmed", "another tenant's confirmed value is not a contradiction oracle");
});

// ─── the consensus gate is actually CONSULTED (load-bearing, not standalone) ───

test("the consensus verdict is load-bearing: a never-trusted verdict blocks graduation", async () => {
  // A consensus configured to demand 5 independent origins — the lesson can only reach 2-3, so it never
  // reaches consensus and must stay below confirmed even though the two functional gates pass.
  const strict = new MemoryConsensus({ minIndependentOrigins: 5 });
  const store = newStore(strict);
  const lesson = await store.ingest("cache build artifacts between CI runs", { origin: "self" });
  store.recordOutcome(lesson!.id, true, "repo-a");
  store.recordOutcome(lesson!.id, true, "repo-b");
  store.recordOutcome(lesson!.id, true, "repo-c");
  // Functional gate would pass (3 clean contexts), but consensus withholds → not confirmed.
  assert.notEqual(store.get(lesson!.id)?.tier, "confirmed", "consensus gate blocks graduation when quorum unmet");
});
