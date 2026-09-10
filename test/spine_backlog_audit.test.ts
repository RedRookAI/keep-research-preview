import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { canonicalize, type StagedEvent } from "../src/spine/event.js";
import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { MAX_BLOCK_BYTES, sealBlock, type SealedBlock } from "../src/spine/hashchain.js";
import { InMemoryWitnessSink } from "../src/spine/witness_sink.js";
import { SpineDurableWitness, intentEntryHash, type WitnessIntent } from "../src/witness/pre_effect_witness.js";

const fixture = () => mkdtempSync(join(tmpdir(), "keep-backlog-audit-"));
const core = (store: FileSpineStore, sink?: InMemoryWitnessSink) => new Spine(store, new InProcessLock(), new SchemaRegistry(), () => 1234, sink);
const event = (id: string, size: number): StagedEvent => ({ id, schemaVersion: 1, type: "generic", actor: "owner", ts: 1234, payload: { data: "x".repeat(size) } });
const bytes = (b: SealedBlock) => Buffer.byteLength(canonicalize(b), "utf8");

if (process.argv[2] === "--backlog-restart") {
  const store = new FileSpineStore(process.argv[3]!, { fsync: true });
  const spine = core(store);
  if (process.argv[4] === "drain") await spine.seal();
  console.log(JSON.stringify({ ok: spine.verify().ok, ids: spine.replay().map(e => e.id), pending: spine.pending().map(e => e.id), sizes: store.readBlocks().map(bytes) }));
} else {
  const restart = (dir: string, drain = false) => {
    const result = spawnSync(process.execPath, [fileURLToPath(import.meta.url), "--backlog-restart", dir, drain ? "drain" : "read"], { encoding: "utf8", timeout: 15_000, maxBuffer: 64 * 1024 });
    assert.equal(result.status, 0, result.stderr + result.stdout);
    return JSON.parse(result.stdout) as { ok: boolean; ids: string[]; pending: string[]; sizes: number[] };
  };
  for (const tenant of [undefined, "alpha"]) test(`KEEP-09A-003 drains admitted backlog in one call (${tenant ?? "personal"})`, async () => {
    const dir = fixture(), store = new FileSpineStore(dir, { fsync: true }), sink = new InMemoryWitnessSink(), spine = core(store, sink);
    const ids = [600_000, 600_000, 5].map((size, i) => spine.stage({ type: "generic", actor: tenant ? "alpha-agent" : "owner", payload: { ...(tenant ? { tenant } : {}), data: "x".repeat(size), i } }));
    const stagingBefore = readFileSync(join(dir, "staging.jsonl"));
    const final = await spine.seal();
    assert.equal(final?.seq, 1);
    assert.deepEqual(spine.replay().map(e => e.id), ids);
    assert.equal(spine.pending().length, 0);
    assert.equal(sink.latest()?.headHash, final?.hash);
    assert.equal(sink.history().length, 1, "publish the successful full-drain head");
    assert.deepEqual(readFileSync(join(dir, "staging.jsonl")), stagingBefore);
    const restored = restart(dir);
    assert.equal(restored.ok, true); assert.deepEqual(restored.ids, ids); assert.deepEqual(restored.pending, []);
    assert.ok(restored.sizes.every(n => n <= MAX_BLOCK_BYTES));
  });

  test("admission includes event/block envelopes, escapes and multibyte bytes", async () => {
    const spine = core(new FileSpineStore(fixture(), { fsync: true }));
    assert.throws(() => spine.stage({ type: "generic", actor: "owner", payload: { data: "x".repeat(MAX_BLOCK_BYTES - 100) } }), /bound|fit|size/i);
    assert.throws(() => spine.stage({ type: "generic", actor: "a".repeat(MAX_BLOCK_BYTES), payload: {} }), /bound|fit|size/i);
    assert.throws(() => spine.stage({ type: "generic", actor: "owner", payload: { data: "é".repeat(MAX_BLOCK_BYTES / 2 - 50) } }), /bound|fit|size/i);
    assert.equal(spine.pending().length, 0);
    const ids = ["é".repeat(300_000), "\\\"".repeat(150_000)].map(data => spine.stage({ type: "generic", actor: "owner", payload: { data } }));
    await spine.seal(); assert.deepEqual(spine.replay().map(e => e.id), ids); assert.equal(spine.verify().ok, true);
  });

  test("checkpoint splits large backlog and keeps ordinary checkpoint events distinct", async () => {
    const dir = fixture(), store = new FileSpineStore(dir, { fsync: true }), spine = core(store);
    spine.stage({ type: "generic", actor: "owner", payload: { initial: true } });
    const prior = await spine.seal();
    const ids = [600_000, 600_000].map(size => spine.stage({ type: "checkpoint", actor: "owner", payload: { ordinary: true, data: "x".repeat(size) } }));
    const cp = await spine.checkpoint("owner");
    const marker = cp.events.at(-1)!;
    assert.equal(marker.type, "checkpoint"); assert.equal(marker.payload.attestsRootUpTo, prior!.cumulativeRoot);
    assert.deepEqual(spine.replay().slice(1, -1).map(e => e.id), ids);
    assert.ok(store.readBlocks().every(b => bytes(b) <= MAX_BLOCK_BYTES));
    assert.deepEqual(restart(dir).pending, []);
    const before = readFileSync(join(dir, "chain.jsonl"));
    await assert.rejects(() => spine.checkpoint("a".repeat(MAX_BLOCK_BYTES)), /bound|fit|size/i);
    assert.deepEqual(readFileSync(join(dir, "chain.jsonl")), before, "oversized marker refused before mutation");
  });

  for (const nonGenesis of [false, true]) test(`near-limit event fits future numeric envelopes and splits marker (existing head=${nonGenesis})`, async () => {
    const dir = fixture(), store = new FileSpineStore(dir, { fsync: true });
    let now = 1234;
    const spine = new Spine(store, new InProcessLock(), new SchemaRegistry(), () => now);
    if (nonGenesis) { spine.stage({ type: "generic", actor: "owner", payload: { seed: true } }); await spine.seal(); }
    const available = MAX_BLOCK_BYTES - bytes(sealBlock(undefined, [event("x".repeat(36), 0)], 0)) - 48;
    assert.throws(() => spine.stage({ type: "generic", actor: "owner", payload: { data: "x".repeat(available + 1) } }), /envelope bound/);
    const id = spine.stage({ type: "generic", actor: "owner", payload: { data: "x".repeat(available) } });
    now = -0.0000012345678901234567;
    assert.equal(JSON.stringify(now).length, 25);
    const cp = await spine.checkpoint("owner");
    assert.equal(cp.seq, nonGenesis ? 2 : 1); assert.equal(cp.events.length, 1); assert.equal(cp.events[0]!.type, "checkpoint");
    assert.equal(store.readBlocks()[nonGenesis ? 1 : 0]!.events[0]!.id, id);
    assert.ok(store.readBlocks().every(b => bytes(b) <= MAX_BLOCK_BYTES));
    assert.equal(restart(dir).ids.length, nonGenesis ? 3 : 2);
  });

  for (const fault of ["append", "cursor"] as const) for (const mode of ["seal", "checkpoint"] as const) test(`bounded ${mode} recovers a ${fault} failure after committed progress`, async () => {
    const dir = fixture();
    class FaultStore extends FileSpineStore {
      calls = 0;
      override appendBlock(b: SealedBlock): void {
        if (fault === "append" && ++this.calls === 2) throw new Error("controlled append failure before mutation");
        super.appendBlock(b);
      }
      override removeStaged(count: number): void {
        if (fault === "cursor" && ++this.calls === 2) throw new Error("controlled cursor failure after durable second block");
        super.removeStaged(count);
      }
    }
    const store = new FaultStore(dir, { fsync: true }), spine = core(store);
    const ids = [600_000, 600_000, 600_000].map(size => spine.stage({ type: "generic", actor: "owner", payload: { data: "x".repeat(size) } }));
    await assert.rejects(() => mode === "seal" ? spine.seal() : spine.checkpoint("owner"), /controlled/);
    assert.equal(store.readBlocks().length, fault === "append" ? 1 : 2);
    const restored = restart(dir, true);
    assert.equal(restored.ok, true); assert.deepEqual(restored.ids, ids); assert.deepEqual(restored.pending, []);
    assert.ok(restored.sizes.every(n => n <= MAX_BLOCK_BYTES));
  });

  test("final checkpoint cursor recovery skips only its exact synthetic suffix", async () => {
    const dir = fixture();
    class LastCursorStore extends FileSpineStore {
      calls = 0;
      override removeStaged(count: number): void {
        if (++this.calls === 2) throw new Error("controlled final cursor failure");
        super.removeStaged(count);
      }
    }
    const store = new LastCursorStore(dir, { fsync: true }), spine = core(store);
    const ids = [600_000, 600_000].map(size => spine.stage({ type: "checkpoint", actor: "owner", payload: { ordinary: true, data: "x".repeat(size) } }));
    await assert.rejects(() => spine.checkpoint("owner"), /controlled final cursor/);
    const marker = store.lastBlock()!.events.at(-1)!;
    assert.equal(marker.payload.attestsRootUpTo, "0".repeat(64));
    const restored = restart(dir, true);
    assert.deepEqual(restored.ids, [...ids, marker.id]); assert.deepEqual(restored.pending, []);
    assert.equal(await core(new FileSpineStore(dir, { fsync: true })).seal(), undefined, "no new block on recovery-only/no-work path");
    assert.equal(restored.ok, true);
  });

  test("an append after snapshot is preserved for the next seal", async () => {
    const dir = fixture(), late = event("late", 8);
    class LateStore extends FileSpineStore {
      added = false;
      override appendBlock(b: SealedBlock): void { super.appendBlock(b); if (!this.added) { this.added = true; this.appendStaged(late); } }
    }
    const store = new LateStore(dir, { fsync: true }), spine = core(store);
    const ids = [600_000, 600_000].map(size => spine.stage({ type: "generic", actor: "owner", payload: { data: "x".repeat(size) } }));
    await spine.seal(); assert.deepEqual(spine.replay().map(e => e.id), ids); assert.deepEqual(spine.pending().map(e => e.id), [late.id]);
    assert.deepEqual(restart(dir, true).ids, [...ids, late.id]);
  });

  test("old admitted backlog drains; an old individually unsealable event is retained explicitly", async () => {
    const dir = fixture(), store = new FileSpineStore(dir, { fsync: true });
    store.appendStaged(event("old-a", 600_000)); store.appendStaged(event("old-b", 600_000));
    assert.deepEqual(restart(dir, true).ids, ["old-a", "old-b"]);
    store.appendStaged(event("oversized-legacy", MAX_BLOCK_BYTES)); store.appendStaged(event("later", 1));
    const before = readFileSync(join(dir, "staging.jsonl")), cursor = readFileSync(join(dir, "staging.cursor"));
    await assert.rejects(() => core(store).seal(), /oversized-legacy/);
    assert.deepEqual(readFileSync(join(dir, "staging.jsonl")), before); assert.deepEqual(readFileSync(join(dir, "staging.cursor")), cursor);
    assert.deepEqual(restart(dir).pending, ["oversized-legacy", "later"]);
  });

  test("legacy Unicode block verification stays historical; new writes enforce bytes", async () => {
    const dir = fixture(), store = new FileSpineStore(dir, { fsync: true });
    const legacy = sealBlock(undefined, [{ ...event("legacy", 0), payload: { data: "é".repeat(600_000) } }], 1234);
    assert.ok(canonicalize(legacy).length < MAX_BLOCK_BYTES); assert.ok(bytes(legacy) > MAX_BLOCK_BYTES);
    assert.throws(() => store.appendBlock(legacy), /byte|size|bound/i);
    writeFileSync(join(dir, "chain.jsonl"), JSON.stringify(legacy) + "\n");
    assert.equal(restart(dir).ok, true, "read compatibility does not qualify it under the new write bound");
    const before = readFileSync(join(dir, "chain.jsonl"), "utf8"), spine = core(store);
    spine.stage({ type: "generic", actor: "owner", payload: { next: true } }); await spine.seal();
    assert.equal(readFileSync(join(dir, "chain.jsonl"), "utf8").startsWith(before), true);
    assert.equal(restart(dir).ok, true); assert.ok(bytes(store.lastBlock()!) <= MAX_BLOCK_BYTES);
  });

  test("pre-effect witness acknowledges the intent at the end of the drained backlog", async () => {
    const dir = fixture(), store = new FileSpineStore(dir, { fsync: true }), spine = core(store);
    for (let i = 0; i < 2; i++) spine.stage({ type: "generic", actor: "owner", payload: { data: "x".repeat(600_000) } });
    const witness = new SpineDurableWitness(spine, "audit-chain");
    const intent: WitnessIntent = { idemKey: "intent", attemptId: "one", permitId: "permit", epoch: 1n, family: "test", operation: "write", objectId: "synthetic", executionDigest: "a".repeat(64), bindingKind: "semantic-invocation", keyEpoch: 1n, causalParents: [] };
    const ack = await witness.sealIntent(intent);
    const last = spine.replay().at(-1)!;
    assert.equal(last.type, "effect.intent"); assert.equal(ack.entryHash, intentEntryHash(intent));
    assert.equal(ack.headHash, store.lastBlock()!.hash); assert.equal(ack.seq, 1n);
    assert.deepEqual(spine.pending(), []); assert.equal(restart(dir).ids.at(-1), last.id);
  });
}
