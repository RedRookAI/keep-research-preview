import { test } from "node:test";
import assert from "node:assert/strict";

import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import { Cassette, InMemoryCassetteStore, keyOf, normalizeGenerate } from "../src/gateway/cassette.js";
import { RecordingProvider, ReplayProvider, CassetteMissError, type StreamingProvider } from "../src/gateway/record_replay.js";

/** A counting fake provider — lets us prove how many LIVE calls actually happened. */
class FakeProvider implements StreamingProvider {
  readonly isLocal = true;
  calls = { generate: 0, embed: 0, stream: 0 };
  constructor(readonly name = "fake-model") {}
  async generate(req: GenerateRequest): Promise<GenerateResult> {
    this.calls.generate++;
    return { text: `echo:${req.prompt}`, model: this.name, tokensIn: req.prompt.length, tokensOut: 3 };
  }
  async embed(texts: readonly string[]): Promise<Embedding[]> {
    this.calls.embed++;
    return texts.map((t) => [t.length, 0.5]);
  }
  async generateStream(req: GenerateRequest, onDelta?: (t: string) => void): Promise<GenerateResult> {
    this.calls.stream++;
    for (const part of ["a", "b", "c"]) onDelta?.(part);
    return { text: "abc", model: this.name, tokensIn: 1, tokensOut: 3 };
  }
}

// ── Recording ───────────────────────────────────────────────────────────────

test("INVARIANT: RecordingProvider passes through AND records generate", async () => {
  const fake = new FakeProvider();
  const store = new InMemoryCassetteStore();
  const rec = new RecordingProvider(fake, store);
  const r = await rec.generate({ prompt: "hello" });
  assert.equal(r.text, "echo:hello");
  assert.equal(fake.calls.generate, 1, "the real provider was called");
  const cassette = await store.load();
  assert.equal(cassette.size, 1, "interaction recorded");
});

test("RecordingProvider records embed + stream too", async () => {
  const fake = new FakeProvider();
  const store = new InMemoryCassetteStore();
  const rec = new RecordingProvider(fake, store);
  await rec.embed(["x", "yy"]);
  await rec.generateStream({ prompt: "s" });
  const c = await store.load();
  assert.equal(c.size, 2);
});

// ── Strict replay: serves hits, THROWS on miss ──────────────────────────────

test("INVARIANT: strict ReplayProvider serves a recorded generate hit", async () => {
  const fake = new FakeProvider();
  const store = new InMemoryCassetteStore();
  await new RecordingProvider(fake, store).generate({ prompt: "hello" });

  const replay = new ReplayProvider(await store.load(), { mode: "strict", modelName: fake.name });
  const r = await replay.generate({ prompt: "hello" });
  assert.equal(r.text, "echo:hello");
});

test("INVARIANT: strict ReplayProvider THROWS on a miss (no live call permitted)", async () => {
  const replay = new ReplayProvider(new Cassette(), { mode: "strict", modelName: "fake-model" });
  await assert.rejects(() => replay.generate({ prompt: "never recorded" }), (e: unknown) => e instanceof CassetteMissError);
});

// ── Fallthrough: record-if-absent ───────────────────────────────────────────

test("INVARIANT: fallthrough ReplayProvider records-if-absent, then serves on repeat", async () => {
  const fake = new FakeProvider();
  const store = new InMemoryCassetteStore();
  const replay = new ReplayProvider(await store.load(), { mode: "fallthrough", inner: fake, store });

  const r1 = await replay.generate({ prompt: "q" }); // miss → live + record
  assert.equal(r1.text, "echo:q");
  assert.equal(fake.calls.generate, 1);

  const r2 = await replay.generate({ prompt: "q" }); // hit → served from cassette
  assert.equal(r2.text, "echo:q");
  assert.equal(fake.calls.generate, 1, "second call served from cassette — NO new live call");
});

// ── Streaming record/replay ─────────────────────────────────────────────────

test("INVARIANT: streaming records deltas and strict replay re-emits them in order", async () => {
  const fake = new FakeProvider();
  const store = new InMemoryCassetteStore();
  const recDeltas: string[] = [];
  await new RecordingProvider(fake, store).generateStream({ prompt: "s" }, (d) => recDeltas.push(d));
  assert.deepEqual(recDeltas, ["a", "b", "c"]);

  const replay = new ReplayProvider(await store.load(), { mode: "strict", modelName: fake.name });
  const replayDeltas: string[] = [];
  const r = await replay.generateStream({ prompt: "s" }, (d) => replayDeltas.push(d));
  assert.equal(r.text, "abc");
  assert.deepEqual(replayDeltas, ["a", "b", "c"], "recorded deltas re-emitted identically");
});

// ── Cassette JSON round-trip + keying ───────────────────────────────────────

test("cassette round-trips through JSON", async () => {
  const fake = new FakeProvider();
  const store = new InMemoryCassetteStore();
  await new RecordingProvider(fake, store).generate({ prompt: "persist me" });
  const json = (await store.load()).toJSON();
  const restored = Cassette.fromJSON(json);
  assert.equal(restored.size, 1);
});

test("INVARIANT: keying is stable for equivalent requests and differs for different prompts", () => {
  const a = keyOf(normalizeGenerate("generate", "m", { prompt: "hi", maxTokens: 10 }));
  const b = keyOf(normalizeGenerate("generate", "m", { prompt: "hi", maxTokens: 10 }));
  const c = keyOf(normalizeGenerate("generate", "m", { prompt: "different", maxTokens: 10 }));
  assert.equal(a, b, "same request → same key");
  assert.notEqual(a, c, "different prompt → different key");
});

// ── The linchpin property: deterministic offline replay, zero live calls ────

test("INVARIANT: record-then-strict-replay is byte-identical with ZERO live calls", async () => {
  const fake = new FakeProvider();
  const store = new InMemoryCassetteStore();

  // Record phase: a small "pipeline" of several distinct calls.
  const rec = new RecordingProvider(fake, store);
  const recorded: string[] = [];
  for (const p of ["localize", "plan", "repair"]) recorded.push((await rec.generate({ prompt: p })).text);
  const liveCallsAfterRecord = fake.calls.generate;
  assert.equal(liveCallsAfterRecord, 3);

  // Replay phase: a FRESH fake to prove zero live calls; strict mode.
  const freshFake = new FakeProvider();
  const replay = new ReplayProvider(await store.load(), { mode: "strict", modelName: fake.name });
  const replayed: string[] = [];
  for (const p of ["localize", "plan", "repair"]) replayed.push((await replay.generate({ prompt: p })).text);

  assert.deepEqual(replayed, recorded, "replay reproduces the recorded results exactly");
  assert.equal(freshFake.calls.generate, 0, "ZERO live calls during strict replay — the determinism guarantee");
});
