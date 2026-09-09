import { test } from "node:test";
import assert from "node:assert/strict";

import { Bm25Index, tokenize, reciprocalRankFusion } from "../src/currency/bm25.js";
import { LandscapeCatalog } from "../src/currency/landscape_catalog.js";

// --- BM25 core ---

test("a rare/specific term outranks a generic common one (the IDF precision property)", () => {
  const idx = new Bm25Index();
  idx.index([
    { id: "tts", text: "text to speech voice synthesis narration audio" },
    { id: "ffmpeg", text: "audio video convert media encode audio audio" }, // 'audio' is common/repeated
    { id: "pandoc", text: "document convert markdown pdf epub" },
  ]);
  const hits = idx.search("text to speech tts voice");
  assert.equal(hits[0]!.id, "tts"); // the specific voice tool wins, not the generic audio one
});

test("exact-topic docs rank above weakly-related ones", () => {
  const idx = new Bm25Index();
  idx.index([
    { id: "a", text: "invoice billing payments stripe" },
    { id: "b", text: "email newsletter marketing" },
  ]);
  const hits = idx.search("stripe payments");
  assert.equal(hits[0]!.id, "a");
});

test("a query with no shared terms returns no hits (honest, no false match)", () => {
  const idx = new Bm25Index();
  idx.index([{ id: "a", text: "audio video convert" }]);
  assert.equal(idx.search("quantum chromodynamics").length, 0);
});

test("tokenize lowercases and splits on non-alphanumeric", () => {
  assert.deepEqual(tokenize("Text-to-Speech, v2!"), ["text", "to", "speech", "v2"]);
});

test("reciprocal rank fusion combines rankings; empty dense leaves lexical intact", () => {
  const lex = [{ id: "a", score: 3 }, { id: "b", score: 2 }];
  assert.deepEqual(reciprocalRankFusion(lex, []).map((h) => h.id), ["a", "b"]);
  // A doc ranked highly by BOTH should rise to the top.
  const dense = [{ id: "b", score: 9 }, { id: "c", score: 8 }];
  const fused = reciprocalRankFusion(lex, dense);
  assert.equal(fused[0]!.id, "b"); // b appears in both -> highest fused score
});

// --- Catalog precision (the fix in situ) ---

test("a TTS query now ranks a voice tool first, not ffmpeg/pandoc (precision fix proven)", () => {
  const cat = new LandscapeCatalog();
  const hits = cat.matchesTask(["tts", "voice", "text-to-speech", "narration"]);
  assert.ok(hits.length > 0);
  const top = hits[0]!;
  assert.ok(/elevenlabs|voice|speech|tts/i.test(`${top.name} ${top.summary} ${top.tags.join(" ")}`));
  // ffmpeg/pandoc should NOT be the top match for a pure TTS query.
  assert.ok(!/ffmpeg|pandoc/i.test(top.name));
});

test("a catalog query with no relevant option returns nothing (no false-positive suggestions)", () => {
  const cat = new LandscapeCatalog();
  assert.equal(cat.matchesTask(["zzzznomatchatall"]).length, 0);
});
