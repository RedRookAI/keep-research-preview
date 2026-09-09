import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";

import { sanitizeForPrompt, chunkText, chunkCode, estimateTokens } from "../src/frontdoor/chunker.js";
import { buildProjectUnderstanding, summarizeForHuman, type ChunkSummarizer } from "../src/frontdoor/project_understanding.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-f3a-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

// --- Sanitizer (injection front line) ---

test("sanitizeForPrompt strips bidi overrides, zero-width, and control chars", () => {
  const evil = "safe\u202Ereversed\u200Bzerowidth\u0007bell";
  const clean = sanitizeForPrompt(evil);
  assert.ok(!/\u202E/.test(clean)); // bidi override gone
  assert.ok(!/\u200B/.test(clean)); // zero-width gone
  assert.ok(!/\u0007/.test(clean)); // bell (control) replaced
  assert.ok(clean.includes("safe") && clean.includes("reversed"));
});

test("sanitizeForPrompt preserves normal text, tabs, and newlines", () => {
  const s = "line1\n\tindented\nline2";
  assert.equal(sanitizeForPrompt(s), s);
});

// --- Chunker ---

test("chunkText produces chunks near the target size with provenance", () => {
  const raw = Array.from({ length: 50 }, (_, i) => `Paragraph ${i} with some words to fill space.`).join("\n\n");
  const chunks = chunkText(raw, { targetTokens: 64, source: "notes.md" });
  assert.ok(chunks.length > 1);
  assert.equal(chunks[0]!.source, "notes.md");
  assert.equal(chunks[0]!.index, 0);
  for (const c of chunks) assert.ok(c.approxTokens <= 64 * 2, "no chunk wildly over target");
});

test("chunkText hard-splits an oversized single paragraph", () => {
  const huge = "word ".repeat(2000); // ~10k chars, one paragraph
  const chunks = chunkText(huge, { targetTokens: 128 });
  assert.ok(chunks.length > 1); // did not return one giant chunk
});

test("chunkText applies overlap when requested", () => {
  const raw = Array.from({ length: 10 }, (_, i) => `Distinct paragraph number ${i} here.`).join("\n\n");
  const noOverlap = chunkText(raw, { targetTokens: 16, overlapTokens: 0 });
  const withOverlap = chunkText(raw, { targetTokens: 16, overlapTokens: 8 });
  // Overlap makes later chunks longer (they carry a tail of the previous chunk).
  const overlapLonger = withOverlap.slice(1).some((c, i) => c.text.length > (noOverlap[i + 1]?.text.length ?? 0));
  assert.ok(overlapLonger);
});

test("chunkCode splits structure-aware on blank-line block boundaries", () => {
  const code = "function a() {\n  return 1;\n}\n\nfunction b() {\n  return 2;\n}\n\nfunction c() {\n  return 3;\n}";
  const chunks = chunkCode(code, { targetTokens: 8 }); // small target forces splits
  assert.ok(chunks.length >= 2);
});

test("estimateTokens is a positive heuristic", () => {
  assert.ok(estimateTokens("hello world") > 0);
});

// --- Project understanding ---

const echoSummarizer: ChunkSummarizer = async (text) => `summary: ${text.slice(0, 20)}`;

test("a copyleft chunk is REJECTED and never trusted", async () => {
  const spine = newSpine();
  const chunks = [
    { text: "This project builds a task queue in TypeScript.", source: "readme.md", index: 0, approxTokens: 12 },
    { text: "This file is licensed under the GNU General Public License (GPL) v3.", source: "LICENSE", index: 0, approxTokens: 16 },
  ];
  const u = await buildProjectUnderstanding(spine, chunks, echoSummarizer);
  assert.equal(u.rejected.length, 1); // the GPL chunk
  assert.equal(u.rejected[0]!.source, "LICENSE");
  assert.equal(u.chunksProcessed, 1); // only the clean chunk
});

test("a chunk with a secret is REDACTED before it reaches the summarizer", async () => {
  const spine = newSpine();
  let sawSecret = false;
  const spySummarizer: ChunkSummarizer = async (text) => {
    if (text.includes("sk-ant-supersecret")) sawSecret = true;
    return "ok";
  };
  const chunks = [{ text: "config: apiKey = sk-ant-supersecretvalue1234567890ABCD", source: "config.js", index: 0, approxTokens: 20 }];
  const u = await buildProjectUnderstanding(spine, chunks, spySummarizer);
  assert.equal(sawSecret, false); // the summarizer never saw the raw secret
  assert.equal(u.hadRedactions, true);
});

test("understanding is built incrementally, carrying prior context to each chunk", async () => {
  const spine = newSpine();
  const seenPriors: string[] = [];
  const trackingSummarizer: ChunkSummarizer = async (_text, prior) => {
    seenPriors.push(prior);
    return "part";
  };
  const chunks = [
    { text: "Chunk one about auth.", source: "a.md", index: 0, approxTokens: 6 },
    { text: "Chunk two about billing.", source: "a.md", index: 1, approxTokens: 6 },
    { text: "Chunk three about email.", source: "a.md", index: 2, approxTokens: 6 },
  ];
  await buildProjectUnderstanding(spine, chunks, trackingSummarizer);
  assert.equal(seenPriors[0], ""); // first chunk has no prior
  assert.ok(seenPriors[1]!.length > 0); // second chunk received the running understanding
  assert.ok(seenPriors[2]!.length > seenPriors[1]!.length); // it grew
});

test("understanding is budget-bounded and says so", async () => {
  const spine = newSpine();
  const chunks = Array.from({ length: 10 }, (_, i) => ({ text: `chunk ${i}`, source: "big.md", index: i, approxTokens: 3 }));
  const u = await buildProjectUnderstanding(spine, chunks, echoSummarizer, { maxChunks: 4 });
  assert.equal(u.chunksProcessed, 4);
  assert.ok(/large drop/i.test(u.note)); // notes that more remains
});

test("a summarizer failure on one chunk does not abort the whole ingestion", async () => {
  const spine = newSpine();
  let n = 0;
  const flaky: ChunkSummarizer = async () => {
    n++;
    if (n === 2) throw new Error("model hiccup");
    return "ok";
  };
  const chunks = Array.from({ length: 3 }, (_, i) => ({ text: `c${i}`, source: "x.md", index: i, approxTokens: 2 }));
  const u = await buildProjectUnderstanding(spine, chunks, flaky);
  assert.equal(u.chunksProcessed, 2); // 2 succeeded, 1 failed
  assert.ok(u.rejected.some((r) => r.reason === "summary-failed"));
});

test("summarizeForHuman produces a plain-language recap", async () => {
  const spine = newSpine();
  const chunks = [{ text: "A small project.", source: "readme.md", index: 0, approxTokens: 5 }];
  const u = await buildProjectUnderstanding(spine, chunks, echoSummarizer);
  const recap = summarizeForHuman(u);
  assert.ok(/file/i.test(recap));
  assert.ok(!/error|exception/i.test(recap)); // jargon-free
});
