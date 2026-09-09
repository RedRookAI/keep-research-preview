import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { buildCorpusSuite } from "../src/research/corpus_suite.js";
import type { ResearchReport } from "../src/research/research_loop.js";

function reportWith(supportingText: string, locator = "http://src.example/1"): ResearchReport {
  return {
    need: { needed: true, reason: "test" } as unknown as ResearchReport["need"],
    searched: true,
    iterations: 1,
    claims: [
      { id: "c1", text: "a claim", citations: [{ id: "z1", title: "Source One", locator, supportingText } as never] },
    ],
  } as unknown as ResearchReport;
}

test("detectNeed: a research-derived report warrants a corpus; a bare goal does not", () => {
  const suite = buildCorpusSuite({ projectName: "p-need" });
  assert.equal(suite.detectNeed("write a haiku").needed, false, "no durable-corpus signal");
  assert.equal(suite.detectNeed("build a knowledge base of drone specs").needed, true, "explicit corpus goal");
});

test("LOOP CLOSURE: corpus built from research feeds retrieval, and the retrieved chunks ground a RAG answer", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-corpus-")) });

  const report = reportWith("quantum computing relies on qubits and superposition to perform computation");
  const built = app.corpusSuite.buildFromResearch("build a rag index about quantum computing", report);
  assert.ok(built.ingested >= 1 && built.totalChunks >= 1, "a source was governed-ingested into the corpus");

  const chunks = app.corpusSuite.retrieve("qubits superposition");
  assert.ok(chunks.length >= 1, "retrieval returns the ingested chunk(s)");

  // The retrieved chunks ground a faithful answer (pass) but not an unrelated one (fabrication → fail) — loop closed.
  const grounded = await app.vettingGates.vetRagAnswer({ answer: "quantum computing relies on qubits.", chunks });
  assert.notEqual(grounded.finalDecision, "fail", "an answer grounded in the retrieved corpus is not failed");
  const ungrounded = await app.vettingGates.vetRagAnswer({ answer: "zebras migrate across the Serengeti each spring.", chunks });
  assert.equal(ungrounded.finalDecision, "fail", "an answer not grounded in the corpus is caught as fabrication");
});

test("PROJECT ISOLATION: a source ingested in one corpus project is not retrievable from another", () => {
  const a = buildCorpusSuite({ projectName: "proj-A" });
  const b = buildCorpusSuite({ projectName: "proj-B" });
  a.buildFromResearch("build a corpus about drones", reportWith("drones use lithium polymer batteries for flight"));
  assert.ok(a.retrieve("lithium drones").length >= 1, "A can retrieve its own source");
  assert.equal(b.retrieve("lithium drones").length, 0, "B cannot see A's corpus (isolation by construction)");
});

test("GOVERNANCE-PRESERVING: sources are ingested through the pipeline (chunks indexed), not raw-stored", () => {
  const suite = buildCorpusSuite({ projectName: "p-gov" });
  const res = suite.buildFromResearch("build a knowledge base", reportWith("the capital of France is Paris"));
  assert.equal(res.ingested, 1);
  assert.ok(res.totalChunks >= 1, "the source went through classify/sanitize/chunk/index (governed), not bypassed");
  assert.ok(res.note.includes("governed project corpus"), "the corpus is the governed project corpus");
});

test("WIRE: composeKeep exposes the corpus suite end-to-end", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-corpus-wire-")) });
  assert.ok(app.corpusSuite, "corpus suite wired onto the app");
  assert.equal(app.corpusSuite.detectNeed("build a rag corpus").needed, true);
});
