import { test } from "node:test";
import assert from "node:assert/strict";

import {
  detectRetrievalNeed,
  CorpusBuilder,
  sourcesFromReport,
  type GovernedCorpus,
} from "../src/research/corpus_builder.js";
import {
  checkGroundedness,
  buildGroundedAnswer,
  splitSentences,
  type RetrievedChunk,
} from "../src/research/grounded_answer.js";
import {
  assessSufficiency,
  RagGroundingFloorTier,
  type RagVetPayload,
} from "../src/research/rag_grounding_floor.js";
import { VerificationCascade } from "../src/cascade/verification_cascade.js";
import { ConfidenceEscalationPolicy } from "../src/cascade/escalation_policy.js";
import type { ResearchReport } from "../src/research/research_loop.js";

// A fake governed corpus that records ingest calls (proves CorpusBuilder goes through governance).
function fakeCorpus() {
  const ingested: Array<{ sourceId: string; purpose: string; lawfulBasis: string; text: string }> = [];
  const store: Array<{ text: string; sourceId: string; asOf?: string }> = [];
  const corpus: GovernedCorpus = {
    ingest(input) {
      ingested.push({ sourceId: input.sourceId, purpose: input.purpose, lawfulBasis: input.lawfulBasis, text: input.text });
      store.push({ text: input.text, sourceId: input.sourceId });
      return { sourceId: input.sourceId, chunks: 1 };
    },
    search(query, _k) {
      return store.filter((c) => c.text.toLowerCase().includes(query.toLowerCase())).map((chunk) => ({ chunk, score: 1 }));
    },
  };
  return { corpus, ingested };
}

function report(claims: ResearchReport["claims"]): ResearchReport {
  return { need: { needed: true, triggers: ["recency-sensitive"], reason: "", keywords: [] }, claims, searched: true, iterations: 1 };
}

// ── Retrieval-need detector ─────────────────────────────────────────────────

test("retrieval-need fires on research-derived / reference / corpus-goal signals", () => {
  const r = report([{ id: "c", text: "x", citations: [{ id: "1", title: "P", locator: "http://x", supportingText: "x" }] }]);
  assert.equal(detectRetrievalNeed("some goal", r).needed, true, "research-derived");
  assert.equal(detectRetrievalNeed("query the documentation for X").needed, true, "reference-heavy");
  assert.equal(detectRetrievalNeed("build a knowledge base of specs").needed, true, "explicit-corpus-goal");
  assert.equal(detectRetrievalNeed("add two numbers").needed, false);
});

// ── CorpusBuilder goes THROUGH governance, project-scoped ────────────────────

test("INVARIANT: CorpusBuilder pipes sources THROUGH the governed pipeline (not around it)", () => {
  const { corpus, ingested } = fakeCorpus();
  const builder = new CorpusBuilder(corpus);
  const r = report([
    { id: "a", text: "t", citations: [{ id: "1", title: "Paper A", locator: "http://a", supportingText: "finding A" }] },
    { id: "b", text: "t", citations: [{ id: "2", title: "Paper B", locator: "http://b", supportingText: "finding B" }] },
  ]);
  const result = builder.buildFromResearch("research goal", r);
  assert.equal(result.ingested, 2, "both sources ingested through governance");
  assert.equal(ingested.length, 2, "ingest() was actually called per source");
  assert.ok(ingested.every((i) => i.purpose === "research-corpus"), "declared purpose set");
  assert.ok(ingested.every((i) => i.lawfulBasis === "legitimate-interest"), "lawful basis set");
});

test("CorpusBuilder skips sources with no text (counted honestly)", () => {
  const { corpus } = fakeCorpus();
  const builder = new CorpusBuilder(corpus);
  const r = report([{ id: "a", text: "t", citations: [{ id: "1", title: "Empty", locator: "http://a", supportingText: "" }] }]);
  const result = builder.buildFromResearch("research goal", r);
  assert.equal(result.ingested, 0);
  assert.equal(result.skipped, 1);
});

test("sourcesFromReport dedups sources across claims", () => {
  const r = report([
    { id: "a", text: "t", citations: [{ id: "1", title: "P", locator: "http://same", supportingText: "x" }] },
    { id: "b", text: "t", citations: [{ id: "2", title: "P", locator: "http://same", supportingText: "x" }] },
  ]);
  assert.equal(sourcesFromReport(r).length, 1, "same locator deduped");
});

// ── Groundedness gate (answers must cite retrieved chunks) ───────────────────

const chunks: RetrievedChunk[] = [
  { text: "PX4 and ArduPilot dominate open-source drone flight control in 2026.", sourceId: "s1", score: 1 },
  { text: "Visual-inertial odometry improves GPS-denied navigation.", sourceId: "s2", score: 1 },
];

test("INVARIANT: a fully grounded answer passes the groundedness gate", () => {
  const g = checkGroundedness("PX4 dominates open-source drone flight control.", chunks);
  assert.equal(g.status, "grounded");
  assert.ok(g.sentences[0]!.citedSources.includes("s1"));
});

test("INVARIANT: an ungrounded answer (fabrication) FAILS the groundedness gate", () => {
  const g = checkGroundedness("Drones can travel to distant galaxies using warp drives.", chunks);
  assert.equal(g.status, "ungrounded", "no sentence traces to a chunk");
});

test("INVARIANT: a partially grounded answer is flagged partially-grounded", () => {
  const g = checkGroundedness("PX4 dominates open-source drone flight control. Warp drives enable galactic travel.", chunks);
  assert.equal(g.status, "partially-grounded");
  assert.ok(g.groundedFraction > 0 && g.groundedFraction < 1);
});

test("buildGroundedAnswer attaches the faithfulness gauge when provided", () => {
  const ga = buildGroundedAnswer("PX4 dominates drone flight control.", chunks, { gauge: () => 0.92 });
  assert.equal(ga.faithfulnessGauge, 0.92);
  assert.equal(ga.groundedness.status, "grounded");
});

// ── Abstain-when-insufficient (disciplined refusal) ─────────────────────────

test("INVARIANT: no chunks → insufficient → abstain (never answer without evidence)", () => {
  assert.equal(assessSufficiency([]).status, "insufficient");
});

test("INVARIANT: off-topic retrieval (top score below floor) → insufficient → abstain", () => {
  const weak: RetrievedChunk[] = [{ text: "unrelated", sourceId: "s", score: 0.1 }];
  assert.equal(assessSufficiency(weak, { minTopScore: 0.5 }).status, "insufficient");
});

test("sufficient retrieval passes the sufficiency check", () => {
  assert.equal(assessSufficiency(chunks, { minChunks: 1 }).status, "sufficient");
});

// ── Cascade Tier-0 integration ──────────────────────────────────────────────

test("INVARIANT: insufficient retrieval FAILS at the RAG floor (abstain), brain never overturns", async () => {
  const payload: RagVetPayload = { answer: "some confident answer", chunks: [] };
  const tiers = [
    new RagGroundingFloorTier(),
    { tier: 1, name: "brain", sound: false, available: () => true, verify: () => ({ tier: 1, name: "brain", decision: "pass" as const, reason: "brain is confident", sound: false, certainty: 1 }) },
  ];
  const cascade = new VerificationCascade<RagVetPayload>(tiers, new ConfidenceEscalationPolicy());
  const out = await cascade.run({ id: "rag1", kind: "rag", payload });
  assert.equal(out.finalDecision, "fail", "abstained — no evidence");
  assert.equal(out.decidedAtTier, 0, "sound floor; brain never got to answer without evidence");
});

test("INVARIANT: ungrounded answer FAILS at the RAG floor even with good retrieval", async () => {
  const payload: RagVetPayload = { answer: "Warp drives enable instant galactic drone travel.", chunks };
  const cascade = new VerificationCascade<RagVetPayload>([new RagGroundingFloorTier()], new ConfidenceEscalationPolicy());
  const out = await cascade.run({ id: "rag2", kind: "rag", payload });
  assert.equal(out.finalDecision, "fail", "fabricated answer fails groundedness even though chunks were retrieved");
});

test("fully grounded + sufficient answer PASSES the RAG floor", async () => {
  const payload: RagVetPayload = { answer: "PX4 dominates open-source drone flight control.", chunks };
  const cascade = new VerificationCascade<RagVetPayload>([new RagGroundingFloorTier()], new ConfidenceEscalationPolicy());
  const out = await cascade.run({ id: "rag3", kind: "rag", payload });
  assert.equal(out.finalDecision, "pass");
  assert.equal(out.decidedAtTier, 0);
});

// ── Auto-Research → corpus → grounded-answer round trip ─────────────────────

test("round-trip: research sources → governed corpus → retrieve → grounded answer", () => {
  const { corpus } = fakeCorpus();
  const builder = new CorpusBuilder(corpus);
  const r = report([{ id: "a", text: "t", citations: [{ id: "1", title: "P", locator: "http://a", supportingText: "PX4 dominates open-source drone flight control in 2026." }] }]);
  builder.buildFromResearch("research drone SOTA", r);
  const hits = corpus.search("PX4", 5);
  assert.ok(hits.length >= 1, "ingested source is retrievable from the corpus");
  const retrieved: RetrievedChunk[] = hits.map((h) => ({ text: h.chunk.text, sourceId: h.chunk.sourceId, score: h.score }));
  const g = checkGroundedness("PX4 dominates open-source drone flight control.", retrieved);
  assert.equal(g.status, "grounded", "answer built from the corpus is grounded in it");
});

test("splitSentences handles multi-sentence answers", () => {
  assert.equal(splitSentences("One. Two! Three?").length, 3);
});
