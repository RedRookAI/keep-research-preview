import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ContextAssembler,
  episodicSourceFromLog,
  type SemanticHit,
  type SemanticRetriever,
  type EpisodicSource,
} from "../src/memory/context_assembler.js";
import { EpisodicTurnLog } from "../src/memory/episodic_turns.js";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import { AdaptivePromptLayer } from "../src/prompt/adaptive_prompt_layer.js";
import { PromptStore } from "../src/prompt/prompt_store.js";
import { ComplexityClassifier } from "../src/prompt/complexity_router.js";

// Deterministic stub sources (no embedder needed for the core logic).
function semanticStub(hits: SemanticHit[]): SemanticRetriever {
  return async (_q, k) => hits.slice(0, k);
}
function episodicStub(items: { id: string; text: string; recencyRank: number; keywordScore: number }[]): EpisodicSource {
  return { relevant: (_q, limit) => items.slice(0, limit) };
}

const SEM: SemanticHit[] = [
  { id: "l1", text: "prefer bullet points for readability", score: 0.9, tier: "confirmed" },
  { id: "l2", text: "use TypeScript strict mode by convention", score: 0.6, tier: "probation" },
];
const EPI = [
  { id: "t1", text: "retry limit set to 3 in upload.ts", recencyRank: 0, keywordScore: 0.9 },
  { id: "t2", text: "deploy succeeded on tuesday", recencyRank: 1, keywordScore: 0.2 },
];

test("BLEND: both tracks contribute — not a binary selection", async () => {
  const a = new ContextAssembler(semanticStub(SEM), episodicStub(EPI));
  const out = await a.assemble({ query: "how did we set the retry value", charBudget: 4000 });
  const tracks = new Set(out.items.map((i) => i.track));
  assert.ok(tracks.has("episodic") && tracks.has("semantic"), "both tracks present in the blend");
  assert.ok(out.weights.episodic > 0 && out.weights.semantic > 0, "both weights positive (never zeroed)");
});

test("SELECTION: exact-detail query tilts episodic; general query tilts semantic", async () => {
  const a = new ContextAssembler(semanticStub(SEM), episodicStub(EPI));
  const exact = await a.assemble({ query: "what exact retry value in line 3", charBudget: 4000 });
  assert.ok(exact.weights.episodic > exact.weights.semantic, "exact-detail → episodic-heavy");
  assert.equal(exact.items[0]!.track, "episodic", "top item is the episodic exact-detail hit");

  const general = await a.assemble({ query: "how should I approach formatting, generally", charBudget: 4000 });
  assert.ok(general.weights.semantic > general.weights.episodic, "general → semantic-heavy");
  assert.equal(general.items[0]!.track, "semantic", "top item is the semantic generalization");
});

test("EGRESS REDACTION: a secret in a retrieved hit never reaches durableContext", async () => {
  const withSecret: SemanticHit[] = [{ id: "x", text: "deploy key AKIAIOSFODNN7EXAMPLE for prod", score: 0.99, tier: "confirmed" }];
  const a = new ContextAssembler(semanticStub(withSecret), episodicStub([]));
  const out = await a.assemble({ query: "deploy key", charBudget: 4000 });
  assert.ok(!out.durableContext.includes("AKIAIOSFODNN7EXAMPLE"), "the AWS key must be redacted out of the slice");
  assert.ok(out.redactionFindings.length > 0, "redaction findings reported");
});

test("TOKEN-BOUND + RECALL: slice fits the budget yet keeps the most relevant item", async () => {
  const many: SemanticHit[] = Array.from({ length: 20 }, (_, i) => ({ id: `l${i}`, text: `lesson number ${i} about something`, score: (20 - i) / 20, tier: "confirmed" as const }));
  const a = new ContextAssembler(semanticStub(many), episodicStub([]));
  const out = await a.assemble({ query: "lesson", charBudget: 80 });
  assert.ok(out.durableContext.length <= 80 + 8, "slice is bounded (curated << full history)");
  assert.equal(out.truncated, true, "truncation flagged when over budget");
  // Recall: the highest-scored item (lesson number 0) survives the bound.
  assert.ok(out.items.some((i) => i.text.includes("lesson number 0")), "top-relevance item retained");
});

test("ADAPTER: episodicSourceFromLog reads readable turns; omits erased (forgotten stays forgotten)", () => {
  const keys = new CryptoShredKeyStore();
  const log = new EpisodicTurnLog(keys, (() => { let t = 1; return () => t++; })());
  log.record({ scope: "project", subject: "alice", origin: "self", trusted: true, content: { goal: "tune the retry backoff", action: "edited upload.ts" } });
  log.record({ scope: "project", subject: "bob", origin: "self", trusted: true, content: { goal: "unrelated bob thing" } });
  const src = episodicSourceFromLog(log);
  const hits = src.relevant("retry backoff", 5);
  assert.ok(hits.some((h) => h.text.includes("retry backoff")), "keyword-relevant turn surfaces");
  // Erase alice → her turn must drop out of retrieval.
  log.eraseSubject("alice");
  const after = episodicSourceFromLog(log).relevant("retry backoff", 5);
  assert.ok(!after.some((h) => h.text.includes("retry backoff")), "erased turn is omitted from retrieval");
});

test("PROMPT-PATH CONSUMPTION: assembled context flows into AdaptivePromptLayer.durableContext", async () => {
  const a = new ContextAssembler(semanticStub(SEM), episodicStub(EPI));
  const ctx = await a.assemble({ query: "how did we set the retry value", charBudget: 4000 });
  assert.ok(ctx.durableContext.length > 0);

  const layer = new AdaptivePromptLayer(new PromptStore(), new ComplexityClassifier());
  const prompt = layer.assemble({
    taskShape: "implement",
    goal: "add another retry guard",
    durableContext: ctx.durableContext,
    profile: { tier: "standard", effortKnob: "none", timeoutClass: "standard" },
  });
  // The memory the assembler retrieved is now IN the prompt the model will see.
  assert.ok(prompt.text.includes("retry limit set to 3"), "episodic memory reached the harness");
  assert.ok(prompt.text.includes("bullet points"), "semantic memory reached the harness");
});
