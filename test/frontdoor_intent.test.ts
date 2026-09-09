import { test } from "node:test";
import assert from "node:assert/strict";

import { IntentShapeRouter, type LlmShapeClassifier } from "../src/frontdoor/intent_router.js";

// --- Rule tier: explicit signals ---

test("an artifact drop (attachments present) routes to artifact-drop with high confidence", async () => {
  const r = new IntentShapeRouter();
  const res = await r.route({ text: "here's my project", hasAttachments: true });
  assert.equal(res.shape, "artifact-drop");
  assert.ok(res.confidence >= 0.9);
  assert.equal(res.via, "rule");
});

test("attachmentCount also triggers artifact-drop", async () => {
  const r = new IntentShapeRouter();
  const res = await r.route({ text: "continue this", attachmentCount: 12 });
  assert.equal(res.shape, "artifact-drop");
});

test("revision verbs route to revision", async () => {
  const r = new IntentShapeRouter();
  for (const text of ["actually, change the goal to a mobile app", "let's rebuild the plan", "go back to the old approach", "I changed my mind"]) {
    const res = await r.route({ text });
    assert.equal(res.shape, "revision", `"${text}"`);
  }
});

test("an open-ended aspiration routes to open-ended-goal", async () => {
  const r = new IntentShapeRouter();
  const res = await r.route({ text: "I want you to run marketing for my small business" });
  assert.equal(res.shape, "open-ended-goal");
});

test("a concrete actionable ask routes to concrete-task", async () => {
  const r = new IntentShapeRouter();
  const res = await r.route({ text: "add retry-with-backoff to the payments client" });
  assert.equal(res.shape, "concrete-task");
});

// --- Never guess: ambiguous -> clarify ---

test("weak/ambiguous input falls through to a clarifying question (never forces a bucket)", async () => {
  const r = new IntentShapeRouter(); // no LLM tier
  const res = await r.route({ text: "hmm" });
  assert.equal(res.shape, "ambiguous");
  assert.equal(res.via, "clarify-fallback");
  assert.ok(res.clarifyingQuestion && res.clarifyingQuestion.length > 0);
});

test("an explicit external-action command is concrete intent while authority remains a separate gate", async () => {
  const res = await new IntentShapeRouter().route({ text: "email the report to the team" });
  assert.equal(res.shape, "concrete-task");
  assert.equal(res.via, "rule");
});

// --- LLM tier only when rules are unsure ---

test("the LLM tier is consulted only when the rule tier is unsure, and a confident answer is honored", async () => {
  let called = false;
  const llm: LlmShapeClassifier = async () => { called = true; return { shape: "concrete-task", confidence: 0.9 }; };
  const r = new IntentShapeRouter(llm);
  // A clearly-ruled input should NOT consult the LLM.
  await r.route({ text: "here's my project", hasAttachments: true });
  assert.equal(called, false);
  // An ambiguous input SHOULD consult the LLM, and honor a confident answer.
  const res = await r.route({ text: "the thing" });
  assert.equal(called, true);
  assert.equal(res.shape, "concrete-task");
  assert.equal(res.via, "llm");
});

test("a throwing LLM classifier still falls back to clarify (never crashes)", async () => {
  const llm: LlmShapeClassifier = async () => { throw new Error("model down"); };
  const r = new IntentShapeRouter(llm);
  const res = await r.route({ text: "??" });
  assert.equal(res.shape, "ambiguous");
  assert.equal(res.via, "clarify-fallback");
});

test("a low-confidence LLM answer does not auto-route (falls to clarify)", async () => {
  const llm: LlmShapeClassifier = async () => ({ shape: "concrete-task", confidence: 0.4 });
  const r = new IntentShapeRouter(llm);
  const res = await r.route({ text: "stuff" });
  assert.equal(res.shape, "ambiguous"); // below threshold -> clarify, not guess
});

test("every non-ambiguous shape carries a plain-language note", async () => {
  const r = new IntentShapeRouter();
  for (const input of [{ text: "x", hasAttachments: true }, { text: "rebuild it" }, { text: "run my marketing" }, { text: "add a login page" }]) {
    const res = await r.route(input);
    assert.ok(res.note.length > 0);
    assert.ok(!/error|exception/i.test(res.note)); // jargon-free
  }
});
