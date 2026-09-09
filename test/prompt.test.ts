import { test } from "node:test";
import assert from "node:assert/strict";

import {
  selectStrategy,
  applyEffort,
  type ModelProfile,
} from "../src/prompt/prompt_strategy.js";
import {
  ComplexityClassifier,
  FirewallRouter,
  type RouteCandidate,
} from "../src/prompt/complexity_router.js";
import { PromptStore, type PromptKey, type PromptTrace } from "../src/prompt/prompt_store.js";
import {
  AdaptivePromptLayer,
  VettingPromptBuilder,
  type VettingRubric,
} from "../src/prompt/adaptive_prompt_layer.js";

const rich: ModelProfile = { tier: "rich", effortKnob: "graded", timeoutClass: "reasoning" };
const chat: ModelProfile = { tier: "standard", effortKnob: "graded", timeoutClass: "reasoning" };
const lean: ModelProfile = { tier: "lean", effortKnob: "none", timeoutClass: "standard" };

// ── The Prompting Inversion matrix ──────────────────────────────────────────

test("INVARIANT: rich/reasoning model gets a BRIEF prompt with NO CoT (inversion)", () => {
  const s = selectStrategy(rich, "complex");
  assert.equal(s.shape, "brief");
  assert.equal(s.includeCoT, false, "explicit CoT would HURT a reasoning model");
  assert.equal(s.includeFewShot, false, "few-shot stuffing hurts reasoning models");
});

test("INVARIANT: chat/standard model gets SCAFFOLDED prompt with few-shot", () => {
  const s = selectStrategy(chat, "moderate");
  assert.equal(s.shape, "scaffolded");
  assert.equal(s.includeFewShot, true, "chat models reward scaffolding + examples");
});

test("INVARIANT: lean model on a HARD task gets DECOMPOSED (Trace-of-Thought), not thin", () => {
  const s = selectStrategy(lean, "complex");
  assert.equal(s.shape, "decomposed", "weak model + hard task → explicit subproblems");
  assert.equal(s.includeCoT, true);
});

test("lean model on an EASY task gets light scaffolding (no verbose CoT)", () => {
  const s = selectStrategy(lean, "simple");
  assert.equal(s.shape, "scaffolded");
  assert.equal(s.includeCoT, false);
});

// ── Effort maps across knob types (capability-detected, provider-agnostic) ──

test("INVARIANT: effort maps onto the model's ACTUAL knob (graded/binary/none)", () => {
  assert.deepEqual(applyEffort("graded", "high"), { kind: "graded", level: "high" });
  assert.deepEqual(applyEffort("binary", "high"), { kind: "binary", thinking: true });
  assert.deepEqual(applyEffort("binary", "low"), { kind: "binary", thinking: false });
  assert.deepEqual(applyEffort("none", "high"), { kind: "none" }, "no knob → prompt shape carries it");
});

// ── Complexity classifier ───────────────────────────────────────────────────

test("complexity classifier: trivial vs complex signals", () => {
  const c = new ComplexityClassifier();
  assert.equal(c.classify({ text: "list the files" }).complexity, "trivial");
  assert.equal(
    c.classify({ text: "architect an end-to-end multi-step migration and prove correctness" }).complexity,
    "complex",
  );
});

// ── Firewall router: cheapest-that-clears, escalate to avoid false economy ──

const candidates: RouteCandidate[] = [
  { id: "cheap", tier: "lean", costWeight: 1 },
  { id: "mid", tier: "standard", costWeight: 3 },
  { id: "strong", tier: "rich", costWeight: 10 },
];

test("INVARIANT: router picks the cheapest candidate that CLEARS the bar (not the cheapest)", () => {
  // all succeed with high prob → for a simple task, cheapest (lean) clears
  const r = new FirewallRouter(() => 0.9);
  const d = r.route(candidates, "simple");
  assert.equal(d.kind, "route");
  if (d.kind === "route") assert.equal(d.candidateId, "cheap", "cheapest that clears wins");
});

test("INVARIANT: firewall escalates when cheap models would likely FAIL (false-economy guard)", () => {
  // cheap/mid predicted to fail; only strong clears
  const predictor = (id: string) => (id === "strong" ? 0.9 : 0.2);
  const r = new FirewallRouter(predictor);
  const d = r.route(candidates, "complex");
  assert.equal(d.kind, "route");
  if (d.kind === "route") assert.equal(d.candidateId, "strong", "escalate past cheap to avoid retry cost");
});

test("INVARIANT: single-model mode degrades to HUMAN handoff, never a silent low-confidence ship", () => {
  const only: RouteCandidate[] = [{ id: "solo", tier: "lean", costWeight: 1 }];
  const r = new FirewallRouter(() => 0.2); // solo well below the bar
  const d = r.route(only, "complex");
  assert.equal(d.kind, "single-model");
  if (d.kind === "single-model") assert.equal(d.action, "human-handoff", "honest handoff, no silent ship");
});

test("single-model marginal case uses self-consistency (sample-and-vote)", () => {
  const only: RouteCandidate[] = [{ id: "solo", tier: "standard", costWeight: 1 }];
  const r = new FirewallRouter(() => 0.45, 0.6); // marginal: between threshold-0.2 and threshold
  const d = r.route(only, "moderate");
  assert.equal(d.kind, "single-model");
  if (d.kind === "single-model") assert.equal(d.action, "self-consistency");
});

// ── GEPA-style improvement loop ─────────────────────────────────────────────

const key: PromptKey = { taskShape: "plan", modelTier: "rich" };

test("prompt store promotes trust with good validation traces", () => {
  const store = new PromptStore();
  const v = store.seed(key, "brief", "do the plan");
  for (let i = 0; i < 8; i++) store.record(v.id, { quality: 0.9, costTokens: 100, split: "validation" });
  assert.equal(store.versionsFor(key)[0]!.tier, "confirmed", "8 good val traces → confirmed");
});

test("INVARIANT: improve() REJECTS an edit that doesn't beat the incumbent on validation", () => {
  const store = new PromptStore();
  const v = store.seed(key, "brief", "incumbent prompt");
  for (let i = 0; i < 8; i++) store.record(v.id, { quality: 0.9, costTokens: 100, split: "validation" });
  // optimizer proposes a WORSE prompt (validation quality 0.5)
  const worse = store.improve(
    key,
    () => ({ newText: "worse prompt", reason: "reflection said try X" }),
    () => [{ quality: 0.5, costTokens: 100, split: "validation" }],
  );
  assert.equal(worse, undefined, "a worse candidate is rejected; incumbent kept");
});

test("INVARIANT: improve() ACCEPTS a validated improvement; length penalty blocks padding", () => {
  const store = new PromptStore();
  const v = store.seed(key, "brief", "short");
  for (let i = 0; i < 8; i++) store.record(v.id, { quality: 0.8, costTokens: 100, split: "validation" });
  // a genuinely better, concise edit is accepted
  const better = store.improve(
    key,
    () => ({ newText: "short but better", reason: "clearer goal" }),
    () => [{ quality: 0.95, costTokens: 100, split: "validation" }],
  );
  assert.ok(better, "validated improvement accepted");
  // a padded edit with the SAME quality is rejected by the length penalty
  const padded = store.improve(
    key,
    () => ({ newText: "x".repeat(50_000), reason: "more words" }),
    () => [{ quality: 0.8, costTokens: 100, split: "validation" }],
  );
  assert.equal(padded, undefined, "padding cannot win (length penalty)");
});

test("model change invalidates that tier's prompts back to candidate (re-earn trust)", () => {
  const store = new PromptStore();
  const v = store.seed(key, "brief", "p");
  for (let i = 0; i < 8; i++) store.record(v.id, { quality: 0.9, costTokens: 100, split: "validation" });
  assert.equal(store.versionsFor(key)[0]!.tier, "confirmed");
  const n = store.invalidateTier("rich");
  assert.equal(n, 1);
  assert.equal(store.versionsFor(key)[0]!.tier, "candidate", "must re-earn trust after model change");
});

// ── Tailored vetting: rubric content invariant, delivery adapts ─────────────

test("INVARIANT: vetting rubric CONTENT is invariant across tiers; only delivery changes", () => {
  const rubric: VettingRubric = { name: "merge-readiness", gates: ["tests pass", "no secrets in diff", "human-approved"] };
  const b = new VettingPromptBuilder();
  const richP = b.build(rubric, rich);
  const leanP = b.build(rubric, lean);
  // every gate appears in BOTH regardless of tier (auditable invariant)
  for (const g of rubric.gates) {
    assert.ok(richP.includes(g), `rich prompt contains gate: ${g}`);
    assert.ok(leanP.includes(g), `lean prompt contains gate: ${g}`);
  }
  // delivery differs: lean gets explicit numbered YES/NO gates
  assert.ok(leanP.includes("Gate 1:"), "lean verifier gets decomposed gates");
  assert.ok(!richP.includes("Gate 1:"), "rich verifier gets rubric+brief, not decomposed");
});

// ── Cache-friendly assembly ─────────────────────────────────────────────────

test("APL orders prompt for cache hits: durable prefix first, volatile task last", () => {
  const store = new PromptStore();
  const apl = new AdaptivePromptLayer(store);
  const a = apl.assemble({
    taskShape: "plan",
    goal: "build a drone flight controller",
    durableContext: "PROJECT: acme. PREFERENCES: metric units, terse.",
    profile: rich,
  });
  assert.ok(a.text.indexOf("PROJECT: acme") < a.text.indexOf("Task:"), "stable prefix precedes volatile task");
  assert.ok(a.cacheableProbablePrefixLen > 0);
  assert.equal(a.strategy.shape, "brief", "rich model → brief strategy applied");
});
