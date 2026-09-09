import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AdaptivePromptLayer, VettingPromptBuilder } from "../src/prompt/adaptive_prompt_layer.js";
import { PromptStore } from "../src/prompt/prompt_store.js";
import { ComplexityClassifier } from "../src/prompt/complexity_router.js";
import type { ModelProfile } from "../src/prompt/prompt_strategy.js";

const layer = () => new AdaptivePromptLayer(new PromptStore(), new ComplexityClassifier());
const rich: ModelProfile = { tier: "rich", effortKnob: "none", timeoutClass: "standard" };
const lean: ModelProfile = { tier: "lean", effortKnob: "none", timeoutClass: "standard" };

test("CACHE ORDERING (SOTA cost lever): durable context is the stable PREFIX, the volatile task is LAST", () => {
  const a = layer().assemble({ taskShape: "plan", goal: "do the volatile thing", durableContext: "STABLE PROJECT FACTS", profile: rich });
  assert.ok(a.text.startsWith("STABLE PROJECT FACTS"), "stable durable context leads");
  assert.ok(a.text.trimEnd().endsWith("do the volatile thing"), "the volatile task is last");
  // the cacheable prefix is exactly the stable portion, before the task marker
  assert.equal(a.text.slice(0, a.cacheableProbablePrefixLen).includes("do the volatile thing"), false, "the volatile goal is OUTSIDE the cacheable prefix");
});

test("CACHE STABILITY: changing only the volatile goal does NOT change the cacheable prefix (byte-stable → cache hit)", () => {
  const l = layer();
  const base = { taskShape: "plan", durableContext: "STABLE FACTS", profile: rich } as const;
  const a = l.assemble({ ...base, goal: "task one" });
  const b = l.assemble({ ...base, goal: "a completely different task two" });
  assert.equal(a.cacheableProbablePrefixLen, b.cacheableProbablePrefixLen, "prefix length identical");
  assert.equal(a.text.slice(0, a.cacheableProbablePrefixLen), b.text.slice(0, b.cacheableProbablePrefixLen), "prefix bytes identical → a real cache hit");
});

test("DETERMINISTIC: identical inputs produce byte-identical prompts (no cache-busting nondeterminism)", () => {
  const req = { taskShape: "implement", goal: "g", durableContext: "d", profile: rich } as const;
  assert.equal(layer().assemble(req).text, layer().assemble(req).text);
});

test("VETTING (rubric invariant, delivery adapts): rich = rubric+brief; lean = decomposed numbered yes/no gates", () => {
  const b = new VettingPromptBuilder();
  const rubric = { name: "grounding", gates: ["output cites >=1 source", "no fabricated citations"] };
  const richP = b.build(rubric, rich);
  const leanP = b.build(rubric, lean);
  // rubric CONTENT is invariant across tiers (auditability) — both contain the gate text
  for (const gate of rubric.gates) { assert.ok(richP.includes(gate)); assert.ok(leanP.includes(gate)); }
  // rich: trusts the model to apply gates + per-gate reason (the grounding SOTA favors)
  assert.match(richP, /pass\/fail per gate with a one-line reason/i);
  // lean: decomposed into explicit numbered sequential gates
  assert.match(leanP, /Gate 1:/); assert.match(leanP, /Gate 2:/);
  assert.match(leanP, /strictly YES or NO/i);
  assert.match(leanP, /OVERALL: PASS only if every gate is YES/i);
});

test("VETTING: the verifier is told to JUDGE, not rewrite (no false continuation)", () => {
  const p = new VettingPromptBuilder().build({ name: "x", gates: ["g"] }, rich);
  assert.match(p, /Do NOT rewrite or improve it/i);
});

test("WIRE: composeKeep exposes the prompt layer; assembled prompts are cache-ordered", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-apl-")) });
  assert.ok(app.promptLayer, "prompt layer wired onto the app");
  const a = app.promptLayer.assemble({ taskShape: "plan", goal: "vol", durableContext: "STABLE", profile: rich });
  assert.ok(a.text.startsWith("STABLE"));
  const vet = app.promptLayer.assembleVetting({ name: "r", gates: ["g1"] }, lean);
  assert.match(vet, /Gate 1:/);
});
