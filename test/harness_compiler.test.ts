import { test } from "node:test";
import assert from "node:assert/strict";

import { compileHarness, harnessAssemble, type ModelTuning } from "../src/prompt/harness_compiler.js";
import { AdaptivePromptLayer } from "../src/prompt/adaptive_prompt_layer.js";
import { PromptStore } from "../src/prompt/prompt_store.js";

test("H-3-REVET KNOWN: a current model (gpt-5.6-sol) compiles to its real tuned harness (distinct from default)", () => {
  const h = compileHarness("gpt-5.6-sol", "rich");
  assert.equal(h.known, true, "gpt-5.6-sol is a known Aug-2026 model");
  assert.equal(h.rung, "rich");
  assert.equal(h.effortControl.kind, "mode+effort", "real OpenAI two-axis knob");
  const def = compileHarness("some-random-model", "rich");
  assert.notEqual(h.effortControl.kind, def.effortControl.kind, "tuned differs from the default (none)");
});

test("H-3-REVET UNKNOWN: an unknown model -> safe NL default, not fabricated", () => {
  const h = compileHarness("mystery-model-xyz", "rich");
  assert.equal(h.known, false);
  assert.equal(h.rung, "standard", "capped at the conservative default, not fabricated up to rich");
  assert.equal(h.effortControl.kind, "none", "no effort knob invented");
});

test("H-3-REVET SAFE-DEGRADING: a lower capability tier caps the rung", () => {
  assert.equal(compileHarness("gpt-5.6-sol", "rich").rung, "rich");
  assert.equal(compileHarness("gpt-5.6-sol", "lean").rung, "lean", "weak host -> degraded, never richer than supported");
});

test("H-3-REVET KNOB KINDS: the effort-control kind is real per-model", () => {
  assert.equal(compileHarness("gpt-5.6-sol", "rich").effortControl.kind, "mode+effort", "OpenAI");
  assert.equal(compileHarness("claude-opus-5", "rich").effortControl.kind, "adaptive", "Claude Opus adaptive");
  assert.equal(compileHarness("claude-fable-5", "rich").effortControl.kind, "adaptive", "Fable adaptive");
  assert.equal(compileHarness("gemini-3.1-pro", "rich").effortControl.kind, "thinking_level", "Gemini thinking level");
  assert.equal(compileHarness("deepseek-v4", "standard").effortControl.kind, "thinking_mode", "DeepSeek thinking mode");
});

test("H-3-REVET CEILING-NOT-FLOOR: reported for a ceiling-semantics model, never claims a floor", () => {
  const sol = compileHarness("gpt-5.6-sol", "rich");
  assert.equal(sol.effortControl.ceilingNotFloor, true, "GPT-5.6 effort is a ceiling");
  assert.match(sol.reason, /CEILING not a floor/, "the compiler reports it honestly");
  const opus = compileHarness("claude-opus-5", "rich");
  assert.equal(opus.effortControl.ceilingNotFloor, false, "adaptive is not ceiling-not-floor");
});

test("H-3-REVET CACHE MECHANICS: per-model cache mechanics are correct", () => {
  const sol = compileHarness("gpt-5.6-sol", "rich").cache;
  assert.equal(sol.cacheStyle, "explicit-breakpoint");
  assert.equal(sol.minCacheablePrefixTokens, 1024);
  assert.equal(sol.lookback, 50);
  assert.equal(sol.ttlClass, "30min");
  const opus = compileHarness("claude-opus-5", "rich").cache;
  assert.equal(opus.cacheStyle, "explicit-cache_control");
  assert.equal(opus.minCacheablePrefixTokens, 512);
  assert.equal(opus.lookback, 20);
  assert.equal(opus.ttlClass, "5min");
  assert.equal(compileHarness("gemini-3.1-pro", "rich").cache.cacheStyle, "implicit");
});

test("H-3-REVET CONFIG OVERRIDE: an operator override replaces/extends the seeded table (staleness resistance)", () => {
  const custom: ModelTuning = {
    tier: "rich",
    effortControl: { kind: "thinking_level", ceilingNotFloor: false },
    timeoutClass: "reasoning",
    cache: { minCacheablePrefixTokens: 256, cacheStyle: "implicit", breakpointBudget: 0, lookback: 0, ttlClass: "none", writePremium: 1 },
  };
  // extend: a brand-new model id
  const added = compileHarness("qwen-4-next", "rich", { models: { "qwen-4-next": custom } });
  assert.equal(added.known, true, "override adds a new model");
  assert.equal(added.cache.minCacheablePrefixTokens, 256);
  // replace: override an existing seeded entry
  const replaced = compileHarness("gpt-5.6-sol", "rich", { models: { "gpt-5.6-sol": custom } });
  assert.equal(replaced.effortControl.kind, "thinking_level", "override wins over the built-in seed");
});

test("H-3-REVET COMPOSES the AdaptivePromptLayer (no parallel prompt path)", () => {
  const layer = new AdaptivePromptLayer(new PromptStore());
  const h = compileHarness("gpt-5.6-sol", "rich");
  const out = harnessAssemble(h, layer, { taskShape: "plan", goal: "design the module" });
  assert.ok(out.text.includes("design the module"), "assembled via the compiled profile");
});
