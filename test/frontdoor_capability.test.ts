import { test } from "node:test";
import assert from "node:assert/strict";

import { localBrain, brainFromKey } from "../src/frontdoor/brain_port.js";
import {
  classifyCapability,
  adaptiveProfileFor,
  profileRespectsSafetyFloor,
  SAFETY_FLOOR,
  type CapabilityTier,
} from "../src/frontdoor/capability_adaptive.js";

const hosted = brainFromKey("sk-ant-abcdefghij1234567890", { baseURL: "https://api.anthropic.com/v1" });

// --- Tiering across the spectrum ---

test("a frontier hosted model (big context / high cost) is 'rich'", () => {
  assert.equal(classifyCapability(hosted, { contextWindow: 1_000_000, costPerMTokUSD: 5 }), "rich");
});

test("a solid mid-tier hosted model is 'standard'", () => {
  assert.equal(classifyCapability(hosted, { contextWindow: 128_000, costPerMTokUSD: 3 }), "standard");
});

test("a cheap hosted model is 'lean'", () => {
  assert.equal(classifyCapability(hosted, { costPerMTokUSD: 0.4 }), "lean");
});

test("THE African-laptop case: a local model + declared low-resource is 'minimal'", () => {
  const local = localBrain();
  assert.equal(classifyCapability(local, { lowResourceDeclared: true }), "minimal");
});

test("a plain local model (no big context) is 'lean'", () => {
  assert.equal(classifyCapability(localBrain(), {}), "lean");
});

test("a local model with a large context is 'standard'", () => {
  assert.equal(classifyCapability(localBrain(), { contextWindow: 128_000 }), "standard");
});

// --- Precedence + safe defaults ---

test("a measured quality score takes precedence over other signals", () => {
  assert.equal(classifyCapability(hosted, { measuredQuality: 0.9, costPerMTokUSD: 0.1 }), "rich");
  assert.equal(classifyCapability(hosted, { measuredQuality: 0.3, contextWindow: 1_000_000 }), "minimal");
});

test("an unknown hosted model defaults to 'standard' (safe middle, never assumes 'rich')", () => {
  assert.equal(classifyCapability(hosted, {}), "standard");
});

// --- Degrade, never break ---

test("the minimal tier degrades to the deterministic F1 flow", () => {
  const p = adaptiveProfileFor(localBrain(), { lowResourceDeclared: true });
  assert.equal(p.tier, "minimal");
  assert.equal(p.useDeterministicFallback, true); // never breaks — falls back to the state machine
});

test("weak tiers use structured-only conversation (avoids the silent quality regression)", () => {
  assert.equal(adaptiveProfileFor(hosted, { costPerMTokUSD: 0.4 }).conversationStyle, "structured-only");
  assert.equal(adaptiveProfileFor(localBrain(), { lowResourceDeclared: true }).conversationStyle, "structured-only");
});

test("richer tiers get bigger context + output budgets than weaker ones", () => {
  const rich = adaptiveProfileFor(hosted, { contextWindow: 1_000_000, costPerMTokUSD: 5 });
  const minimal = adaptiveProfileFor(localBrain(), { lowResourceDeclared: true });
  assert.ok(rich.contextTokenBudget > minimal.contextTokenBudget);
  assert.ok(rich.maxOutputTokens > minimal.maxOutputTokens);
});

// --- THE SAFETY INVARIANT: weaker capability NEVER means weaker safety ---

test("every tier respects the safety floor", () => {
  const tiers: { brain: ReturnType<typeof localBrain>; signals: object }[] = [
    { brain: hosted, signals: { contextWindow: 1_000_000, costPerMTokUSD: 5 } }, // rich
    { brain: hosted, signals: { contextWindow: 128_000, costPerMTokUSD: 3 } }, // standard
    { brain: hosted, signals: { costPerMTokUSD: 0.4 } }, // lean
    { brain: localBrain(), signals: { lowResourceDeclared: true } }, // minimal
  ];
  for (const { brain, signals } of tiers) {
    const p = adaptiveProfileFor(brain, signals);
    assert.ok(profileRespectsSafetyFloor(p), `tier ${p.tier} must respect the safety floor`);
  }
});

test("the external-confidence bar RISES (never falls) as capability drops", () => {
  const order: CapabilityTier[] = ["rich", "standard", "lean", "minimal"];
  const thresholds = order.map((tier) => {
    // Build a representative profile for each tier via a signal that lands there.
    const p =
      tier === "rich" ? adaptiveProfileFor(hosted, { contextWindow: 1_000_000, costPerMTokUSD: 5 })
      : tier === "standard" ? adaptiveProfileFor(hosted, { contextWindow: 128_000, costPerMTokUSD: 3 })
      : tier === "lean" ? adaptiveProfileFor(hosted, { costPerMTokUSD: 0.4 })
      : adaptiveProfileFor(localBrain(), { lowResourceDeclared: true });
    return p.gate.externalConfidenceThreshold;
  });
  // Monotonically non-decreasing from rich -> minimal.
  for (let i = 1; i < thresholds.length; i++) {
    assert.ok(thresholds[i]! >= thresholds[i - 1]!, `weaker tier ${order[i]} must be >= stricter, got ${thresholds[i]} < ${thresholds[i - 1]}`);
  }
  // And the weakest is the strictest.
  assert.ok(thresholds[3]! >= thresholds[0]!);
});

test("adversarial vetting rounds never drop below the floor on any tier", () => {
  for (const p of [
    adaptiveProfileFor(hosted, { contextWindow: 1_000_000, costPerMTokUSD: 5 }),
    adaptiveProfileFor(localBrain(), { lowResourceDeclared: true }),
  ]) {
    assert.ok(p.gate.adversarialRounds >= SAFETY_FLOOR.minAdversarialRounds);
  }
});
