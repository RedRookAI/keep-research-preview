import { test } from "node:test";
import assert from "node:assert/strict";

import { decideAsk, decideAskFromConfidence, AskGate, DEFAULT_ASK_GATE_CONFIG } from "../src/anticipate/ask_gate.js";

test("LOW-CONSEQUENCE ambiguity PROCEEDS (does not ask) — reversibility beats asking", () => {
  const d = decideAsk({ intentUncertainty: 0.9, consequence: "reversible" });
  assert.notEqual(d.verdict, "ask");
  // Highly ambiguous but reversible → proceed (with a note, since it's very uncertain).
  assert.equal(d.verdict, "proceed-with-note");
});

test("HIGH-CONSEQUENCE ambiguity ASKS — the one case worth a question", () => {
  const d = decideAsk({ intentUncertainty: 0.9, consequence: "irreversible" });
  assert.equal(d.verdict, "ask");
  assert.ok(d.valueOfInformation > 0);
});

test("CONFIDENT + irreversible PROCEEDS — gate on consequence×uncertainty, not confidence alone", () => {
  // Low uncertainty even on an irreversible action → don't ask (the action-side veto still backstops the act).
  const d = decideAsk({ intentUncertainty: 0.1, consequence: "irreversible" });
  assert.equal(d.verdict, "proceed");
});

test("REVERSIBLE stays PROCEED across the whole uncertainty range (never asks)", () => {
  for (const u of [0.1, 0.3, 0.5, 0.7, 0.95]) {
    const d = decideAsk({ intentUncertainty: u, consequence: "reversible" });
    assert.notEqual(d.verdict, "ask", `reversible u=${u} must never ask`);
  }
});

test("UNKNOWN consequence is precautionary (between reversible and irreversible)", () => {
  assert.equal(decideAsk({ intentUncertainty: 0.5, consequence: "unknown" }).verdict, "ask");
  assert.equal(decideAsk({ intentUncertainty: 0.1, consequence: "unknown" }).verdict, "proceed");
});

test("INVARIANT to cold-start: identical inputs give identical verdicts with no cues/history", () => {
  // The gate uses only (uncertainty, consequence) — no personalization/baseline — so it is stable on turn 1.
  const a = decideAsk({ intentUncertainty: 0.2, consequence: "irreversible" });
  const b = decideAsk({ intentUncertainty: 0.2, consequence: "irreversible" });
  assert.deepEqual(a, b);
  assert.equal(a.verdict, "ask"); // 0.2×1.0 − 0.15 = 0.05 > 0
});

test("confidence adapter maps intent-router confidence → uncertainty", () => {
  // confidence 0.3 → uncertainty 0.7; irreversible → ask.
  assert.equal(decideAskFromConfidence(0.3, "irreversible").verdict, "ask");
  // confidence 0.95 → uncertainty 0.05; irreversible → proceed.
  assert.equal(decideAskFromConfidence(0.95, "irreversible").verdict, "proceed");
});

test("AskGate class respects an injected (org-calibrated) config", () => {
  // A deployment that tolerates fewer asks raises askCost — then a mid-uncertainty irreversible proceeds.
  const strict = new AskGate({ ...DEFAULT_ASK_GATE_CONFIG, askCost: 0.5 });
  assert.equal(strict.decide({ intentUncertainty: 0.4, consequence: "irreversible" }).verdict, "proceed");
  // Default config would ask on the same input.
  assert.equal(decideAsk({ intentUncertainty: 0.4, consequence: "irreversible" }).verdict, "ask");
});
