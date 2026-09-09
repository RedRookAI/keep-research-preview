import { test } from "node:test";
import assert from "node:assert/strict";

import { predictNextNeed, recordPredictionOutcome, type PredictionPattern } from "../src/anticipate/predictor.js";
import { priorPosterior, posteriorMean, updatePosterior, type SuccessPosterior } from "../src/routing/uncertainty_router.js";

function pattern(over: Partial<PredictionPattern> = {}): PredictionPattern {
  return {
    id: "p1",
    description: "open the file you edited yesterday",
    consequence: "reversible",
    confidence: priorPosterior(),
    utility: 1,
    interruptionCost: 0.1,
    ...over,
  };
}

/** A well-evidenced belief: many accepted outcomes. */
function proven(): SuccessPosterior {
  let p = priorPosterior();
  for (let i = 0; i < 30; i++) p = updatePosterior(p, true);
  return p;
}

test("PROBATIONARY: a pattern with weak evidence has low confidence (not trusted on first sight)", () => {
  const pred = predictNextNeed({ candidates: [pattern({ consequence: "irreversible", confidence: priorPosterior() })] });
  // Even if offered, the consequence-scaled (LCB) confidence is near zero with only the prior.
  if (pred) assert.ok(pred.successEstimate < 0.3, `unproven confidence should be low, got ${pred?.successEstimate}`);
});

test("PROBATIONARY vs PROVEN: a proven pattern outranks an unproven one", () => {
  const pred = predictNextNeed({
    candidates: [
      pattern({ id: "unproven", confidence: priorPosterior() }),
      pattern({ id: "proven", confidence: proven() }),
    ],
  });
  assert.equal(pred?.pattern.id, "proven", "confidence is earned, not assumed");
  assert.ok(pred!.successEstimate > 0.6);
});

test("OVERRIDABLE: a declined prediction lowers the belief; accepted raises it", () => {
  const start = proven();
  const declined = recordPredictionOutcome(start, false);
  const accepted = recordPredictionOutcome(start, true);
  assert.ok(posteriorMean(declined) < posteriorMean(start), "decline lowers confidence");
  assert.ok(posteriorMean(accepted) > posteriorMean(start), "accept raises confidence");
});

test("ENVELOPE: a predicted irreversible action is OFFERED, never surfaced/auto — and never auto-executes", () => {
  const pred = predictNextNeed({ candidates: [pattern({ consequence: "irreversible", confidence: proven(), utility: 5 })] });
  assert.ok(pred);
  assert.equal(pred!.autoExecuted, false, "the predictor never executes");
  assert.equal(pred!.disposition, "offer-on-pull", "a consequential prediction is offered for the human, never auto-surfaced");
});

test("EXPLORATION-PRESERVING: a reversible confident prediction may surface; nothing clears → null", () => {
  const surf = predictNextNeed({ candidates: [pattern({ consequence: "reversible", confidence: proven(), utility: 4, interruptionCost: 0.1 })] });
  assert.equal(surf?.disposition, "surface", "reversible + confident + useful may surface (still just a suggestion)");
  // An un-vettable candidate is never surfaced → null.
  const none = predictNextNeed({ candidates: [pattern({ vettable: false })] });
  assert.equal(none, null);
});

test("TRANSPARENT: every prediction carries a non-empty rationale", () => {
  const pred = predictNextNeed({ candidates: [pattern({ confidence: proven() })] });
  assert.ok(pred && pred.rationale.length > 0, "a prediction must explain itself");
});

test("confidence is EARNED: repeated acceptance raises the surfaced success estimate", () => {
  let p = priorPosterior();
  const low = predictNextNeed({ candidates: [pattern({ consequence: "irreversible", confidence: p })] })?.successEstimate ?? 0;
  for (let i = 0; i < 40; i++) p = recordPredictionOutcome(p, true);
  const high = predictNextNeed({ candidates: [pattern({ consequence: "irreversible", confidence: p })] })?.successEstimate ?? 0;
  assert.ok(high > low + 0.3, "accumulated acceptance earns real confidence");
});
