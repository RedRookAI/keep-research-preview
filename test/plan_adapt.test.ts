import { test } from "node:test";
import assert from "node:assert/strict";

import { adaptPlan, DEFAULT_ADAPT_CONFIG, type StepFailure } from "../src/logic/plan_adapt.js";

function fail(over: Partial<StepFailure> = {}): StepFailure {
  return { stepId: "s1", kind: "transient", priorAttempts: 0, consequence: "reversible", ...over };
}

test("DETERMINISTIC-FIRST: a transient reversible failure retries locally with NO LLM call", () => {
  const r = adaptPlan(fail({ kind: "transient" }));
  assert.equal(r.repair.kind, "retry");
  assert.equal(r.viaLLM, false, "a local retry must not call the LLM");
  assert.equal(r.scope, "local");
});

test("DETERMINISTIC: a param-out-of-bounds failure is clamped to the valid range, no LLM", () => {
  const r = adaptPlan(fail({ kind: "param-out-of-bounds", param: { name: "timeout", value: 999, min: 1, max: 30 } }));
  assert.equal(r.repair.kind, "clamp-param");
  if (r.repair.kind === "clamp-param") assert.equal(r.repair.to, 30);
  assert.equal(r.viaLLM, false);
});

test("DETERMINISTIC: a step-unavailable failure substitutes a known equivalent, no LLM", () => {
  const r = adaptPlan(fail({ kind: "step-unavailable", knownEquivalent: "s1-alt" }));
  assert.equal(r.repair.kind, "substitute");
  if (r.repair.kind === "substitute") assert.equal(r.repair.withStepId, "s1-alt");
  assert.equal(r.viaLLM, false);
});

test("ESCALATING: a non-local failure escalates to the LLM replan", () => {
  const r = adaptPlan(fail({ kind: "non-local" }));
  assert.equal(r.repair.kind, "escalate-replan");
  assert.equal(r.scope, "replan");
  assert.equal(r.viaLLM, true, "a non-local failure needs the LLM replan");
});

test("ESCALATING: a fixable kind with no substitute available still escalates (no silent no-op)", () => {
  const r = adaptPlan(fail({ kind: "step-unavailable" })); // no knownEquivalent
  assert.equal(r.repair.kind, "escalate-replan");
  assert.equal(r.viaLLM, true);
});

test("ENVELOPE-SAFE: a deterministic fix on a consequential step is GATED, never auto-applied", () => {
  const r = adaptPlan(fail({ kind: "transient", consequence: "irreversible" }));
  assert.equal(r.repair.kind, "gate", "a consequential repair must route through the gate");
  assert.equal(r.viaLLM, false);
  // unknown consequence is also precautionary (not reversible → gate).
  assert.equal(adaptPlan(fail({ kind: "transient", consequence: "unknown" })).repair.kind, "gate");
});

test("BOUNDED: once the local repair budget is spent, adapt escalates instead of retrying forever", () => {
  const r = adaptPlan(fail({ kind: "transient", priorAttempts: DEFAULT_ADAPT_CONFIG.maxLocalAttempts }));
  assert.equal(r.repair.kind, "escalate-replan");
  assert.equal(r.viaLLM, true);
});

test("BACKOFF grows with prior attempts (deterministic exponential)", () => {
  const a0 = adaptPlan(fail({ kind: "transient", priorAttempts: 0 }));
  const a1 = adaptPlan(fail({ kind: "transient", priorAttempts: 1 }));
  const b0 = a0.repair.kind === "retry" ? a0.repair.backoffMs : 0;
  const b1 = a1.repair.kind === "retry" ? a1.repair.backoffMs : 0;
  assert.ok(b1 > b0, "backoff increases with attempts");
});
