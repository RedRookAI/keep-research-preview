import { test } from "node:test";
import assert from "node:assert/strict";

import { monitorExecution, type ObservedOutcome } from "../src/logic/execution_monitor.js";
import type { Plan, PlanStep } from "../src/logic/plan_gate.js";

// The plan-level execution-monitor — the "after" half. Walks the plan, compares each step's actual outcome
// to its predicted establishes, halts + replans at the first divergence. The execution wiring is the SEAM.

const step = (id: string, establishes: readonly string[], deletes: readonly string[] = []): PlanStep => ({
  id, prerequisites: [], advancesGoal: "G", predictedCost: 1, subProblemValue: 1, undoes: [],
  progressAfter: 1, requires: [], establishes, deletes,
});

const plan: Plan = {
  goals: ["G"], committed: [], initialState: ["start"], goalFacts: ["done"],
  steps: [step("a", ["mid"]), step("b", ["done"], ["mid"])],
};

const obs = (stepId: string, actualEstablished: readonly string[] | undefined): ObservedOutcome => ({ stepId, actualEstablished });

test("exec-monitor: all steps match predictions → COMPLETE (no false replan)", () => {
  const r = monitorExecution(plan, [obs("a", ["mid"]), obs("b", ["done"])]);
  assert.equal(r.status, "complete");
  assert.ok(r.observedState.includes("done"));
  assert.ok(!r.observedState.includes("mid"), "b deleted mid");
});

test("exec-monitor: step b's actual diverges from prediction → REPLAN at b with observed state", () => {
  const r = monitorExecution(plan, [obs("a", ["mid"]), obs("b", ["something-else"])]);
  assert.equal(r.status, "replan");
  if (r.status === "replan") {
    assert.equal(r.atStep, "b");
    assert.ok(r.reason.startsWith("divergence"));
    assert.ok(r.observedState.includes("something-else"), "observed state carries what actually happened");
    assert.ok(!r.observedState.includes("done"), "the predicted fact did NOT occur");
  }
});

test("exec-monitor: a missing observed outcome ⇒ REPLAN (fail-safe, isolated)", () => {
  const r = monitorExecution(plan, [obs("a", ["mid"]), obs("b", undefined)]);
  assert.equal(r.status, "replan");
  if (r.status === "replan") {
    assert.equal(r.atStep, "b");
    assert.equal(r.reason, "unknown-actual-outcome");
  }
});

test("exec-monitor: HALTS at the FIRST divergence — does not process later steps (isolated)", () => {
  const threeStep: Plan = {
    goals: ["G"], committed: [], initialState: [], goalFacts: ["z"],
    steps: [step("a", ["x"]), step("b", ["y"]), step("c", ["z"])],
  };
  // a diverges; b and c would match — the monitor must halt at a, never reaching b/c.
  const r = monitorExecution(threeStep, [obs("a", ["WRONG"]), obs("b", ["y"]), obs("c", ["z"])]);
  assert.equal(r.status, "replan");
  if (r.status === "replan") {
    assert.equal(r.atStep, "a", "halted at the first divergence, not a later one");
    assert.ok(!r.observedState.includes("y"), "did not process step b after halting");
  }
});

test("exec-monitor: a first-step divergence with an unobserved outcome still halts at step 1", () => {
  const r = monitorExecution(plan, [obs("a", undefined)]);
  assert.equal(r.status, "replan");
  if (r.status === "replan") assert.equal(r.atStep, "a");
});
