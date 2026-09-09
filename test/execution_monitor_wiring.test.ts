import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { composeKeep } from "../src/compose.js";
import type { Plan, PlanStep } from "../src/logic/plan_gate.js";
import type { ObservedOutcome } from "../src/logic/execution_monitor.js";

// WIRING PROOF (P0-A #3): after-execution plan vetting + grounded estimator reachable + consulted.

function sb() {
  return composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-em-")) }).secondBrain;
}
const step = (id: string, establishes: string[], deletes: string[] = []): PlanStep => ({
  id, prerequisites: [], advancesGoal: undefined, predictedCost: undefined, subProblemValue: undefined,
  undoes: [], progressAfter: undefined, requires: undefined, establishes, deletes,
});
const plan: Plan = { goals: ["g"], steps: [step("s1", ["a"]), step("s2", ["b"])], committed: [], initialState: [], goalFacts: ["a", "b"] };

test("composeKeep exposes after-execution vetting + the grounded estimator", () => {
  const s = sb();
  assert.equal(typeof s.monitorPlan, "function");
  assert.equal(typeof s.estimateWork, "function");
});

test("a clean on-envelope execution passes (complete)", () => {
  const observed: ObservedOutcome[] = [{ stepId: "s1", actualEstablished: ["a"] }, { stepId: "s2", actualEstablished: ["b"] }];
  const r = sb().monitorPlan(plan, observed);
  assert.equal(r.status, "complete");
});

test("a diverged execution is CAUGHT (replan at the diverging step)", () => {
  const observed: ObservedOutcome[] = [{ stepId: "s1", actualEstablished: ["WRONG"] }, { stepId: "s2", actualEstablished: ["b"] }];
  const r = sb().monitorPlan(plan, observed);
  assert.equal(r.status, "replan", "a divergence between predicted and observed is flagged, not passed silently");
  if (r.status === "replan") assert.equal(r.atStep, "s1");
});

test("fail-safe: an unobserved step ⇒ replan", () => {
  const observed: ObservedOutcome[] = [{ stepId: "s1", actualEstablished: ["a"] }]; // s2 not observed
  const r = sb().monitorPlan(plan, observed);
  assert.equal(r.status, "replan");
});

test("the grounded estimator is reachable and never fabricates (honest ungrounded with no history)", async () => {
  const est = await sb().estimateWork({ taskShape: "novel-chapter", provider: "local", model: "m", units: 1 });
  assert.equal(est.grounded, false, "with no measured samples it declines to guess (never fabricates a number)");
  assert.equal(est.cost, undefined);
});
