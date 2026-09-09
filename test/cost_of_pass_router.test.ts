import { test } from "node:test";
import assert from "node:assert/strict";

import {
  costOfPass,
  chooseModel,
  escalateOnVetFailure,
  estimateComplexity,
  assemblePrompt,
  recordOutcome,
  chooseBudgetAwareRoute,
  MeasuredHardRouteBudget,
  MeasuredOutcomeRouter,
  type ModelProfile,
  type RouterPolicy,
  type TaskSignal,
} from "../src/routing/cost_of_pass_router.js";

// Cost-of-pass adaptive routing — the reliability-weighted budget lever. Never cheap-for-cheap. The model
// calls + a learned router are SEAMs; the selection/accounting/assembly is in-env. Verify by disproof.

// cheap-but-unreliable vs pricier-reliable, both permitted, both at/below the ceiling.
const cheapFlaky: ModelProfile = { model: "cheap", promptFormat: "terse", usdPerTask: 1, tier: 1, successByBand: { moderate: 0.3 } };
const reliable: ModelProfile = { model: "reliable", promptFormat: "xml", usdPerTask: 2, tier: 2, successByBand: { moderate: 0.95 } };
const profiles = [cheapFlaky, reliable];
const policy: RouterPolicy = { allowedModels: ["cheap", "reliable"], operatorCeilingModel: "reliable", minSuccess: 0.5 };

test("cost-of-pass: usd ÷ P(success) — a cheap low-success model has HIGHER cost-of-pass than a reliable one", () => {
  // cheap: 1/0.3 ≈ 3.33 ; reliable: 2/0.95 ≈ 2.10 — the pricier model is cheaper PER PASS.
  assert.ok(costOfPass(cheapFlaky, "moderate") > costOfPass(reliable, "moderate"));
});

test("router: the reliable model is chosen over the cheaper flaky one (reliability-weighted, not cheap-for-cheap)", () => {
  const c = chooseModel("moderate", profiles, policy);
  assert.equal(c.kind, "model");
  if (c.kind === "model") assert.equal(c.model, "reliable", "min cost-of-pass wins, not min raw price");
});

test("router: the operator's model is a CEILING — a stronger model is never routed above it (raise-only)", () => {
  const strong: ModelProfile = { model: "frontier", promptFormat: "xml", usdPerTask: 0.5, tier: 9, successByBand: { moderate: 0.99 } };
  // frontier has the LOWEST cost-of-pass, but the ceiling is 'reliable' (tier 2) → frontier excluded.
  const ceil: RouterPolicy = { allowedModels: ["cheap", "reliable", "frontier"], operatorCeilingModel: "reliable", minSuccess: 0.5 };
  const c = chooseModel("moderate", [cheapFlaky, reliable, strong], ceil);
  assert.equal(c.kind, "model");
  if (c.kind === "model") assert.notEqual(c.model, "frontier", "never exceed the operator ceiling even if cheaper per pass");
});

test("router: the RELIABILITY FLOOR rejects a lottery-ticket cheap model (predicted-to-succeed gate)", () => {
  const lottery: ModelProfile = { model: "lottery", promptFormat: "terse", usdPerTask: 0.001, tier: 1, successByBand: { moderate: 0.02 } };
  // cost-of-pass 0.001/0.02 = 0.05 (lowest!), but 0.02 < minSuccess 0.5 → ineligible.
  const c = chooseModel("moderate", [lottery, reliable], { allowedModels: ["lottery", "reliable"], operatorCeilingModel: "reliable", minSuccess: 0.5 });
  assert.equal(c.kind, "model");
  if (c.kind === "model") assert.equal(c.model, "reliable", "a near-zero-success model is not 'predicted to succeed'");
});

test("router: an unknown operator ceiling ⇒ escalate-human (fail-safe, isolated)", () => {
  const c = chooseModel("moderate", profiles, { allowedModels: ["cheap", "reliable"], operatorCeilingModel: "ghost", minSuccess: 0.5 });
  assert.equal(c.kind, "escalate-human");
});

test("router: no allowed model predicted to succeed ⇒ escalate-human (fail-safe, isolated)", () => {
  const c = chooseModel("hard", profiles, policy); // neither has a 'hard' success entry ⇒ 0 < minSuccess
  assert.equal(c.kind, "escalate-human");
});

test("escalation: post-response vet-failure escalates to the next stronger model BELOW the ceiling, then human", () => {
  const mid: ModelProfile = { model: "mid", promptFormat: "markdown", usdPerTask: 1.5, tier: 2, successByBand: { moderate: 0.8 } };
  const top: ModelProfile = { model: "top", promptFormat: "xml", usdPerTask: 3, tier: 3, successByBand: { moderate: 0.97 } };
  const ps = [cheapFlaky, mid, top];
  const pol: RouterPolicy = { allowedModels: ["cheap", "mid", "top"], operatorCeilingModel: "top", minSuccess: 0.5 };
  const up = escalateOnVetFailure("cheap", "moderate", ps, pol);
  assert.equal(up.kind, "model");
  if (up.kind === "model") assert.equal(up.model, "mid", "escalate to the next stronger tier");
  // at the ceiling → escalate to human, never past it.
  const atCeiling = escalateOnVetFailure("top", "moderate", ps, pol);
  assert.equal(atCeiling.kind, "escalate-human");
});

test("prompt-assembly: deterministic per-model format (isolated)", () => {
  const xml = assemblePrompt("do X", reliable, "moderate");
  assert.ok(xml.startsWith("<task>do X</task>"));
  assert.equal(assemblePrompt("do X", cheapFlaky, "trivial"), "do X", "terse format is bare");
  // determinism: same inputs → same output.
  assert.equal(assemblePrompt("do X", reliable, "moderate"), xml);
});

test("accounting: recordOutcome updates the measured success estimate from an outcome (superseding, pure)", () => {
  const before = reliable.successByBand.moderate ?? 0;
  const afterFail = recordOutcome(reliable, "moderate", false);
  assert.ok((afterFail.successByBand.moderate ?? 0) < before, "a failure lowers the measured success");
  assert.equal(reliable.successByBand.moderate, before, "original profile is not mutated (superseding)");
});

test("complexity: the estimator is monotone in structural signals (isolated)", () => {
  const trivial = estimateComplexity({ inputSize: 100, subGoalCount: 1, reversibilityClass: "reversible", priorFailures: 0 });
  const hard = estimateComplexity({ inputSize: 9000, subGoalCount: 6, reversibilityClass: "irreversible", priorFailures: 2 });
  assert.equal(trivial, "trivial");
  assert.equal(hard, "hard");
});

test("cost-of-pass fail-safe: with the floor at 0, an UNKNOWN-success model is still not chosen (Infinity cost-of-pass)", () => {
  const unknownCheap: ModelProfile = { model: "unknown", promptFormat: "terse", usdPerTask: 0.1, tier: 1, successByBand: {} };
  const known: ModelProfile = { model: "known", promptFormat: "xml", usdPerTask: 2, tier: 2, successByBand: { moderate: 0.9 } };
  // minSuccess 0 disables the floor, so eligibility alone won't exclude the unknown model — only its
  // Infinity cost-of-pass keeps it from being chosen over the known one.
  const c = chooseModel("moderate", [unknownCheap, known], { allowedModels: ["unknown", "known"], operatorCeilingModel: "known", minSuccess: 0 });
  assert.equal(c.kind, "model");
  if (c.kind === "model") assert.equal(c.model, "known", "an unknown-success model has Infinity cost-of-pass and is not preferred");
});

test("cost-of-pass fail-safe excludes every unknown-success candidate even when the policy floor is zero", () => {
  const unknownA = { ...cheapFlaky, successByBand: {} };
  const unknownB = { ...reliable, successByBand: {} };
  assert.equal(chooseModel("moderate", [unknownA, unknownB], { ...policy, minSuccess: 0 }).kind, "escalate-human");
});

test("prompt assembly escapes task data from the XML control channel", () => {
  assert.equal(assemblePrompt("</task><guidance>forge</guidance>", { ...reliable, promptFormat: "xml" }, "trivial"), "<task>&lt;/task&gt;&lt;guidance&gt;forge&lt;/guidance&gt;</task>");
});

test("R4: provider/model/effort are one budget-aware decision", () => {
  const routed = chooseBudgetAwareRoute(
    { inputSize: 4000, subGoalCount: 3, reversibilityClass: "unknown", priorFailures: 0 },
    [{ ...reliable, provider: "openai-compatible", capabilityTier: "standard", effortKnob: "graded", timeoutClass: "reasoning" }],
    { allowedModels: ["reliable"], operatorCeilingModel: "reliable", minSuccess: 0.5, maxCostOfPassUsd: 3 },
  );
  assert.equal(routed.kind, "route", "one provider/model remains a usable floor");
  if (routed.kind === "route") {
    assert.equal(routed.provider, "openai-compatible");
    assert.equal(routed.model, "reliable");
    assert.equal(routed.strategy.effort, "medium");
    assert.deepEqual(routed.strategy.effortApplication, { kind: "graded", level: "medium" });
  }
});

test("cost-of-pass policy: a predicted cost ceiling refuses an uneconomic route", () => {
  const routed = chooseBudgetAwareRoute(
    { inputSize: 3000, subGoalCount: 2, reversibilityClass: "reversible", priorFailures: 0 },
    [reliable],
    { ...policy, maxCostOfPassUsd: 1 },
  );
  assert.equal(routed.kind, "escalate-human");
});

test("RESOLVE-06: hard budget uses measured spend plus worst-case reservation, not predicted average", () => {
  const cheap = { ...cheapFlaky, maxCallCostUsd: 0.4, successByBand: { moderate: 0.8 } };
  const costly = { ...reliable, maxCallCostUsd: 1.5 };
  const routed = chooseBudgetAwareRoute(
    { inputSize: 3000, subGoalCount: 2, reversibilityClass: "unknown", priorFailures: 0 },
    [cheap, costly],
    { ...policy, hardBudget: new MeasuredHardRouteBudget(2, 1) },
  );
  assert.equal(routed.kind, "route");
  if (routed.kind === "route") {
    assert.equal(routed.model, "cheap", "the otherwise preferable route is excluded when its full reservation breaches the cap");
    assert.equal(routed.reservedCostUsd, 0.4);
    assert.equal(routed.measuredSpendBeforeUsd, 1);
  }
});

test("RESOLVE-06: hard budget fails closed for missing bounds, invalid measured state, and exhausted capacity", () => {
  const signal: TaskSignal = { inputSize: 3000, subGoalCount: 2, reversibilityClass: "unknown", priorFailures: 0 };
  const noBound = chooseBudgetAwareRoute(signal, [reliable], { ...policy, hardBudget: new MeasuredHardRouteBudget(10) });
  assert.equal(noBound.kind, "escalate-human", "an average task cost is not accepted as a hard upper bound");
  const bounded = { ...reliable, maxCallCostUsd: 2 };
  assert.equal(chooseBudgetAwareRoute(signal, [bounded], { ...policy, hardBudget: new MeasuredHardRouteBudget(1) }).kind, "escalate-human");
  assert.throws(() => new MeasuredHardRouteBudget(1, 2), /invalid hard route budget/);
});

test("RESOLVE-06: one-provider floor remains functional under a hard budget", () => {
  const solo = { ...reliable, provider: "only-provider", maxCallCostUsd: 0.5 };
  const routed = chooseBudgetAwareRoute(
    { inputSize: 3000, subGoalCount: 2, reversibilityClass: "unknown", priorFailures: 0 },
    [solo],
    { allowedModels: [solo.model], operatorCeilingModel: solo.model, minSuccess: 0.5, hardBudget: new MeasuredHardRouteBudget(1, 0.25) },
  );
  assert.equal(routed.kind, "route");
  if (routed.kind === "route") assert.equal(routed.provider, "only-provider");
});

test("RESOLVE-06: atomic reservations prevent concurrent route oversubscription", () => {
  const budget = new MeasuredHardRouteBudget(1);
  const solo = { ...reliable, maxCallCostUsd: 0.6 };
  const signal: TaskSignal = { inputSize: 3000, subGoalCount: 2, reversibilityClass: "unknown", priorFailures: 0 };
  const route = () => chooseBudgetAwareRoute(signal, [solo], { ...policy, hardBudget: budget });
  const first = route();
  const second = route();
  assert.equal(first.kind, "route");
  assert.equal(second.kind, "escalate-human", "the outstanding reservation consumes capacity before execution settles");
  if (first.kind === "route") {
    assert.ok(first.budgetReservationId);
    budget.settle(first.budgetReservationId!, 0.4);
  }
  assert.equal(budget.snapshot().measuredSpentUsd, 0.4);
  assert.equal(route().kind, "route", "unused reserved capacity is released when measured spend settles");
});

test("RESOLVE-06: the legacy model-only chooser cannot bypass budget reservation or effort enforcement", () => {
  const bounded = { ...reliable, maxCallCostUsd: 0.5, effortKnob: "graded" as const };
  assert.equal(chooseModel("moderate", [bounded], { ...policy, hardBudget: new MeasuredHardRouteBudget(1) }).kind, "escalate-human");
  assert.equal(chooseModel("moderate", [bounded], { ...policy, requestedEffortControl: { kind: "graded", level: "high" } }).kind, "escalate-human");
});

test("RESOLVE-06: unsupported effort controls are refused; supported controls are applied exactly", () => {
  const signal: TaskSignal = { inputSize: 3000, subGoalCount: 2, reversibilityClass: "unknown", priorFailures: 0 };
  const noKnob = { ...reliable, effortKnob: "none" as const };
  const request = { kind: "graded" as const, level: "high" as const };
  assert.equal(chooseBudgetAwareRoute(signal, [noKnob], { ...policy, requestedEffortControl: request }).kind, "escalate-human");
  const graded = { ...reliable, effortKnob: "graded" as const };
  const routed = chooseBudgetAwareRoute(signal, [graded], { ...policy, requestedEffortControl: request });
  assert.equal(routed.kind, "route");
  if (routed.kind === "route") {
    assert.equal(routed.strategy.effort, "high");
    assert.deepEqual(routed.strategy.effortApplication, request);
  }
  const binary = { ...reliable, effortKnob: "binary" as const };
  assert.equal(chooseBudgetAwareRoute(signal, [binary], { ...policy, requestedEffortControl: request }).kind, "escalate-human", "binary thinking is not fabricated as graded high");
});

test("R4: measured outcomes change a later routing decision", () => {
  const initiallyCheap: ModelProfile = { model: "cheap", provider: "local", promptFormat: "terse", usdPerTask: 0.2, tier: 1, successByBand: { moderate: 0.9 } };
  const strong: ModelProfile = { model: "strong", provider: "remote", promptFormat: "xml", usdPerTask: 0.6, tier: 2, successByBand: { moderate: 0.95 } };
  const learningPolicy: RouterPolicy = { allowedModels: ["cheap", "strong"], operatorCeilingModel: "strong", minSuccess: 0.5 };
  const signal: TaskSignal = { inputSize: 3000, subGoalCount: 2, reversibilityClass: "unknown", priorFailures: 0 };
  const before = chooseBudgetAwareRoute(signal, [initiallyCheap, strong], learningPolicy);
  assert.equal(before.kind === "route" && before.model, "cheap");

  let learned = initiallyCheap;
  learned = recordOutcome(learned, "moderate", false, 0.5);
  learned = recordOutcome(learned, "moderate", false, 0.5);
  const after = chooseBudgetAwareRoute(signal, [learned, strong], learningPolicy);
  assert.equal(after.kind === "route" && after.model, "strong", "observed failures lower the cheap model below the reliability floor");
});

test("RESOLVE-07: routing learns only from unique measured outcomes and regression restores the exact prior profile", () => {
  const cheap: ModelProfile = { model: "cheap", promptFormat: "terse", usdPerTask: 0.2, tier: 1, successByBand: { moderate: 0.9 } };
  const strong: ModelProfile = { model: "strong", promptFormat: "xml", usdPerTask: 0.6, tier: 2, successByBand: { moderate: 0.95 } };
  const router = new MeasuredOutcomeRouter([cheap, strong]);
  const routingPolicy: RouterPolicy = { allowedModels: ["cheap", "strong"], operatorCeilingModel: "strong", minSuccess: 0.5 };
  assert.equal(chooseModel("moderate", router.profiles(), routingPolicy).kind === "model" && (chooseModel("moderate", router.profiles(), routingPolicy) as { model: string }).model, "cheap");
  assert.equal(router.record("cheap", "moderate", { measurementId: "", basis: "executed-task", success: false, regressed: false }).kind, "rejected");
  const prior = router.profiles().find((profile) => profile.model === "cheap")!;
  const updated = router.record("cheap", "moderate", { measurementId: "run-1", basis: "executed-task", success: false, regressed: false }, 0.5);
  assert.equal(updated.kind, "updated");
  assert.equal(router.record("cheap", "moderate", { measurementId: "run-1", basis: "executed-task", success: false, regressed: false }).kind, "rejected", "one execution cannot be counted twice");
  assert.notDeepEqual(router.profiles().find((profile) => profile.model === "cheap"), prior);
  const rerouted = chooseModel("moderate", router.profiles(), routingPolicy);
  assert.equal(rerouted.kind === "model" && rerouted.model, "strong", "the measured failure changes the live route");
  const rollback = router.record("cheap", "moderate", { measurementId: "run-2", basis: "held-out-eval", success: false, regressed: true });
  assert.equal(rollback.kind, "rolled-back");
  assert.deepEqual(router.profiles().find((profile) => profile.model === "cheap"), prior, "rollback restores the byte-equivalent pre-update routing profile");
  const restoredRoute = chooseModel("moderate", router.profiles(), routingPolicy);
  assert.equal(restoredRoute.kind === "model" && restoredRoute.model, "cheap", "regression restores the actual prior route, not only stored metadata");
});

test("RESOLVE-07: rollback restores only its measured band and a rejected rollback does not burn its receipt", () => {
  const base: ModelProfile = { ...reliable, successByBand: { easy: 0.8, hard: 0.9 } };
  const router = new MeasuredOutcomeRouter([base]);
  assert.equal(router.record(base.model, "easy", { measurementId: "premature", basis: "held-out-eval", success: false, regressed: true }).kind, "rejected");
  assert.equal(router.record(base.model, "easy", { measurementId: "easy-update", basis: "executed-task", success: false, regressed: false }, 0.5).kind, "updated");
  assert.equal(router.record(base.model, "hard", { measurementId: "hard-update", basis: "executed-task", success: false, regressed: false }, 0.5).kind, "updated");
  assert.equal(router.record(base.model, "easy", { measurementId: "premature", basis: "held-out-eval", success: false, regressed: true }).kind, "rolled-back");
  const restored = router.profiles()[0]!;
  assert.equal(restored.successByBand.easy, 0.8);
  assert.equal(restored.successByBand.hard, 0.45, "an easy-band rollback cannot erase the later hard-band measurement");
});

test("RESOLVE-06: observed overruns remain charged and visible instead of restoring spent capacity", () => {
  const budget = new MeasuredHardRouteBudget(1);
  const reservation = budget.tryReserve(0.4);
  assert.equal(reservation.accepted, true);
  if (!reservation.accepted) return;
  assert.ok(Math.abs(budget.settle(reservation.reservationId, 0.7).overrunUsd - 0.3) < 1e-12);
  assert.deepEqual(budget.snapshot(), { capUsd: 1, measuredSpentUsd: 0.7, reservedUsd: 0 });
});

test("explicit no-effort policy remains compatible with the model-only chooser", () => {
  assert.equal(chooseModel("moderate", [reliable], { ...policy, requestedEffortControl: { kind: "none" } }).kind, "model");
});
