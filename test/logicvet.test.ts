import { test } from "node:test";
import assert from "node:assert/strict";

import {
  orderCritic,
  constraintCritic,
  proportionalityCritic,
  contradictionCritic,
  deterministicCritics,
  type Plan,
  type PlanConstraints,
} from "../src/logicvet/deterministic_critics.js";
import {
  premiseGroundingCritic,
  type Claim,
} from "../src/logicvet/grounded_critics.js";
import { consensus, postureForTaskShape } from "../src/logicvet/consensus.js";
import { LogicVet } from "../src/logicvet/logic_vet.js";
import { checkHeterogeneous, assertHeterogeneous } from "../src/review/heterogeneous.js";

const noConstraints: PlanConstraints = {};

// ── Order-of-operations critic (sound) ──────────────────────────────────────

test("INVARIANT: order critic detects a dependency CYCLE (sound block)", () => {
  const plan: Plan = {
    goal: "g",
    steps: [
      { id: "a", description: "a", dependsOn: ["c"] },
      { id: "b", description: "b", dependsOn: ["a"] },
      { id: "c", description: "c", dependsOn: ["b"] },
    ],
  };
  const v = orderCritic(plan);
  assert.equal(v.status, "block");
  assert.equal(v.sound, true, "order critic is sound (deterministic)");
  assert.match(v.reason, /cycle/);
});

test("INVARIANT: order critic detects a forward reference (step depends on a later step)", () => {
  const plan: Plan = {
    goal: "g",
    steps: [
      { id: "a", description: "a", dependsOn: ["b"] }, // b comes after a
      { id: "b", description: "b", dependsOn: [] },
    ],
  };
  const v = orderCritic(plan);
  assert.equal(v.status, "block");
  assert.match(v.reason, /out of order|later step/);
});

test("order critic detects a missing prerequisite", () => {
  const plan: Plan = { goal: "g", steps: [{ id: "a", description: "a", dependsOn: ["ghost"] }] };
  const v = orderCritic(plan);
  assert.equal(v.status, "block");
  assert.match(v.reason, /missing prerequisite/);
});

test("order critic PASSES a well-ordered acyclic plan", () => {
  const plan: Plan = {
    goal: "g",
    steps: [
      { id: "a", description: "a", dependsOn: [] },
      { id: "b", description: "b", dependsOn: ["a"] },
      { id: "c", description: "c", dependsOn: ["a", "b"] },
    ],
  };
  assert.equal(orderCritic(plan).status, "pass");
});

// ── Constraint / proportionality / contradiction ────────────────────────────

test("constraint critic blocks over-budget, infeasible, and forbidden actions", () => {
  const plan: Plan = { goal: "g", steps: [{ id: "a", description: "delete production database", dependsOn: [] }] };
  const over = constraintCritic(plan, { budgetTokens: 100, estimatedTokens: 500 });
  assert.equal(over.status, "block");
  const infeasible = constraintCritic(plan, { feasibilityClass: "infeasible" });
  assert.equal(infeasible.status, "block");
  const forbidden = constraintCritic(plan, { forbiddenActions: ["delete production"] });
  assert.equal(forbidden.status, "block");
  assert.match(forbidden.reason, /forbidden/);
});

test("proportionality critic flags over-engineering and under-scoping", () => {
  const big: Plan = { goal: "g", steps: Array.from({ length: 12 }, (_, i) => ({ id: `s${i}`, description: "x", dependsOn: [] })) };
  assert.equal(proportionalityCritic(big, { maxSteps: 3 }).status, "concern");
  const small: Plan = { goal: "g", steps: [{ id: "a", description: "x", dependsOn: [] }] };
  assert.equal(proportionalityCritic(small, { minSteps: 3 }).status, "concern");
});

test("INVARIANT: contradiction critic detects assert-vs-require conflict (sound)", () => {
  const plan: Plan = {
    goal: "g",
    steps: [
      { id: "a", description: "logout", dependsOn: [], asserts: ["not authenticated"] },
      { id: "b", description: "read secrets", dependsOn: [], requires: ["authenticated"] },
    ],
  };
  const v = contradictionCritic(plan);
  assert.equal(v.status, "block");
  assert.equal(v.sound, true);
  assert.match(v.reason, /negation|contradict/);
});

// ── Consensus: only SOUND critics gate ──────────────────────────────────────

test("INVARIANT: a fuzzy (non-sound) critic block is demoted — cannot gate alone", () => {
  const fuzzyBlock = { critic: "premise-grounding", status: "block" as const, reason: "unsupported", implicated: ["a"], sound: false };
  const v = consensus([fuzzyBlock], "strict");
  assert.notEqual(v.decision, "block", "a fuzzy critic alone cannot BLOCK");
  assert.equal(v.decision, "rework", "it's demoted to a concern → rework");
});

test("INVARIANT: a SOUND critic block DOES gate (block)", () => {
  const soundBlock = { critic: "order-of-operations", status: "block" as const, reason: "cycle", implicated: ["a"], sound: true };
  assert.equal(consensus([soundBlock], "strict").decision, "block");
});

test("INVARIANT: permissive posture preserves divergent ideas (proportionality concern doesn't block)", () => {
  const plan: Plan = { goal: "brainstorm novel premises", steps: Array.from({ length: 12 }, (_, i) => ({ id: `s${i}`, description: "wild idea", dependsOn: [] })) };
  const critics = deterministicCritics(plan, { maxSteps: 3 });
  const strict = consensus(critics, "strict");
  const permissive = consensus(critics, "permissive");
  assert.equal(strict.decision, "rework", "strict flags over-engineering");
  assert.equal(permissive.decision, "pass", "permissive preserves divergent brainstorm");
});

test("permissive STILL blocks on internal contradiction (gross-infeasibility gate holds)", () => {
  const plan: Plan = {
    goal: "brainstorm",
    steps: [
      { id: "a", description: "x", dependsOn: [], asserts: ["not possible"] },
      { id: "b", description: "y", dependsOn: [], requires: ["possible"] },
    ],
  };
  const critics = deterministicCritics(plan, {});
  assert.equal(consensus(critics, "permissive").decision, "block", "contradiction blocks even in brainstorm");
});

test("postureForTaskShape: creative → permissive, build → strict", () => {
  assert.equal(postureForTaskShape("brainstorm novel premises"), "permissive");
  assert.equal(postureForTaskShape("implement REST API"), "strict");
});

// ── Single-model failsafe (§9 / §9.1) ───────────────────────────────────────

test("INVARIANT: checkHeterogeneous NEVER throws (single-model must not error)", () => {
  const author = { agentId: "solo", modelFamily: "deepseek" };
  // same agent + family = single model
  const s = checkHeterogeneous(author, author);
  assert.equal(s.singleModel, true);
  assert.equal(s.independent, false);
  // contrast: assertHeterogeneous DOES throw (kept for hard-gate multi-model paths)
  assert.throws(() => assertHeterogeneous(author, author));
});

test("INVARIANT: single-model premise critic FLAGS (concern), never authoritative-blocks", () => {
  const claims: Claim[] = [{ stepId: "a", text: "assumes X", grounding: { kind: "citation", ref: "r" } }];
  // independent critic finds unsupported → could block
  const indep = premiseGroundingCritic(claims, { independentCriticAvailable: true, checker: () => ({ supported: false, reason: "source doesn't support" }) });
  assert.equal(indep.status, "block", "independent critic can block on unsupported");
  // single-model finds unsupported → only concern (flag for human), never block
  const single = premiseGroundingCritic(claims, { independentCriticAvailable: false, checker: () => ({ supported: false, reason: "source doesn't support" }) });
  assert.equal(single.status, "concern", "single-model flags, does not bless/condemn");
  assert.equal(single.sound, false, "fuzzy critic is never sound");
});

test("single-model LogicVet still gates HARD on deterministic critics (sound floor holds)", () => {
  const lv = new LogicVet();
  const plan: Plan = { goal: "implement", steps: [{ id: "a", description: "a", dependsOn: ["b"] }, { id: "b", description: "b", dependsOn: ["a"] }] };
  const r = lv.vetPlan({ plan, constraints: {}, taskShape: "implement" }); // no reviewer = single-model
  assert.equal(r.singleModel, true);
  assert.equal(r.verdict.decision, "block", "cycle still blocks in single-model mode (deterministic gate)");
  assert.match(r.note, /single-model/);
});

// ── Rabbit-hole guard: recheck suppression ──────────────────────────────────

test("INVARIANT: recheck suppression — unchanged already-passed steps are NOT re-vetted", () => {
  const lv = new LogicVet();
  const plan: Plan = {
    goal: "implement",
    steps: [
      { id: "a", description: "a", dependsOn: [] },
      { id: "b", description: "b", dependsOn: ["a"] },
    ],
  };
  // first artifact vet: both steps vetted + pass → remembered
  const first = lv.vetArtifact({ plan, constraints: {}, taskShape: "implement" }, "v1", ["a", "b"]);
  assert.equal(first.verdict.decision, "pass");
  // re-entry with NO changed steps → recheck suppressed
  const second = lv.vetArtifact({ plan, constraints: {}, taskShape: "implement" }, "v1", []);
  assert.match(second.verdict.reason, /recheck suppressed|no changed steps/);
  assert.equal(second.critics.length, 0, "no critics re-run on unchanged settled steps");
});
