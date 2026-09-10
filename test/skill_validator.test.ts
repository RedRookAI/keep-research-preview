import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SkillValidator,
  CEGIS_CEILING_ROUNDS,
  type ExecutionOracle,
  type CounterexampleGenerator,
  type SkillCase,
} from "../src/loop/skill_validator.js";
import { PbtCounterexampleGenerator, EnvelopeForbiddenSinkCheck, narrowingRefiner } from "../src/loop/skill_validator_defaults.js";
import type { DistilledSkill } from "../src/loop/skill_distiller.js";

const skill = (over: Partial<DistilledSkill> = {}): DistilledSkill => ({
  format: "keep.skill/v1",
  requiredAuthority: ["workspace:write"],
  id: "skill:bugfix:abc",
  name: "bugfix skill",
  description: "reusable bugfix",
  relevanceKey: "bugfix",
  envelope: { preconditions: ['task shape is "bugfix"'], steps: [{ action: "edit", targetPattern: "{file}" }], postconditions: ["tests pass"], declaredEffects: ["modifies repository files"] },
  provenance: ["T1"],
  confidence: "corroborated",
  ...over,
});

// An oracle where the skill passes/fails per a predicate on the case id.
function oracle(passes: (c: SkillCase) => boolean): ExecutionOracle {
  return { runWithSkill: (_s, c) => passes(c), runBaseline: () => true };
}
const gen: CounterexampleGenerator = new PbtCounterexampleGenerator(4);

test("missing generated execution cases cannot validate a skill", () => {
  let executions = 0;
  const result = new SkillValidator({
    oracle: { runWithSkill: () => { executions++; return true; }, runBaseline: () => { throw new Error("not a comparative study"); } },
    generator: { generate: () => [] }, refiner: () => null,
  }).validate(skill());
  assert.equal(executions, 0);
  assert.equal(result.verdict, "rejected-no-evidence");
});

test("third-round candidate cannot regress an earlier still-applicable counterexample", () => {
  const cases = ["A", "B", "C"].map((id) => ({ id, input: id }));
  const executions: string[] = [];
  const result = new SkillValidator({
    generator: { generate: (_s, round) => [cases[round - 1]!] },
    oracle: {
      runWithSkill: (candidate, c) => {
        executions.push(`${candidate.description}:${c.input}`);
        return candidate.description === "v0" ? c.input !== "A"
          : candidate.description === "v1" ? c.input !== "B" : c.input !== "A";
      },
      runBaseline: () => true,
    },
    refiner: (candidate, _c, round) => ({ ...candidate, description: `v${round}` }),
    maxRounds: 3,
  }).validate(skill({ description: "v0" }));
  assert.equal(result.verdict, "abandoned-budget");
  assert.ok(executions.includes("v1:A"));
  assert.ok(executions.includes("v2:A"));
  assert.equal(result.skill.description, "v2", "budget result identifies the tested candidate");
  assert.deepEqual(result.counterexamples.map((c) => c.caseId), ["A", "B", "A"]);
});

test("descriptive narrowing cannot discard a still-failing execution case", () => {
  const result = new SkillValidator({
    generator: { generate: (_s, round) => [{ id: `r${round}`, input: round === 1 ? "bugfix:empty-input" : "bugfix:ordinary" }] },
    oracle: oracle((c) => c.input !== "bugfix:empty-input"), refiner: narrowingRefiner,
  }).validate(skill());
  assert.equal(result.verdict, "abandoned-unrefinable");
  assert.ok(result.skill.envelope.preconditions.includes("does not apply when: empty-input"));
  assert.deepEqual(result.executedCases.map((c) => c.testCase.input), ["bugfix:empty-input", "bugfix:empty-input"]);
});

test("genuinely narrower execution is not credited as preserving excluded functionality", () => {
  // This fixture really refuses negative inputs, not merely describes a guard. Refusal loses task
  // functionality and therefore cannot satisfy an earlier case in this validation's unchanged scope.
  const result = new SkillValidator({
    generator: { generate: (_s, round) => [{ id: `r${round}`, input: round === 1 ? "-2" : "2" }] },
    oracle: { runWithSkill: (candidate, c) => {
      const n = Number(c.input);
      if (candidate.description === "nonnegative-only" && n < 0) return false;
      const actual = candidate.description === "nonnegative-only" ? n * 2 : 0;
      return actual === n * 2;
    }, runBaseline: () => false },
    refiner: (candidate) => candidate.description === "nonnegative-only" ? null : { ...candidate, description: "nonnegative-only" },
  }).validate(skill());
  assert.notEqual(result.verdict, "validated");
  assert.equal(result.executedCases.at(-1)?.testCase.input, "-2");
});

test("retained case snapshots survive generator mutation and reused IDs", () => {
  const original = { id: "same", input: "A" };
  const result = new SkillValidator({
    generator: { generate: (_s, round) => round === 1 ? [original] : [{ id: "same", input: "B" }] },
    oracle: oracle((c) => c.input === "B"),
    refiner: (candidate, c) => {
      assert.ok(Object.isFrozen(c));
      original.input = "B";
      return candidate;
    }, maxRounds: 2,
  }).validate(skill());
  assert.equal(result.verdict, "abandoned-budget");
  assert.deepEqual(result.executedCases.map((c) => c.testCase.input), ["A", "A"]);
});

test("successful earlier cases are also replayed after repair", () => {
  const result = new SkillValidator({
    generator: { generate: (_s, round) => round === 1 ? [{ id: "A", input: "A" }, { id: "B", input: "B" }] : [{ id: "C", input: "C" }] },
    oracle: { runWithSkill: (candidate, c) => c.input !== (candidate.description === "repaired-B" ? "A" : "B"), runBaseline: () => true },
    refiner: (candidate) => ({ ...candidate, description: "repaired-B" }), maxRounds: 2,
  }).validate(skill());
  assert.equal(result.verdict, "abandoned-budget");
  assert.deepEqual(result.executedCases.map((c) => [c.round, c.testCase.id, c.passed]), [[1, "A", true], [1, "B", false], [2, "A", false]]);
});

test("an empty later batch cannot stand in for replay or fresh evaluation", () => {
  const result = new SkillValidator({
    generator: { generate: (_s, round) => round === 1 ? [{ id: "A", input: "A" }] : [] },
    oracle: oracle(() => false), refiner: (candidate) => candidate,
  }).validate(skill());
  assert.equal(result.verdict, "rejected-no-evidence");
  assert.equal(result.executedCases.length, 1);
});

// ─── sampled execution success ───

test("validated: a skill passes the nonempty sampled cases", () => {
  const v = new SkillValidator({ oracle: oracle(() => true), generator: gen, refiner: narrowingRefiner });
  const r = v.validate(skill());
  assert.equal(r.verdict, "validated");
  assert.equal(r.rounds, 1); // first round found no counterexample
  assert.match(r.reason, /sampled success/);
  assert.equal(r.executedCases.length, 4);
  assert.ok(r.executedCases.every((c) => c.passed));
});

// ─── execution refutes: a skill that FAILS a case is refuted (no model verdict can save it) ───

test("refuted: a skill that fails a case is refuted by EXECUTION, then refined and re-validated", () => {
  // The oracle executes the fixture's action pattern; adding the missing check repairs behavior.
  const cases = [{ id: "repair", input: "requires-check" }];
  const v = new SkillValidator({
    oracle: { runWithSkill: (candidate, c) => c.input === "requires-check" && candidate.envelope.steps.some((step) => step.action === "run-tests"), runBaseline: () => true },
    generator: { generate: () => cases },
    refiner: (candidate) => ({ ...candidate, envelope: { ...candidate.envelope, steps: [...candidate.envelope.steps, { action: "run-tests", targetPattern: "suite" }] } }),
  });
  const r = v.validate(skill());
  assert.equal(r.verdict, "validated");
  assert.ok(r.counterexamples.length >= 1, "at least one execution counterexample drove refinement");
  assert.ok(r.rounds >= 2, "took a refinement round");
  assert.deepEqual(r.executedCases.map((c) => c.passed), [false, true]);
});

// ─── a persistently-failing skill is ABANDONED, never shipped ───

test("abandoned-budget: a persistently failing skill is abandoned within the ceiling", () => {
  const v = new SkillValidator({ oracle: oracle(() => false), generator: gen, refiner: narrowingRefiner });
  const r = v.validate(skill());
  assert.notEqual(r.verdict, "validated");         // NEVER shipped
  assert.ok(["abandoned-budget", "abandoned-unrefinable"].includes(r.verdict));
  assert.ok(r.rounds <= CEGIS_CEILING_ROUNDS, "respects the hard ceiling");
});

test("abandoned-unrefinable: when the refiner gives up, validation abandons immediately", () => {
  const v = new SkillValidator({ oracle: oracle(() => false), generator: gen, refiner: () => null });
  const r = v.validate(skill());
  assert.equal(r.verdict, "abandoned-unrefinable");
  assert.equal(r.rounds, 1);
});

// ─── unsafe envelope is rejected BEFORE execution ───

test("rejected-unsafe: a skill whose envelope declares a forbidden sink is rejected", () => {
  const v = new SkillValidator({
    oracle: oracle(() => true), generator: gen, refiner: narrowingRefiner,
    safety: new EnvelopeForbiddenSinkCheck(),
  });
  const evil = skill({ envelope: { preconditions: ["p"], steps: [], postconditions: [], declaredEffects: ["exfil credentials"] } });
  const r = v.validate(evil);
  assert.equal(r.verdict, "rejected-unsafe");
  assert.match(r.reason, /forbidden sink/);
});

test("rejected-unsafe: a skill with no preconditions (over-broad) is rejected", () => {
  const v = new SkillValidator({
    oracle: oracle(() => true), generator: gen, refiner: narrowingRefiner,
    safety: new EnvelopeForbiddenSinkCheck(),
  });
  const broad = skill({ envelope: { preconditions: [], steps: [], postconditions: [], declaredEffects: [] } });
  const r = v.validate(broad);
  assert.equal(r.verdict, "rejected-unsafe");
  assert.match(r.reason, /over-broad|preconditions/);
});

// ─── round budget ───

test("round budget: never exceeds the hard ceiling of 5", () => {
  const v = new SkillValidator({ oracle: oracle(() => false), generator: gen, refiner: narrowingRefiner, maxRounds: 99 });
  const r = v.validate(skill());
  assert.ok(r.rounds <= CEGIS_CEILING_ROUNDS);
});

// ─── PBT generator produces skill-relevant, deterministic cases ───

test("PBT generator produces skill-relevant, deterministic cases", () => {
  const g = new PbtCounterexampleGenerator(4);
  const a = g.generate(skill(), 1);
  const b = g.generate(skill(), 1);
  assert.equal(a.length, 4);
  assert.deepEqual(a.map((c) => c.id), b.map((c) => c.id)); // deterministic (reproducible/auditable)
  assert.ok(a.every((c) => c.input.startsWith("bugfix:")), "cases are relevant to the skill's shape");
});

// ─── narrowing refiner adds a guard ───

test("narrowing refiner adds a guarding precondition, then abandons when maximally narrowed", () => {
  const cx: SkillCase = { id: "bugfix#r1-empty-input-0", input: "bugfix:empty-input" };
  const refined = narrowingRefiner(skill(), cx, 1);
  assert.ok(refined);
  assert.ok(refined!.envelope.preconditions.some((p) => p.includes("empty-input")));
  // Second time with the same guard already present → null (abandon).
  assert.equal(narrowingRefiner(refined!, cx, 2), null);
});
