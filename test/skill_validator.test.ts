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

// ─── execution adjudicates: a skill that passes all cases is validated (fix-point) ───

test("validated: a skill that passes every generated case reaches an execution fix-point", () => {
  const v = new SkillValidator({ oracle: oracle(() => true), generator: gen, refiner: narrowingRefiner });
  const r = v.validate(skill());
  assert.equal(r.verdict, "validated");
  assert.equal(r.rounds, 1); // first round found no counterexample
  assert.match(r.reason, /fix-point/);
});

// ─── execution refutes: a skill that FAILS a case is refuted (no model verdict can save it) ───

test("refuted: a skill that fails a case is refuted by EXECUTION, then refined and re-validated", () => {
  // Fails only the first case it ever sees; the narrowing refiner adds a guard, subsequent rounds pass.
  let failsSeen = 0;
  const v = new SkillValidator({
    oracle: { runWithSkill: () => (failsSeen++ === 0 ? false : true), runBaseline: () => true },
    generator: gen, refiner: narrowingRefiner,
  });
  const r = v.validate(skill());
  assert.equal(r.verdict, "validated");
  assert.ok(r.counterexamples.length >= 1, "at least one execution counterexample drove refinement");
  assert.ok(r.rounds >= 2, "took a refinement round");
});

// ─── a persistently-failing skill is ABANDONED, never shipped ───

test("abandoned-budget: a skill that never reaches a fix-point is abandoned within the ceiling", () => {
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
