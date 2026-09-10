import { test } from "node:test";
import assert from "node:assert/strict";
import type { DistilledSkill } from "../src/loop/skill_distiller.js";
import { verifySkillProgram } from "../src/loop/skill_program.js";
import { SkillValidator } from "../src/loop/skill_validator.js";
import { composeKeep } from "../src/compose.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function typedSkill(): DistilledSkill {
  return {
    format: "keep.skill/v1", id: "typed:add", name: "typed add", description: "adds two numbers", relevanceKey: "math",
    envelope: { preconditions: ["numbers supplied"], steps: [{ action: "add", targetPattern: "{a},{b}" }], postconditions: ["sum returned"], declaredEffects: [] },
    program: { entrypoint: "math.add", inputs: { a: "number", b: "number" }, cases: [
      { name: "positive", input: { a: 2, b: 3 }, expected: 5 },
      { name: "negative", input: { a: -2, b: 1 }, expected: -1 },
    ] },
    requiredAuthority: [], provenance: ["solve-1"], confidence: "corroborated",
  };
}

test("S4: a typed skill remains JSON-portable and its host program passes deterministic cases", () => {
  const portable = JSON.parse(JSON.stringify(typedSkill())) as DistilledSkill;
  assert.equal(portable.format, "keep.skill/v1", "typed support does not replace the portable structured format");
  assert.deepEqual(verifySkillProgram(portable, { "math.add": (i) => Number(i.a) + Number(i.b) }), { ok: true, casesPassed: 2 });
});

test("S4: typed verification fails closed on wrong behavior, invalid input, or unavailable code", () => {
  const skill = typedSkill();
  const wrong = verifySkillProgram(skill, { "math.add": () => 0 });
  assert.equal(wrong.ok, false);
  if (!wrong.ok) assert.match(wrong.detail, /did not match/);
  const unavailable = verifySkillProgram(skill, {});
  assert.equal(unavailable.ok, false);
  if (!unavailable.ok) assert.match(unavailable.detail, /unavailable/);
  const invalid = { ...skill, program: { ...skill.program!, cases: [{ name: "bad", input: { a: "2", b: 3 }, expected: 5 }] } };
  const result = verifySkillProgram(invalid, { "math.add": () => 5 });
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.detail, /a must be number/);
});

test("S4: the normal skill validation gate rejects a typed contract whose executable examples fail", () => {
  const validator = new SkillValidator({
    oracle: { runWithSkill: () => true, runBaseline: () => true }, generator: { generate: () => [] }, refiner: () => null,
    programs: { "math.add": () => 0 },
  });
  const result = validator.validate(typedSkill());
  assert.equal(result.verdict, "rejected-unsafe");
  assert.match(result.reason, /typed program verification failed/);
});

test("passing typed examples do not replace missing candidate execution evidence", () => {
  let programCalls = 0;
  const result = new SkillValidator({
    oracle: { runWithSkill: () => { throw new Error("no generated tasks"); }, runBaseline: () => false },
    generator: { generate: () => [] }, refiner: () => null,
    programs: { "math.add": (i) => { programCalls++; return Number(i.a) + Number(i.b); } },
  }).validate(typedSkill());
  assert.equal(programCalls, 2);
  assert.equal(result.verdict, "rejected-no-evidence");
  assert.deepEqual(result.executedCases, []);
});

test("SKILL-04: composed validation executes a host program without replacing the portable envelope", () => {
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-skill-program-")),
    skillOracle: { runWithSkill: () => true, runBaseline: () => false },
    skillPrograms: { "math.add": (input) => Number(input["a"]) + Number(input["b"]) },
  });
  const skill = typedSkill();
  const before = JSON.parse(JSON.stringify(skill.envelope));
  const result = app.skillValidator!.validate(skill);
  assert.equal(result.verdict, "validated");
  assert.deepEqual(result.skill.envelope, before, "typed execution does not replace or mutate the portable representation");
});
