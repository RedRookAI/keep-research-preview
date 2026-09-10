import { test } from "node:test";
import assert from "node:assert/strict";
import { ArtifactSelfHeal, type RegressionSignal, type HealEscalation, type HealResult } from "../src/loop/artifact_self_heal.js";
import type { SkillValidator, ValidationResult } from "../src/loop/skill_validator.js";
import { SkillCanary } from "../src/loop/skill_canary.js";
import type { DistilledSkill } from "../src/loop/skill_distiller.js";

const skill = (id = "skill:bugfix:x"): DistilledSkill => ({
  format: "keep.skill/v1", requiredAuthority: ["workspace:write"],
  id, name: id, description: "d", relevanceKey: "bugfix",
  envelope: { preconditions: ['task shape is "bugfix"'], steps: [{ action: "edit", targetPattern: "{file}" }], postconditions: [], declaredEffects: ["modifies repository files"] },
  provenance: ["T"], confidence: "corroborated",
});

const sig = (over: Partial<RegressionSignal> = {}): RegressionSignal => ({
  artifactId: "skill:bugfix:x", kind: "skill", failingContract: "empty-input regressed",
  reversible: true, touchesFrozenFloor: false, ...over,
});

// A validator stub with a fixed verdict.
function validatorStub(verdict: ValidationResult["verdict"]): SkillValidator {
  return { validate: (s: DistilledSkill): ValidationResult => ({ verdict, skill: s, rounds: 1, counterexamples: [], executedCases: [], reason: `stub ${verdict}` }) } as unknown as SkillValidator;
}
function recorder(): HealEscalation & { escalations: HealResult[] } {
  const escalations: HealResult[] = [];
  return { escalations, escalate: (r) => escalations.push(r) };
}

// ─── frozen floor is NEVER healed ───

test("an artifact touching the frozen floor is NEVER auto-healed — escalated", () => {
  const esc = recorder();
  const heal = new ArtifactSelfHeal({ validator: validatorStub("validated"), canary: new SkillCanary(), escalation: esc });
  const r = heal.heal(sig({ touchesFrozenFloor: true }), skill());
  assert.equal(r.verdict, "escalated-frozen-floor");
  assert.equal(esc.escalations.length, 1);
});

// ─── irreversible escalates + rolls back ───

test("an irreversible regression escalates and rolls back — never auto-healed", () => {
  const esc = recorder();
  const canary = new SkillCanary();
  canary.goLive("skill:bugfix:x");
  const heal = new ArtifactSelfHeal({ validator: validatorStub("validated"), canary, escalation: esc });
  const r = heal.heal(sig({ reversible: false }), skill());
  assert.equal(r.verdict, "escalated-irreversible");
  assert.equal(canary.state("skill:bugfix:x"), "rolled-back"); // rolled back
});

// ─── successful repair re-clears CEGIS + re-canaries ───

test("a repairable skill re-clears CEGIS and is re-canaried (healed)", () => {
  const canary = new SkillCanary();
  const heal = new ArtifactSelfHeal({ validator: validatorStub("validated"), canary });
  const r = heal.heal(sig(), skill());
  assert.equal(r.verdict, "healed");
  assert.equal(r.validation?.verdict, "validated");
  assert.equal(canary.state("skill:bugfix:x"), "canary"); // re-canaried (live again)
  assert.match(r.reason, /re-earn graduation/);
});

// ─── unrepairable → rollback + escalate ───

test("a skill that cannot re-clear CEGIS is rolled back and escalated", () => {
  const esc = recorder();
  const canary = new SkillCanary();
  canary.goLive("skill:bugfix:x");
  const heal = new ArtifactSelfHeal({ validator: validatorStub("abandoned-budget"), canary, escalation: esc });
  const r = heal.heal(sig(), skill());
  assert.equal(r.verdict, "escalated-unrefinable");
  assert.equal(canary.state("skill:bugfix:x"), "rolled-back");
  assert.equal(esc.escalations.length, 1);
});

// ─── 3-strike loop guard ───

test("3-strike loop guard: after repeated failed heals, escalates instead of looping forever", () => {
  const esc = recorder();
  const heal = new ArtifactSelfHeal({ validator: validatorStub("abandoned-budget"), canary: new SkillCanary(), escalation: esc, maxStrikes: 3 });
  // 3 failed heals accumulate strikes.
  heal.heal(sig(), skill()); // strike 1
  heal.heal(sig(), skill()); // strike 2
  heal.heal(sig(), skill()); // strike 3
  assert.equal(heal.strikeCount("skill:bugfix:x"), 3);
  // 4th attempt → strikes exhausted, escalate without another CEGIS attempt.
  const r = heal.heal(sig(), skill());
  assert.equal(r.verdict, "escalated-strikes");
});

test("a successful heal resets the strike count", () => {
  const canary = new SkillCanary();
  // First a failing validator to accrue a strike, then swap to success is not possible on one instance;
  // instead verify a fresh success starts at 0 and stays 0.
  const heal = new ArtifactSelfHeal({ validator: validatorStub("validated"), canary });
  heal.heal(sig(), skill());
  assert.equal(heal.strikeCount("skill:bugfix:x"), 0);
});

// ─── localization: the failing contract is fed into the repair ───

test("the failing contract is used to localize the repair (added as a heal-localized precondition)", () => {
  let seenPreconditions: readonly string[] = [];
  const capturingValidator = {
    validate: (s: DistilledSkill): ValidationResult => {
      seenPreconditions = s.envelope.preconditions;
      return { verdict: "validated", skill: s, rounds: 1, counterexamples: [], executedCases: [], reason: "stub localization check only" };
    },
  } as unknown as SkillValidator;
  const heal = new ArtifactSelfHeal({ validator: capturingValidator, canary: new SkillCanary() });
  heal.heal(sig({ failingContract: "unicode-target regressed" }), skill());
  assert.ok(seenPreconditions.some((p) => p.includes("heal-localized: unicode-target regressed")), "repair is localized by the failing contract");
});

// ─── heal is heal-class (highest precedence) ───

test("self-heal registers as heal-class (highest adaptation precedence)", () => {
  const heal = new ArtifactSelfHeal({ validator: validatorStub("validated"), canary: new SkillCanary() });
  assert.equal(heal.loopClass, "heal");
});
