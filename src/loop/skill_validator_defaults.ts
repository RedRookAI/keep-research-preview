/**
 * Default floor implementations of the CEGIS ports (Increment 18.5) — zero-dep, NO model. These make skill
 * validation runnable at the floor (N=1, one family, no GPU) using only EXECUTION + property-based testing.
 * Richer generators (a second family proposing adversarial cases) plug in at the standard/rich tiers.
 */

import type { DistilledSkill } from "./skill_distiller.js";
import type { CounterexampleGenerator, EnvelopeSafetyCheck, SkillCase, SkillRefiner } from "./skill_validator.js";

/**
 * PBT/fuzzing counterexample generator: derives skill-RELEVANT cases from the skill's relevance shape by
 * mutating along dimensions that commonly break brittle skills — empty/edge inputs, boundary sizes,
 * reordered/absent preconditions. Deterministic (seeded by round) so runs are reproducible + auditable.
 */
export class PbtCounterexampleGenerator implements CounterexampleGenerator {
  constructor(private readonly casesPerRound = 6) {}

  generate(skill: DistilledSkill, round: number): readonly SkillCase[] {
    const shape = skill.relevanceKey;
    // Metamorphic/edge dimensions — the classic brittleness surfaces, no model needed.
    const dims = ["empty-input", "boundary-large", "boundary-small", "missing-precondition", "reordered-steps", "unicode-target", "nested-target", "concurrent-context"];
    const out: SkillCase[] = [];
    for (let i = 0; i < this.casesPerRound; i++) {
      const dim = dims[(round * 31 + i * 7) % dims.length]!;
      out.push({ id: `${shape}#r${round}-${dim}-${i}`, input: `${shape}:${dim}` });
    }
    return out;
  }
}

/** Sinks a skill envelope may never declare without a human gate (mirrors the distiller + reference monitor). */
const FORBIDDEN_SINKS = ["exfil", "external-send", "credential", "escalate-privilege", "delete-external"];

/**
 * Envelope safety check backed by the same forbidden-sink contract the reference monitor enforces on the
 * trace. A distilled skill whose declared effects reach a forbidden sink is rejected as unsafe — it cannot be
 * validated into "live" no matter how well it executes. Cross-modal: the STRUCTURED effects are what's checked.
 */
export class EnvelopeForbiddenSinkCheck implements EnvelopeSafetyCheck {
  check(skill: DistilledSkill): string | null {
    for (const eff of skill.envelope.declaredEffects) {
      const low = eff.toLowerCase();
      for (const sink of FORBIDDEN_SINKS) {
        if (low.includes(sink)) return `declared effect "${eff}" reaches forbidden sink "${sink}"`;
      }
    }
    // Precondition sanity: a skill with no preconditions applies everywhere (over-broad) — unsafe.
    if (skill.envelope.preconditions.length === 0) return "skill has no preconditions (over-broad activation)";
    return null;
  }
}

/**
 * Default refiner: tightens the skill in response to a counterexample by ADDING a guarding precondition that
 * excludes the failing case's dimension. This is the zero-dep "narrow the skill's applicability" move —
 * a skill that fails an edge case is restricted so it no longer claims to handle it. Returns null only if the
 * skill is already maximally narrowed (nothing left to guard) → abandon.
 */
export const narrowingRefiner: SkillRefiner = (skill, counterexample) => {
  const dim = counterexample.input.split(":")[1] ?? counterexample.id;
  const guard = `does not apply when: ${dim}`;
  if (skill.envelope.preconditions.includes(guard)) return null; // already guarded → cannot refine further
  return {
    ...skill,
    envelope: { ...skill.envelope, preconditions: [...skill.envelope.preconditions, guard] },
    description: `${skill.description} (refined: excludes ${dim})`,
  };
};
