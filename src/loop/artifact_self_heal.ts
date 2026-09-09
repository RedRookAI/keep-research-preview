/**
 * ArtifactSelfHeal (Increment C3, Phase D) — the self-heal CEGIS loop for SELF-AUTHORED artifacts. When a
 * distilled skill or learned lesson REGRESSES in production (drift latch from C4, a canary demotion, a failing
 * contract), Keep attempts a bounded, execution-adjudicated SELF-REPAIR of THAT artifact — never the frozen
 * floor, never irreversible external effects, and never by laundering a bad artifact past validation.
 *
 * This is distinct from the two existing repair loops and reuses their machinery rather than duplicating it:
 *  - safe_remediation.ts (16.9a) heals a PATCH before the human gate.
 *  - repair_loop.ts (13c) is the SOLVE-time re-plan loop.
 *  - C3 heals a SELF-IMPROVEMENT ARTIFACT (skill/lesson) via the CEGIS validator (18.5) + canary (18.6).
 *
 * SOTA basis (2026-08-05):
 *  - "Skill drift is CONTRACT VIOLATION" and the violated contract LOCALIZES the repair — one-round repair
 *    jumps 10%→78% with localization (SKILLGUARD arXiv 2605.10990). → C3 localizes using the failing
 *    precondition/counterexample, not a blind re-derivation.
 *  - Escalation by REVERSIBILITY + risk (Zylos / NoOps 2026): Level 1 automated (reversible, well-understood),
 *    Level 3 human on destructive OR 3+ consecutive failed attempts. → reversibility gate + 3-strike bound.
 *  - Acceptance oracle = formal RE-VERIFICATION, not test pass/fail alone (ESBMC self-healing, AST 2025):
 *    "iterate until verifier-passing or exhaust the budget." → the repaired artifact must RE-CLEAR CEGIS
 *    (execution-adjudicated), or it is NOT accepted.
 *  - Self-healing application LOGIC is a dangerous frontier (module.today 2026) → conservative: heal only
 *    reversible self-authored artifacts, re-validate, escalate everything else. Human merge gate untouched.
 *
 * Zero runtime deps. The validator + canary + escalation notifier are injected (ports).
 */

import type { DistilledSkill } from "./skill_distiller.js";
import type { SkillValidator, ValidationResult } from "./skill_validator.js";
import type { SkillCanary } from "./skill_canary.js";

/** The kind of self-authored artifact being healed. The frozen floor is NEVER an artifact kind here. */
export type HealableKind = "skill" | "lesson";

/** A detected regression that may trigger a self-heal. */
export interface RegressionSignal {
  readonly artifactId: string;
  readonly kind: HealableKind;
  /** Why it regressed — the failing contract/counterexample used to LOCALIZE the repair (SKILLGUARD). */
  readonly failingContract: string;
  /** Is the artifact's effect reversible + bounded? Irreversible → escalate, never auto-heal. */
  readonly reversible: boolean;
  /** Does the artifact touch the frozen safety floor? If so it is NEVER healed here (hard invariant). */
  readonly touchesFrozenFloor: boolean;
}

export type HealVerdict =
  | "healed"                    // repaired + re-cleared CEGIS + re-canaried
  | "escalated-irreversible"    // not reversible → human
  | "escalated-frozen-floor"    // touches the floor → never auto-healed
  | "escalated-unrefinable"     // CEGIS could not repair → rollback + human
  | "escalated-strikes";        // too many consecutive failed heals → rollback + human

export interface HealResult {
  readonly verdict: HealVerdict;
  readonly artifactId: string;
  readonly attempts: number;
  readonly validation?: ValidationResult;
  readonly reason: string;
}

/** Escalation notifier (reuses the canary's tiered model conceptually; a heal escalation is a ticket/page). */
export interface HealEscalation {
  escalate(result: HealResult): void;
}

export interface ArtifactSelfHealConfig {
  readonly validator: SkillValidator;
  readonly canary: SkillCanary;
  /** Max consecutive failed heal attempts for a signature before escalating (Level-3, 3-strike). Default 3. */
  readonly maxStrikes?: number;
  readonly escalation?: HealEscalation;
}

export class ArtifactSelfHeal {
  readonly id = "artifact-self-heal";
  readonly loopClass = "heal" as const;
  private readonly validator: SkillValidator;
  private readonly canary: SkillCanary;
  private readonly maxStrikes: number;
  private readonly escalation: HealEscalation | undefined;
  /** Per-artifact consecutive failed-heal count (the loop guard — never heal the same thing forever). */
  private readonly strikes = new Map<string, number>();

  constructor(config: ArtifactSelfHealConfig) {
    this.validator = config.validator;
    this.canary = config.canary;
    this.maxStrikes = config.maxStrikes ?? 3;
    this.escalation = config.escalation;
  }

  /**
   * Attempt a self-heal of a regressed skill. HARD gates first (frozen floor, irreversibility, strikes), then a
   * localized CEGIS repair that must RE-CLEAR validation. On success the repaired skill is re-canaried (live,
   * instant-rollback). On any failure the artifact is rolled back and the human is notified. Never merges.
   */
  heal(signal: RegressionSignal, current: DistilledSkill): HealResult {
    // HARD invariant: the frozen floor is never auto-healed.
    if (signal.touchesFrozenFloor) {
      return this.escalateResult("escalated-frozen-floor", signal.artifactId, 0, "artifact touches the frozen safety floor — never auto-healed, routed to human");
    }
    // Reversibility gate: irreversible/unbounded effects escalate (Level-3), never auto-heal.
    if (!signal.reversible) {
      this.canary.forceRollback(signal.artifactId, `irreversible regression: ${signal.failingContract}`);
      return this.escalateResult("escalated-irreversible", signal.artifactId, 0, "regression is not reversible/bounded — rolled back + routed to human");
    }
    // 3-strike loop guard: too many consecutive failed heals → stop trying, escalate.
    const priorStrikes = this.strikes.get(signal.artifactId) ?? 0;
    if (priorStrikes >= this.maxStrikes) {
      this.canary.forceRollback(signal.artifactId, `heal strikes exhausted: ${signal.failingContract}`);
      return this.escalateResult("escalated-strikes", signal.artifactId, priorStrikes, `healed unsuccessfully ${priorStrikes}× — rolled back + routed to human (no infinite heal loop)`);
    }

    // LOCALIZED CEGIS repair: seed the validator with the failing contract so refinement targets the actual
    // violation (SKILLGUARD localization). The repaired artifact must RE-CLEAR execution-adjudicated validation.
    const localized: DistilledSkill = {
      ...current,
      envelope: { ...current.envelope, preconditions: [...current.envelope.preconditions, `heal-localized: ${signal.failingContract}`] },
    };
    const validation = this.validator.validate(localized);

    if (validation.verdict === "validated") {
      // Re-clears CEGIS → accept. Re-canary it: live again, instant-rollback, must re-earn graduation.
      this.strikes.delete(signal.artifactId); // reset on success
      this.canary.goLive(validation.skill.id);
      return { verdict: "healed", artifactId: signal.artifactId, attempts: priorStrikes + 1, validation, reason: `self-heal re-cleared CEGIS (${validation.reason}); re-canaried, must re-earn graduation` };
    }

    // Did not re-clear → count a strike, roll back, escalate.
    this.strikes.set(signal.artifactId, priorStrikes + 1);
    this.canary.forceRollback(signal.artifactId, `heal failed CEGIS: ${validation.reason}`);
    return this.escalateResult("escalated-unrefinable", signal.artifactId, priorStrikes + 1, `CEGIS could not repair the artifact (${validation.verdict}) — rolled back + routed to human`, validation);
  }

  private escalateResult(verdict: HealVerdict, artifactId: string, attempts: number, reason: string, validation?: ValidationResult): HealResult {
    const result: HealResult = validation
      ? { verdict, artifactId, attempts, validation, reason }
      : { verdict, artifactId, attempts, reason };
    this.escalation?.escalate(result);
    return result;
  }

  /** Consecutive failed-heal count for an artifact (diagnostics/tests). */
  strikeCount(artifactId: string): number { return this.strikes.get(artifactId) ?? 0; }
}
