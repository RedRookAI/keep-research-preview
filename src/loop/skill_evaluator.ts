import type { DistilledSkill } from "./skill_distiller.js";
import type { ExecutionOracle, SkillCase } from "./skill_validator.js";
import type { SkillCanary } from "./skill_canary.js";
import type { BoundedCrossFamilyCriticism, CriticismGateResult } from "../learning/cross_family_criticism.js";

/** Aggregate execution evidence for one arm of a held-out skill evaluation. */
export interface SkillEvalArm {
  readonly passed: number;
  readonly total: number;
  readonly rate: number;
}

export interface SkillDiagnosticCase extends SkillCase {
  readonly shouldTrigger: boolean;
  readonly requiredInstructions: readonly string[];
  readonly requiredSolutionPath: readonly string[];
}

export interface SkillDiagnosticObservation {
  readonly triggered: boolean;
  readonly followedInstructions: readonly string[];
  readonly solutionPath: readonly string[];
  readonly quality: number;
}

export interface SkillDiagnosticOracle {
  run(candidate: DistilledSkill | undefined, testCase: SkillDiagnosticCase): SkillDiagnosticObservation;
}

export interface SkillDiagnosticProfile {
  readonly cases: number;
  readonly triggerPrecision: number;
  readonly instructionCompliance: number;
  readonly solutionPathCoverage: number;
  readonly candidateQuality: number;
  readonly baselineQuality: number;
  readonly qualityImpact: number;
}
export interface RetainedSkillSink { add(skill: DistilledSkill): void; }

export type SkillEvaluationResult =
  | {
      readonly verdict: "retained";
      readonly skill: DistilledSkill;
      readonly withSkill: SkillEvalArm;
      readonly baseline: SkillEvalArm;
      readonly delta: number;
      readonly criticism?: CriticismGateResult;
    }
  | {
      readonly verdict: "rejected-no-improvement" | "rolled-back-degradation" | "rejected-no-cases" | "rejected-invalid-cases" | "held-for-criticism";
      readonly skill: DistilledSkill;
      readonly withSkill: SkillEvalArm;
      readonly baseline: SkillEvalArm;
      readonly delta: number;
      readonly criticism?: CriticismGateResult;
    };

/**
 * Execution-adjudicated A/B gate for a candidate skill. The cases are supplied by the
 * caller as a held-out set; the candidate cannot generate or alter them. A candidate
 * is retained only when it strictly improves the same-case no-skill baseline.
 */
export class SkillEvaluator {
  constructor(
    private readonly oracle: ExecutionOracle,
    private readonly canary: SkillCanary,
    private readonly criticism?: BoundedCrossFamilyCriticism,
    private readonly retained?: RetainedSkillSink,
  ) {}

  evaluate(candidate: DistilledSkill, heldOutCases: readonly SkillCase[]): SkillEvaluationResult {
    if (heldOutCases.length === 0) {
      return {
        verdict: "rejected-no-cases",
        skill: candidate,
        withSkill: arm(0, 0),
        baseline: arm(0, 0),
        delta: 0,
      };
    }
    if (new Set(heldOutCases.map((testCase) => testCase.id)).size !== heldOutCases.length) {
      return { verdict: "rejected-invalid-cases", skill: candidate, withSkill: arm(0, heldOutCases.length), baseline: arm(0, heldOutCases.length), delta: 0 };
    }

    // Snapshot the case records before either arm runs so an oracle cannot change the
    // comparison population between the baseline and candidate executions.
    const cases = Object.freeze(heldOutCases.map((testCase) => Object.freeze({ ...testCase })));
    let baselinePassed = 0;
    let withSkillPassed = 0;
    for (const testCase of cases) {
      if (this.oracle.runBaseline(testCase)) baselinePassed++;
      if (this.oracle.runWithSkill(candidate, testCase)) withSkillPassed++;
    }

    const baseline = arm(baselinePassed, cases.length);
    const withSkill = arm(withSkillPassed, cases.length);
    const delta = withSkill.rate - baseline.rate;
    if (delta > 0) {
      const highImpact = candidate.requiredAuthority.includes("workspace:write") || candidate.requiredAuthority.includes("sandbox:execute");
      const criticism = this.criticism?.assess({
        proposalId: candidate.id,
        proposalKind: "skill",
        summary: `${candidate.name}: ${candidate.envelope.declaredEffects.join(", ")}`,
        execution: { baselineScore: baseline.rate, candidateScore: withSkill.rate, passed: true },
      }, highImpact);
      if (highImpact && (!criticism || criticism.status !== "cleared")) {
        return { verdict: "held-for-criticism", skill: candidate, withSkill, baseline, delta, ...(criticism ? { criticism } : {}) };
      }
      this.canary.goLive(candidate.id);
      this.retained?.add(candidate);
      return { verdict: "retained", skill: candidate, withSkill, baseline, delta, ...(criticism ? { criticism } : {}) };
    }

    if (delta < 0) {
      this.canary.forceRollback(candidate.id, `held-out execution regressed ${(Math.abs(delta) * 100).toFixed(1)} percentage points versus no-skill baseline`);
      return { verdict: "rolled-back-degradation", skill: candidate, withSkill, baseline, delta };
    }

    return { verdict: "rejected-no-improvement", skill: candidate, withSkill, baseline, delta };
  }

  /** Read-only held-out diagnostic; it never retains, rejects, canaries, or rolls back a skill. */
  diagnose(candidate: DistilledSkill, heldOutCases: readonly SkillDiagnosticCase[], oracle: SkillDiagnosticOracle): SkillDiagnosticProfile {
    if (heldOutCases.length === 0) throw new Error("skill diagnostic requires a non-empty held-out denominator");
    if (new Set(heldOutCases.map((testCase) => testCase.id)).size !== heldOutCases.length) throw new Error("skill diagnostic case ids must be unique");
    let triggered = 0; let correctTriggers = 0;
    let instructionRequired = 0; let instructionFollowed = 0;
    let pathRequired = 0; let pathCovered = 0;
    let candidateQuality = 0; let baselineQuality = 0;
    const cases = heldOutCases.map((value) => Object.freeze({ ...value, requiredInstructions: Object.freeze([...value.requiredInstructions]), requiredSolutionPath: Object.freeze([...value.requiredSolutionPath]) }));
    for (const testCase of cases) {
      const withSkill = oracle.run(candidate, testCase);
      const baseline = oracle.run(undefined, testCase);
      for (const observation of [withSkill, baseline]) if (!Number.isFinite(observation.quality) || observation.quality < 0 || observation.quality > 1) throw new RangeError("diagnostic quality must be within [0,1]");
      if (withSkill.triggered) { triggered++; if (testCase.shouldTrigger) correctTriggers++; }
      if (testCase.shouldTrigger) {
        instructionRequired += testCase.requiredInstructions.length;
        instructionFollowed += testCase.requiredInstructions.filter((item) => withSkill.followedInstructions.includes(item)).length;
        pathRequired += testCase.requiredSolutionPath.length;
        pathCovered += testCase.requiredSolutionPath.filter((item) => withSkill.solutionPath.includes(item)).length;
      }
      candidateQuality += withSkill.quality;
      baselineQuality += baseline.quality;
    }
    candidateQuality /= heldOutCases.length;
    baselineQuality /= heldOutCases.length;
    return Object.freeze({
      cases: heldOutCases.length,
      triggerPrecision: triggered === 0 ? 0 : correctTriggers / triggered,
      instructionCompliance: instructionRequired === 0 ? 1 : instructionFollowed / instructionRequired,
      solutionPathCoverage: pathRequired === 0 ? 1 : pathCovered / pathRequired,
      candidateQuality,
      baselineQuality,
      qualityImpact: candidateQuality - baselineQuality,
    });
  }
}

function arm(passed: number, total: number): SkillEvalArm {
  return { passed, total, rate: total === 0 ? 0 : passed / total };
}
