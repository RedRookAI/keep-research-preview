/**
 * M6 — THE CLOSED SELF-IMPROVEMENT LOOP. The individual primitives already exist: `decideTraining` (the SOTA decision
 * tree), the `SkillDistiller` (self-skill authorship), `ShadowModeGate` (verify-before-promote), and the revert path.
 * What was missing is the autonomous cycle that SEQUENCES them: recognize a measured gap → plan the narrowest fix →
 * implement it behind shadow-mode → verify before promotion. This is that cycle, and nothing more — it composes the
 * primitives; it invents no new training or rollback engine.
 *
 * SAFETY (cardinal): every improvement ships behind the shadow-mode gate and is only promoted on a clean evaluation —
 * a bad self-improvement is caught and reverted, never promoted (the Shadow-Alignment guard: "a few bad examples undo
 * safety"). OFF BY DEFAULT: the n=1 floor never has autonomous self-improvement forced on. HONEST: real weight training
 * is a SEAM (S-10, operator-authorized compute) — the loop makes the decision and STAGES it; it never trains silently.
 */

import { decideTraining, type TrainingSignals, type TrainingDecision, type TrainingDecisionOptions } from "../autotrain/training_decision.js";
import type { ShadowModeGate } from "./shadow_mode.js";

export type PlannedAction = "author-skill" | "stage-training" | "gradient-free";

export interface SelfImprovementDeps {
  /** OFF by default. The n=1 floor never has autonomous self-improvement forced on; an org opts in on a schedule. */
  readonly enabled?: boolean;
  /** The verify-before-promote guard (held-out CAPABILITY regression corpus). Composed, not re-implemented. */
  readonly shadow: ShadowModeGate;
  /**
   * MANDATORY SAFETY-REGRESSION gate (2026 cardinal): a second ShadowModeGate over a SAFETY corpus (refusals/guardrails).
   * Because test-time / self-directed training can UNDERMINE existing safety guardrails (arXiv 2605.22984 — 95% ASR@10;
   * degradation even on benign data; method-agnostic across fine-tune/LoRA/distill), no artifact promotes without passing
   * it. It is checked FIRST and its verdict is FINAL — a capability pass NEVER overrides a safety regression.
   */
  readonly safety?: ShadowModeGate;
  readonly decideOpts?: TrainingDecisionOptions;
  /** The planned gradient-free improvement to shadow-test before promotion (a distilled skill / lesson). */
  readonly candidate?: { readonly id: string; readonly content: string };
}

export interface SelfImprovementOutcome {
  /** False when the loop is disabled (off by default) — it did not run. */
  readonly ran: boolean;
  /** Did a real, measured capability gap get recognized? */
  readonly recognizedGap: boolean;
  readonly plannedAction?: PlannedAction;
  readonly decision?: TrainingDecision;
  /** Did an improvement get implemented (submitted to the shadow gate)? */
  readonly implemented: boolean;
  /** Promoted only after a clean shadow verification. */
  readonly promoted: boolean;
  /** Caught by shadow verification and reverted (never promoted). */
  readonly reverted: boolean;
  /** CARDINAL: the candidate regressed the SAFETY corpus (refusals/guardrails) → blocked from promotion, always. */
  readonly safetyRegressed: boolean;
  /** Training was warranted → STAGED for operator-authorized compute (seam S-10); never executed here. */
  readonly stagedTrainingOnly: boolean;
  readonly rationale: string;
}

function off(): SelfImprovementOutcome {
  return { ran: false, recognizedGap: false, implemented: false, promoted: false, reverted: false, safetyRegressed: false, stagedTrainingOnly: false, rationale: "self-improvement loop disabled (off by default — the n=1 floor is never forced on)" };
}

/**
 * Run one closed self-improvement cycle. Recognize → plan → implement → verify, composing `decideTraining` + the
 * shadow gate. Returns a fully-audited outcome; performs no real training (that is staged for the operator).
 */
export function runSelfImprovementCycle(signals: TrainingSignals, deps: SelfImprovementDeps): SelfImprovementOutcome {
  // OFF BY DEFAULT — an org enables it on a schedule; a solo operator is never forced into autonomous self-modification.
  if (!deps.enabled) return off();

  // (1) RECOGNIZE — a real, measured capability gap (a recurring failure with residual failure after gradient-free).
  const recognizedGap = signals.recurringFailureMode && signals.residualFailureRate > 0;
  if (!recognizedGap) {
    return { ran: true, recognizedGap: false, implemented: false, promoted: false, reverted: false, safetyRegressed: false, stagedTrainingOnly: false, rationale: "no measured capability gap — nothing specific to improve" };
  }

  // (2) PLAN — the narrowest fix. decideTraining walks the SOTA decision tree and names the actual reason.
  const decision = decideTraining(signals, deps.decideOpts);

  // Real training is a SEAM: if training is warranted, STAGE it for operator-authorized compute (S-10). Never run here.
  if (decision.shouldTrain) {
    return { ran: true, recognizedGap: true, plannedAction: "stage-training", decision, implemented: false, promoted: false, reverted: false, safetyRegressed: false, stagedTrainingOnly: true, rationale: "training warranted (method: " + (decision.approach?.method ?? "tbd") + ") — STAGED for operator-authorized compute (seam S-10). MANDATORY: the staged artifact must PASS the safety-regression corpus before any operator promotion (method-agnostic — fine-tune/LoRA/distill all degrade safety); the loop never trains silently" };
  }

  // Otherwise the plan is a gradient-free improvement (author a skill / lesson). Needs a candidate to shadow-test.
  if (!deps.candidate) {
    return { ran: true, recognizedGap: true, plannedAction: "gradient-free", decision, implemented: false, promoted: false, reverted: false, safetyRegressed: false, stagedTrainingOnly: false, rationale: decision.alternative ?? "gradient-free remedy planned; no candidate supplied to implement this cycle" };
  }

  // (3) IMPLEMENT behind shadow-mode + (4) VERIFY.
  // CARDINAL: the SAFETY-regression gate runs FIRST and its verdict is FINAL. A candidate that regresses a refusal/
  // guardrail is reverted no matter how well it performs on capability — safety is never overridden by capability.
  if (deps.safety) {
    const safe = deps.safety.evaluate(deps.candidate.id, deps.candidate.content);
    if (!safe.passed) {
      return { ran: true, recognizedGap: true, plannedAction: "author-skill", decision, implemented: true, promoted: false, reverted: true, safetyRegressed: true, stagedTrainingOnly: false, rationale: `improvement REGRESSED the safety corpus (${safe.failedCases.length} guardrail/refusal case(s)) — BLOCKED from promotion and reverted; safety is cardinal and is never overridden by capability` };
    }
  }
  // Capability regression gate — promote ONLY on a clean evaluation; otherwise revert.
  const shadow = deps.shadow.evaluate(deps.candidate.id, deps.candidate.content);
  if (!shadow.passed) {
    return { ran: true, recognizedGap: true, plannedAction: "author-skill", decision, implemented: true, promoted: false, reverted: true, safetyRegressed: false, rationale: `improvement failed shadow verification (${shadow.failedCases.length} regression(s)) — reverted; the system is uncorrupted`, stagedTrainingOnly: false };
  }
  return { ran: true, recognizedGap: true, plannedAction: "author-skill", decision, implemented: true, promoted: true, reverted: false, safetyRegressed: false, stagedTrainingOnly: false, rationale: "improvement passed BOTH the safety-regression corpus and the capability shadow corpus — promoted" };
}
