/**
 * The LOGIC / PLAN-VETTING layer (theme 3 of the in-env extraction — the highest-value piece).
 *
 * Keep's effect-gate (`composeGate`) vets one EFFECT with deterministic external critics. This layer lifts
 * that pattern ONE LEVEL UP: it vets the AI's proposed PLAN — its order of operations, goal alignment,
 * proportionality, and non-regression — BEFORE any effect is attempted. It composes ABOVE the solver's plan
 * and BELOW the effect-gate: a plan clears the logic-critics, then each of its effects clears the gate.
 *
 * WHY (SOTA, 2026 — Kambhampati LLM-Modulo): auto-regressive LLMs CANNOT reliably self-verify —
 * self-critique WORSENS performance and degrades as more self-critique rounds are added (high false-negative
 * rate as their own verifier). The fix is EXTERNAL, SOUND critics; the LLM is an idea generator, not its own
 * judge. So — the LOAD-BEARING DESIGN RULE — every critic here is a DETERMINISTIC pure function, NEVER an LLM
 * critiquing the LLM. That is the only way to escape the self-verification false-negative trap.
 *
 * This directly answers the operator's worry: catch the AI's OWN illogical plans, rabbit-holes, and
 * over-reactions structurally, before bothering the human — routing to a human only when a critic cannot be
 * satisfied. It is the "maximal safe lift" enabler.
 *
 * BUILT vs SEAM: BUILT + proven in-env are the four deterministic critics + the deny-overrides composition.
 * A LEARNED goal/difficulty mapper (mapping a step to its goal-contribution, or estimating sub-problem value)
 * is a SEAM behind the critic interface — but the VERIFICATION stays deterministic.
 *
 * Mirrors `composeGate`: deny-overrides (any critic holds ⇒ the plan is held, ALL reasons collected, no
 * masking), monotone (a critic can only ADD a hold, never clear one), fail-safe (unknown prerequisite/goal
 * ⇒ hold). It does NOT modify the effect-gate, the floor, the fleet barriers, R11, the panel, or R25.
 */

import { evaluateResearchPlanningEligibility, type CrossFamilyResearchReview, type ResearchEligibilityContext, type TriResearchManifest } from "../research/tri_research_admission.js";
import { evaluateReviewYield, type VerifiedMeaningfulReviewPass } from "../discipline/review_policy.js";
import { types } from "node:util";

/** One step of a proposed plan. Undefined declared fields mean UNKNOWN ⇒ fail-safe (hold). */
export interface PlanStep {
  readonly id: string;
  /** Step ids that must complete before this one (the precedence edges). */
  readonly prerequisites: readonly string[];
  /** Which declared goal id this step advances. `undefined` = unknown ⇒ fail-safe. */
  readonly advancesGoal: string | undefined;
  /** Predicted cost of this step (same unit as `subProblemValue`). `undefined` = unknown ⇒ fail-safe. */
  readonly predictedCost: number | undefined;
  /** The value of the sub-problem this step addresses (proportionality denominator). */
  readonly subProblemValue: number | undefined;
  /** Committed, goal-serving step ids this step would undo (a regression), if any. */
  readonly undoes: readonly string[];
  /** A monotone progress measure toward the goal after this step (for rabbit-hole detection). */
  readonly progressAfter: number | undefined;
  /**
   * WORLD-MODEL fields (the state-simulation critic). `requires` = fact ids that must hold in the
   * SIMULATED state before this step runs; `establishes`/`deletes` = facts this step's effect adds/removes.
   * `undefined` requires ⇒ unknown ⇒ fail-safe. The effect-schema (what each step establishes/deletes) is
   * the MODEL — the SEAM, acquired offline and validated; the SIMULATION over it is deterministic + in-env.
   */
  readonly requires: readonly string[] | undefined;
  readonly establishes: readonly string[];
  readonly deletes: readonly string[];
}

export interface Plan {
  /** The declared goal ids this plan serves. */
  readonly goals: readonly string[];
  /** The ordered steps (index = execution order). */
  readonly steps: readonly PlanStep[];
  /** Committed, goal-serving step ids already done (non-regression baseline). */
  readonly committed: readonly string[];
  /** Facts true before the plan runs (the initial simulated state). */
  readonly initialState: readonly string[];
  /** Fact ids that must hold in the FINAL simulated state for the goal to be ACHIEVED. */
  readonly goalFacts: readonly string[];
  /** Exact research package for a policy-classified consequential plan. Never model-decided. */
  readonly researchPackage?: {
    readonly manifest: TriResearchManifest;
    readonly review: CrossFamilyResearchReview;
    readonly context: ResearchEligibilityContext;
  };
  /** Verifier-owned, candidate-bound review evidence. Structural eligibility never replaces deployment verification. */
  readonly reviewPasses?: readonly VerifiedMeaningfulReviewPass[];
}

export interface PlanPolicy {
  /** Max predictedCost / subProblemValue before a step is a disproportionate rabbit-hole. */
  readonly maxCostValueRatio: number;
  /** Max consecutive steps with no progress increase before it's a no-progress-loop rabbit-hole. */
  readonly maxNoProgressRun: number;
  /** Deterministic outer policy classification; the proposed plan cannot lower this requirement. */
  readonly researchRequirement: "not-required" | "structural-and-external";
  readonly reviewRequirement: "not-required" | "two-to-four-cross-family";
}

type CapturedPlanPolicy = {
  readonly maxCostValueRatio: number;
  readonly maxNoProgressRun: number;
  readonly researchRequirement: unknown;
  readonly reviewRequirement: unknown;
};

/** Capture caller-owned policy once; no accessor, Proxy, symbol, or extra-key evaluation is admissible. */
function capturePlanPolicy(input: unknown): CapturedPlanPolicy | null {
  if (input === null || typeof input !== "object" || Array.isArray(input) || types.isProxy(input)) return null;
  if (Object.getPrototypeOf(input) !== Object.prototype) return null;
  if (Object.getOwnPropertySymbols(input).length !== 0) return null;
  const descriptors = Object.getOwnPropertyDescriptors(input) as Record<string, PropertyDescriptor>;
  const expected = ["maxCostValueRatio", "maxNoProgressRun", "researchRequirement", "reviewRequirement"];
  if (Object.keys(descriptors).sort().join("\0") !== [...expected].sort().join("\0")) return null;
  for (const key of expected) {
    const descriptor = descriptors[key];
    if (!descriptor || descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true || !("value" in descriptor)) return null;
  }
  const maxCostValueRatio = descriptors.maxCostValueRatio!.value;
  const maxNoProgressRun = descriptors.maxNoProgressRun!.value;
  if (typeof maxCostValueRatio !== "number" || !Number.isFinite(maxCostValueRatio) || maxCostValueRatio <= 0) return null;
  if (!Number.isSafeInteger(maxNoProgressRun) || maxNoProgressRun < 1) return null;
  return { maxCostValueRatio, maxNoProgressRun, researchRequirement: descriptors.researchRequirement!.value, reviewRequirement: descriptors.reviewRequirement!.value };
}

function inertRecord(input: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> | null {
  if (input === null || typeof input !== "object" || Array.isArray(input) || types.isProxy(input)) return null;
  if (Object.getPrototypeOf(input) !== Object.prototype || Object.getOwnPropertySymbols(input).length !== 0) return null;
  const descriptors = Object.getOwnPropertyDescriptors(input) as Record<string, PropertyDescriptor>;
  const keys = Object.keys(descriptors).sort();
  if (required.some((key) => !keys.includes(key)) || keys.some((key) => !required.includes(key) && !optional.includes(key))) return null;
  const owned: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true || !("value" in descriptor)) return null;
    owned[key] = descriptor.value;
  }
  return owned;
}

function inertDenseArray(input: unknown): readonly unknown[] | null {
  if (types.isProxy(input) || !Array.isArray(input)) return null;
  const descriptors = Object.getOwnPropertyDescriptors(input) as Record<string, PropertyDescriptor>;
  if (Object.getOwnPropertySymbols(input).length !== 0) return null;
  const lengthDescriptor = descriptors.length;
  if (!lengthDescriptor || !("value" in lengthDescriptor) || !Number.isSafeInteger(lengthDescriptor.value) || lengthDescriptor.value < 0 || lengthDescriptor.value > 10_000) return null;
  const length = lengthDescriptor.value as number;
  const owned: unknown[] = new Array(length);
  const expected = new Set(["length", ...Array.from({ length }, (_, index) => String(index))]);
  if (Object.keys(descriptors).some((key) => !expected.has(key)) || Object.keys(descriptors).length !== expected.size) return null;
  for (let index = 0; index < length; index++) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true || !("value" in descriptor)) return null;
    owned[index] = descriptor.value;
  }
  return owned;
}

function stringArray(input: unknown): readonly string[] | null {
  const values = inertDenseArray(input);
  return values && values.every((value) => typeof value === "string") ? values as readonly string[] : null;
}

/** Snapshot the complete caller-owned plan shell before any critic observes it. */
function capturePlan(input: unknown): Plan | null {
  const row = inertRecord(input, ["goals", "steps", "committed", "initialState", "goalFacts"], ["researchPackage", "reviewPasses"]);
  if (!row) return null;
  const goals = stringArray(row.goals); const committed = stringArray(row.committed);
  const initialState = stringArray(row.initialState); const goalFacts = stringArray(row.goalFacts);
  const stepInputs = inertDenseArray(row.steps);
  if (!goals || !committed || !initialState || !goalFacts || !stepInputs) return null;
  const steps: PlanStep[] = [];
  for (const inputStep of stepInputs) {
    const step = inertRecord(inputStep, ["id", "prerequisites", "advancesGoal", "predictedCost", "subProblemValue", "undoes", "progressAfter", "requires", "establishes", "deletes"]);
    if (!step || typeof step.id !== "string") return null;
    const prerequisites = stringArray(step.prerequisites); const undoes = stringArray(step.undoes);
    const establishes = stringArray(step.establishes); const deletes = stringArray(step.deletes);
    const requires = step.requires === undefined ? undefined : stringArray(step.requires);
    if (!prerequisites || !undoes || !establishes || !deletes || (step.requires !== undefined && !requires)) return null;
    if (step.advancesGoal !== undefined && typeof step.advancesGoal !== "string") return null;
    for (const key of ["predictedCost", "subProblemValue", "progressAfter"] as const) if (step[key] !== undefined && (typeof step[key] !== "number" || !Number.isFinite(step[key]))) return null;
    steps.push({ id: step.id, prerequisites, advancesGoal: step.advancesGoal as string | undefined, predictedCost: step.predictedCost as number | undefined, subProblemValue: step.subProblemValue as number | undefined, undoes, progressAfter: step.progressAfter as number | undefined, requires: requires ?? undefined, establishes, deletes });
  }
  let researchPackage: Plan["researchPackage"];
  if ("researchPackage" in row) {
    const research = inertRecord(row.researchPackage, ["manifest", "review", "context"]);
    if (!research) return null;
    researchPackage = { manifest: research.manifest as TriResearchManifest, review: research.review as CrossFamilyResearchReview, context: research.context as ResearchEligibilityContext };
  }
  const reviewInputs = "reviewPasses" in row ? inertDenseArray(row.reviewPasses) : undefined;
  if ("reviewPasses" in row && !reviewInputs) return null;
  const reviewPasses = reviewInputs as readonly VerifiedMeaningfulReviewPass[] | undefined;
  return { goals, steps, committed, initialState, goalFacts, ...(researchPackage === undefined ? {} : { researchPackage }), ...(reviewPasses === undefined ? {} : { reviewPasses }) };
}

/** Deployment-owned verifier port. Keep does not hard-code a provider family; policy selects trusted adapters. */
export interface ResearchExternalVerifier {
  verify(input: { readonly manifestDigest: string; readonly review: CrossFamilyResearchReview }): { readonly verified: boolean; readonly reason: string };
}

export type PlanVerdict = {
  readonly proceed: boolean;
  /** Every reason the plan is held (empty iff it proceeds). No reason is masked. */
  readonly holds: readonly string[];
  /**
   * HARD holds are sound vetoes (schema + causal/precondition + goal-achievement + non-regression): a plan
   * proceeds only if there are NONE. SOFT holds are heuristic advisories (proportionality / rabbit-hole):
   * surfaced but NOT sound, so they do not by themselves veto (honest hard/soft stratification per LLM-Modulo).
   */
  readonly hardHolds: readonly string[];
  readonly softHolds: readonly string[];
};

// ---- the deterministic critics (pure) ----

/**
 * FORMAT/SCHEMA critic (takes precedence — a malformed plan makes every other critic meaningless).
 * A step is malformed if its id is empty or duplicated. HARD.
 */
export function schemaWellFormed(plan: Plan): string[] {
  const holds: string[] = [];
  const seen = new Set<string>();
  for (const s of plan.steps) {
    if (s.id.length === 0) holds.push("schema:empty-step-id");
    if (seen.has(s.id)) holds.push(`schema:duplicate-step-id:${s.id}`);
    seen.add(s.id);
  }
  return holds;
}

/**
 * STATE-SIMULATION critic (the world-model hard critic — the load-bearing SOTA safety component). Instead of
 * trusting the plan's DECLARED order, it SIMULATES: from the initial state, apply each step's effects and
 * check each step's preconditions actually HOLD in the simulated state, then check the goal facts hold in the
 * FINAL state (goal ACHIEVEMENT, not per-step tagging). This is isomorphic-w.r.t.-the-model: an internally
 * inconsistent plan (a step needing a fact nothing establishes) or a non-achieving plan is caught even when
 * its declarations are well-formed — far harder to game than an extensional check. HARD.
 * The effect-schema (establishes/deletes) is the MODEL/SEAM; the simulation over it is deterministic.
 */
export function stateSimulation(plan: Plan): string[] {
  const holds: string[] = [];
  const state = new Set(plan.initialState);
  for (const s of plan.steps) {
    if (s.requires === undefined) {
      holds.push(`sim:unknown-precondition:${s.id}`); // fail-safe
      continue;
    }
    for (const need of s.requires) {
      if (!state.has(need)) holds.push(`sim:unmet-precondition:${need}@${s.id}`);
    }
    for (const d of s.deletes) state.delete(d);
    for (const e of s.establishes) state.add(e);
  }
  // goal ACHIEVEMENT: every declared goal fact must hold in the final simulated state.
  for (const g of plan.goalFacts) {
    if (!state.has(g)) holds.push(`sim:goal-not-achieved:${g}`);
  }
  return holds;
}

/**
 * MODEL-GATED state simulation (R41): refuse to simulate against an unverified effect-model. The plan's
 * declared per-step effects are only trustworthy if they came from a model signed by a trusted key
 * (control-plane), not one the generator (data-plane) could forge or edit. `modelVerification` is the result
 * of `verifiedEffectModel(...)`. Fail-closed: an unverified model ⇒ a single hard-hold `sim:unattested-model`
 * and NO simulation (we do not trust the declarations enough to reason over them). A verified model ⇒ the
 * normal simulation runs. This closes R41's core: a tampered/unsigned model can no longer pass the sim critic.
 */
export function stateSimulationGated(
  plan: Plan,
  modelVerification: { readonly verified: boolean },
): string[] {
  if (modelVerification.verified !== true) return ["sim:unattested-model"]; // fail-closed
  return stateSimulation(plan);
}

/** Order-of-operations: a step scheduled before one of its prerequisites is illogical. (2.3 precedence.) */
export function orderOfOperations(plan: Plan): string[] {
  const holds: string[] = [];
  const positionById = new Map<string, number>();
  plan.steps.forEach((s, idx) => positionById.set(s.id, idx));
  plan.steps.forEach((s, idx) => {
    for (const pre of s.prerequisites) {
      const prePos = positionById.get(pre);
      // fail-safe: a prerequisite not present in the plan and not already committed ⇒ unknown ⇒ hold.
      if (prePos === undefined) {
        if (!plan.committed.includes(pre)) holds.push(`order:unknown-prereq:${pre}@${s.id}`);
        continue;
      }
      if (prePos >= idx) holds.push(`order:prereq-after-step:${pre}@${s.id}`);
    }
  });
  return holds;
}

/** Goal alignment: every step must advance a declared goal; an unaligned/unknown step is held. */
export function goalAlignment(plan: Plan): string[] {
  const holds: string[] = [];
  const goals = new Set(plan.goals);
  for (const s of plan.steps) {
    if (s.advancesGoal === undefined) {
      holds.push(`goal:unknown-contribution:${s.id}`); // fail-safe
    } else if (!goals.has(s.advancesGoal)) {
      holds.push(`goal:step-off-goal:${s.id}->${s.advancesGoal}`);
    }
  }
  return holds;
}

/** Proportionality: a step whose cost ≫ its sub-problem value (over-reaction), or a no-progress loop. */
export function proportionality(plan: Plan, policy: PlanPolicy): string[] {
  const holds: string[] = [];
  for (const s of plan.steps) {
    if (s.predictedCost === undefined || s.subProblemValue === undefined) {
      holds.push(`proportion:unknown-cost-or-value:${s.id}`); // fail-safe
      continue;
    }
    if (s.subProblemValue <= 0 || s.predictedCost / s.subProblemValue > policy.maxCostValueRatio) {
      holds.push(`proportion:disproportionate:${s.id}:${s.predictedCost}/${s.subProblemValue}`);
    }
  }
  // no-progress-loop (rabbit-hole): a run of steps with non-increasing progress longer than the policy allows.
  let run = 0;
  let prev = -Infinity;
  for (const s of plan.steps) {
    if (s.progressAfter === undefined) {
      holds.push(`proportion:unknown-progress:${s.id}`); // fail-safe
      prev = -Infinity;
      run = 0;
      continue;
    }
    if (s.progressAfter <= prev) {
      run++;
      if (run >= policy.maxNoProgressRun) holds.push(`proportion:no-progress-loop:${s.id}:run=${run}`);
    } else {
      run = 0;
    }
    prev = s.progressAfter;
  }
  return holds;
}

/** Non-regression: a step that undoes committed, goal-serving work is held. */
export function nonRegression(plan: Plan): string[] {
  const holds: string[] = [];
  const committed = new Set(plan.committed);
  for (const s of plan.steps) {
    for (const u of s.undoes) {
      if (committed.has(u)) holds.push(`regression:undoes-committed:${u}@${s.id}`);
    }
  }
  return holds;
}

/**
 * Compose the critics. Deny-overrides: the plan proceeds only if NO critic holds; otherwise it is held with
 * ALL reasons collected (no masking). Monotone toward caution; fail-safe on unknown declared fields.
 * The LLM is the GENERATOR of the plan; this function is the external, sound, DETERMINISTIC verifier.
 */
export function vetPlan(plan: Plan, policy: PlanPolicy, externalResearchVerifier?: ResearchExternalVerifier): PlanVerdict {
  // Capture policy first: no caller-owned plan accessor may mutate or downgrade it before admission.
  const capturedPolicy = capturePlanPolicy(policy);
  if (capturedPolicy === null) {
    const holds = ["policy:invalid-or-noninert"];
    return { proceed: false, holds, hardHolds: holds, softHolds: [] };
  }
  const capturedPlan = capturePlan(plan);
  if (capturedPlan === null) {
    const holds = ["plan:invalid-or-noninert"];
    return { proceed: false, holds, hardHolds: holds, softHolds: [] };
  }
  // FORMAT critic takes precedence: on a malformed plan, every other critic is meaningless — hard-hold now.
  const schema = schemaWellFormed(capturedPlan);
  if (schema.length > 0) {
    return { proceed: false, holds: schema, hardHolds: schema, softHolds: [] };
  }

  // HARD critics (sound vetoes): causal/precondition + goal-achievement (simulation), declared-order,
  // goal-alignment, non-regression, and the no-declared-goal fail-safe.
  const hardHolds: string[] = [
    ...stateSimulation(capturedPlan),
    ...orderOfOperations(capturedPlan),
    ...goalAlignment(capturedPlan),
    ...nonRegression(capturedPlan),
  ];
  if (capturedPlan.goals.length === 0) hardHolds.push("plan:no-declared-goal"); // fail-safe

  if (capturedPolicy.researchRequirement !== "not-required" && capturedPolicy.researchRequirement !== "structural-and-external") {
    hardHolds.push("research:unknown-policy-requirement");
  } else if (capturedPolicy.researchRequirement === "structural-and-external") {
    if (!capturedPlan.researchPackage) {
      hardHolds.push("research:package-required");
    } else {
      const eligibility = evaluateResearchPlanningEligibility(capturedPlan.researchPackage.manifest, capturedPlan.researchPackage.review, capturedPlan.researchPackage.context);
      if (!eligibility.readyForExternalVerification || eligibility.manifestDigest === null) {
        hardHolds.push(...eligibility.reasons.map((reason) => `research:structural:${reason}`));
      } else if (!externalResearchVerifier) {
        hardHolds.push("research:external-verifier-unavailable");
      } else {
        try {
          const verified = externalResearchVerifier.verify({ manifestDigest: eligibility.manifestDigest, review: capturedPlan.researchPackage.review });
          if (verified.verified !== true) hardHolds.push(`research:external-verification-failed:${verified.reason}`);
        } catch {
          hardHolds.push("research:external-verification-failed:verifier-error");
        }
      }
    }
  }

  if (capturedPolicy.reviewRequirement !== "not-required" && capturedPolicy.reviewRequirement !== "two-to-four-cross-family") {
    hardHolds.push("review:unknown-policy-requirement");
  } else if (capturedPolicy.reviewRequirement === "two-to-four-cross-family") {
    const reviewDecision = evaluateReviewYield(capturedPlan.reviewPasses ?? []);
    if (reviewDecision.status !== "eligible") hardHolds.push(`review:${reviewDecision.reason}`);
  }

  // SOFT critics (heuristic advisories — NOT sound; surfaced but do not by themselves veto).
  const softHolds: string[] = [...proportionality(capturedPlan, capturedPolicy as PlanPolicy)];

  // deny-overrides on HARD holds only; ALL reasons collected (no masking). proceed iff no hard hold.
  return {
    proceed: hardHolds.length === 0,
    holds: [...hardHolds, ...softHolds],
    hardHolds,
    softHolds,
  };
}
