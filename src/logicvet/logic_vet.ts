/**
 * LogicVet panel + rabbit-hole guard (Increment 3.8d) — the orchestrator.
 *
 * SOTA basis (2026-08-04): a panel of grounded partial critics with consensus (arXiv 2402.08115),
 * where SOUND deterministic critics gate and correlated LLM critics only flag (SAVeR arXiv
 * 2604.08401). Rabbit-hole guard = the Self-Verification Dilemma (arXiv 2602.03485): suppress
 * redundant RECHECK (re-verifying already-passed unchanged steps), permit RETHINK (revising a
 * flagged step). The panel runs ONCE per plan version and, on re-entry, only re-vets CHANGED steps
 * — so the vetting itself stays bounded and logical, never its own rabbit hole.
 *
 * Single-model failsafe (§9): the deterministic critics are the author-independent gate and run
 * with zero models; the generative grounding check uses checkHeterogeneous (NEVER throws) so a
 * one-key operator gets full-strength sound vetting + a flag-only generative cross-check.
 *
 * Zero deps.
 */

import {
  deterministicCritics,
  type Plan,
  type PlanConstraints,
  type CriticVerdict,
} from "./deterministic_critics.js";
import {
  premiseGroundingCritic,
  claimsFromPlan,
  type GroundingOptions,
  type GroundingSource,
} from "./grounded_critics.js";
import { consensus, postureForTaskShape, type VetVerdict, type VetPosture } from "./consensus.js";
import { checkHeterogeneous, type Authorship } from "../review/heterogeneous.js";

/** Inputs to a logic-vet pass. */
export interface LogicVetRequest {
  readonly plan: Plan;
  readonly constraints: PlanConstraints;
  readonly taskShape: string; // drives posture (creative → permissive, build → strict)
  readonly grounding?: ReadonlyMap<string, GroundingSource>;
  readonly author?: Authorship;
  readonly reviewer?: Authorship;
  readonly checker?: GroundingOptions["checker"];
  /** Posture override (else derived from taskShape). */
  readonly posture?: VetPosture;
}

/** A completed vet pass, with the full audit trail. */
export interface LogicVetResult {
  readonly verdict: VetVerdict;
  readonly critics: readonly CriticVerdict[];
  readonly singleModel: boolean;
  readonly note: string;
}

export class LogicVet {
  /** Remembers, per plan-version signature, which step ids already passed (recheck suppression). */
  private readonly passedSteps = new Map<string, Set<string>>();

  /**
   * Vet a plan (the `vet_plan` stage). Runs the deterministic critics (always, zero models) + the
   * grounded premise critic (generative check only flags in single-model mode). Consensus with the
   * task-appropriate posture. Records the audit trail.
   */
  vetPlan(req: LogicVetRequest): LogicVetResult {
    const posture = req.posture ?? postureForTaskShape(req.taskShape);

    // Heterogeneity is checked WITHOUT throwing — single-model must not error (§9.1 fix).
    const het =
      req.author && req.reviewer ? checkHeterogeneous(req.author, req.reviewer) : { independent: false, singleModel: true, reason: "no reviewer configured — single-model" };

    const critics: CriticVerdict[] = [...deterministicCritics(req.plan, req.constraints)];

    // grounded premise critic: independent critic can block; single-model only flags
    const claims = claimsFromPlan(req.plan, req.grounding ?? new Map());
    if (claims.length > 0) {
      const groundingOpts: GroundingOptions = {
        independentCriticAvailable: het.independent,
        ...(req.checker ? { checker: req.checker } : {}),
      };
      critics.push(premiseGroundingCritic(claims, groundingOpts));
    }

    const verdict = consensus(critics, posture);
    const note = het.singleModel
      ? "single-model mode: deterministic critics gate at full strength; generative cross-check flags only (add a free independent model — e.g. Gemini/Groq/OpenRouter — to strengthen)"
      : het.independent
        ? "multi-model: independent critic active"
        : "same-family reviewer: treated as a weak signal";

    return { verdict, critics, singleModel: het.singleModel, note };
  }

  /**
   * Vet a produced artifact (the `vet_artifact` stage), re-running only the CHANGED steps
   * (recheck suppression — the rabbit-hole guard). `changedStepIds` names what actually changed
   * since the last pass; unchanged, already-passed steps are NOT re-vetted.
   */
  vetArtifact(
    req: LogicVetRequest,
    planVersionKey: string,
    changedStepIds: readonly string[],
  ): LogicVetResult {
    const already = this.passedSteps.get(planVersionKey) ?? new Set<string>();
    // Restrict the plan to changed (or not-yet-passed) steps — don't recheck settled ones.
    const changed = new Set(changedStepIds);
    const stepsToVet = req.plan.steps.filter((s) => changed.has(s.id) || !already.has(s.id));

    if (stepsToVet.length === 0) {
      // Everything already passed and nothing changed → no recheck (bounded, per the dilemma).
      return {
        verdict: { decision: "pass", posture: req.posture ?? postureForTaskShape(req.taskShape), reason: "no changed steps — recheck suppressed (rabbit-hole guard)", blocking: [], concerns: [], reworkTargets: [] },
        critics: [],
        singleModel: !(req.author && req.reviewer && checkHeterogeneous(req.author, req.reviewer).independent),
        note: "recheck suppressed: only changed steps are re-vetted",
      };
    }

    const subReq: LogicVetRequest = { ...req, plan: { goal: req.plan.goal, steps: stepsToVet } };
    const result = this.vetPlan(subReq);

    // On pass, remember these steps as settled for this plan version.
    if (result.verdict.decision === "pass") {
      for (const s of stepsToVet) already.add(s.id);
      this.passedSteps.set(planVersionKey, already);
    }
    return result;
  }

  /** Reset the recheck-suppression memory (e.g. on a new plan version / major rethink). */
  resetMemory(planVersionKey?: string): void {
    if (planVersionKey) this.passedSteps.delete(planVersionKey);
    else this.passedSteps.clear();
  }
}
