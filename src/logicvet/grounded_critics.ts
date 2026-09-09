/**
 * Grounded partial critics + single-model selective verification (Increment 3.8b).
 *
 * SOTA basis (re-verified 2026-08-04): sound external verification works, but LLM critics that
 * share a model share blind spots — "consensus is NOT faithfulness" (SAVeR arXiv 2604.08401;
 * preprints.org: correlated generator/evaluator errors make self-evaluation non-identifying). So:
 *  - The premise-grounding critic checks each load-bearing claim traces to a REAL source. This is
 *    partly deterministic (is there a citation/fact/constraint attached?) and partly generative
 *    (does the source actually support the claim?).
 *  - With MULTIPLE independent models, an independent critic can judge support.
 *  - With ONE model, it degrades to PAG/ReVeal SELECTIVE self-verification: the single model may
 *    FLAG a concern for the human (higher bar, lighter touch) but never BLESSES its own plan as
 *    sound on fuzzy dimensions — "LLMs lack reliable self-judgment." Sound (deterministic) critics
 *    still gate hard; the fuzzy critics only ever raise `concern`, never authoritative `block`.
 *
 * Zero deps.
 */

import type { Plan, PlanStep, CriticVerdict } from "./deterministic_critics.js";

/** A grounding source a claim can trace to. */
export interface GroundingSource {
  readonly kind: "citation" | "measured-fact" | "user-constraint";
  readonly ref: string;
}

/** A load-bearing claim in the plan + its (optional) grounding. */
export interface Claim {
  readonly stepId: string;
  readonly text: string;
  readonly grounding?: GroundingSource;
}

/**
 * A generative support-checker seam (an independent critic model). Given a claim + its source,
 * returns whether the source supports the claim. Injected; in single-model mode this is the same
 * model wearing a verifier hat (selective self-verification), which can only downgrade to concern.
 */
export type SupportChecker = (claim: Claim) => { supported: boolean; reason: string };

export interface GroundingOptions {
  /** True when at least one INDEPENDENT model (different family) is available as critic. */
  readonly independentCriticAvailable: boolean;
  readonly checker?: SupportChecker;
}

/**
 * Premise-grounding critic. Deterministic part: every load-bearing claim must HAVE a grounding
 * source (ungrounded premises are flagged — this part is sound). Generative part: if a checker is
 * present, verify the source supports the claim.
 *
 * Independence rule (the SAVeR fix): a generative "unsupported" judgement can only `block` when the
 * critic is INDEPENDENT of the author. In single-model mode it degrades to `concern` (flag for
 * human), never an authoritative block — the model cannot bless/condemn its own plan on fuzzy
 * grounds. Missing-grounding (the deterministic part) can still `concern` regardless.
 */
export function premiseGroundingCritic(claims: readonly Claim[], opts: GroundingOptions): CriticVerdict {
  const ungrounded = claims.filter((c) => !c.grounding);
  const implicated = ungrounded.map((c) => c.stepId);

  // Generative support check (only if a checker is present)
  const unsupported: string[] = [];
  if (opts.checker) {
    for (const claim of claims) {
      if (!claim.grounding) continue; // ungrounded handled above
      const r = opts.checker(claim);
      if (!r.supported) unsupported.push(`step ${claim.stepId}: ${r.reason}`);
    }
  }

  if (ungrounded.length === 0 && unsupported.length === 0) {
    return { critic: "premise-grounding", status: "pass", reason: "all load-bearing claims grounded and supported", implicated: [], sound: false };
  }

  const reasons: string[] = [];
  if (ungrounded.length > 0) reasons.push(`ungrounded claim(s): ${ungrounded.map((c) => c.stepId).join(", ")}`);
  if (unsupported.length > 0) reasons.push(`unsupported by source: ${unsupported.join("; ")}`);

  // In multi-model mode with an independent critic finding UNSUPPORTED claims, this is a strong
  // signal → block. Otherwise (single-model, or only missing-grounding), it's a concern to flag.
  const status: CriticVerdict["status"] =
    opts.independentCriticAvailable && unsupported.length > 0 ? "block" : "concern";

  return {
    critic: "premise-grounding",
    status,
    reason: reasons.join("; ") + (status === "concern" ? " (flagged for human; single-model verification does not bless/condemn on fuzzy grounds)" : ""),
    implicated,
    sound: false, // NEVER sound — a fuzzy critic; deterministic critics are the hard gate
  };
}

/** Extract load-bearing claims from a plan (steps that assert facts or make grounding-worthy statements). */
export function claimsFromPlan(plan: Plan, grounding: ReadonlyMap<string, GroundingSource> = new Map()): Claim[] {
  return plan.steps
    .filter((s: PlanStep) => (s.asserts?.length ?? 0) > 0 || /\b(because|assumes|requires|based on|since)\b/i.test(s.description))
    .map((s: PlanStep) => {
      const src = grounding.get(s.id);
      return src ? { stepId: s.id, text: s.description, grounding: src } : { stepId: s.id, text: s.description };
    });
}
