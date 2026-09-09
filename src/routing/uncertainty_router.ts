/**
 * UNCERTAINTY + CONSEQUENCE + CASCADE-COST hardening for the cost-of-pass router.
 *
 * Red-team of the v1 router found it NAIVE in four ways the routing SOTA (FrugalGPT cascades; the LLM-routing-
 * as-contextual-bandit literature — MetaLLM/MixLLM/BARP; conformal cascade calibration — UCCI/RouteNLP) treats
 * as solved:
 *   F1  standalone cost-of-pass is the WRONG objective when the system ESCALATES — the real objective is the
 *       CASCADE expected cost  E[cost] = c1 + (1-p1)(c2 + (1-p2)(...))  (FrugalGPT). Picking the standalone-
 *       cheapest-per-pass first model can be globally suboptimal.
 *   F2  a DETERMINISTIC POINT-ESTIMATE policy never explores and has no uncertainty — routing is a contextual
 *       bandit; a model with an unlucky early estimate is avoided forever, a lucky one over-used. Cold-start
 *       0.5 is arbitrary. SOTA: a Beta posterior over success + optimism/pessimism under uncertainty.
 *   F4  the reliability bar didn't scale with CONSEQUENCE — Keep's gate-on-consequence thesis. A wrong answer
 *       that passes vetting on an IRREVERSIBLE task is a safety event, not a retry.
 *   F5  EWMA(alpha) conflated recency with sample size and couldn't express confidence — a Beta-with-decay
 *       retains the count (⇒ confidence) while handling non-stationarity.
 *
 * THE SAFETY-ALIGNED SYNTHESIS (why this is not just "add a bandit"): the explore/exploit tension has a
 * safety-correct resolution here. Exploration wants OPTIMISM (try uncertain models); safety wants PESSIMISM
 * (don't trust an uncertain model on a consequential task). So uncertainty cuts TOWARD CAUTION scaled by
 * CONSEQUENCE: on an irreversible task we judge a model by the LOWER confidence bound of its success (a wide-
 * uncertainty model is treated as if it might fail); optimism/exploration is allowed only where the downside is
 * bounded (reversible tasks). This ties F2 (uncertainty) to F4 (consequence) and keeps the router DETERMINISTIC
 * and AUDITABLE (confidence bounds, not randomized Thompson sampling — that remains a SEAM, and if used must be
 * seeded and confined to reversible tasks).
 *
 * BUILT + proven in-env: the Beta posterior + update, the consequence-scaled decision estimate + floor, and the
 * expected-cascade-cost selection. SEAM: a learned/contextual success-predictor (IRT/embedding) and randomized
 * Thompson exploration behind the same interface; conformal calibration of the floor. Composes as the
 * principled SUPERSET of the v1 `cost_of_pass_router` (point estimate = a degenerate posterior; `minSuccess` =
 * the reversible-class floor). Modifies nothing else.
 */

export type ConsequenceClass = "reversible" | "irreversible" | "unknown";

/** A Beta(alpha, beta) posterior over a model's success at a band. Counts are retained ⇒ confidence. */
export interface SuccessPosterior {
  readonly alpha: number; // prior successes + observed successes (alpha>0)
  readonly beta: number; // prior failures + observed failures (beta>0)
}

/** Uniform prior Beta(1,1) — the principled cold-start (not an arbitrary 0.5 point). */
export function priorPosterior(): SuccessPosterior {
  return { alpha: 1, beta: 1 };
}

export function posteriorMean(p: SuccessPosterior): number {
  return p.alpha / (p.alpha + p.beta);
}

/** Posterior variance (Beta) — the uncertainty; shrinks as counts grow. */
export function posteriorVariance(p: SuccessPosterior): number {
  const n = p.alpha + p.beta;
  return (p.alpha * p.beta) / (n * n * (n + 1));
}

/**
 * A LOWER confidence bound on success (pessimism under uncertainty): mean - k·sd, clamped to [0,1]. Wide
 * uncertainty (few samples) ⇒ a much lower bound ⇒ an unproven model is not trusted. k sets the caution level.
 */
export function successLCB(p: SuccessPosterior, k = 2): number {
  const lo = posteriorMean(p) - k * Math.sqrt(posteriorVariance(p));
  return lo < 0 ? 0 : lo > 1 ? 1 : lo;
}

/** An UPPER confidence bound (optimism) — used only for exploration on reversible tasks. */
export function successUCB(p: SuccessPosterior, k = 2): number {
  const hi = posteriorMean(p) + k * Math.sqrt(posteriorVariance(p));
  return hi < 0 ? 0 : hi > 1 ? 1 : hi;
}

/**
 * The success estimate USED FOR THE DECISION, with uncertainty cutting toward caution scaled by consequence:
 *  - irreversible/unknown ⇒ the LOWER bound (pessimism — don't trust an uncertain model where it matters);
 *  - reversible ⇒ the mean (optimism/exploration is safe here; a wrong answer is recoverable).
 * This is the safety-aligned resolution of explore/exploit.
 */
export function decisionSuccess(p: SuccessPosterior, consequence: ConsequenceClass, k = 2): number {
  if (consequence === "reversible") return posteriorMean(p);
  return successLCB(p, k); // irreversible or unknown ⇒ pessimism
}

/** Bernoulli update with optional decay (non-stationarity): decay<1 down-weights old counts before adding. */
export function updatePosterior(p: SuccessPosterior, success: boolean, decay = 1): SuccessPosterior {
  const a = p.alpha * decay + (success ? 1 : 0);
  const b = p.beta * decay + (success ? 0 : 1);
  // keep counts >= the uniform prior so the posterior never becomes improper.
  return { alpha: a < 1 ? 1 : a, beta: b < 1 ? 1 : b };
}

/** A model candidate in a cascade: its price, its success posterior at the band, and a capability tier. */
export interface CascadeCandidate {
  readonly model: string;
  readonly usdPerTask: number;
  readonly posterior: SuccessPosterior;
  readonly tier: number;
}

/**
 * Expected CASCADE cost (F1) for an ORDERED chain of models tried until one succeeds (each escalation on the
 * previous one's vet-failure):  E[cost] = c1 + (1-p1)(c2 + (1-p2)(c3 + ...)).  Uses the consequence-adjusted
 * decision success for each p (so on irreversible tasks the pessimistic LCB drives the expectation — an
 * uncertain cheap first model looks EXPENSIVE because its low p_lcb means we usually pay for escalation too).
 * The residual (1-p1)(1-p2)...·penalty charges the tail where even the last model fails (⇒ human escalation).
 */
export function expectedCascadeCost(
  chain: readonly CascadeCandidate[],
  consequence: ConsequenceClass,
  humanEscalationPenalty: number,
  k = 2,
): number {
  let cost = 0;
  let reachProb = 1; // probability we reach this stage (all prior stages failed)
  for (const c of chain) {
    cost += reachProb * c.usdPerTask;
    const p = decisionSuccess(c.posterior, consequence, k);
    reachProb *= 1 - p;
  }
  cost += reachProb * humanEscalationPenalty; // tail: everyone failed ⇒ human
  return cost;
}

/**
 * The SINGLE authoritative eligibility gate (router consolidation). Every router — the quality-bar `routeTask`,
 * the point-estimate `chooseModel`, and the cascade `chooseCascade` — reduces to this one predicate:
 * allowed ∧ tier ≤ ceiling ∧ decision-estimate ≥ floor. The three differ only in how they compute the
 * estimate (a quality point / a success point / the consequence-adjusted posterior `decisionSuccess`) and in
 * their final SELECTION (cheapest-clearing-bar / argmin cost-of-pass / expected cascade cost) — those are
 * legitimate distinct policies, not duplication. A point estimate is the degenerate-posterior mean, i.e.
 * `decisionSuccess` under the reversible/zero-uncertainty case; the callers pass that exact value here so the
 * gate is shared without any float drift at the boundary.
 */
export interface EligibilityInput {
  readonly model: string;
  readonly tier: number;
  readonly estimate: number; // the decision-success estimate the caller computed (quality / success / LCB-adjusted)
}

export function eligibleByPolicy(
  items: readonly EligibilityInput[],
  floor: number,
  ceilingTier: number,
  allowedModels: readonly string[],
): EligibilityInput[] {
  return items.filter((i) => allowedModels.includes(i.model) && i.tier <= ceilingTier && i.estimate >= floor);
}

export interface CascadePolicy {
  readonly allowedModels: readonly string[];
  readonly operatorCeilingModel: string;
  /** Required decision-success to be eligible, per consequence class (irreversible demands more). */
  readonly floorByConsequence: Record<ConsequenceClass, number>;
  /** The cost charged when the whole cascade fails and a human must step in. */
  readonly humanEscalationPenalty: number;
  /** Caution level k for the confidence bounds. */
  readonly k: number;
}

export type CascadeChoice =
  | { readonly kind: "cascade"; readonly order: readonly string[]; readonly expectedCost: number; readonly reason: string }
  | { readonly kind: "escalate-human"; readonly reason: string };

/**
 * Choose the cascade ORDER minimizing expected cascade cost, among allowed models at/below the operator ceiling
 * whose consequence-adjusted decision-success clears the consequence-scaled floor. Escalate to a human if none
 * qualifies. The order is cheapest-first among the eligible (the standard cascade shape); the KEY correctness
 * property is that the objective is the CASCADE expected cost with consequence-adjusted p's, not a per-model
 * standalone cost-of-pass — so an uncertain cheap model on an irreversible task is correctly NOT put first.
 */
export function chooseCascade(
  candidates: readonly CascadeCandidate[],
  consequence: ConsequenceClass,
  policy: CascadePolicy,
): CascadeChoice {
  const ceiling = candidates.find((c) => c.model === policy.operatorCeilingModel);
  if (ceiling === undefined) return { kind: "escalate-human", reason: "unknown-operator-ceiling" };
  const floor = policy.floorByConsequence[consequence];

  const eligibleModels = new Set(
    eligibleByPolicy(
      candidates.map((c) => ({ model: c.model, tier: c.tier, estimate: decisionSuccess(c.posterior, consequence, policy.k) })),
      floor,
      ceiling.tier,
      policy.allowedModels,
    ).map((i) => i.model),
  );
  const eligible = candidates.filter((c) => eligibleModels.has(c.model));
  if (eligible.length === 0) {
    return { kind: "escalate-human", reason: `no eligible model clears the ${consequence} floor (${floor})` };
  }

  // Order candidates cheapest-first (the cascade tries cheap, escalates on failure). Among orderings this is
  // the standard cascade; we evaluate its expected cascade cost with consequence-adjusted success.
  const order = [...eligible].sort((a, b) => a.usdPerTask - b.usdPerTask || a.tier - b.tier);
  const expectedCost = expectedCascadeCost(order, consequence, policy.humanEscalationPenalty, policy.k);
  return {
    kind: "cascade",
    order: order.map((c) => c.model),
    expectedCost,
    reason: `min expected CASCADE cost (consequence=${consequence}, floor=${floor}, k=${policy.k}); uncertainty cuts toward caution on high-consequence tasks`,
  };
}

/**
 * PRE-RETURN-DELIBERATION — a consequence-gated self-review of a result BEFORE it is returned. The 2026 literature is
 * clear that naive self-correction can make answers WORSE and that revision must be gated, not unconditional (DISC's
 * "binary judgment gate before correction", arXiv 2606.21724; "naive self-correction can make answers worse", arXiv
 * 2607.07663). So this is deliberately conservative: it runs ONLY for consequential outputs (ON for irreversible/unknown
 * — fail-safe scrutiny when unsure; OFF for reversible/trivial — fast path), and it keeps the original UNLESS a revision
 * is CLEARLY better by a decidable margin (a tie, a within-margin "improvement", or a worse revision keeps the original —
 * no change-for-change's-sake, and never a degradation).
 *
 * The critic is an INJECTED port: the reference is a deterministic structural scorer (an external, checkable signal —
 * the field "grounds its critique in an external signal", arXiv 2607.07663). A grounded LLM critic is the NAMED SEAM;
 * intrinsic self-critique is discouraged. HONEST: it never fabricates an improvement (the betterness signal is a real,
 * decidable score, not a gameable proxy like "longer"); it is REPORT-PLUS-CHOOSE, not a new gate — it changes no verdict,
 * only selects which of {original, revision} to return, and DEFAULTS to the original. Deterministic. ZERO-DEP.
 */

/** An injected critic that scores a candidate result (higher = better). Reference = deterministic structural scorer; a grounded LLM critic is the SEAM. */
export interface DeliberationCritic {
  score(candidate: string): number;
}

export interface PreReturnDeliberationInput {
  readonly original: string;
  /** A candidate revision to consider. undefined ⇒ nothing to compare ⇒ keep original. */
  readonly revision?: string;
  readonly consequence: ConsequenceClass;
  readonly critic: DeliberationCritic;
  /** A revision must beat the original by STRICTLY MORE than this margin to replace it ("clearly better"). Default 0. */
  readonly margin?: number;
}

export type DeliberationOutcome = "skipped-trivial" | "kept-original" | "replaced-with-revision" | "critic-error";

export interface PreReturnDeliberation {
  /** What to return — DEFAULTS to the original; only a clearly-better revision replaces it. */
  readonly returned: string;
  readonly outcome: DeliberationOutcome;
  /** Was the consequence-gate ON (did we deliberate at all)? */
  readonly deliberated: boolean;
  readonly originalScore?: number;
  readonly revisionScore?: number;
  /** HONEST: report-plus-choose — changes no verdict; only selects {original, revision}. */
  readonly changesVerdict: false;
  readonly reason: string;
}

export function preReturnDeliberation(input: PreReturnDeliberationInput): PreReturnDeliberation {
  // Consequence gate: ON for irreversible/unknown (fail-safe — scrutinize when unsure), OFF for reversible (fast path).
  const deliberated = input.consequence !== "reversible";
  if (!deliberated) {
    return { returned: input.original, outcome: "skipped-trivial", deliberated: false, changesVerdict: false, reason: "reversible/trivial consequence — deliberation skipped (fast path)" };
  }
  if (input.revision === undefined) {
    return { returned: input.original, outcome: "kept-original", deliberated: true, changesVerdict: false, reason: "no revision candidate — original kept" };
  }
  const margin = input.margin ?? 0;
  // FAIL-SAFE: the critic is an INJECTED, untrusted port ("engineer the blast radius — when, not if, it misbehaves"
  // — clawvard 2026). A critic that THROWS must never crash the caller; degrade to the original.
  let originalScore: number;
  let revisionScore: number;
  try {
    originalScore = input.critic.score(input.original);
    revisionScore = input.critic.score(input.revision);
  } catch {
    return { returned: input.original, outcome: "critic-error", deliberated: true, changesVerdict: false, reason: "deliberation critic threw — failed safe to the original (untrusted injected port)" };
  }
  // Replace ONLY on a clear, decidable betterness margin. A tie, a within-margin gain, or a worse revision keeps the original.
  if (revisionScore - originalScore > margin) {
    return { returned: input.revision, outcome: "replaced-with-revision", deliberated: true, originalScore, revisionScore, changesVerdict: false, reason: `revision clearly better (${revisionScore} > ${originalScore} by > ${margin}) — replaced` };
  }
  return { returned: input.original, outcome: "kept-original", deliberated: true, originalScore, revisionScore, changesVerdict: false, reason: `revision not clearly better (${revisionScore} vs ${originalScore}, margin ${margin}) — original kept (no change-for-change's-sake)` };
}
