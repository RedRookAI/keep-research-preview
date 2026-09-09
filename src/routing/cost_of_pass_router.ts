/**
 * Adaptive per-model prompting + COST-OF-PASS routing (theme 1 — the reliability-weighted budget lever).
 *
 * The operator's insight, and the SOTA metric (FrugalGPT/RouteLLM + cost-of-pass, Mahmood/Erol et al.):
 * NEVER cheap-for-cheap. The honest unit is COST-OF-PASS = inference cost ÷ P(success in that pass) — a
 * cheap model that needs several tries is more expensive than a pricier reliable one. So routing minimizes
 * cost-of-pass, not raw price. Two more SOTA pieces: PROMPT ADAPTATION (tailor the prompt to the model) and
 * POST-RESPONSE ESCALATION (get a cheap answer, vet it, escalate on vet-failure — beats blind upfront
 * routing). And the accessibility requirement: the operator's chosen model is a CEILING (raise-only) — the
 * policy may pick CHEAPER only when cost-of-pass predicts success; it may never exceed the operator's ceiling.
 *
 * This GENERALIZES the v1 quality-bar router (`src/observability/routing.ts::routeTask`): a quality BAR is a
 * crude proxy; cost-of-pass reliability-weights expected cost. This module is the principled core; the v1
 * router is left intact (consolidation is a follow-up).
 *
 * BUILT vs SEAM: BUILT + proven in-env is the SELECTION + ACCOUNTING + PROMPT-ASSEMBLY logic (deterministic,
 * inspectable). SEAM: the actual model calls, and a LEARNED router/success-predictor behind the same
 * interface (the in-env estimator is a transparent scoring function the operator can read and tune).
 *
 * DESIGN GUARDRAIL (industry-leading, not a proxy): pure cost-of-pass minimization has a known failure — a
 * "lottery-ticket" cheap model with near-zero success can show a deceptively low cost-of-pass. So a
 * RELIABILITY FLOOR (`minSuccess`) is the "predicted to succeed" gate: a model below it is ineligible
 * regardless of price. Savings are MEASURED on the operator's workload, never promised.
 */

import { eligibleByPolicy } from "./uncertainty_router.js";
import { selectStrategy, type PromptStrategy, type PromptEffortLevel } from "../prompt/prompt_strategy.js";
import type { CapabilityTier } from "../frontdoor/capability_adaptive.js";
import type { EffortKnob } from "../reference/reference_registry.js";

export type ComplexityBand = "trivial" | "easy" | "moderate" | "hard";
const BAND_ORDER: readonly ComplexityBand[] = ["trivial", "easy", "moderate", "hard"];

export type PromptFormat = "xml" | "markdown" | "terse" | "json";

export interface ModelProfile {
  readonly model: string;
  /** Provider is explicit so routing remains provider-agnostic. Defaults to the model id for older profiles. */
  readonly provider?: string;
  /** The prompt format this model performs best with (per-model adaptation). */
  readonly promptFormat: PromptFormat;
  /** Blended price signal (USD per typical task). */
  readonly usdPerTask: number;
  /** Conservative pre-call reservation. Required when a hard budget is enforced; averages are not hard bounds. */
  readonly maxCallCostUsd?: number;
  /** Capability tier (higher = stronger); the escalation + ceiling ordering. */
  readonly tier: number;
  /** MEASURED clean-success rate per complexity band, 0..1. `undefined` for a band = unknown ⇒ fail-safe. */
  readonly successByBand: Partial<Record<ComplexityBand, number>>;
  /** Capability metadata used to select the model's real effort knob. */
  readonly capabilityTier?: CapabilityTier;
  readonly effortKnob?: EffortKnob;
  readonly timeoutClass?: "standard" | "reasoning";
}

/** Transparent structural signals for complexity — inspectable, not a black box. */
export interface TaskSignal {
  readonly inputSize: number; // chars/tokens
  readonly subGoalCount: number; // decomposition breadth
  readonly reversibilityClass: "reversible" | "irreversible" | "unknown";
  readonly priorFailures: number; // times this task already failed
}

export interface RouterPolicy {
  readonly allowedModels: readonly string[];
  /** The operator's chosen model = the CEILING (raise-only): nothing above this tier may be routed to. */
  readonly operatorCeilingModel: string;
  /** The reliability floor — a model below this measured success at the band is not "predicted to succeed". */
  readonly minSuccess: number;
  /** Optional hard ceiling for the predicted cost of a successful pass. */
  readonly maxCostOfPassUsd?: number;
  /** Stateful atomic reservation gate. A route must reserve its full max-call cost before it is returned. */
  readonly hardBudget?: HardRouteBudget;
  /** Exact provider control requested by the caller. Knob-kind mismatch is refused, never approximated. */
  readonly requestedEffortControl?: PromptStrategy["effortApplication"];
}

export interface HardRouteBudgetSnapshot {
  readonly capUsd: number;
  readonly measuredSpentUsd: number;
  readonly reservedUsd: number;
}
export interface HardRouteBudget {
  snapshot(): HardRouteBudgetSnapshot;
  tryReserve(maxCostUsd: number): { readonly accepted: true; readonly reservationId: string; readonly measuredSpendBeforeUsd: number } | { readonly accepted: false };
  settle(reservationId: string, measuredActualUsd: number): { readonly overrunUsd: number };
  cancel(reservationId: string): void;
}

/** In-process hard gate: synchronous reservations serialize competing routes before any provider call starts. */
export class MeasuredHardRouteBudget implements HardRouteBudget {
  readonly #reservations = new Map<string, number>();
  #measuredSpentUsd: number;
  #sequence = 0;
  constructor(readonly capUsd: number, measuredSpentUsd = 0) {
    if (!Number.isFinite(capUsd) || capUsd < 0 || !Number.isFinite(measuredSpentUsd) || measuredSpentUsd < 0 || measuredSpentUsd > capUsd) throw new Error("invalid hard route budget");
    this.#measuredSpentUsd = measuredSpentUsd;
  }
  snapshot(): HardRouteBudgetSnapshot {
    return { capUsd: this.capUsd, measuredSpentUsd: this.#measuredSpentUsd, reservedUsd: [...this.#reservations.values()].reduce((sum, value) => sum + value, 0) };
  }
  tryReserve(maxCostUsd: number) {
    if (!Number.isFinite(maxCostUsd) || maxCostUsd < 0) return { accepted: false as const };
    const before = this.snapshot();
    if (before.measuredSpentUsd + before.reservedUsd + maxCostUsd > before.capUsd) return { accepted: false as const };
    const reservationId = `route-budget:${++this.#sequence}`;
    this.#reservations.set(reservationId, maxCostUsd);
    return { accepted: true as const, reservationId, measuredSpendBeforeUsd: before.measuredSpentUsd };
  }
  settle(reservationId: string, measuredActualUsd: number): { readonly overrunUsd: number } {
    const reserved = this.#reservations.get(reservationId);
    if (reserved === undefined) throw new Error("unknown route budget reservation");
    if (!Number.isFinite(measuredActualUsd) || measuredActualUsd < 0) throw new Error("invalid measured route cost");
    this.#reservations.delete(reservationId);
    this.#measuredSpentUsd += measuredActualUsd;
    return { overrunUsd: Math.max(0, measuredActualUsd - reserved) };
  }
  cancel(reservationId: string): void {
    if (!this.#reservations.delete(reservationId)) throw new Error("unknown route budget reservation");
  }
}

export type RouteChoice =
  | { readonly kind: "model"; readonly model: string; readonly costOfPass: number; readonly reason: string }
  | { readonly kind: "escalate-human"; readonly reason: string };

/** COST-OF-PASS = usd ÷ P(success at this band). Unknown success ⇒ Infinity (fail-safe: never preferred). */
export function costOfPass(profile: ModelProfile, band: ComplexityBand): number {
  const p = profile.successByBand[band];
  if (p === undefined || p <= 0) return Infinity; // unknown or never-succeeds ⇒ not a real option
  return profile.usdPerTask / p;
}

/** Transparent complexity estimate — a readable scoring function, not a learned model (that's the SEAM). */
export function estimateComplexity(sig: TaskSignal): ComplexityBand {
  let score = 0;
  if (sig.inputSize > 8000) score += 2;
  else if (sig.inputSize > 2000) score += 1;
  if (sig.subGoalCount >= 5) score += 2;
  else if (sig.subGoalCount >= 2) score += 1;
  if (sig.reversibilityClass === "irreversible") score += 2; // irreversible ⇒ treat as harder (more care)
  else if (sig.reversibilityClass === "unknown") score += 1; // fail-safe: unknown ⇒ lean harder
  if (sig.priorFailures > 0) score += Math.min(sig.priorFailures, 2); // failed before ⇒ harder
  if (score >= 5) return "hard";
  if (score >= 3) return "moderate";
  if (score >= 1) return "easy";
  return "trivial";
}

/** Deterministic per-model prompt assembly: format per the profile; more scaffolding for harder bands. */
export function assemblePrompt(task: string, profile: ModelProfile, band: ComplexityBand): string {
  const scaffold = band === "hard" || band === "moderate";
  const steps = scaffold ? "\nThink step by step and state assumptions." : "";
  switch (profile.promptFormat) {
    case "xml":
      return `<task>${task.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")}</task>${scaffold ? "\n<guidance>step-by-step; state assumptions</guidance>" : ""}`;
    case "json":
      return JSON.stringify({ task, guidance: scaffold ? "step-by-step; state assumptions" : undefined });
    case "terse":
      return task; // terse models: no scaffolding noise
    case "markdown":
    default:
      return `## Task\n${task}${steps}`;
  }
}

function tierOf(model: string, profiles: readonly ModelProfile[]): number | undefined {
  return profiles.find((p) => p.model === model)?.tier;
}

function supportsEffort(profile: ModelProfile, requested: RouterPolicy["requestedEffortControl"]): boolean {
  if (!requested || requested.kind === "none") return true;
  return profile.effortKnob === requested.kind;
}

function fitsHardBudget(profile: ModelProfile, budget: RouterPolicy["hardBudget"]): boolean {
  if (!budget) return true;
  const state = budget.snapshot();
  const reservation = profile.maxCallCostUsd;
  return reservation !== undefined && Number.isFinite(reservation) && reservation >= 0
    && state.measuredSpentUsd + state.reservedUsd + reservation <= state.capUsd;
}

/**
 * Choose the minimum-cost-of-pass model that is (a) allowed, (b) AT OR BELOW the operator's ceiling tier
 * (raise-only — never exceed the operator's choice), and (c) predicted to succeed (measured success ≥
 * minSuccess at this band — the reliability floor). If none qualifies, escalate to a human. Fail-safe: an
 * unknown/undefined success (Infinity cost-of-pass, or below the floor) makes a model ineligible.
 */
function chooseModelCandidate(
  band: ComplexityBand,
  profiles: readonly ModelProfile[],
  policy: RouterPolicy,
): RouteChoice {
  const ceilingTier = tierOf(policy.operatorCeilingModel, profiles);
  if (ceilingTier === undefined) return { kind: "escalate-human", reason: "unknown-operator-ceiling" }; // fail-safe

  // Eligibility delegates to the single authoritative core gate (a point estimate is the degenerate-posterior
  // mean; the reliability floor is the reversible-consequence floor). Selection (argmin cost-of-pass) stays here.
  const eligibleModels = new Set(
    eligibleByPolicy(
      profiles.map((p) => ({ model: p.model, tier: p.tier, estimate: p.successByBand[band] ?? 0 })),
      policy.minSuccess,
      ceilingTier,
      policy.allowedModels,
    ).map((i) => i.model),
  );
  const eligible = profiles.filter((p) => eligibleModels.has(p.model)
    && fitsHardBudget(p, policy.hardBudget)
    && supportsEffort(p, policy.requestedEffortControl)
    && Number.isFinite(costOfPass(p, band))
    && costOfPass(p, band) <= (policy.maxCostOfPassUsd ?? Infinity));
  if (eligible.length === 0) {
    return { kind: "escalate-human", reason: `no allowed model at/below ceiling predicted to succeed at ${band}` };
  }
  // minimize cost-of-pass; tie-break by lower tier (cheaper capability) then name for determinism.
  const chosen = [...eligible].sort((a, b) => {
    const ca = costOfPass(a, band);
    const cb = costOfPass(b, band);
    if (ca !== cb) return ca - cb;
    if (a.tier !== b.tier) return a.tier - b.tier;
    return a.model < b.model ? -1 : 1;
  })[0]!;
  return {
    kind: "model",
    model: chosen.model,
    costOfPass: costOfPass(chosen, band),
    reason: `min cost-of-pass at/below the operator ceiling, above the ${policy.minSuccess} reliability floor`,
  };
}

export function chooseModel(
  band: ComplexityBand,
  profiles: readonly ModelProfile[],
  policy: RouterPolicy,
): RouteChoice {
  if (policy.hardBudget || (policy.requestedEffortControl !== undefined && policy.requestedEffortControl.kind !== "none")) {
    return { kind: "escalate-human", reason: "hard budget or explicit effort control requires chooseBudgetAwareRoute" };
  }
  return chooseModelCandidate(band, profiles, policy);
}

export interface BudgetAwareRoute {
  readonly kind: "route";
  readonly provider: string;
  readonly model: string;
  readonly band: ComplexityBand;
  readonly predictedCostOfPassUsd: number;
  /** Worst-case amount reserved against the hard cap before execution; null when no hard cap was requested. */
  readonly reservedCostUsd: number | null;
  readonly measuredSpendBeforeUsd: number | null;
  readonly budgetReservationId: string | null;
  readonly strategy: PromptStrategy;
}

/**
 * Join provider/model selection with the capability-detected effort strategy. This is also the one-provider
 * floor: with a single eligible profile, complexity still changes effort even though provider/model cannot move.
 */
export function chooseBudgetAwareRoute(
  task: TaskSignal,
  profiles: readonly ModelProfile[],
  policy: RouterPolicy,
): BudgetAwareRoute | Extract<RouteChoice, { kind: "escalate-human" }> {
  const band = estimateComplexity(task);
  const choice = chooseModelCandidate(band, profiles, policy);
  if (choice.kind !== "model") return choice;
  const profile = profiles.find((p) => p.model === choice.model)!;
  const complexity = band === "easy" ? "simple" : band === "hard" ? "complex" : band;
  const baseStrategy = selectStrategy({
    tier: profile.capabilityTier ?? (profile.tier >= 3 ? "rich" : profile.tier === 2 ? "standard" : "lean"),
    effortKnob: profile.effortKnob ?? "none",
    timeoutClass: profile.timeoutClass ?? "standard",
  }, complexity);
  const requested = policy.requestedEffortControl;
  const requestedLevel: PromptEffortLevel = requested?.kind === "graded" ? requested.level
    : requested?.kind === "binary" ? (requested.thinking ? "high" : "none")
    : baseStrategy.effort;
  const strategy = requested ? { ...baseStrategy, effort: requestedLevel, effortApplication: requested } : baseStrategy;
  const reservation = policy.hardBudget?.tryReserve(profile.maxCallCostUsd!);
  if (reservation && !reservation.accepted) return { kind: "escalate-human", reason: "hard budget changed before route reservation; no call authorized" };
  return {
    kind: "route",
    provider: profile.provider ?? profile.model,
    model: profile.model,
    band,
    predictedCostOfPassUsd: choice.costOfPass,
    reservedCostUsd: policy.hardBudget ? profile.maxCallCostUsd! : null,
    measuredSpendBeforeUsd: reservation?.accepted ? reservation.measuredSpendBeforeUsd : null,
    budgetReservationId: reservation?.accepted ? reservation.reservationId : null,
    strategy,
  };
}

/**
 * POST-RESPONSE escalation: on a vet-failure of `currentModel`, escalate to the next-STRONGER allowed model
 * that is still AT OR BELOW the operator's ceiling. If the current model is already the ceiling (or none
 * stronger qualifies), escalate to a human — never past the operator's choice.
 */
export function escalateOnVetFailure(
  currentModel: string,
  band: ComplexityBand,
  profiles: readonly ModelProfile[],
  policy: RouterPolicy,
): RouteChoice {
  const ceilingTier = tierOf(policy.operatorCeilingModel, profiles);
  const curTier = tierOf(currentModel, profiles);
  if (ceilingTier === undefined || curTier === undefined) return { kind: "escalate-human", reason: "unknown-model-or-ceiling" };
  const stronger = profiles
    .filter((p) => policy.allowedModels.includes(p.model) && p.tier > curTier && p.tier <= ceilingTier && (p.successByBand[band] ?? 0) >= policy.minSuccess)
    .sort((a, b) => a.tier - b.tier)[0];
  if (stronger === undefined) return { kind: "escalate-human", reason: "reached the operator ceiling; no stronger model permitted" };
  return { kind: "model", model: stronger.model, costOfPass: costOfPass(stronger, band), reason: "post-response escalation to the next stronger model below the ceiling" };
}

/**
 * Cost-of-pass ACCOUNTING: update a profile's measured success at a band from a recorded outcome (EWMA), so
 * the estimator improves with use — in-env accounting, not a learned black box. Pure/superseding: returns a
 * new profile (the old record is not mutated). `alpha` weights the new observation.
 */
export function recordOutcome(profile: ModelProfile, band: ComplexityBand, success: boolean, alpha = 0.2): ModelProfile {
  const prior = profile.successByBand[band] ?? 0.5; // unseen band starts neutral
  const updated = (1 - alpha) * prior + alpha * (success ? 1 : 0);
  return { ...profile, successByBand: { ...profile.successByBand, [band]: updated } };
}

export interface MeasuredRoutingOutcome {
  readonly measurementId: string;
  readonly basis: "executed-task" | "held-out-eval";
  readonly success: boolean;
  readonly regressed: boolean;
}
export type RoutingUpdate =
  | { readonly kind: "updated"; readonly profile: ModelProfile }
  | { readonly kind: "rolled-back"; readonly profile: ModelProfile }
  | { readonly kind: "rejected"; readonly reason: string };

/** Stateful routing learner: accepts unique measured receipts only and retains the exact pre-update profile. */
export class MeasuredOutcomeRouter {
  readonly #profiles = new Map<string, ModelProfile>();
  readonly #prior = new Map<string, { readonly existed: boolean; readonly value?: number }>();
  readonly #seen = new Set<string>();
  constructor(profiles: readonly ModelProfile[]) {
    for (const profile of profiles) this.#profiles.set(profile.model, structuredClone(profile));
  }
  profiles(): readonly ModelProfile[] { return [...this.#profiles.values()].map((profile) => structuredClone(profile)); }
  record(model: string, band: ComplexityBand, outcome: MeasuredRoutingOutcome, alpha = 0.2): RoutingUpdate {
    if (typeof outcome.measurementId !== "string" || outcome.measurementId.trim() === "" || (outcome.basis !== "executed-task" && outcome.basis !== "held-out-eval")) {
      return { kind: "rejected", reason: "routing updates require identified execution or held-out measurements" };
    }
    if (this.#seen.has(outcome.measurementId)) return { kind: "rejected", reason: "duplicate routing measurement" };
    const current = this.#profiles.get(model);
    if (!current) return { kind: "rejected", reason: "unknown routed model" };
    if (!Number.isFinite(alpha) || alpha <= 0 || alpha > 1) return { kind: "rejected", reason: "invalid outcome weight" };
    if (this.#seen.size >= 100_000) return { kind: "rejected", reason: "routing measurement identity capacity exhausted" };
    const key = `${model}:${band}`;
    if (outcome.regressed) {
      const prior = this.#prior.get(key);
      if (!prior) return { kind: "rejected", reason: "no prior measured route exists to restore" };
      const successByBand = { ...current.successByBand };
      if (prior.existed) successByBand[band] = prior.value!;
      else delete successByBand[band];
      const restored = { ...current, successByBand };
      this.#profiles.set(model, restored);
      this.#prior.delete(key);
      this.#seen.add(outcome.measurementId);
      return { kind: "rolled-back", profile: structuredClone(restored) };
    }
    this.#prior.set(key, current.successByBand[band] === undefined ? { existed: false } : { existed: true, value: current.successByBand[band] });
    const updated = recordOutcome(current, band, outcome.success, alpha);
    this.#profiles.set(model, updated);
    this.#seen.add(outcome.measurementId);
    return { kind: "updated", profile: structuredClone(updated) };
  }
}

export { BAND_ORDER };
