/**
 * ComplexityClassifier + FirewallRouter (Increment 3.7b) — the budget lever, done right.
 *
 * SOTA basis (re-verified 2026-08-04):
 *  - Route to "the cheapest model that CLEARS a quality bar for the task type" — NOT the cheapest
 *    model (lushbinary; SurePrompts: "route to the cheapest tier that meets the bar on each task
 *    class"). Cheap-by-default is a real false economy: "push hard prompts to the small model and
 *    the savings evaporate into retries and escalations" (digitalapplied); in the cascade case
 *    total cost can EXCEED routing to the strong model first (OpenLegion).
 *  - FIREWALL routing (arXiv 2606.27457): block queries from reaching small models when predicted
 *    failure is too high — a named guard against the false economy.
 *  - Routing overhead is negligible (rule <1ms) vs inference (500-2000ms) — a classifier is free.
 *  - The objective is lowest EXPECTED TOTAL cost incl. retries (the GroundedEstimator models this).
 *
 * Single-model mode is first-class: with one model there's nothing to route BETWEEN, so the
 * firewall instead decides effort-up vs. self-consistency vs. HONEST human handoff (never silently
 * ship a low-confidence result because there's no fallback).
 *
 * Zero deps.
 */

import type { CapabilityTier } from "../frontdoor/capability_adaptive.js";
import type { TaskComplexity } from "./prompt_strategy.js";

/** Signals a classifier can use (rule-first; embedding/LLM seam for the ambiguous middle). */
export interface ComplexitySignals {
  readonly text: string;
  /** Optional caller hint (e.g. stage = "vet_plan") to bias classification. */
  readonly hint?: string;
}

/** A pluggable classifier seam (embedding/LLM) for cases the rules can't resolve confidently. */
export type ComplexityBackend = (signals: ComplexitySignals) => TaskComplexity | undefined;

/** Rule-first complexity classifier. Deterministic, zero-dep, ~microseconds. */
export class ComplexityClassifier {
  constructor(private readonly backend?: ComplexityBackend) {}

  classify(signals: ComplexitySignals): { complexity: TaskComplexity; confident: boolean } {
    const t = signals.text.toLowerCase();
    const len = signals.text.length;
    const words = signals.text.split(/\s+/).filter(Boolean).length;

    // Strong signals of genuine complexity
    const complexKeywords =
      /\b(architect|design|prove|derive|optimize|refactor|migrate|debug|reconcile|synthesize|multi-step|trade-?off|end-to-end|from scratch)\b/;
    const trivialKeywords = /\b(list|rename|format|capitalize|echo|convert|lookup|yes\/no|classify)\b/;
    const multipart = (t.match(/\band\b|\bthen\b|;|\n-|\n\d\./g) ?? []).length;

    let complexity: TaskComplexity;
    let confident = true;

    if (complexKeywords.test(t) || words > 200 || multipart >= 4) {
      complexity = "complex";
    } else if (trivialKeywords.test(t) && words < 20) {
      complexity = "trivial";
    } else if (words < 40 && multipart <= 1) {
      complexity = "simple";
    } else {
      // the ambiguous middle — defer to the backend seam if present
      complexity = "moderate";
      confident = false;
    }

    if (!confident && this.backend) {
      const backendCall = this.backend(signals);
      if (backendCall) return { complexity: backendCall, confident: true };
    }
    return { complexity, confident };
  }
}

/** A candidate model to route among. */
export interface RouteCandidate {
  readonly id: string;
  readonly tier: CapabilityTier;
  /** Relative cost weight (higher = pricier). Used only to pick cheapest-that-clears. */
  readonly costWeight: number;
}

/** Predicts a candidate's success probability on a task shape (measured-history seam). */
export type SuccessPredictor = (candidateId: string, complexity: TaskComplexity) => number;

/** The routing decision. */
export type RouteDecision =
  | { kind: "route"; candidateId: string; reason: string }
  | { kind: "single-model"; action: "effort-up" | "self-consistency" | "human-handoff"; reason: string };

/** Minimum tier that can clear a complexity bar (the "quality bar" per task class). */
const MIN_TIER_FOR: Record<TaskComplexity, number> = { trivial: 0, simple: 0, moderate: 1, complex: 2 };
const TIER_RANK: Record<CapabilityTier, number> = { minimal: 0, lean: 1, standard: 2, rich: 3 };

export class FirewallRouter {
  /**
   * @param successThreshold below this predicted success, the firewall blocks a candidate.
   */
  constructor(
    private readonly predictor: SuccessPredictor,
    private readonly successThreshold = 0.6,
  ) {}

  /**
   * Choose the cheapest candidate that (a) meets the minimum tier for the complexity AND (b) clears
   * the firewall's predicted-success threshold. If none qualify, escalate to the most capable
   * available. With a single candidate, returns a single-model action instead of routing.
   */
  route(candidates: readonly RouteCandidate[], complexity: TaskComplexity): RouteDecision {
    if (candidates.length === 0) {
      return { kind: "single-model", action: "human-handoff", reason: "no model available" };
    }

    if (candidates.length === 1) {
      const only = candidates[0]!;
      const p = this.predictor(only.id, complexity);
      if (p >= this.successThreshold) {
        // one model that can handle it: raise effort for harder tasks, else run as-is
        return {
          kind: "single-model",
          action: complexity === "complex" || complexity === "moderate" ? "effort-up" : "effort-up",
          reason: `single model, predicted success ${p.toFixed(2)} ≥ ${this.successThreshold}`,
        };
      }
      // one model that likely can't: self-consistency buys accuracy; if still too low, human.
      if (p >= this.successThreshold - 0.2) {
        return { kind: "single-model", action: "self-consistency", reason: `single model marginal (${p.toFixed(2)}); sample-and-vote` };
      }
      return {
        kind: "single-model",
        action: "human-handoff",
        reason: `single model below bar (${p.toFixed(2)}); honest handoff, never silent low-confidence ship`,
      };
    }

    const minRank = MIN_TIER_FOR[complexity];
    // eligible = meets tier floor AND clears firewall
    const eligible = candidates
      .filter((c) => TIER_RANK[c.tier] >= minRank)
      .filter((c) => this.predictor(c.id, complexity) >= this.successThreshold)
      .sort((a, b) => a.costWeight - b.costWeight); // cheapest first among those that CLEAR the bar

    if (eligible.length > 0) {
      const pick = eligible[0]!;
      return {
        kind: "route",
        candidateId: pick.id,
        reason: `cheapest candidate clearing the ${complexity} bar (tier ${pick.tier}, success ≥ ${this.successThreshold})`,
      };
    }

    // firewall blocked everything cheap → escalate to the most capable available
    const strongest = [...candidates].sort((a, b) => TIER_RANK[b.tier] - TIER_RANK[a.tier])[0]!;
    return {
      kind: "route",
      candidateId: strongest.id,
      reason: `firewall blocked cheaper models (predicted failure); escalated to strongest (${strongest.tier}) to avoid retry false-economy`,
    };
  }
}
