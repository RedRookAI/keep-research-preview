/**
 * Combines candidate patterns, anticipation decisions and a success posterior into suggestions.
 *
 * New patterns begin with a Beta(1,1) prior. Consequential suggestions use a lower confidence bound;
 * acceptance and decline update the posterior. Predictions carry a rationale and never execute actions.
 * The caller supplies patterns grounded in task context and recurring goals.
 */

import { anticipate, type CandidateNeed, type Disposition } from "./anticipation.js";
import {
  type SuccessPosterior,
  type ConsequenceClass,
  decisionSuccess,
  updatePosterior,
} from "../routing/uncertainty_router.js";

/** A candidate for what the user likely wants next (grounded upstream in M2 retrieval / recurring goals). */
export interface PredictionPattern {
  readonly id: string;
  readonly description: string;
  /** The consequence of acting on this prediction (drives pessimism + gating). */
  readonly consequence: ConsequenceClass;
  /** The probationary belief that this is genuinely what they want (starts at the uniform prior). */
  readonly confidence: SuccessPosterior;
  readonly utility: number;
  readonly interruptionCost: number;
  /** An un-vettable candidate is never surfaced. Default true. */
  readonly vettable?: boolean;
}

export interface Prediction {
  readonly pattern: PredictionPattern;
  readonly disposition: Disposition;
  /** Consequence-scaled success estimate (LCB where consequential) — the probationary confidence used to rank. */
  readonly successEstimate: number;
  readonly confidence: SuccessPosterior;
  readonly rationale: string;
  /** Structural: the predictor NEVER executes; it only proposes. Always false. */
  readonly autoExecuted: false;
}

export interface PredictContext {
  readonly candidates: readonly PredictionPattern[];
}

/**
 * Map the ConsequenceClass vocabulary to anticipate's (reversible | consequential). Irreversible AND unknown both
 * map to `consequential` — never auto-surfaced (precautionary; an unknown-consequence prediction is not assumed safe).
 */
function toAnticipateConsequence(c: ConsequenceClass): "reversible" | "consequential" {
  return c === "reversible" ? "reversible" : "consequential";
}

/**
 * Propose the single best next-need prediction, or null if nothing clears. Composes `anticipate` for the
 * disposition and `decisionSuccess` for the probationary, consequence-scaled confidence. Never returns an action.
 */
export function predictNextNeed(ctx: PredictContext): Prediction | null {
  let best: Prediction | null = null;
  let bestScore = -Infinity;
  for (const p of ctx.candidates) {
    const candidate: CandidateNeed = {
      description: p.description,
      utility: p.utility,
      interruptionCost: p.interruptionCost,
      consequence: toAnticipateConsequence(p.consequence),
      vettable: p.vettable ?? true,
      confidence: p.confidence,
    };
    const decision = anticipate(candidate);
    // Exploration-preserving: a silent disposition is not a prediction to offer — skip, never force it forward.
    if (decision.disposition === "stay-silent") continue;

    const successEstimate = decisionSuccess(p.confidence, p.consequence); // LCB where consequential (pessimism)
    const rationale = `${decision.reason}; success≈${successEstimate.toFixed(2)} (belief ${p.confidence.alpha}/${p.confidence.beta})`;
    const pred: Prediction = {
      pattern: p,
      disposition: decision.disposition,
      successEstimate,
      confidence: p.confidence,
      rationale,
      autoExecuted: false,
    };
    // Rank by probationary confidence × net benefit — an unproven pattern (low LCB) can't outrank a proven one.
    const score = successEstimate * (p.utility - p.interruptionCost);
    if (score > bestScore) {
      bestScore = score;
      best = pred;
    }
  }
  return best;
}

/**
 * Record the outcome of a surfaced/offered prediction to update its probationary belief. Accepted ⇒ the pattern
 * earns confidence; declined (overridden) ⇒ the belief drops and the pattern must re-earn it. Decay < 1 down-weights
 * stale evidence (non-stationarity — needs change).
 */
export function recordPredictionOutcome(confidence: SuccessPosterior, accepted: boolean, decay = 1): SuccessPosterior {
  return updatePosterior(confidence, accepted, decay);
}
