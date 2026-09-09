/**
 * Auto-Training system: permission + explanation layer (Increment 11c).
 *
 * The system must ask the human "I'd like to train on X, for reason Y; it will involve Z; I need your
 * permission" WHEN the situation warrants — and proceed autonomously when it's SOTA-safe to do so
 * without over-bothering them. This layer decides which, and renders both the ask and the reasoning
 * in PLAIN LANGUAGE a non-engineer can follow — because "make AI training accessible to everyone who
 * isn't an engineer" is the whole point, and it all has to be auditable + explainable.
 *
 * Calibration principle (from the autonomy-calibration research already used in item 7): over-asking
 * is itself a failure. So a narrow, low-impact, verifiable run that a standing authorization already
 * covers can proceed; anything novel, higher-impact, first-of-its-kind, or outside the standing grant
 * asks first. Zero deps.
 */

import type { TrainingDecision } from "./training_decision.js";

export type PermissionMode = "autonomous" | "ask-permission" | "blocked";

export interface PermissionContext {
  /** Does a standing per-session/operator authorization already cover this class of run? */
  readonly standingAuthorization: boolean;
  /** Is this the FIRST time training this capability/base model (novel = ask)? */
  readonly firstOfItsKind: boolean;
  /** Estimated compute cost in USD (higher → ask). */
  readonly estimatedCostUsd: number;
  /** Would the trained adapter be auto-promoted past canary? (Never autonomous — always ask.) */
  readonly wouldAutoPromote: boolean;
  /** Cost threshold above which permission is always requested. Default set in options. */
}

export interface PermissionOptions {
  /** Cost ceiling for autonomous runs. Above this → ask. Default $2.00. */
  readonly autonomousCostCeiling?: number;
}

export interface PermissionDecision {
  readonly mode: PermissionMode;
  readonly reason: string;
}

/**
 * Decide whether a training run may proceed autonomously, must ask permission, or is blocked. Ordered
 * + conservative: a decision that isn't "train" is blocked here (nothing to run); promotion past
 * canary always asks; novelty / cost / no-standing-auth trigger an ask; otherwise a narrow verifiable
 * run under a standing grant proceeds autonomously.
 */
export function permissionFor(decision: TrainingDecision, ctx: PermissionContext, opts: PermissionOptions = {}): PermissionDecision {
  const ceiling = opts.autonomousCostCeiling ?? 2.0;

  if (!decision.shouldTrain) {
    return { mode: "blocked", reason: "the decision policy did not recommend training — nothing to run" };
  }
  // Promotion past a canary is never autonomous.
  if (ctx.wouldAutoPromote) {
    return { mode: "ask-permission", reason: "promoting a trained adapter past canary to full activation always requires explicit human approval" };
  }
  // First-of-its-kind → ask (establish the pattern with a human once).
  if (ctx.firstOfItsKind) {
    return { mode: "ask-permission", reason: "this is the first training run of its kind for this capability — asking so you can approve the pattern before it becomes routine" };
  }
  // No standing authorization → ask.
  if (!ctx.standingAuthorization) {
    return { mode: "ask-permission", reason: "no standing authorization covers this run — asking for explicit permission" };
  }
  // Cost above the autonomous ceiling → ask.
  if (ctx.estimatedCostUsd > ceiling) {
    return { mode: "ask-permission", reason: `estimated cost $${ctx.estimatedCostUsd.toFixed(2)} exceeds the autonomous ceiling $${ceiling.toFixed(2)} — asking first` };
  }
  // Narrow, verifiable, low-cost, covered by a standing grant, not a promotion → proceed.
  return { mode: "autonomous", reason: `covered by standing authorization, low cost ($${ctx.estimatedCostUsd.toFixed(2)}), a routine verifiable run — proceeding without interrupting you` };
}

/** The plain-language permission request shown to the operator. */
export interface PermissionRequest {
  readonly headline: string;
  readonly what: string;
  readonly why: string;
  readonly involves: string;
  readonly risksAndSafeguards: string;
  readonly ask: string;
}

/**
 * Build the "I'd like to train on X, for reason Y, it will involve Z, I need your permission" message
 * — in plain language, with the auditable basis. `what/why` come from the decision's own rationale.
 */
export function buildPermissionRequest(
  decision: TrainingDecision,
  details: { capability: string; baseModel: string; exampleCount: number; estimatedCostUsd: number; estimatedGainPct: number },
): PermissionRequest {
  return {
    headline: `Permission to train a small specialized adapter for: ${details.capability}`,
    what: `I'd like to train a narrow adapter on ${details.exampleCount} verified examples to improve how I handle "${details.capability}".`,
    why: decision.rationale,
    involves: `This will run a small, sandboxed training job on a copy of ${details.baseModel} (nothing leaves your machine unless you've set that up). It won't touch the base model — it makes a separate, removable adapter. Estimated cost: about $${details.estimatedCostUsd.toFixed(2)}. Expected improvement: about ${details.estimatedGainPct}% on this specific task.`,
    risksAndSafeguards: `Safeguards: it trains only against an automatic success check (so it can't learn the wrong thing), keeps some general practice data mixed in (so it doesn't forget other skills), and is watched for "gaming the metric" during training. Before anything is used, it must pass before/after safety and capability checks, and a combined-safety check with any other adapters. It ships as a trial ("canary") first, with one-tap undo, and I'll never fully activate it without your say-so.`,
    ask: `May I go ahead and train this adapter? (yes / no / tell me more)`,
  };
}

/** Render any training decision (train or not) as a short plain-language explanation. */
export function explainTrainingDecision(decision: TrainingDecision): string {
  if (decision.shouldTrain) {
    return `Decision: TRAIN. ${decision.rationale}`;
  }
  const alt = decision.alternative ? ` Instead: ${decision.alternative}.` : "";
  return `Decision: don't train (${decision.recommendation}). ${decision.rationale}${alt}`;
}
