/**
 * PromptStrategy + Model Adaptation seam (Increment 3.7a) — model×complexity → prompt shape.
 *
 * SOTA basis (re-verified 2026-08-04): "optimal prompting strategies must co-evolve with model
 * capabilities" (arXiv 2510.22251 — the Prompting Inversion). The clean rule (Macplanet;
 * karozieminski; OpenAI guidance): **chat models reward detailed scaffolding; reasoning models
 * reward brevity + a clear end goal.** On reasoning models "think step by step", few-shot
 * stuffing, and context overload BACKFIRE. Weak models need explicit subproblem DECOMPOSITION,
 * not verbose CoT (Trace-of-Thought). The budget dial is `reasoning_effort` (Low/Med/High) set via
 * API param, NOT prose (digitalapplied; SurePrompts).
 *
 * Model knobs are CAPABILITY-DETECTED, never assumed (SAGAI-MID arXiv 2603.28731): OpenAI-compat
 * "leaks every time on reasoning-effort params" — GPT/Gemini graded, Kimi/Qwen binary, Grok none.
 * So effort maps through the family's EffortKnob (from the 3.6 reference layer): graded → set a
 * level; binary → on/off by complexity; none → no knob, lean on prompt SHAPE instead. The layer
 * NEVER assumes a provider; the single-model floor holds for ANY one model.
 *
 * Zero deps.
 */

import type { CapabilityTier } from "../frontdoor/capability_adaptive.js";
import type { EffortKnob } from "../reference/reference_registry.js";

/** Task complexity (from the classifier in 3.7b, or supplied directly). */
export type TaskComplexity = "trivial" | "simple" | "moderate" | "complex";

/** The shape of prompt to construct (the co-evolution axis). */
export type PromptShape =
  | "brief" // reasoning/rich: role in one line, clear goal, rubric named, no CoT scaffolding
  | "scaffolded" // chat/standard: role + context + structure + few-shot + explicit format
  | "decomposed"; // lean/minimal on a hard task: explicit subproblem steps (Trace-of-Thought)

/** An effort setting normalized across knob types. */
export type PromptEffortLevel = "none" | "low" | "medium" | "high";

/** What the model actually supports (capability-detected; provider-agnostic). */
export interface ModelProfile {
  readonly tier: CapabilityTier;
  /** How this model exposes reasoning effort (from the family map; unknown → "none"). */
  readonly effortKnob: EffortKnob;
  /** Reasoning models need longer timeouts. */
  readonly timeoutClass: "standard" | "reasoning";
}

/** The concrete strategy chosen for a (model, task) pair. */
export interface PromptStrategy {
  readonly shape: PromptShape;
  readonly effort: PromptEffortLevel;
  /** How the effort maps onto THIS model's actual knob (transparent adaptation). */
  readonly effortApplication:
    | { kind: "graded"; level: "low" | "medium" | "high" }
    | { kind: "binary"; thinking: boolean }
    | { kind: "none" }; // no knob — the prompt shape carries the load
  readonly includeFewShot: boolean;
  readonly includeCoT: boolean; // explicit "think step by step" — only for weak models
  readonly timeoutClass: "standard" | "reasoning";
  readonly rationale: string;
}

/** Map a normalized effort level onto whatever knob the model actually exposes. */
export function applyEffort(
  knob: EffortKnob,
  effort: PromptEffortLevel,
): PromptStrategy["effortApplication"] {
  if (knob === "graded") {
    const level = effort === "none" ? "low" : (effort as "low" | "medium" | "high");
    return { kind: "graded", level };
  }
  if (knob === "binary") {
    // on for anything above trivial/simple; off when we deliberately want a fast shallow pass
    return { kind: "binary", thinking: effort === "medium" || effort === "high" };
  }
  return { kind: "none" };
}

/**
 * Select the prompt strategy for a model profile + task complexity. Deterministic; encodes the
 * co-evolution rule. This is the SAME function whether Keep has a fleet or one model — with one
 * model the tier is fixed and complexity moves the effort/shape within it (single-model mode).
 */
export function selectStrategy(profile: ModelProfile, complexity: TaskComplexity): PromptStrategy {
  const effort = effortForComplexity(complexity);
  const effortApplication = applyEffort(profile.effortKnob, effort);

  // Shape by tier, per the inversion rule.
  let shape: PromptShape;
  let includeFewShot: boolean;
  let includeCoT: boolean;
  let rationale: string;

  if (profile.tier === "rich") {
    // reasoning/rich model → brevity wins; NO CoT, minimal/no few-shot.
    shape = "brief";
    includeFewShot = false;
    includeCoT = false;
    rationale = "rich/reasoning model: brief clear-goal prompt; effort via knob; scaffolding hurts";
  } else if (profile.tier === "standard") {
    // chat/standard model → scaffolding helps.
    shape = "scaffolded";
    includeFewShot = complexity !== "trivial";
    includeCoT = complexity === "complex"; // moderate CoT only when genuinely hard
    rationale = "standard/chat model: scaffolded role+structure+format; few-shot aids";
  } else {
    // lean/minimal model
    if (complexity === "complex" || complexity === "moderate") {
      shape = "decomposed"; // Trace-of-Thought explicit subproblems
      includeFewShot = true;
      includeCoT = true;
      rationale = "lean model on a hard task: explicit subproblem decomposition (Trace-of-Thought)";
    } else {
      shape = "scaffolded";
      includeFewShot = complexity !== "trivial";
      includeCoT = false;
      rationale = "lean model on an easy task: light scaffolding, no verbose CoT";
    }
  }

  return {
    shape,
    effort,
    effortApplication,
    includeFewShot,
    includeCoT,
    timeoutClass: profile.timeoutClass,
    rationale,
  };
}

/** Complexity → normalized effort (the budget dial). */
function effortForComplexity(complexity: TaskComplexity): PromptEffortLevel {
  switch (complexity) {
    case "trivial":
      return "none";
    case "simple":
      return "low";
    case "moderate":
      return "medium";
    case "complex":
      return "high";
  }
}
