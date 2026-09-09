/**
 * VettingPromptBuilder + AdaptivePromptLayer (Increment 3.7d) — the composer + tailored vetting.
 *
 * SOTA basis (2026-08-04): vetting/verifier prompts are rigid, greppable, hand-written RUBRICS +
 * sequential gate checks — "we never tell validators to think step by step; we hand-write fixed
 * auditable rubrics" (real-pipeline SOTA; SurePrompts: "run high-stakes outputs through llm-as-
 * judge rubrics, evaluate slot-by-slot against the brief"). The rubric CONTENT is the invariant
 * (auditable); only the DELIVERY adapts to tier (rich → rubric+brief; lean → rubric decomposed
 * into explicit yes/no gates).
 *
 * The AdaptivePromptLayer orders prompts for CACHE HITS by construction — stable system+durable
 * context first, volatile task last — because context caching is "the single biggest cost lever"
 * with one model (single-model floor). Metaprompt mode (digitalapplied 2026): a high-effort model
 * can author a production prompt for a cheaper model — supported as a strategy, not required.
 *
 * Zero deps.
 */

import {
  selectStrategy,
  type ModelProfile,
  type PromptStrategy,
  type TaskComplexity,
} from "./prompt_strategy.js";
import { ComplexityClassifier } from "./complexity_router.js";
import { PromptStore, type PromptKey } from "./prompt_store.js";

/** A rubric is an ordered list of auditable gate checks (the invariant content). */
export interface VettingRubric {
  readonly name: string;
  readonly gates: readonly string[]; // each a checkable assertion, e.g. "output cites ≥1 source"
}

/** Build a vetting prompt whose rubric content is fixed; only delivery adapts to tier. */
export class VettingPromptBuilder {
  build(rubric: VettingRubric, profile: ModelProfile): string {
    const header = `You are a verifier. Apply the "${rubric.name}" rubric to the artifact below. ` +
      `Do NOT rewrite or improve it — only judge it against the rubric.`;
    if (profile.tier === "rich") {
      // rich verifier: rubric + brief, trust it to apply gates without hand-holding
      return `${header}\nRubric gates:\n${rubric.gates.map((g) => `- ${g}`).join("\n")}\n` +
        `Return a pass/fail per gate with a one-line reason each, then an overall verdict.`;
    }
    // lean/standard verifier: decompose into explicit sequential yes/no gates
    const numbered = rubric.gates
      .map((g, i) => `Gate ${i + 1}: ${g}\n  Answer strictly YES or NO, then a one-line reason.`)
      .join("\n");
    return `${header}\nAnswer each gate in order; do not skip any.\n${numbered}\n` +
      `After all gates, output OVERALL: PASS only if every gate is YES, else FAIL.`;
  }
}

/** The assembled prompt ready to send, plus the strategy that produced it (for audit). */
export interface AssembledPrompt {
  readonly text: string;
  readonly strategy: PromptStrategy;
  readonly complexity: TaskComplexity;
  readonly cacheableProbablePrefixLen: number; // chars of stable prefix (cache-friendly)
}

/** Inputs to assemble a prompt for a task. */
export interface PromptRequest {
  readonly taskShape: string; // "plan" | "implement" | "vet_plan" | ...
  readonly goal: string; // the volatile, task-specific instruction
  readonly durableContext?: string; // stable context (project facts, preferences) — cached prefix
  readonly profile: ModelProfile;
  /** Optional explicit complexity; else classified from the goal. */
  readonly complexity?: TaskComplexity;
}

export class AdaptivePromptLayer {
  constructor(
    private readonly store: PromptStore,
    private readonly classifier: ComplexityClassifier = new ComplexityClassifier(),
    private readonly vetting: VettingPromptBuilder = new VettingPromptBuilder(),
  ) {}

  /**
   * Assemble a prompt: classify complexity → select strategy (shape+effort) → pull the stored
   * prompt version for (taskShape, tier) → order for cache hits (stable prefix first, volatile
   * last). Falls back to a strategy-shaped default when no stored version exists yet.
   */
  assemble(req: PromptRequest): AssembledPrompt {
    const complexity = req.complexity ?? this.classifier.classify({ text: req.goal, ...(req.taskShape ? { hint: req.taskShape } : {}) }).complexity;
    const strategy = selectStrategy(req.profile, complexity);

    const key: PromptKey = { taskShape: req.taskShape, modelTier: req.profile.tier };
    const stored = this.store.select(key, "balanced");
    const body = stored ? stored.text : this.defaultBody(strategy);

    // Cache-friendly ordering: durable context + system body FIRST (stable), volatile goal LAST.
    const prefixParts: string[] = [];
    if (req.durableContext) prefixParts.push(req.durableContext.trim());
    prefixParts.push(body.trim());
    const prefix = prefixParts.join("\n\n");
    const text = `${prefix}\n\n---\nTask: ${req.goal.trim()}`;

    return {
      text,
      strategy,
      complexity,
      cacheableProbablePrefixLen: prefix.length,
    };
  }

  /** Build a tailored vetting prompt (rubric invariant; delivery adapts to tier). */
  assembleVetting(rubric: VettingRubric, profile: ModelProfile): string {
    return this.vetting.build(rubric, profile);
  }

  /** A strategy-shaped default when no stored/learned prompt exists yet for this key. */
  private defaultBody(strategy: PromptStrategy): string {
    switch (strategy.shape) {
      case "brief":
        return "Complete the task below. Be direct; state the result and a one-line justification.";
      case "scaffolded":
        return (
          "Role: expert assistant.\nApproach: (1) restate the task, (2) outline the steps, " +
          "(3) produce the result, (4) state the output in the requested format." +
          (strategy.includeCoT ? "\nWork through the steps explicitly before the final answer." : "")
        );
      case "decomposed":
        return (
          "Break the task into explicit subproblems and solve each in order:\n" +
          "Subproblem 1: identify inputs and the goal.\n" +
          "Subproblem 2: solve each part step by step.\n" +
          "Subproblem 3: combine the parts into the final result.\n" +
          "Then output the final result in the requested format."
        );
    }
  }
}
