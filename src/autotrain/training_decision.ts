/**
 * Auto-Training system: the training-decision policy (Increment 11a).
 *
 * The system must RECOGNIZE when training genuinely helps vs when it doesn't — and, per the
 * convergent 2026 SOTA, the honest answer is usually "don't train": fine-tuning is the right call
 * ~10% of the time; the other ~90% is solved by better prompts, retrieval, or self-validation
 * (buildmvpfast/AgamiSoft 2026). The decision is "does the use case NEED it," not "can we afford it"
 * (PEFT made it cheap). The real cost is eval + data curation + lifecycle ownership (3-5x training
 * cost), not GPU (BigDataBoutique 2026). So this policy is deliberately conservative: it recommends
 * the gradient-free floor unless a specific, measured, persistent failure mode with enough verified
 * data and a verifiable reward clears a bar that accounts for lifecycle cost.
 *
 * The output is a TrainingDecision with a PLAIN-LANGUAGE rationale — the system must be able to
 * explain "why train / why not" to a human who isn't an engineer. Zero deps.
 */

/** What the system recommends doing about a capability gap. */
export type TrainingRecommendation =
  | "gradient-free" // prompt / RAG / memory already suffices or would — the default, ~90% of cases
  | "train" // a measured, persistent failure mode that training would genuinely fix
  | "insufficient-data" // training might help but there isn't enough verified data yet
  | "no-verifiable-reward" // can't train safely without a verifiable reward signal
  | "not-worth-it"; // expected gain doesn't clear the lifecycle-cost bar

/** The signals the decision is made from — all measured, none guessed. */
export interface TrainingSignals {
  /** Is this a recurring, MEASURED failure mode (from the failure-mode detector, item 8)? */
  readonly recurringFailureMode: boolean;
  /** Occurrences of the failure mode (recurrence strength). */
  readonly occurrences: number;
  /** Did gradient-free remedies (better prompt / RAG / more lessons) already get TRIED and fall short? */
  readonly gradientFreeTried: boolean;
  /** Residual failure rate AFTER gradient-free remedies (0..1). High = gradient-free wasn't enough. */
  readonly residualFailureRate: number;
  /** Count of VERIFIED training examples available (held-out-checked, item 8). */
  readonly verifiedExampleCount: number;
  /** Is a genuinely verifiable reward available (unit tests / compiler / exact-match)? */
  readonly verifiableRewardAvailable: boolean;
  /** Estimated target-metric improvement if trained (0..1), from the eval-set delta. */
  readonly estimatedTargetGain: number;
  /** Is the task narrow + stable (good fit) vs broad/general (bad fit — use an API)? */
  readonly narrowStableTask: boolean;
  /** FACT-vs-FORM (2026): is the gap FACTUAL (belongs in retrieval/memory) or FORM/behavior (weights)? Default "form". */
  readonly gapKind?: "fact" | "form";
  /** Stable, HIGH-VOLUME task with a capable teacher available → distill-for-cost is the strongest 2026 case. */
  readonly highVolumeStableTask?: boolean;
  /** Preference pairs available → DPO is the fit (vs GRPO for verifiable reward, vs QLoRA default). */
  readonly preferencePairsAvailable?: boolean;
}

/** How to train, once training is warranted — the real 2026 method ladder, each with the cheaper alternative it ruled out. */
export interface TrainingApproach {
  readonly method: "rag" | "distill" | "grpo" | "dpo" | "qlora" | "full-ft";
  readonly why: string;
  readonly ruledOut: string;
}

export interface TrainingDecisionOptions {
  /** Minimum verified examples to consider training. Default 500 (SOTA: <5k → usually don't; hard floor 500). */
  readonly minExamples?: number;
  /** Minimum residual failure rate after gradient-free to justify training. Default 0.15. */
  readonly minResidualFailure?: number;
  /**
   * Minimum expected target-metric gain to clear the LIFECYCLE-cost bar (revalidation, drift,
   * adapter versioning = 3-5x training cost). Default 0.10 (10 points) — training must earn its keep.
   */
  readonly minGainForLifecycle?: number;
}

export interface TrainingDecision {
  readonly recommendation: TrainingRecommendation;
  /** True only if the recommendation is to actually train. */
  readonly shouldTrain: boolean;
  /** Plain-language reason a non-engineer can read. */
  readonly rationale: string;
  /** The gradient-free alternative to try first / instead, when not training. */
  readonly alternative?: string;
  /** When training (or routing to RAG): the chosen method + why + the cheaper alternative it ruled out. */
  readonly approach?: TrainingApproach;
  /** The signals, echoed for the audit trail. */
  readonly signals: TrainingSignals;
}

/**
 * Decide whether weight training is warranted. Conservative + ordered: it walks the SOTA decision
 * tree and returns at the first disqualifier, so the rationale names the ACTUAL reason. Only a fully
 * qualified case (measured persistent failure + gradient-free already tried + enough verified data +
 * verifiable reward + gain clearing the lifecycle bar + narrow task) recommends training.
 */
export function decideTraining(signals: TrainingSignals, opts: TrainingDecisionOptions = {}): TrainingDecision {
  const minExamples = opts.minExamples ?? 500;
  const minResidual = opts.minResidualFailure ?? 0.15;
  const minGain = opts.minGainForLifecycle ?? 0.10;

  // 1. Is there even a measured, recurring failure mode? If not — gradient-free / nothing.
  if (!signals.recurringFailureMode) {
    return decision("gradient-free", signals, "No recurring, measured failure mode was detected, so there's nothing specific for training to fix. Keep will keep using its existing knowledge, retrieval, and lessons.", "keep using prompt + RAG + memory (the default)");
  }

  // 2. Broad/general task → training is the wrong tool (use the base model via the API path).
  if (!signals.narrowStableTask) {
    return decision("gradient-free", signals, "This looks like a broad, general task. Training a specialized adapter for it would add cost and risk without a clear benefit — a general model handles this better. Keep will use its general reasoning instead.", "use the general model (no specialized training)");
  }

  // 2b. FACT-vs-FORM routing (2026): a FACTUAL gap belongs in retrieval/memory (updates instantly, stays auditable),
  //     NOT in weights. Only a FORM/behavior gap is a fine-tuning candidate. This routes fact gaps away from training.
  if (signals.gapKind === "fact") {
    return decision("gradient-free", signals, "The gap is FACTUAL — the model needs to KNOW something, not behave differently. Facts belong in retrieval and memory, where Keep can update them instantly and show exactly what was used. Baking facts into weights would be slower, staler, and unauditable.", "add the facts to RAG / memory (not training)", { method: "rag", why: "a factual gap is fixed by retrieval/memory, which is instant, auditable, and reversible", ruledOut: "fine-tuning (baking facts into weights is slow, goes stale, and can't be audited)" });
  }

  // 3. Was the cheap fix even tried? SOTA: try prompt/RAG/self-validation FIRST (~90% solved there).
  if (!signals.gradientFreeTried) {
    return decision("gradient-free", signals, "The cheaper fixes — a better prompt, retrieval from the project corpus, and applying learned lessons — haven't been fully tried yet. These solve most cases without training, so Keep will try them first and only reconsider training if the problem persists.", "try better prompts + RAG + lessons first");
  }

  // 4. Did gradient-free actually fall short? If the residual is low, don't train.
  if (signals.residualFailureRate < minResidual) {
    return decision("gradient-free", signals, `After trying the cheaper fixes, the failure rate is already low (${pct(signals.residualFailureRate)}). Training would add a lot of ongoing maintenance for a small gain, so it isn't worth it — the current approach is working well enough.`, "keep the gradient-free approach (it's working)");
  }

  // 5. An OBJECTIVE training signal is mandatory for SAFE training — a verifiable reward (tests/compiler/exact-match)
  //    OR preference pairs. A signal-free fine-tune (plain SFT on examples) is exactly what erodes safety guardrails.
  if (!signals.verifiableRewardAvailable && signals.preferencePairsAvailable !== true) {
    return decision("no-verifiable-reward", signals, "Training can only be done safely here when there's an objective signal to learn from — either an automatic success check (unit tests / compiler / exact-match) or curated preference pairs. Neither is available yet, so Keep won't train — a signal-free fine-tune risks learning the wrong thing and can even weaken safety guardrails.", "gather a verifiable success check (e.g. tests) or preference pairs before considering training");
  }

  // 6. Enough VERIFIED data? SOTA: <~500 clean examples → don't train (quality over quantity, but a floor).
  if (signals.verifiedExampleCount < minExamples) {
    return decision("insufficient-data", signals, `Training needs enough verified examples to learn from reliably — at least ${minExamples}. Right now there are ${signals.verifiedExampleCount}. Keep will keep collecting verified examples from real outcomes and revisit training once there are enough.`, `keep collecting verified examples (have ${signals.verifiedExampleCount}, need ${minExamples})`);
  }

  // 7. Does the expected gain clear the lifecycle-cost bar? Training carries 3-5x ongoing cost.
  if (signals.estimatedTargetGain < minGain) {
    return decision("not-worth-it", signals, `Training might help a little (about ${pct(signals.estimatedTargetGain)} improvement), but a trained adapter has to be maintained, re-checked, and updated over time — usually several times its initial cost. That expected gain doesn't justify the ongoing upkeep, so Keep won't train for this.`, "keep the gradient-free approach; the gain doesn't justify the upkeep");
  }

  // Fully qualified: a measured, persistent, narrow FORM/behavior failure with verified data, a verifiable reward,
  // and a gain that clears the lifecycle bar. Choose the METHOD (distill-for-cost / GRPO / DPO / QLoRA).
  const approach = chooseApproach(signals);
  return decision("train", signals, `Training is genuinely worth it here: there's a specific, repeated problem (${signals.occurrences} occurrences) that the cheaper fixes couldn't resolve (${pct(signals.residualFailureRate)} still failing), Keep has ${signals.verifiedExampleCount} verified examples to learn from, success can be checked automatically, and the expected improvement (${pct(signals.estimatedTargetGain)}) clearly justifies the upkeep. Recommended method: ${approach.method} — ${approach.why}`, undefined, approach);
}

/** Choose the training METHOD once training is warranted — the real 2026 ladder, each naming the cheaper option it ruled out. */
function chooseApproach(signals: TrainingSignals): TrainingApproach {
  // Distill-for-cost: the strongest 2026 case — a stable, high-volume task where a capable teacher compresses to a cheaper student.
  if (signals.highVolumeStableTask === true) {
    return { method: "distill", why: "a stable, high-volume task — distilling a capable teacher into a smaller student cuts per-call cost the most while holding quality", ruledOut: "serving the large model directly (far higher ongoing inference cost at this volume)" };
  }
  // GRPO: a verifiable reward (tests / compiler / exact-match) is the strongest training signal when present. Runs on
  // low-cost LoRA/QLoRA adapters (4-bit base + small adapters) rather than a full fine-tune.
  if (signals.verifiableRewardAvailable) {
    return { method: "grpo", why: "a verifiable reward (tests/compiler/exact-match) is available — GRPO optimizes directly against it, on low-cost QLoRA adapters", ruledOut: "a full fine-tune / plain SFT (higher cost and a weaker, indirect signal than the verifiable reward you already have)" };
  }
  // DPO: preference pairs → direct preference optimization, also on QLoRA adapters.
  return { method: "dpo", why: "preference pairs are available — DPO aligns behavior directly from them, on low-cost QLoRA adapters", ruledOut: "full RLHF (a much heavier pipeline for the same preference signal)" };
}

function decision(rec: TrainingRecommendation, signals: TrainingSignals, rationale: string, alternative?: string, approach?: TrainingApproach): TrainingDecision {
  return {
    recommendation: rec,
    shouldTrain: rec === "train",
    rationale,
    ...(alternative !== undefined ? { alternative } : {}),
    ...(approach !== undefined ? { approach } : {}),
    signals,
  };
}

function pct(x: number): string {
  return `${Math.round(x * 100)}%`;
}
