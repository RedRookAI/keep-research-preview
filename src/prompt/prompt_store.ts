/**
 * PromptStore + gradient-free improvement loop (Increment 3.7c) — GEPA-style, in-house default.
 *
 * SOTA basis (2026-08-04): GEPA (ICLR 2026 Oral) — gradient-free prompt optimization that reflects
 * over execution traces in NATURAL LANGUAGE ("a reward of 0.43 tells the model less than a sentence
 * describing what failed"), keeps a PARETO frontier of candidates, beats GRPO by 6-19 pts with 35×
 * fewer rollouts. Overfitting guards: trust only a held-out VALIDATION slice, and a LENGTH PENALTY
 * so the optimizer can't win by padding. Prompt optimization is the cheapest, first optimization
 * tier (llm-stats) — before any fine-tuning.
 *
 * Prompts are versioned artifacts keyed by (taskShape, modelTier), carrying the existing TrustTier
 * lifecycle (candidate→probation→confirmed→retired). When a model changes, its prompts re-earn
 * trust as `candidate` (UniRoute/Inversion: don't assume the old prompt transfers — it may hurt).
 * The optimizer is behind a port: the default is this zero-dep reflect-and-accept loop over Keep's
 * own eval history; a DSPy/GEPA backend is a connected-env swap.
 *
 * Zero deps.
 */

import type { TrustTier } from "../memory/model.js";
import type { PromptShape } from "./prompt_strategy.js";
import type { CapabilityTier } from "../frontdoor/capability_adaptive.js";

/** The key a prompt is specialized for. */
export interface PromptKey {
  readonly taskShape: string; // e.g. "plan", "implement", "vet_plan"
  readonly modelTier: CapabilityTier;
}

/** A measured outcome of using a prompt version (the anchor for gradient-free improvement). */
export interface PromptTrace {
  readonly quality: number; // 0..1 (from vetting/validation, NOT self-reported)
  readonly costTokens: number;
  readonly split: "train" | "validation"; // trust only validation for acceptance
  /** Natural-language reflection on what failed/succeeded (GEPA's signal, not a scalar). */
  readonly reflection?: string;
}

/** A versioned prompt artifact. */
export interface PromptVersion {
  readonly id: string;
  readonly key: PromptKey;
  readonly shape: PromptShape;
  readonly text: string;
  tier: TrustTier;
  readonly createdAt: number;
  /** Aggregates over validation traces only. */
  valQuality: number;
  valCostTokens: number;
  valCount: number;
}

function keyStr(k: PromptKey): string {
  return `${k.taskShape}::${k.modelTier}`;
}

/** A proposed edit from the reflection step (the optimizer port emits these). */
export interface PromptEdit {
  readonly newText: string;
  readonly reason: string; // natural-language rationale (GEPA-style)
}

/** The optimizer seam: given the incumbent + its traces, propose an edit (or none). */
export type PromptOptimizer = (incumbent: PromptVersion, traces: readonly PromptTrace[]) => PromptEdit | undefined;

export class PromptStore {
  private readonly versions = new Map<string, PromptVersion[]>(); // key → versions (Pareto set)
  private seq = 0;

  /** Register an initial (seed) prompt for a key as `candidate`. */
  seed(key: PromptKey, shape: PromptShape, text: string, now: number = Date.now()): PromptVersion {
    const v: PromptVersion = {
      id: `pv_${this.seq++}`,
      key,
      shape,
      text,
      tier: "candidate",
      createdAt: now,
      valQuality: 0,
      valCostTokens: 0,
      valCount: 0,
    };
    const list = this.versions.get(keyStr(key)) ?? [];
    list.push(v);
    this.versions.set(keyStr(key), list);
    return v;
  }

  /** All versions for a key (the Pareto set). */
  versionsFor(key: PromptKey): readonly PromptVersion[] {
    return this.versions.get(keyStr(key)) ?? [];
  }

  /**
   * Pick the active prompt for a key given a preference: "quality" → best validated quality;
   * "cost" → cheapest among acceptable-quality; default balances. Confirmed/probation preferred
   * over candidate. This is the Pareto pick — choose the trade-off at call time.
   */
  select(key: PromptKey, prefer: "quality" | "cost" | "balanced" = "balanced"): PromptVersion | undefined {
    const list = this.versionsFor(key).filter((v) => v.tier !== "retired");
    if (list.length === 0) return undefined;
    const trusted = list.filter((v) => v.tier === "confirmed" || v.tier === "probation");
    const pool = trusted.length ? trusted : list; // fall back to candidates if nothing trusted yet
    if (prefer === "quality") return [...pool].sort((a, b) => score(b, "quality") - score(a, "quality"))[0];
    if (prefer === "cost") return [...pool].sort((a, b) => a.valCostTokens - b.valCostTokens)[0];
    return [...pool].sort((a, b) => score(b, "balanced") - score(a, "balanced"))[0];
  }

  /** Record a trace against a version (updates validation aggregates only). */
  record(versionId: string, trace: PromptTrace): void {
    for (const list of this.versions.values()) {
      const v = list.find((x) => x.id === versionId);
      if (!v) continue;
      if (trace.split === "validation") {
        v.valQuality = (v.valQuality * v.valCount + trace.quality) / (v.valCount + 1);
        v.valCostTokens = (v.valCostTokens * v.valCount + trace.costTokens) / (v.valCount + 1);
        v.valCount++;
        // trust promotion: enough good validation → probation → confirmed
        if (v.valCount >= 3 && v.valQuality >= 0.8 && v.tier === "candidate") v.tier = "probation";
        if (v.valCount >= 8 && v.valQuality >= 0.85 && v.tier === "probation") v.tier = "confirmed";
      }
      return;
    }
  }

  /**
   * One gradient-free improvement round for a key. Reflects over traces via the optimizer port,
   * proposes an edit, and accepts the new candidate ONLY IF it beats the incumbent on VALIDATION
   * quality after a LENGTH PENALTY (anti-padding). Never removes the incumbent — keeps a Pareto
   * set. Returns the new version if accepted.
   */
  improve(
    key: PromptKey,
    optimizer: PromptOptimizer,
    evaluate: (candidateText: string) => readonly PromptTrace[],
    now: number = Date.now(),
  ): PromptVersion | undefined {
    const incumbent = this.select(key, "quality");
    if (!incumbent) return undefined;
    const incumbentTraces = this.collectTraces(incumbent.id);
    const edit = optimizer(incumbent, incumbentTraces);
    if (!edit) return undefined;

    // evaluate the candidate on a validation slice
    const traces = evaluate(edit.newText).filter((t) => t.split === "validation");
    if (traces.length === 0) return undefined;
    const candQuality = traces.reduce((s, t) => s + t.quality, 0) / traces.length;

    // length penalty: candidate must beat incumbent AFTER penalizing extra length
    const lenPenalty = penalty(edit.newText.length, incumbent.text.length);
    const adjustedCand = candQuality - lenPenalty;
    if (adjustedCand <= incumbent.valQuality) return undefined; // reject: didn't beat incumbent

    // accept: add as a new candidate version (Pareto set grows; incumbent stays)
    const v = this.seed(key, incumbent.shape, edit.newText, now);
    for (const t of traces) this.record(v.id, t);
    return v;
  }

  /** When a model changes: reset all versions for that tier to candidate (re-earn trust). */
  invalidateTier(modelTier: CapabilityTier): number {
    let n = 0;
    for (const list of this.versions.values()) {
      for (const v of list) {
        if (v.key.modelTier === modelTier && v.tier !== "candidate") {
          v.tier = "candidate";
          v.valCount = 0;
          v.valQuality = 0;
          n++;
        }
      }
    }
    return n;
  }

  private collectTraces(_versionId: string): PromptTrace[] {
    // In-house default keeps aggregates, not raw traces; the optimizer works from aggregates +
    // any reflections the caller passes. A DSPy/GEPA backend would retain full traces.
    return [];
  }
}

function score(v: PromptVersion, prefer: "quality" | "balanced"): number {
  if (prefer === "quality") return v.valQuality;
  // balanced: quality minus a small normalized cost term
  return v.valQuality - Math.min(0.2, v.valCostTokens / 100_000);
}

/** Length penalty: extra characters beyond the incumbent cost a little quality credit. */
function penalty(candLen: number, incumbentLen: number): number {
  if (candLen <= incumbentLen) return 0;
  const extra = candLen - incumbentLen;
  return Math.min(0.1, extra / 10_000); // cap the penalty at 0.1
}
