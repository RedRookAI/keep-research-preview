/**
 * Learners (Increment 18.2, Phase G) — the real IMPROVE-class adaptation axes that turn solve outcomes into
 * governed self-improvement proposals. Each registers on the SelfImprovementBus (18.1) as an "improve"
 * learner, so it is AUTOMATICALLY DORMANT until the anchor is ready (observing→learning gate) and PAUSED
 * under drift safe-mode (C4) — no per-learner dormancy logic needed. A learner never applies a change itself;
 * it PROPOSES through the MetaHarness bounded loop (18.0), which runs the triad + anchor + multi-set
 * no-regression before anything goes live. Human merge/reject remains the owner's gate.
 *
 * SOTA basis (2026-08-05):
 *  - "First dollar to the HARNESS, not the training run" (GPU-Poor Manifesto): the prompt/heuristic/memory
 *    axes are the highest-ROI, gradient-free floor — exactly these learners.
 *  - GEPA-style reflective prompt evolution (natural-language rationale from concrete failures) — PromptLearner.
 *  - Gradient-free memory consolidation by recency + frequency + reuse-utility (A-MemGuard dual-memory;
 *    forgetting-curve) — MemoryLearner, which consolidates a lesson only once CORROBORATED (seen ≥K times),
 *    guarding against one-off noise / poison.
 *  - Curriculum from observed failure modes (what to practice next) — CurriculumLearner as a prioritization
 *    signal, not an autonomous mutator.
 *
 * Everything behind ports; zero runtime deps.
 */

import type { Learner, OutcomeSignal } from "./self_improvement_bus.js";
import { reuseSignal } from "./self_improvement_bus.js";

/**
 * The minimal proposer port a learner needs — satisfied by MetaHarness.proposeLoop. Decouples learners from
 * the concrete harness (swappable + testable).
 */
export interface ImprovementProposer {
  proposeLoop(
    initial: ProposalLike,
    refine: (previous: ProposalLike, counterexample: string, round: number) => ProposalLike | null,
    maxRounds?: number,
  ): { outcome: { decision: string; reason: string }; rounds: number };
}

export interface ProposalLike {
  readonly component: string;
  readonly fromVersion: string;
  readonly toVersion: string;
  readonly rationale: string;
  readonly declaredEffects?: readonly string[];
}

/** How a proposer applied version is generated from accumulated evidence (injectable → testable, no model needed). */
export type VersionMinter = (currentVersion: string, evidence: readonly string[]) => string;

// ─────────────────────────────── PromptLearner ───────────────────────────────

export interface PromptLearnerConfig {
  /** Min outcomes for a task shape before a proposal may fire (avoid proposing on noise). Default 5. */
  readonly minSamples?: number;
  /** Failure rate over the window that triggers a proposal. Default 0.4. */
  readonly failureRateTrigger?: number;
  /** Sliding window size per task shape. Default 10. */
  readonly windowSize?: number;
  /** Current live prompt version supplier (per task shape). */
  readonly currentVersion: (taskShape: string) => string;
  /** Mint the candidate improved version from the failure evidence. */
  readonly mint: VersionMinter;
}

/**
 * Detects a PATTERN of failures for a task shape (not one-off), then proposes a prompt improvement through the
 * loop. A cooldown prevents re-proposing for the same shape until new evidence accrues.
 */
export class PromptLearner implements Learner {
  readonly id = "prompt-learner";
  readonly loopClass = "improve" as const;
  private readonly minSamples: number;
  private readonly trigger: number;
  private readonly windowSize: number;
  private readonly current: (s: string) => string;
  private readonly mint: VersionMinter;
  private readonly windows = new Map<string, boolean[]>(); // per shape: recent pass/fail
  private readonly evidence = new Map<string, string[]>(); // per shape: failure reasons
  private readonly cooldown = new Set<string>(); // shapes with an in-flight/recent proposal

  constructor(private readonly proposer: ImprovementProposer, config: PromptLearnerConfig) {
    this.minSamples = config.minSamples ?? 5;
    this.trigger = config.failureRateTrigger ?? 0.4;
    this.windowSize = config.windowSize ?? 10;
    this.current = config.currentVersion;
    this.mint = config.mint;
  }

  onOutcome(signal: OutcomeSignal): void {
    const shape = signal.taskShape;
    const win = this.windows.get(shape) ?? [];
    win.push(signal.testsPassed);
    if (win.length > this.windowSize) win.shift();
    this.windows.set(shape, win);

    const rr = reuseSignal(signal);
    if (rr.counterexample) {
      const ev = this.evidence.get(shape) ?? [];
      ev.push(rr.counterexample);
      this.evidence.set(shape, ev);
    }

    if (win.length < this.minSamples || this.cooldown.has(shape)) return;
    const failRate = win.filter((p) => !p).length / win.length;
    if (failRate < this.trigger) return;

    // Pattern detected → propose a prompt improvement through the governed loop.
    const from = this.current(shape);
    const evidence = this.evidence.get(shape) ?? [`elevated failure rate ${failRate.toFixed(2)} for ${shape}`];
    const to = this.mint(from, evidence);
    this.cooldown.add(shape); // one proposal per evidence-epoch
    this.proposer.proposeLoop(
      { component: "prompt", fromVersion: from, toVersion: to, rationale: `reflective prompt improvement for "${shape}" from ${evidence.length} failure(s)`, declaredEffects: ["adjusts prompt wording"] },
      (prev, cx) => ({ ...prev, toVersion: this.mint(prev.toVersion, [...evidence, cx]), rationale: `${prev.rationale} (refined: ${cx.slice(0, 40)})` }),
    );
  }

  /** New evidence for a shape clears its cooldown (opportunity-based, not calendar). */
  clearCooldown(taskShape: string): void {
    this.cooldown.delete(taskShape);
    this.evidence.delete(taskShape);
  }
}

// ─────────────────────────────── MemoryLearner ───────────────────────────────

export interface MemoryLearnerConfig {
  /** Times a lesson must recur before consolidation (corroboration guard vs one-off noise/poison). Default 2. */
  readonly corroborationK?: number;
  readonly currentVersion: () => string;
  readonly mint: VersionMinter;
}

/**
 * Distills a LESSON from an outcome's counterexample (reject-reason) and consolidates it ONLY once
 * corroborated ≥K times (recency+frequency, forgetting-curve). A corroborated lesson is proposed as a
 * "memory-lesson" improvement through the loop. One-off reasons never consolidate — poison/noise guard.
 */
export class MemoryLearner implements Learner {
  readonly id = "memory-learner";
  readonly loopClass = "improve" as const;
  private readonly k: number;
  private readonly current: () => string;
  private readonly mint: VersionMinter;
  private readonly counts = new Map<string, number>(); // lesson-key → times seen
  private readonly consolidated = new Set<string>();

  constructor(private readonly proposer: ImprovementProposer, config: MemoryLearnerConfig) {
    this.k = config.corroborationK ?? 2;
    this.current = config.currentVersion;
    this.mint = config.mint;
  }

  onOutcome(signal: OutcomeSignal): void {
    const rr = reuseSignal(signal);
    if (!rr.counterexample) return;
    const key = this.lessonKey(signal.taskShape, rr.counterexample);
    const n = (this.counts.get(key) ?? 0) + 1;
    this.counts.set(key, n);
    if (n < this.k || this.consolidated.has(key)) return;

    // Corroborated → consolidate as a governed memory-lesson improvement.
    this.consolidated.add(key);
    const from = this.current();
    const to = this.mint(from, [key]);
    this.proposer.proposeLoop(
      { component: "memory-lesson", fromVersion: from, toVersion: to, rationale: `consolidate corroborated lesson (${n}×): ${key}`, declaredEffects: ["adds an episodic/semantic lesson"] },
      (prev, cx) => ({ ...prev, toVersion: this.mint(prev.toVersion, [key, cx]), rationale: `${prev.rationale} (refined)` }),
    );
  }

  private lessonKey(taskShape: string, reason: string): string {
    return `${taskShape}:${reason.toLowerCase().trim().slice(0, 60)}`;
  }

  /** Diagnostics: how many times a lesson has been observed. */
  timesSeen(taskShape: string, reason: string): number {
    return this.counts.get(this.lessonKey(taskShape, reason)) ?? 0;
  }
}

// ─────────────────────────────── CurriculumLearner ───────────────────────────────

/**
 * Tracks FAILURE MODES per task shape to produce a prioritization signal ("what should Keep get better at
 * next?"). A protect-class OBSERVER — it does not mutate anything autonomously; it informs the other learners
 * and the human. Runs even in the observing phase (protect-class) so the curriculum is warm by learning-time.
 */
export class CurriculumLearner implements Learner {
  readonly id = "curriculum-learner";
  readonly loopClass = "protect" as const;
  private readonly failures = new Map<string, number>();
  private readonly totals = new Map<string, number>();

  onOutcome(signal: OutcomeSignal): void {
    const shape = signal.taskShape;
    this.totals.set(shape, (this.totals.get(shape) ?? 0) + 1);
    if (!signal.testsPassed) this.failures.set(shape, (this.failures.get(shape) ?? 0) + 1);
  }

  /** The curriculum: task shapes ranked by failure count (what to prioritize), with failure rate. */
  curriculum(): readonly { taskShape: string; failures: number; total: number; failureRate: number }[] {
    return [...this.totals.keys()]
      .map((shape) => {
        const failures = this.failures.get(shape) ?? 0;
        const total = this.totals.get(shape) ?? 0;
        return { taskShape: shape, failures, total, failureRate: total > 0 ? failures / total : 0 };
      })
      .sort((a, b) => b.failures - a.failures);
  }

  /** The single highest-priority shape to improve next, or null if nothing is failing. */
  topPriority(): string | null {
    const c = this.curriculum().filter((x) => x.failures > 0);
    return c.length > 0 ? c[0]!.taskShape : null;
  }
}
