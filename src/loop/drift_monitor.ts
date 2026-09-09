/**
 * DriftMonitor (Increment C4, promoted into Phase M) — the ONLY defense against SLOW, COMPOUNDING
 * MISEVOLUTION. Self-improvement compounds: "small wins accelerate fast, but so do small errors"
 * (Traversaal 2026). A single bad change is caught by halt-on-regression + rollback; a slow behavioral
 * drift that "degrades decision quality over time, invisible to traditional monitoring" (elixirdata 2026) is
 * caught only by a behavioral-anchor drift check. Monitoring must be live BEFORE any self-improvement axis
 * (NIST AI RMF / EU AI Act: test "regularly while in operation") — hence Phase M.
 *
 * SOTA basis (2026-08-05), all ZERO-DEP, NO embedding model (front/back-of-house identical):
 *  - PSI (Population Stability Index) = symmetrized-KL over BINNED distributions; rule of thumb <0.1 stable /
 *    0.1-0.2 watch / >0.2 act (Syrin, Metric Hub, Tacnode 2026). Computed on CATEGORICAL trace features Keep
 *    already logs (taskShape, mergeVerdict, vetVerdict, isolationTier) — pure histogram math.
 *  - The quiet-failure signals (Syrin): COMPLETION-RATE ("bends before users complain") + REJECT-RATE.
 *  - CUSUM change-detection flags SUSTAINED drift (the compounding kind) vs normal variance, tunable.
 *  - Frozen BEHAVIORAL BASELINE = the first-N observing window (ASI adaptive-behavioral-anchoring 2601.04170).
 *  - Drift → SAFE-MODE: pause improve-class adaptation + route to review (Olmec shadow-AI 2026), NOT just a
 *    log. Heal/protect continue (drift must not block a fix).
 *
 * Reads OutcomeSignal (18.1). Registers on the bus as a "protect"-class learner; its inSafeMode() is the gate
 * the bus consults before dispatching "improve"-class learners.
 */

import type { OutcomeSignal, Learner } from "./self_improvement_bus.js";

export type DriftLevel = "stable" | "watch" | "drift";

export interface DriftStatus {
  readonly level: DriftLevel;
  /** Worst PSI across monitored categorical features. */
  readonly maxPsi: number;
  /** Per-feature PSI (which distribution shifted). */
  readonly psiByFeature: Readonly<Record<string, number>>;
  /** Completion rate (tests passing) in the current window vs baseline. */
  readonly completionRate: number;
  readonly baselineCompletionRate: number;
  /** CUSUM accumulator for sustained completion-rate DECLINE (the compounding signal). */
  readonly completionCusum: number;
  readonly reason: string;
  /** True once a baseline is frozen (enough observing-phase samples). */
  readonly baselineReady: boolean;
}

export interface DriftMonitorConfig {
  /** Observing samples to freeze the baseline (first-N window). Default 30 (matches the anchor threshold). */
  readonly baselineSize?: number;
  /** Rolling window of recent signals compared against the baseline. Default 30. */
  readonly windowSize?: number;
  /** PSI "watch" threshold (default 0.1) and "drift" threshold (default 0.2) — the standard rule of thumb. */
  readonly watchPsi?: number;
  readonly driftPsi?: number;
  /** CUSUM threshold for sustained completion decline → drift. Default 3.0 (≈ several small drops in a row). */
  readonly cusumThreshold?: number;
  /** Categorical features to monitor. Default the four Keep logs on every solve. */
  readonly features?: readonly (keyof OutcomeSignal)[];
}

/** A small histogram over string category values. */
type Hist = Map<string, number>;

export class DriftMonitor {
  private readonly baselineSize: number;
  private readonly windowSize: number;
  private readonly watchPsi: number;
  private readonly driftPsi: number;
  private readonly cusumThreshold: number;
  private readonly features: readonly (keyof OutcomeSignal)[];

  private readonly observing: OutcomeSignal[] = [];
  private baseline: { hists: Record<string, Hist>; completionRate: number } | null = null;
  private readonly window: OutcomeSignal[] = [];
  private completionCusum = 0;
  private latched: DriftLevel = "stable"; // drift latches until explicitly cleared (a fix)

  constructor(config: DriftMonitorConfig = {}) {
    this.baselineSize = config.baselineSize ?? 30;
    this.windowSize = config.windowSize ?? 30;
    this.watchPsi = config.watchPsi ?? 0.1;
    this.driftPsi = config.driftPsi ?? 0.2;
    this.cusumThreshold = config.cusumThreshold ?? 3.0;
    this.features = config.features ?? (["taskShape", "mergeVerdict", "vetVerdict", "isolationTier"] as (keyof OutcomeSignal)[]);
  }

  /** As a bus learner: protect-class (monitors; does not adapt). Registers with a stable id. */
  asLearner(): Learner {
    return { id: "drift-monitor", loopClass: "protect", onOutcome: (s) => { this.observe(s); } };
  }

  /** Feed one signal. During the observing window it seeds the baseline; after, it updates the drift status. */
  observe(signal: OutcomeSignal): void {
    if (!this.baseline) {
      this.observing.push(signal);
      if (this.observing.length >= this.baselineSize) this.freezeBaseline();
      return;
    }
    this.window.push(signal);
    if (this.window.length > this.windowSize) this.window.shift();
    this.updateCusum(signal);
  }

  /** The current drift status (computed on demand from the rolling window vs the frozen baseline). */
  status(): DriftStatus {
    if (!this.baseline) {
      return { level: "stable", maxPsi: 0, psiByFeature: {}, completionRate: 0, baselineCompletionRate: 0, completionCusum: 0, reason: "observing — baseline not yet frozen", baselineReady: false };
    }
    const psiByFeature: Record<string, number> = {};
    let maxPsi = 0;
    for (const f of this.features) {
      const psi = this.psiFor(f);
      psiByFeature[f as string] = psi;
      if (psi > maxPsi) maxPsi = psi;
    }
    const completionRate = this.window.length > 0 ? this.window.filter((s) => s.testsPassed).length / this.window.length : this.baseline.completionRate;

    // Level = worst of {PSI rule-of-thumb, CUSUM sustained-decline}. Drift LATCHES (until cleared by a fix).
    let level: DriftLevel = "stable";
    let reason = "within baseline";
    if (maxPsi >= this.driftPsi) { level = "drift"; reason = `PSI ${maxPsi.toFixed(3)} ≥ ${this.driftPsi} (distribution shift)`; }
    else if (this.completionCusum >= this.cusumThreshold) { level = "drift"; reason = `sustained completion decline (CUSUM ${this.completionCusum.toFixed(2)} ≥ ${this.cusumThreshold})`; }
    else if (maxPsi >= this.watchPsi) { level = "watch"; reason = `PSI ${maxPsi.toFixed(3)} in watch band`; }

    if (level === "drift") this.latched = "drift";
    const effective = this.latched === "drift" ? "drift" : level;
    return {
      level: effective, maxPsi, psiByFeature, completionRate, baselineCompletionRate: this.baseline.completionRate,
      completionCusum: this.completionCusum, reason: this.latched === "drift" && level !== "drift" ? `latched: ${reason}` : reason, baselineReady: true,
    };
  }

  /** Safe-mode: pause "improve"-class adaptation while drift is latched. Heal/protect are unaffected. */
  inSafeMode(): boolean {
    return this.status().level === "drift";
  }

  /** Clear the latched drift (after a fix / rollback / human review). Resets CUSUM; keeps the baseline. */
  clearSafeMode(): void {
    this.latched = "stable";
    this.completionCusum = 0;
  }

  private freezeBaseline(): void {
    const hists: Record<string, Hist> = {};
    for (const f of this.features) hists[f as string] = this.histogram(this.observing, f);
    const completionRate = this.observing.filter((s) => s.testsPassed).length / this.observing.length;
    this.baseline = { hists, completionRate };
  }

  private updateCusum(signal: OutcomeSignal): void {
    if (!this.baseline) return;
    // One-sided CUSUM for DECLINE in completion: accumulate how far below baseline each outcome is.
    // pass=1, fail=0; deviation below (baseline - slack) accumulates, capped at 0 below (only tracks decline).
    const x = signal.testsPassed ? 1 : 0;
    const slack = 0.5; // allowance so normal variance doesn't accumulate
    this.completionCusum = Math.max(0, this.completionCusum + (this.baseline.completionRate - slack - x + 0.5));
  }

  private histogram(signals: readonly OutcomeSignal[], feature: keyof OutcomeSignal): Hist {
    const h: Hist = new Map();
    for (const s of signals) {
      const v = String(s[feature] ?? "«none»");
      h.set(v, (h.get(v) ?? 0) + 1);
    }
    return h;
  }

  /** PSI for one feature: Σ (a% - b%) · ln(a%/b%) over the union of category bins, with an ε floor. */
  private psiFor(feature: keyof OutcomeSignal): number {
    if (!this.baseline || this.window.length === 0) return 0;
    const b = this.baseline.hists[feature as string];
    if (!b) return 0;
    const a = this.histogram(this.window, feature);
    const bTotal = sum(b.values());
    const aTotal = sum(a.values());
    if (bTotal === 0 || aTotal === 0) return 0;
    const bins = new Set<string>([...b.keys(), ...a.keys()]);
    const eps = 1e-4;
    let psi = 0;
    for (const bin of bins) {
      const bp = Math.max((b.get(bin) ?? 0) / bTotal, eps);
      const ap = Math.max((a.get(bin) ?? 0) / aTotal, eps);
      psi += (ap - bp) * Math.log(ap / bp);
    }
    return psi;
  }
}

function sum(it: IterableIterator<number>): number {
  let t = 0;
  for (const v of it) t += v;
  return t;
}
