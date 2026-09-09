/**
 * Autonomy Engine — GroundedEstimator (build item 3).
 *
 * The projection mandate, enforced in code: Keep NEVER emits a cost or time projection
 * from model guesswork. AI estimates are systematically wrong ("this'll take months" for
 * an afternoon; "this'll be expensive" for pennies), so every projection here is grounded
 * in measured reality or honestly labelled unknown.
 *
 * Re-verified 2026 SOTA:
 *  - Two-rate pricing: C = in·in_price + out·out_price; input/output differ 3–8× — never
 *    conflate them (arXiv 2606.07846). Rates are fetched THAT DAY, never remembered.
 *  - Output length is the hard part: estimate via EMA/median over HISTORICAL output for
 *    the same task-shape; input tokens are computable exactly.
 *  - "Low-P / high-variance agents should be tagged uncertain and excluded until history
 *    stabilizes" — i.e. the honest "not enough data yet" fallback is the SOTA-endorsed move.
 *  - Failed runs cost far more (2.77–4×), so fold in a failure-inflation factor.
 *
 * Three grounded inputs: (1) current rates (injected RatesPort) → the existing cost-aware
 * CostModel does the dollar math; (2) Keep's own measured EstimationSample history (the
 * primary anchor); (3) explicit p50/p90 range + failure inflation. Composes with CostModel
 * and (optionally) the temporal layer's can't-verify honesty. Zero deps.
 */

import { CostModel, type ModelPricing } from "../observability/cost_model.js";

/** One measured observation of a completed unit of work (the anchor for estimates). */
export interface EstimationSample {
  /** The task-shape bucket this belongs to, e.g. "novel-chapter", "rest-endpoint". */
  readonly taskShape: string;
  readonly inputTokens: number;
  readonly outputTokens: number;
  readonly durationMs: number;
  /** Whether the run succeeded (failed runs are more expensive; tracked for inflation). */
  readonly succeeded: boolean;
}

/** Current provider rates, fetched that day (never remembered). Returns null if unfetchable. */
export interface RatesPort {
  (provider: string, model: string): Promise<ModelPricing | null>;
}

export interface EstimateRequest {
  readonly taskShape: string;
  readonly provider: string;
  readonly model: string;
  /** How many units of this shape the project will do (e.g. 24 chapters). */
  readonly units: number;
  /** If the input size is known now, tokenize it exactly; else it's estimated from history. */
  readonly knownInputTokens?: number;
}

export interface GroundedEstimate {
  readonly grounded: boolean;
  /** Plain-language basis + honesty statement. Always present. */
  readonly basis: string;
  /** Present only when grounded. */
  readonly cost?: {
    readonly p50Usd: number;
    readonly p90Usd: number;
    readonly currency: "USD";
  };
  readonly time?: {
    readonly p50Ms: number;
    readonly p90Ms: number;
  };
  /** How many measured samples backed this (0 => not grounded). */
  readonly sampleCount: number;
}

export interface GroundedEstimatorConfig {
  /** Minimum samples for a task-shape before we'll ground an estimate on it. */
  readonly minSamples: number;
  /** Multiplier applied to the p90 tail to reflect failure inflation. */
  readonly failureInflation: number;
}

const DEFAULT_CONFIG: GroundedEstimatorConfig = { minSamples: 3, failureInflation: 2.77 };

export class GroundedEstimator {
  private readonly samples: EstimationSample[] = [];
  private readonly config: GroundedEstimatorConfig;

  constructor(
    private readonly rates: RatesPort,
    config: Partial<GroundedEstimatorConfig> = {},
  ) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /** Record a measured observation (from a real completed unit of work). */
  record(sample: EstimationSample): void {
    this.samples.push(sample);
  }

  /** Seed many samples at once (e.g. replayed from BuildOutcome history). */
  seed(samples: readonly EstimationSample[]): void {
    for (const s of samples) this.samples.push(s);
  }

  private forShape(shape: string): EstimationSample[] {
    return this.samples.filter((s) => s.taskShape === shape);
  }

  /**
   * Produce a grounded estimate — or an honest "not enough data" verdict. Never fabricates
   * a number. Cost math is delegated to the cost-aware CostModel with rates fetched today.
   */
  async estimate(req: EstimateRequest): Promise<GroundedEstimate> {
    const hist = this.forShape(req.taskShape);
    const pricing = await this.rates(req.provider, req.model).catch(() => null);

    // Honest fallback #1: no measured history for this shape.
    if (hist.length < this.config.minSamples) {
      return {
        grounded: false,
        sampleCount: hist.length,
        basis:
          `I don't have enough measured history for "${req.taskShape}" yet ` +
          `(${hist.length} of ${this.config.minSamples} needed), so I'd rather not guess at cost or time. ` +
          `Once I've done a few of these and measured them, I can give you a grounded range.`,
      };
    }

    // Honest fallback #2: history exists but today's rates couldn't be fetched.
    if (!pricing) {
      const t = quantiles(hist.map((s) => s.durationMs));
      return {
        grounded: false,
        sampleCount: hist.length,
        basis:
          `I have measured timing history for "${req.taskShape}", but I couldn't fetch today's ` +
          `pricing for ${req.provider}/${req.model}, so I won't state a dollar figure from stale rates. ` +
          `On time alone, similar past units took roughly ${fmtMs(t.p50)}–${fmtMs(t.p90)} each.`,
        time: { p50Ms: t.p50 * req.units, p90Ms: t.p90 * req.units },
      };
    }

    // Grounded path: estimate tokens from history (output is the hard part), price with today's rates.
    const inSamples = req.knownInputTokens !== undefined ? [req.knownInputTokens] : hist.map((s) => s.inputTokens);
    const inQ = quantiles(inSamples);
    const outQ = quantiles(hist.map((s) => s.outputTokens));
    const durQ = quantiles(hist.map((s) => s.durationMs));
    const failureRate = hist.filter((s) => !s.succeeded).length / hist.length;

    const cm = new CostModel();
    cm.registerPricing(pricing);
    // p50: typical unit. p90: tail unit, further inflated for failure retries.
    const perUnitP50 = cm.cost(req.model, { freshInputTokens: inQ.p50, cachedInputTokens: 0, outputTokens: outQ.p50 }).totalUsd;
    const tailInflation = 1 + failureRate * (this.config.failureInflation - 1);
    const perUnitP90 = cm.cost(req.model, { freshInputTokens: inQ.p90, cachedInputTokens: 0, outputTokens: outQ.p90 }).totalUsd * tailInflation;

    return {
      grounded: true,
      sampleCount: hist.length,
      cost: {
        p50Usd: round(perUnitP50 * req.units),
        p90Usd: round(perUnitP90 * req.units),
        currency: "USD",
      },
      time: {
        p50Ms: durQ.p50 * req.units,
        p90Ms: durQ.p90 * req.units * tailInflation,
      },
      basis:
        `Grounded in ${hist.length} measured "${req.taskShape}" runs and today's ${req.provider}/${req.model} rates ` +
        `(input $${pricing.inputPerMillion}/M, output $${pricing.outputPerMillion}/M). ` +
        `Typical unit ≈ $${round(perUnitP50)}; I'm giving a p50–p90 range for ${req.units} units because real cost varies` +
        (failureRate > 0 ? `, and I've folded in a failure-inflation factor since ${Math.round(failureRate * 100)}% of past runs needed retries.` : `.`),
    };
  }
}

/** Simple p50/p90 quantiles over a numeric sample (linear interpolation). */
function quantiles(xs: readonly number[]): { p50: number; p90: number } {
  if (xs.length === 0) return { p50: 0, p90: 0 };
  const s = [...xs].sort((a, b) => a - b);
  return { p50: quantile(s, 0.5), p90: quantile(s, 0.9) };
}
function quantile(sorted: readonly number[], q: number): number {
  if (sorted.length === 1) return sorted[0]!;
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  const frac = pos - lo;
  return sorted[lo]! * (1 - frac) + sorted[hi]! * frac;
}
function round(n: number): number {
  return Math.round(n * 10000) / 10000;
}
function fmtMs(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}min`;
}
