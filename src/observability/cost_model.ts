/**
 * Cost model (Phase 4, Feature 39 foundation).
 *
 * Real cost accounting, not a token counter. Grounded in SOTA (Aug 2026):
 *  - Separate CACHED vs FRESH input tokens (cache-heavy work otherwise looks
 *    costlier than it is) — cached tokens are billed at a reduced rate.
 *  - Register per-model pricing rules (USD per million tokens).
 *  - NOT ALL COST IS TOKENS: include human-approval time, infra, and tool-API fees
 *    for an honest total.
 *  - Map to OTel gen_ai.* at the boundary (gen_ai.system, gen_ai.request.model,
 *    input/output token counts). Internal canonical model stays stable while the
 *    conventions remain experimental.
 */

/** Pricing for a model, in USD per 1,000,000 tokens. */
export interface ModelPricing {
  readonly model: string;
  readonly inputPerMillion: number;
  readonly outputPerMillion: number;
  /** Cached input tokens are cheaper; default 25% of fresh input if unset. */
  readonly cachedInputPerMillion?: number;
}

/** Token usage for a single model call, cached and fresh separated. */
export interface TokenUsage {
  readonly freshInputTokens: number;
  readonly cachedInputTokens: number;
  readonly outputTokens: number;
}

/** Non-token cost dimensions (an honest total is more than tokens). */
export interface NonTokenCost {
  /** Human approval/review time in seconds, priced by an hourly rate. */
  readonly humanApprovalSeconds?: number;
  /** Infra cost attributed to this unit of work (USD). */
  readonly infraUsd?: number;
  /** Third-party tool/API fees (USD). */
  readonly toolApiUsd?: number;
}

export interface CostBreakdown {
  readonly inputUsd: number;
  readonly cachedInputUsd: number;
  readonly outputUsd: number;
  readonly tokenUsd: number;
  readonly humanUsd: number;
  readonly infraUsd: number;
  readonly toolApiUsd: number;
  readonly totalUsd: number;
}

export class CostModel {
  private readonly pricing = new Map<string, ModelPricing>();

  constructor(
    /** Hourly rate used to price human-approval time, USD/hour. */
    private readonly humanHourlyUsd = 100,
  ) {
    if (!Number.isFinite(humanHourlyUsd) || humanHourlyUsd < 0) throw new Error("invalid hourly price");
  }

  registerPricing(p: ModelPricing): void {
    if (typeof p.model !== "string" || !p.model.length ||
      [p.inputPerMillion, p.outputPerMillion, p.cachedInputPerMillion ?? 0].some(n => !Number.isFinite(n) || n < 0)) throw new Error("invalid model pricing");
    this.pricing.set(p.model, Object.freeze({ ...p }));
  }

  hasPricing(model: string): boolean {
    return this.pricing.has(model);
  }

  /** Compute a full cost breakdown for one model call + its non-token costs. */
  cost(model: string, usage: TokenUsage, nonToken: NonTokenCost = {}): CostBreakdown {
    if ([usage.freshInputTokens, usage.cachedInputTokens, usage.outputTokens].some(n => !Number.isSafeInteger(n) || n < 0) ||
      Object.values(nonToken).some(n => !Number.isFinite(n) || n < 0)) throw new Error("invalid cost inputs");
    const p = this.pricing.get(model);
    if (!p) throw new Error(`no pricing registered for model "${model}"`);
    const cachedRate = p.cachedInputPerMillion ?? p.inputPerMillion * 0.25;

    const inputUsd = (usage.freshInputTokens / 1_000_000) * p.inputPerMillion;
    const cachedInputUsd = (usage.cachedInputTokens / 1_000_000) * cachedRate;
    const outputUsd = (usage.outputTokens / 1_000_000) * p.outputPerMillion;
    const tokenUsd = inputUsd + cachedInputUsd + outputUsd;

    const humanUsd = ((nonToken.humanApprovalSeconds ?? 0) / 3600) * this.humanHourlyUsd;
    const infraUsd = nonToken.infraUsd ?? 0;
    const toolApiUsd = nonToken.toolApiUsd ?? 0;

    const totalUsd = tokenUsd + humanUsd + infraUsd + toolApiUsd;
    if (!Number.isFinite(totalUsd)) throw new Error("cost overflow");
    return { inputUsd, cachedInputUsd, outputUsd, tokenUsd, humanUsd, infraUsd, toolApiUsd, totalUsd };
  }

  /**
   * Map an internal usage record to OTel gen_ai.* boundary attributes. Kept here so
   * the mapping is one place (the conventions are experimental; the core is stable).
   */
  toOtelAttributes(system: string, model: string, usage: TokenUsage): Record<string, string | number> {
    return {
      "gen_ai.system": system,
      "gen_ai.request.model": model,
      "gen_ai.usage.input_tokens": usage.freshInputTokens + usage.cachedInputTokens,
      "gen_ai.usage.output_tokens": usage.outputTokens,
      // Non-standard but useful extension; kept namespaced.
      "keep.usage.cached_input_tokens": usage.cachedInputTokens,
    };
  }
}
