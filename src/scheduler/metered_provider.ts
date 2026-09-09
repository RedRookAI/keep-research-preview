/**
 * L7 (money-enforcement — arming). A ModelProvider that routes the UNATTENDED autonomy path's model
 * calls through the MeteredGateway's enforced `generateMetered()` under a granted budget envelope:
 *  - `willBreach` HARD-STOPS an over-budget call BEFORE it is made (fail-closed, LLM cannot override);
 *  - the TokenVelocityBreaker trips on rate-of-spend or a repetitive-identical-call burst;
 *  - real spend is recorded to the BudgetLedger after each successful call.
 *
 * The attended/interactive path keeps using the plain gateway (`generate`, unmetered — the operator is
 * present), exactly as the MeteredGateway design intends. This provider is injected ONLY into the
 * autonomy loop's solve, so composeKeep's ingress solve is unchanged.
 *
 * HONEST SEAM (scope): this arms ONE granted envelope for the whole unattended autonomy SUBSYSTEM
 * (daily cap + per-run cap + per-call token ceiling + velocity). PER-PROJECT-RUN envelope granularity
 * needs the solve to thread a per-run context — FILED as L7b, not built here.
 */

import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../gateway/gateway.js";
import type { MeteredGateway } from "./metered_gateway.js";
import type { AuthorizationEnvelope, LoopClass, ModelTier } from "./authorization_envelope.js";
import { CostModel, type TokenUsage, type CostBreakdown, type NonTokenCost } from "../observability/cost_model.js";

/**
 * A CostModel for the metering ledger. It resolves a model's price from (1) prices already registered,
 * then (2) an injected `priceLookup` (compose passes the live pricing registry). A model that BOTH is
 * unregistered AND the lookup doesn't know is treated as $0 — this is the genuinely-free local case.
 *
 * So the USD caps (dailyCapUsd/perRunCapUsd) DO bite for any model the pricing registry prices (the paid
 * remote case); the velocity rate-check is fed real cost for those too. HONEST SEAM: a model with NO
 * price anywhere (local, or a remote model the registry hasn't priced yet) counts as $0 against the USD
 * caps and is bounded by the per-call token ceiling + velocity/repetition until it is priced. Used ONLY
 * by the metering ledger — the scheduler's ledger keeps the strict throw-on-unpriced CostModel.
 */
export class LenientCostModel extends CostModel {
  constructor(private readonly priceLookup?: (model: string) => { inputPerM: number; outputPerM: number } | undefined) {
    super();
  }
  override cost(model: string, usage: TokenUsage, nonToken: NonTokenCost = {}): CostBreakdown {
    if (!this.hasPricing(model)) {
      const p = this.priceLookup?.(model);
      if (p) this.registerPricing({ model, inputPerMillion: p.inputPerM, outputPerMillion: p.outputPerM });
    }
    if (this.hasPricing(model)) return super.cost(model, usage, nonToken);
    return { inputUsd: 0, cachedInputUsd: 0, outputUsd: 0, tokenUsd: 0, humanUsd: 0, infraUsd: 0, toolApiUsd: 0, totalUsd: 0 };
  }
}

export interface MeteredProviderContext {
  readonly runId: string;
  readonly cls: LoopClass;
  readonly tier: ModelTier;
}

/** Pre-call token projection from the request (real usage is recorded after the call). ~4 chars/token. */
function projectUsage(req: GenerateRequest): TokenUsage {
  return {
    freshInputTokens: Math.ceil(req.prompt.length / 4),
    cachedInputTokens: 0,
    outputTokens: req.maxTokens ?? 512,
  };
}

export class MeteredProvider implements ModelProvider {
  constructor(
    private readonly inner: ModelProvider,
    private readonly metered: MeteredGateway,
    private readonly ctx: MeteredProviderContext,
  ) {}

  get name(): string {
    return this.inner.name;
  }
  get isLocal(): boolean {
    return this.inner.isLocal;
  }

  /** Enforced generate: willBreach + velocity BEFORE the call; recordSpend AFTER. Throws BudgetExceeded on breach. */
  generate(req: GenerateRequest): Promise<GenerateResult> {
    return this.metered.generateMetered(req, { ...this.ctx, projected: projectUsage(req) }, this.name);
  }

  /** Embeddings pass through unmetered — `generate` is the spend enforcement point. (No generateStream so
   *  streaming callers fall back to the metered `generate`, never an unmetered bypass.) */
  embed(texts: readonly string[]): Promise<Embedding[]> {
    return this.inner.embed(texts);
  }
}

/**
 * The default operator-overridable autonomy budget envelope. GENEROUS by default (n=1 free path is never
 * blocked — LocalProvider cost is $0, and the token ceiling clears normal calls) but REAL and tightenable:
 * an operator sets `config.autonomyBudget` to bound autonomous spend. Never expires by default (operator
 * grants/revokes explicitly). `allowedTiers: []` = all tiers permitted.
 */
export function defaultAutonomyEnvelope(): AuthorizationEnvelope {
  return {
    id: "autonomy-default",
    projectId: "autonomy-subsystem",
    allowedClasses: ["auto-research", "auto-rag", "auto-learning", "auto-training"],
    allowedTiers: [],
    dailyCapUsd: 100,
    perRunCapUsd: 50,
    perCallTokenCeiling: 32_000,
    expiresAt: Number.MAX_SAFE_INTEGER,
    grantedReason: "default unattended-autonomy budget (generous; operator-overridable via config.autonomyBudget)",
  };
}
