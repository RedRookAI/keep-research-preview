/**
 * L7 (money-enforcement — arming). A ModelProvider that routes the UNATTENDED autonomy path's model
 * calls through the MeteredGateway's enforced `generateMetered()` under a granted budget envelope:
 *  - durable admission reserves projected token cost before the provider is entered;
 *  - the TokenVelocityBreaker trips on rate-of-spend or a repetitive-identical-call burst;
 *  - valid reported usage settles that reservation; entered failures keep an unresolved hold.
 *
 * The attended/interactive path keeps using the plain gateway (`generate`, unmetered — the operator is
 * present), exactly as the MeteredGateway design intends. This provider is injected ONLY into the
 * composed automated solve paths; direct interactive gateway calls remain unmetered.
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
 * Historical exported name retained for compatibility. Resolve configured prices
 * dynamically; unknown pricing is an error, never an implicit zero-dollar rate.
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
    return super.cost(model, usage, nonToken);
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

  /** Capture one effective output/attempt bound for both reservation and dispatch. */
  generate(req: GenerateRequest): Promise<GenerateResult> {
    const request = Object.freeze({ ...req, maxTokens: req.maxTokens ?? 512, maxAttempts: 1 });
    return this.metered.generateMetered(request, { ...this.ctx, projected: projectUsage(request) }, this.name);
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
