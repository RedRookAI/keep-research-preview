/**
 * ProviderRouter (Increment 12d) — resolution + cascade + failover over the existing router machinery.
 *
 * SOTA basis (2026-08-05): production LLM routing combines three strategies — complexity-based
 * (classify → tier), cost-based (cheapest model that clears the quality bar), and cascade (try cheap
 * first, escalate ONLY on a failed check). Keep already has the first two (ComplexityClassifier +
 * FirewallRouter). This layer adds provider RESOLUTION + cascade + failover, and — critically — the
 * cascade escalation rate is a COST VARIABLE to monitor, not a fire-and-forget setting (TrueFoundry's
 * runaway-bill story; BuilderWorld: "escalation rate > 30% means the cheap tier is too weak"). Failover
 * is a SEPARATE concern from cascade (Logic 2026: cascade handles cost, failover handles availability).
 *
 * So: rule-first (complexity → tier → cheapest provider), cascade on a provably-failed quality check
 * (bounded + recorded), failover on a transient provider outage (post-retry). Reuses ModelTier +
 * CapabilityTier; records every route + escalation to the spine so cost/budget stay in one place.
 * Zero deps.
 */

import type { Spine } from "../spine/spine.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "./gateway.js";
import { ComplexityClassifier, FirewallRouter, type RouteCandidate } from "../prompt/complexity_router.js";
import type { TaskComplexity } from "../prompt/prompt_strategy.js";
import type { CapabilityTier } from "../frontdoor/capability_adaptive.js";
import { ProviderError } from "./http_provider.js";
import { isFailoverEligible, classifyProviderError } from "../frontdoor/fallback_chain.js";
import { interceptEgress, type EgressPrompt, type EgressResult, type EgressFlowContext } from "../privacy/egress_interceptor.js";
import { DataClassifier } from "../ingest/data_classifier.js";
import { RedactionGateway } from "../privacy/redaction_gateway.js";
import {
  assemblePrompt,
  chooseBudgetAwareRoute,
  type BudgetAwareRoute,
  type MeasuredOutcomeRouter,
  type ModelProfile as CostOfPassModelProfile,
  type RouterPolicy as CostOfPassPolicy,
  type TaskSignal as CostOfPassTaskSignal,
} from "../routing/cost_of_pass_router.js";

/** The egress interceptor as the router consumes it (injected; the policy is baked into the closure by compose). */
export type EgressFn = (prompt: EgressPrompt, provider: { readonly isLocal: boolean }) => EgressResult;

/** Thrown when the egress interceptor recommends blocking (high-risk + low-confidence) — the call fails SAFE, unsent. */
export class EgressBlockedError extends Error {
  constructor(reason: string) { super(reason); this.name = "EgressBlockedError"; }
}

/**
 * Conservative default refusal detector. Errs toward DETECTING a refusal: a false positive merely returns the cheap
 * answer instead of escalating (harmless), while a false negative would route around a refusal to a stronger model
 * (the circumvention we must prevent). Operators can override with a real refusal classifier.
 */
const REFUSAL_MARKERS: readonly RegExp[] = [
  /\bI can(?:'|no)?t help\b/i,
  /\bI cannot (?:help|assist|comply|do that)\b/i,
  /\bI(?:'m| am) (?:not able|unable) to\b/i,
  /\bI (?:won'?t|will not)\b/i,
  /\bcan(?:'|no)?t assist with\b/i,
  /\bI must (?:decline|refuse)\b/i,
];
export function looksLikeRefusal(text: string): boolean {
  return REFUSAL_MARKERS.some((r) => r.test(text));
}

/** A registered provider with its capability tier + relative cost weight (for cheapest-that-clears). */
export interface RegisteredProvider {
  readonly id: string;
  readonly tier: CapabilityTier;
  readonly costWeight: number;
  readonly provider: ModelProvider;
}

/** A quality check on a candidate answer — returns true if the answer is good enough (no cascade). */
export type QualityCheck = (result: GenerateResult, req: GenerateRequest) => boolean;

export interface ProviderRunOptions {
  readonly hint?: string;
  readonly qualityCheck?: QualityCheck;
  readonly refusalCheck?: QualityCheck;
  /** Exact initial provider selected by the measured cost-of-pass owner. */
  readonly preferredProviderId?: string;
  /** Provider set admitted by the same cost/quality/ceiling policy; failover cannot escape it. */
  readonly allowedProviderIds?: ReadonlySet<string>;
  /** Internal accounting hook fired immediately before a provider call can incur cost. */
  readonly onAttempt?: (providerId: string) => void;
}

export interface RouteOutcome {
  readonly result: GenerateResult;
  /** The provider id that ultimately answered. */
  readonly providerId: string;
  /** The tier that answered (may be higher than the initial pick if it cascaded). */
  readonly tier: CapabilityTier;
  /** How many cascade escalations happened (0 = the first pick sufficed). */
  readonly escalations: number;
  /** How many failover hops happened (provider outages). */
  readonly failovers: number;
}

export interface ProviderRouterOptions {
  /** Max cascade escalations before giving up (bounded — cascade is a cost multiplier). Default 2. */
  readonly maxEscalations?: number;
  /** Firewall success threshold passed to FirewallRouter. Default 0.6. */
  readonly successThreshold?: number;
  /**
   * R-EGRESS-WIRE: the egress redaction interceptor, applied to EVERY outbound provider call (hard dependency in the
   * path, not optional middleware). LOCAL providers are skipped (byte-identical); REMOTE providers get redact-before-
   * send + rehydrate-response; a blockRecommended verdict fails the call SAFE (EgressBlockedError, nothing sent).
   */
  readonly egress?: EgressFn;
}

const TIER_ORDER: readonly CapabilityTier[] = ["minimal", "lean", "standard", "rich"];

export class ProviderRouter {
  private readonly providers: RegisteredProvider[] = [];
  private readonly classifier: ComplexityClassifier;
  private readonly firewall: FirewallRouter;
  private readonly maxEscalations: number;

  /** Running escalation accounting — the SOTA "cost variable to monitor". */
  readonly stats = { routes: 0, escalations: 0, failovers: 0 };

  constructor(
    private readonly spine: Spine,
    predictor: (candidateId: string, complexity: TaskComplexity) => number,
    opts: ProviderRouterOptions = {},
  ) {
    this.classifier = new ComplexityClassifier();
    this.firewall = new FirewallRouter(predictor, opts.successThreshold ?? 0.6);
    this.maxEscalations = opts.maxEscalations ?? 2;
    const classifier = new DataClassifier();
    this.egress = opts.egress ?? ((prompt, provider) => interceptEgress(prompt, provider, { classifier, session: () => new RedactionGateway() }));
  }

  private readonly egress: EgressFn;

  /**
   * STREAM-SENDPATH: streaming send with egress. Redacts the prompt (remote), streams the response through the
   * StreamingRehydrator so a surrogate split across chunk boundaries is restored before it reaches the caller's onDelta,
   * flushes the held tail on stream end, and returns the fully-rehydrated result. Opt-in: a provider WITHOUT
   * generateStream falls back to the non-streaming run() path. LOCAL providers stream byte-identical (rehydrate is
   * identity). No mid-stream quality-cascade (a streamed response can't be un-streamed) — a single provider is chosen.
   * SEAM: LLM06 output-filtering on a streamed response runs on flush (named follow-on).
   */
  async runStream(req: GenerateRequest, onDelta?: (text: string) => void, opts: ProviderRunOptions = {}): Promise<GenerateResult> {
    const { complexity } = this.classifier.classify({ text: req.prompt, ...(opts.hint !== undefined ? { hint: opts.hint } : {}) });
    const candidates: RouteCandidate[] = this.providers.map((p) => ({ id: p.id, tier: p.tier, costWeight: p.costWeight }));
    const decision = this.firewall.route(candidates, complexity);
    let rp: RegisteredProvider | undefined;
    if (opts.preferredProviderId !== undefined) rp = this.providers.find((p) => p.id === opts.preferredProviderId && (opts.allowedProviderIds?.has(p.id) ?? true));
    else if (decision.kind === "route") rp = this.providers.find((p) => p.id === decision.candidateId && (opts.allowedProviderIds?.has(p.id) ?? true));
    rp = rp ?? this.inTier(TIER_ORDER[this.lowestAvailableTierIdx()]!).find((p) => opts.allowedProviderIds?.has(p.id) ?? true);
    if (!rp) throw new Error("no provider registered for runStream");

    // OPT-IN: a provider without streaming support uses the existing non-streaming path unchanged.
    if (!rp.provider.generateStream) {
      const outcome = await this.run(req, opts);
      onDelta?.(outcome.result.text);
      return outcome.result;
    }

    this.stats.routes++;

    const eg = this.applyEgress(req, rp.provider);
    if (eg.blocked) {
      this.spine.stage({ type: "identity.action", actor: "router", payload: { event: "egress_blocked", provider: rp.id, reason: eg.reason ?? "egress fail-safe" } });
      throw new EgressBlockedError(eg.reason ?? "egress interceptor blocked the call — failed safe, nothing sent");
    }
    // Hold all remote output until the complete response passes inbound DLP; a late or split secret
    // must not make an earlier callback irreversible.
    this.spine.stage({ type: "identity.action", actor: "router", payload: { event: "routed_stream", provider: rp.id, tier: rp.tier } });
    opts.onAttempt?.(rp.id);
    const raw = await rp.provider.generateStream(eg.outbound, () => {});
    const safe = eg.rehydrateText(raw.text);
    if (safe.length > 0) onDelta?.(safe);
    return { ...raw, text: safe };
  }

  /**
   * Apply the egress interceptor around a single outbound call. Splits the prompt at an optional `stablePrefixLen`
   * hint (so the cacheable prefix stays byte-identical); LOCAL → unchanged; REMOTE → redacted prompt + a rehydrate
   * wrapper for the response; blockRecommended → fail safe.
   */
  private applyEgress(req: GenerateRequest, provider: { readonly isLocal: boolean }): { readonly outbound: GenerateRequest; readonly rehydrate: (r: GenerateResult) => GenerateResult; readonly rehydrateText: (t: string) => string; readonly blocked: boolean; readonly reason?: string } {
    const splitAt = typeof req.hints?.["stablePrefixLen"] === "number" ? (req.hints["stablePrefixLen"] as number) : 0;
    const flow = req.hints?.["egressFlow"] as EgressFlowContext | undefined;
    const prompt: EgressPrompt = { stablePrefix: req.prompt.slice(0, splitAt), volatile: req.prompt.slice(splitAt), ...(flow ? { flow } : {}) };
    const res = this.egress(prompt, { isLocal: provider.isLocal });
    if (res.blocked) return { outbound: req, rehydrate: (r) => r, rehydrateText: (t) => t, blocked: true, ...(res.reason !== undefined ? { reason: res.reason } : {}) };
    const safeText = (text: string): string => {
      const restored = res.rehydrate(text);
      const scan = res.inspect(restored, { blockOnNovelSecret: true });
      if (scan.blockRecommended) throw new EgressBlockedError(scan.reason ?? "live output filter blocked response");
      return restored;
    };
    return { outbound: { ...req, prompt: res.outbound }, rehydrate: (r: GenerateResult): GenerateResult => ({ ...r, text: safeText(r.text) }), rehydrateText: safeText, blocked: false };
  }

  register(p: RegisteredProvider): void {
    if (this.providers.some((registered) => registered.id === p.id)) throw new Error("duplicate provider id");
    this.providers.push(p);
    this.spine.stage({ type: "identity.action", actor: "router", payload: { event: "provider_registered", id: p.id, tier: p.tier } });
  }

  /** Providers in a given tier, cheapest first. */
  private inTier(tier: CapabilityTier): RegisteredProvider[] {
    return this.providers.filter((p) => p.tier === tier).sort((a, b) => a.costWeight - b.costWeight);
  }

  /**
   * Resolve + run a request. Classifies complexity, picks the cheapest provider in the required tier
   * (via FirewallRouter), runs it, and — if a quality check is given and FAILS — cascades up one tier
   * (bounded). Provider outages (transient ProviderError after the provider's own retries) trigger
   * failover to another provider in the same tier. Every route + escalation is audited.
   */
  async run(req: GenerateRequest, opts: ProviderRunOptions = {}): Promise<RouteOutcome> {
    this.stats.routes++;
    const { complexity } = this.classifier.classify({ text: req.prompt, ...(opts.hint !== undefined ? { hint: opts.hint } : {}) });

    // Rule-first: pick the starting tier via the firewall over all registered providers as candidates.
    const candidates: RouteCandidate[] = this.providers.map((p) => ({ id: p.id, tier: p.tier, costWeight: p.costWeight }));
    const decision = this.firewall.route(candidates, complexity);
    let startTierIdx: number;
    let startProviderId: string | undefined;
    if (opts.preferredProviderId !== undefined) {
      const chosen = this.providers.find((provider) => provider.id === opts.preferredProviderId);
      if (chosen === undefined) throw new Error("cost-of-pass selected an unregistered provider");
      startProviderId = chosen.id;
      startTierIdx = TIER_ORDER.indexOf(chosen.tier);
    } else if (decision.kind === "route") {
      startProviderId = decision.candidateId;
      const chosen = this.providers.find((p) => p.id === decision.candidateId)!;
      startTierIdx = TIER_ORDER.indexOf(chosen.tier);
    } else {
      // single-model action (effort-up / self-consistency / human-handoff) → start at the lowest tier
      // that has a provider and let cascade escalate.
      startTierIdx = this.lowestAvailableTierIdx();
    }

    let escalations = 0;
    let failovers = 0;

    for (let tierIdx = startTierIdx; tierIdx < TIER_ORDER.length; tierIdx++) {
      const tier = TIER_ORDER[tierIdx]!;
      let pool = this.inTier(tier).filter((provider) => opts.allowedProviderIds?.has(provider.id) ?? true);
      // On the very first tier, prefer the firewall's chosen provider first if present.
      if (tierIdx === startTierIdx && startProviderId) {
        pool = [...pool].sort((a, b) => (a.id === startProviderId ? -1 : b.id === startProviderId ? 1 : 0));
      }
      if (pool.length === 0) continue;

      // Failover loop within the tier: try providers until one answers without an outage.
      let lastOutage: ProviderError | undefined;
      for (const rp of pool) {
        let result: GenerateResult;
        // R-EGRESS-WIRE: redact BEFORE the prompt leaves the process (remote), rehydrate the response on the way back.
        const eg = this.applyEgress(req, rp.provider);
        if (eg.blocked) {
          this.spine.stage({ type: "identity.action", actor: "router", payload: { event: "egress_blocked", provider: rp.id, tier, reason: eg.reason ?? "egress fail-safe" } });
          throw new EgressBlockedError(eg.reason ?? "egress interceptor blocked the call (high-risk + low-confidence) — failed safe, nothing sent");
        }
        try {
          opts.onAttempt?.(rp.id);
          result = eg.rehydrate(await rp.provider.generate(eg.outbound));
        } catch (err) {
          if (err instanceof ProviderError && isFailoverEligible(classifyProviderError(err.status, err.permanent))) {
            // availability failure (429 / 5xx / timeout / access-revoked 403-404) → failover to the next provider
            lastOutage = err;
            failovers++;
            this.stats.failovers++;
            this.spine.stage({ type: "identity.action", actor: "router", payload: { event: "failover", from: rp.id, tier, reason: err.message, kind: classifyProviderError(err.status, err.permanent) } });
            continue;
          }
          throw err; // client error (400/401/422) is not a failover case — fails identically elsewhere
        }

        // Quality gate: if none given, or it passes, we're done.
        if (!opts.qualityCheck || opts.qualityCheck(result, req)) {
          this.spine.stage({ type: "identity.action", actor: "router", payload: { event: "routed", provider: rp.id, tier, escalations, failovers } });
          return { result, providerId: rp.id, tier, escalations, failovers };
        }

        // Quality check FAILED. But if the answer is a policy REFUSAL, escalating to a stronger model is attempted
        // circumvention — STOP and return the refusal, never route around it (DeepInspect 2026).
        const isRefusal = (opts.refusalCheck ?? ((r: GenerateResult) => looksLikeRefusal(r.text)))(result, req);
        if (isRefusal) {
          this.spine.stage({ type: "identity.action", actor: "router", payload: { event: "policy_refusal_stop", provider: rp.id, tier } });
          return { result, providerId: rp.id, tier, escalations, failovers };
        }

        // Quality check FAILED → cascade to the next tier (bounded).
        const laterAdmittedPoolExists = TIER_ORDER.slice(tierIdx + 1).some((laterTier) =>
          this.inTier(laterTier).some((provider) => opts.allowedProviderIds?.has(provider.id) ?? true));
        if (escalations >= this.maxEscalations || !laterAdmittedPoolExists) {
          this.spine.stage({ type: "identity.action", actor: "router", payload: { event: "cascade_capped", provider: rp.id, tier, escalations } });
          return { result, providerId: rp.id, tier, escalations, failovers }; // return best-effort at the cap
        }
        escalations++;
        this.stats.escalations++;
        this.spine.stage({ type: "identity.action", actor: "router", payload: { event: "cascade_escalate", from: rp.id, fromTier: tier, escalations } });
        break; // stop trying providers in THIS tier; move up a tier
      }

      void lastOutage;
    }

    throw new ProviderError("no provider could satisfy the request (all tiers exhausted via outage/cascade)", 503, false);
  }

  private lowestAvailableTierIdx(): number {
    for (let i = 0; i < TIER_ORDER.length; i++) if (this.inTier(TIER_ORDER[i]!).length > 0) return i;
    return 0;
  }

  /** The escalation rate — SOTA says watch this; >0.3 means the cheap tier is too weak. */
  get escalationRate(): number {
    return this.stats.routes === 0 ? 0 : this.stats.escalations / this.stats.routes;
  }
}

/**
 * RoutedModelProvider — a drop-in ModelProvider that fronts a ProviderRouter, so the pipeline can use complexity→tier
 * cost-cascade routing (with same-tier failover, access-revoked failover, and the refusal-stop) as its brain. This is
 * the multi-tier / front-of-house counterpart to the free-tier-first ResilientModelProvider: routing (cost/quality) is
 * a SEPARATE layer from failover (availability) — conflating them causes incidents (truefoundry 2026) — but both
 * present the same ModelProvider port so either can be the pipeline's model.
 */
export interface RoutedModelConfig {
  readonly providers: readonly RegisteredProvider[];
  readonly predictor: (candidateId: string, complexity: TaskComplexity) => number;
  readonly qualityCheck?: QualityCheck;
  readonly refusalCheck?: QualityCheck;
  readonly routerOptions?: ProviderRouterOptions;
  /** Optional measured cost-of-pass owner. Omitted preserves the zero-configuration routing floor. */
  readonly costOfPass?: {
    readonly profiles: readonly CostOfPassModelProfile[];
    readonly policy: CostOfPassPolicy;
    readonly taskSignal?: (request: GenerateRequest) => CostOfPassTaskSignal;
    /** Required to settle a hard reservation from observed cost rather than an average estimate. */
    readonly measuredCostUsd?: (result: GenerateResult, route: BudgetAwareRoute) => number;
    /** Optional measured receipt learner; its current profiles become the next call's routing basis. */
    readonly outcomeLearning?: {
      readonly router: MeasuredOutcomeRouter;
      readonly measurementId: (result: GenerateResult, request: GenerateRequest) => string;
      readonly success: (result: GenerateResult, request: GenerateRequest) => boolean;
    };
  };
}

export class RoutedModelProvider implements ModelProvider {
  readonly name = "routed";
  readonly isLocal: boolean;
  private readonly router: ProviderRouter;
  constructor(private readonly spine: Spine, private readonly cfg: RoutedModelConfig) {
    if (cfg.providers.length === 0) throw new Error("RoutedModelProvider needs at least one provider");
    this.router = new ProviderRouter(spine, cfg.predictor, cfg.routerOptions ?? {});
    for (const p of cfg.providers) this.router.register(p);
    if (cfg.costOfPass !== undefined) {
      const ids = new Set(cfg.providers.map((provider) => provider.id));
      for (const profile of cfg.costOfPass.profiles) {
        if (!ids.has(profile.provider ?? profile.model)) throw new Error("cost-of-pass profile does not map to a registered provider");
      }
      for (const profile of cfg.costOfPass.outcomeLearning?.router.profiles() ?? []) {
        if (!ids.has(profile.provider ?? profile.model)) throw new Error("learned cost-of-pass profile does not map to a registered provider");
        if (cfg.costOfPass.policy.hardBudget !== undefined && (!Number.isFinite(profile.maxCallCostUsd) || profile.maxCallCostUsd! < 0)) throw new Error("learned hard-budget profile lacks a valid maximum call cost");
      }
      if (cfg.costOfPass.policy.hardBudget !== undefined && cfg.costOfPass.measuredCostUsd === undefined) throw new Error("hard cost-of-pass routing requires measured cost settlement");
    }
    // Air-gap / sovereignty safe only if EVERY registered provider is local.
    this.isLocal = cfg.providers.every((p) => p.provider.isLocal);
  }

  async generate(req: GenerateRequest): Promise<GenerateResult> {
    const configured = this.cfg.costOfPass;
    if (configured === undefined) {
      const outcome = await this.router.run(req, {
        ...(this.cfg.qualityCheck ? { qualityCheck: this.cfg.qualityCheck } : {}),
        ...(this.cfg.refusalCheck ? { refusalCheck: this.cfg.refusalCheck } : {}),
      });
      return outcome.result;
    }
    const signal = configured.taskSignal?.(req) ?? {
      inputSize: req.prompt.length,
      subGoalCount: 1,
      reversibilityClass: "unknown" as const,
      priorFailures: 0,
    };
    const currentProfiles = configured.outcomeLearning?.router.profiles() ?? configured.profiles;
    const route = chooseBudgetAwareRoute(signal, currentProfiles, configured.policy);
    if (route.kind !== "route") throw new ProviderError(`cost-of-pass route held: ${route.reason}`, 503, false);
    let reservationOpen = route.budgetReservationId !== null;
    let dispatchStarted = false;
    try {
      const profile = currentProfiles.find((candidate) => candidate.model === route.model)!;
      const forwardedHints = Object.fromEntries(Object.entries(req.hints ?? {}).filter(([key]) => key !== "stablePrefixLen"));
      const routedRequest: GenerateRequest = {
        ...req,
        prompt: assemblePrompt(req.prompt, profile, route.band),
        hints: Object.freeze({ ...forwardedHints, effort: route.strategy.effortApplication, timeoutClass: route.strategy.timeoutClass }),
      };
      // The cost owner admitted one exact provider/model/budget tuple. Generic failover must not silently
      // substitute another model whose measured reliability, effort knob, or reservation was not selected.
      const allowedProviderIds = new Set([route.provider]);
      const outcome = await this.router.run(routedRequest, {
        preferredProviderId: route.provider,
        allowedProviderIds,
        onAttempt: () => { dispatchStarted = true; },
        ...(this.cfg.qualityCheck ? { qualityCheck: this.cfg.qualityCheck } : {}),
        ...(this.cfg.refusalCheck ? { refusalCheck: this.cfg.refusalCheck } : {}),
      });
      if (route.budgetReservationId !== null) {
        let measured = route.reservedCostUsd!;
        try {
          const observed = configured.measuredCostUsd!(outcome.result, route);
          if (Number.isFinite(observed) && observed >= 0) measured = observed;
        } catch { /* retain the conservative reservation rather than erase observed spend */ }
        const settlement = configured.policy.hardBudget!.settle(route.budgetReservationId, measured);
        reservationOpen = false;
        if (settlement.overrunUsd > 0) this.spine.stage({ type: "identity.action", actor: "router", payload: { event: "route_budget_overrun", provider: route.provider, model: route.model, overrunUsd: settlement.overrunUsd } });
      }
      if (configured.outcomeLearning !== undefined) {
        const update = configured.outcomeLearning.router.record(route.model, route.band, {
          measurementId: configured.outcomeLearning.measurementId(outcome.result, req), basis: "executed-task",
          success: configured.outcomeLearning.success(outcome.result, req), regressed: false,
        });
        if (update.kind === "rejected") this.spine.stage({ type: "identity.action", actor: "router", payload: { event: "routing_measurement_rejected", model: route.model, reason: update.reason } });
      }
      return outcome.result;
    } catch (error) {
      if (route.budgetReservationId !== null && reservationOpen) {
        if (dispatchStarted) configured.policy.hardBudget!.settle(route.budgetReservationId, route.reservedCostUsd!);
        else configured.policy.hardBudget!.cancel(route.budgetReservationId);
      }
      throw error;
    }
  }

  /** Embeddings are tier-agnostic — try the cheapest provider first, fail over on availability errors. */
  async embed(texts: readonly string[]): Promise<Embedding[]> {
    const byCost = [...this.cfg.providers].sort((a, b) => Number(b.provider.isLocal) - Number(a.provider.isLocal) || a.costWeight - b.costWeight);
    let lastErr: unknown;
    for (const p of byCost) {
      let outbound = texts;
      const egress = this.cfg.routerOptions?.egress;
      if (egress !== undefined && !p.provider.isLocal) {
        const redacted: string[] = [];
        for (const text of texts) {
          const result = egress({ stablePrefix: "", volatile: text }, { isLocal: false });
          if (result.blocked) throw new EgressBlockedError(result.reason ?? "egress interceptor blocked embedding input");
          redacted.push(result.outbound);
        }
        outbound = redacted;
      }
      try { return await p.provider.embed(outbound); }
      catch (e) {
        lastErr = e;
        if (!(e instanceof ProviderError) || !isFailoverEligible(classifyProviderError(e.status, e.permanent))) throw e;
      }
    }
    throw new ProviderError(`all routed providers failed to embed: ${String(lastErr)}`, 503, false);
  }

  /** The escalation rate — SOTA cost variable to monitor (>0.3 means the cheap tier is too weak). */
  get escalationRate(): number { return this.router.escalationRate; }
}
