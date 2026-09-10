/**
 * MeteredGateway reserves projected token cost through the durable BudgetLedger.
 * Prices, projection and provider results are trusted inputs with explicit limits.
 * The repetition check runs before admission; the rate check runs after settlement.
 * See docs/monetary-accounting.md for route coverage and migration behavior.
 */

import type { ModelGateway, GenerateRequest, GenerateResult } from "../gateway/gateway.js";
import type { Spine } from "../spine/spine.js";
import type { BudgetLedger, LoopClass, ModelTier, BreachKind } from "./authorization_envelope.js";
import type { TokenUsage } from "../observability/cost_model.js";

/** A refused admission or a post-call velocity stop. Retrying does not clear ledger state. */
export class BudgetExceeded extends Error {
  constructor(
    readonly kind: BreachKind | "velocity",
    reason: string,
    readonly runId: string,
  ) {
    super(`budget enforcement (${kind}): ${reason}`);
    this.name = "BudgetExceeded";
  }
}

/** Context that scopes a metered call to a run + envelope + class/tier + projected usage. */
export interface MeteredCallContext {
  readonly runId: string;
  readonly cls: LoopClass;
  readonly tier: ModelTier;
  /** Projected usage for the pre-call breach check (real usage recorded after). */
  readonly projected: TokenUsage;
}

export interface VelocityThresholds {
  /** Max USD/minute rate before the breaker trips (rate, not total). */
  readonly maxUsdPerMinute: number;
  /** Max identical consecutive prompts before the repetitive-loop breaker trips. */
  readonly maxRepeatedIdentical: number;
}

const DEFAULT_VELOCITY: VelocityThresholds = { maxUsdPerMinute: 5, maxRepeatedIdentical: 5 };

/**
 * Process-local repetition and reported-spend-rate checks, separate from durable
 * cumulative accounting. Rate detection cannot prevent costs already incurred.
 */
export class TokenVelocityBreaker {
  private readonly window: Array<{ ts: number; usd: number }> = [];
  private lastPrompt: string | undefined;
  private repeatCount = 0;
  private tripped = false;
  private readonly t: VelocityThresholds;

  constructor(
    private readonly spine: Spine,
    thresholds: Partial<VelocityThresholds> = {},
    private readonly clock: () => number = () => Date.now(),
  ) {
    this.t = { ...DEFAULT_VELOCITY, ...thresholds };
  }

  get isTripped(): boolean {
    return this.tripped;
  }

  /** Check BEFORE a call: repetitive identical prompt burst (leading loop signal). */
  checkRepetition(prompt: string): void {
    if (this.tripped) throw new Error("velocity breaker already tripped");
    if (prompt === this.lastPrompt) {
      this.repeatCount++;
    } else {
      this.lastPrompt = prompt;
      this.repeatCount = 1;
    }
    if (this.repeatCount >= this.t.maxRepeatedIdentical) {
      this.trip("repeated-identical", `${this.repeatCount} identical consecutive prompts — loop detected`);
    }
  }

  /** Record spend AFTER a call and check the rate window. */
  recordAndCheckRate(usd: number): void {
    const now = this.clock();
    this.window.push({ ts: now, usd });
    const cutoff = now - 60_000;
    while (this.window.length > 0 && this.window[0]!.ts < cutoff) this.window.shift();
    const usdLastMinute = this.window.reduce((s, e) => s + e.usd, 0);
    if (usdLastMinute > this.t.maxUsdPerMinute) {
      this.trip("rate-of-spend", `$${usdLastMinute.toFixed(2)}/min > $${this.t.maxUsdPerMinute}/min`);
    }
  }

  private trip(kind: string, reason: string): never {
    this.tripped = true;
    this.spine.stage({ type: "identity.action", actor: "scheduler", payload: { event: "velocity_breaker_tripped", kind, reason } });
    throw new BudgetExceeded("velocity", `${kind}: ${reason}`, "velocity");
  }

  reset(justification: string): void {
    this.spine.stage({ type: "identity.action", actor: "scheduler", payload: { event: "velocity_breaker_reset", justification } });
    this.tripped = false;
    this.window.length = 0;
    this.repeatCount = 0;
    this.lastPrompt = undefined;
  }
}

/**
 * The enforcement gateway. Wraps a ModelGateway; every metered generate() consults the ledger
 * BEFORE the call and hard-stops (throws BudgetExceeded) if a cap would breach — no override. On
 * success, records real spend to the ledger + the velocity breaker. Unmetered generate() (the
 * interactive, human-attended path) passes straight through — enforcement is for UNATTENDED loops.
 */
export class MeteredGateway {
  constructor(
    private readonly inner: ModelGateway,
    private readonly ledger: BudgetLedger,
    private readonly breaker: TokenVelocityBreaker,
    private readonly spine: Spine,
  ) {}

  get providerName(): string {
    return this.inner.providerName;
  }

  /** The human-attended path — no envelope enforcement (the operator is present). */
  generate(req: GenerateRequest): Promise<GenerateResult> {
    return this.inner.generate(req);
  }

  /**
   * Reserve projected exposure before entry. Entered failures retain their reservation.
   * A post-call rate breach can occur after delivered work; it is not a pre-dispatch refusal.
   */
  async generateMetered(req: GenerateRequest, ctx: MeteredCallContext, model: string): Promise<GenerateResult> {
    const request = Object.freeze({ ...req, maxTokens: req.maxTokens ?? ctx.projected.outputTokens, maxAttempts: 1 });
    if (!Number.isSafeInteger(request.maxTokens) || request.maxTokens < 0 || request.maxTokens > ctx.projected.outputTokens) throw new BudgetExceeded("token-ceiling", "effective request exceeds its projection", ctx.runId);
    request.signal?.throwIfAborted();
    if (this.breaker.isTripped) {
      throw new BudgetExceeded("velocity", "breaker already tripped — awaiting human reset", ctx.runId);
    }
    // Leading signal: repetitive-identical-call burst (checked before spend).
    this.breaker.checkRepetition(request.prompt);

    // Admission includes pending reservations in the configured shared lock domain.
    const { breach, reservation } = await this.ledger.reserve(ctx.runId, ctx.cls, ctx.tier, model, ctx.projected);
    if (breach.wouldBreach) {
      this.spine.stage({ type: "identity.action", actor: "scheduler", payload: { event: "call_hard_stopped", runId: ctx.runId, kind: breach.kind, reason: breach.reason } });
      throw new BudgetExceeded(breach.kind!, breach.reason!, ctx.runId);
    }

    if (!reservation) throw new Error("monetary admission returned no reservation");
    if (request.signal?.aborted) {
      await this.ledger.voidBeforeDispatch(reservation.id);
      request.signal.throwIfAborted();
    }
    // An exception after this boundary cannot establish that no provider work occurred.
    const result = await this.inner.generate(request);
    if (result.usageComplete === false) throw new Error("provider usage incomplete; monetary reservation remains unresolved");

    const usage: TokenUsage = { freshInputTokens: result.tokensIn, cachedInputTokens: 0, outputTokens: result.tokensOut };
    const cost = await this.ledger.settle(reservation.id, usage);
    this.breaker.recordAndCheckRate(cost);
    return result;
  }
}
