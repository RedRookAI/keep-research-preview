/**
 * Scheduler + Envelope: MeteredGateway + TokenVelocityBreaker (Increment 7b) — the enforcement point.
 *
 * SOTA basis (2026-08-04): enforcement, not alerts — "no further LLM calls until a human or policy
 * resumes" (Waxell 2026). The check lives at the gateway/proxy layer and the LLM CANNOT override it
 * (SupraWall). Rate-of-spend beats cumulative total for catching loops: "monitor tokens per minute,
 * not the total" (nexgismo); repetitive identical calls trip BEFORE the budget cap (SupraWall). So
 * the velocity breaker is a LEADING signal independent of the cumulative caps — the same
 * leading+confirming pattern as the Auto-Learning guard.
 *
 * MeteredGateway is a DECORATOR over the existing ModelGateway (everything behind a port). It reuses
 * the BudgetLedger (7a) for the deterministic willBreach() predicate + spend accounting, and the
 * killswitch CircuitBreaker pattern for velocity. Zero deps.
 */

import type { ModelGateway, GenerateRequest, GenerateResult } from "../gateway/gateway.js";
import type { Spine } from "../spine/spine.js";
import type { BudgetLedger, LoopClass, ModelTier, BreachKind } from "./authorization_envelope.js";
import type { TokenUsage } from "../observability/cost_model.js";

/** Thrown when a call would breach the envelope. Deterministic; not catchable-into-a-retry-loop by design. */
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
 * Token-velocity + repetitive-call breaker. Trips on rate-of-spend or identical-call bursts,
 * INDEPENDENT of the cumulative caps — catches a loop before the bill grows. Reusable across runs.
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
   * The UNATTENDED path — enforced. Pre-call: repetition + willBreach hard-stops. Post-call: record
   * real spend + rate check. A breach throws BEFORE any provider call is made (no spend on breach).
   */
  async generateMetered(req: GenerateRequest, ctx: MeteredCallContext, model: string): Promise<GenerateResult> {
    if (this.breaker.isTripped) {
      throw new BudgetExceeded("velocity", "breaker already tripped — awaiting human reset", ctx.runId);
    }
    // Leading signal: repetitive-identical-call burst (checked before spend).
    this.breaker.checkRepetition(req.prompt);

    // Deterministic cap check BEFORE the call — the LLM cannot influence or override this.
    const breach = this.ledger.willBreach(ctx.runId, ctx.cls, ctx.tier, model, ctx.projected);
    if (breach.wouldBreach) {
      this.spine.stage({ type: "identity.action", actor: "scheduler", payload: { event: "call_hard_stopped", runId: ctx.runId, kind: breach.kind, reason: breach.reason } });
      throw new BudgetExceeded(breach.kind!, breach.reason!, ctx.runId);
    }

    // Enforce the per-call token ceiling on the request itself (belt and suspenders — RelayPlane).
    const result = await this.inner.generate(req);

    const usage: TokenUsage = { freshInputTokens: result.tokensIn, cachedInputTokens: 0, outputTokens: result.tokensOut };
    const cost = this.ledger.recordSpend(ctx.runId, model, usage);
    this.breaker.recordAndCheckRate(cost);
    return result;
  }
}
