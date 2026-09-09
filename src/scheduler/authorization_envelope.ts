/**
 * Scheduler + Envelope: AuthorizationEnvelope + BudgetLedger (Increment 7a).
 *
 * SOTA basis (2026-08-04): runaway agents are a documented, expensive failure — a 4-agent loop
 * burned $47K over 11 days because the team "had observability, not enforcement" (Waxell 2026); the
 * fix is a HARD STOP before the next call, at the gateway layer, that the LLM cannot override
 * (SupraWall: "no exceptions, no overrides, no matter what the LLM requests"). A daily cap alone is
 * insufficient ("$500/month still allows burning $500 in 20 minutes" — aisecuritygateway), so caps
 * are DAILY + PER-RUN + per-call-token-ceiling, three independent bounds. Caps are USER-DIRECTED:
 * granted once via the F2 directive path, never an assumed number.
 *
 * This module is the model + accounting. The MeteredGateway (7b) is the enforcement point; the
 * Scheduler (7c) runs envelope-gated cadence. Spend accounting REUSES the existing CostModel — it
 * does not reinvent pricing. Zero deps.
 */

import type { Spine } from "../spine/spine.js";
import type { CostModel, TokenUsage } from "../observability/cost_model.js";

/** The classes of machine-directed loop an envelope may authorize. */
export type LoopClass = "auto-research" | "auto-rag" | "auto-learning" | "auto-training";

/** Coarse model tiers an envelope may restrict to (dev keys → cheap tiers — aisecuritygateway). */
export type ModelTier = "local" | "small" | "frontier";

/** The one-time authorization grant: a class + budget + expiry, revisable, revocable. */
export interface AuthorizationEnvelope {
  readonly id: string;
  readonly projectId: string;
  /** Which loop classes this envelope authorizes to run unattended. */
  readonly allowedClasses: readonly LoopClass[];
  /** Which model tiers may be called under it (empty = any). */
  readonly allowedTiers: readonly ModelTier[];
  /** Hard daily spend ceiling (USD) — bounds a runaway to one small day. */
  readonly dailyCapUsd: number;
  /** Hard per-run spend ceiling (USD) — bounds a single scheduled run. */
  readonly perRunCapUsd: number;
  /** Per-call output-token ceiling (a single response can't run to 8k+ — RelayPlane). */
  readonly perCallTokenCeiling: number;
  /** Expiry (epoch ms). After this, the envelope no longer authorizes anything. */
  readonly expiresAt: number;
  /** Granting justification (audit). */
  readonly grantedReason: string;
}

/** A spend record within a single scheduled run. */
export interface RunSpend {
  readonly runId: string;
  readonly envelopeId: string;
  spentUsd: number;
  calls: number;
  readonly dayKey: string; // YYYY-MM-DD for the daily rollup
}

export type BreachKind = "expired" | "class-not-authorized" | "tier-not-authorized" | "per-run-cap" | "daily-cap" | "token-ceiling";

export interface BreachCheck {
  readonly wouldBreach: boolean;
  readonly kind?: BreachKind;
  readonly reason?: string;
}

/** Deterministic day key (UTC) for daily rollups. */
function dayKeyOf(now: number): string {
  return new Date(now).toISOString().slice(0, 10);
}

/**
 * Tracks real spend per envelope, per run and per day, and answers the deterministic willBreach()
 * predicate the gateway consults BEFORE each call. Spend is computed via the injected CostModel.
 */
export class BudgetLedger {
  private readonly envelopes = new Map<string, AuthorizationEnvelope>();
  private readonly runs = new Map<string, RunSpend>();
  /** envelopeId → dayKey → spentUsd */
  private readonly daily = new Map<string, Map<string, number>>();

  constructor(
    private readonly spine: Spine,
    private readonly costModel: CostModel,
    private readonly clock: () => number = () => Date.now(),
  ) {}

  /** Register (grant) an envelope — the one-time authorization. Audited. */
  grant(env: AuthorizationEnvelope): void {
    this.envelopes.set(env.id, env);
    this.spine.stage({
      type: "identity.action",
      actor: "scheduler",
      payload: { event: "envelope_granted", envelopeId: env.id, projectId: env.projectId, dailyCapUsd: env.dailyCapUsd, perRunCapUsd: env.perRunCapUsd, expiresAt: env.expiresAt, reason: env.grantedReason },
    });
  }

  /** Revoke an envelope (operator stays in control). */
  revoke(envelopeId: string, reason: string): void {
    this.envelopes.delete(envelopeId);
    this.spine.stage({ type: "identity.action", actor: "scheduler", payload: { event: "envelope_revoked", envelopeId, reason } });
  }

  getEnvelope(id: string): AuthorizationEnvelope | undefined {
    return this.envelopes.get(id);
  }

  /** Begin a run under an envelope — mints a RunSpend accumulator. */
  beginRun(runId: string, envelopeId: string): RunSpend {
    const now = this.clock();
    const run: RunSpend = { runId, envelopeId, spentUsd: 0, calls: 0, dayKey: dayKeyOf(now) };
    this.runs.set(runId, run);
    return run;
  }

  /**
   * Would a call of the given class/tier and projected usage BREACH the envelope? Checked BEFORE the
   * call (enforcement, not alerting). Deterministic — the LLM cannot influence this.
   */
  willBreach(runId: string, cls: LoopClass, tier: ModelTier, model: string, projected: TokenUsage): BreachCheck {
    const run = this.runs.get(runId);
    if (!run) return { wouldBreach: true, kind: "per-run-cap", reason: `no run ${runId}` };
    const env = this.envelopes.get(run.envelopeId);
    if (!env) return { wouldBreach: true, kind: "expired", reason: "envelope revoked/absent" };

    const now = this.clock();
    if (now > env.expiresAt) return { wouldBreach: true, kind: "expired", reason: `envelope expired at ${new Date(env.expiresAt).toISOString()}` };
    if (!env.allowedClasses.includes(cls)) return { wouldBreach: true, kind: "class-not-authorized", reason: `class ${cls} not in envelope` };
    if (env.allowedTiers.length > 0 && !env.allowedTiers.includes(tier)) return { wouldBreach: true, kind: "tier-not-authorized", reason: `tier ${tier} not authorized` };
    if (projected.outputTokens > env.perCallTokenCeiling) return { wouldBreach: true, kind: "token-ceiling", reason: `projected ${projected.outputTokens} output tokens > ceiling ${env.perCallTokenCeiling}` };

    const callCost = this.costModel.cost(model, projected).totalUsd;
    if (run.spentUsd + callCost > env.perRunCapUsd) return { wouldBreach: true, kind: "per-run-cap", reason: `run spend ${(run.spentUsd + callCost).toFixed(4)} > per-run cap ${env.perRunCapUsd}` };

    const dayMap = this.daily.get(env.id);
    const spentToday = dayMap?.get(dayKeyOf(now)) ?? 0;
    if (spentToday + callCost > env.dailyCapUsd) return { wouldBreach: true, kind: "daily-cap", reason: `daily spend ${(spentToday + callCost).toFixed(4)} > daily cap ${env.dailyCapUsd}` };

    return { wouldBreach: false };
  }

  /** Record actual spend AFTER a call succeeds (updates run + daily rollups). Audited. */
  recordSpend(runId: string, model: string, usage: TokenUsage): number {
    const run = this.runs.get(runId);
    if (!run) throw new Error(`no run ${runId}`);
    const env = this.envelopes.get(run.envelopeId);
    const cost = this.costModel.cost(model, usage).totalUsd;
    run.spentUsd += cost;
    run.calls++;
    if (env) {
      const now = this.clock();
      const key = dayKeyOf(now);
      let dayMap = this.daily.get(env.id);
      if (!dayMap) { dayMap = new Map(); this.daily.set(env.id, dayMap); }
      dayMap.set(key, (dayMap.get(key) ?? 0) + cost);
    }
    return cost;
  }

  runSpend(runId: string): RunSpend | undefined {
    return this.runs.get(runId);
  }

  dailySpend(envelopeId: string, now = this.clock()): number {
    return this.daily.get(envelopeId)?.get(dayKeyOf(now)) ?? 0;
  }
}
