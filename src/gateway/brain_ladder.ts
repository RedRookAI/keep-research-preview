/**
 * BrainLadder (Increment 16.9d) — free-tier-aware graceful degradation for the compute plane (the brain).
 *
 * The back-of-the-room operator runs on a rate-limited free tier. A 429 or a brief outage must be treated
 * as BACK OFF + try the next option, not as a crash. This is an ordered ladder of brain "rungs" (e.g.
 * free-model-A → free-model-B → local-if-present). On a rate-limit/transient failure it advances down the
 * ladder honoring backoff; on a circuit-open rung it skips; on full exhaustion it returns a GRACEFUL DEFER
 * outcome so the caller can pause the (budget-resumable) ProjectLoop instead of failing.
 *
 * SOTA basis (2026-08-05): layered resilience = circuit breakers + fallback chains + graceful degradation
 * from zero-dep primitives (zylos 2026; dev.to). The free-tier 429/quota exhaustion is THE named failure;
 * the fix is a gateway fallback chain — "429 is not a crash, it's the gateway telling the agent to back
 * off" (truefoundry 2026). Progressive fallback layers keep ~95% functionality (hendricks 2026). KEY SAFETY
 * RULE: switch brains only when the fallback preserves the SAME interface AND SAFETY ENVELOPE (buildmvpfast
 * 2026) — this ladder chooses WHICH brain; it NEVER relaxes the deterministic floors.
 *
 * Zero deps. Builds on ProviderError (status/permanent) + the KillSwitch circuit breaker.
 */

import type { ModelProvider, GenerateRequest, GenerateResult } from "./gateway.js";

/** One rung of the ladder: a brain option, tagged for cost-awareness. */
export interface BrainRung {
  readonly id: string;
  readonly provider: ModelProvider;
  /** "free" rungs are tried first for the free-tier operator; "local" is the last-resort in-box rung. */
  readonly cost: "free" | "paid" | "local";
}

/** A minimal circuit-breaker check (satisfied by KillSwitch.checkCircuitBreaker-style logic). */
export interface CircuitCheck {
  /** True if this rung's circuit is OPEN (too many recent failures) → skip it. */
  isOpen(rungId: string): boolean;
  /** Record a failure for this rung (feeds the breaker). */
  recordFailure(rungId: string): void;
  /** Record a success (may close the breaker). */
  recordSuccess(rungId: string): void;
}

export interface LadderAttempt {
  readonly rungId: string;
  readonly outcome: "ok" | "rate-limited" | "transient-error" | "circuit-open" | "permanent-error";
  readonly detail?: string;
}

export type LadderResult =
  | { readonly status: "ok"; readonly rungId: string; readonly result: GenerateResult; readonly attempts: readonly LadderAttempt[] }
  | { readonly status: "deferred"; readonly reason: string; readonly attempts: readonly LadderAttempt[]; readonly retryAfterMs?: number };

export interface BrainLadderOptions {
  readonly circuit?: CircuitCheck;
  /** Sleep hook (injectable for tests). Default: real timer. */
  readonly sleep?: (ms: number) => Promise<void>;
  /** Cap on total backoff waited across the whole ladder before deferring. Default 30s. */
  readonly maxTotalBackoffMs?: number;
  /** Base for exponential backoff before advancing to the next rung. Default 250ms. */
  readonly baseBackoffMs?: number;
  /** Randomness source for FULL JITTER (injectable for deterministic tests). Default Math.random. */
  readonly rng?: () => number;
}

/** Shape of the ProviderError we recognize (status + permanent), without importing the class. */
interface ProviderErrorLike { status: number; permanent: boolean; retryAfterMs?: number; message?: string; }
function asProviderError(e: unknown): ProviderErrorLike | null {
  if (e && typeof e === "object" && "status" in e && "permanent" in e) return e as ProviderErrorLike;
  return null;
}

/**
 * Try the ladder in order. Free rungs first. A 429/transient error advances to the next rung (honoring
 * backoff, capped); a circuit-open rung is skipped; a permanent error on a rung is not retried on THAT rung
 * but the ladder continues. On exhaustion, returns a graceful "deferred" outcome (never throws for
 * capacity reasons). The caller runs the SAME safety floors on whichever rung succeeds.
 */
export class BrainLadder {
  private readonly rungs: readonly BrainRung[];
  private readonly circuit: CircuitCheck | undefined;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly maxTotalBackoffMs: number;
  private readonly baseBackoffMs: number;
  private readonly rng: () => number;

  constructor(rungs: readonly BrainRung[], opts: BrainLadderOptions = {}) {
    // Free-tier-first ordering: free rungs, then local, then paid (never surprise the operator with cost).
    this.rungs = [...rungs].sort((a, b) => costOrder(a.cost) - costOrder(b.cost));
    this.circuit = opts.circuit;
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.maxTotalBackoffMs = opts.maxTotalBackoffMs ?? 30_000;
    this.baseBackoffMs = opts.baseBackoffMs ?? 250;
    this.rng = opts.rng ?? Math.random;
  }

  async generate(req: GenerateRequest): Promise<LadderResult> {
    const attempts: LadderAttempt[] = [];
    let totalBackoff = 0;
    let lastRetryAfter: number | undefined;
    let failureCount = 0;
    // FULL JITTER exponential backoff before advancing (AWS: reduces retry storms 60-80%). Because we advance to a
    // DIFFERENT rung, the leaving rung's Retry-After does not gate this wait (it's a different provider); the wait's
    // job is to de-synchronize concurrent agents advancing in lockstep. Retry-After IS surfaced in the defer result
    // so the caller knows when the rate-limited rungs might recover.
    const backoff = (): number => {
      const expo = Math.min(this.baseBackoffMs * 2 ** failureCount, this.maxTotalBackoffMs);
      return Math.min(this.rng() * expo, this.maxTotalBackoffMs - totalBackoff);
    };

    for (const [i, rung] of this.rungs.entries()) {
      const isLast = i === this.rungs.length - 1;
      if (this.circuit?.isOpen(rung.id)) {
        attempts.push({ rungId: rung.id, outcome: "circuit-open" });
        continue; // skip a rung whose breaker is open
      }
      try {
        const result = await rung.provider.generate(req);
        this.circuit?.recordSuccess(rung.id);
        attempts.push({ rungId: rung.id, outcome: "ok" });
        return { status: "ok", rungId: rung.id, result, attempts };
      } catch (e) {
        const pe = asProviderError(e);
        this.circuit?.recordFailure(rung.id);
        if (pe && pe.status === 429) {
          // Rate-limited: 429 is not a crash — jittered back off, then advance to the NEXT rung.
          lastRetryAfter = pe.retryAfterMs ?? lastRetryAfter;
          attempts.push({ rungId: rung.id, outcome: "rate-limited", detail: `retryAfterMs=${pe.retryAfterMs ?? "n/a"}` });
          if (!isLast) { const wait = backoff(); failureCount++; if (wait > 0) { await this.sleep(wait); totalBackoff += wait; } }
          continue;
        }
        if (pe && pe.permanent) {
          // Permanent error on this rung (e.g. 400) → won't recover by waiting; advance immediately, no backoff.
          attempts.push({ rungId: rung.id, outcome: "permanent-error", ...(pe.message ? { detail: pe.message } : {}) });
          continue;
        }
        // Transient/5xx/unknown error → jittered back off (de-sync), then try the next rung.
        attempts.push({ rungId: rung.id, outcome: "transient-error", detail: pe?.message ?? String(e) });
        if (!isLast) { const wait = backoff(); failureCount++; if (wait > 0) { await this.sleep(wait); totalBackoff += wait; } }
        continue;
      }
    }

    // Ladder exhausted → GRACEFUL DEFER (the caller pauses the budget-resumable loop; floors still operate).
    return {
      status: "deferred",
      reason: "all brain rungs exhausted (rate-limited / unavailable) — deferring; will resume when capacity returns",
      attempts,
      ...(lastRetryAfter !== undefined ? { retryAfterMs: lastRetryAfter } : {}),
    };
  }
}

function costOrder(c: BrainRung["cost"]): number {
  return c === "free" ? 0 : c === "local" ? 1 : 2; // free → local → paid
}
