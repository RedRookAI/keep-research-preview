/**
 * ResilientModelProvider (Increment 12e/16.9d-wire) — makes the pipeline's brain resilient by wrapping an ordered
 * ladder of model providers behind the standard ModelProvider port. A rate-limit (429), transient error, or brief
 * outage on one rung backs off and advances to the next; an open circuit skips a sick rung; on full exhaustion it
 * degrades gracefully (a transient, budget-resumable error) instead of crashing. This is the "laptop in Africa on
 * one free-tier key" case: a 429 is a back-off signal, not a dead end.
 *
 * SOTA basis (2026-08-07): a single-provider integration is a single point of failure (repeated 2024–2026 outages);
 * fail over on availability errors (429/5xx/timeout), honoring Retry-After; free-tier-first ordering never surprises
 * the operator with cost; graceful degradation keeps functionality when capacity returns. CROWN-JEWEL SAFETY RULE: a
 * content-policy refusal must NOT be routed around to another model — that is attempted policy circumvention. In
 * Keep, refusals surface as TEXT output (the model says "I can't help"), which the ladder returns as a success and
 * this wrapper passes through UNCHANGED — so no failover-around-a-refusal can occur. (A provider that instead raised
 * a refusal as an error is handled by the richer fallback_chain taxonomy, the next wire in this cluster.)
 *
 * Drop-in: it implements ModelProvider, so anything taking a model gets resilience with no other change.
 */

import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "./gateway.js";
import { ProviderError } from "./http_provider.js";
import { BrainLadder, type BrainRung, type BrainLadderOptions, type CircuitCheck } from "./brain_ladder.js";
import { CircuitBreaker } from "../frontdoor/fallback_chain.js";
import type { Spine } from "../spine/spine.js";

export class ResilientModelProvider implements ModelProvider {
  readonly name = "resilient";
  /** Air-gap / sovereignty safe ONLY if every rung is local (no rung can egress). */
  readonly isLocal: boolean;
  private readonly ladder: BrainLadder;
  private readonly rungs: readonly BrainRung[];

  constructor(rungs: readonly BrainRung[], opts: BrainLadderOptions = {}, private readonly spine?: Spine) {
    if (rungs.length === 0) throw new Error("ResilientModelProvider needs at least one rung");
    this.rungs = rungs;
    // Persistent circuit breaker (keyed per rung) so a dead rung FAST-FAILS across generate() calls instead of
    // being re-hammered on every request ("a dead provider stops eating latency on every request"). Reuses the
    // fallback_chain CircuitBreaker; caller can override via opts.circuit.
    const breaker = new CircuitBreaker();
    const circuit: CircuitCheck = opts.circuit ?? {
      isOpen: (id) => breaker.isOpen(id),
      recordFailure: (id) => breaker.recordFailure(id),
      recordSuccess: (id) => breaker.recordSuccess(id),
    };
    this.ladder = new BrainLadder(rungs, { ...opts, circuit });
    this.isLocal = rungs.every((r) => r.provider.isLocal);
  }

  async generate(req: GenerateRequest): Promise<GenerateResult> {
    const res = await this.ladder.generate(req);
    if (res.status === "ok") {
      this.audit({ event: "brain_ladder.ok", rung: res.rungId, attempts: res.attempts.length });
      return res.result; // includes a policy-refusal-as-text, passed through UNCHANGED — never routed around
    }
    // Exhaustion → graceful defer. Surface as a transient (non-permanent) error so the solve gives up gracefully
    // and the budget-resumable loop can retry when capacity returns — not a crash, not a silent wrong answer.
    this.audit({ event: "brain_ladder.deferred", reason: res.reason, attempts: res.attempts.length, ...(res.retryAfterMs !== undefined ? { retryAfterMs: res.retryAfterMs } : {}) });
    throw new ProviderError(`brains exhausted — deferring (resumable): ${res.reason}`, 503, false);
  }

  /** Embeddings fail over across rungs too (first success wins); all-fail surfaces as a resumable error. */
  async embed(texts: readonly string[]): Promise<Embedding[]> {
    let lastErr: unknown;
    for (const rung of this.rungs) {
      try { return await rung.provider.embed(texts); }
      catch (e) { lastErr = e; }
    }
    throw new ProviderError(`all rungs failed to embed (resumable): ${String(lastErr)}`, 503, false);
  }

  private audit(payload: Record<string, unknown>): void {
    this.spine?.stage({ type: "identity.action", actor: "resilient-brain", payload: { ...payload, ts: Date.now() } });
  }
}
