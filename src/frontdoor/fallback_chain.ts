/**
 * F1.9 — Resilient fallback chain (deterministic, health + policy aware, never hard-fails).
 *
 * Designs for the front AND back of the room: a frontier multi-model stack gets clean
 * failover; the person with a single API key or one local model gets an explicit,
 * honest contingency path that still works. The Jun 12 2026 Fable/Mythos suspension
 * showed single-model apps failing within minutes — so this handles access-revoked and
 * model-not-found, not just outages.
 *
 * Failure taxonomy (2026 SOTA): 429 / 5xx / timeout / access-revoked / quality-check
 * failure => FAILOVER-ELIGIBLE (try the next hop). A content-policy REFUSAL is NOT
 * failover-eligible — routing around a refusal is attempted policy circumvention, so
 * the chain stops. A circuit breaker skips brains that are currently unhealthy.
 *
 * The chain ALWAYS terminates: it ends at the deterministic non-LLM path (the F1 state
 * machine), so onboarding survives even total brain loss — degrade, never break.
 */

import type { BrainDescriptor } from "./brain_port.js";
import type { CapabilityRegistry, CapabilityRecord } from "./capability_registry.js";
import { isPlanningRole, type TaskRole } from "./role_router.js";

export type FailureKind = "rate-limit" | "server-error" | "timeout" | "access-revoked" | "quality-fail" | "policy-refusal" | "client-error";

/** Which failures should try the next hop vs stop the chain. */
export function isFailoverEligible(kind: FailureKind): boolean {
  // Routing around a policy refusal is circumvention; a 400-class client error (malformed/unauthorized) will fail
  // identically on the next provider, so failing over just burns quota. Everything else is availability-eligible.
  return kind !== "policy-refusal" && kind !== "client-error";
}

/**
 * Map a provider error (status + permanent flag) to a failover taxonomy. 2026 threat model: a 403/404 on a model
 * that previously worked is an access revocation / model recall (the Fable 5 recall made this a Tuesday) and IS
 * failover-eligible; a 400/401/422 is a client error that won't be fixed elsewhere; 429 rate-limit and 5xx/timeout
 * are availability failures. This is the single classifier both the router and the ladder reason over.
 */
export function classifyProviderError(status: number, permanent: boolean): FailureKind {
  if (status === 429) return "rate-limit";
  if (status === 403 || status === 404) return "access-revoked";
  if (status >= 500) return "server-error";
  if (status === 0) return "timeout"; // connect/abort/timeout surfaced with status 0
  if (status >= 400) return "client-error"; // 400/401/422 etc. — not failover-eligible
  return permanent ? "client-error" : "server-error";
}

/** A brain plus its live availability, as the chain sees it. */
export interface CandidateBrain {
  readonly brain: BrainDescriptor;
  readonly capability: CapabilityRecord;
}

export interface ChainHop {
  readonly kind: "llm" | "deterministic";
  readonly brain?: BrainDescriptor;
  readonly capability?: CapabilityRecord;
  /** True if this is planning-class work on a less-than-'rich' brain. */
  readonly degraded: boolean;
  readonly reason: string;
}

/** A simple in-memory circuit breaker: opens after N consecutive failures, half-opens after cooldown. */
export class CircuitBreaker {
  private readonly fails = new Map<string, { count: number; openedAt: number }>();
  constructor(private readonly threshold = 3, private readonly cooldownMs = 30_000) {}

  isOpen(key: string, now = Date.now()): boolean {
    const s = this.fails.get(key);
    if (!s) return false;
    if (s.count < this.threshold) return false;
    // Half-open after cooldown: allow a trial.
    if (now - s.openedAt > this.cooldownMs) return false;
    return true;
  }
  recordFailure(key: string, now = Date.now()): void {
    const s = this.fails.get(key) ?? { count: 0, openedAt: now };
    s.count += 1;
    s.openedAt = now;
    this.fails.set(key, s);
  }
  recordSuccess(key: string): void {
    this.fails.delete(key);
  }
}

/**
 * Build the ordered fallback chain for a role. Planning-class => brains ranked best
 * first (so failover keeps the strongest available). Mechanical => cheapest first
 * (economize, failover upward if the cheap one is down). Unhealthy brains (open
 * breaker) are skipped. Always appends the deterministic terminal.
 */
export function buildChain(
  role: TaskRole,
  candidates: readonly CandidateBrain[],
  breaker: CircuitBreaker,
  now = Date.now(),
): ChainHop[] {
  const planning = isPlanningRole(role);
  const healthy = candidates.filter((c) => !breaker.isOpen(keyOf(c), now));
  const ordered = [...healthy].sort((a, b) =>
    planning ? b.capability.score - a.capability.score : a.capability.score - b.capability.score,
  );

  const hops: ChainHop[] = ordered.map((c, i) => {
    const degraded = planning && c.capability.tier !== "rich";
    return {
      kind: "llm" as const,
      brain: c.brain,
      capability: c.capability,
      degraded,
      reason:
        i === 0
          ? planning
            ? degraded
              ? `Planning: best available is ${c.brain.providerLabel} (${c.capability.tier}) — doing our best; plan quality is capped by the available model.`
              : `Planning: routed to the best available brain (${c.brain.providerLabel}).`
            : `Routine work: routed to ${c.brain.providerLabel} (${c.capability.tier}).`
          : `Fallback #${i}: ${c.brain.providerLabel} (${c.capability.tier}) if the preferred brain is unavailable.`,
    };
  });

  // Terminal: the deterministic non-LLM path — onboarding survives total brain loss.
  hops.push({
    kind: "deterministic",
    degraded: planning, // if we reached here for planning, quality is maximally degraded
    reason:
      "Last resort: continue with the built-in guided flow (no model needed) so you're never stuck. It's simpler, still safe, and I'll pick a model back up as soon as one is available.",
  });
  return hops;
}

/** The result of attempting one hop, provided by the caller's executor. */
export type HopAttempt = (hop: ChainHop) => Promise<{ ok: true; output: unknown } | { ok: false; failure: FailureKind }>;

export interface WalkResult {
  readonly succeededAt?: ChainHop;
  readonly output?: unknown;
  /** Every hop attempted, with its outcome — the explicit, audited trail. */
  readonly trail: readonly { hop: ChainHop; outcome: "ok" | FailureKind | "stopped-policy" | "skipped" }[];
}

/**
 * Walk the chain: attempt each hop in order; on a failover-eligible failure, record the
 * breaker failure and try the next; on a policy refusal, STOP (no circumvention); the
 * deterministic terminal always "succeeds" (it needs no model). Never throws.
 */
export async function walkChain(
  hops: readonly ChainHop[],
  attempt: HopAttempt,
  breaker: CircuitBreaker,
  now = Date.now(),
): Promise<WalkResult> {
  const trail: { hop: ChainHop; outcome: "ok" | FailureKind | "stopped-policy" | "skipped" }[] = [];
  for (const hop of hops) {
    if (hop.kind === "deterministic") {
      trail.push({ hop, outcome: "ok" });
      return { succeededAt: hop, output: undefined, trail };
    }
    const res = await attempt(hop);
    if (res.ok) {
      if (hop.brain) breaker.recordSuccess(hop.brain.providerLabel + (hop.brain.model ?? ""));
      trail.push({ hop, outcome: "ok" });
      return { succeededAt: hop, output: res.output, trail };
    }
    // A policy refusal stops the chain — failing over would be circumvention.
    if (!isFailoverEligible(res.failure)) {
      trail.push({ hop, outcome: "stopped-policy" });
      return { trail };
    }
    if (hop.brain) breaker.recordFailure(hop.brain.providerLabel + (hop.brain.model ?? ""), now);
    trail.push({ hop, outcome: res.failure });
  }
  return { trail };
}

function keyOf(c: CandidateBrain): string {
  return c.brain.providerLabel + (c.brain.model ?? "");
}
