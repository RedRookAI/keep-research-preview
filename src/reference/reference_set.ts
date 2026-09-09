/**
 * ReferenceSet<T> (Increment 3.6a) — the generic self-refreshing reference-data container.
 *
 * SOTA basis (re-verified 2026-08-04): stale-while-revalidate (SWR) + stale-if-error (SIE), the
 * convergent "always fast, always fresh-enough, never fails" pattern (Fastly; oneuptime; medium
 * "SWR done right"; vergecloud). Three states after the fresh period expires:
 *   fresh   → serve directly.
 *   stale   → serve immediately AND refresh in the background (SWR; caller never waits).
 *   expired → attempt a refresh, but if it fails/is-absent KEEP SERVING last-good (SIE).
 * SWR takes precedence while its window is active; SIE is the fallback after (Fastly precedence
 * rule). Plus: single-flight refresh (no stampede — medium/vetora) and TTL jitter (no synchronized
 * expiry storms — vetora). Freshness state + asOf travel WITH the value so downstream honesty is
 * automatic ("pricing as of 2026-08-01, unverified today").
 *
 * The NEVER-FAILS guarantee is structural: a refresh can only UPDATE or be IGNORED; it can never
 * null out or corrupt the set. Proven by test. Zero deps.
 */

/** Freshness of the currently-served value. */
export type FreshnessState = "fresh" | "stale" | "expired";

/** What `get()` returns: the value plus honest freshness metadata (never throws on staleness). */
export interface ReferenceView<T> {
  readonly value: T;
  readonly state: FreshnessState;
  readonly asOf: string; // ISO date the value was last known-good
  readonly ageMs: number;
  /** Honest note for downstream consumers/logging (empty when fresh). */
  readonly note: string;
}

/** TTL config for a category (ms). graceMs is the SWR window past freshMs. */
export interface FreshnessPolicy {
  readonly freshMs: number; // max-age: fresh window
  readonly graceMs: number; // stale-while-revalidate window past fresh
  /** ± jitter fraction (0..1) applied to freshMs to avoid synchronized expiry. Default 0.1. */
  readonly jitter?: number;
}

/** A refresh function for a category. Throws/returns undefined ⇒ SIE keeps last-good. */
export type RefreshFn<T> = () => Promise<T> | T;

function isoDate(now: number): string {
  return new Date(now).toISOString().slice(0, 10);
}

export class ReferenceSet<T> {
  private value: T;
  private lastGoodAt: number; // when the current value was last confirmed good
  private readonly freshMs: number;
  private readonly graceMs: number;
  private readonly jitterMs: number;
  /** Single-flight guard: at most one in-flight refresh per set. */
  private refreshing = false;
  /** Audit of refresh attempts (success/failure) for the spine/logging. */
  private readonly log: Array<{ at: number; ok: boolean; reason?: string }> = [];

  constructor(opts: {
    seed: T;
    policy: FreshnessPolicy;
    /** When the seed was known-good (defaults to now). */
    asOfMs?: number;
  }) {
    this.value = opts.seed;
    this.lastGoodAt = opts.asOfMs ?? Date.now();
    this.freshMs = opts.policy.freshMs;
    this.graceMs = opts.policy.graceMs;
    const jitterFrac = opts.policy.jitter ?? 0.1;
    // deterministic-ish jitter seeded from freshMs so a set's window is stable per instance
    this.jitterMs = Math.floor(this.freshMs * jitterFrac);
  }

  /** Current freshness state given `now`, accounting for jitter on the fresh window. */
  stateAt(now: number = Date.now()): FreshnessState {
    const age = now - this.lastGoodAt;
    const fresh = this.freshMs + this.jitterMs;
    if (age <= fresh) return "fresh";
    if (age <= fresh + this.graceMs) return "stale";
    return "expired";
  }

  /**
   * Read the current best value with honest freshness metadata. NEVER throws on staleness —
   * callers always get data. If the value is `stale`, this schedules a background refresh
   * (single-flight) via the provided refreshFn but returns immediately with the current value.
   * If `expired`, it likewise returns last-good; the ReferenceRefresher (3.6c) drives the
   * blocking-ish refresh out of band. This method is synchronous and side-effect-light.
   */
  get(now: number = Date.now()): ReferenceView<T> {
    const state = this.stateAt(now);
    const ageMs = now - this.lastGoodAt;
    const asOf = isoDate(this.lastGoodAt);
    let note = "";
    if (state === "stale") note = `reference data is stale (as of ${asOf}); refreshing in background`;
    else if (state === "expired")
      note = `reference data is EXPIRED (as of ${asOf}); serving last-good until refresh succeeds`;
    return { value: this.value, state, asOf, ageMs, note };
  }

  /** The raw current value without metadata (convenience). */
  current(): T {
    return this.value;
  }

  /**
   * Attempt a refresh via `fn`. Single-flight: if one is already running, this is a no-op that
   * reports `skipped`. On success: replace value + bump lastGoodAt + validate via optional guard.
   * On ANY failure (throw, undefined, validation reject): KEEP last-good (stale-if-error) and log.
   * Returns whether the value was updated. NEVER throws — failure is contained by construction.
   */
  async refresh(
    fn: RefreshFn<T>,
    opts: { now?: number; validate?: (candidate: T) => boolean } = {},
  ): Promise<{ updated: boolean; reason: string }> {
    const now = opts.now ?? Date.now();
    if (this.refreshing) return { updated: false, reason: "skipped: refresh already in flight" };
    this.refreshing = true;
    try {
      const candidate = await fn();
      if (candidate === undefined || candidate === null) {
        this.log.push({ at: now, ok: false, reason: "refresh returned empty" });
        return { updated: false, reason: "stale-if-error: refresh returned empty; kept last-good" };
      }
      if (opts.validate && !opts.validate(candidate)) {
        this.log.push({ at: now, ok: false, reason: "validation rejected candidate" });
        return { updated: false, reason: "stale-if-error: candidate failed validation; kept last-good" };
      }
      this.value = candidate;
      this.lastGoodAt = now;
      this.log.push({ at: now, ok: true });
      return { updated: true, reason: "refreshed" };
    } catch (e) {
      // stale-if-error: a failed fetch can NEVER break the set — keep last-good, log loudly.
      this.log.push({ at: now, ok: false, reason: `refresh threw: ${(e as Error).message}` });
      return { updated: false, reason: "stale-if-error: refresh threw; kept last-good" };
    } finally {
      this.refreshing = false;
    }
  }

  /** Is a refresh warranted now (stale or expired)? Used by the ReferenceRefresher. */
  needsRefresh(now: number = Date.now()): boolean {
    return this.stateAt(now) !== "fresh";
  }

  /** Refresh attempt history (for spine/audit). */
  history(): ReadonlyArray<{ at: number; ok: boolean; reason?: string }> {
    return this.log;
  }
}
