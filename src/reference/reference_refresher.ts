/**
 * ReferenceRefresher (Increment 3.6c) — the background revalidator.
 *
 * SOTA basis (2026-08-04): background, non-blocking revalidation — "the current caller does not
 * wait" (microlink); single-flight so N ticks don't stampede one category (medium/vetora); jitter
 * lives in each ReferenceSet's fresh window so categories stagger. This is the scheduled-autonomy
 * loop (item 7) wearing a reference-data hat: on each tick it refreshes only categories past their
 * TTL, within budget, spine-logged.
 *
 * The RefreshFns are CONNECTED-ENV SEAMS: a category's fetcher (pricing endpoint, model-family
 * feed, provider list) is injected. When no fetcher is registered or the env is offline, there is
 * simply no refresh and the honest dated seed stands (never a failure). A registered fetcher that
 * throws/returns-junk is contained by the ReferenceSet's stale-if-error — it can only leave data
 * slightly stale, never break Keep.
 *
 * Zero deps.
 */

import type { ReferenceSet, RefreshFn } from "./reference_set.js";

/** A registered category: its set, its (optional) fetcher, and an optional validator. */
interface Registered<T> {
  readonly name: string;
  readonly set: ReferenceSet<T>;
  readonly fetcher?: RefreshFn<T>;
  readonly validate?: (candidate: T) => boolean;
}

/** Result of one refresh tick — what was attempted and what happened (for the spine). */
export interface RefreshTickReport {
  readonly at: number;
  readonly attempted: readonly string[];
  readonly updated: readonly string[];
  readonly keptLastGood: readonly string[]; // stale-if-error kept the seed/last-good
  readonly skipped: readonly string[]; // fresh, or no fetcher, or single-flight
}

export class ReferenceRefresher {
  private readonly categories: Array<Registered<unknown>> = [];

  /** Register a category to be kept fresh. `fetcher` is a connected-env seam (may be omitted). */
  register<T>(name: string, set: ReferenceSet<T>, fetcher?: RefreshFn<T>, validate?: (c: T) => boolean): void {
    const entry: Registered<unknown> = {
      name,
      set: set as ReferenceSet<unknown>,
      ...(fetcher ? { fetcher: fetcher as RefreshFn<unknown> } : {}),
      ...(validate ? { validate: validate as (c: unknown) => boolean } : {}),
    };
    this.categories.push(entry);
  }

  /**
   * One revalidation tick. For each category past its TTL WITH a registered fetcher, attempt a
   * single-flight refresh; stale-if-error keeps last-good on any failure. Categories that are
   * fresh, or have no fetcher (offline seam), are skipped honestly. Never throws.
   */
  async tick(now: number = Date.now()): Promise<RefreshTickReport> {
    const attempted: string[] = [];
    const updated: string[] = [];
    const keptLastGood: string[] = [];
    const skipped: string[] = [];

    for (const cat of this.categories) {
      if (!cat.set.needsRefresh(now)) {
        skipped.push(cat.name);
        continue;
      }
      if (!cat.fetcher) {
        // no connected-env fetcher → the honest seed/last-good stands
        skipped.push(cat.name);
        continue;
      }
      attempted.push(cat.name);
      const res = await cat.set.refresh(cat.fetcher, {
        now,
        ...(cat.validate ? { validate: cat.validate } : {}),
      });
      if (res.updated) updated.push(cat.name);
      else keptLastGood.push(cat.name);
    }

    return { at: now, attempted, updated, keptLastGood, skipped };
  }

  /** Names of registered categories (for introspection/testing). */
  registered(): readonly string[] {
    return this.categories.map((c) => c.name);
  }
}
