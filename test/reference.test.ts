import { test } from "node:test";
import assert from "node:assert/strict";

import { ReferenceSet } from "../src/reference/reference_set.js";
import {
  ReferenceRegistry,
  UNKNOWN_FAMILY_DEFAULT,
  SEED_AS_OF,
} from "../src/reference/reference_registry.js";
import { ReferenceRefresher } from "../src/reference/reference_refresher.js";

const DAY = 86_400_000;

function set<T>(seed: T, freshMs: number, graceMs: number) {
  return new ReferenceSet<T>({ seed, policy: { freshMs, graceMs, jitter: 0 }, asOfMs: 0 });
}

// ── Three-state SWR transitions ─────────────────────────────────────────────

test("three-state freshness: fresh -> stale -> expired at TTL boundaries", () => {
  const s = set("v1", 10 * DAY, 20 * DAY);
  assert.equal(s.stateAt(5 * DAY), "fresh", "within fresh window");
  assert.equal(s.stateAt(15 * DAY), "stale", "past fresh, within grace (SWR window)");
  assert.equal(s.stateAt(40 * DAY), "expired", "past grace");
});

test("get() never throws on staleness and returns an honest note", () => {
  const s = set("v1", 1 * DAY, 1 * DAY);
  const fresh = s.get(0);
  assert.equal(fresh.state, "fresh");
  assert.equal(fresh.note, "", "fresh has no note");
  const stale = s.get(1.5 * DAY);
  assert.equal(stale.state, "stale");
  assert.match(stale.note, /stale/, "stale note surfaced");
  const expired = s.get(5 * DAY);
  assert.equal(expired.state, "expired");
  assert.match(expired.note, /EXPIRED|last-good/, "expired note surfaced honestly");
  // in every case a value came back — never an error
  assert.equal(expired.value, "v1");
});

// ── NEVER-FAILS: stale-if-error keeps last-good on every failure mode ────────

test("INVARIANT: refresh that THROWS keeps last-good (stale-if-error)", async () => {
  const s = set("good", 1 * DAY, 1 * DAY);
  const r = await s.refresh(() => { throw new Error("network down"); }, { now: 5 * DAY });
  assert.equal(r.updated, false);
  assert.match(r.reason, /stale-if-error/);
  assert.equal(s.current(), "good", "last-good preserved after a throwing refresh");
});

test("INVARIANT: refresh returning empty keeps last-good", async () => {
  const s = set("good", 1 * DAY, 1 * DAY);
  // @ts-expect-error deliberately returning undefined to test the guard
  const r = await s.refresh(() => undefined, { now: 5 * DAY });
  assert.equal(r.updated, false);
  assert.equal(s.current(), "good", "empty refresh cannot null out the category");
});

test("INVARIANT: refresh failing validation keeps last-good", async () => {
  const s = set(10, 1 * DAY, 1 * DAY);
  const r = await s.refresh(() => -999, { now: 5 * DAY, validate: (n) => n > 0 });
  assert.equal(r.updated, false);
  assert.equal(s.current(), 10, "a bad/absurd value is rejected; last-good kept");
});

test("a VALID refresh updates the value and bumps freshness", async () => {
  const s = set("old", 1 * DAY, 1 * DAY);
  const r = await s.refresh(() => "new", { now: 5 * DAY });
  assert.equal(r.updated, true);
  assert.equal(s.current(), "new");
  assert.equal(s.stateAt(5 * DAY), "fresh", "lastGoodAt bumped, so fresh again");
});

// ── Single-flight (no stampede) ─────────────────────────────────────────────

test("INVARIANT: concurrent refreshes are single-flight (second is skipped)", async () => {
  const s = set("v", 1 * DAY, 1 * DAY);
  let calls = 0;
  const slow = () => new Promise<string>((res) => { calls++; setTimeout(() => res("fresh"), 20); });
  const [a, b] = await Promise.all([
    s.refresh(slow, { now: 5 * DAY }),
    s.refresh(slow, { now: 5 * DAY }),
  ]);
  const skipped = [a, b].filter((r) => r.reason.includes("already in flight")).length;
  assert.equal(skipped, 1, "exactly one refresh was skipped by single-flight");
  assert.equal(calls, 1, "the fetcher ran only once");
});

// ── Registry seeds + provider-agnostic fall-through ─────────────────────────

test("registry seeds are dated and usable offline (day-one, no network)", () => {
  const reg = new ReferenceRegistry();
  const fams = reg.modelFamilies.get(Date.parse(SEED_AS_OF + "T00:00:00Z")).value;
  assert.ok(fams.length >= 5, "model families seeded");
  assert.ok(reg.endpoints.current().some((e) => e.id === "ollama"), "local endpoint seeded");
  assert.ok(reg.pricing.current().length >= 1, "pricing seeded");
});

test("INVARIANT: unknown model family falls through to the model-blind default (provider-agnostic)", () => {
  const reg = new ReferenceRegistry();
  const known = reg.familyFor("gpt-5.4-mini");
  assert.equal(known.family, "gpt", "known family recognized");
  const unknown = reg.familyFor("some-brand-new-model-2027");
  assert.equal(unknown, UNKNOWN_FAMILY_DEFAULT, "unknown family → default, never throws");
  assert.equal(unknown.effortKnob, "none", "default assumes no knobs (detect at runtime)");
});

test("pricingFor returns undefined for unknown model (estimator then declines to quote)", () => {
  const reg = new ReferenceRegistry();
  assert.ok(reg.pricingFor("deepseek-v4-flash"), "known model priced");
  assert.equal(reg.pricingFor("nonexistent-model"), undefined, "unknown model → no stale quote");
});

// ── Refresher (background revalidator) ──────────────────────────────────────

test("refresher skips fresh categories and categories with no fetcher (honest offline)", async () => {
  const reg = new ReferenceRegistry();
  const refresher = new ReferenceRefresher();
  // register pricing WITH a fetcher, endpoints WITHOUT (offline seam)
  refresher.register("pricing", reg.pricing, () => reg.pricing.current());
  refresher.register("endpoints", reg.endpoints); // no fetcher
  // at seed time everything is fresh → all skipped
  const seedMs = Date.parse(SEED_AS_OF + "T00:00:00Z");
  const t1 = await refresher.tick(seedMs);
  assert.deepEqual([...t1.skipped].sort(), ["endpoints", "pricing"], "all fresh → skipped");
  // far in the future: pricing is stale+has fetcher → attempted; endpoints stale but no fetcher → skipped
  const t2 = await refresher.tick(seedMs + 100 * DAY);
  assert.ok(t2.attempted.includes("pricing"), "pricing attempted (has fetcher, is stale)");
  assert.ok(t2.skipped.includes("endpoints"), "endpoints skipped (no fetcher — seed stands honestly)");
});

test("INVARIANT: a category can never be corrupted by the refresher (bad fetcher kept last-good)", async () => {
  const reg = new ReferenceRegistry();
  const refresher = new ReferenceRefresher();
  const before = reg.pricing.current();
  refresher.register("pricing", reg.pricing, () => { throw new Error("bad feed"); });
  const seedMs = Date.parse(SEED_AS_OF + "T00:00:00Z");
  const t = await refresher.tick(seedMs + 100 * DAY);
  assert.ok(t.keptLastGood.includes("pricing"), "stale-if-error kept last-good");
  assert.deepEqual(reg.pricing.current(), before, "pricing seed intact after a throwing refresh");
});
