import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ReferenceRefresher } from "../src/reference/reference_refresher.js";
import { ReferenceSet } from "../src/reference/reference_set.js";

const POLICY = { freshMs: 1000, graceMs: 1000 };
const staleSet = <T>(seed: T) => new ReferenceSet<T>({ seed, policy: POLICY, asOfMs: 0 }); // asOf=0 → long past TTL
const freshSet = <T>(seed: T) => new ReferenceSet<T>({ seed, policy: POLICY, asOfMs: 1_000_000_000 });
const NOW = 1_000_000_000;

test("OFFLINE HONESTY: a stale category with NO fetcher is skipped — the honest seed stands", async () => {
  const r = new ReferenceRefresher();
  const set = staleSet([{ model: "m", price: 1 }]);
  r.register("pricing", set);
  const report = await r.tick(NOW);
  assert.deepEqual([...report.skipped], ["pricing"], "no fetcher → skipped honestly");
  assert.equal(report.attempted.length, 0);
  assert.deepEqual(set.current(), [{ model: "m", price: 1 }], "seed value untouched");
});

test("REFRESH: a stale category WITH a fetcher is refreshed", async () => {
  const r = new ReferenceRefresher();
  const set = staleSet([{ model: "m", price: 1 }]);
  r.register("pricing", set, async () => [{ model: "m", price: 2 }]);
  const report = await r.tick(NOW);
  assert.deepEqual([...report.attempted], ["pricing"]);
  assert.deepEqual([...report.updated], ["pricing"]);
  assert.deepEqual(set.current(), [{ model: "m", price: 2 }], "value refreshed to the fetched data");
});

test("NEVER-FAILS (crown): a fetcher that THROWS keeps last-good — tick never throws, value unchanged", async () => {
  const r = new ReferenceRefresher();
  const set = staleSet([{ model: "m", price: 1 }]);
  r.register("pricing", set, async () => { throw new Error("pricing endpoint down"); });
  const report = await r.tick(NOW); // must not throw
  assert.deepEqual([...report.keptLastGood], ["pricing"], "stale-if-error kept last-good");
  assert.deepEqual(set.current(), [{ model: "m", price: 1 }], "the last-good value still serves — a bad refresh can only be IGNORED");
});

test("FRESH → SKIPPED: a fresh category is not refreshed (no stampede, TTL respected)", async () => {
  const r = new ReferenceRefresher();
  let fetched = false;
  r.register("pricing", freshSet([1]), async () => { fetched = true; return [2]; });
  const report = await r.tick(NOW);
  assert.deepEqual([...report.skipped], ["pricing"]);
  assert.equal(fetched, false, "the fetcher was not called for a fresh category");
});

test("WIRE: composeKeep registers the 4 reference categories, ticked by the heartbeat; offline it skips honestly", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-rr-")) });
  assert.ok(app.referenceRefresher, "refresher wired onto the app");
  assert.deepEqual([...app.referenceRefresher.registered()].sort(), ["capabilities", "endpoints", "modelFamilies", "pricing"]);
  const report = await app.referenceRefresher.tick();
  // Offline (no fetchers configured) → every category is skipped honestly, nothing attempted, never throws.
  assert.equal(report.attempted.length, 0, "no connected-env fetchers → nothing attempted offline");
  assert.equal(report.updated.length, 0);
});
