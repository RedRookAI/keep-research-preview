import { test } from "node:test";
import assert from "node:assert/strict";
import { checkCurrency, type CurrencyResearch } from "../src/pipeline/plan_currency.js";
import { buildTemporalContext } from "../src/currency/temporal_context.js";
import { LandscapeCatalog } from "../src/currency/landscape_catalog.js";

const NOW = new Date("2026-08-05T00:00:00Z");
const catalog = () => new LandscapeCatalog();

test("INVARIANT: the date check ALWAYS runs (offline), stamping today's date", async () => {
  const t = buildTemporalContext(NOW, undefined, false);
  const v = await checkCurrency("do a simple refactor", t, catalog(), undefined, NOW);
  assert.equal(v.dateStamp, "2026-08-05");
});

test("INVARIANT: a 'best practice' assertion is flagged for currency verification", async () => {
  const t = buildTemporalContext(NOW, "2025-01", false);
  const v = await checkCurrency("use the current best practice for auth", t, catalog(), undefined, NOW);
  assert.equal(v.decision, "verify-currency");
  assert.ok(v.claims.some((c) => c.kind === "best-practice-assertion"));
  assert.ok(v.verifyThese.length > 0);
});

test("INVARIANT: a version pin is flagged (can be superseded)", async () => {
  const t = buildTemporalContext(NOW, "2025-01", false);
  const v = await checkCurrency("upgrade to React 18 and pin it", t, catalog(), undefined, NOW);
  assert.equal(v.decision, "verify-currency");
  assert.ok(v.claims.some((c) => c.kind === "version-pin"));
});

test("INVARIANT: far-past-cutoff raises verify-currency even with no explicit claims", async () => {
  const t = buildTemporalContext(NOW, "2024-06", false); // ~14 months → far past
  const v = await checkCurrency("rename a variable", t, catalog(), undefined, NOW);
  assert.equal(v.decision, "verify-currency");
  assert.ok((v.monthsSinceCutoff ?? 0) >= 12);
});

test("INVARIANT: research egress is PRIVACY-PRESERVING — only minimal claim terms are sent, never the plan body", async () => {
  const t = buildTemporalContext(NOW, "2025-01", true);
  let sent: readonly string[] | null = null;
  const research: CurrencyResearch = { async verifyCurrent(terms) { sent = terms; return { current: true, note: "still current" }; } };
  const secretPlan = "SECRET-IP: our proprietary algorithm uses the current best practice approach";
  await checkCurrency(secretPlan, t, catalog(), research, NOW);
  assert.ok(sent !== null, "research was consulted");
  const joined = (sent as unknown as string[]).join(" ");
  assert.ok(!joined.includes("SECRET-IP"), "the plan body / IP is NOT sent to research");
  assert.ok(!joined.includes("proprietary algorithm"), "no plan internals leak");
});

test("INVARIANT: research finding of staleness → 'stale' verdict with the current alternative", async () => {
  const t = buildTemporalContext(NOW, "2025-01", true);
  const research: CurrencyResearch = { async verifyCurrent() { return { current: false, note: "approach X was superseded by Y in 2026" }; } };
  const v = await checkCurrency("use the recommended approach X", t, catalog(), research, NOW);
  assert.equal(v.decision, "stale");
  assert.ok(v.researchNotes.some((n) => /superseded/.test(n)));
});

test("INVARIANT: offline (canVerify=false) degrades gracefully — never throws, dated caveat stands", async () => {
  const t = buildTemporalContext(NOW, "2025-01", false);
  const research: CurrencyResearch = { async verifyCurrent() { throw new Error("should not be called offline"); } };
  const v = await checkCurrency("use the best practice approach", t, catalog(), research, NOW);
  assert.equal(v.researchNotes.length, 0, "research not called when canVerify is false");
  assert.equal(v.decision, "verify-currency", "still flags via offline signals");
});

test("INVARIANT: the check FLAGS + routes, never rewrites the plan (no mutated-plan field exists)", async () => {
  const t = buildTemporalContext(NOW, "2025-01", false);
  const v = await checkCurrency("use the current best practice", t, catalog(), undefined, NOW);
  assert.equal((v as unknown as { rewrittenPlan?: unknown }).rewrittenPlan, undefined, "no rewrite — proposes, human decides");
  assert.ok(v.verifyThese.length > 0, "gives the reviewer something to verify");
});

test("a plan with no time-sensitive content passes", async () => {
  const t = buildTemporalContext(NOW, "2026-06", false); // recent cutoff, not far-past
  const v = await checkCurrency("fix an off-by-one error in the loop bound", t, catalog(), undefined, NOW);
  assert.equal(v.decision, "pass");
});
