import { test } from "node:test";
import assert from "node:assert/strict";
import { defaultPlanVetter } from "../src/pipeline/plan_vetter.js";
import { buildTemporalContext } from "../src/currency/temporal_context.js";
import { LandscapeCatalog } from "../src/currency/landscape_catalog.js";
import type { CurrencyResearch } from "../src/pipeline/plan_currency.js";

const NOW = new Date("2026-08-05T00:00:00Z");

test("INVARIANT: every plan gets a currency verdict (date check) alongside consequence analysis", async () => {
  const vet = defaultPlanVetter({ temporal: buildTemporalContext(NOW, "2025-06", false), catalog: new LandscapeCatalog() });
  const d = await vet({ id: "x", text: "fix a typo in the readme", repoRef: "r" });
  assert.ok(d.currency, "currency verdict is attached to every plan");
  assert.equal(d.currency!.dateStamp, "2026-08-05");
});

test("INVARIANT: a research-confirmed STALE approach downgrades a clean plan pass → rework (flag + route)", async () => {
  const research: CurrencyResearch = { async verifyCurrent() { return { current: false, note: "superseded in 2026" }; } };
  const vet = defaultPlanVetter({ temporal: buildTemporalContext(NOW, "2025-01", true), catalog: new LandscapeCatalog(), currencyResearch: research });
  const d = await vet({ id: "x", text: "use the recommended approach for this", repoRef: "r" });
  assert.equal(d.decision, "rework", "stale currency downgrades pass → rework");
  assert.equal(d.cleared, false);
  assert.match(d.reason, /CURRENCY/);
});

test("INVARIANT: verify-currency annotates but does NOT block an otherwise-clean plan", async () => {
  const vet = defaultPlanVetter({ temporal: buildTemporalContext(NOW, "2024-01", false), catalog: new LandscapeCatalog() }); // far past cutoff
  const d = await vet({ id: "x", text: "rename a local variable", repoRef: "r" });
  assert.equal(d.currency!.decision, "verify-currency");
  assert.equal(d.decision, "pass", "verify-currency annotates; it does not block a clean plan");
});

test("INVARIANT: the plan vetter is SOVEREIGN by default (no deps → offline currency check runs)", async () => {
  const vet = defaultPlanVetter(); // no deps at all
  const d = await vet({ id: "x", text: "fix an off-by-one", repoRef: "r" });
  assert.ok(d.currency, "runs fully offline with no external config");
});
