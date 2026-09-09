import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";

import { buildTemporalContext } from "../src/currency/temporal_context.js";
import { LandscapeCatalog, type LandscapeEntry } from "../src/currency/landscape_catalog.js";
import { priorArtCheck, type PriorArtSearch } from "../src/currency/prior_art.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-cur-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

// --- TemporalContext ---

test("temporal context injects today's date (human + ISO)", () => {
  const t = buildTemporalContext(new Date("2026-08-04T00:00:00Z"));
  assert.equal(t.todayISO, "2026-08-04");
  assert.ok(/August 4, 2026/.test(t.todayHuman));
  assert.ok(t.directive.includes("2026-08-04"));
});

test("temporal context computes months since cutoff", () => {
  const t = buildTemporalContext(new Date("2026-08-04T00:00:00Z"), "2026-01");
  assert.equal(t.monthsSinceCutoff, 7);
  assert.equal(t.brainCutoff, "2026-01");
});

test("directive is HONEST: says verify when it can, says cannot-check when it cannot", () => {
  const canVerify = buildTemporalContext(new Date("2026-08-04T00:00:00Z"), "2026-01", true);
  assert.ok(/verify/i.test(canVerify.directive));
  const cannot = buildTemporalContext(new Date("2026-08-04T00:00:00Z"), "2026-01", false);
  assert.ok(/do not|don't|not.*available|unverified/i.test(cannot.directive));
  assert.ok(!/prefer freshly-retrieved/i.test(cannot.directive)); // doesn't claim a tool it lacks
});

// --- LandscapeCatalog ---

test("catalog ranks by relevance (BM25); free-first breaks ties within a relevance band", () => {
  const cat = new LandscapeCatalog();
  // A pure TTS query: the strongest match should win on relevance even if paid
  // (the locked principle is "paid only when materially better" — a genuinely stronger
  // match IS materially better, and honesty-over-lock-in surfaces it).
  const voice = cat.matchesTask(["tts", "voice", "text-to-speech"]);
  assert.ok(voice.length >= 1);
  assert.ok(/elevenlabs|voice|speech|tts/i.test(`${voice[0]!.name} ${voice[0]!.summary} ${voice[0]!.tags.join(" ")}`));

  // But when two options are comparably relevant, free sorts first. Build a catalog
  // with a free and a paid entry sharing identical text to force a relevance tie.
  const tie = new (cat.constructor as typeof LandscapeCatalog)(
    [
      { name: "PaidWidget", summary: "does widget things", tags: ["widget"], cost: "paid", asOf: "2026-08-01" },
      { name: "FreeWidget", summary: "does widget things", tags: ["widget"], cost: "free", asOf: "2026-08-01" },
    ],
    "2026-08-01",
  );
  const widgets = tie.matchesTask(["widget"]);
  assert.equal(widgets[0]!.cost, "free"); // free-first tiebreak within equal relevance
});

test("catalog knows when it is stale", () => {
  const fresh = new LandscapeCatalog(undefined, "2026-08-01");
  assert.equal(fresh.isStale(new Date("2026-08-04")), false);
  const stale = new LandscapeCatalog(undefined, "2026-01-01");
  assert.equal(stale.isStale(new Date("2026-08-04")), true);
  assert.ok(/out of date/i.test(stale.stalenessNote(new Date("2026-08-04"))));
});

test("refresh folds in newly-discovered options", () => {
  const cat = new LandscapeCatalog();
  const fresh: LandscapeEntry = { name: "NewTool", summary: "does the thing", tags: ["widget"], cost: "free", asOf: "2026-08-04" };
  cat.refresh([fresh], "2026-08-04");
  assert.ok(cat.matchesTask(["widget"]).some((e) => e.name === "NewTool"));
});

// --- priorArtCheck ---

const temporalOffline = buildTemporalContext(new Date("2026-08-04T00:00:00Z"), "2026-01", false);
const temporalOnline = buildTemporalContext(new Date("2026-08-04T00:00:00Z"), "2026-01", true);

test("a goal with a free existing option -> adopt, recommending the free one", async () => {
  const spine = newSpine();
  const report = await priorArtCheck(
    { goal: "convert my docs to epub", keywords: ["document", "convert", "epub"] },
    { spine, catalog: new LandscapeCatalog(), temporal: temporalOffline },
  );
  assert.equal(report.verdict, "adopt");
  assert.ok(report.options.some((o) => o.cost === "free"));
  assert.ok(/already exist/i.test(report.recommendation));
});

test("a core-differentiator goal favors build (or combine), not blind adopt", async () => {
  const spine = newSpine();
  const report = await priorArtCheck(
    { goal: "my secret sauce ranking engine", keywords: ["document"], isCoreDifferentiator: true },
    { spine, catalog: new LandscapeCatalog(), temporal: temporalOffline },
  );
  assert.ok(report.verdict === "combine" || report.verdict === "build");
});

test("a goal with nothing matching -> build", async () => {
  const spine = newSpine();
  const report = await priorArtCheck(
    { goal: "something totally novel", keywords: ["zzznomatch"] },
    { spine, catalog: new LandscapeCatalog(), temporal: temporalOffline },
  );
  assert.equal(report.verdict, "build");
});

test("when no search is available, the report is honest (unverified + caveat)", async () => {
  const spine = newSpine();
  const report = await priorArtCheck(
    { goal: "convert audio", keywords: ["audio", "convert"] },
    { spine, catalog: new LandscapeCatalog(), temporal: temporalOffline },
  );
  assert.equal(report.verified, false);
  assert.ok(report.caveat && report.caveat.length > 0);
});

test("a live search that finds a fresher option is used and marks the report verified", async () => {
  const spine = newSpine();
  const search: PriorArtSearch = async () => [
    { name: "FreshVoiceTool", summary: "new tts", tags: ["tts", "voice"], cost: "free", asOf: "2026-08-04" },
  ];
  const report = await priorArtCheck(
    { goal: "narrate my book", keywords: ["tts", "voice"] },
    { spine, catalog: new LandscapeCatalog(), temporal: temporalOnline, search },
  );
  assert.equal(report.verified, true);
  assert.ok(report.options.some((o) => o.name === "FreshVoiceTool"));
});

test("prior-art check is spine-logged for audit", async () => {
  const spine = newSpine();
  await priorArtCheck({ goal: "x", keywords: ["document"] }, { spine, catalog: new LandscapeCatalog(), temporal: temporalOffline });
  await spine.seal();
  const events = spine.replay().map((e) => (e.payload as Record<string, unknown>)["event"]);
  assert.ok(events.includes("prior_art.checked"));
});
