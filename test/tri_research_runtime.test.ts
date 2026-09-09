import assert from "node:assert/strict";
import test from "node:test";
import { TriResearchRuntime, isAdmissibleTriResearchSource, supportsBoundedReversibleWork, type TriResearchLane, type TriResearchSource, type TriResearchTransport } from "../src/research/tri_research_runtime.js";

const source = (lane: TriResearchLane, overrides: Partial<TriResearchSource> = {}): TriResearchSource => ({
  id: lane, title: lane, locator: `https://evidence.invalid/${lane}`,
  retrievedAt: "2026-08-28T10:00:00Z", asOf: "2026-08-01", summary: `${lane} evidence`, ...overrides,
});

test("built-in tri-research coordinator completes all lanes without an optional high-level coordinator", async () => {
  const transport: TriResearchTransport = { id: "primary", search: async (lane) => [source(lane)] };
  const report = await new TriResearchRuntime({ transports: [transport], asOf: () => "2026-08-28" }).run("safe autonomous orchestration");
  assert.equal(report.currentSince, "2026-05-28");
  assert.equal(report.complete, true);
  assert.deepEqual(Object.keys(report.lanes).sort(), ["cross-disciplinary", "current", "historical"]);
});

test("whitespace-only source identities and summaries are never admitted as research evidence", () => {
  for (const overrides of [{ summary: " \n" }, { id: "  " }, { locator: "\t" }]) {
    assert.equal(isAdmissibleTriResearchSource("current", source("current", overrides), "2026-05-28", "2026-08-28"), false);
  }
});

test("route failure continues to an alternate route and records every attempted route", async () => {
  const broken: TriResearchTransport = { id: "broken", search: async () => { throw new Error("offline"); } };
  const alternate: TriResearchTransport = { id: "alternate", search: async (lane) => [source(lane)] };
  const report = await new TriResearchRuntime({ transports: [broken, alternate], asOf: () => "2026-08-28" }).run("x");
  assert.equal(report.complete, true);
  assert.deepEqual(report.lanes.current.routesTried, ["broken", "alternate"]);
});

test("missing routes produce exact debt rather than failure or fabricated completion", async () => {
  const report = await new TriResearchRuntime({ asOf: () => "2026-08-28" }).run("x");
  assert.equal(report.complete, false);
  assert.match(report.lanes.current.debt!, /unavailable/);
  assert.match(report.lanes.historical.debt!, /none configured/);
});

test("stale LKG never satisfies current/SOTA but remains explicitly visible", async () => {
  const stale = source("current", { id: "old", asOf: "2025-01-01" });
  const report = await new TriResearchRuntime({ asOf: () => "2026-08-28", lastKnownGood: { current: [stale] } }).run("x");
  assert.equal(report.lanes.current.verified, false);
  assert.equal(report.lanes.current.sources[0]?.stale, true);
  assert.equal(report.lanes.current.usableForBoundedWork, false);
});

test("stale historical/cross evidence is labeled and usable only for bounded non-current work", async () => {
  const report = await new TriResearchRuntime({ asOf: () => "2026-08-28", lastKnownGood: { historical: [source("historical")], "cross-disciplinary": [source("cross-disciplinary")] } }).run("x");
  assert.equal(report.complete, false);
  assert.equal(report.lanes.historical.verified, false);
  assert.equal(report.lanes.historical.usableForBoundedWork, true);
  assert.equal(report.lanes["cross-disciplinary"].usableForBoundedWork, true);
  assert.equal(report.lanes.historical.sources[0]?.routeId, "last-known-good");
  assert.equal(supportsBoundedReversibleWork(report), false, "missing fresh current evidence can never use the bounded path");
});

test("last-known-good evidence without a valid retrieval timestamp cannot support bounded work", async () => {
  const report = await new TriResearchRuntime({
    asOf: () => "2026-08-28",
    lastKnownGood: { historical: [source("historical", { retrievedAt: "unknown" })] },
  }).run("x");
  assert.equal(report.lanes.historical.sources[0]?.stale, true, "the rejected carrier remains visible for audit");
  assert.equal(report.lanes.historical.usableForBoundedWork, false);
});

test("fresh current plus labelled non-current LKG supports only the explicit bounded admission predicate", async () => {
  const currentOnly: TriResearchTransport = { id: "current-only", search: async (lane) => lane === "current" ? [source(lane)] : null };
  const report = await new TriResearchRuntime({
    transports: [currentOnly], asOf: () => "2026-08-28",
    lastKnownGood: { historical: [source("historical")], "cross-disciplinary": [source("cross-disciplinary")] },
  }).run("x");
  assert.equal(report.complete, false);
  assert.equal(report.lanes.current.verified, true);
  assert.equal(supportsBoundedReversibleWork(report), true);
});

test("a hanging route times out and the next route completes the lane", async () => {
  const hanging: TriResearchTransport = { id: "hanging", search: async () => new Promise<readonly TriResearchSource[]>(() => {}) };
  const alternate: TriResearchTransport = { id: "alternate", search: async (lane) => [source(lane)] };
  const report = await new TriResearchRuntime({ transports: [hanging, alternate], transportTimeoutMs: 5, asOf: () => "2026-08-28" }).run("x");
  assert.equal(report.complete, true);
  assert.equal(report.lanes.current.sources[0]?.routeId, "alternate");
});

test("current evidence outside the three-month window cannot satisfy currency", async () => {
  const transport: TriResearchTransport = { id: "old", search: async (lane) => [source(lane, lane === "current" ? { asOf: "2026-05-27" } : {})] };
  const report = await new TriResearchRuntime({ transports: [transport], asOf: () => "2026-08-28" }).run("x");
  assert.equal(report.lanes.current.verified, false);
  assert.equal(report.complete, false);
});

test("an adapter cannot make an old retrieval current by self-declaring a fresh asOf", async () => {
  const transport: TriResearchTransport = { id: "dishonest", search: async (lane) => [source(lane, lane === "current" ? { retrievedAt: "2019-01-01T00:00:00Z", asOf: "2026-08-20" } : {})] };
  const report = await new TriResearchRuntime({ transports: [transport], asOf: () => "2026-08-28" }).run("x");
  assert.equal(report.lanes.current.verified, false);
  assert.equal(report.complete, false);
});
