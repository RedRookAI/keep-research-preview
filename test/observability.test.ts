import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";

import { CostModel } from "../src/observability/cost_model.js";
import { TraceRecorder, attributeCost, type Span } from "../src/observability/tracing.js";
import { forecastTask, forecastBurnRate, breakerTrips, percentile } from "../src/observability/forecasting.js";
import { triageFailure, confirmByRerun } from "../src/observability/failure_localization.js";
import { routeTask, measuredSavings, type ModelQualityRecord, type RoutingPolicy } from "../src/observability/routing.js";
import type { CostBreakdown } from "../src/observability/cost_model.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-obs-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

// --- Cost model ---

test("cached tokens are billed cheaper than fresh (cache-heavy work isn't over-costed)", () => {
  const cm = new CostModel();
  cm.registerPricing({ model: "m", inputPerMillion: 3, outputPerMillion: 15, cachedInputPerMillion: 0.3 });
  const allFresh = cm.cost("m", { freshInputTokens: 1_000_000, cachedInputTokens: 0, outputTokens: 0 });
  const allCached = cm.cost("m", { freshInputTokens: 0, cachedInputTokens: 1_000_000, outputTokens: 0 });
  assert.ok(allCached.totalUsd < allFresh.totalUsd);
  assert.ok(Math.abs(allFresh.inputUsd - 3) < 1e-9);
  assert.ok(Math.abs(allCached.cachedInputUsd - 0.3) < 1e-9);
});

test("cost includes non-token dimensions (human/infra/tool) for an honest total", () => {
  const cm = new CostModel(100); // $100/hr human
  cm.registerPricing({ model: "m", inputPerMillion: 0, outputPerMillion: 0 });
  const c = cm.cost("m", { freshInputTokens: 0, cachedInputTokens: 0, outputTokens: 0 }, { humanApprovalSeconds: 3600, infraUsd: 5, toolApiUsd: 2 });
  assert.ok(Math.abs(c.humanUsd - 100) < 1e-9);
  assert.ok(Math.abs(c.totalUsd - 107) < 1e-9);
});

test("missing pricing throws (no silent zero-cost)", () => {
  const cm = new CostModel();
  assert.throws(() => cm.cost("unknown", { freshInputTokens: 1, cachedInputTokens: 0, outputTokens: 0 }));
});

// --- Attribution + hierarchical tracing ---

function breakdown(usd: number): CostBreakdown {
  return { inputUsd: usd, cachedInputUsd: 0, outputUsd: 0, tokenUsd: usd, humanUsd: 0, infraUsd: 0, toolApiUsd: 0, totalUsd: usd };
}

test("attribution rolls up across task/agent/node and the NOVEL per-lesson grain", () => {
  const spans: Span[] = [
    { spanId: "s1", traceId: "t", name: "a", taskId: "T1", provider: "provider-a", agent: "claude", node: "arch", lessonIds: ["L1"], cost: breakdown(2), startTs: 0, endTs: 1, status: "ok" },
    { spanId: "s2", traceId: "t", name: "b", taskId: "T1", provider: "provider-b", agent: "gemini", node: "audit", lessonIds: ["L1", "L2"], cost: breakdown(3), startTs: 1, endTs: 2, status: "ok" },
  ];
  const attr = attributeCost(spans);
  assert.equal(attr.total, 5);
  assert.equal(attr.byTask.get("T1"), 5);
  assert.equal(attr.byProvider.get("provider-a"), 2);
  assert.equal(attr.byProvider.get("provider-b"), 3);
  assert.equal(attr.byAgent.get("claude"), 2);
  assert.equal(attr.byAgent.get("gemini"), 3);
  assert.equal(attr.byLesson.get("L1"), 5); // L1 influenced both spans
  assert.equal(attr.byLesson.get("L2"), 3);
});

test("spans nest into a trace tree via parentId", () => {
  const rec = new TraceRecorder(newSpine());
  const root = rec.record({ name: "task", taskId: "T1", cost: breakdown(1), startTs: 0, endTs: 10 });
  const child = rec.record({ parentId: root.spanId, name: "step", taskId: "T1", cost: breakdown(1), startTs: 1, endTs: 5 });
  assert.equal(child.traceId, root.traceId); // inherits the trace
  assert.equal(rec.children(root.spanId).length, 1);
});

test("trace records survive restart, isolate exact tenants, and quarantine malformed owned evidence", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-obs-restart-"));
  const firstSpine = new Spine(new FileSpineStore(dir, { fsync: true }), new InProcessLock(), new SchemaRegistry());
  const first = new TraceRecorder(firstSpine);
  first.record({ name: "alpha-call", taskId: "alpha-task", tenant: "alpha", provider: "local", lessonIds: ["L1"], cost: breakdown(2), startTs: 1, endTs: 2 });
  first.record({ name: "beta-call", taskId: "beta-task", tenant: "beta", provider: "remote", cost: breakdown(3), startTs: 2, endTs: 3 });
  firstSpine.stage({ type: "identity.action", actor: "trace", payload: { event: "span", schema: "keep.trace-span/v1", spanId: "malformed" } });
  await firstSpine.seal();

  const restarted = new TraceRecorder(new Spine(new FileSpineStore(dir, { fsync: true }), new InProcessLock(), new SchemaRegistry()));
  assert.deepEqual(restarted.all("alpha").map((span) => span.taskId), ["alpha-task"]);
  assert.deepEqual(restarted.all("beta").map((span) => span.taskId), ["beta-task"]);
  assert.equal(restarted.all().length, 2, "n=1/local administration can retain the complete local history");
  assert.equal(restarted.integrityStatus().quarantined, 1, "malformed trace-owned evidence cannot poison valid history silently");
  assert.throws(() => restarted.all("../alpha"), /invalid trace tenant/u);
});

// --- Forecasting: bands not points, and the hard breaker ---

test("per-task forecast returns a p50/p95 BAND, not a point estimate", () => {
  const history = [10, 12, 15, 20, 50, 300]; // 30x spread is real
  const band = forecastTask(history);
  assert.ok(band.p95 > band.p50); // it's a band
  assert.equal(band.credible, true);
});

test("forecast flags low-sample history as non-credible (no invented point)", () => {
  const band = forecastTask([10, 12]); // < minSamples
  assert.equal(band.credible, false);
});

test("hard breaker trips on token ceiling (halts the 30x spiral)", () => {
  const r = breakerTrips({ tokens: 500_000, usd: 1 }, { maxTokens: 100_000, maxUsd: 50 });
  assert.equal(r.tripped, true);
  assert.ok(r.reason!.includes("token ceiling"));
});

test("hard breaker trips on cost ceiling", () => {
  const r = breakerTrips({ tokens: 1, usd: 75 }, { maxTokens: 100_000, maxUsd: 50 });
  assert.equal(r.tripped, true);
  assert.ok(r.reason!.includes("cost ceiling"));
});

test("burn-rate aggregate forecast scales with the trailing window", () => {
  const f = forecastBurnRate({ trailingWindowUsd: 60, windowSeconds: 60, activeSessions: 1, horizonSeconds: 3600 });
  assert.ok(Math.abs(f - 3600) < 1e-6); // $1/s * 3600s
});

test("percentile interpolates correctly", () => {
  assert.equal(percentile([10, 20, 30], 0.5), 20);
});

// --- Failure localization: root, and confirm-by-rerun ---

function span(id: string, parentId: string | undefined, status: Span["status"], startTs: number): Span {
  return { spanId: id, traceId: "t", name: id, taskId: "T", lessonIds: [], cost: breakdown(0), startTs, endTs: startTs + 1, status, ...(parentId ? { parentId } : {}) };
}

test("triage finds the ROOT failing span, treating downstream failures as propagation", () => {
  const spans = [
    span("root", undefined, "ok", 0),
    span("bad", "root", "tool-error", 1), // the real cause
    span("downstream", "bad", "llm-error", 2), // propagated
  ];
  const dx = triageFailure(spans);
  assert.ok(dx);
  assert.equal(dx!.implicatedSpanId, "bad"); // not "downstream"
  assert.equal(dx!.failureType, "tool-error");
});

test("triage returns nothing when all spans are ok", () => {
  assert.equal(triageFailure([span("a", undefined, "ok", 0)]), undefined);
});

test("attribution is CONFIRMED only when a targeted rerun recovers (else unproven)", async () => {
  const dx = triageFailure([span("root", undefined, "ok", 0), span("bad", "root", "llm-error", 1)])!;
  const confirmed = await confirmByRerun(dx, async () => true); // rerun recovers
  assert.equal(confirmed.confirmed, true);
  const unconfirmed = await confirmByRerun(dx, async () => false); // rerun doesn't recover
  assert.equal(unconfirmed.confirmed, false);
  assert.ok(unconfirmed.note.includes("NOT confirmed"));
});

// --- Routing: cheapest-that-clears-the-bar, never quality-for-price ---

const models: ModelQualityRecord[] = [
  { model: "cheap", qualityByClass: { trivial: 0.95, moderate: 0.6 }, typicalTaskUsd: 0.01 },
  { model: "premium", qualityByClass: { trivial: 0.99, moderate: 0.95 }, typicalTaskUsd: 0.20 },
];
const policy: RoutingPolicy = {
  allowedModels: ["cheap", "premium"],
  qualityBar: { trivial: 0.9, easy: 0.9, moderate: 0.9, hard: 0.9 },
};

test("routing picks the CHEAPEST model that clears the quality bar (arbitrage)", () => {
  const d = routeTask("trivial", models, policy);
  assert.equal(d!.model, "cheap"); // both clear 0.9 at trivial -> cheapest wins
});

test("routing preserves quality: routes to premium when cheap misses the bar", () => {
  const d = routeTask("moderate", models, policy);
  assert.equal(d!.model, "premium"); // cheap=0.6 < 0.9 bar; premium=0.95 clears -> premium
  assert.ok(d!.measuredQuality >= policy.qualityBar.moderate);
});

test("routing NEVER trades quality for price: when NO model clears the bar, picks highest quality", () => {
  const subBarModels: ModelQualityRecord[] = [
    { model: "cheap", qualityByClass: { hard: 0.5 }, typicalTaskUsd: 0.01 },
    { model: "premium", qualityByClass: { hard: 0.8 }, typicalTaskUsd: 0.20 }, // higher, still < bar
  ];
  const strictPolicy: RoutingPolicy = {
    allowedModels: ["cheap", "premium"],
    qualityBar: { trivial: 0.9, easy: 0.9, moderate: 0.9, hard: 0.99 },
  };
  const d = routeTask("hard", subBarModels, strictPolicy);
  assert.equal(d!.model, "premium"); // 0.8 > 0.5, neither clears 0.99 -> highest quality, not cheapest
  assert.ok(d!.reason.includes("quality over price"));
});

test("measured savings are computed vs a baseline (presented, not promised)", () => {
  const s = measuredSavings(0.20, 0.01);
  assert.ok(Math.abs(s.pct - 95) < 1e-9);
});
