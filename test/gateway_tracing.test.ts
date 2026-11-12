import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { TraceRecorder, attributeCost } from "../src/observability/tracing.js";
import { TracingModelProvider, type PriceFor } from "../src/gateway/tracing_provider.js";
import { localCostTraceView, toPrivateOtlpSpans } from "../src/observability/fleet_telemetry.js";
import { runWithinTrace } from "../src/observability/trace_context.js";
import type { ModelProvider, GenerateResult } from "../src/gateway/gateway.js";

function newSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-gwt-"))), new InProcessLock(), new SchemaRegistry());
}
const price: PriceFor = (m) => (m === "test-model" ? { inputPerM: 1, outputPerM: 3 } : undefined);
function providerReturning(res: Partial<GenerateResult>): ModelProvider {
  return {
    name: "p", isLocal: true,
    generate: async () => ({ text: "hi", model: "test-model", tokensIn: 1000, tokensOut: 1000, ...res }),
    embed: async () => [],
  };
}

test("COST SPAN: a model call records a span with cost = usage × pricing", async () => {
  const rec = new TraceRecorder(newSpine());
  const tp = new TracingModelProvider(providerReturning({}), rec, price);
  await runWithinTrace({ traceId: "T", taskId: "task-1" }, () => tp.generate({ prompt: "x" }));
  const spans = rec.trace("T");
  assert.equal(spans.length, 1);
  assert.equal(spans[0]!.taskId, "task-1", "the span is attributed to the current task");
  assert.equal(spans[0]!.provider, "p", "the concrete provider is measured separately from model/agent identity");
  assert.equal(spans[0]!.status, "ok");
  assert.equal(spans[0]!.costStatus, "known");
  // 1000/1e6*1 + 1000/1e6*3 = 0.001 + 0.003 = 0.004
  assert.ok(Math.abs(spans[0]!.cost.totalUsd - 0.004) < 1e-9, "per-call cost computed from tokens × price");
});

test("an unpriced call retains usage and explicit unknown cost coverage", async () => {
  const rec = new TraceRecorder(newSpine());
  const tp = new TracingModelProvider(providerReturning({ model: "mystery-model" }), rec, price);
  await runWithinTrace({ traceId: "T", taskId: "t" }, () => tp.generate({ prompt: "x" }));
  assert.equal(rec.all()[0]!.costStatus, "unpriced");
  assert.deepEqual(rec.all()[0]!.tokens, { input: 1000, output: 1000 });
  const costs = attributeCost(rec.all());
  assert.equal(costs.total, 0, "no unknown amount is estimated");
  assert.equal(costs.costKnown, false);
  assert.equal(costs.totalKind, "observed-subtotal");
  assert.equal(costs.unknownCostSpans, 1);
});

test("HIERARCHY: a model-call span nests under the ambient parent span", async () => {
  const rec = new TraceRecorder(newSpine());
  const tp = new TracingModelProvider(providerReturning({}), rec, price);
  await runWithinTrace({ traceId: "T", taskId: "t", parentSpanId: "stage-span-9" }, () => tp.generate({ prompt: "x" }));
  assert.equal(rec.all()[0]!.parentId, "stage-span-9", "the llm span is a child of the current stage span");
});

test("LLM-ERROR LOCALIZATION: a throwing model call records an llm-error span and re-throws", async () => {
  const rec = new TraceRecorder(newSpine());
  const failing: ModelProvider = { name: "p", isLocal: true, generate: async () => { throw new Error("boom"); }, embed: async () => [] };
  const tp = new TracingModelProvider(failing, rec, price);
  await assert.rejects(() => runWithinTrace({ traceId: "T", taskId: "t" }, () => tp.generate({ prompt: "x" })), /boom/);
  assert.equal(rec.all()[0]!.status, "llm-error", "the failed call is recorded as an llm-error span");
  assert.equal(rec.all()[0]!.costStatus, "usage-unknown");
  assert.equal(rec.all()[0]!.tokens, undefined, "a thrown call has no measured usage counters");
});

test("priced, explicit zero, unpriced, incomplete and failed calls keep cost coverage through rollups, export and restore", async () => {
  const spine = newSpine(), rec = new TraceRecorder(spine);
  const pricing: PriceFor = model => model === "free-model" ? { inputPerM: 0, outputPerM: 0 } : price(model);
  for (const [taskId, response] of [
    ["priced", {}],
    ["free", { model: "free-model", tokensIn: 0, tokensOut: 0 }],
    ["unpriced", { model: "mystery-model" }],
    ["partial", { usageComplete: false }],
  ] as const) {
    const provider = new TracingModelProvider(providerReturning(response), rec, pricing);
    await runWithinTrace({ traceId: "coverage", taskId, agent: "worker", lessonIds: ["lesson"] }, () => provider.generate({ prompt: "x" }));
  }
  const failure = new Error("provider response lost after dispatch");
  const provider = new TracingModelProvider({ ...providerReturning({}), generate: async () => { throw failure; } }, rec, pricing);
  await assert.rejects(() => runWithinTrace({ traceId: "coverage", taskId: "failed", agent: "worker", lessonIds: ["lesson"] }, () => provider.generate({ prompt: "x" })), error => error === failure);
  const spans = rec.trace("coverage"), byTask = new Map(spans.map(span => [span.taskId, span]));
  assert.equal(byTask.get("free")!.cost.totalUsd, 0);
  assert.equal(byTask.get("free")!.costStatus, "known", "declared free pricing and reported zero usage are known zero");
  assert.equal(byTask.get("partial")!.costStatus, "usage-unknown");
  assert.equal(byTask.get("partial")!.tokens, undefined);
  const attributed = attributeCost(spans);
  assert.equal(attributed.total, 0.004);
  assert.equal(attributed.totalKind, "observed-subtotal");
  assert.equal(attributed.unknownCostSpans, 3);
  assert.equal(attributed.unknownByTask.get("priced"), undefined);
  assert.equal(attributed.unknownByTask.get("failed"), 1);
  assert.equal(attributed.unknownByProvider.get("p"), 3);
  assert.equal(attributed.unknownByAgent.get("worker"), 3);
  assert.equal(attributed.unknownByLesson.get("lesson"), 3);
  const view = localCostTraceView(spans);
  assert.equal(view.totalUsd, 0.004);
  assert.equal(view.costKnown, false);
  assert.equal(view.totalKind, "observed-subtotal");
  assert.equal(view.unknownCostSpans, 3);
  assert.equal(view.attribution.providers[0]!.costKnown, false);
  assert.equal(view.attribution.providers[0]!.unknownCostSpans, 3);
  assert.equal(view.forecast.sampleSize, 2, "unknown tasks do not become zero-cost forecast samples");
  assert.equal(view.traces.find(trace => trace.taskId === "unpriced")!.costStatus, "unpriced");
  const exported = toPrivateOtlpSpans(spans, "p".repeat(32));
  assert.equal(exported.filter(span => span.attributes["keep.cost.status"] === "known").length, 2);
  assert.deepEqual(exported.filter(span => span.attributes["keep.cost.status"] === "known").map(span => span.attributes["keep.cost.usd"]), [0.004, 0]);
  assert.ok(exported.filter(span => span.attributes["keep.cost.status"] !== "known").every(span => !("keep.cost.usd" in span.attributes)));
  await spine.seal();
  const restored = localCostTraceView(new TraceRecorder(spine).trace("coverage"));
  assert.equal(restored.totalUsd, view.totalUsd);
  assert.equal(restored.unknownCostSpans, 3);
  assert.deepEqual(restored.traces.map(trace => trace.costStatus), view.traces.map(trace => trace.costStatus));
});

test("legacy persisted costs retain their recorded amount with unknown coverage", async () => {
  const spine = newSpine(), rec = new TraceRecorder(spine);
  await new TracingModelProvider(providerReturning({}), rec, price).generate({ prompt: "x" });
  const { costStatus: _status, ...legacy } = rec.all()[0]!;
  spine.stage({ type: "identity.action", actor: "trace", payload: { event: "span", schema: "keep.trace-span/v1", ...legacy, spanId: "legacy-span" } });
  await spine.seal();
  const restored = new TraceRecorder(spine);
  assert.equal(restored.all().find(span => span.spanId === "legacy-span")!.costStatus, "legacy-unknown");
  const view = localCostTraceView(restored.all());
  assert.equal(view.totalUsd, 0.008, "existing recorded amounts remain available");
  assert.equal(view.totalKind, "observed-subtotal");
  assert.equal(view.unknownCostSpans, 1);
});

test("NO CONTEXT: a model call outside any run still records (adhoc task), never crashes", async () => {
  const rec = new TraceRecorder(newSpine());
  const tp = new TracingModelProvider(providerReturning({}), rec, price);
  await tp.generate({ prompt: "x" });
  assert.equal(rec.all()[0]!.taskId, "adhoc");
});

test("privacy-minimized trace identities remain distinct and queryable by their original run ids", () => {
  const rec = new TraceRecorder(newSpine());
  const cost = { inputUsd: 0, cachedInputUsd: 0, outputUsd: 0, tokenUsd: 0, humanUsd: 0, infraUsd: 0, toolApiUsd: 0, totalUsd: 0 };
  const first = "proj-0f215ee7-ecf9-4a60-ab4f-43baecdba6ec";
  const second = "proj-1f215ee7-ecf9-4a60-ab4f-43baecdba6ec";
  rec.record({ traceId: first, name: "one", taskId: first, cost, startTs: 1, endTs: 2 });
  rec.record({ traceId: second, name: "two", taskId: second, cost, startTs: 1, endTs: 2 });
  assert.equal(rec.trace(first)[0]?.name, "one");
  assert.equal(rec.trace(second)[0]?.name, "two");
  assert.notEqual(rec.trace(first)[0]?.traceId, rec.trace(second)[0]?.traceId);
  assert.notEqual(rec.trace(first)[0]?.traceId, first, "secret-shaped durable identifiers are minimized at rest");
});

test("WIRE (end-to-end): a real autonomy run's model calls land in the run trace with attributed cost", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-gwt-wire-")),
    // The solve seam makes a real model call through the (traced) gateway during the implement stage.
    solve: async (issue) => {
      await app.gateway.generate({ prompt: `solve ${issue.text}` });
      return { solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, detail: "ok" } } } as never;
    },
  });
  await app.autonomyLoop!.runProject("implement and test a parser module", { runId: "runZ", stepBudget: 50 });
  const spans = app.observability.recorder.trace("runZ");
  assert.ok(spans.some((s) => s.name.startsWith("gen_ai:")), "the run trace includes a model-call span");
  const attribution = app.observability.attribute("runZ");
  assert.ok(attribution.byTask.has("runZ"), "cost is attributed to the run");
});
