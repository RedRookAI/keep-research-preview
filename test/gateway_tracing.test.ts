import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { TraceRecorder } from "../src/observability/tracing.js";
import { TracingModelProvider, type PriceFor } from "../src/gateway/tracing_provider.js";
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
  // 1000/1e6*1 + 1000/1e6*3 = 0.001 + 0.003 = 0.004
  assert.ok(Math.abs(spans[0]!.cost.totalUsd - 0.004) < 1e-9, "per-call cost computed from tokens × price");
});

test("HONEST COST: an unknown model → zero cost (never fabricated)", async () => {
  const rec = new TraceRecorder(newSpine());
  const tp = new TracingModelProvider(providerReturning({ model: "mystery-model" }), rec, price);
  await runWithinTrace({ traceId: "T", taskId: "t" }, () => tp.generate({ prompt: "x" }));
  assert.equal(rec.all()[0]!.cost.totalUsd, 0, "no pricing → zero, not a guess");
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
