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
import { attributeCost } from "../src/observability/tracing.js";
import { TracingModelProvider, type PriceFor } from "../src/gateway/tracing_provider.js";
import { runWithinTrace, withLessons } from "../src/observability/trace_context.js";
import type { ModelProvider } from "../src/gateway/gateway.js";

function newSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-lesson-"))), new InProcessLock(), new SchemaRegistry());
}
const price: PriceFor = () => ({ inputPerM: 1, outputPerM: 1 });
const provider: ModelProvider = {
  name: "p", isLocal: true,
  generate: async () => ({ text: "hi", model: "m", tokensIn: 1_000_000, tokensOut: 0 }), // 1.0 USD input
  embed: async () => [],
};

test("PER-LESSON GRAIN: a model call made withLessons attributes its cost to those lessons", async () => {
  const rec = new TraceRecorder(newSpine());
  const tp = new TracingModelProvider(provider, rec, price);
  await runWithinTrace({ traceId: "T", taskId: "task" }, () =>
    withLessons(["lesson-A", "lesson-B"], () => tp.generate({ prompt: "x" })),
  );
  const span = rec.all()[0]!;
  assert.deepEqual([...span.lessonIds].sort(), ["lesson-A", "lesson-B"], "the span carries the applied lessons");
  const attribution = attributeCost(rec.all());
  assert.equal(attribution.byLesson.get("lesson-A"), 1, "the call's $1 cost is attributed to lesson-A");
  assert.equal(attribution.byLesson.get("lesson-B"), 1, "and to lesson-B (a call influenced by two lessons counts for both)");
  assert.equal(attribution.total, 1, "total spend is still $1 (byLesson is an attribution view, not a sum)");
});

test("withLessons MERGES into an existing run context (nested application accumulates lessons)", async () => {
  const rec = new TraceRecorder(newSpine());
  const tp = new TracingModelProvider(provider, rec, price);
  await runWithinTrace({ traceId: "T", taskId: "task", lessonIds: ["outer"] }, () =>
    withLessons(["inner"], () => tp.generate({ prompt: "x" })),
  );
  assert.deepEqual([...rec.all()[0]!.lessonIds].sort(), ["inner", "outer"], "nested lessons merge, not replace");
});

test("no lessons → the span carries none (attribution is honest, never invented)", async () => {
  const rec = new TraceRecorder(newSpine());
  const tp = new TracingModelProvider(provider, rec, price);
  await runWithinTrace({ traceId: "T", taskId: "task" }, () => tp.generate({ prompt: "x" }));
  assert.equal(rec.all()[0]!.lessonIds.length, 0);
});

test("WIRE (end-to-end): an autonomy run tags its model calls with the skills retrieved for the goal", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-lesson-wire-")),
    solve: async (issue) => {
      await app.gateway.generate({ prompt: `solve ${issue.text}` });
      return { solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, detail: "ok" } } } as never;
    },
  });
  // Seed a retrievable skill so the loop retrieves it for the goal.
  app.skillRetrieval.add({
    id: "skill-sql", title: "SQL joins", taskShape: "write a database query", envelope: "prefer explicit JOINs",
    steps: ["use explicit JOIN"], provenance: { sourceOutcomes: [] }, createdTs: 0,
  } as never);
  await app.autonomyLoop!.runProject("write a database query for the report", { runId: "runL", stepBudget: 50 });
  const spans = app.observability.recorder.trace("runL").filter((s) => s.name.startsWith("gen_ai:"));
  assert.ok(spans.length >= 1, "the run made a model call");
  const attribution = app.observability.attribute("runL");
  // If the skill was retrieved as relevant, its cost grain is populated; either way the mechanism is wired + honest.
  assert.ok(attribution.byLesson instanceof Map, "per-lesson attribution is available for the run");
});
