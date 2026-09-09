import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { buildObservabilitySuite } from "../src/observability/observability_suite.js";
import type { Span } from "../src/observability/tracing.js";

function newSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-obs-"))), new InProcessLock(), new SchemaRegistry());
}
const zero = { inputUsd: 0, cachedInputUsd: 0, outputUsd: 0, tokenUsd: 0, humanUsd: 0, infraUsd: 0, toolApiUsd: 0, totalUsd: 0 };

test("TRIAGE: the earliest failing span with no failing ancestor is the root; downstream is propagation", () => {
  const obs = buildObservabilitySuite(newSpine());
  const t = 1000;
  // root fails first; a later span also fails (propagation).
  obs.recorder.record({ name: "localize", taskId: "T", traceId: "T", cost: zero, startTs: t, endTs: t + 1, status: "ok" });
  obs.recorder.record({ name: "plan", taskId: "T", traceId: "T", cost: zero, startTs: t + 2, endTs: t + 3, status: "tool-error" });
  obs.recorder.record({ name: "implement", taskId: "T", traceId: "T", cost: zero, startTs: t + 4, endTs: t + 5, status: "llm-error" });
  const d = obs.diagnose("T");
  assert.ok(d, "a diagnosis is produced");
  assert.equal(d!.failureType, "tool-error", "the ROOT (earliest) failure type, not the downstream one");
  assert.ok(d!.evidence.some((e) => /propagation/.test(e)), "downstream failures noted as propagation");
});

test("TRIAGE: a clean trace yields no diagnosis", () => {
  const obs = buildObservabilitySuite(newSpine());
  obs.recorder.record({ name: "plan", taskId: "T", traceId: "T", cost: zero, startTs: 1, endTs: 2, status: "ok" });
  assert.equal(obs.diagnose("T"), undefined);
});

test("CONFIRM-BY-RERUN (SOTA): attribution is unproven until a targeted rerun RECOVERS the task", async () => {
  const obs = buildObservabilitySuite(newSpine());
  const diagnosis = { implicatedSpanId: "s1", failureType: "tool-error" as const, rootCause: "x", evidence: [], triageConfidence: 0.7 };
  const notRecovered = await obs.confirm(diagnosis, async () => false);
  assert.equal(notRecovered.confirmed, false, "a fix that doesn't recover does NOT confirm the hypothesis");
  const recovered = await obs.confirm(diagnosis, async () => true);
  assert.equal(recovered.confirmed, true, "only a recovering rerun confirms attribution");
});

test("COST ATTRIBUTION: spend rolls up per task", () => {
  const obs = buildObservabilitySuite(newSpine());
  obs.recorder.record({ name: "call", taskId: "T1", traceId: "T1", agent: "claude", cost: { ...zero, totalUsd: 0.5 }, startTs: 1, endTs: 2, status: "ok" });
  const a = obs.attribute();
  assert.equal(a.total, 0.5);
  assert.equal(a.byTask.get("T1"), 0.5);
  assert.equal(a.byAgent.get("claude"), 0.5);
});

test("WIRE (end-to-end): a real autonomy run records per-stage spans, and a failing stage is localized", async () => {
  const { composeKeep } = await import("../src/compose.js");
  let solveCalls = 0;
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-obs-wire-")),
    solve: async () => { solveCalls++; throw new Error("solve blew up in implement"); },
  });
  assert.ok(app.observability, "observability wired onto the app");
  const run = await app.autonomyLoop!.runProject("fix the failing auth test", { runId: "runX", stepBudget: 50 });
  assert.equal(solveCalls, 1, "the intended solver fault was actually reached");
  assert.equal(run.state.status, "waiting-reconciliation", "a throwing solver has an uncertain outcome, not proven retry safety");
  assert.match(run.state.note ?? "", /solve blew up in implement/u);
  const spans: Span[] = app.observability.recorder.trace("runX");
  assert.ok(spans.length >= 1, "the autonomy loop recorded stage spans for the run");
  const d = app.observability.diagnose("runX");
  assert.ok(d, "the failing run is diagnosed");
  assert.equal(d!.failureType, "tool-error", "the throwing stage is localized as a tool-error");
  const resumed = await app.autonomyLoop!.resumeProject("runX");
  assert.deepEqual(resumed.state.wait, run.state.wait);
  assert.equal(solveCalls, 1, "diagnosis and ordinary resume do not authorize replay");
});
