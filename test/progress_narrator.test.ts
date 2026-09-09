import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { ProgressNarrator, bufferSink } from "../src/autonomy/progress_narrator.js";

function newSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-narr-"))), new InProcessLock(), new SchemaRegistry());
}

test("events are sequenced and timestamped", () => {
  const n = new ProgressNarrator("run-1", newSpine(), () => 1000);
  const a = n.start("research", "Looking into the romance market");
  const b = n.update("research", "Found 12 comps");
  assert.equal(a.seq, 0);
  assert.equal(b.seq, 1);
  assert.equal(a.at, 1000);
  assert.equal(a.runId, "run-1");
});

test("subscribers receive typed events", () => {
  const n = new ProgressNarrator("run-2", newSpine());
  const { sink, events } = bufferSink();
  n.subscribe(sink);
  n.start("plan", "Drafting a beat sheet");
  assert.equal(events.length, 1);
  assert.equal(events[0]!.stage, "plan");
  assert.equal(events[0]!.phase, "start");
  assert.equal(events[0]!.headline, "Drafting a beat sheet");
});

test("a throwing sink does not break narration (best-effort fan-out)", () => {
  const n = new ProgressNarrator("run-3", newSpine());
  n.subscribe(() => {
    throw new Error("render crashed");
  });
  const { sink, events } = bufferSink();
  n.subscribe(sink);
  // Should not throw despite the bad sink, and the good sink still gets the event.
  assert.doesNotThrow(() => n.update("implement", "Writing chapter 3"));
  assert.equal(events.length, 1);
});

test("every event is spine-logged as an auditable trace", async () => {
  const spine = newSpine();
  const n = new ProgressNarrator("run-4", spine);
  n.start("vet", "Running safety checks");
  n.done("vet", "All checks passed");
  await spine.seal();
  const events = spine.replay().map((e) => (e.payload as Record<string, unknown>)["event"]);
  const narrated = events.filter((e) => e === "progress.narrated");
  assert.equal(narrated.length, 2);
});

test("fraction is clamped to [0,1] and omitted when not provided (never fabricated)", () => {
  const n = new ProgressNarrator("run-5", newSpine());
  assert.equal(n.update("x", "no fraction").fraction, undefined);
  assert.equal(n.narrate({ stage: "x", phase: "update", headline: "over", fraction: 1.7 }).fraction, 1);
  assert.equal(n.narrate({ stage: "x", phase: "update", headline: "under", fraction: -0.3 }).fraction, 0);
});

test("all five phases are representable, including blocked and failed (honest framing)", () => {
  const n = new ProgressNarrator("run-6", newSpine());
  assert.equal(n.start("s", "h").phase, "start");
  assert.equal(n.update("s", "h").phase, "update");
  assert.equal(n.done("s", "h").phase, "done");
  assert.equal(n.blocked("s", "waiting on your OK to deploy").phase, "blocked");
  assert.equal(n.failed("s", "the build broke").phase, "failed");
});

test("unsubscribe stops delivery", () => {
  const n = new ProgressNarrator("run-7", newSpine());
  const { sink, events } = bufferSink();
  const off = n.subscribe(sink);
  n.start("s", "one");
  off();
  n.start("s", "two");
  assert.equal(events.length, 1); // only the first was delivered
});

test("detail is carried when provided and trimmed", () => {
  const n = new ProgressNarrator("run-8", newSpine());
  const e = n.start("research", "  Researching  ", "  the current market for cozy mysteries  ");
  assert.equal(e.headline, "Researching");
  assert.equal(e.detail, "the current market for cozy mysteries");
});
