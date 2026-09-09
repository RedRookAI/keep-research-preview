import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SelfImprovementBus,
  CollectingLearningErrorSink,
  reuseSignal,
  type OutcomeSignal,
  type Learner,
} from "../src/loop/self_improvement_bus.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function sig(over: Partial<OutcomeSignal> = {}): OutcomeSignal {
  return {
    solveId: "s1",
    taskShape: "build",
    testsPassed: true,
    mergeVerdict: "merged",
    timestamp: Date.now(),
    ...over,
  };
}

function recordingLearner(id: string, loopClass: Learner["loopClass"], sink: string[]): Learner {
  return { id, loopClass, onOutcome: () => { sink.push(id); } };
}

// ─── observing → learning gate ───

test("observing phase: below threshold, records but does NOT dispatch to learners", async () => {
  const fired: string[] = [];
  const bus = new SelfImprovementBus({ anchorThreshold: 3 });
  bus.register(recordingLearner("L", "improve", fired));
  const r1 = await bus.publish(sig());
  const r2 = await bus.publish(sig());
  assert.equal(r1.dispatched, false);
  assert.equal(r2.dispatched, false);
  assert.equal(r1.recorded, true);
  assert.deepEqual(fired, []); // no learning yet — observing
  assert.equal(bus.readiness().ready, false);
});

test("learning phase: at/above threshold, dispatches to learners", async () => {
  const fired: string[] = [];
  const bus = new SelfImprovementBus({ anchorThreshold: 3 });
  bus.register(recordingLearner("L", "improve", fired));
  await bus.publish(sig());
  await bus.publish(sig());
  const r3 = await bus.publish(sig()); // count reaches 3 → ready → dispatch
  assert.equal(r3.readiness.ready, true);
  assert.equal(r3.dispatched, true);
  assert.deepEqual(fired, ["L"]);
});

// ─── learner isolation: one throw cannot break the loop ───

test("isolation: a throwing learner does not stop the others or the bus", async () => {
  const fired: string[] = [];
  const errors: string[] = [];
  const bus = new SelfImprovementBus({ anchorThreshold: 1, onLearnerError: (id) => errors.push(id) });
  bus.register({ id: "boom", loopClass: "improve", onOutcome: () => { throw new Error("kaboom"); } });
  bus.register(recordingLearner("ok", "improve", fired));
  const r = await bus.publish(sig());
  assert.equal(r.dispatched, true);
  assert.deepEqual(errors, ["boom"]);   // the error was caught + reported
  assert.deepEqual(fired, ["ok"]);       // the healthy learner still ran
});

test("isolated learner failures remain visible through a spine-independent diagnostic sink", async () => {
  const sink = new CollectingLearningErrorSink();
  const bus = new SelfImprovementBus({ anchorThreshold: 1, errorSink: sink });
  bus.register({ id: "broken-protector", loopClass: "protect", onOutcome: () => { throw new Error("append failed"); } });
  await bus.publish(sig());
  assert.deepEqual(sink.snapshot().map((failure) => failure.componentId), ["broken-protector"]);
  assert.match(sink.snapshot()[0]?.error ?? "", /append failed/);
});

test("ephemeral tenant authority is delivered only to a learner that explicitly accepts it", async () => {
  const seen: Array<object | undefined> = [];
  const bus = new SelfImprovementBus({ anchorThreshold: 1 });
  bus.register({ id: "ordinary", loopClass: "protect", onOutcome: (signal) => { seen.push(signal.scopeToken); } });
  bus.register({ id: "scope-consumer", loopClass: "protect", acceptsScopeBinding: true,
    onOutcome: (signal) => { seen.push(signal.scopeToken); } });
  const token = {};
  await bus.publish(sig({ scopeId: "tenant-a", scopeToken: token }));
  assert.deepEqual(seen, [undefined, token]);
});

// ─── precedence: heal > protect > improve ───

test("precedence: learners fire in heal → protect → improve order regardless of registration order", async () => {
  const fired: string[] = [];
  const bus = new SelfImprovementBus({ anchorThreshold: 1 });
  bus.register(recordingLearner("improve", "improve", fired));
  bus.register(recordingLearner("heal", "heal", fired));
  bus.register(recordingLearner("protect", "protect", fired));
  await bus.publish(sig());
  assert.deepEqual(fired, ["heal", "protect", "improve"]);
});

// ─── spine recording (Monitor writes to the shared K even while observing) ───

test("monitor: every signal is recorded to the spine, even in the observing phase", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-bus-"));
  const spine = new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
  const bus = new SelfImprovementBus({ spine, anchorThreshold: 100 }); // never leaves observing
  await bus.publish(sig({ solveId: "obs-1" }));
  await spine.seal();
  const events = spine.replay().filter((e) => (e.payload as { event?: string })?.event === "outcome_signal");
  assert.equal(events.length, 1);
  assert.equal((events[0]?.payload as { solveId?: string })?.solveId, "obs-1");
});

// ─── sequencing: registration is idempotent by id ───

test("register is idempotent by id", () => {
  const bus = new SelfImprovementBus({ anchorThreshold: 1 });
  const l = recordingLearner("dup", "improve", []);
  bus.register(l);
  bus.register(l);
  assert.deepEqual(bus.learnerIds, ["dup"]);
});

// ─── reuse signal: execution + human combined; reject-reason → counterexample ───

test("reuseSignal: passing tests + merge is strongly positive", () => {
  const r = reuseSignal(sig({ testsPassed: true, mergeVerdict: "merged" }));
  assert.equal(r.reward, 2);
  assert.equal(r.counterexample, undefined);
});

test("reuseSignal: failing tests + reject is strongly negative, with reason as counterexample", () => {
  const r = reuseSignal(sig({ testsPassed: false, mergeVerdict: "rejected", rejectReason: "broke the build on edge case X" }));
  assert.equal(r.reward, -2);
  assert.equal(r.counterexample, "broke the build on edge case X");
});

test("reuseSignal: execution dominates — passing tests but human reject is net neutral, not positive", () => {
  // Guard: never let acceptance-rate alone drive it. Tests pass (+1), human rejects (-1) → 0.
  const r = reuseSignal(sig({ testsPassed: true, mergeVerdict: "rejected" }));
  assert.equal(r.reward, 0);
});
