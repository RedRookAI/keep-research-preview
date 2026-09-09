import { test } from "node:test";
import assert from "node:assert/strict";
import { DriftMonitor } from "../src/loop/drift_monitor.js";
import { SelfImprovementBus, type OutcomeSignal, type Learner } from "../src/loop/self_improvement_bus.js";

function sig(over: Partial<OutcomeSignal> = {}): OutcomeSignal {
  return { solveId: "s", taskShape: "build", testsPassed: true, mergeVerdict: "merged", timestamp: Date.now(), ...over };
}

// ─── baseline lifecycle ───

test("baseline: not ready until baselineSize signals observed, then frozen", () => {
  const dm = new DriftMonitor({ baselineSize: 5 });
  for (let i = 0; i < 4; i++) dm.observe(sig());
  assert.equal(dm.status().baselineReady, false);
  dm.observe(sig()); // 5th → freeze
  assert.equal(dm.status().baselineReady, true);
});

// ─── PSI detects a categorical distribution shift ───

test("PSI: a large shift in taskShape distribution registers drift", () => {
  const dm = new DriftMonitor({ baselineSize: 10, windowSize: 10, driftPsi: 0.2 });
  // Baseline: all "build".
  for (let i = 0; i < 10; i++) dm.observe(sig({ taskShape: "build" }));
  assert.equal(dm.status().level, "stable");
  // Window: all "refactor" — a total distribution shift → high PSI.
  for (let i = 0; i < 10; i++) dm.observe(sig({ taskShape: "refactor" }));
  const st = dm.status();
  assert.equal(st.level, "drift");
  assert.ok(st.maxPsi >= 0.2, `expected high PSI, got ${st.maxPsi}`);
  assert.match(st.reason, /PSI|latched/);
});

test("PSI: a stable distribution stays 'stable'", () => {
  const dm = new DriftMonitor({ baselineSize: 10, windowSize: 10 });
  for (let i = 0; i < 10; i++) dm.observe(sig({ taskShape: "build" }));
  for (let i = 0; i < 10; i++) dm.observe(sig({ taskShape: "build" }));
  assert.equal(dm.status().level, "stable");
});

// ─── CUSUM catches sustained completion decline (the compounding signal) ───

test("CUSUM: sustained completion-rate decline registers drift even without a PSI shift", () => {
  // Baseline: high completion (all pass), taskShape constant (no PSI shift).
  const dm = new DriftMonitor({ baselineSize: 10, windowSize: 20, cusumThreshold: 3.0 });
  for (let i = 0; i < 10; i++) dm.observe(sig({ testsPassed: true }));
  // Now a run of failures — same taskShape (PSI ~0) but completion collapses.
  for (let i = 0; i < 10; i++) dm.observe(sig({ testsPassed: false }));
  const st = dm.status();
  assert.equal(st.level, "drift");
  assert.ok(st.completionCusum >= 3.0, `expected CUSUM accumulation, got ${st.completionCusum}`);
});

// ─── drift latches until cleared ───

test("latch: drift stays latched until clearSafeMode(), then resets", () => {
  const dm = new DriftMonitor({ baselineSize: 5, windowSize: 5, driftPsi: 0.2 });
  for (let i = 0; i < 5; i++) dm.observe(sig({ taskShape: "build" }));
  for (let i = 0; i < 5; i++) dm.observe(sig({ taskShape: "totally-different" }));
  assert.equal(dm.inSafeMode(), true);
  // Even if the window returns to baseline-like, the latch holds until explicitly cleared.
  for (let i = 0; i < 5; i++) dm.observe(sig({ taskShape: "build" }));
  assert.equal(dm.inSafeMode(), true, "drift must latch until a fix clears it");
  dm.clearSafeMode();
  assert.equal(dm.inSafeMode(), false);
});

// ─── integration: safe-mode pauses IMPROVE but not HEAL/PROTECT on the bus ───

test("integration: in drift safe-mode the bus pauses improve-class learners but still runs heal/protect", async () => {
  const fired: string[] = [];
  const dm = new DriftMonitor({ baselineSize: 1, windowSize: 5, driftPsi: 0.2 });
  const bus = new SelfImprovementBus({ anchorThreshold: 1, improveGate: () => !dm.inSafeMode() });

  // Register: the drift monitor (protect) + a heal learner + an improve learner.
  bus.register(dm.asLearner());
  const heal: Learner = { id: "heal", loopClass: "heal", onOutcome: () => { fired.push("heal"); } };
  const improve: Learner = { id: "improve", loopClass: "improve", onOutcome: () => { fired.push("improve"); } };
  bus.register(heal);
  bus.register(improve);

  // Signal 1 freezes the drift baseline (taskShape "build").
  await bus.publish(sig({ taskShape: "build" }));
  // Signals with a shifted taskShape drive the monitor into drift; on the drifting signal, the monitor
  // (protect, runs first) latches drift, so the improve learner is gated OFF while heal still runs.
  fired.length = 0;
  await bus.publish(sig({ taskShape: "shifted" }));
  await bus.publish(sig({ taskShape: "shifted" }));

  assert.ok(dm.inSafeMode(), "monitor should be in drift safe-mode after the shift");
  assert.ok(fired.includes("heal"), "heal-class learner must still run in safe-mode");
  // After drift latched, improve must be paused. Count how many improve fires happened AFTER latch:
  const improveAfterLatch = fired.filter((f) => f === "improve").length;
  assert.equal(improveAfterLatch, 0, "improve-class learner must be paused in drift safe-mode");
});

test("integration: with no drift, improve-class learners run normally", async () => {
  const fired: string[] = [];
  const dm = new DriftMonitor({ baselineSize: 1, windowSize: 5, driftPsi: 0.2 });
  const bus = new SelfImprovementBus({ anchorThreshold: 1, improveGate: () => !dm.inSafeMode() });
  bus.register(dm.asLearner());
  bus.register({ id: "improve", loopClass: "improve", onOutcome: () => { fired.push("improve"); } });
  await bus.publish(sig({ taskShape: "build" }));
  await bus.publish(sig({ taskShape: "build" })); // stable → no drift
  assert.ok(fired.includes("improve"), "improve should run when stable");
});
