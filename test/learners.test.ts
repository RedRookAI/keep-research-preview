import { test } from "node:test";
import assert from "node:assert/strict";
import {
  PromptLearner,
  MemoryLearner,
  CurriculumLearner,
  type ImprovementProposer,
  type ProposalLike,
} from "../src/loop/learners.js";
import { SelfImprovementBus, type OutcomeSignal } from "../src/loop/self_improvement_bus.js";
import { DriftMonitor } from "../src/loop/drift_monitor.js";

function sig(over: Partial<OutcomeSignal> = {}): OutcomeSignal {
  return { solveId: "s", taskShape: "build", testsPassed: true, mergeVerdict: "merged", timestamp: Date.now(), ...over };
}

// A spy proposer that records proposals and always accepts.
function spyProposer(): ImprovementProposer & { proposals: ProposalLike[] } {
  const proposals: ProposalLike[] = [];
  return {
    proposals,
    proposeLoop(initial) {
      proposals.push(initial);
      return { outcome: { decision: "accepted", reason: "ok" }, rounds: 1 };
    },
  };
}

const bump = (v: string, e: readonly string[]): string => `${v}+${e.length}`;

// ─── PromptLearner: proposes only on a PATTERN, not noise ───

test("PromptLearner does NOT propose below min samples", () => {
  const p = spyProposer();
  const learner = new PromptLearner(p, { minSamples: 5, currentVersion: () => "v1", mint: bump });
  learner.onOutcome(sig({ testsPassed: false }));
  learner.onOutcome(sig({ testsPassed: false }));
  assert.equal(p.proposals.length, 0); // only 2 samples < 5
});

test("PromptLearner proposes once a failure pattern crosses the trigger", () => {
  const p = spyProposer();
  const learner = new PromptLearner(p, { minSamples: 5, failureRateTrigger: 0.4, windowSize: 10, currentVersion: (s) => `prompt@${s}`, mint: bump });
  // 5 samples, 3 failures = 0.6 > 0.4 trigger.
  for (const passed of [false, false, true, false, true]) learner.onOutcome(sig({ testsPassed: passed }));
  assert.equal(p.proposals.length, 1);
  assert.equal(p.proposals[0]?.component, "prompt");
  assert.match(p.proposals[0]?.rationale ?? "", /build/);
});

test("PromptLearner does NOT propose when the failure rate is below trigger", () => {
  const p = spyProposer();
  const learner = new PromptLearner(p, { minSamples: 5, failureRateTrigger: 0.4, currentVersion: () => "v", mint: bump });
  for (const passed of [true, true, true, true, false]) learner.onOutcome(sig({ testsPassed: passed })); // 0.2 < 0.4
  assert.equal(p.proposals.length, 0);
});

test("PromptLearner cooldown prevents repeat proposals until cleared", () => {
  const p = spyProposer();
  const learner = new PromptLearner(p, { minSamples: 3, failureRateTrigger: 0.4, currentVersion: () => "v", mint: bump });
  for (let i = 0; i < 6; i++) learner.onOutcome(sig({ testsPassed: false }));
  assert.equal(p.proposals.length, 1); // cooldown holds
  learner.clearCooldown("build");
  for (let i = 0; i < 3; i++) learner.onOutcome(sig({ testsPassed: false }));
  assert.equal(p.proposals.length, 2); // fires again after new evidence
});

// ─── MemoryLearner: consolidates only after K corroborations (poison/noise guard) ───

test("MemoryLearner does NOT consolidate a one-off lesson", () => {
  const p = spyProposer();
  const learner = new MemoryLearner(p, { corroborationK: 2, currentVersion: () => "m", mint: bump });
  learner.onOutcome(sig({ testsPassed: false, mergeVerdict: "rejected", rejectReason: "flaky test" }));
  assert.equal(p.proposals.length, 0); // seen once, K=2
});

test("MemoryLearner consolidates a lesson after K corroborations", () => {
  const p = spyProposer();
  const learner = new MemoryLearner(p, { corroborationK: 2, currentVersion: () => "m", mint: bump });
  const s = sig({ testsPassed: false, mergeVerdict: "rejected", rejectReason: "missing null check" });
  learner.onOutcome(s);
  learner.onOutcome(s); // 2nd corroboration → consolidate
  assert.equal(p.proposals.length, 1);
  assert.equal(p.proposals[0]?.component, "memory-lesson");
  assert.equal(learner.timesSeen("build", "missing null check"), 2);
});

test("MemoryLearner ignores outcomes with no counterexample", () => {
  const p = spyProposer();
  const learner = new MemoryLearner(p, { corroborationK: 1, currentVersion: () => "m", mint: bump });
  learner.onOutcome(sig({ testsPassed: true, mergeVerdict: "merged" })); // no reject-reason
  assert.equal(p.proposals.length, 0);
});

// ─── CurriculumLearner: ranks failure modes ───

test("CurriculumLearner ranks task shapes by failure count and reports top priority", () => {
  const c = new CurriculumLearner();
  c.onOutcome(sig({ taskShape: "refactor", testsPassed: false }));
  c.onOutcome(sig({ taskShape: "refactor", testsPassed: false }));
  c.onOutcome(sig({ taskShape: "bugfix", testsPassed: false }));
  c.onOutcome(sig({ taskShape: "feature", testsPassed: true }));
  const curriculum = c.curriculum();
  assert.equal(curriculum[0]?.taskShape, "refactor"); // most failures
  assert.equal(curriculum[0]?.failures, 2);
  assert.equal(c.topPriority(), "refactor");
});

test("CurriculumLearner reports null priority when nothing is failing", () => {
  const c = new CurriculumLearner();
  c.onOutcome(sig({ testsPassed: true }));
  assert.equal(c.topPriority(), null);
});

// ─── integration: learners are dormant in observing, fire after ready, pause under drift ───

test("integration: improve-learners are dormant during observing, active after anchor-ready", async () => {
  const p = spyProposer();
  const bus = new SelfImprovementBus({ anchorThreshold: 3 });
  bus.register(new PromptLearner(p, { minSamples: 1, failureRateTrigger: 0.1, currentVersion: () => "v", mint: bump }));
  // Observing (below 3): learner should not be dispatched.
  await bus.publish(sig({ testsPassed: false }));
  await bus.publish(sig({ testsPassed: false }));
  assert.equal(p.proposals.length, 0, "dormant during observing");
  // Crosses threshold → dispatched.
  await bus.publish(sig({ testsPassed: false }));
  assert.ok(p.proposals.length >= 1, "active after anchor-ready");
});

test("integration: a curriculum (protect) learner runs even during observing", async () => {
  const c = new CurriculumLearner();
  const bus = new SelfImprovementBus({ anchorThreshold: 100 }); // never leaves observing
  bus.register(c);
  await bus.publish(sig({ taskShape: "x", testsPassed: false }));
  assert.equal(c.topPriority(), "x", "protect-class monitor observes during observing phase");
});

test("integration: improve-learners paused under drift safe-mode, curriculum still runs", async () => {
  const p = spyProposer();
  const dm = new DriftMonitor({ baselineSize: 1, windowSize: 5, driftPsi: 0.2 });
  const bus = new SelfImprovementBus({ anchorThreshold: 1, improveGate: () => !dm.inSafeMode() });
  bus.register(dm.asLearner());
  const c = new CurriculumLearner();
  bus.register(c);
  bus.register(new PromptLearner(p, { minSamples: 1, failureRateTrigger: 0.1, currentVersion: () => "v", mint: bump }));

  await bus.publish(sig({ taskShape: "build", testsPassed: false })); // baseline
  const before = p.proposals.length;
  await bus.publish(sig({ taskShape: "shifted", testsPassed: false })); // drift
  await bus.publish(sig({ taskShape: "shifted", testsPassed: false }));
  assert.ok(dm.inSafeMode(), "drift latched");
  // Curriculum kept tracking; prompt learner paused after latch.
  assert.ok(c.curriculum().length > 0, "curriculum still tracks under drift");
  // no NEW proposals should occur while latched (the shifted-shape signals are gated off for improve)
  assert.equal(p.proposals.length, before, "improve paused under drift safe-mode");
});
