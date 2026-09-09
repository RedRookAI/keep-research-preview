import { test } from "node:test";
import assert from "node:assert/strict";

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { MemoryStore } from "../src/memory/store.js";
import { RollbackLedger } from "../src/control/rollback.js";
import { LearningLoop, type LearningObservation } from "../src/learning/learning_loop.js";
import { RegressionGuard, type RegressionGuardDeps } from "../src/learning/regression_guard.js";
import type { LearningStepReport } from "../src/learning/learning_loop.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-learn-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}
function newMemory(spine: Spine): MemoryStore {
  return new MemoryStore(spine, new ModelGateway(new LocalProvider()));
}

// ── LearningLoop closes the loop through REAL graduation ─────────────────────

test("INVARIANT: LearningLoop graduates a lesson ONLY via recorded clean outcomes (not assertion)", async () => {
  const spine = newSpine();
  const memory = newMemory(spine);
  const lesson = (await memory.ingest("always run the linter", { origin: "self", scope: "project" }))!;
  assert.equal(lesson.tier, "candidate", "starts as candidate");

  const loop = new LearningLoop({ memory });
  // Feed repeated clean outcomes — graduation happens through the store's two gates.
  let graduatedAt = -1;
  for (let i = 0; i < 8; i++) {
    const obs: LearningObservation[] = [{ appliedLessonIds: [lesson.id], cleanResolved: true, context: `task-${i}` }];
    const report = loop.step(obs);
    if (report.graduated.includes(lesson.id)) { graduatedAt = i; break; }
  }
  assert.ok(graduatedAt >= 0, "lesson graduated to confirmed via recorded outcomes");
  assert.equal(memory.get(lesson.id)!.tier, "confirmed");
});

test("INVARIANT: a lesson with failing outcomes never graduates", async () => {
  const spine = newSpine();
  const memory = newMemory(spine);
  const lesson = (await memory.ingest("bad habit rule here", { origin: "self", scope: "project" }))!;
  const loop = new LearningLoop({ memory });
  for (let i = 0; i < 8; i++) {
    loop.step([{ appliedLessonIds: [lesson.id], cleanResolved: false, context: `t-${i}` }]);
  }
  assert.notEqual(memory.get(lesson.id)!.tier, "confirmed", "failing lesson stays untrusted");
});

test("LearningLoop computes A/B improvement vs a frozen baseline", () => {
  const spine = newSpine();
  const memory = newMemory(spine);
  const loop = new LearningLoop({ memory, baseline: { cleanResolvedRate: 0.5, regressionRate: 0.1 } });
  const report = loop.step([{ appliedLessonIds: [], cleanResolved: true, context: "t" }], { cleanResolvedRate: 0.7, regressionRate: 0.1 });
  assert.ok(report.improvement, "improvement report present");
  assert.ok(report.improvement!.cleanResolvedDelta > 0, "learning helps (positive delta)");
});

test("LearningLoop reports the diversity signal over a batch", () => {
  const spine = newSpine();
  const memory = newMemory(spine);
  const loop = new LearningLoop({ memory });
  const repetitive = loop.step([
    { appliedLessonIds: [], cleanResolved: true, context: "same" },
    { appliedLessonIds: [], cleanResolved: true, context: "same" },
    { appliedLessonIds: [], cleanResolved: true, context: "same" },
    { appliedLessonIds: [], cleanResolved: true, context: "same" },
  ]);
  assert.ok(repetitive.diversitySignal < 0.5, "repetitive batch → low diversity signal");
});

// ── RegressionGuard: three trip conditions ──────────────────────────────────

function guardDeps(spine: Spine): { deps: RegressionGuardDeps; undos: string[] } {
  const undos: string[] = [];
  const rollback = new RollbackLedger(spine);
  // seed some reversible learning actions so rollback has something to invert
  for (let i = 0; i < 10; i++) {
    rollback.record({ id: `a${i}`, artifact: `lesson-promo-${i}`, undo: async () => { undos.push(`a${i}`); } });
  }
  return { deps: { spine, rollback }, undos };
}

function stepReport(primary: number, diversity = 1, corroborationConflict = false): LearningStepReport {
  return {
    observed: 10, outcomesRecorded: 10, graduated: [], demoted: [],
    primaryMetric: primary, diversitySignal: diversity,
    ...(corroborationConflict ? { improvement: { baseline: { cleanResolvedRate: 0.5, regressionRate: 0.1 }, current: { cleanResolvedRate: 0.7, regressionRate: 0.3 }, cleanResolvedDelta: 0.2, corroborationConflict: true } } : {}),
  };
}

test("INVARIANT: rise-then-collapse — drop-from-peak trips the guard + rolls back to peak", async () => {
  const spine = newSpine();
  const { deps, undos } = guardDeps(spine);
  const guard = new RegressionGuard(deps);
  // rise
  await guard.observe(stepReport(0.6));
  await guard.observe(stepReport(0.8)); // peak
  await guard.observe(stepReport(0.85)); // new peak, past warmup
  const drop = await guard.observe(stepReport(0.5)); // collapse from 0.85
  assert.equal(drop.tripped, true, "collapse detected");
  assert.equal(drop.trip!.kind, "drop-from-peak");
  assert.equal(guard.isFrozen, true, "loop frozen on trip");
  assert.ok(undos.length > 0, "rollback ran real inverses to restore last-good state");
});

test("INVARIANT: diversity-collapse is a LEADING indicator — trips before the metric falls", async () => {
  const spine = newSpine();
  const { deps } = guardDeps(spine);
  const guard = new RegressionGuard(deps);
  await guard.observe(stepReport(0.6, 1));
  await guard.observe(stepReport(0.7, 1));
  await guard.observe(stepReport(0.9, 1)); // metric still HIGH...
  const collapse = await guard.observe(stepReport(0.9, 0.1)); // ...but diversity collapsed
  assert.equal(collapse.tripped, true, "early-warning fired while metric still high");
  assert.equal(collapse.trip!.kind, "diversity-collapse");
});

test("INVARIANT: Goodhart conflict trips even while the primary metric RISES", async () => {
  const spine = newSpine();
  const { deps } = guardDeps(spine);
  const guard = new RegressionGuard(deps);
  await guard.observe(stepReport(0.6));
  const hack = await guard.observe(stepReport(0.9, 1, /*corroborationConflict*/ true)); // metric up, but regression up too
  assert.equal(hack.tripped, true);
  assert.equal(hack.trip!.kind, "goodhart-conflict");
});

test("INVARIANT: once frozen, the guard stays frozen until human reset()", async () => {
  const spine = newSpine();
  const { deps } = guardDeps(spine);
  const guard = new RegressionGuard(deps);
  await guard.observe(stepReport(0.6));
  await guard.observe(stepReport(0.85));
  await guard.observe(stepReport(0.9));
  await guard.observe(stepReport(0.4)); // trip
  assert.equal(guard.isFrozen, true);
  const whileFrozen = await guard.observe(stepReport(0.95)); // even a great step is ignored
  assert.equal(whileFrozen.tripped, false);
  assert.equal(whileFrozen.frozen, true, "still frozen — no silent resume");
  guard.reset("human reviewed, root cause fixed");
  assert.equal(guard.isFrozen, false, "human-gated resume");
});

test("INVARIANT: healthy monotonic improvement NEVER trips the guard", async () => {
  const spine = newSpine();
  const { deps } = guardDeps(spine);
  const guard = new RegressionGuard(deps);
  for (const m of [0.5, 0.6, 0.7, 0.75, 0.8, 0.82, 0.85]) {
    const r = await guard.observe(stepReport(m, 1));
    assert.equal(r.tripped, false, `healthy step ${m} must not trip`);
  }
  assert.equal(guard.isFrozen, false);
});

test("small dips within tolerance do NOT trip (avoid false alarms)", async () => {
  const spine = newSpine();
  const { deps } = guardDeps(spine);
  const guard = new RegressionGuard({ ...deps, options: { dropTolerance: 0.15, warmupSteps: 2 } });
  await guard.observe(stepReport(0.7));
  await guard.observe(stepReport(0.8));
  await guard.observe(stepReport(0.85));
  const smallDip = await guard.observe(stepReport(0.75)); // 0.10 below peak, within 0.15
  assert.equal(smallDip.tripped, false, "noise-level dip tolerated");
});
