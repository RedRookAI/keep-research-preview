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

import { distillFromEdit, distillFromDismissal } from "../src/learning/edit_delta.js";
import { ShadowModeGate, type RegressionCase } from "../src/learning/shadow_mode.js";
import { computeImprovement, AggregateDriftDetector } from "../src/learning/baseline_metric.js";
import { buildLessonBadge, detectSpecDrift } from "../src/learning/badges_drift.js";
import type { Lesson } from "../src/memory/model.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-l35-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}
function newMemory(spine: Spine): MemoryStore {
  return new MemoryStore(spine, new ModelGateway(new LocalProvider()));
}

// --- Feature 5: edit-delta distillation (objective-anchored) ---

test("edit-delta distills a GENERALIZED lesson to PROBATION, not confirmed (must earn graduation)", async () => {
  const store = newMemory(newSpine());
  const distilled = await distillFromEdit(store, {
    produced: "function add(a,b){return a-b}",
    shipped: "function add(a,b){return a+b}",
    context: "repoA/math.ts",
  });
  assert.ok(distilled);
  assert.notEqual(distilled!.lesson.tier, "confirmed"); // never trusted on the human signal alone
  assert.equal(distilled!.lesson.origin, "external");
  // It captured the PATTERN (operator substitution), not the literal before/after pair.
  assert.equal(distilled!.patternKind, "operator-substitution");
  assert.ok(distilled!.patternSignature.startsWith("op-sub:"));
  assert.ok(!distilled!.lesson.content.includes("function add")); // generalized, not memorized text
});

test("identical produced/shipped is a no-op (no correction, no signal)", async () => {
  const store = newMemory(newSpine());
  const distilled = await distillFromEdit(store, { produced: "same", shipped: "same", context: "repoA" });
  assert.equal(distilled, undefined);
});

test("whitespace-only edit is a no-op (no structural change)", async () => {
  const store = newMemory(newSpine());
  const distilled = await distillFromEdit(store, { produced: "return a+b", shipped: "return  a  +  b", context: "repoA" });
  assert.equal(distilled, undefined);
});

test("dismissal distills a suppression lesson (stops resurfacing)", async () => {
  const store = newMemory(newSpine());
  const lesson = await distillFromDismissal(store, {
    category: "style",
    patternSignature: "prefer-const",
    context: "repoA",
  });
  assert.ok(lesson);
  assert.ok(lesson!.content.includes("down-weight"));
});

// --- Round 16: shadow-mode (proactive pre-live gate) ---

test("shadow-mode AUTO-REVOKES a lesson that breaks a held-out regression case BEFORE live", () => {
  const corpus: RegressionCase[] = [
    { id: "reg-1", passesUnder: (content) => !content.includes("skip validation") },
  ];
  const gate = new ShadowModeGate(newSpine(), corpus);
  let revoked: string | undefined;
  const cleared = gate.gate("lesson-bad", "always skip validation to speed up", (id) => { revoked = id; });
  assert.equal(cleared, false); // not cleared for live use
  assert.equal(revoked, "lesson-bad"); // auto-revoked
});

test("shadow-mode clears a lesson that passes the held-out corpus", () => {
  const corpus: RegressionCase[] = [
    { id: "reg-1", passesUnder: (content) => !content.includes("skip validation") },
  ];
  const gate = new ShadowModeGate(newSpine(), corpus);
  const cleared = gate.gate("lesson-good", "run the linter before committing", () => {});
  assert.equal(cleared, true);
});

// --- Round 12/16: baseline metric + aggregate drift ---

test("improvement is measured as the clean-resolved DELTA vs a learning-disabled baseline", () => {
  const report = computeImprovement(
    { cleanResolvedRate: 0.60, regressionRate: 0.10 },
    { cleanResolvedRate: 0.72, regressionRate: 0.09 },
  );
  assert.ok(Math.abs(report.cleanResolvedDelta - 0.12) < 1e-9); // learning helps by +12pp
  assert.equal(report.corroborationConflict, false);
});

test("Goodhart guard: resolved-rate up AND regression-rate up is flagged as conflict", () => {
  const report = computeImprovement(
    { cleanResolvedRate: 0.60, regressionRate: 0.10 },
    { cleanResolvedRate: 0.70, regressionRate: 0.18 }, // gamed: resolves more but regresses more
  );
  assert.equal(report.corroborationConflict, true);
});

test("aggregate-drift recommends rollback on whole-system decline (Simpson's paradox)", () => {
  const detector = new AggregateDriftDetector(newSpine(), 0.05);
  // Every per-lesson check may have passed, yet the aggregate dropped 8pp.
  const check = detector.check({ cleanResolvedRate: 0.75, regressionRate: 0.1 }, { cleanResolvedRate: 0.67, regressionRate: 0.1 });
  assert.equal(check.declined, true);
  assert.equal(check.shouldRollback, true); // 0.08 > 0.05 threshold
});

test("aggregate-drift does not over-trigger on noise below threshold", () => {
  const detector = new AggregateDriftDetector(newSpine(), 0.05);
  const check = detector.check({ cleanResolvedRate: 0.75, regressionRate: 0.1 }, { cleanResolvedRate: 0.73, regressionRate: 0.1 });
  assert.equal(check.shouldRollback, false); // 0.02 < 0.05
});

// --- Feature 8/9: badges + spec-drift ---

function lesson(tier: Lesson["tier"], id: string): Lesson {
  return { id, content: "x", tier, origin: "self", provenanceEventId: "e", scope: "project", kind: "procedure", importance: 0.5, evidence: [], createdTs: 0, validFrom: 0 };
}

test("confidence badge counts only CONFIRMED lessons", () => {
  const badge = buildLessonBadge([lesson("confirmed", "a"), lesson("probation", "b"), lesson("confirmed", "c")]);
  assert.equal(badge.confirmedCount, 2);
  assert.deepEqual(badge.lessonIds, ["a", "c"]);
});

test("spec-drift: a missing required capability is flagged as drift", () => {
  const r = detectSpecDrift({
    approvedIntent: "add retry with backoff to the client",
    requiredCapabilities: ["retry", "backoff"],
    changeSummary: "added retry to the client",
    testsPass: true,
  });
  assert.equal(r.drifted, true);
  assert.deepEqual(r.missingCapabilities, ["backoff"]);
});

test("spec-drift: failing spec-encoding tests are an objective drift signal", () => {
  const r = detectSpecDrift({
    approvedIntent: "x", requiredCapabilities: [], changeSummary: "x", testsPass: false,
  });
  assert.equal(r.drifted, true);
});

test("spec-drift: a change satisfying intent + passing tests does not drift", () => {
  const r = detectSpecDrift({
    approvedIntent: "add retry with backoff",
    requiredCapabilities: ["retry", "backoff"],
    changeSummary: "added retry with exponential backoff",
    testsPass: true,
  });
  assert.equal(r.drifted, false);
});
