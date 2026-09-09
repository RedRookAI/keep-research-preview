import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";

import { detectFailureModes } from "../src/training/failure_mode_detector.js";
import type { BuildOutcome } from "../src/learning/corpus_curation.js";
import {
  ABSTAIN,
  buildLabelMatrix,
  pairwiseAgreement,
  flagCorrelatedLFs,
  denoise,
  type LabelingFunction,
} from "../src/training/labeling.js";
import {
  DataEngineLoop,
  trainingReadiness,
  type DataEngineItem,
  type TrainingArtifacts,
} from "../src/training/data_engine_loop.js";
import type { FailureMode } from "../src/training/failure_mode_detector.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-train-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

function outcome(sig: string | undefined, ctx: string, ts: number, clean = false): BuildOutcome {
  return { buildId: `b${ts}`, context: ctx, cleanResolved: clean, ...(sig ? { regressionSignature: sig } : {}), ts };
}

// ── Failure-mode detector ───────────────────────────────────────────────────

test("INVARIANT: a recurring failure signature (≥ threshold) is detected", () => {
  const outcomes: BuildOutcome[] = [
    outcome("null-deref", "moduleA", 1), outcome("null-deref", "moduleB", 2), outcome("null-deref", "moduleA", 3),
  ];
  const modes = detectFailureModes(outcomes, { recurrenceThreshold: 3 });
  assert.equal(modes.length, 1);
  assert.equal(modes[0]!.signature, "null-deref");
  assert.equal(modes[0]!.occurrences, 3);
  assert.equal(modes[0]!.contexts.length, 2, "tracked across 2 contexts");
});

test("INVARIANT: a one-off regression does NOT trigger training (not bulk)", () => {
  const outcomes: BuildOutcome[] = [outcome("rare-bug", "moduleA", 1), outcome("null-deref", "moduleA", 2), outcome("null-deref", "moduleA", 3), outcome("null-deref", "moduleB", 4)];
  const modes = detectFailureModes(outcomes, { recurrenceThreshold: 3 });
  assert.ok(!modes.some((m) => m.signature === "rare-bug"), "one-off not surfaced");
  assert.ok(modes.some((m) => m.signature === "null-deref"), "recurring surfaced");
});

test("clean builds carry no failure signature and are ignored", () => {
  const outcomes: BuildOutcome[] = [outcome("x", "a", 1, true), outcome("x", "a", 2, true), outcome("x", "a", 3, true)];
  assert.equal(detectFailureModes(outcomes, { recurrenceThreshold: 2 }).length, 0);
});

// ── Labeling functions + label model ────────────────────────────────────────

const lfHi: LabelingFunction<{ text: string }> = { name: "hi", apply: (x) => (x.text.includes("crash") ? 1 : x.text.includes("ok") ? 0 : ABSTAIN), priorAccuracy: 0.9 };
const lfLo: LabelingFunction<{ text: string }> = { name: "lo", apply: (x) => (x.text.includes("ok") ? 1 : 0), priorAccuracy: 0.55 }; // noisy, always votes

test("INVARIANT: labeling functions can abstain", () => {
  assert.equal(lfHi.apply({ text: "neutral" }), ABSTAIN);
});

test("INVARIANT: the label model flags over-correlated LFs (conditional-independence violation)", () => {
  const items = [{ text: "crash" }, { text: "ok here" }, { text: "crash now" }];
  // two identical LFs → perfectly correlated
  const dup1: LabelingFunction<{ text: string }> = { name: "d1", apply: (x) => (x.text.includes("crash") ? 1 : 0) };
  const dup2: LabelingFunction<{ text: string }> = { name: "d2", apply: (x) => (x.text.includes("crash") ? 1 : 0) };
  const lm = buildLabelMatrix(items, [dup1, dup2]);
  const flagged = flagCorrelatedLFs(lm, 0.95);
  assert.equal(flagged.length, 1);
  assert.equal(flagged[0]!.agreement, 1);
});

test("pairwise agreement is 1.0 on the diagonal", () => {
  const items = [{ text: "crash" }, { text: "ok" }];
  const lm = buildLabelMatrix(items, [lfHi, lfLo]);
  const agree = pairwiseAgreement(lm);
  assert.equal(agree[0]![0], 1);
});

test("INVARIANT: the label model rejects LFs below the accuracy floor", () => {
  const items = [{ text: "crash" }, { text: "ok" }, { text: "crash" }, { text: "ok" }];
  const result = denoise(items, [lfHi, lfLo], { accuracyFloor: 0.8 });
  const loStats = result.lfStats.find((s) => s.name === "lo")!;
  assert.equal(loStats.rejected, true, "the 0.55-accuracy LF is rejected below the 0.8 floor");
  const hiStats = result.lfStats.find((s) => s.name === "hi")!;
  assert.equal(hiStats.rejected, false, "the 0.9-accuracy LF is kept");
});

test("denoise produces labels + confidence for covered items", () => {
  const items = [{ text: "crash" }, { text: "ok" }];
  const result = denoise(items, [lfHi], {});
  assert.equal(result.labels[0], 1);
  assert.equal(result.labels[1], 0);
  assert.ok(result.confidence[0]! > 0);
});

// ── DataEngineLoop: gradient-free artifacts, gated ──────────────────────────

function mode(sig = "null-deref"): FailureMode {
  return { signature: sig, occurrences: 3, contexts: ["a", "b"], buildIds: ["b1", "b2", "b3"], lastSeenTs: 3 };
}

test("INVARIANT: DataEngineLoop emits gradient-free artifacts (eval + exemplars + anchors) on success", () => {
  const spine = newSpine();
  const loop = new DataEngineLoop(spine);
  const items: DataEngineItem[] = [
    { id: "i1", text: "crash on null", gold: 1 }, { id: "i2", text: "ok path", gold: 0 },
    { id: "i3", text: "crash again", gold: 1 }, { id: "i4", text: "ok fine", gold: 0 },
  ];
  const lf: LabelingFunction<DataEngineItem> = { name: "crash-lf", apply: (x) => (x.text.includes("crash") ? 1 : 0), priorAccuracy: 0.9 };
  const artifacts = loop.build(mode(), items, [lf], { consensusFloor: 0.5, heldOutFraction: 0.25 });
  assert.equal(artifacts.accepted, true);
  assert.ok(artifacts.evalCases.length > 0, "eval cases emitted");
  assert.ok(artifacts.exemplars.length > 0, "few-shot exemplars emitted");
  assert.equal(artifacts.anchors[0]!.signature, "null-deref", "retrieval anchor emitted");
});

test("INVARIANT: DataEngineLoop REJECTS when LFs are over-correlated (won't ship overconfident labels)", () => {
  const spine = newSpine();
  const loop = new DataEngineLoop(spine);
  const items: DataEngineItem[] = [{ id: "i1", text: "crash", gold: 1 }, { id: "i2", text: "ok", gold: 0 }, { id: "i3", text: "crash", gold: 1 }, { id: "i4", text: "ok", gold: 0 }];
  const d1: LabelingFunction<DataEngineItem> = { name: "d1", apply: (x) => (x.text.includes("crash") ? 1 : 0) };
  const d2: LabelingFunction<DataEngineItem> = { name: "d2", apply: (x) => (x.text.includes("crash") ? 1 : 0) };
  const artifacts = loop.build(mode(), items, [d1, d2], {});
  assert.equal(artifacts.accepted, false);
  assert.match(artifacts.rejectionReason ?? "", /correlated/);
});

test("INVARIANT: DataEngineLoop REJECTS when held-out accuracy is below the floor", () => {
  const spine = newSpine();
  const loop = new DataEngineLoop(spine);
  // LF is systematically WRONG vs gold → held-out accuracy collapses
  const items: DataEngineItem[] = [
    { id: "i1", text: "crash", gold: 1 }, { id: "i2", text: "crash", gold: 1 }, { id: "i3", text: "crash", gold: 1 }, { id: "i4", text: "crash", gold: 1 },
  ];
  const wrongLf: LabelingFunction<DataEngineItem> = { name: "wrong", apply: () => 0, priorAccuracy: 0.9 }; // always says 0, gold is 1
  const artifacts = loop.build(mode(), items, [wrongLf], { heldOutFraction: 0.5, heldOutAccuracyFloor: 0.7 });
  assert.equal(artifacts.accepted, false);
  assert.match(artifacts.rejectionReason ?? "", /held-out/);
});

// ── Training readiness: hands off to the Auto-Training system (item 11) ──────

function acceptedArtifacts(): TrainingArtifacts {
  return { mode: mode(), evalCases: [], exemplars: [], anchors: [], heldOutAccuracy: 1, accepted: true };
}

test("INVARIANT: training readiness requires accepted artifacts (fix data first)", () => {
  const spine = newSpine();
  const bad = { mode: mode(), evalCases: [], exemplars: [], anchors: [], heldOutAccuracy: 0, accepted: false } as TrainingArtifacts;
  const d = trainingReadiness(spine, { artifacts: bad, operatorAuthorized: true, sandboxed: true });
  assert.equal(d.proceeded, false);
  assert.match(d.reason, /nothing to train on/);
});

test("INVARIANT: training readiness requires a sandbox (never assume isolation)", () => {
  const spine = newSpine();
  const d = trainingReadiness(spine, { artifacts: acceptedArtifacts(), operatorAuthorized: true, sandboxed: false });
  assert.equal(d.proceeded, false);
  assert.match(d.reason, /sandbox/);
});

test("INVARIANT: with accepted artifacts + sandbox, readiness HANDS OFF to the training pipeline (does not dead-end)", () => {
  const spine = newSpine();
  const d = trainingReadiness(spine, { artifacts: acceptedArtifacts(), operatorAuthorized: true, sandboxed: true });
  assert.equal(d.proceeded, true, "ready to train — hands off to the Auto-Training decision policy");
  assert.match(d.reason, /hand off|Auto-Training/);
});
