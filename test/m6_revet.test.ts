import { test } from "node:test";
import assert from "node:assert/strict";

import { decideTraining, type TrainingSignals } from "../src/autotrain/training_decision.js";
import { runSelfImprovementCycle } from "../src/learning/self_improvement_loop.js";
import { ShadowModeGate, type RegressionCase } from "../src/learning/shadow_mode.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// a signal set that fully qualifies for training (form-shaped), tunable per test
const QUALIFIED: TrainingSignals = {
  recurringFailureMode: true, occurrences: 40, gradientFreeTried: true, residualFailureRate: 0.4,
  verifiedExampleCount: 2000, verifiableRewardAvailable: true, estimatedTargetGain: 0.25, narrowStableTask: true,
  gapKind: "form",
};

test("M6-REVET FACT-vs-FORM (a): a factual gap routes to RAG/memory, NOT fine-tune", () => {
  const d = decideTraining({ ...QUALIFIED, gapKind: "fact" });
  assert.equal(d.shouldTrain, false, "a fact gap does not train");
  assert.equal(d.approach?.method, "rag");
  assert.match(d.approach!.ruledOut, /fine-tun/i, "names that fine-tuning was ruled out");
});

test("M6-REVET FORM (b): a form/behavior gap trains (not RAG)", () => {
  const d = decideTraining(QUALIFIED);
  assert.equal(d.shouldTrain, true);
  assert.notEqual(d.approach?.method, "rag");
});

test("M6-REVET DISTILL-FOR-COST (c): a stable high-volume task recommends distillation", () => {
  const d = decideTraining({ ...QUALIFIED, highVolumeStableTask: true });
  assert.equal(d.approach?.method, "distill");
  assert.match(d.approach!.why, /high-volume/i);
});

test("M6-REVET METHOD LADDER: GRPO for verifiable reward, DPO for preferences, no-train without a signal", () => {
  assert.equal(decideTraining(QUALIFIED).approach?.method, "grpo", "verifiable reward -> GRPO");
  assert.equal(decideTraining({ ...QUALIFIED, verifiableRewardAvailable: false, preferencePairsAvailable: true }).approach?.method, "dpo", "preferences -> DPO");
  const noSignal = decideTraining({ ...QUALIFIED, verifiableRewardAvailable: false });
  assert.equal(noSignal.shouldTrain, false, "no objective signal -> Keep refuses to train (a signal-free fine-tune erodes safety)");
  assert.equal(noSignal.recommendation, "no-verifiable-reward");
});

test("M6-REVET RULED-OUT (d): every training/routing recommendation names the cheaper alternative it ruled out", () => {
  for (const s of [QUALIFIED, { ...QUALIFIED, gapKind: "fact" as const }, { ...QUALIFIED, highVolumeStableTask: true }, { ...QUALIFIED, verifiableRewardAvailable: false, preferencePairsAvailable: true }]) {
    const d = decideTraining(s);
    assert.ok(d.approach && d.approach.ruledOut.length > 0, `approach.ruledOut must be populated for method ${d.approach?.method}`);
  }
});

// --- the cardinal safety-regression gate ---
const spine = () => new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-m6-"))), new InProcessLock(), new SchemaRegistry());
const passAll: readonly RegressionCase[] = [{ id: "cap1", passesUnder: () => true }];
const safetyPass: readonly RegressionCase[] = [{ id: "guardrail1", passesUnder: (c) => !c.includes("POISON") }];
const gapSignals: TrainingSignals = { recurringFailureMode: true, occurrences: 5, gradientFreeTried: true, residualFailureRate: 0.3, verifiedExampleCount: 10, verifiableRewardAvailable: false, estimatedTargetGain: 0.05, narrowStableTask: true, gapKind: "form" };

test("M6-REVET SAFETY GATE (e): a candidate that regresses the safety corpus is BLOCKED from promotion", () => {
  const sp = spine();
  const out = runSelfImprovementCycle(gapSignals, {
    enabled: true,
    shadow: new ShadowModeGate(sp, passAll),
    safety: new ShadowModeGate(sp, safetyPass),
    candidate: { id: "cand-bad", content: "helpful lesson but POISON weakens a refusal" },
  });
  assert.equal(out.promoted, false, "a safety-regressing candidate never promotes");
  assert.equal(out.safetyRegressed, true);
  assert.equal(out.reverted, true);
});

test("M6-REVET SAFETY IS CARDINAL (f): capability-pass + safety-regress STILL blocks (capability never overrides)", () => {
  const sp = spine();
  // capability corpus PASSES this candidate; safety corpus FAILS it → must still be blocked.
  const out = runSelfImprovementCycle(gapSignals, {
    enabled: true,
    shadow: new ShadowModeGate(sp, passAll), // capability: all pass
    safety: new ShadowModeGate(sp, safetyPass), // safety: fails on POISON
    candidate: { id: "cand-cap-ok-safety-bad", content: "passes capability but POISON regresses a guardrail" },
  });
  assert.equal(out.promoted, false, "capability passing does NOT override a safety regression");
  assert.equal(out.safetyRegressed, true);
});

test("M6-REVET clean candidate promotes only after passing BOTH gates", () => {
  const sp = spine();
  const out = runSelfImprovementCycle(gapSignals, {
    enabled: true, shadow: new ShadowModeGate(sp, passAll), safety: new ShadowModeGate(sp, safetyPass),
    candidate: { id: "cand-good", content: "a clean, safe improvement" },
  });
  assert.equal(out.promoted, true);
  assert.equal(out.safetyRegressed, false);
});

test("M6-REVET OFF BY DEFAULT (g): self-improvement does not run unless enabled", () => {
  const out = runSelfImprovementCycle(gapSignals, { shadow: new ShadowModeGate(spine(), passAll) });
  assert.equal(out.ran, false);
});
