import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluateCueAblation, type CueAblationCase } from "../src/anticipate/cue_ablation.js";
import { composeKeep } from "../src/compose.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const config = { lossWeight: { reversible: 0.1, irreversible: 1, unknown: 0.7 } as const, askCost: 0.25, noteThreshold: 0.5 };
function usefulCases(): CueAblationCase[] {
  const cases: CueAblationCase[] = [];
  for (let i = 0; i < 19; i++) cases.push({ message: "maybe wipe it and start over, i think?", intentUncertainty: 0.1, consequence: "irreversible", desiredVerdict: "ask" });
  cases.push({ message: "wipe it and start over", intentUncertainty: 0.1, consequence: "irreversible", desiredVerdict: "proceed" });
  return cases;
}
test("paired ablation enables cues only when evidence improves decisions within the corrected risk threshold", () => {
  const result = evaluateCueAblation(usefulCases(), 0.05, config);
  assert.deepEqual({ baseline: result.baselineErrors, cue: result.cueErrors, changed: result.changedDecisions, harmful: result.harmfulFlips, rate: result.correctedHarmfulFlipRate, enabled: result.enabled }, { baseline: 19, cue: 0, changed: 19, harmful: 0, rate: 0.05, enabled: true });
});
test("thin evidence cannot certify a strict risk target", () => assert.equal(evaluateCueAblation(usefulCases().slice(0, 2), 0.1, config).enabled, false));
test("a cue arm that increases error remains disabled", () => {
  const cases = Array.from({ length: 10 }, (): CueAblationCase => ({ message: "maybe wipe it and start over", intentUncertainty: 0.1, consequence: "irreversible", desiredVerdict: "proceed" }));
  assert.equal(evaluateCueAblation(cases, 1, config).enabled, false);
});
test("empty evidence and malformed bounds fail closed", () => {
  assert.equal(evaluateCueAblation([], 0.1, config).enabled, false);
  assert.throws(() => evaluateCueAblation(usefulCases(), 0, config), /maxHarmfulFlipRate/);
  assert.throws(() => evaluateCueAblation([{ ...usefulCases()[0]!, intentUncertainty: Number.NaN }], 0.1, config), /malformed/);
  assert.throws(() => evaluateCueAblation(Array.from({ length: 10_001 }, () => usefulCases()[0]!), 0.1, config), /10000-case bound/);
});
test("composition exposes the fixed startup decision to operators", () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-cue-ablation-")), cueAblation: { cases: usefulCases(), maxHarmfulFlipRate: 0.05, askGateConfig: config } });
  assert.equal(app.cueAblation?.enabled, true);
  assert.equal(app.cueAblation?.cases, 20);
});
