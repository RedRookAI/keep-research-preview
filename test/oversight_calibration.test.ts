import { test } from "node:test";
import assert from "node:assert/strict";
import { OversightCalibration } from "../src/pipeline/oversight_calibration.js";
import { GovernanceLedger } from "../src/governance/decision_record.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function newSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-oc-"))), new InProcessLock(), new SchemaRegistry());
}

test("INVARIANT: the reversible/low-magnitude/confident/normal long tail does NOT escalate (solo user not burdened)", () => {
  const oc = new OversightCalibration();
  const d = oc.shouldEscalate({ reversible: true, highMagnitude: false, confidence: 0.95, anomalous: false });
  assert.equal(d.escalate, false, "routine safe change is NOT sent to the human");
});

test("INVARIANT: RISK signals drive escalation — irreversible escalates", () => {
  const oc = new OversightCalibration();
  assert.equal(oc.shouldEscalate({ reversible: false, highMagnitude: false, confidence: 0.95, anomalous: false }).escalate, true);
});

test("INVARIANT: low deterministic confidence escalates", () => {
  const oc = new OversightCalibration({ lowConfidenceThreshold: 0.6 });
  assert.equal(oc.shouldEscalate({ reversible: true, highMagnitude: false, confidence: 0.5, anomalous: false }).escalate, true);
});

test("INVARIANT: an ANOMALY escalates even if reversible + confident", () => {
  const oc = new OversightCalibration();
  const d = oc.shouldEscalate({ reversible: true, highMagnitude: false, confidence: 0.95, anomalous: true });
  assert.equal(d.escalate, true);
  assert.ok(d.reasons.some((r) => /anomal/.test(r)));
});

test("INVARIANT: clean outcomes on a REVERSIBLE class → reduce-escalation CANDIDATE (fewer rubber-stamps), not more", () => {
  const oc = new OversightCalibration({ minCleanSample: 10, maxRevertRate: 0.05 });
  for (let i = 0; i < 12; i++) { oc.record("patch", true, true); oc.recordOutcome("patch", "clean"); }
  const a = oc.assess("patch");
  assert.equal(a.recommendation, "reduce-escalation-candidate");
  assert.match(a.reason, /REDUCE escalation|governed/);
});

test("INVARIANT: a rising revert rate → increase-scrutiny on that class", () => {
  const oc = new OversightCalibration({ minCleanSample: 10, maxRevertRate: 0.05 });
  for (let i = 0; i < 12; i++) { oc.record("patch", true, true); oc.recordOutcome("patch", i < 3 ? "reverted" : "clean"); }
  const a = oc.assess("patch");
  assert.equal(a.recommendation, "increase-scrutiny");
});

test("INVARIANT: an IRREVERSIBLE class never becomes a reduce-escalation candidate (even with clean outcomes)", () => {
  const oc = new OversightCalibration({ minCleanSample: 10, maxRevertRate: 0.05 });
  for (let i = 0; i < 12; i++) { oc.record("schema", false, true); oc.recordOutcome("schema", "clean"); }
  const a = oc.assess("schema");
  assert.notEqual(a.recommendation, "reduce-escalation-candidate");
});

test("INVARIANT: recommendations are AUDITED but never auto-applied (governed policy change only)", async () => {
  const spine = newSpine();
  const gov = new GovernanceLedger(spine);
  const oc = new OversightCalibration({ minCleanSample: 10, governance: gov });
  for (let i = 0; i < 12; i++) { oc.record("patch", true, true); oc.recordOutcome("patch", "clean"); }
  const a = oc.recommend("patch");
  assert.equal(a.recommendation, "reduce-escalation-candidate");
  await spine.seal();
  assert.ok(gov.readTrail().some((x) => x.action === "oversight.recommend-reduce"), "recommendation audited");
  // The class of methods contains no 'apply'/'loosen' that mutates policy — recommendation only.
  assert.equal(typeof (oc as unknown as { autoLoosen?: unknown }).autoLoosen, "undefined");
});

test("a small sample holds (no premature recommendation for a solo operator)", () => {
  const oc = new OversightCalibration({ minCleanSample: 10 });
  for (let i = 0; i < 4; i++) { oc.record("patch", true, true); oc.recordOutcome("patch", "clean"); }
  assert.equal(oc.assess("patch").recommendation, "hold");
});
