import { test } from "node:test";
import assert from "node:assert/strict";
import { CalibrationWire } from "../src/oversight/calibration_wire.js";
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
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-cw-"))), new InProcessLock(), new SchemaRegistry());
}
function wireWith(gov?: GovernanceLedger, min = 3): CalibrationWire {
  const cal = new OversightCalibration(gov ? { governance: gov, minCleanSample: min, maxRevertRate: 0.05 } : { minCleanSample: min, maxRevertRate: 0.05 });
  return new CalibrationWire(gov ? { calibration: cal, governance: gov } : { calibration: cal });
}
function cleanRun(w: CalibrationWire, cls: string, n: number): void {
  for (let i = 0; i < n; i++) { w.recordDecision(cls, true, true); w.observeOutcome(cls, "clean"); }
}

test("F2: clean reversible outcomes produce a reduce-candidate that is NOT auto-applied (loosening needs a human)", () => {
  const w = wireWith();
  cleanRun(w, "low", 4);
  assert.deepEqual([...w.pendingReductions()], ["low"]); // proposed
  assert.equal(w.activePolicyGates().has("low"), false); // but NOT applied
});

test("F2: a human authorizes the reduction → an active, revocable policy the router can consume", () => {
  const w = wireWith();
  cleanRun(w, "low", 4);
  const p = w.authorizeReduction("low", "operator");
  assert.ok(p && p.authorizedBy === "operator");
  assert.equal(w.activePolicyGates().has("low"), true);
  assert.equal(w.pendingReductions().length, 0);
});

test("F2: a human CANNOT authorize a class the outcomes don't support (no candidate → no policy)", () => {
  const w = wireWith();
  assert.equal(w.authorizeReduction("medium", "operator"), null);
  assert.equal(w.activePolicyGates().has("medium"), false);
});

test("F2 (bidirectional, safe direction): a rising revert rate AUTOMATICALLY revokes an active policy (no human needed)", () => {
  const w = wireWith();
  cleanRun(w, "low", 4);
  w.authorizeReduction("low", "operator");
  assert.equal(w.activePolicyGates().has("low"), true);
  // a real post-approval revert arrives → revert rate rises → automatic re-tighten
  w.recordDecision("low", true, true);
  const a = w.observeOutcome("low", "reverted");
  assert.equal(a.recommendation, "increase-scrutiny");
  assert.equal(w.activePolicyGates().has("low"), false, "policy auto-revoked (re-tightened) without a human");
});

test("F2: the loosening/tightening trail is governed + audited (recommend, authorize, revoke)", async () => {
  const spine = newSpine();
  const gov = new GovernanceLedger(spine);
  const w = wireWith(gov);
  cleanRun(w, "low", 4);
  w.authorizeReduction("low", "operator");
  w.recordDecision("low", true, true);
  w.observeOutcome("low", "reverted"); // triggers auto-revoke
  await spine.seal();
  const actions = gov.readTrail().map((x) => x.action);
  assert.ok(actions.includes("oversight.recommend-reduce"), "reduce proposal audited");
  assert.ok(actions.includes("oversight.authorize-reduce"), "human authorization audited");
  assert.ok(actions.includes("oversight.revoke-reduce"), "automatic tightening audited");
});
