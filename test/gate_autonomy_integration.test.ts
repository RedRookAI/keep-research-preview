import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { PolicyEngine } from "../src/governance/policy_engine.js";
import { PlanExecuteGate } from "../src/frontdoor/plan_execute_gate.js";
import { AutonomyCalibration, type AutonomyLevel } from "../src/frontdoor/autonomy_profile.js";
import type { ProposedAction } from "../src/frontdoor/action_schema.js";

const safe = async () => ({ safe: true });
function newSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-gate-int-"))), new InProcessLock(), new SchemaRegistry());
}
function gate(level: AutonomyLevel, cal?: AutonomyCalibration): PlanExecuteGate {
  return new PlanExecuteGate(newSpine(), new PolicyEngine("v1", []), safe, { autonomyLevel: level }, cal);
}
function act(kind: ProposedAction["kind"]): ProposedAction {
  return { kind, args: {}, rationale: "test" };
}

// --- (1) Autonomy level changes the external decision (the whole point) ---

test("a higher autonomy seat auto-approves a mid-confidence external action that a lower seat escalates", async () => {
  const conf = 0.6;
  assert.equal((await gate("collaborator").decide(act("bind_channel"), conf)).disposition, "human-approval-required");
  assert.equal((await gate("operator").decide(act("bind_channel"), conf)).disposition, "auto-approved");
  assert.equal((await gate("delegator").decide(act("bind_channel"), conf)).disposition, "auto-approved");
});

// --- (2) The irreversible floor is untouchable at ANY autonomy level ---

test("the irreversible floor holds at max autonomy + full confidence", async () => {
  for (const kind of ["spend_money", "deploy_production", "delete_data", "drop_database", "revoke_access"] as const) {
    const d = await gate("delegator").decide(act(kind), 1.0);
    assert.equal(d.disposition, "human-approval-required", `${kind} must still require approval`);
  }
});

// --- (3) Reversible-internal still auto-approves with no confidence (fatigue property) ---

test("reversible-internal actions still auto-approve with no confidence, at every level", async () => {
  for (const level of ["observer", "collaborator", "delegator"] as const) {
    const d = await gate(level).decide(act("capture_goal")); // no confidence passed
    assert.equal(d.disposition, "auto-approved", `capture_goal should auto-approve at ${level}`);
  }
});

// --- (4) Calibration flips a borderline external case ---

test("calibration flips a borderline external action from ask to auto after repeated approvals", async () => {
  const cal = new AutonomyCalibration();
  const g = gate("collaborator", cal);
  assert.equal((await g.decide(act("bind_channel"), 0.66)).disposition, "human-approval-required");
  for (let i = 0; i < 8; i++) cal.record("bind_channel", true);
  assert.equal((await g.decide(act("bind_channel"), 0.66)).disposition, "auto-approved");
});

// --- (5) A burst of the same external action trips the criticality ceiling ---

test("a burst of the same external action trips the criticality ceiling (runaway protection)", async () => {
  const g = gate("delegator"); // even max autonomy
  // Fire many of the same external action rapidly; the burst should eventually force a check.
  let sawEscalation = false;
  for (let i = 0; i < 8; i++) {
    const d = await g.decide(act("bind_channel"), 1.0);
    if (d.disposition === "human-approval-required") sawEscalation = true;
  }
  assert.ok(sawEscalation, "a rapid burst should trip the ceiling at least once");
});
