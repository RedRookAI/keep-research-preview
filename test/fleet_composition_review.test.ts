import { test } from "node:test";
import assert from "node:assert/strict";

import { fleetAdmit, type FleetChecks } from "../src/fleet/fleet_gate.js";
import { SharedResourceLedger } from "../src/fleet/shared_resource.js";
import { JointReversibilityLedger, type Effect } from "../src/fleet/joint_reversibility.js";
import { checkCrossAgentFlow, type ProvenanceChain } from "../src/fleet/cross_agent_taint.js";

// FLEET-COMPOSITION CLOSE-OUT REVIEW — attack the three fleet barriers as they compose above the
// per-decision gate (via fleetAdmit). STPA + common-cause, layered (fleet above per-decision). Every
// test BITES. Each neuter was verified to apply before trusting its result.

// helpers to produce real checks from the three barriers.
const okReserve = () => new SharedResourceLedger({ cap: 100 }).reserve("A", 10); // granted
const denyReserve = () => new SharedResourceLedger(undefined).reserve("A", 10); // fail-closed (unknown cap)
const eff = (id: string, w: readonly string[] | undefined, d: readonly string[] | undefined): Effect =>
  ({ id, agent: id, writeSet: w, inverseDependsOn: d });
const okJoint = () => new JointReversibilityLedger().check(eff("B", ["r:2"], ["r:2"])); // ok (empty ledger)
function denyJoint() {
  const l = new JointReversibilityLedger();
  l.register(eff("A", ["r:1"], ["r:1"]));
  return l.check(eff("B", ["r:1"], ["r:1"])); // reversibility-conflict
}
const cleanChain: ProvenanceChain = { hops: [{ agent: "a", taint: "trusted", source: "internal" }] };
const taintedChain: ProvenanceChain = { hops: [{ agent: "a", taint: "untrusted", source: "web_fetch" }] };
const okFlow = () => checkCrossAgentFlow({ agent: "a", externalSink: true, chain: cleanChain }); // clean
const okCorr = () => ({ ok: true }) as const; // correlation clear
const denyCorr = () => ({ ok: false, reason: "correlated-lockstep:model:X:3>2" }) as const;
const denyFlow = () => checkCrossAgentFlow({ agent: "a", externalSink: true, chain: taintedChain }); // tainted

const allClear = (): FleetChecks => ({ reserve: okReserve(), jointReversibility: okJoint(), crossAgent: okFlow(), correlation: okCorr() });

test("HUNT-A9F: all clear + gate auto-proceed → proceed; but failing ONLY 2.4 holds (no barrier bypassable)", () => {
  assert.equal(fleetAdmit(true, allClear()).proceed, true, "all clear → proceed");
  const only24 = fleetAdmit(true, { reserve: okReserve(), jointReversibility: okJoint(), crossAgent: denyFlow(), correlation: okCorr() });
  assert.equal(only24.proceed, false, "gate+2.2+2.3 pass but 2.4 fails → held (2.4 not bypassed)");
  assert.ok(only24.reasons.some((r) => r.startsWith("fleet-2.4")));
});

test("HUNT-A9F: failing ONLY 2.2 or ONLY 2.3 each independently holds (each barrier is load-bearing)", () => {
  assert.equal(fleetAdmit(true, { reserve: denyReserve(), jointReversibility: okJoint(), crossAgent: okFlow(), correlation: okCorr() }).proceed, false);
  assert.equal(fleetAdmit(true, { reserve: okReserve(), jointReversibility: denyJoint(), crossAgent: okFlow(), correlation: okCorr() }).proceed, false);
});

test("HUNT-B9F: correlated fail-safe — all three on UNKNOWN state fail CLOSED together (safe direction)", () => {
  // each barrier's unknown-state check: 2.2 unknown cap, 2.3 unknown dependency, 2.4 unknown origin.
  const l = new JointReversibilityLedger();
  l.register(eff("A", ["r:1"], undefined)); // unknown dependency
  const unknownJoint = l.check(eff("B", ["r:1"], ["r:1"]));
  const unknownFlow = checkCrossAgentFlow({ agent: "a", externalSink: true, chain: { hops: [] } }); // empty ⇒ tainted
  const admission = fleetAdmit(true, { reserve: denyReserve(), jointReversibility: unknownJoint, crossAgent: unknownFlow, correlation: denyCorr() });
  assert.equal(admission.proceed, false, "all three fail-closed compose to a fleet hold");
  assert.equal(admission.reasons.length, 4, "all four fail-safe reasons present — none masked");
});

test("HUNT-C9F: NO MASKING — an effect failing TWO barriers is held with BOTH reasons reported", () => {
  const admission = fleetAdmit(true, { reserve: okReserve(), jointReversibility: denyJoint(), crossAgent: denyFlow(), correlation: okCorr() });
  assert.equal(admission.proceed, false);
  assert.ok(admission.reasons.some((r) => r.startsWith("fleet-2.3")), "2.3 reason present");
  assert.ok(admission.reasons.some((r) => r.startsWith("fleet-2.4")), "2.4 reason present (not masked by 2.3)");
});

test("HUNT-D9F: the fleet layer NEVER overrides a gate hold — gate holds + all fleet clear → held", () => {
  const admission = fleetAdmit(false, allClear());
  assert.equal(admission.proceed, false, "a gate hold is never rescued by the fleet layer");
  assert.ok(admission.reasons.includes("per-decision-gate-hold"));
});

test("HUNT-E9F: monotone toward caution — fleetAdmit proceeds ⟹ the gate auto-proceeds (pure AND)", () => {
  // exhaustively over the gate bit with all-clear fleet: proceed only when the gate proceeds.
  assert.equal(fleetAdmit(true, allClear()).proceed, true);
  assert.equal(fleetAdmit(false, allClear()).proceed, false);
  // and with any fleet hold, proceed is false regardless of the gate — the fleet only subtracts.
  const anyHold = { reserve: denyReserve(), jointReversibility: okJoint(), crossAgent: okFlow(), correlation: okCorr() };
  assert.equal(fleetAdmit(true, anyHold).proceed, false);
  assert.equal(fleetAdmit(false, anyHold).proceed, false);
});
