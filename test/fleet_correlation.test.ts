import { test } from "node:test";
import assert from "node:assert/strict";

import { FleetCorrelationLedger, type CorrelatedEffect, type CorrelationPolicy } from "../src/fleet/fleet_correlation.js";
import { fleetAdmit, type FleetChecks } from "../src/fleet/fleet_gate.js";
import { SharedResourceLedger } from "../src/fleet/shared_resource.js";
import { JointReversibilityLedger, type Effect } from "../src/fleet/joint_reversibility.js";
import { checkCrossAgentFlow } from "../src/fleet/cross_agent_taint.js";

// Finding 2.5 — the fleet correlation barrier. Proves the diversity-threshold logic that caps how many
// concurrent effects may share one common-cause basis. The cross-host correlation observation is the SEAM.

const eff = (id: string, basis: string | undefined): CorrelatedEffect => ({ id, agent: id, basis });
const policy: CorrelationPolicy = { maxPerBasis: 2 };

test("2.5: concurrent effects sharing ONE basis beyond the threshold → the exceeding one is DENIED", () => {
  const ledger = new FleetCorrelationLedger();
  ledger.register(eff("e1", "model:X"));
  ledger.register(eff("e2", "model:X")); // 2 sharing model:X — at the cap
  const third = ledger.check(eff("e3", "model:X"), policy); // a 3rd would make the fleet act in lockstep
  assert.equal(third.ok, false, "a single fault in model:X would flip all three — denied");
  if (!third.ok) assert.ok(third.reason.startsWith("correlated-lockstep"));
});

test("2.5: a DIVERSE set (distinct bases) under the threshold all proceed — no false positive (isolated)", () => {
  const ledger = new FleetCorrelationLedger();
  ledger.register(eff("e1", "model:X"));
  ledger.register(eff("e2", "model:Y"));
  assert.equal(ledger.check(eff("e3", "model:Z"), policy).ok, true, "diverse bases are independent");
  assert.equal(ledger.check(eff("e4", "model:X"), policy).ok, true, "a 2nd on X is still within the cap");
});

test("2.5: an UNKNOWN basis ⇒ correlated/deny (fail-safe, isolated)", () => {
  const ledger = new FleetCorrelationLedger();
  assert.equal(ledger.check(eff("e1", undefined), policy).ok, false, "diversity cannot be proven → deny");
});

test("2.5: the correlation count CLEARS as concurrent effects complete — transient (isolated)", () => {
  const ledger = new FleetCorrelationLedger();
  ledger.register(eff("e1", "model:X"));
  ledger.register(eff("e2", "model:X"));
  assert.equal(ledger.check(eff("e3", "model:X"), policy).ok, false, "at the cap → denied");
  assert.equal(ledger.complete("e1"), true); // e1 finishes
  assert.equal(ledger.check(eff("e3", "model:X"), policy).ok, true, "after e1 completes, room reopens");
});

test("2.5: fleetAdmit now requires the 4th check — passing 2.2/2.3/2.4 but CORRELATED is held (compose)", () => {
  const reserve = new SharedResourceLedger({ cap: 100 }).reserve("A", 10); // granted
  const jr = new JointReversibilityLedger().check({ id: "B", agent: "B", writeSet: ["r:2"], inverseDependsOn: ["r:2"] } as Effect);
  const flow = checkCrossAgentFlow({ agent: "a", externalSink: true, chain: { hops: [{ agent: "a", taint: "trusted", source: "internal" }] } });
  const correlated = { ok: false, reason: "correlated-lockstep:model:X:3>2" } as const;
  const checks: FleetChecks = { reserve, jointReversibility: jr, crossAgent: flow, correlation: correlated };
  const admission = fleetAdmit(true, checks);
  assert.equal(admission.proceed, false, "the fleet holds on correlation even when 2.2/2.3/2.4 all clear");
  assert.ok(admission.reasons.some((r) => r.startsWith("fleet-2.5")));
});
