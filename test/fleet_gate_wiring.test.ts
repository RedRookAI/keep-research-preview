import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { composeKeep } from "../src/compose.js";
import type { FleetChecks } from "../src/fleet/fleet_gate.js";

// WIRING PROOF (P0-A #8): fleet_gate is reachable + enforces the deny-overrides fleet invariant.

function sb() {
  return composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-fg-")) }).secondBrain;
}
const allClear: FleetChecks = {
  reserve: { granted: true, reservationId: "r1" },
  jointReversibility: { ok: true },
  crossAgent: { clean: true },
  correlation: { ok: true },
};

test("composeKeep exposes fleet admission", () => {
  assert.equal(typeof sb().admitFleetAction, "function");
});

test("a compliant fleet action proceeds (gate allows + all barriers clear)", () => {
  const a = sb().admitFleetAction(true, allClear);
  assert.equal(a.proceed, true);
  assert.equal(a.reasons.length, 0);
});

test("THE bite: a fleet barrier vetoes an action the single-agent gate would allow", () => {
  const jointIrreversible: FleetChecks = { ...allClear, jointReversibility: { ok: false, reason: "joint-irreversible" } };
  const a = sb().admitFleetAction(true, jointIrreversible); // gate says proceed, but the fleet says no
  assert.equal(a.proceed, false, "a fleet-level concern refuses an action the per-decision gate allowed");
  assert.ok(a.reasons.some((r) => r.includes("joint")), "the fleet reason is reported");
});

test("deny-overrides, no masking: every failing reason is reported", () => {
  const twoFail: FleetChecks = {
    ...allClear,
    reserve: { granted: false, reason: "contended" },
    correlation: { ok: false, reason: "correlated-failure" },
  };
  const a = sb().admitFleetAction(false, twoFail);
  assert.equal(a.proceed, false);
  assert.ok(a.reasons.length >= 3, "gate-hold + both fleet failures all surfaced (no reason masked)");
});

test("n=1 graceful: single instance, no fleet contention ⇒ follows the gate decision", () => {
  assert.equal(sb().admitFleetAction(true, allClear).proceed, true, "solo operator unaffected when the gate allows");
  assert.equal(sb().admitFleetAction(false, allClear).proceed, false, "and still held when the gate holds");
});
