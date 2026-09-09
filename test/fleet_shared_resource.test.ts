import { test } from "node:test";
import assert from "node:assert/strict";

import { SharedResourceLedger, fleetComposedAdmit } from "../src/fleet/shared_resource.js";

// Finding 2.2 — the fleet shared-resource barrier. Proves the reservation logic that prevents N
// individually-within-budget agents from jointly exhausting a shared cap. The distributed ledger across
// hosts is the SEAM. Verify by disproof.

test("2.2: N agents each within their OWN budget jointly over the shared cap → the breaching reserve is DENIED", () => {
  const ledger = new SharedResourceLedger({ cap: 100 });
  // each agent's per-agent budget allows 60 (checked by its own gate); the fleet cap is 100.
  const a = ledger.reserve("agent-A", 60);
  assert.equal(a.granted, true, "A's 60 is within the shared cap");
  const b = ledger.reserve("agent-B", 60); // B's own budget allows 60, but 60+60=120 > 100
  assert.equal(b.granted, false, "the shared cap denies the joint overshoot the gate cannot see");
  if (!b.granted) assert.ok(b.reason.startsWith("shared-cap-exceeded"));
});

test("2.2: a RELEASED (uncommitted) reservation frees the cap — reversible (isolated)", () => {
  const ledger = new SharedResourceLedger({ cap: 100 });
  const a = ledger.reserve("agent-A", 60);
  assert.equal(a.granted, true);
  assert.equal(ledger.reserve("agent-B", 60).granted, false, "B blocked while A holds 60");
  if (a.granted) assert.equal(ledger.release(a.reservationId), true);
  assert.equal(ledger.reserve("agent-B", 60).granted, true, "after A releases, B's 60 fits");
});

test("2.2: unknown/absent shared cap ⇒ DENY (fail-closed, isolated)", () => {
  const ledger = new SharedResourceLedger(undefined); // no policy → unknown shared state
  assert.equal(ledger.reserve("agent-A", 1).granted, false);
  const bad = new SharedResourceLedger({ cap: Number.NaN });
  assert.equal(bad.reserve("agent-A", 1).granted, false);
});

test("2.2: a COMMITTED reservation holds the resource — no double-spend (isolated)", () => {
  const ledger = new SharedResourceLedger({ cap: 100 });
  const a = ledger.reserve("agent-A", 60);
  assert.equal(a.granted, true);
  if (a.granted) assert.equal(ledger.commit(a.reservationId), true);
  assert.equal(ledger.committedTotal(), 60);
  // the committed 60 still counts against the cap — B cannot reuse it.
  assert.equal(ledger.reserve("agent-B", 60).granted, false, "committed resource is not double-spent");
});

test("2.2: exactly-at-cap fits; one over does not (boundary)", () => {
  const ledger = new SharedResourceLedger({ cap: 100 });
  assert.equal(ledger.reserve("A", 100).granted, true, "exactly the cap is allowed");
  assert.equal(ledger.reserve("B", 1).granted, false, "one over the cap is denied");
});

test("2.2: fleetComposedAdmit composes ABOVE the gate — both must clear (isolated)", () => {
  const granted = { granted: true, reservationId: "r1" } as const;
  const denied = { granted: false, reason: "shared-cap-exceeded" } as const;
  // gate auto-proceeds AND fleet grants → proceed.
  assert.equal(fleetComposedAdmit(true, granted).proceed, true);
  // gate auto-proceeds BUT the fleet denies → HOLD (the fleet barrier the gate cannot see).
  assert.equal(fleetComposedAdmit(true, denied).proceed, false);
  // gate holds → hold regardless of the fleet (the fleet only ADDS caution).
  assert.equal(fleetComposedAdmit(false, granted).proceed, false);
});
