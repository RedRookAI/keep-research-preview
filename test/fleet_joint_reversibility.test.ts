import { test } from "node:test";
import assert from "node:assert/strict";

import { JointReversibilityLedger, fleetReversibilityAdmit, type Effect } from "../src/fleet/joint_reversibility.js";

// Finding 2.3 — the fleet joint-reversibility barrier. Proves the conflict logic that prevents N
// individually-reversible effects from composing into a jointly-irreversible outcome. The cross-host
// dependency graph is the SEAM. Verify by disproof.

const eff = (id: string, writeSet: readonly string[] | undefined, inverseDependsOn: readonly string[] | undefined): Effect =>
  ({ id, agent: `agent-${id}`, writeSet, inverseDependsOn });

test("2.3: an effect whose write-set invalidates an in-flight effect's inverse is DENIED (jointly irreversible)", () => {
  const ledger = new JointReversibilityLedger();
  // A's envelope is open; its rollback relies on migration:X being unchanged.
  ledger.register(eff("A", ["migration:X"], ["migration:X"]));
  // B is individually reversible, but committing it reverts migration:X — stranding A's inverse.
  const check = ledger.check(eff("B", ["migration:X"], ["migration:X"]));
  assert.equal(check.ok, false, "the joint outcome is irreversible even though each effect is reversible");
  if (!check.ok) assert.ok(check.reason.startsWith("reversibility-conflict"));
});

test("2.3: two INDEPENDENT reversible effects both proceed — no false conflict (isolated)", () => {
  const ledger = new JointReversibilityLedger();
  ledger.register(eff("A", ["res:1"], ["res:1"]));
  const check = ledger.check(eff("B", ["res:2"], ["res:2"])); // disjoint resources
  assert.equal(check.ok, true, "independent effects do not conflict");
});

test("2.3: unknown write-set OR unknown in-flight dependency ⇒ DENY (fail-safe, isolated)", () => {
  const ledger = new JointReversibilityLedger();
  ledger.register(eff("A", ["res:1"], ["res:1"]));
  assert.equal(ledger.check(eff("B", undefined, ["res:2"])).ok, false, "unknown write-set → deny");
  const ledger2 = new JointReversibilityLedger();
  ledger2.register(eff("A", ["res:1"], undefined)); // A's rollback needs are unknown
  assert.equal(ledger2.check(eff("B", ["res:2"], ["res:2"])).ok, false, "unknown dependency → deny");
});

test("2.3: the conflict CLEARS once the in-flight effect commits — transient (isolated)", () => {
  const ledger = new JointReversibilityLedger();
  ledger.register(eff("A", ["migration:X"], ["migration:X"]));
  assert.equal(ledger.check(eff("B", ["migration:X"], ["migration:X"])).ok, false, "conflict while A is in-flight");
  assert.equal(ledger.commit("A"), true); // A commits → leaves in-flight
  assert.equal(ledger.check(eff("B", ["migration:X"], ["migration:X"])).ok, true, "conflict cleared after A commits");
});

test("2.3: a released effect also clears the conflict (rollback path)", () => {
  const ledger = new JointReversibilityLedger();
  ledger.register(eff("A", ["migration:X"], ["migration:X"]));
  assert.equal(ledger.check(eff("B", ["migration:X"], ["migration:X"])).ok, false);
  assert.equal(ledger.release("A"), true);
  assert.equal(ledger.check(eff("B", ["migration:X"], ["migration:X"])).ok, true);
});

test("2.3: fleetReversibilityAdmit composes ABOVE the gate — both must clear (isolated)", () => {
  const ok = { ok: true } as const;
  const conflict = { ok: false, reason: "reversibility-conflict:X@A" } as const;
  assert.equal(fleetReversibilityAdmit(true, ok).proceed, true);
  assert.equal(fleetReversibilityAdmit(true, conflict).proceed, false, "gate passed but joint-reversibility holds");
  assert.equal(fleetReversibilityAdmit(false, ok).proceed, false, "gate hold is never overridden");
});
