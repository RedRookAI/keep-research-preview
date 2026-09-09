import { test } from "node:test";
import assert from "node:assert/strict";

import { CryptoShredKeyStore, type ErasurePhase } from "../src/keystore/keystore.js";
import {
  SeparationOfDuties,
  type Identity,
  type IdentityId,
} from "../src/identity/identity.js";

test("crypto-shred: encrypt/decrypt round-trips", () => {
  const ks = new CryptoShredKeyStore();
  ks.ensureKey("s1");
  const ct = ks.encrypt("s1", "hello");
  assert.equal(ks.decrypt("s1", ct), "hello");
});

test("crypto-shred: keys are per-subject isolated", () => {
  const ks = new CryptoShredKeyStore();
  ks.ensureKey("s1");
  ks.ensureKey("s2");
  const ct = ks.encrypt("s1", "secret");
  // s2's key must not decrypt s1's ciphertext.
  assert.throws(() => ks.decrypt("s2", ct));
});

test("crypto-shred: erasure makes ciphertext unrecoverable but is two-phase audited", () => {
  const ks = new CryptoShredKeyStore();
  const phases: ErasurePhase[] = [];
  ks.onErasure((_s, phase) => phases.push(phase));
  ks.ensureKey("s1");
  const ct = ks.encrypt("s1", "secret");
  assert.equal(ks.shred("s1"), true);
  assert.throws(() => ks.decrypt("s1", ct)); // unrecoverable
  assert.deepEqual(phases, ["requested", "confirmed"]); // audit survives the destroy
});

function ops(...ids: string[]): Map<IdentityId, Identity> {
  const m = new Map<IdentityId, Identity>();
  for (const id of ids) m.set(id, { id, isOperator: true, displayName: id });
  return m;
}

test("SoD single-operator (N=1): self-approval allowed WITH step-up", () => {
  const sod = new SeparationOfDuties(ops("lisa"), { n: 1 });
  const r = sod.authorize({
    action: "memory.promote_global",
    author: "lisa",
    approvers: ["lisa"],
    stepUpVerified: true,
    now: 1,
  });
  assert.equal(r.mode, "single-operator");
});

test("SoD single-operator: step-up is required (stands in for the 2nd human)", () => {
  const sod = new SeparationOfDuties(ops("lisa"), { n: 1 });
  assert.throws(() =>
    sod.authorize({
      action: "memory.promote_global",
      author: "lisa",
      approvers: ["lisa"],
      stepUpVerified: false,
      now: 1,
    }),
  );
});

test("SoD multi-operator (N=2): author cannot be sole approver", () => {
  const sod = new SeparationOfDuties(ops("lisa", "sam"), { n: 2 });
  assert.throws(() =>
    sod.authorize({
      action: "policy.change_invariant",
      author: "lisa",
      approvers: ["lisa"],
      stepUpVerified: true,
      now: 1,
    }),
  );
});

test("SoD multi-operator (N=2): two distinct approvers with step-up succeeds", () => {
  const sod = new SeparationOfDuties(ops("lisa", "sam"), { n: 2 });
  const r = sod.authorize({
    action: "policy.change_invariant",
    author: "lisa",
    approvers: ["lisa", "sam"],
    stepUpVerified: true,
    now: 1,
  });
  assert.equal(r.mode, "multi-operator");
  assert.equal(r.approvers.length, 2);
});

test("SoD: N>=2 never blocks a genuinely solo deployment (falls to single-operator)", () => {
  // Config asks for 2, but only one operator exists -> single-operator mode, not a hard block.
  const sod = new SeparationOfDuties(ops("lisa"), { n: 2 });
  const r = sod.authorize({
    action: "audit.config_change",
    author: "lisa",
    approvers: ["lisa"],
    stepUpVerified: true,
    now: 1,
  });
  assert.equal(r.mode, "single-operator");
});

test("SoD: non-security-critical actions are rejected from the SoD path", () => {
  const sod = new SeparationOfDuties(ops("lisa"), { n: 1 });
  assert.throws(() =>
    sod.authorize({
      // @ts-expect-error deliberately invalid action for the guard test
      action: "routine.thing",
      author: "lisa",
      approvers: ["lisa"],
      stepUpVerified: true,
      now: 1,
    }),
  );
});
