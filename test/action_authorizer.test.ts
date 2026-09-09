import { test } from "node:test";
import assert from "node:assert/strict";

import {
  classifyExternalAction,
  authorizeAutonomousAction,
  type SpendCap,
  type ActionDescriptor,
} from "../src/scheduler/action_authorizer.js";

const unlimited: SpendCap = { canAfford: () => true };
const brokeCap: SpendCap = { canAfford: () => false };

function action(over: Partial<ActionDescriptor> = {}): ActionDescriptor {
  return { description: "reorganize my notes", consequence: "reversible", ...over };
}

test("TAXONOMIC: every action maps to exactly one external class (highest-stakes wins)", () => {
  assert.equal(classifyExternalAction("pay the invoice and email a receipt"), "pay"); // pay > send
  assert.equal(classifyExternalAction("publish the post"), "publish");
  assert.equal(classifyExternalAction("deploy to production"), "deploy");
  assert.equal(classifyExternalAction("send the email"), "send");
  assert.equal(classifyExternalAction("delete the old branch"), "delete");
  assert.equal(classifyExternalAction("reformat this local draft"), "none");
});

test("ENVELOPE: a send/pay/publish action is external → veto (never autonomous)", () => {
  for (const [desc, cls] of [["email the client", "send"], ["charge the card", "pay"], ["publish the release notes", "publish"]] as const) {
    const r = authorizeAutonomousAction(action({ description: desc }), unlimited);
    assert.equal(r.verdict, "veto", `${desc} must be vetoed`);
    assert.equal(r.externalClass, cls);
  }
});

test("ENVELOPE: an irreversible action is vetoed EVEN under an unlimited cap", () => {
  const r = authorizeAutonomousAction(action({ description: "reorganize my notes", consequence: "irreversible", costUsd: 0 }), unlimited);
  assert.equal(r.verdict, "veto", "irreversible is never autonomous regardless of spend");
});

test("CAP-BOUNDED: a local action whose spend breaches the cap is BLOCKED", () => {
  const r = authorizeAutonomousAction(action({ description: "run a big local batch", costUsd: 5 }), brokeCap);
  assert.equal(r.verdict, "blocked-over-cap", "over-cap spend is blocked, never executed");
});

test("AUTONOMOUS: a local, reversible action within the cap proceeds autonomously", () => {
  const r = authorizeAutonomousAction(action({ description: "reformat my local draft", costUsd: 1 }), unlimited);
  assert.equal(r.verdict, "autonomous");
  assert.equal(r.externalClass, "none");
});

test("COMPOSED: a zero-cost local reversible action needs no cap check and is autonomous", () => {
  // brokeCap.canAfford would refuse, but a zero-cost action never consults it.
  const r = authorizeAutonomousAction(action({ description: "tidy my notes", costUsd: 0 }), brokeCap);
  assert.equal(r.verdict, "autonomous");
});
