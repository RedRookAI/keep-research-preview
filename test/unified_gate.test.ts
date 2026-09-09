import { test } from "node:test";
import assert from "node:assert/strict";
import { buildUnifiedGate, type FloorAdapter } from "../src/cascade/unified_gate.js";
import type { VerificationItem, TierResult } from "../src/cascade/verification_cascade.js";

// A "plan" floor: blocks if the plan text says "drop database".
const planFloor: FloorAdapter<string> = {
  name: "plan-consequence-floor",
  evaluate: (text) => /drop database/i.test(text) ? { decision: "fail", reason: "destructive" } : { decision: "pass", reason: "ok" },
};
// A "patch" floor: fails if the patch text modifies a test file.
const patchFloor: FloorAdapter<string> = {
  name: "patch-verifier-floor",
  evaluate: (text) => /test\//.test(text) ? { decision: "fail", reason: "modifies tests" } : { decision: "pass", reason: "ok" },
};
const item = (id: string, payload: string, kind: string): VerificationItem<string> => ({ id, kind, payload });

test("INVARIANT: BOTH plan and patch route through the SAME unified gate (one cascade path)", async () => {
  const planGate = buildUnifiedGate(planFloor, { capability: "lean" });
  const patchGate = buildUnifiedGate(patchFloor, { capability: "lean" });
  const planOut = await planGate(item("p1", "refactor the module", "plan"));
  const patchOut = await patchGate(item("q1", "edit src/x.ts", "patch"));
  // Same outcome shape from both gates (unification).
  assert.ok("finalDecision" in planOut && "trail" in planOut);
  assert.ok("finalDecision" in patchOut && "trail" in patchOut);
  assert.equal(planOut.finalDecision, "pass");
  assert.equal(patchOut.finalDecision, "pass");
});

test("INVARIANT: the deterministic floor is authoritative (plan destructive → fail)", async () => {
  const planGate = buildUnifiedGate(planFloor, { capability: "rich",
    singleBrain: () => ({ decision: "pass", reason: "model ok", certainty: 1 }),
    singleBrainAuthorship: { agentId: "a", modelFamily: "fam-A" } });
  const out = await planGate(item("p2", "drop database and continue", "plan"));
  assert.equal(out.finalDecision, "fail", "sound floor fail is authoritative over a model pass");
  assert.equal(out.decidedAtTier, 0);
});

test("INVARIANT: the deterministic floor is authoritative (patch modifies tests → fail)", async () => {
  const patchGate = buildUnifiedGate(patchFloor, { capability: "none" });
  const out = await patchGate(item("q2", "edit test/x.test.ts", "patch"));
  assert.equal(out.finalDecision, "fail");
});

test("INVARIANT: capability adaptation flows through the unified gate (none → floor + human only)", async () => {
  const gate = buildUnifiedGate(planFloor, { capability: "none" });
  const out = await gate(item("p3", "harmless change", "plan"));
  assert.ok(out.trail.some((t) => t.tier === 0), "floor always runs");
  assert.ok(!out.trail.some((t) => t.tier === 1), "no model tier for none");
});

test("INVARIANT: every tier decision is audited via the logger", async () => {
  const logged: TierResult[] = [];
  const gate = buildUnifiedGate(planFloor, { capability: "none", logger: (r) => logged.push(r) });
  await gate(item("p4", "harmless", "plan"));
  assert.ok(logged.some((r) => r.tier === 0), "floor decision logged to the audit trail");
});
