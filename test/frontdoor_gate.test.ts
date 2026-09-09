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

import { PlanExecuteGate, type AdversarialReviewer } from "../src/frontdoor/plan_execute_gate.js";
import { classifyProposedAction, isDestructiveKind, type ProposedAction } from "../src/frontdoor/action_schema.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-f15-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

// Reviewers of varying trustworthiness.
const alwaysSafe: AdversarialReviewer = async () => ({ safe: true });
const alwaysVeto: AdversarialReviewer = async () => ({ safe: false, concern: "over-scoped access" });
const throwing: AdversarialReviewer = async () => { throw new Error("reviewer down"); };

function gate(reviewer: AdversarialReviewer, spine = newSpine()) {
  return new PlanExecuteGate(spine, new PolicyEngine("v1", []), reviewer);
}

function action(kind: ProposedAction["kind"], rationale = "because the user asked"): ProposedAction {
  return { kind, args: {}, rationale };
}

// --- Auto-approve the reversible tier (the high-bar-for-humans contract) ---

test("a reversible-internal action AUTO-APPROVES with no human when vetting passes", async () => {
  const d = await gate(alwaysSafe).decide(action("capture_goal"));
  assert.equal(d.disposition, "auto-approved");
});

test("multiple reversible actions never bother the human (permission-fatigue avoidance)", async () => {
  const g = gate(alwaysSafe);
  for (const k of ["capture_goal", "set_preference", "note_project", "index_uploaded_file"] as const) {
    assert.equal((await g.decide(action(k))).disposition, "auto-approved");
  }
});

// --- THE CRITICAL PROPERTY: destructive actions can't be downgraded by the model ---

test("a destructive action requires human approval EVEN IF the reviewer is fooled into saying safe", async () => {
  // The adversarial reviewer is compromised and approves everything.
  const d = await gate(alwaysSafe).decide(action("drop_database"), 1); // even at max confidence
  assert.equal(d.disposition, "human-approval-required"); // structural tier gate, not the reviewer
  assert.ok(/can't be undone/i.test(d.reason));
  // And it must NOT have auto-approved under any circumstance.
  assert.notEqual(d.disposition, "auto-approved");
});

test("every destructive kind is pinned irreversible and cannot auto-approve", async () => {
  const g = gate(alwaysSafe);
  for (const k of ["delete_data", "drop_database", "revoke_access", "spend_money", "send_external_comms", "deploy_production", "grant_broad_scope"] as const) {
    assert.equal(isDestructiveKind(k), true);
    assert.equal(classifyProposedAction(action(k)).tier, "irreversible");
    assert.equal((await g.decide(action(k))).disposition, "human-approval-required");
  }
});

// --- Untrusted LLM output + policy ---

test("an unknown/malformed action kind is blocked (untrusted model output)", async () => {
  const d = await gate(alwaysSafe).decide({ kind: "rm_rf_everything" as ProposedAction["kind"], args: {}, rationale: "trust me" });
  assert.equal(d.disposition, "blocked");
});

test("a policy DENY blocks the action", async () => {
  const spine = newSpine();
  const denyChannels = new PolicyEngine("v1", [
    { id: "no-channels", effect: "deny", description: "channels disabled", when: (c) => c.attributes?.["actionKind"] === "bind_channel" },
  ]);
  const g = new PlanExecuteGate(spine, denyChannels, alwaysSafe);
  assert.equal((await g.decide(action("bind_channel"), 0.9)).disposition, "blocked"); // deny beats high confidence
});

test("external actions FAIL SAFE: with no confidence passed, they escalate (not silent auto-approve)", async () => {
  const g = gate(alwaysSafe);
  // No confidence argument => default 0 => must escalate an external-touching action.
  assert.equal((await g.decide(action("bind_channel"))).disposition, "human-approval-required");
  assert.equal((await g.decide(action("request_file_access"))).disposition, "human-approval-required");
  // Reversible-internal is unaffected by the confidence default.
  assert.equal((await g.decide(action("capture_goal"))).disposition, "auto-approved");
});

// --- Adversarial vetting escalates, fail-closed ---

test("an adversarial veto on a reversible action escalates to a human (not auto)", async () => {
  const d = await gate(alwaysVeto).decide(action("start_background_research"));
  assert.equal(d.disposition, "human-approval-required");
  assert.ok(d.vetting.some((v) => !v.safe));
});

test("a reviewer that throws is treated as unsafe (fail-closed)", async () => {
  const d = await gate(throwing).decide(action("capture_goal"));
  assert.equal(d.disposition, "human-approval-required"); // did not silently auto-approve
});

// --- External-touching confidence gate ---

test("external-touching auto-approves above the confidence threshold, escalates below", async () => {
  const g = gate(alwaysSafe);
  const hi = await g.decide(action("bind_channel"), 0.9); // >= 0.75
  assert.equal(hi.disposition, "auto-approved");
  const lo = await g.decide(action("bind_channel"), 0.5); // < 0.75
  assert.equal(lo.disposition, "human-approval-required");
});

// --- Auditability ---

test("every gate decision is logged to the spine with disposition + risk", async () => {
  const spine = newSpine();
  const g = new PlanExecuteGate(spine, new PolicyEngine("v1", []), alwaysSafe);
  await g.decide(action("capture_goal"));
  await g.decide(action("drop_database"));
  const decisions = spine.currentEvents().filter((e) => (e.payload as Record<string, unknown>)["event"] === "gate.decision");
  assert.equal(decisions.length, 2);
  const kinds = decisions.map((e) => (e.payload as Record<string, unknown>)["disposition"]);
  assert.ok(kinds.includes("auto-approved"));
  assert.ok(kinds.includes("human-approval-required"));
});

test("suggest_runtime is read-only (a suggestion has no side effect) and auto-approves", async () => {
  const d = await gate(alwaysSafe).decide(action("suggest_runtime"));
  assert.equal(d.disposition, "auto-approved");
});
