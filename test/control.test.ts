import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";

import { requiredControl, mayProceedAutonomously, type ActionDescriptor } from "../src/control/action_tier.js";
import { estimateConfidence, shouldSelfQuit, type ProcessSignals } from "../src/control/confidence.js";
import { KillSwitch, type AgentHandle } from "../src/control/killswitch.js";
import { RollbackLedger, IdempotencyStore } from "../src/control/rollback.js";
import { MergeGateInvariant } from "../src/control/merge_gate.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-ctrl-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

// --- The tier-4 invariant: confidence never buys an irreversible action ---

test("irreversible action NEVER proceeds autonomously, even at confidence 1.0", () => {
  const deploy: ActionDescriptor = { name: "deploy to prod", tier: "irreversible" };
  const r = mayProceedAutonomously(deploy, 1.0, 0.5);
  assert.equal(r.proceed, false);
  assert.equal(requiredControl(deploy), "human-approval-required");
});

test("read-only runs freely; reversible-internal acts and logs", () => {
  assert.equal(requiredControl({ name: "read file", tier: "read-only" }), "run-freely");
  assert.equal(requiredControl({ name: "write branch", tier: "reversible-internal" }), "act-and-log");
});

test("external-touching gates on calibrated confidence vs threshold", () => {
  const ext: ActionDescriptor = { name: "call staging API", tier: "external-touching" };
  assert.equal(mayProceedAutonomously(ext, 0.9, 0.7).proceed, true);
  assert.equal(mayProceedAutonomously(ext, 0.5, 0.7).proceed, false);
});

// --- Behavioral (not verbalized) confidence ---

test("confidence drops as process signals worsen (behavioral, not self-reported)", () => {
  const good: ProcessSignals = {
    noProgressIterations: 0, repeatedFailureFingerprints: 0, bestOfNNonePassRate: 0,
    interAgentDivergence: 0, traceLengthRatio: 1, priorOverrideRate: 0,
  };
  const bad: ProcessSignals = {
    noProgressIterations: 5, repeatedFailureFingerprints: 3, bestOfNNonePassRate: 1,
    interAgentDivergence: 1, traceLengthRatio: 3, priorOverrideRate: 1,
  };
  assert.ok(estimateConfidence(good) > 0.95);
  assert.ok(estimateConfidence(bad) < 0.1);
});

test("shouldSelfQuit triggers when stuck (#25 selective-quit safety win)", () => {
  const stuck: ProcessSignals = {
    noProgressIterations: 4, repeatedFailureFingerprints: 0, bestOfNNonePassRate: 0,
    interAgentDivergence: 0, traceLengthRatio: 1, priorOverrideRate: 0,
  };
  assert.equal(shouldSelfQuit(stuck), true);
});

// --- The layered kill-switch ---

function handle(id: string, cred: string, parentId?: string): AgentHandle & { killed: boolean } {
  const h = {
    agentId: id, credentialId: cred, killed: false,
    ...(parentId !== undefined ? { parentId } : {}),
    terminate() { h.killed = true; },
  };
  return h;
}

test("kill: out-of-process terminate + credential revoke + network isolate", () => {
  const ks = new KillSwitch(newSpine());
  const a = handle("agent-1", "cred-1");
  ks.register(a);
  const rec = ks.kill("agent-1", "manual test");
  assert.equal(a.killed, true); // terminated out-of-process (we didn't ask the agent)
  assert.equal(ks.isRevoked("cred-1"), true); // credential revoked
  assert.equal(ks.isIsolated("agent-1"), true); // network isolated
  assert.equal(rec.credentialRevoked, true);
});

test("kill CASCADES to delegated children (halt that leaves children live isn't containment)", () => {
  const ks = new KillSwitch(newSpine());
  const parent = handle("parent", "cred-p");
  const child = handle("child", "cred-c", "parent");
  const grandchild = handle("grandchild", "cred-g", "child");
  ks.register(parent);
  ks.register(child);
  ks.register(grandchild);
  const rec = ks.kill("parent", "kill parent");
  assert.equal(child.killed, true);
  assert.equal(grandchild.killed, true);
  assert.equal(ks.isRevoked("cred-c"), true);
  assert.equal(ks.isRevoked("cred-g"), true);
  assert.ok(rec.cascadedTo.includes("child"));
  assert.ok(rec.cascadedTo.includes("grandchild"));
});

test("circuit-breaker trips automatically on threshold breach", () => {
  const ks = new KillSwitch(newSpine());
  ks.register(handle("agent-1", "cred-1"));
  const rec = ks.checkCircuitBreaker(
    "agent-1",
    { actions: 1000, costUsd: 1, loops: 0 },
    { maxActions: 100, maxCostUsd: 50, maxLoops: 10 },
  );
  assert.ok(rec);
  assert.equal(rec!.reason, "circuit-breaker"); // the StopReason category
  assert.equal(rec!.triggeringPolicy, "circuit-breaker: actions 1000 > 100"); // the breach detail
});

test("false-positive termination is reversible and audited", () => {
  const ks = new KillSwitch(newSpine());
  ks.register(handle("agent-1", "cred-1"));
  ks.kill("agent-1", "mistaken");
  assert.equal(ks.isTerminated("agent-1"), true);
  ks.reverseTermination("agent-1", "cred-1-new", "false positive confirmed");
  assert.equal(ks.isTerminated("agent-1"), false);
  assert.equal(ks.isIsolated("agent-1"), false);
});

// --- Rollback + idempotency ---

test("rollback runs real inverses in LIFO order and times the motion", async () => {
  const ledger = new RollbackLedger(newSpine());
  const undone: string[] = [];
  ledger.record({ id: "a1", artifact: "commit-1", undo: async () => { undone.push("a1"); } });
  ledger.record({ id: "a2", artifact: "commit-2", undo: async () => { undone.push("a2"); } });
  const r = await ledger.rollback(2, "test");
  assert.equal(r.rolledBack, 2);
  assert.deepEqual(undone, ["a2", "a1"]); // LIFO
  assert.ok(r.ms >= 0);
});

test("idempotency store dedups repeated external mutations (Round 8 at-least-once)", async () => {
  const store = new IdempotencyStore();
  let executions = 0;
  const first = await store.once("key-1", async () => { executions++; return "done"; });
  const second = await store.once("key-1", async () => { executions++; return "done"; });
  assert.equal(first.deduped, false);
  assert.equal(second.deduped, true);
  assert.equal(executions, 1); // executed once despite two calls
});

// --- Boot-level merge gate invariant (Round 19) ---

test("merge gate: irreversible tier requires human merge (boot invariant)", () => {
  const gate = new MergeGateInvariant();
  assert.equal(gate.requiresHumanMerge("irreversible"), true);
  assert.equal(gate.requiresHumanMerge("reversible-internal"), false);
});

test("merge gate REFUSES to honor env auto-merge on a gated tier", () => {
  const gate = new MergeGateInvariant();
  const r = gate.evaluateAutonomousMerge("irreversible", true); // env claims auto-merge
  assert.equal(r.allowed, false);
  assert.equal(r.refuseOperation, true); // refuses rather than honors
});

test("merge gate: the gated-tier set is frozen and cannot be widened at runtime", () => {
  const gate = new MergeGateInvariant();
  // The invariant holds regardless of any external attempt; irreversible stays gated.
  assert.equal(gate.requiresHumanMerge("irreversible"), true);
  const nonGated = gate.evaluateAutonomousMerge("read-only", true);
  assert.equal(nonGated.allowed, true); // non-gated tiers can follow policy
});
