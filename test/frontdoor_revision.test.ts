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

import { RevisionStore } from "../src/frontdoor/revision_store.js";
import { classifyRebuild } from "../src/frontdoor/rebuild_classifier.js";
import { PlanExecuteGate } from "../src/frontdoor/plan_execute_gate.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-f3b-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

// --- Revision store: non-destructive supersession ---

test("revise keeps the old version (retained, superseded) and makes the new one current", () => {
  const store = new RevisionStore(newSpine());
  const v1 = store.create("goal:1", "directive", "build a todo app", 1000);
  const v2 = store.revise("goal:1", "build a todo app with reminders", "added reminders", 2000)!;
  // Current view is structural: only the new version.
  assert.equal(store.current("goal:1")!.id, v2.id);
  assert.equal(store.current("goal:1")!.content, "build a todo app with reminders");
  // The old version is RETAINED, marked superseded, and linked forward.
  const history = store.history("goal:1");
  assert.equal(history.length, 2);
  const oldV1 = history.find((v) => v.id === v1.id)!;
  assert.equal(oldV1.status, "superseded");
  assert.equal(oldV1.supersededBy, v2.id);
});

test("history reconstructs all versions oldest-first; allCurrent excludes superseded", () => {
  const store = new RevisionStore(newSpine());
  store.create("p:1", "plan", "v1", 1000);
  store.revise("p:1", "v2", undefined, 2000);
  store.revise("p:1", "v3", undefined, 3000);
  const hist = store.history("p:1");
  assert.deepEqual(hist.map((v) => v.content), ["v1", "v2", "v3"]);
  assert.equal(store.allCurrent("plan").length, 1); // only v3 is current
  assert.equal(store.allCurrent("plan")[0]!.content, "v3");
});

test("restore reinstates a prior version as a new current one (old work never lost)", () => {
  const store = new RevisionStore(newSpine());
  const v1 = store.create("goal:1", "directive", "original goal", 1000);
  store.revise("goal:1", "changed goal", undefined, 2000);
  const restored = store.restore(v1.id, "changed my mind back", 3000)!;
  assert.equal(store.current("goal:1")!.content, "original goal"); // back to v1's content
  assert.equal(restored.id !== v1.id, true); // as a NEW version (auditable)
  assert.equal(store.history("goal:1").length, 3); // v1, revision, restored — nothing lost
});

test("asOf reconstructs the content that was current at a past timestamp", () => {
  const store = new RevisionStore(newSpine());
  store.create("g", "directive", "first", 1000);
  store.revise("g", "second", undefined, 2000);
  assert.equal(store.asOf("g", 1500)!.content, "first"); // at t=1500, "first" was current
  assert.equal(store.asOf("g", 2500)!.content, "second"); // at t=2500, "second"
});

test("revise on an unknown item returns undefined (nothing to revise)", () => {
  const store = new RevisionStore(newSpine());
  assert.equal(store.revise("nope", "x"), undefined);
});

// --- Rebuild classifier: the additive/destructive line ---

test("a directive/plan revision is a PURE reversible revision", () => {
  const c = classifyRebuild({ text: "actually, change the goal to a mobile app", target: "directive" });
  assert.equal(c.isPureRevision, true);
  assert.ok(/keep the previous version/i.test(c.summary));
});

test("deleting real work (files/code/build-output) is DESTRUCTIVE", () => {
  for (const target of ["files", "code", "build-output"] as const) {
    const c = classifyRebuild({ text: `delete the ${target} and start over`, target });
    assert.equal(c.isPureRevision, false);
    assert.ok(["delete_data", "deploy_production"].includes(c.action.kind));
  }
});

test("a deployment change is destructive even without a destructive verb", () => {
  const c = classifyRebuild({ text: "rebuild and push it live", target: "deployment" });
  assert.equal(c.isPureRevision, false);
  assert.equal(c.action.kind, "deploy_production");
});

test("destructive phrasing with an unknown target FAILS SAFE to destructive", () => {
  const c = classifyRebuild({ text: "just wipe everything and start fresh" });
  assert.equal(c.isPureRevision, false);
  assert.equal(c.action.kind, "delete_data");
});

// --- The line holds end-to-end through the gate ---

test("a destructive rebuild action is STILL human-gated through the F1.5 gate", async () => {
  const gate = new PlanExecuteGate(newSpine(), new PolicyEngine("v1", []), async () => ({ safe: true }));
  const c = classifyRebuild({ text: "delete all the code and rebuild", target: "code" });
  const decision = await gate.decide(c.action, 1);
  assert.equal(decision.disposition, "human-approval-required"); // the line holds
});

test("a pure revision action auto-approves through the gate (reversible)", async () => {
  const gate = new PlanExecuteGate(newSpine(), new PolicyEngine("v1", []), async () => ({ safe: true }));
  const c = classifyRebuild({ text: "change the goal to add dark mode", target: "directive" });
  const decision = await gate.decide(c.action, 1);
  assert.equal(decision.disposition, "auto-approved"); // reversible revision, no human needed
});
