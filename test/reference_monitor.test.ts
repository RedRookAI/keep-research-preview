import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ReferenceMonitor,
  neverEvent,
  precededBy,
  type TraceEvent,
} from "../src/control/reference_monitor.js";
import {
  defaultKeepClauses,
  frozenFloorNeverMutated,
  selfImprovementRequiresTriad,
  gatedMergeRequiresApproval,
} from "../src/control/reference_clauses.js";

const e = (type: string, payload: Record<string, unknown> = {}, actor = "keep"): TraceEvent => ({ type, actor, payload });

// ─── THE core property: trace-level catches what per-action cannot ───

test("trace-level: a gated merge with NO prior approval is a violation (per-action check would miss it)", () => {
  const rm = new ReferenceMonitor().register(gatedMergeRequiresApproval());
  // The merge event ALONE looks fine to a per-action check. Only the TRACE (no approval before it) is a violation.
  const violations = rm.audit([
    e("identity.action", { event: "merge", gated: "true", target: "PR-1" }),
  ]);
  assert.equal(violations.length, 1);
  assert.equal(violations[0]?.clauseId, "gated-merge-requires-approval");
});

test("trace-level: the SAME merge event is FINE when preceded by an approval in the trace", () => {
  const rm = new ReferenceMonitor().register(gatedMergeRequiresApproval());
  const violations = rm.audit([
    e("sod.approval", { target: "PR-1", tier: "gated" }),      // approval first
    e("identity.action", { event: "merge", gated: "true", target: "PR-1" }), // now the merge is legitimate
  ]);
  assert.deepEqual(violations, []);
});

test("trace-level: approval for a DIFFERENT target does not authorize this merge", () => {
  const rm = new ReferenceMonitor().register(gatedMergeRequiresApproval());
  const violations = rm.audit([
    e("sod.approval", { target: "PR-OTHER" }),
    e("identity.action", { event: "merge", gated: "true", target: "PR-1" }),
  ]);
  assert.equal(violations.length, 1); // correlation key matters — a per-action check can't do this either
});

// ─── frozen floor never mutated ───

test("frozen floor: a write to a frozen-floor component is a violation", () => {
  const rm = new ReferenceMonitor().register(frozenFloorNeverMutated());
  const violations = rm.audit([e("identity.action", { event: "component_write", component: "eval-anchor" })]);
  assert.equal(violations.length, 1);
  assert.equal(violations[0]?.clauseId, "frozen-floor-immutable");
});

test("frozen floor: a write to an improvable component is fine", () => {
  const rm = new ReferenceMonitor().register(frozenFloorNeverMutated());
  const violations = rm.audit([e("identity.action", { event: "component_write", component: "prompt" })]);
  assert.deepEqual(violations, []);
});

// ─── accepted self-improvement requires a preceding triad pass ───

test("self-improvement: an accepted improvement with NO preceding triad pass is a violation", () => {
  const rm = new ReferenceMonitor().register(selfImprovementRequiresTriad());
  const violations = rm.audit([
    e("identity.action", { event: "self_improvement", decision: "accepted", component: "prompt" }),
  ]);
  assert.equal(violations.length, 1);
  assert.equal(violations[0]?.clauseId, "self-improvement-requires-triad");
});

test("self-improvement: an accepted improvement PRECEDED by its triad pass is fine", () => {
  const rm = new ReferenceMonitor().register(selfImprovementRequiresTriad());
  const violations = rm.audit([
    e("identity.action", { event: "triad_pass", component: "prompt" }),
    e("identity.action", { event: "self_improvement", decision: "accepted", component: "prompt" }),
  ]);
  assert.deepEqual(violations, []);
});

// ─── enforcement primitive: wouldViolate speculates WITHOUT mutating state ───

test("wouldViolate: speculatively checks a candidate without advancing the real trace state", () => {
  const rm = new ReferenceMonitor().register(frozenFloorNeverMutated());
  const candidate = e("identity.action", { event: "component_write", component: "spine" });
  const v1 = rm.wouldViolate(candidate);
  assert.equal(v1.length, 1); // would violate
  // The real state was NOT advanced — a second identical check still just "would" violate, not "has".
  const v2 = rm.wouldViolate(candidate);
  assert.equal(v2.length, 1);
  assert.equal(rm.eventsObserved, 0); // nothing was committed
});

test("wouldViolate returns empty for a safe candidate → caller may proceed", () => {
  const rm = new ReferenceMonitor().register(frozenFloorNeverMutated());
  assert.deepEqual(rm.wouldViolate(e("identity.action", { event: "component_write", component: "prompt" })), []);
});

// ─── single plug-in point: all default clauses enforced together ───

test("single point: the monitor enforces ALL registered clauses over one trace", () => {
  const rm = new ReferenceMonitor();
  for (const c of defaultKeepClauses()) rm.register(c);
  assert.equal(rm.clauseIds.length, 4);
  const violations = rm.audit([
    e("identity.action", { event: "component_write", component: "patch-verifier" }), // clause 1
    e("identity.action", { event: "self_improvement", decision: "accepted", component: "routing-threshold" }), // clause 2
    e("identity.action", { event: "merge", gated: "true", target: "PR-9" }), // clause 3
  ]);
  const ids = new Set(violations.map((v) => v.clauseId));
  assert.ok(ids.has("frozen-floor-immutable"));
  assert.ok(ids.has("self-improvement-requires-triad"));
  assert.ok(ids.has("gated-merge-requires-approval"));
});

test("register is idempotent by clause id", () => {
  const c = neverEvent("dup", "d", () => false);
  const rm = new ReferenceMonitor().register(c).register(c);
  assert.deepEqual(rm.clauseIds, ["dup"]);
});

// ─── a custom clause via the precededBy builder ───

test("precededBy builder: latches a violation and stays violated (no false clear)", () => {
  const rm = new ReferenceMonitor().register(
    precededBy("x", "b requires prior a", (ev) => ev.type === "a", (ev) => ev.type === "b", (ev) => String(ev.payload.k)),
  );
  const violations = rm.audit([
    e("b", { k: "1" }), // violation: no prior a
    e("a", { k: "1" }), // a later a does not retroactively fix it
  ]);
  assert.ok(violations.length >= 1);
});

// ─── CLAUSE 4: external effect (publish) requires prior isolated execution (forbidWithout) ───

import { externalEffectRequiresIsolation } from "../src/control/reference_clauses.js";

test("isolation backstop: a publish with NO prior isolated execution is a violation (isolation path bypassed)", () => {
  const rm = new ReferenceMonitor().register(externalEffectRequiresIsolation());
  const violations = rm.audit([
    e("identity.action", { event: "solve_to_pr", branch: "keep/PR-1" }),
  ]);
  assert.equal(violations.length, 1);
  assert.equal(violations[0]!.clauseId, "external-effect-requires-isolation");
});

test("isolation backstop: a publish PRECEDED by a real isolated execution is fine (the normal solve path)", () => {
  const rm = new ReferenceMonitor().register(externalEffectRequiresIsolation());
  const violations = rm.audit([
    e("identity.action", { event: "isolated_execution", tier: "process", executed: true, patchRisk: "medium" }),
    e("identity.action", { event: "solve_to_pr", branch: "keep/PR-1" }),
  ]);
  assert.deepEqual(violations, [], "isolation ran before the publish → no violation");
});

test("isolation backstop: a REFUSED isolation (executed:false) does NOT establish the guard — a later publish violates", () => {
  const rm = new ReferenceMonitor().register(externalEffectRequiresIsolation());
  const violations = rm.audit([
    e("identity.action", { event: "isolated_execution", tier: "none", executed: false, patchRisk: "high" }),
    e("identity.action", { event: "solve_to_pr", branch: "keep/PR-1" }),
  ]);
  assert.equal(violations.length, 1, "a refused (executed:false) isolation cannot authorize a publish");
});

test("isolation backstop is in the DEFAULT clause set (registered into the composed monitor)", () => {
  const rm = new ReferenceMonitor();
  for (const c of defaultKeepClauses()) rm.register(c);
  assert.ok(rm.clauseIds.includes("external-effect-requires-isolation"), "wired into defaultKeepClauses");
});
