import { test } from "node:test";
import assert from "node:assert/strict";
import { SolveOutcomeWire, type SolveResultLike } from "../src/loop/solve_outcome_wire.js";
import { SelfImprovementBus, CollectingLearningErrorSink, reuseSignal, type OutcomeSignal } from "../src/loop/self_improvement_bus.js";
import { ReferenceMonitor } from "../src/control/reference_monitor.js";
import { gatedMergeRequiresApproval } from "../src/control/reference_clauses.js";
import { WIRING_LEDGER, ledgerModules } from "../src/loop/wiring_ledger.js";
import { readdirSync } from "node:fs";
import { join } from "node:path";

const solveResult = (over: Partial<SolveResultLike["solveResult"]> = {}, safety: SolveResultLike["safety"] = {}): SolveResultLike => ({
  solveResult: { issueId: "ISSUE-1", solved: true, ...over },
  safety,
});

// ─── the wire: solve result → OutcomeSignal ───

test("toSignal maps a solved result to a passing OutcomeSignal (execution-grounded)", () => {
  const wire = new SolveOutcomeWire(new SelfImprovementBus({ anchorThreshold: 1 }));
  const sig = wire.toSignal(solveResult({ solved: true }, { isolationTier: "tier-2", vettingCleared: true }));
  assert.equal(sig.solveId, "ISSUE-1");
  assert.equal(sig.testsPassed, true);
  assert.equal(sig.vetVerdict, "pass");
  assert.equal(sig.isolationTier, "tier-2");
  assert.equal(sig.mergeVerdict, "pending"); // human hasn't reviewed yet
});

test("toSignal maps an unsolved result to a failing signal", () => {
  const wire = new SolveOutcomeWire(new SelfImprovementBus({ anchorThreshold: 1 }));
  const sig = wire.toSignal(solveResult({ solved: false }, { vettingCleared: false }));
  assert.equal(sig.testsPassed, false);
  assert.equal(sig.vetVerdict, "escalate");
});

// ─── wrapSolve: auto-publishes without altering the result ───

test("wrapSolve publishes the outcome to the bus and returns the result unchanged", async () => {
  const seen: OutcomeSignal[] = [];
  const bus = new SelfImprovementBus({ anchorThreshold: 1 });
  bus.register({ id: "spy", loopClass: "improve", onOutcome: (s) => { seen.push(s); } });
  const wire = new SolveOutcomeWire(bus);

  const rawSolve = async (id: string): Promise<SolveResultLike> => solveResult({ issueId: id, solved: true });
  const wrapped = wire.wrapSolve(rawSolve, { taskShape: "refactor" });
  const result = await wrapped("ISSUE-42");

  assert.equal(result.solveResult.issueId, "ISSUE-42"); // unchanged
  assert.equal(seen.length, 1);
  assert.equal(seen[0]?.solveId, "ISSUE-42");
  assert.equal(seen[0]?.taskShape, "refactor");
});

test("wrapSolve preserves a successful solve when outcome persistence fails and exposes the failure", async () => {
  const sink = new CollectingLearningErrorSink();
  const bus = { publish: async () => { throw new Error("ENOSPC"); } } as unknown as SelfImprovementBus;
  const wire = new SolveOutcomeWire(bus, undefined, undefined, sink);
  const expected = solveResult({ issueId: "SURVIVES" });
  const actual = await wire.wrapSolve(async () => expected)();
  assert.equal(actual, expected);
  assert.equal(wire.learningFailures()[0]?.phase, "outcome-publish");
  assert.match(wire.learningFailures()[0]?.error ?? "", /ENOSPC/);
});

// ─── recordMergeVerdict: the human reuse signal ───

test("recordMergeVerdict emits a reject signal with reason as counterexample", async () => {
  const seen: OutcomeSignal[] = [];
  const bus = new SelfImprovementBus({ anchorThreshold: 1 });
  bus.register({ id: "spy", loopClass: "improve", onOutcome: (s) => { seen.push(s); } });
  const wire = new SolveOutcomeWire(bus);

  await wire.recordMergeVerdict(solveResult({ solved: true }), "rejected", { rejectReason: "style violation" });
  assert.equal(seen.length, 1);
  assert.equal(seen[0]?.mergeVerdict, "rejected");
  const rr = reuseSignal(seen[0] as OutcomeSignal);
  assert.equal(rr.counterexample, "style violation");
  // solved (tests pass, +1) but human rejected (-1) → net neutral (Goodhart guard).
  assert.equal(rr.reward, 0);
});

// ─── guardIrreversible: denies via the reference monitor ───

test("guardIrreversible denies a gated merge with no prior approval on the trace", () => {
  const monitor = new ReferenceMonitor().register(gatedMergeRequiresApproval());
  const wire = new SolveOutcomeWire(new SelfImprovementBus({ anchorThreshold: 1 }), monitor);
  const violations = wire.guardIrreversible({ type: "identity.action", actor: "keep", payload: { event: "merge", gated: "true", target: "PR-1" } });
  assert.equal(violations.length, 1);
  assert.equal(violations[0]?.clauseId, "gated-merge-requires-approval");
});

test("guardIrreversible returns empty (no enforcement) when no monitor is wired", () => {
  const wire = new SolveOutcomeWire(new SelfImprovementBus({ anchorThreshold: 1 }));
  assert.deepEqual(wire.guardIrreversible({ type: "x", actor: "a", payload: {} }), []);
});

// ─── the ledger enforcement: no undocumented orphans ───

test("wiring ledger: every entry has a disposition and a hub", () => {
  for (const e of WIRING_LEDGER) {
    assert.ok(e.module.length > 0, "module named");
    assert.ok(e.hub.length > 0, `${e.module} has a hub`);
    assert.ok(["live", "entry-point", "adapter", "pending-wire", "retire"].includes(e.disposition), `${e.module} disposition valid`);
    assert.ok(e.rationale.length > 10, `${e.module} has a real rationale`);
  }
});

test("wiring ledger: the known true-gap islands are ALL accounted for (no orphan hides)", () => {
  // The islands identified in the completeness audit must each appear in the ledger with a disposition.
  const knownIslands = [
    "grounded_estimator", "prior_art", "brain_resolver", "config_applier",
    "local_first_defaults", "rebuild_classifier", "soul_render", "ci_adapter",
    "oversight_calibration", "hostile_mcp_gateway", "mcp", "capability_port",
    "notification_router", "batch_digest", "merge_readiness", "review_intake", "non_engineer_view", "review_core", "review_web", "review_server", "rbac", "identity", "session_store", "identity_provider", "security_gate", "best_of_n", "selector", "novel_tests", "budget_cascade", "resolution_curve", "solve_monitor",
  ];
  const accounted = ledgerModules();
  for (const island of knownIslands) {
    assert.ok(accounted.has(island), `island "${island}" must be accounted for in the wiring ledger`);
  }
});

test("wiring ledger: the solve→loop wire and monitors are marked live", () => {
  const live = new Set(WIRING_LEDGER.filter((e) => e.disposition === "live").map((e) => e.module));
  for (const m of ["solve_outcome_wire", "self_improvement_bus", "drift_monitor", "reference_monitor"]) {
    assert.ok(live.has(m), `${m} should be marked live`);
  }
});
