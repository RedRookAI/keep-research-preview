import { test } from "node:test";
import assert from "node:assert/strict";
import {
  MetaHarness,
  type EvalAnchor,
  type ImprovementProposal,
  type Refiner,
} from "../src/meta/meta_harness.js";
import { ProposalTriad, type TriadCheck } from "../src/meta/proposal_triad.js";

// A simple anchor whose score is the numeric value of the version string ("0.5" → 0.5).
function numericAnchor(extra?: Partial<EvalAnchor>): EvalAnchor {
  return {
    cases: [{ id: "c1", input: "i", expected: "e" }],
    score: (v) => Number(v) || 0,
    weakensSafetyFloor: () => false,
    ...extra,
  };
}

const base = (over: Partial<ImprovementProposal> = {}): ImprovementProposal => ({
  component: "prompt",
  fromVersion: "0.50",
  toVersion: "0.90",
  rationale: "reflective improvement grounded in current practice",
  ...over,
});

// ─── The four original invariants must still hold (increment 18 had NO proving tests — add them) ───

test("invariant: a frozen-floor target is rejected as not-improvable", () => {
  const mh = new MetaHarness({ anchor: numericAnchor() });
  const out = mh.propose(base({ component: "eval-anchor" }));
  assert.equal(out.decision, "rejected-not-improvable");
});

test("invariant: a strict gain on the anchor is accepted", () => {
  const mh = new MetaHarness({ anchor: numericAnchor() });
  mh.register("prompt", "0.50");
  const out = mh.propose(base());
  assert.equal(out.decision, "accepted");
  assert.equal(mh.liveVersion("prompt"), "0.90");
});

test("invariant: a no-gain candidate is rejected", () => {
  const mh = new MetaHarness({ anchor: numericAnchor() });
  mh.register("prompt", "0.90");
  const out = mh.propose(base({ fromVersion: "0.90", toVersion: "0.90" }));
  // no-op is caught by the triad's logic check first (from==to) — still a rejection, never accepted.
  assert.notEqual(out.decision, "accepted");
});

test("invariant: anchor tamper is detected and rejected", () => {
  const cases = [{ id: "c1", input: "i", expected: "e" }];
  const mutable = { list: cases };
  const anchor: EvalAnchor = {
    get cases() { return mutable.list; },
    score: (v) => Number(v) || 0,
    weakensSafetyFloor: () => false,
  };
  const mh = new MetaHarness({ anchor });
  mutable.list = [{ id: "c2", input: "x", expected: "y" }]; // tamper after construction
  const out = mh.propose(base());
  assert.equal(out.decision, "rejected-anchor-tamper");
});

test("invariant: weakening the safety floor is rejected regardless of score", () => {
  const mh = new MetaHarness({ anchor: numericAnchor({ weakensSafetyFloor: () => true }) });
  mh.register("prompt", "0.10");
  const out = mh.propose(base());
  assert.equal(out.decision, "rejected-floor");
});

test("invariant: model-adapter without an extra gate is rejected", () => {
  const mh = new MetaHarness({ anchor: numericAnchor() });
  const out = mh.propose(base({ component: "model-adapter" }));
  assert.equal(out.decision, "rejected-extra-gate");
});

// ─── 18.0: the mandatory triad gates BEFORE the anchor ───

test("triad: a proposal with no rationale is rejected by the triad (research check), before the anchor", () => {
  const mh = new MetaHarness({ anchor: numericAnchor() });
  mh.register("prompt", "0.10");
  const out = mh.propose(base({ rationale: "" }));
  assert.equal(out.decision, "rejected-triad");
  assert.match(out.reason, /research/);
});

test("triad: a no-op (from==to) is rejected by the triad logic check even if it would 'score'", () => {
  const mh = new MetaHarness({ anchor: numericAnchor() });
  mh.register("prompt", "0.10");
  const out = mh.propose(base({ fromVersion: "0.90", toVersion: "0.90" }));
  assert.equal(out.decision, "rejected-triad");
  assert.match(out.reason, /logic|no-op/);
});

test("triad: a declared irreversible external effect is refuted by the consequence check", () => {
  const mh = new MetaHarness({ anchor: numericAnchor() });
  mh.register("prompt", "0.10");
  const out = mh.propose(base({ declaredEffects: ["sends an external-send email to the user"] }));
  assert.equal(out.decision, "rejected-triad");
  assert.match(out.reason, /consequence|sink/);
});

test("triad: the triad cannot be bypassed — it runs even when the anchor gain is huge", () => {
  const mh = new MetaHarness({ anchor: numericAnchor() });
  mh.register("prompt", "0.01");
  // Huge anchor gain (0.01 → 0.99) but a triad-failing no-op-style rationale-less proposal.
  const out = mh.propose(base({ fromVersion: "0.01", toVersion: "0.99", rationale: "" }));
  assert.equal(out.decision, "rejected-triad"); // anchor never even consulted
});

// ─── 18.0: multi-set no-regression (Goodhart-resistant anchor) ───

test("multi-set: a target gain that regresses the SAFETY set ships nothing", () => {
  const anchor: EvalAnchor = {
    cases: [{ id: "c1", input: "i", expected: "e" }],
    score: (v) => Number(v) || 0, // target set: candidate 0.90 > baseline 0.50 → a gain
    weakensSafetyFloor: () => false,
    baselineSet: (s) => (s === "safety" ? 1.0 : 1.0),
    scoreSet: (s, v) => (s === "safety" ? 0.5 : Number(v) || 0), // candidate regresses safety (0.5 < 1.0)
  };
  const mh = new MetaHarness({ anchor });
  mh.register("prompt", "0.50");
  const out = mh.propose(base());
  assert.equal(out.decision, "rejected-set-regression");
  assert.match(out.reason, /safety/);
});

test("multi-set: a target gain that HOLDS safety+capability is accepted", () => {
  const anchor: EvalAnchor = {
    cases: [{ id: "c1", input: "i", expected: "e" }],
    score: (v) => Number(v) || 0,
    weakensSafetyFloor: () => false,
    baselineSet: () => 0.5,
    scoreSet: () => 0.9, // both sets improve/hold
  };
  const mh = new MetaHarness({ anchor });
  mh.register("prompt", "0.50");
  const out = mh.propose(base());
  assert.equal(out.decision, "accepted");
});

// ─── 18.0: the bounded, execution-adjudicated refine LOOP ───

test("loop: refines a failing proposal into a passing one and accepts (convergence)", () => {
  const mh = new MetaHarness({ anchor: numericAnchor() });
  mh.register("prompt", "0.50");
  // First attempt has no rationale (triad-fails); the refiner supplies one on round 2.
  const initial = base({ rationale: "" });
  const refine: Refiner = (prev, _cx, _round) => ({ ...prev, rationale: "now grounded" });
  const res = mh.proposeLoop(initial, refine);
  assert.equal(res.outcome.decision, "accepted");
  assert.equal(res.rounds, 2);
  assert.equal(res.trail[0]?.decision, "rejected-triad");
  assert.equal(res.trail[1]?.decision, "accepted");
});

test("loop: abandons within the ceiling when the refiner cannot fix it (no loopmaxxing)", () => {
  const mh = new MetaHarness({ anchor: numericAnchor() });
  mh.register("prompt", "0.50");
  const initial = base({ rationale: "" });
  const refine: Refiner = (prev) => ({ ...prev, rationale: "" }); // never fixes → keeps failing
  const res = mh.proposeLoop(initial, refine, 5);
  assert.notEqual(res.outcome.decision, "accepted");
  assert.ok(res.rounds <= MetaHarness.REFINE_CEILING_ROUNDS, "must not exceed the hard ceiling");
  assert.equal(res.rounds, 5);
});

test("loop: a terminal (non-refinable) decision stops immediately, no wasted rounds", () => {
  const mh = new MetaHarness({ anchor: numericAnchor() });
  // frozen-floor target → rejected-not-improvable is terminal; the loop must stop at round 1.
  const res = mh.proposeLoop(base({ component: "eval-anchor" }), () => base(), 5);
  assert.equal(res.rounds, 1);
  assert.equal(res.outcome.decision, "rejected-not-improvable");
});

test("loop: refiner returning null abandons cleanly", () => {
  const mh = new MetaHarness({ anchor: numericAnchor() });
  mh.register("prompt", "0.50");
  const res = mh.proposeLoop(base({ rationale: "" }), () => null, 5);
  assert.notEqual(res.outcome.decision, "accepted");
  assert.equal(res.rounds, 1); // one attempt, then refiner gave up
});

// ─── 18.0: the triad is a PORT (custom checks compose) ───

test("triad port: a custom check can add a domain gate", () => {
  const forbidFoo: TriadCheck = {
    name: "logic",
    evaluate: (i) => i.toVersion.includes("foo")
      ? { name: "logic", pass: false, counterexample: "contains foo", strength: "full" }
      : { name: "logic", pass: true, counterexample: "", strength: "full" },
  };
  const triad = new ProposalTriad([forbidFoo]);
  const v = triad.evaluate({ component: "prompt", fromVersion: "a", toVersion: "foo", rationale: "r", hasEgress: true });
  assert.equal(v.pass, false);
  assert.match(v.counterexample, /foo/);
});

test("triad honesty: research check is labelled 'degraded' without egress, 'full' with it", () => {
  const triad = new ProposalTriad();
  const off = triad.evaluate({ component: "prompt", fromVersion: "a", toVersion: "b", rationale: "r", hasEgress: false });
  const on = triad.evaluate({ component: "prompt", fromVersion: "a", toVersion: "b", rationale: "r", hasEgress: true });
  const offResearch = off.results.find((r) => r.name === "research");
  const onResearch = on.results.find((r) => r.name === "research");
  assert.equal(offResearch?.strength, "degraded");
  assert.equal(onResearch?.strength, "full");
});
