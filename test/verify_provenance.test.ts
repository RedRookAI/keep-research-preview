import { test } from "node:test";
import assert from "node:assert/strict";

import { verificationProvenance, type VerificationProvenanceInput } from "../src/audit/decision_audit.js";
import type { StableResolutionVerdict } from "../src/eval/swebench_task.js";
import type { CrossFamilyVerdict } from "../src/review/heterogeneous.js";
import type { VerificationConfidence } from "../src/routing/verification_confidence.js";
import type { GateRoute } from "../src/gate/composed_gate.js";

const stable = (flaky: boolean, tests: string[] = []): StableResolutionVerdict => ({
  instanceId: "i", resolved: !flaky, flaky, flakyTests: tests, runs: 3, perRunResolved: [true, true, true], reason: "r",
});
const cross = (accepted: boolean, independent = true): CrossFamilyVerdict => ({
  accepted, deterministicPass: true, usedVerifier: true, independent, authorFamily: "anthropic", verifierFamily: "gemini", agreement: accepted, reason: "r",
});
const conf = (band: "high" | "medium" | "low", score: number): VerificationConfidence => ({ score, band, reasons: ["deterministic pass (+0.50)"] });
const route = (r: "auto-proceed" | "human-hold"): GateRoute => ({ route: r, reasons: r === "human-hold" ? ["low-verification-confidence-on-consequential-action"] : ["all-checks-permit"] });

const full: VerificationProvenanceInput = {
  subjectId: "fix-123", deterministicPass: true, stable: stable(false), crossFamily: cross(true), confidence: conf("high", 1.0), gate: route("auto-proceed"),
};

test("VERIFY-PROVENANCE (a): the record faithfully carries each produced verdict", () => {
  const p = verificationProvenance(full);
  assert.equal(p.deterministic, "pass");
  assert.equal(p.stability.stable, true); assert.equal(p.stability.runs, 3);
  assert.equal(p.crossFamily.authorFamily, "anthropic"); assert.equal(p.crossFamily.verifierFamily, "gemini"); assert.equal(p.crossFamily.accepted, true);
  assert.equal(p.confidence.band, "high"); assert.equal(p.confidence.score, 1.0);
  assert.equal(p.gate.route, "auto-proceed");
  assert.equal(p.overall, "clean");
});

test("VERIFY-PROVENANCE (b): a not-computed signal is marked 'not assessed', never fabricated as a pass", () => {
  const p = verificationProvenance({ subjectId: "fix-x", deterministicPass: true }); // only deterministic assessed
  assert.equal(p.stability.assessed, false);
  assert.equal(p.crossFamily.assessed, false);
  assert.equal(p.confidence.assessed, false);
  assert.equal(p.gate.assessed, false);
  assert.equal(p.stability.stable, undefined, "no fabricated stability pass");
  assert.equal(p.crossFamily.accepted, undefined, "no fabricated cross-family accept");
  // deterministic not assessed at all → cannot attest
  const none = verificationProvenance({ subjectId: "fix-y" });
  assert.equal(none.deterministic, "not-assessed");
  assert.equal(none.overall, "incomplete");
});

test("VERIFY-PROVENANCE (c): the record is report-only — building it mutates no input verdict", () => {
  const input: VerificationProvenanceInput = { subjectId: "fix-z", deterministicPass: true, stable: stable(false), crossFamily: cross(true), confidence: conf("high", 1.0), gate: route("auto-proceed") };
  // freeze the nested verdicts IN PLACE — a report-only composer must not mutate them
  Object.freeze(input.stable); Object.freeze(input.crossFamily); Object.freeze(input.gate); Object.freeze(input.confidence);
  const before = JSON.stringify(input);
  const p = verificationProvenance(input); // must not throw (no mutation of frozen inputs)
  assert.equal(JSON.stringify(input), before, "inputs unchanged");
  assert.ok(p.summary.length > 0);
});

test("VERIFY-PROVENANCE (d): the summary reflects the WORST signal (never summarized as clean when flagged/held/failed)", () => {
  // flaky → flagged
  const flaky = verificationProvenance({ ...full, stable: stable(true, ["t_x"]) });
  assert.equal(flaky.overall, "flagged");
  assert.match(flaky.summary, /FLAGGED/);
  assert.ok(!flaky.summary.includes("CLEAN"));
  // held gate → held (worse than flagged)
  const held = verificationProvenance({ ...full, confidence: conf("low", 0.5), gate: route("human-hold") });
  assert.equal(held.overall, "held");
  assert.match(held.summary, /HELD/);
  // deterministic fail → failed (worst)
  const failed = verificationProvenance({ ...full, deterministicPass: false });
  assert.equal(failed.overall, "failed");
  assert.match(failed.summary, /FAILED/);
});

test("VERIFY-PROVENANCE (e): the record is deterministic and JSON-serializable (same inputs → same record; round-trips)", () => {
  const a = verificationProvenance(full);
  const b = verificationProvenance(full);
  assert.deepEqual(a, b, "same inputs → identical record (deterministic)");
  const round = JSON.parse(JSON.stringify(a));
  assert.deepEqual(round, a, "round-trips through JSON unchanged");
});

test("VERIFY-PROVENANCE (both-tracks): an n=1 minimal record (deterministic-only) is honest and clean", () => {
  const n1 = verificationProvenance({ subjectId: "fix-n1", deterministicPass: true, confidence: conf("medium", 0.75) });
  assert.equal(n1.overall, "clean", "deterministic pass + medium confidence, nothing flagged → clean");
  assert.equal(n1.crossFamily.assessed, false, "no cross-family in n=1 — honestly not-assessed");
});
