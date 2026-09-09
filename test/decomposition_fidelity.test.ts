import { test } from "node:test";
import assert from "node:assert/strict";

import { decompositionFidelity, subGoalsOfPlan } from "../src/eval/report.js";
import type { Plan } from "../src/logicvet/deterministic_critics.js";

const required = ["parse the CSV", "validate rows", "write the report"];

test("NL-FIDELITY-EVAL (a): a plan covering all required sub-goals scores full coverage; missing one does not", () => {
  const full = decompositionFidelity({ requiredSubGoals: required, producedSubGoals: ["Parse the CSV", "validate rows", "write the report"] });
  assert.equal(full.fullCoverage, true);
  assert.deepEqual(full.missing, []);
  assert.equal(full.coveredCount, 3);
  const partial = decompositionFidelity({ requiredSubGoals: required, producedSubGoals: ["parse the CSV", "write the report"] });
  assert.equal(partial.fullCoverage, false);
  assert.deepEqual(partial.missing, ["validate rows"], "the missing required sub-goal is named");
});

test("NL-FIDELITY-EVAL (b): a missing required sub-goal is a HARD miss, never averaged into a passing score", () => {
  // 2 of 3 covered — a naive average would call this 67% 'mostly covered'; the invariant says NOT full coverage.
  const s = decompositionFidelity({ requiredSubGoals: required, producedSubGoals: ["parse the CSV", "validate rows"] });
  assert.equal(s.fullCoverage, false, "a single miss makes fullCoverage false");
  assert.equal(s.missing.length, 1);
  assert.match(s.summary, /MISSING 1 required/);
});

test("NL-FIDELITY-EVAL (c): an extraneous step (present but not required) is flagged, not silently accepted", () => {
  const s = decompositionFidelity({ requiredSubGoals: required, producedSubGoals: [...required, "delete production database"] });
  assert.deepEqual(s.extraneous, ["delete production database"], "the unrequested step is surfaced");
  assert.equal(s.fullCoverage, true, "coverage is still full — extraneous is a separate axis");
});

test("NL-FIDELITY-EVAL (d): fidelity is measured SEPARATELY from correctness (a faithful plan ≠ a correct run)", () => {
  const s = decompositionFidelity({ requiredSubGoals: required, producedSubGoals: required });
  assert.equal(s.fullCoverage, true);
  assert.equal(s.measures, "decomposition-fidelity-not-correctness", "explicitly not a correctness claim");
  assert.match(s.summary, /not correctness/);
  // @ts-expect-error — never asserts execution correctness/success
  assert.equal(s.correct, undefined);
});

test("NL-FIDELITY-EVAL (e): real reference-vs-produced comparison, report-only + deterministic", () => {
  const input = { requiredSubGoals: required, producedSubGoals: ["parse the CSV", "extra"] };
  const a = decompositionFidelity(input);
  const b = decompositionFidelity(input);
  assert.equal(a.changesGate, false, "changes no gate");
  assert.deepEqual(a, b, "deterministic");
  // covered reflects the REAL intersection, not a fabricated positive
  assert.deepEqual(a.covered, ["parse the CSV"]);
  assert.deepEqual(a.missing, ["validate rows", "write the report"]);
});

test("NL-FIDELITY-EVAL (both-tracks): subGoalsOfPlan composes Plan; org sees the breach, n=1 sees the readout", () => {
  const plan: Plan = { goal: "process data", steps: [
    { id: "1", description: "parse the CSV", dependsOn: [] },
    { id: "2", description: "write the report", dependsOn: ["1"] },
  ] };
  const produced = subGoalsOfPlan(plan);
  assert.deepEqual(produced, ["parse the CSV", "write the report"]);
  const s = decompositionFidelity({ requiredSubGoals: required, producedSubGoals: produced });
  assert.equal(s.fullCoverage, false, "org SLO: the missing 'validate rows' surfaces, never smoothed");
  assert.deepEqual(s.missing, ["validate rows"]);
});
