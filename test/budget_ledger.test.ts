import { test } from "node:test";
import assert from "node:assert/strict";

import {
  checkBudget,
  defaultBudgetPolicy,
  type ConsumptionRecord,
  type BudgetPolicy,
} from "../src/budget/budget_ledger.js";

// Build Step 2 — the budget ledger (crude, diverse, structural resource invariants).
// These prove any single ceiling trips the whole thing, and a MISSING count fails safe to
// exceeded (fuse fails open). Verify by disproof.

// A tight policy so each quantity is easy to trip one at a time.
const tight: BudgetPolicy = {
  maxEdits: 5,
  maxBytesWritten: 1000,
  maxFilesTouched: 3,
  maxFanOut: 2,
  maxSteps: 10,
};

// A fully-populated within-budget record.
const ok: ConsumptionRecord = { edits: 1, bytesWritten: 100, filesTouched: 1, fanOut: 0, steps: 1 };

test("BUDGET: a fully-populated within-ceiling record is within-budget", () => {
  assert.equal(checkBudget(ok, tight).verdict, "within-budget");
});

test("BUDGET: each ceiling trips INDIVIDUALLY (diverse-OR — every quantity bites)", () => {
  const overs: Array<[keyof ConsumptionRecord, number, string]> = [
    ["edits", 6, "edits"],
    ["bytesWritten", 1001, "bytesWritten"],
    ["filesTouched", 4, "filesTouched"],
    ["fanOut", 3, "fanOut"],
    ["steps", 11, "steps"],
  ];
  for (const [field, value, label] of overs) {
    const rec = { ...ok, [field]: value };
    const v = checkBudget(rec, tight);
    assert.equal(v.verdict, "exceeded", `${label} over ceiling should trip`);
    if (v.verdict === "exceeded") assert.ok(v.ceilings.some((c) => c.startsWith(label)), `${label} named in ${v.ceilings}`);
  }
});

test("BUDGET: a MISSING count fails safe → exceeded (fuse fails open, not read as under)", () => {
  for (const field of ["edits", "bytesWritten", "filesTouched", "fanOut", "steps"] as const) {
    const rec = { ...ok };
    delete (rec as Record<string, number>)[field];
    const v = checkBudget(rec, tight);
    assert.equal(v.verdict, "exceeded", `missing ${field} must fail safe to exceeded`);
    if (v.verdict === "exceeded") assert.ok(v.ceilings.some((c) => c === `${field}:missing`));
  }
});

test("BUDGET: an empty record (all missing) trips every ceiling", () => {
  const v = checkBudget({}, tight);
  assert.equal(v.verdict, "exceeded");
  if (v.verdict === "exceeded") assert.equal(v.ceilings.length, 5, "all five quantities fail safe");
});

test("BUDGET: exactly-at-ceiling is allowed; one-over trips (boundary is the max allowed)", () => {
  assert.equal(checkBudget({ ...ok, edits: 5 }, tight).verdict, "within-budget"); // == ceiling ok
  assert.equal(checkBudget({ ...ok, edits: 6 }, tight).verdict, "exceeded"); // > ceiling trips
});

test("BUDGET: is pure + model-independent — deterministic on frozen input, no I/O", () => {
  const frozen = Object.freeze({ ...ok });
  assert.deepEqual(checkBudget(frozen, tight), checkBudget(frozen, tight));
  // there is no model parameter — structural counts vs numbers only.
});

test("BUDGET: default policy has generous headroom (a normal small edit is within-budget)", () => {
  const normal: ConsumptionRecord = { edits: 3, bytesWritten: 4000, filesTouched: 2, fanOut: 1, steps: 20 };
  assert.equal(checkBudget(normal, defaultBudgetPolicy()).verdict, "within-budget");
});
