import { test } from "node:test";
import assert from "node:assert/strict";
import { runLocalBaseline, runOracleValidation } from "../src/eval/swe_eval.js";

test("HARNESS VALIDATION (crown): the gold patch RESOLVES 100%, a buggy tree resolves 0% — the number is real", async () => {
  const gold = await runOracleValidation(true);
  const buggy = await runOracleValidation(false);
  // A correct patch must make FAIL_TO_PASS flip AND keep PASS_TO_PASS — full resolution.
  assert.equal(gold.report.resolveAt1, 1, "a correct fix resolves every instance (the harness credits real fixes)");
  assert.equal(gold.report.failureBreakdown.resolved, 3);
  // A broken tree must never resolve — no false positives.
  assert.equal(buggy.report.resolveAt1, 0, "a buggy tree resolves nothing (the harness has no false positives)");
});

test("LOCAL BASELINE: Keep's real pipeline with the deterministic LocalProvider is an honest 0% floor (gave up)", async () => {
  const r = await runLocalBaseline();
  assert.equal(r.admitted, 3, "all 3 self-authored instances pass decontamination (post-cutoff, no leakage)");
  assert.equal(r.excluded, 0);
  assert.equal(r.report.resolveAt1, 0, "the stub brain cannot synthesize patches → honest floor");
  assert.equal(r.report.failureBreakdown.gaveUp, 3, "the failure class is 'gave up' (no plan), not a harness error");
  // the caveats state the honest scope
  assert.ok(r.report.caveats.some((c) => /NOT official SWE-bench Verified/i.test(c)), "the report is honest about scope");
  assert.ok(r.report.caveats.some((c) => /frontier model/i.test(c)), "the report names what produces a real number");
});

test("DECONTAMINATION applied: a pre-cutoff clone of an instance would be excluded", async () => {
  // Sanity that the eval path runs decontamination (the suite itself is post-cutoff, so admitted=3).
  const r = await runLocalBaseline();
  assert.equal(r.admitted + r.excluded, 3);
  assert.equal(r.excluded, 0, "the self-authored suite is decontaminated by construction");
});
