import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";

import { computeReport, computeResolveAtK, compareToBaseline, renderReport, type EvalReport } from "../src/eval/report.js";
import type { InstanceRun } from "../src/eval/harness.js";
import { SyntheticSuite, SyntheticInstanceRunner } from "../src/eval/synthetic_suite.js";
import { runSuite } from "../src/eval/harness.js";

// Build a synthetic InstanceRun with the fields the report reads.
function run(id: string, resolved: boolean, failureClass: InstanceRun["failureClass"], costUsd = 0.005, latencyMs = 10, regressed = false): InstanceRun {
  return {
    instanceId: id,
    verdict: { instanceId: id, resolved, failToPassCleared: [], failToPassMissed: resolved ? [] : ["t"], passToPassRegressed: regressed ? ["p"] : [], reason: "" },
    solveResult: { issueId: id, solved: failureClass !== "gave-up", stagesRun: ["localize", "plan", "apply", "validate", "done"], repairRounds: 0 },
    failureClass,
    costUsd,
    latencyMs,
    stagesRun: ["localize", "plan", "apply", "validate", "done"],
    repairRounds: 0,
  };
}

test("INVARIANT: computeReport matches hand-computed numbers", () => {
  const runs = [
    run("a", true, "resolved", 0.01),
    run("b", true, "resolved", 0.01),
    run("c", false, "gave-up", 0.005),
    run("d", false, "regression", 0.005, 10, true),
  ];
  const r = computeReport("s", runs);
  assert.equal(r.instanceCount, 4);
  assert.equal(r.resolveAt1, 0.5, "2/4 resolved");
  assert.equal(r.regressionRate, 0.25, "1/4 regressed");
  assert.equal(r.failureBreakdown.resolved, 2);
  assert.equal(r.failureBreakdown.gaveUp, 1);
  assert.equal(r.failureBreakdown.regression, 1);
  assert.equal(r.totalCostUsd, 0.03);
  assert.equal(r.costPerResolvedUsd, 0.015, "0.03 / 2 resolved");
});

test("INVARIANT: Resolve@k computes mean + stddev + union/intersection", () => {
  // instance X: resolved in both passes; Y: resolved in one pass only (flaky).
  const pass1 = [run("X", true, "resolved"), run("Y", true, "resolved")];
  const pass2 = [run("X", true, "resolved"), run("Y", false, "fix-incomplete")];
  const k = computeResolveAtK([pass1, pass2]);
  assert.equal(k.k, 2);
  assert.deepEqual(k.perRunResolve, [1, 0.5]);
  assert.equal(k.meanResolve, 0.75);
  assert.ok(k.stddev > 0, "variance captured");
  assert.equal(k.resolveUnion, 1, "both solved at least once");
  assert.equal(k.resolveIntersection, 0.5, "only X solved every run");
});

test("INVARIANT: a deliberately-worse config shows a regression vs baseline", () => {
  const baseline: EvalReport = { ...computeReport("base", [run("a", true, "resolved"), run("b", true, "resolved")]) };
  const worse: EvalReport = { ...computeReport("worse", [run("a", true, "resolved"), run("b", false, "gave-up")]) };
  const cmp = compareToBaseline(baseline, worse);
  assert.ok(cmp.cleanResolvedDelta < 0, `worse config should regress (delta ${cmp.cleanResolvedDelta})`);
});

test("INVARIANT: resolve-up-but-regressions-up flags a corroboration conflict (Goodhart)", () => {
  const baseline = computeReport("base", [run("a", false, "gave-up"), run("b", true, "resolved")]); // 0.5 resolve, 0 regress
  const current = computeReport("cur", [run("a", true, "resolved"), run("b", true, "resolved", 0.005, 10, true)]); // 1.0 resolve, 0.5 regress
  const cmp = compareToBaseline(baseline, current);
  assert.equal(cmp.corroborationConflict, true, "resolve rose but regressions also rose");
});

test("renderReport surfaces caveats and the headline numbers", () => {
  const r = computeReport("synthetic", [run("a", true, "resolved")], ["synthetic — not a real number"]);
  const text = renderReport(r);
  assert.match(text, /Resolve@1/);
  assert.match(text, /Caveats/);
  assert.match(text, /not a real number/);
});

test("INTEGRATION: the real synthetic suite → harness → report (2/3 resolved)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-report-"));
  const spine = new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
  const suite = new SyntheticSuite();
  const runner = new SyntheticInstanceRunner();
  const tasks = await suite.load();
  const runs = await runSuite(tasks, runner, spine);
  const report = computeReport(suite.name, runs, suite.caveats());
  assert.equal(report.instanceCount, 3);
  assert.ok(Math.abs(report.resolveAt1 - 2 / 3) < 0.01, `expected ~0.667, got ${report.resolveAt1}`);
  assert.equal(report.failureBreakdown.resolved, 2);
  assert.equal(report.failureBreakdown.gaveUp, 1);
  assert.ok(report.caveats.length > 0, "caveats carried through");
});
