import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { RollbackLedger } from "../src/control/rollback.js";

import { InMemoryFileTree } from "../src/solve/patch.js";
import { validate, type TestRunner, type TestRunResult } from "../src/solve/validate.js";
import { repairLoop } from "../src/solve/repair_loop.js";
import type { EditPlan } from "../src/solve/issue_model.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-repair-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}
function newLedger(spine: Spine): RollbackLedger { return new RollbackLedger(spine); }

/** A scripted test runner whose result depends on the current file content (so patches change it). */
class ScriptedRunner implements TestRunner {
  constructor(private readonly tree: InMemoryFileTree, private readonly check: (content: string) => TestRunResult) {}
  async run(_repoRef: string): Promise<TestRunResult> {
    const content = (await this.tree.read("src/a.ts")) ?? "";
    return this.check(content);
  }
}

// ── validate ─────────────────────────────────────────────────────────────────

test("INVARIANT: validate passes ONLY when all tests pass (external oracle)", async () => {
  const runner: TestRunner = { async run() { return { results: [{ name: "t1", passed: true }, { name: "t2", passed: true }] }; } };
  const out = await validate("r", runner);
  assert.equal(out.testsPassed, true);
  assert.equal(out.failures.length, 0);
});

test("INVARIANT: a green run with 0 tests is NOT a pass", async () => {
  const runner: TestRunner = { async run() { return { results: [] }; } };
  const out = await validate("r", runner);
  assert.equal(out.testsPassed, false, "0 tests discovered must not count as passing");
  assert.match(out.detail, /0 tests/);
});

test("INVARIANT: structured failures are surfaced for repair feedback", async () => {
  const runner: TestRunner = { async run() { return { results: [{ name: "t1", passed: true }, { name: "t2", passed: false, output: "AssertionError: expected 2 got 1" }] }; } };
  const out = await validate("r", runner);
  assert.equal(out.testsPassed, false);
  assert.deepEqual(out.failures, ["t2"]);
  assert.match(out.detail, /AssertionError/);
});

test("INVARIANT: a runner error fails closed", async () => {
  const runner: TestRunner = { async run() { return { results: [], runnerError: "SyntaxError: unexpected token" }; } };
  const out = await validate("r", runner);
  assert.equal(out.testsPassed, false);
  assert.match(out.detail, /runner error/);
});

test("INVARIANT: the vetting gate can block a test-passing patch", async () => {
  const runner: TestRunner = { async run() { return { results: [{ name: "t1", passed: true }] }; } };
  const out = await validate("r", runner, { vet: async () => false });
  assert.equal(out.testsPassed, true);
  assert.equal(out.vettingCleared, false, "vetting override blocks acceptance even when tests pass");
});

// ── repair_loop ────────────────────────────────────────────────────────────

test("INVARIANT: repair loop fixes a first-failed case in one round", async () => {
  const spine = newSpine();
  const tree = new InMemoryFileTree({ "src/a.ts": "return 1;" });
  // Test passes only when the file says "return 2;".
  let testRuns = 0;
  const runner = new ScriptedRunner(tree, (c) => { testRuns++; return { results: [{ name: "t", passed: c.includes("return 2;"), ...(c.includes("return 2;") ? {} : { output: "expected 2" }) }] }; });
  const ledger = newLedger(spine);

  const fixPlan: EditPlan = { edits: [{ file: "src/a.ts", search: "return 1;", replace: "return 2;", intent: "fix" }], rationale: "fix" };
  const observedFailure = await validate("r", runner);
  const r = await repairLoop("i1", "r", observedFailure, 0, {
    tree, runner, ledger, spine,
    replan: async feedback => {
      assert.equal(feedback, observedFailure.detail, "repair consumes the retained structured observation");
      assert.match(feedback, /t: expected 2/u);
      assert.equal(testRuns, 1, "do not rerun unchanged tests merely to acquire feedback again");
      return fixPlan;
    },
  });
  assert.equal(r.solved, true);
  assert.equal(r.rounds, 1);
  assert.equal(await tree.read("src/a.ts"), "return 2;");
  assert.equal(testRuns, 2, "one initial observation and one verification of changed bytes");
});

test("INVARIANT: repair loop stops at maxRounds with a reason", async () => {
  const spine = newSpine();
  const tree = new InMemoryFileTree({ "src/a.ts": "x0" });
  let n = 0;
  const runner = new ScriptedRunner(tree, () => ({ results: [{ name: "t", passed: false, output: "still failing" }] }));
  const ledger = newLedger(spine);
  // Each replan makes a real but ineffective edit (so it applies but never fixes).
  const r = await repairLoop("i2", "r", { testsPassed: false, failures: ["t"], vettingCleared: false, detail: "fail" }, 0, {
    tree, runner, ledger, spine,
    replan: async (_fb, round) => ({ edits: [{ file: "src/a.ts", search: `x${round - 1}`, replace: `x${round}`, intent: "try" }], rationale: "try" }),
  }, { maxRounds: 2 });
  n = r.rounds;
  assert.equal(r.solved, false);
  assert.equal(n, 2, "ran exactly maxRounds");
  assert.match(r.gaveUpReason ?? "", /max repair rounds/);
});

test("INVARIANT: repair loop respects the spend budget", async () => {
  const spine = newSpine();
  const tree = new InMemoryFileTree({ "src/a.ts": "x" });
  const runner = new ScriptedRunner(tree, () => ({ results: [{ name: "t", passed: false }] }));
  const ledger = newLedger(spine);
  const r = await repairLoop("i3", "r", { testsPassed: false, failures: ["t"], vettingCleared: false, detail: "f" }, 0, {
    tree, runner, ledger, spine,
    replan: async () => ({ edits: [{ file: "src/a.ts", search: "x", replace: "y", intent: "t" }], rationale: "t" }),
    withinBudget: () => false, // budget already exhausted
  });
  assert.equal(r.solved, false);
  assert.match(r.gaveUpReason ?? "", /budget/);
});

test("INVARIANT: RegressionGuard trips + rolls back when a repair round breaks previously-passing tests", async () => {
  const spine = newSpine();
  const tree = new InMemoryFileTree({ "src/a.ts": "good" });
  // 3 tests. Content "good" → 2 pass. A repair to "bad" → 0 pass (a collapse from the peak).
  const runner = new ScriptedRunner(tree, (c) => {
    const ok = c.includes("good");
    return { results: [
      { name: "t1", passed: ok },
      { name: "t2", passed: ok },
      { name: "t3", passed: false, output: "the actual bug" }, // never passes → loop keeps trying
    ] };
  });
  const ledger = newLedger(spine);
  // First validation: 2/3 pass (peak=2). The repair makes it WORSE (breaks t1,t2 → 0 pass).
  const r = await repairLoop("i4", "r", { testsPassed: false, failures: ["t3"], vettingCleared: false, detail: "f" }, 2, {
    tree, runner, ledger, spine,
    replan: async () => ({ edits: [{ file: "src/a.ts", search: "good", replace: "bad", intent: "regress" }], rationale: "oops" }),
  }, { maxRounds: 3 });
  assert.equal(r.regressionTripped, true, "guard caught the rise-then-collapse");
  assert.match(r.gaveUpReason ?? "", /regression guard/);
  assert.equal(await tree.read("src/a.ts"), "good", "the regressing round was rolled back");
});
