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
import { type TestRunner, type TestRunResult } from "../src/solve/validate.js";
import { repairLoop } from "../src/solve/repair_loop.js";
import type { EditPlan } from "../src/solve/issue_model.js";

function newSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-adapt-rl-"))), new InProcessLock(), new SchemaRegistry());
}
const fail: TestRunResult = { results: [{ name: "t", passed: false, output: "boom" }] };
const pass: TestRunResult = { results: [{ name: "t", passed: true }] };

test("ADAPT PRE-TIER: a transient failure is re-run WITHOUT an LLM replan and clears", async () => {
  const spine = newSpine();
  const tree = new InMemoryFileTree({ "src/a.ts": "x" });
  let runs = 0;
  // First run fails (transient), the deterministic re-run passes.
  const runner: TestRunner = { async run() { runs++; return runs >= 2 ? pass : fail; } };
  let replanCalled = false;
  const r = await repairLoop("i1", "r", { testsPassed: false, failures: ["t"], vettingCleared: false, detail: "f" }, 0, {
    tree, runner, ledger: new RollbackLedger(spine), spine,
    replan: async () => { replanCalled = true; return { edits: [], rationale: "x" } as EditPlan; },
    classifyFailure: () => "transient",
  });
  assert.equal(replanCalled, false, "a transient failure must NOT call the LLM replan");
  assert.equal(r.solved, true, "the deterministic re-run cleared it");
});

test("ADAPT PRE-TIER: a non-local failure escalates to the LLM replan", async () => {
  const spine = newSpine();
  const tree = new InMemoryFileTree({ "src/a.ts": "x0" });
  const runner: TestRunner = { async run() { const c = await tree.read("src/a.ts"); return c === "x1" ? pass : fail; } };
  let replanCalled = false;
  const r = await repairLoop("i2", "r", { testsPassed: false, failures: ["t"], vettingCleared: false, detail: "f" }, 0, {
    tree, runner, ledger: new RollbackLedger(spine), spine,
    replan: async () => { replanCalled = true; return { edits: [{ file: "src/a.ts", search: "x0", replace: "x1", intent: "fix" }], rationale: "fix" }; },
    classifyFailure: () => "non-local",
  });
  assert.equal(replanCalled, true, "a non-local failure escalates to the replan");
  assert.equal(r.solved, true);
});

test("ADAPT PRE-TIER: an unchanged transient enters diagnosis instead of speculative code editing", async () => {
  const spine = newSpine();
  const tree = new InMemoryFileTree({ "src/a.ts": "x" });
  const runner: TestRunner = { async run() { return fail; } }; // never clears
  let replanCalls = 0;
  const r = await repairLoop("i3", "r", { testsPassed: false, failures: ["t"], vettingCleared: false, detail: "f" }, 0, {
    tree, runner, ledger: new RollbackLedger(spine), spine,
    replan: async () => { replanCalls++; return { edits: [], rationale: "x" } as EditPlan; },
    classifyFailure: () => "transient",
  }, { maxRounds: 6 });
  assert.equal(replanCalls, 0, "no evidence that a code edit can repair this transient");
  assert.equal(r.rounds, 2, "two unproductive attempts trigger diagnosis, not six reruns");
  assert.match(r.gaveUpReason!, /diagnosis required/);
});
