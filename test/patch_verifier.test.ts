import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyPatch } from "../src/pipeline/patch_verifier.js";
import type { SolveResult, SearchReplaceEdit } from "../src/solve/issue_model.js";

function solveWith(edits: SearchReplaceEdit[], testsPassed = true): SolveResult {
  return {
    issueId: "x", solved: true, stagesRun: ["done"], repairRounds: 0,
    validation: { testsPassed, failures: testsPassed ? [] : ["t"], vettingCleared: true, detail: "" },
    prProposal: { title: "t", body: "b", branch: "keep/solve/x", edits, testsPassed },
  };
}

test("INVARIANT: a clean minimal fix passes all checks", () => {
  const v = verifyPatch({ solveResult: solveWith([{ file: "src/calc.ts", search: "return a - b;", replace: "return a + b;", intent: "fix" }]) });
  assert.equal(v.outcome, "pass");
  assert.equal(v.cleared, true);
});

test("INVARIANT: a patch modifying TEST files → sound fail (oracle-gaming / self-confirmation)", () => {
  const v = verifyPatch({ solveResult: solveWith([
    { file: "src/calc.ts", search: "return a - b;", replace: "return a + b;", intent: "fix" },
    { file: "test/calc.test.ts", search: "expect(5)", replace: "expect(1)", intent: "loosen test" },
  ]) });
  assert.equal(v.outcome, "fail");
  assert.equal(v.cleared, false);
  assert.ok(v.checks.some((c) => c.name === "no-test-file-modification" && c.decision === "fail"));
});

test("INVARIANT: a patch introducing a SECRET token → sound fail", () => {
  const v = verifyPatch({ solveResult: solveWith([
    { file: "src/config.ts", search: "const x = 1;", replace: "const apiKey = 'sk-live-abc'; const password = 'hunter2';", intent: "add config" },
  ]) });
  assert.equal(v.outcome, "fail");
  assert.ok(v.checks.some((c) => c.name === "no-secrets-introduced" && c.decision === "fail"));
});

test("INVARIANT: a patch copying the ISSUE TEXT verbatim → sound fail (solution-leakage inflation)", () => {
  const leaked = "the function should return the sum of a and b not the difference between them okay";
  const v = verifyPatch({
    solveResult: solveWith([{ file: "src/calc.ts", search: "return a - b;", replace: leaked, intent: "x" }]),
    issueText: `Bug: ${leaked} please fix it`,
  });
  assert.equal(v.outcome, "fail");
  assert.ok(v.checks.some((c) => c.name === "no-solution-leakage" && c.decision === "fail"));
});

test("INVARIANT: no-op / malformed edits → sound fail", () => {
  const v = verifyPatch({ solveResult: solveWith([{ file: "src/x.ts", search: "same", replace: "same", intent: "noop" }]) });
  assert.equal(v.outcome, "fail");
  assert.ok(v.checks.some((c) => c.name === "edits-well-formed" && c.decision === "fail"));
});

test("INVARIANT: tests-not-passing → sound fail", () => {
  const v = verifyPatch({ solveResult: solveWith([{ file: "src/x.ts", search: "a", replace: "b", intent: "x" }], false) });
  assert.equal(v.outcome, "fail");
  assert.ok(v.checks.some((c) => c.name === "tests-pass" && c.decision === "fail"));
});

test("INVARIANT: an added early-return alongside a fix → heuristic flag → escalate-human (#1 semantic-failure pattern)", () => {
  const v = verifyPatch({ solveResult: solveWith([
    { file: "src/proc.ts", search: "if (x == null) { log(x); }", replace: "if (x == null) { log(x); return; }", intent: "null guard" },
  ]) });
  assert.equal(v.outcome, "escalate-human");
  assert.equal(v.cleared, false);
  assert.ok(v.checks.some((c) => c.name === "no-unintended-control-flow" && c.decision === "flag"));
});

test("INVARIANT: too many edits → scope-creep flag → escalate-human", () => {
  const many: SearchReplaceEdit[] = Array.from({ length: 15 }, (_, i) => ({ file: `src/f${i}.ts`, search: `a${i}`, replace: `b${i}`, intent: "x" }));
  const v = verifyPatch({ solveResult: solveWith(many) });
  assert.equal(v.outcome, "escalate-human");
  assert.ok(v.checks.some((c) => c.name === "scope-bounded" && c.decision === "flag"));
});

test("the verdict carries the full auditable check trail", () => {
  const v = verifyPatch({ solveResult: solveWith([{ file: "src/calc.ts", search: "a - b", replace: "a + b", intent: "fix" }]) });
  const names = v.checks.map((c) => c.name);
  assert.ok(names.includes("no-test-file-modification"));
  assert.ok(names.includes("no-secrets-introduced"));
  assert.ok(names.includes("no-unintended-control-flow"));
  assert.ok(names.includes("scope-bounded"));
});

test("RED-TEAM REGRESSION: test-infrastructure files (conftest.py, jest.config) can't dodge the test-mod check", () => {
  for (const f of ["conftest.py", "pytest.ini", "jest.config.js", "tox.ini"]) {
    const v = verifyPatch({ solveResult: solveWith([{ file: f, search: "a", replace: "b", intent: "i" }]) });
    assert.equal(v.outcome, "fail", `${f} must be treated as a test file (oracle-gaming)`);
  }
  // a normal source file still passes
  assert.equal(verifyPatch({ solveResult: solveWith([{ file: "src/calc.ts", search: "a", replace: "b", intent: "i" }]) }).outcome, "pass");
});
