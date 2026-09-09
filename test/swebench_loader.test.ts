import { test } from "node:test";
import assert from "node:assert/strict";

import { loadSwebenchTasks, parseRecord, type SwebenchRecord } from "../src/eval/swebench_loader.js";
import { judgeResolution } from "../src/eval/swebench_task.js";

function record(over: Partial<SwebenchRecord> = {}): SwebenchRecord {
  return {
    instance_id: "django__django-12345",
    repo: "django/django",
    base_commit: "abc123",
    problem_statement: "Fix the widget rendering bug.",
    patch: "--- a/x.py\n+++ b/x.py\n@@\n-old\n+new implementation line here\n",
    test_patch: "--- a/test_x.py\n+++ b/test_x.py\n@@\n+def test_widget(): ...\n",
    FAIL_TO_PASS: JSON.stringify(["tests/test_x.py::test_widget"]),
    PASS_TO_PASS: JSON.stringify(["tests/test_x.py::test_existing"]),
    created_at: "2024-01-01T00:00:00Z",
    version: "5.0",
    ...over,
  };
}

test("LOADER: a well-formed record maps into an EvalTask whose fail/pass tests match (JSON-string arrays parsed)", () => {
  const r = loadSwebenchTasks([record()]);
  assert.equal(r.tasks.length, 1);
  const t = r.tasks[0]!;
  assert.equal(t.instanceId, "django__django-12345");
  assert.equal(t.repo, "django/django");
  assert.equal(t.baseCommit, "abc123");
  assert.deepEqual(t.failToPass, ["tests/test_x.py::test_widget"], "FAIL_TO_PASS → failToPass");
  assert.deepEqual(t.passToPass, ["tests/test_x.py::test_existing"], "PASS_TO_PASS → passToPass");
  assert.equal(t.goldPatch, record().patch, "patch → goldPatch (provenance)");
});

test("LOADER: also accepts FAIL_TO_PASS/PASS_TO_PASS as real arrays (not just JSON strings)", () => {
  const r = loadSwebenchTasks([record({ FAIL_TO_PASS: ["a::b"], PASS_TO_PASS: ["c::d"] })]);
  assert.deepEqual(r.tasks[0]!.failToPass, ["a::b"]);
});

test("LOADER: a malformed record is REJECTED, not coerced", () => {
  const noFtp = loadSwebenchTasks([record({ FAIL_TO_PASS: "not-json[" })]);
  assert.equal(noFtp.tasks.length, 0, "no admitted task");
  assert.equal(noFtp.malformed.length, 1, "the bad record is rejected with a reason");
  assert.match(noFtp.malformed[0]!.reason, /FAIL_TO_PASS/);
  // a record missing base_commit is also rejected, not silently defaulted
  const noCommit = parseRecord(record({ base_commit: undefined }));
  assert.ok("reason" in noCommit && /base_commit/.test(noCommit.reason));
});

test("LOADER: a leakage-failing task is EXCLUDED by the existing decontamination policy", () => {
  // The gold patch's added line appears verbatim in the problem statement → high leakage overlap → excluded.
  const leaky = record({
    patch: "--- a/x.py\n+++ b/x.py\n@@\n+return compute_the_special_total(items)\n",
    problem_statement: "The fix is: return compute_the_special_total(items) in the handler.",
  });
  const r = loadSwebenchTasks([leaky], { maxLeakageOverlap: 0.5 });
  assert.equal(r.tasks.length, 0, "the leaked task is not admitted");
  assert.ok(r.decontamination.rejected.length >= 1, "it's recorded as a decontamination rejection");
});

test("LOADER: a loaded task round-trips through the REAL judgeResolution", () => {
  const t = loadSwebenchTasks([record()]).tasks[0]!;
  // The oracle resolves ONLY when the fail-to-pass test passes and no pass-to-pass regresses.
  const resolved = judgeResolution(t, { passed: { "tests/test_x.py::test_widget": true, "tests/test_x.py::test_existing": true } });
  assert.equal(resolved.resolved, true, "correct fix + no regression → resolved");
  const unresolved = judgeResolution(t, { passed: { "tests/test_x.py::test_widget": false, "tests/test_x.py::test_existing": true } });
  assert.equal(unresolved.resolved, false, "fail-to-pass not cleared → not resolved");
});

test("LOADER: the result carries the honest 'loading is not running' caveat", () => {
  const r = loadSwebenchTasks([record()]);
  assert.ok(r.caveats.some((c) => /real ModelProvider|not a benchmark result/i.test(c)), "loading ≠ a benchmark number");
});
