import test from "node:test";
import assert from "node:assert/strict";
import { appraisePostMergeRun } from "../src/pipeline/keep_pipeline.js";

test("post-merge verification accepts only a completed nonempty all-green run", () => {
  assert.deepEqual(appraisePostMergeRun({ results: [{ name: "installed", passed: true }] }), { regressed: false });
});

test("post-merge runner refusal is adverse and cannot be laundered into verified-clean", () => {
  assert.deepEqual(
    appraisePostMergeRun({ results: [], runnerError: "microVM UID allocator is held" }),
    { regressed: true, detail: "microVM UID allocator is held" },
  );
});

test("post-merge empty result without an error is adverse", () => {
  assert.deepEqual(
    appraisePostMergeRun({ results: [] }),
    { regressed: true, detail: "post-merge verifier returned no test results" },
  );
});

test("post-merge failed cases are adverse and named", () => {
  assert.deepEqual(
    appraisePostMergeRun({ results: [{ name: "a", passed: false }, { name: "b", passed: true }, { name: "c", passed: false }] }),
    { regressed: true, detail: "a, c" },
  );
});
