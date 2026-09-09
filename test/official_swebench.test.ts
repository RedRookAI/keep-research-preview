import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { executePrivateRunMilestone, materializeOfficialTask, officialRunPrerequisites, runOfficialTaskLocally } from "../src/eval/official_swebench.js";
import type { EvalTask } from "../src/eval/swebench_task.js";

test("EVAL-02 materializes the exact public base, then applies hidden tests only after solve", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-r6-")); const repo = join(root, "mirror"); mkdirSync(repo);
  execFileSync("git", ["init", "-q"], { cwd: repo }); execFileSync("git", ["config", "user.email", "test@keep.local"], { cwd: repo }); execFileSync("git", ["config", "user.name", "Keep Test"], { cwd: repo });
  writeFileSync(join(repo, "app.py"), "BUG = True\n"); execFileSync("git", ["add", "."], { cwd: repo }); execFileSync("git", ["commit", "-qm", "base"], { cwd: repo });
  const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();
  const task: EvalTask = { instanceId: "org__repo-1", repo: "org/repo", baseCommit: commit, problemStatement: "fix bug", failToPass: ["test_bug"], passToPass: [], goldPatch: "do not apply", testPatch: "diff --git a/test_bug.py b/test_bug.py\nnew file mode 100644\nindex 0000000..a5dc8cc\n--- /dev/null\n+++ b/test_bug.py\n@@ -0,0 +1 @@\n+assert True\n" };
  const out = await materializeOfficialTask(task, repo, join(root, "work"));
  assert.equal(readFileSync(join(out.projectDir, "app.py"), "utf8"), "BUG = True\n");
  assert.equal(existsSync(join(out.projectDir, "test_bug.py")), false, "plain materialization contains no hidden test");
  assert.equal("testPatch" in out.task, false); assert.equal("goldPatch" in out.task, false);
  await out.cleanup();

  const order: string[] = [];
  const result = await runOfficialTaskLocally({
    task, mirrorDir: repo, workspaceBase: join(root, "run"),
    solve: async (visible, projectDir) => {
      order.push("solve");
      assert.equal("testPatch" in visible, false); assert.equal("goldPatch" in visible, false);
      assert.equal(Object.isFrozen(visible.failToPass), true, "nested public task data cannot be mutated during solve");
      assert.equal(existsSync(join(projectDir, "test_bug.py")), false, "hidden test is absent for the entire solve callback");
      writeFileSync(join(projectDir, "app.py"), "BUG = False\n");
      return { patch: "candidate", nested: { frozen: true } };
    },
    judge: async (_fullTask, projectDir, solution) => {
      order.push("judge");
      assert.equal(readFileSync(join(projectDir, "test_bug.py"), "utf8"), "assert True\n");
      assert.equal(Object.isFrozen(solution), true, "the solve result is frozen before hidden judging");
      assert.equal(Object.isFrozen(solution.nested), true, "nested solution evidence is frozen too");
      return "judged";
    },
  });
  assert.deepEqual(order, ["solve", "judge"]); assert.equal(result.judgment, "judged");
});

test("R6 refuses to invent a score when run resources are absent", () => {
  assert.deepEqual(officialRunPrerequisites({ containerRuntime: false, containerImage: false, remoteProvider: false }), { ready: false, missing: ["responding container runtime", "local SWE-bench image", "configured real provider"] });
  assert.equal(officialRunPrerequisites({ containerRuntime: true, containerImage: true, remoteProvider: true }).ready, true);
});

test("EVAL-03: unavailable resources produce a null-score refusal and never invoke a provider", async () => {
  let called = false;
  const result = await executePrivateRunMilestone({
    prerequisites: officialRunPrerequisites({ containerRuntime: true, containerImage: false, remoteProvider: false }),
    run: async () => { called = true; throw new Error("must not run"); },
  });
  assert.equal(called, false); assert.deepEqual(result, { status: "unavailable", missing: ["local SWE-bench image", "configured real provider"], score: null });
});

test("EVAL-03: a ready private run must durably retain only allowlisted sanitized diagnostics", async () => {
  const retained: unknown[] = [];
  const raw = { runDate: "2026-08-26", taskId: "private-1", providerClass: "openai-compatible", model: "private-model", promptTokens: 10, completionTokens: 20, costUsd: 0.01, resolved: true, apiKey: "must-not-survive", prompt: "private source" };
  const result = await executePrivateRunMilestone({
    prerequisites: officialRunPrerequisites({ containerRuntime: true, containerImage: true, remoteProvider: true }),
    run: async () => raw,
    diagnosticsSink: { write: async (record) => { retained.push(record); } },
  });
  assert.equal(result.status, "completed"); assert.equal(retained.length, 1);
  const serialized = JSON.stringify(retained[0]); assert.doesNotMatch(serialized, /apiKey|must-not-survive|private source|"prompt":/);
  assert.deepEqual(Object.keys(retained[0] as object).sort(), ["completionTokens", "costUsd", "model", "promptTokens", "providerClass", "resolved", "runDate", "taskId"]);
  await assert.rejects(executePrivateRunMilestone({ prerequisites: { ready: true, missing: [] }, run: async () => raw }), /durable diagnostics sink/);
});
