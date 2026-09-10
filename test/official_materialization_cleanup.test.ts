import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync, renameSync, symlinkSync, lstatSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { materializeOfficialTask, runOfficialTaskLocally } from "../src/eval/official_swebench.js";
import type { EvalTask } from "../src/eval/swebench_task.js";

// Builder-discovered preservation regression, not an original audit finding ID.
function fixture(instanceId = "ordinary-task") {
  const root = mkdtempSync(join(tmpdir(), "keep-official-cleanup-"));
  const source = join(root, "source"), workspace = join(root, "workspace");
  mkdirSync(source); mkdirSync(workspace);
  const git = (...args: string[]) => execFileSync("git", args, { cwd: source, encoding: "utf8", timeout: 5000 }).trim();
  git("init", "-q", "-b", "main"); git("config", "user.name", "Keep Test"); git("config", "user.email", "keep@test.invalid");
  writeFileSync(join(source, "base.txt"), "synthetic source"); git("add", "."); git("commit", "-qm", "base");
  const task: EvalTask = { instanceId, repo: "synthetic/project", baseCommit: git("rev-parse", "HEAD"),
    problemStatement: "synthetic", failToPass: [], passToPass: [], testPatch: "hidden synthetic check" };
  return { root, source, workspace, task, target: join(workspace, instanceId) };
}

for (const kind of ["nonempty directory", "empty directory", "file", "symlink"] as const) {
  test(`official materialization refuses a preexisting ${kind} without removing it`, async () => {
    const f = fixture();
    if (kind === "file") writeFileSync(f.target, "prior file");
    else if (kind === "symlink") symlinkSync(f.source, f.target, "dir");
    else {
      mkdirSync(f.target);
      if (kind === "nonempty directory") writeFileSync(join(f.target, "prior.txt"), "retained");
    }
    const before = lstatSync(f.target, { bigint: true });
    await assert.rejects(() => materializeOfficialTask(f.task, f.source, f.workspace));
    const after = lstatSync(f.target, { bigint: true });
    assert.equal(after.ino, before.ino); assert.equal(after.dev, before.dev);
    if (kind === "file") assert.equal(readFileSync(f.target, "utf8"), "prior file");
    if (kind === "nonempty directory") assert.equal(readFileSync(join(f.target, "prior.txt"), "utf8"), "retained");
    if (kind === "empty directory") assert.deepEqual(readdirSync(f.target), []);
    assert.equal(readFileSync(join(f.source, "base.txt"), "utf8"), "synthetic source");
  });
}

test("official materialization owns only its newly created failed-checkout destination", async () => {
  const f = fixture("..failed-task");
  const unrelated = join(f.workspace, "unrelated"); mkdirSync(unrelated);
  writeFileSync(join(unrelated, "prior.txt"), "retained");
  await assert.rejects(() => materializeOfficialTask({ ...f.task, baseCommit: "0".repeat(40) }, f.source, f.workspace));
  assert.equal(existsSync(f.target), false);
  assert.equal(readFileSync(join(unrelated, "prior.txt"), "utf8"), "retained");
});

test("official materialization concurrent same-name attempts retain the successful workspace", async () => {
  const f = fixture();
  const results = await Promise.allSettled([
    materializeOfficialTask(f.task, f.source, f.workspace),
    materializeOfficialTask(f.task, f.source, f.workspace),
  ]);
  const accepted = results.filter(r => r.status === "fulfilled");
  assert.equal(accepted.length, 1);
  assert.equal(results.filter(r => r.status === "rejected").length, 1);
  assert.equal(readFileSync(join(accepted[0]!.value.projectDir, "base.txt"), "utf8"), "synthetic source");
  await accepted[0]!.value.cleanup();
});

for (const replacement of ["directory", "symlink"] as const) {
  test(`official cleanup refuses a substituted ${replacement} and preserves both directory identities`, async () => {
    const f = fixture();
    const out = await materializeOfficialTask(f.task, f.source, f.workspace);
    const moved = join(f.workspace, "retained-original"); renameSync(out.projectDir, moved);
    if (replacement === "directory") {
      mkdirSync(out.projectDir); writeFileSync(join(out.projectDir, "prior.txt"), "replacement");
    } else symlinkSync(f.source, out.projectDir, "dir");
    const firstCleanup = out.cleanup();
    await assert.rejects(() => firstCleanup, /identity|changed|replaced/);
    assert.equal(out.cleanup(), firstCleanup, "refusal is sticky, not an automatic retry");
    await assert.rejects(() => out.cleanup(), /identity|changed|replaced/);
    assert.equal(readFileSync(join(moved, "base.txt"), "utf8"), "synthetic source");
    if (replacement === "directory") assert.equal(readFileSync(join(out.projectDir, "prior.txt"), "utf8"), "replacement");
    else assert.equal(lstatSync(out.projectDir).isSymbolicLink(), true);
    assert.equal(readFileSync(join(f.source, "base.txt"), "utf8"), "synthetic source");
  });
}

test("official cleanup is one-shot: a later directory at the same name is not removed", async () => {
  const f = fixture();
  const out = await materializeOfficialTask(f.task, f.source, f.workspace);
  await Promise.all([out.cleanup(), out.cleanup()]);
  assert.equal(existsSync(out.projectDir), false);
  mkdirSync(out.projectDir); writeFileSync(join(out.projectDir, "later.txt"), "new work");
  await out.cleanup();
  assert.equal(readFileSync(join(out.projectDir, "later.txt"), "utf8"), "new work");
});

test("official task preserves primary judge error when cleanup also refuses", async () => {
  const f = fixture();
  const primary = new Error("synthetic judge failed");
  const task = { ...f.task, testPatch: "diff --git a/check.txt b/check.txt\nnew file mode 100644\n--- /dev/null\n+++ b/check.txt\n@@ -0,0 +1 @@\n+synthetic\n" };
  await assert.rejects(() => runOfficialTaskLocally({ task, mirrorDir: f.source, workspaceBase: f.workspace,
    solve: async () => ({ synthetic: true }),
    judge: async (_task, projectDir) => {
      assert.equal(readFileSync(join(projectDir, "check.txt"), "utf8"), "synthetic\n");
      renameSync(projectDir, join(f.workspace, "retained-original"));
      mkdirSync(projectDir); writeFileSync(join(projectDir, "prior.txt"), "retained replacement");
      throw primary;
    },
  }), (error: unknown) => {
    assert.ok(error instanceof AggregateError);
    assert.equal(error.errors.length, 2); assert.equal(error.errors[0], primary);
    assert.match(String(error.errors[1]), /identity changed/);
    return true;
  });
  assert.equal(readFileSync(join(f.target, "prior.txt"), "utf8"), "retained replacement");
});

test("official sanitized-name collision refuses without disturbing the first task", async () => {
  const f = fixture();
  const first = await materializeOfficialTask({ ...f.task, instanceId: "a/b" }, f.source, f.workspace);
  await assert.rejects(() => materializeOfficialTask({ ...f.task, instanceId: "a_b" }, f.source, f.workspace), /already exists/);
  assert.equal(readFileSync(join(first.projectDir, "base.txt"), "utf8"), "synthetic source");
  await first.cleanup();
});
