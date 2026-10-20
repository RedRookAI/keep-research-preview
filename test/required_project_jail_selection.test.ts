import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { captureRuntimeContract, RuntimeConfigError } from "../src/cli/runtime_config.js";
import { inspectInstalledReadiness, renderDoctorReport } from "../src/cli/doctor.js";
import { inspectRequiredJailLauncher } from "../src/infra/required_project_jail.js";
import { ProcessIsolationAdapter } from "../src/infra/process_isolation.js";
import { SandboxedCommandRunner, sandboxedRunnerFor } from "../src/solve/sandboxed_runner.js";
import type { NamespaceJailSpec } from "../src/infra/isolation_backend.js";

const revision = "a".repeat(40);
const context = { cwd: "/", realpath: (p: string) => p, isDirectory: () => true, repositoryRoot: () => "/source",
  resolveCommit: () => revision, validateBranch: (_repo: string, branch: string) => branch, resolveBranchCommit: () => revision };
const base = { KEEP_PROVIDER: "local", KEEP_REPOSITORY: "/source", KEEP_WORKSPACE_BASE: "/workspaces", KEEP_REVISION: revision,
  KEEP_REPO_REF: "sample", KEEP_TEST_COMMAND: process.execPath, KEEP_TEST_NAMESPACE_JAIL: "required" };

test("owner jail selection is captured explicitly and refuses relative or ineffective configuration", () => {
  const capture = (env: Record<string, string>) => captureRuntimeContract(env, context, { projectRequired: true });
  assert.equal(capture({ ...base, KEEP_TEST_JAIL_EXECUTABLE: "/owned/bwrap" }).installedProject!.testCommand.jailExecutable, "/owned/bwrap");
  assert.equal(capture(base).installedProject!.testCommand.jailExecutable, undefined);
  for (const value of ["relative/bwrap", "", "/bad\0path"])
    assert.throws(() => capture({ ...base, KEEP_TEST_JAIL_EXECUTABLE: value }), (e: unknown) => e instanceof RuntimeConfigError && e.field === "KEEP_TEST_JAIL_EXECUTABLE");
  for (const mode of ["off", "best-effort"])
    assert.throws(() => capture({ ...base, KEEP_TEST_NAMESPACE_JAIL: mode, KEEP_TEST_JAIL_EXECUTABLE: "/owned/bwrap" }), /KEEP_TEST_JAIL_EXECUTABLE/u);
});

test("doctor separates trusted-helper presence from namespace enforcement and redacts refused paths", () => {
  const options = { context, packageRoot: "/package", stdinIsTTY: true, measurePackage: () => "b".repeat(64) };
  let observed: string | undefined;
  const ready = inspectInstalledReadiness({ ...base, KEEP_TEST_JAIL_EXECUTABLE: "/owned/bwrap" }, {
    ...options, inspectJailLauncher: path => { observed = path; } });
  assert.equal(observed, "/owned/bwrap");
  assert.equal(ready.ready, true, renderDoctorReport(ready));
  assert.match(renderDoctorReport(ready), /namespace setup has not been exercised/u);
  const missing = inspectInstalledReadiness({ ...base, KEEP_TEST_JAIL_EXECUTABLE: "/MISSING-PRIVATE-HELPER/bwrap" }, options);
  assert.equal(missing.ready, false);
  assert.equal(missing.checks.find(c => c.name === "required-jail-launcher")?.status, "missing-input");
  assert.match(renderDoctorReport(missing), /KEEP_TEST_JAIL_EXECUTABLE/u);
  assert.equal(renderDoctorReport(missing).includes("MISSING-PRIVATE-HELPER"), false);
});

test("selected launcher still requires exact bytes and protected executable permissions", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-jail-selection-")), helper = join(root, "bwrap");
  try {
    writeFileSync(helper, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    assert.throws(() => inspectRequiredJailLauncher(helper), /identity mismatch|untrusted/u);
    chmodSync(helper, 0o777);
    assert.throws(() => inspectRequiredJailLauncher(helper), /untrusted/u);
    const fifo = join(root, "not-an-executable");
    execFileSync("/usr/bin/mkfifo", [fifo]);
    assert.throws(() => inspectRequiredJailLauncher(fifo), /untrusted/u);
    assert.throws(() => inspectRequiredJailLauncher("relative"), /absolute/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("direct and factory runners carry the selected helper and refuse its absence before task entry", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-jail-selection-")), project = join(root, "project");
  mkdirSync(project);
  const helper = join(root, "missing-bwrap"), marker = join(project, "entered"), adapter = new ProcessIsolationAdapter();
  let observed: NamespaceJailSpec | undefined;
  const original = adapter.run.bind(adapter);
  adapter.run = async (command, args, policy) => { observed = policy.namespaceJail; return original(command, args, policy); };
  const args = ["-e", `require('node:fs').writeFileSync(${JSON.stringify(marker)},'wrong')`];
  try {
    const runners = [new SandboxedCommandRunner({ command: process.execPath, args, projectDir: project, namespaceJail: "required", jailExecutable: helper, adapter }),
      sandboxedRunnerFor(() => project, process.execPath, args, { namespaceJail: "required", jailExecutable: helper, adapter })("sample")];
    for (const runner of runners) {
      const result = await runner.run(".");
      assert.equal(observed?.jailExecutable, helper);
      assert.equal(result.processCompletion, "not-started");
      assert.equal(existsSync(marker), false);
    }
    const ineffective = await adapter.run(process.execPath, args, { cwd: project, timeoutMs: 1000, namespaceJail: { projectDir: project, jailExecutable: helper } });
    assert.equal(ineffective.completion, "not-started");
    assert.match(ineffective.stderr, /requires the required/u);
    assert.equal(existsSync(marker), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
