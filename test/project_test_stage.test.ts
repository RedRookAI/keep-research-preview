import { mkdirSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";

import { buildProjectTester, type ProjectTestConfig } from "../src/autonomy/project_test_stage.js";
import { projectRepositoryTreeSha256 } from "../src/autonomy/project_localization.js";
import type { ProjectState } from "../src/autonomy/project_state.js";
import { IsolatedTestRunner, MinimumTierExecutor, ProcessIsolationExecutor, type IsolatedExecutor } from "../src/isolation/isolated_executor.js";
import { SandboxedCommandRunner } from "../src/solve/sandboxed_runner.js";
import type { Issue, SolveResult } from "../src/solve/issue_model.js";
import { LocalFsWorkspace } from "../src/solve/workspace.js";
import { computeMicrovmProjectSourceManifestSha256 } from "../src/infra/microvm_boundary.js";

const issue: Issue = { id: "ISSUE-TEST", text: "exercise independent tests", repoRef: "repo", hints: { projectTaskId: "task-01", planStepId: "step-01" } };
const task = { id: "task-01", planStepId: "step-01", objective: issue.text, dependsOn: [], completionCriteria: [{ id: "criterion", statement: "tests pass", evidence: "isolated test artifact" }] };

async function fixture() {
  const root = mkdtempSync(join(tmpdir(), "keep-project-test-fixture-"));
  const canonicalRoot = join(root, "canonical");
  const executionRoot = join(root, "execution");
  for (const base of [canonicalRoot, executionRoot]) {
    mkdirSync(join(base, "repo", "src"), { recursive: true });
    writeFileSync(join(base, "repo", "src", "value.ts"), "export const value = 2;\n");
  }
  const canonical = new LocalFsWorkspace(canonicalRoot);
  const execution = new LocalFsWorkspace(executionRoot);
  const treeDigest = projectRepositoryTreeSha256(await canonical.files("repo"));
  const executionManifest = await computeMicrovmProjectSourceManifestSha256(canonical.dir("repo"));
  const solve: SolveResult = {
    issueId: issue.id, solved: true, stagesRun: ["apply", "validate", "done"], repairRounds: 0,
    validation: { testsPassed: true, vettingCleared: true, failures: [], detail: "canonical validation passed" },
    projectEditReceipt: { schemaVersion: 1, admissionSha256: "a".repeat(64), repositoryTreeAfterSha256: treeDigest,
      touchedFiles: [{ path: "src/value.ts", beforeSha256: "b".repeat(64), afterSha256: "c".repeat(64) }],
      rollbackIds: ["rollback-1"], applied: true, testsExecuted: true },
  };
  const implementation = { schemaVersion: 1 as const, task, issue, solve, repositoryTreeAfterSha256: treeDigest, repositoryExecutionManifestSha256: executionManifest };
  const state: ProjectState = {
    schemaVersion: 1, revision: 0, runId: "run", goal: issue.text, stage: "vet_artifact", posture: "autonomous",
    artifacts: { implement: implementation }, stepsRemaining: 2, reworkCount: 0, status: "running",
    retry: { attemptsByStage: {}, attemptsConsumed: 0, runLimit: 4 }, consumedSignals: [],
  };
  return { root, canonical, execution, canonicalDir: canonical.dir("repo"), executionDir: execution.dir("repo"), state, treeDigest };
}

function config(f: Awaited<ReturnType<typeof fixture>>, script: string, opts: { requiredTier?: "process" | "microvm"; executor?: IsolatedExecutor; timeoutMs?: number } = {}): ProjectTestConfig {
  const executor = opts.executor ?? new ProcessIsolationExecutor(undefined, opts.timeoutMs === undefined ? {} : { timeoutMs: opts.timeoutMs });
  return {
    snapshotFiles: (ref) => f.canonical.files(ref), executionSnapshotFiles: (ref) => f.execution.files(ref),
    canonicalProjectDirFor: () => f.canonicalDir, executionProjectDirFor: () => f.executionDir,
    selectedTier: "process", requiredTier: opts.requiredTier ?? "process", command: "node", args: ["-e", script],
    runnerFor: () => new IsolatedTestRunner(new SandboxedCommandRunner({ command: "node", args: ["-e", script], projectDir: f.executionDir, timeoutMs: 1_000 }), executor, f.executionDir),
  };
}

test("independent verification persists a bounded, redacted, content-bound failure", async () => {
  const f = await fixture();
  const script = `console.log("not ok 1 - regression alice@example.com 30 !== 33"); process.exit(1)`;
  const artifact = await buildProjectTester(config(f, script)).run(issue, f.state);
  assert.equal(artifact.repositoryTreeSha256, f.treeDigest);
  assert.equal(artifact.verdict, "failed");
  assert.equal(artifact.testsExecuted, true);
  assert.equal(artifact.discovered, 1);
  assert.match(artifact.failures[0]!.name, /30 !== 33/);
  assert.doesNotMatch(artifact.failures[0]!.name, /alice@example\.com/);
  assert.match(artifact.failures[0]!.name, /email/i);
  assert.match(artifact.implementationSha256, /^[0-9a-f]{64}$/);
  assert.match(artifact.testRunResultSha256 ?? "", /^[0-9a-f]{64}$/);
  assert.deepEqual(JSON.parse(JSON.stringify(artifact)), artifact);
});

test("a clean non-empty enforcing run passes", async () => {
  const f = await fixture();
  const artifact = await buildProjectTester(config(f, `console.log("ok 1 - regression")`)).run(issue, f.state);
  assert.equal(artifact.verdict, "passed");
  assert.equal(artifact.testsPassed, true);
  assert.equal(artifact.isolation.requirementMet, true);
  assert.deepEqual(artifact.reasons, []);
});

test("required microvm isolation refuses before weak execution", async () => {
  const f = await fixture();
  const script = `require("node:fs").writeFileSync("must-not-exist", "bad"); console.log("ok 1 - bad")`;
  const executor = new MinimumTierExecutor(new ProcessIsolationExecutor(), "microvm");
  const artifact = await buildProjectTester(config(f, script, { requiredTier: "microvm", executor })).run(issue, f.state);
  assert.equal(artifact.verdict, "unavailable");
  assert.equal(artifact.testsExecuted, false);
  assert.match(artifact.runnerError ?? "", /required microvm isolation is unavailable/);
  assert.equal(await f.execution.tree("repo").read("must-not-exist"), undefined);
});

test("stale canonical bytes and a mismatched disposable copy both refuse before execution", async () => {
  const stale = await fixture();
  await stale.canonical.tree("repo").write("src/value.ts", "export const value = 9;\n");
  assert.equal((await buildProjectTester(config(stale, `throw new Error("must not run")`)).run(issue, stale.state)).verdict, "stale");

  const mismatch = await fixture();
  await mismatch.execution.tree("repo").write("src/value.ts", "not the implementation\n");
  const artifact = await buildProjectTester(config(mismatch, `throw new Error("must not run")`)).run(issue, mismatch.state);
  assert.equal(artifact.verdict, "unavailable");
  assert.match(artifact.runnerError ?? "", /disposable verification source/);
});

test("test writes remain confined to the disposable copy and cannot contaminate canonical source", async () => {
  const f = await fixture();
  const script = `require("node:fs").writeFileSync("src/value.ts", "tampered\\n"); console.log("ok 1 - pass")`;
  const artifact = await buildProjectTester(config(f, script)).run(issue, f.state);
  assert.equal(artifact.verdict, "passed");
  assert.equal(await f.canonical.tree("repo").read("src/value.ts"), "export const value = 2;\n");
  assert.equal(await f.execution.tree("repo").read("src/value.ts"), "tampered\n");
});

test("timeout, plain runners, thrown construction, and noncanonical executors become unavailable evidence", async () => {
  const timedFixture = await fixture();
  const timed = await buildProjectTester(config(timedFixture, `setTimeout(() => console.log("ok 1 - late"), 100)`, { timeoutMs: 5 })).run(issue, timedFixture.state);
  assert.equal(timed.verdict, "unavailable");
  assert.match(timed.runnerError ?? "", /exceeded 5ms/);

  const plainFixture = await fixture();
  const plainCfg = { ...config(plainFixture, ""), runnerFor: () => ({ async run() { return { results: [{ name: "fake", passed: true }] }; } }) };
  assert.equal((await buildProjectTester(plainCfg).run(issue, plainFixture.state)).verdict, "unavailable");

  const thrownFixture = await fixture();
  const thrownCfg = { ...config(thrownFixture, ""), runnerFor: () => { throw new Error("ENOENT injected"); } };
  assert.match((await buildProjectTester(thrownCfg).run(issue, thrownFixture.state)).runnerError ?? "", /ENOENT injected/);

  const fakeFixture = await fixture();
  const fake: IsolatedExecutor = { tier: "process", async runIsolated(runner) { return { tier: "process", executed: true, result: await runner.run(".") }; } };
  const forged = await buildProjectTester(config(fakeFixture, `console.log("ok 1 - forged")`, { executor: fake })).run(issue, fakeFixture.state);
  assert.equal(forged.verdict, "unavailable");
  assert.match(forged.runnerError ?? "", /not a canonical enforcing implementation/);
});

test("claimed argv and cwd must match the verifier-owned runner that actually executes", async () => {
  const f = await fixture();
  const script = `console.log("ok 1 - forged")`;
  const wrongArgv = { ...config(f, script), command: "node", args: ["--test"] };
  const artifact = await buildProjectTester(wrongArgv).run(issue, f.state);
  assert.equal(artifact.verdict, "unavailable");
  assert.equal(artifact.testsExecuted, false);
  assert.match(artifact.runnerError ?? "", /runner argv/);
});

test("canonical drift during disposable preparation is stale, while a bad copy alone is unavailable", async () => {
  const f = await fixture();
  const cfg = config(f, `console.log("ok 1 - must-not-run")`);
  const drift = { ...cfg, executionProjectDirFor: () => {
    writeFileSync(join(f.canonicalDir, "src", "value.ts"), "drifted\n");
    writeFileSync(join(f.executionDir, "src", "value.ts"), "drifted\n");
    return f.executionDir;
  } };
  const artifact = await buildProjectTester(drift).run(issue, f.state);
  assert.equal(artifact.verdict, "stale");
  assert.match(artifact.runnerError ?? "", /execution inputs changed|changed while preparing/);
});

test("full execution manifest catches non-localizer files on both canonical and disposable roots", async () => {
  const canonicalDrift = await fixture();
  writeFileSync(join(canonicalDrift.canonicalDir, "build.sh"), "#!/bin/sh\nexit 1\n");
  const stale = await buildProjectTester(config(canonicalDrift, `console.log("ok 1 - must-not-run")`)).run(issue, canonicalDrift.state);
  assert.equal(stale.verdict, "stale");
  assert.match(stale.runnerError ?? "", /execution inputs changed/);

  const badCopy = await fixture();
  writeFileSync(join(badCopy.executionDir, "build.sh"), "#!/bin/sh\nexit 1\n");
  const unavailable = await buildProjectTester(config(badCopy, `console.log("ok 1 - must-not-run")`)).run(issue, badCopy.state);
  assert.equal(unavailable.verdict, "unavailable");
  assert.match(unavailable.runnerError ?? "", /execution inputs do not match/);
});

test("a forged implementation digest disagreement with the edit receipt is refused", async () => {
  const f = await fixture();
  const forged = { ...f.state, artifacts: { implement: { ...(f.state.artifacts["implement"] as object), repositoryTreeAfterSha256: "f".repeat(64) } } };
  await assert.rejects(buildProjectTester(config(f, "")).run(issue, forged), /edit receipt disagree/);
});

test("failure evidence is capped without hiding the total discovered failure count", async () => {
  const f = await fixture();
  const script = `process.stdout.write(Array.from({length:1005}, (_,i) => "not ok " + (i+1) + " - failure-" + (i+1)).join("\\n") + "\\n", () => process.exit(1))`;
  const artifact = await buildProjectTester(config(f, script)).run(issue, f.state);
  assert.equal(artifact.verdict, "failed");
  assert.equal(artifact.discovered, 1005);
  assert.equal(artifact.failures.length, 1000);
  assert.equal(artifact.failuresOmitted, 5);
});

test("every terminal outcome releases its disposable execution source", async () => {
  const f = await fixture();
  let disposals = 0;
  const cfg = { ...config(f, `console.log("ok 1 - pass")`), disposeExecution: () => { disposals += 1; } };
  assert.equal((await buildProjectTester(cfg).run(issue, f.state)).verdict, "passed");
  assert.equal(disposals, 1);

  await f.canonical.tree("repo").write("src/value.ts", "stale\n");
  assert.equal((await buildProjectTester(cfg).run(issue, f.state)).verdict, "stale");
  assert.equal(disposals, 2);
});

test("solver feedback preserves actual failures and confines test writes to the disposable root", async t => {
  const f = await fixture(); t.after(() => rmSync(f.root, { recursive: true, force: true }));
  let disposals = 0;
  const script = `require("node:fs").writeFileSync("src/value.ts", "test-generated\\n"); console.log("ok 1 - retained behavior"); console.log("not ok 2 - actual regression"); process.exit(1)`;
  const runner = buildProjectTester({ ...config(f, script), disposeExecution: () => { disposals++; } }).feedbackRunner("repo");
  const result = await runner.run("repo");
  assert.equal(result.runnerError, undefined);
  assert.deepEqual(result.results.map(row => [row.name, row.passed]), [["retained behavior", true], ["actual regression", false]]);
  assert.equal(await f.canonical.tree("repo").read("src/value.ts"), "export const value = 2;\n");
  assert.equal(await f.execution.tree("repo").read("src/value.ts"), "test-generated\n");
  assert.equal(disposals, 1);
});

test("feedback returns a true pass only after provenance and cleanup pass", async t => {
  const f = await fixture(); t.after(() => rmSync(f.root, { recursive: true, force: true }));
  const cfg = config(f, `console.log("ok 1 - actual pass")`);
  const passed = await buildProjectTester(cfg).feedbackRunner("repo").run("repo");
  assert.deepEqual(passed.results, [{ name: "actual pass", passed: true }]);
  const cleanupFailed = await buildProjectTester({ ...cfg, disposeExecution: () => { throw Error("cleanup unavailable"); } }).feedbackRunner("repo").run("repo");
  assert.deepEqual(cleanupFailed.results, []);
  assert.match(cleanupFailed.runnerError ?? "", /cleanup unavailable/);
  const fake: IsolatedExecutor = { tier: "process", async runIsolated() { throw Error("must not execute"); } };
  const refused = await buildProjectTester(config(f, "", { executor: fake })).feedbackRunner("repo").run("repo");
  assert.deepEqual(refused.results, []);
  assert.match(refused.runnerError ?? "", /not a canonical enforcing implementation/);
});

test("feedback checks repository and expired admission before preparing any execution", async t => {
  const f = await fixture(); t.after(() => rmSync(f.root, { recursive: true, force: true }));
  const cfg = { ...config(f, ""), executionProjectDirFor: () => { throw Error("must not prepare"); } };
  const runner = buildProjectTester(cfg).feedbackRunner("repo");
  assert.match((await runner.run("other")).runnerError ?? "", /bound repository/);
  assert.match((await runner.run("repo", { deadline: Date.now() - 1 })).runnerError ?? "", /deadline exhausted/);
  assert.match((await runner.run("repo", { signal: AbortSignal.abort() })).runnerError ?? "", /deadline exhausted/);
});
