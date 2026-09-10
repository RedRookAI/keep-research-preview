import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SandboxedCommandRunner, parseTap, sandboxedRunnerFor } from "../src/solve/sandboxed_runner.js";
import { LocalFsWorkspace } from "../src/solve/workspace.js";
import { buildDefaultSolver } from "../src/solve/default_solver.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";

function repoWith(testBody: string): string {
  const dir = mkdtempSync(join(tmpdir(), "keep-sbxrun-"));
  writeFileSync(join(dir, "sample.test.mjs"),
    `import { test } from "node:test"; import assert from "node:assert/strict";\n${testBody}\n`);
  return dir;
}

test("REAL PASS: a passing test command runs in the sandbox → testsPassed via exit 0 + TAP", async () => {
  const dir = repoWith(`test("adds", () => assert.equal(1+1, 2));`);
  const runner = new SandboxedCommandRunner({ command: "node", args: ["--test"], projectDir: dir, timeoutMs: 30_000 });
  const r = await runner.run(dir);
  assert.equal(r.runnerError, undefined, "no runner error");
  assert.ok(r.results.length > 0 && r.results.every((c) => c.passed), "all cases passed");
});

test("REAL FAIL: a failing test command → parsed failing case (not a false green)", async () => {
  const dir = repoWith(`test("wrong", () => assert.equal(1+1, 3));`);
  const runner = new SandboxedCommandRunner({ command: "node", args: ["--test"], projectDir: dir, timeoutMs: 30_000 });
  const r = await runner.run(dir);
  assert.equal(r.runnerError, undefined, "the command ran to completion");
  assert.ok(r.results.some((c) => !c.passed), "a failing case was surfaced");
});

test("TIMEOUT: a genuinely hanging command → runnerError (sandbox process-group kill), never a pass", async () => {
  const dir = repoWith(`test("ok", () => assert.ok(true));`);
  // A command that hangs the PROCESS itself (node --test self-limits, so exercise the sandbox's own deadline).
  const runner = new SandboxedCommandRunner({ command: "node", args: ["-e", "setInterval(()=>{}, 1000)"], projectDir: dir, timeoutMs: 800 });
  const r = await runner.run(dir);
  assert.match(r.runnerError ?? "", /killed|exceed/i, "a hang is reported as a runner error");
  assert.equal(r.results.length, 0, "no results ⇒ cannot count as passed");
});

test("PATH ESCAPE: a repoRef outside the project dir is refused", async () => {
  const dir = repoWith(`test("ok", () => assert.ok(true));`);
  const runner = new SandboxedCommandRunner({ command: "node", args: ["--test"], projectDir: dir, timeoutMs: 5_000 });
  const r = await runner.run("/etc");
  assert.match(r.runnerError ?? "", /escape/i, "an out-of-project scope is refused");
});

test("parseTap: ok/not ok/SKIP handling", () => {
  const cases = parseTap(["ok 1 - alpha", "not ok 2 - beta", "ok 3 - gamma # SKIP not ready", "noise line"].join("\n"));
  assert.equal(cases.length, 3);
  assert.deepEqual(cases.map((c) => c.passed), [true, false, true]); // SKIP is non-failing
  assert.equal(cases[1]!.name, "beta");
});

test("END-TO-END: buildDefaultSolver runs its tests INSIDE the sandbox via LocalFsWorkspace", async () => {
  // A real on-disk repo with a buggy function + a real test that pins the fix.
  const base = mkdtempSync(join(tmpdir(), "keep-sbx-e2e-"));
  const repo = join(base, "proj");
  mkdirSync(join(repo, "src"), { recursive: true });
  writeFileSync(join(repo, "src", "math.mjs"), "export const add = (a, b) => a - b;\n");
  writeFileSync(join(repo, "add.test.mjs"),
    `import { test } from "node:test"; import assert from "node:assert/strict";\nimport { add } from "./src/math.mjs";\ntest("add", () => assert.equal(add(1,2), 3));\n`);

  const ws = new LocalFsWorkspace(base);
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-sbx-spine-"))), new InProcessLock(), new SchemaRegistry());
  const plan = JSON.stringify({ rationale: "operator should be +", edits: [{ file: "src/math.mjs", search: "a - b", replace: "a + b", intent: "fix" }] });
  const model: ModelProvider = {
    name: "scripted", isLocal: true,
    async generate(_r: GenerateRequest): Promise<GenerateResult> { return { text: plan, model: "s", tokensIn: 0, tokensOut: 0 } as GenerateResult; },
    async embed(t: readonly string[]): Promise<Embedding[]> { return t.map(() => [0]); },
  };

  const solve = buildDefaultSolver({
    spine, model, workspace: ws,
    // the solver's tests run INSIDE the sandbox against the real repo dir
    runnerFor: sandboxedRunnerFor((ref) => ws.dir(ref), "node", ["--test"], { timeoutMs: 30_000 }),
  });

  const out = await solve({ id: "E2E", text: "add() returns a-b instead of a+b in src/math.mjs", repoRef: "proj" });
  // The sandboxed test executed and gated the result: after the fix, the real test passes.
  assert.equal(out.solveResult.solved, true, "the sandbox-verified solve succeeded");
  assert.equal(out.solveResult.validation?.testsPassed, true, "the REAL test passed inside the boundary");
});

test("COMPOSE WIRE: composeKeep(testCommand + disk workspace) runs the solver's tests sandboxed via runProject", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const base = mkdtempSync(join(tmpdir(), "keep-sbx-compose-"));
  const repo = join(base, "proj");
  mkdirSync(join(repo, "src"), { recursive: true });
  writeFileSync(join(repo, "src", "math.mjs"), "export const add = (a, b) => a - b;\n");
  writeFileSync(join(repo, "add.test.mjs"),
    `import { test } from "node:test"; import assert from "node:assert/strict";\nimport { add } from "./src/math.mjs";\ntest("add", () => assert.equal(add(1,2), 3));\n`);

  const plan = JSON.stringify({ rationale: "fix operator", edits: [{ file: "src/math.mjs", search: "a - b", replace: "a + b", intent: "fix" }] });
  const roles: string[] = [];
  const model: ModelProvider = {
    name: "scripted", isLocal: true,
    async generate(req: GenerateRequest): Promise<GenerateResult> {
      const role = String(req.hints?.["taskRole"]); roles.push(role);
      assert.ok(role === "goal_test" || role === "repository_edit", "explicit scripted provider protocol");
      const text = role === "goal_test" ? JSON.stringify({
        body: "const {pathToFileURL}=await import('node:url');const {join}=await import('node:path');const {add}=await import(pathToFileURL(join(process.cwd(),'src/math.mjs')));for(const [a,b,c] of [[1,2,3],[-4,2,-2],[0,0,0],[1.5,2.25,3.75]])assert.equal(add(a,b),c);",
      }) : plan;
      return { text, model: "s", tokensIn: 0, tokensOut: 0 };
    },
    async embed(t: readonly string[]): Promise<Embedding[]> { return t.map(() => [0]); },
  };

  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-sbx-compose-data-")),
    developmentProvider: model,
    workspace: new LocalFsWorkspace(base),
    repoRef: "proj",
    testCommand: { command: "node", args: ["--test"], timeoutMs: 30_000 }, // sandboxed real execution, no fail-closed
  });

  const run = await app.autonomyLoop!.runProject("fix add() in src/math.mjs so it returns a+b", { runId: "rSbx", stepBudget: 50 });
  assert.ok(run.feasibility?.proceed, "feasible");
  assert.deepEqual(roles, ["repository_edit", "goal_test"]);
  const independent = run.state.artifacts["vet_artifact"] as { schemaVersion?: unknown; verdict?: unknown; repositoryTreeSha256?: unknown; testsExecuted?: unknown };
  assert.ok(independent, JSON.stringify(run.state));
  assert.equal(independent.schemaVersion, 1);
  assert.equal(independent.verdict, "passed", "the installed composition persisted an independent post-implementation verdict");
  assert.equal(independent.testsExecuted, true);
  assert.match(String(independent.repositoryTreeSha256), /^[0-9a-f]{64}$/);
  await app.spine.seal();
  // the sandboxed isolated_execution + the governed decision are both on the trail
  const payloads = app.spine.replay().map((e: any) => e.payload as Record<string, unknown>);
  assert.ok(payloads.some((p) => p?.["event"] === "merge_authority"), "a governed decision was made after sandboxed tests");
});
