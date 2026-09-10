import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest } from "../src/gateway/http_gateway.js";
import type { ModelProvider } from "../src/gateway/gateway.js";
import type { ProjectState } from "../src/autonomy/project_state.js";
import type { ProjectImplementationArtifact } from "../src/solve/project_loop_wiring.js";

// KEEP-03A-001: adapted from the frozen audit's mixed valid/unmatched plan.
// Scripted proposals, real local Git/filesystem and executing arithmetic checks.
// Fresh state only; no model service, source landing, or audit-workspace mutation.
const before = "export function add(a, b) { return a - b; }\n";
const token = "synthetic-refusal-owner";
const headers = { authorization: `Bearer ${token}` };
const childEnv = { ...process.env };
delete childEnv["NODE_TEST_CONTEXT"];
function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", ...args], {
    cwd, encoding: "utf8", timeout: 5000,
    env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_AUTHOR_NAME: "Synthetic fixture", GIT_AUTHOR_EMAIL: "fixture@example.invalid",
      GIT_COMMITTER_NAME: "Synthetic fixture", GIT_COMMITTER_EMAIL: "fixture@example.invalid" },
  }).trim();
}

for (const variant of ["control", "unmatched", "ambiguous"] as const) {
  test(`KEEP-03A-001 public project ${variant}: persisted result agrees with real files`, async () => {
    const root = mkdtempSync(join(tmpdir(), "keep-refusal-audit-"));
    const source = join(root, "source"), workspaceBase = join(root, "workspaces");
    mkdirSync(source); mkdirSync(workspaceBase);
    writeFileSync(join(source, "calc.mjs"), before);
    writeFileSync(join(source, "unrelated.txt"), "unchanged\n");
    writeFileSync(join(source, "repo.test.mjs"), "import test from 'node:test'; import assert from 'node:assert/strict'; import {add} from './calc.mjs'; test('callable',()=>assert.equal(typeof add,'function'));\n");
    // Outside the admitted source/write set; this independently specified oracle
    // also runs after the public request against the actual retained candidate.
    const oracle = join(root, "behavior.mjs");
    writeFileSync(oracle, "import test from 'node:test'; import assert from 'node:assert/strict'; import {pathToFileURL} from 'node:url'; import {join} from 'node:path'; const {add}=await import(pathToFileURL(join(process.cwd(),'calc.mjs'))); for(const [a,b,sum] of [[2,3,5],[-4,2,-2],[0,0,0],[1.5,2.25,3.75]]) test(String([a,b]),()=>assert.equal(add(a,b),sum));\n");
    git(source, "init", "-q", "-b", "main"); git(source, "add", "-A"); git(source, "commit", "-qm", "synthetic base");
    const base = git(source, "rev-parse", "HEAD");
    let generations = 0;
    const model: ModelProvider = { name: "refusal-audit-scripted", isLocal: true,
      async embed() { throw new Error("unexpected embedding call"); },
      async generate(request) {
        generations++;
        const goalTest = request.hints?.["taskRole"] === "goal_test";
        assert.ok(goalTest || request.hints?.["taskRole"] === "repository_edit" || request.prompt.includes("Initial writable files"), "recognized protocol");
        const edits = [{ file: "calc.mjs", search: "return a - b", replace: "return a + b", intent: "add operands" }];
        if (variant !== "control") edits.push({ file: "calc.mjs", search: variant === "unmatched" ? "NO_SUCH_SEARCH_BLOCK" : "a", replace: "never-applied", intent: "inapplicable second hunk" });
        const value = goalTest ? { body: "const {pathToFileURL}=await import('node:url');const {join}=await import('node:path');const {add}=await import(pathToFileURL(join(process.cwd(),'calc.mjs')));assert.equal(add(2,3),5);" }
          : { action: "plan", rationale: "bounded arithmetic repair", edits };
        return { text: JSON.stringify(value), model: "scripted", tokensIn: 1, tokensOut: 1 };
      },
    };
    const config = { dataDir: join(root, "state"), sourceLanding: true,
      repositoryMaterialization: { sourceDir: source, workspaceBase, repoRef: "project", commit: base, baseBranch: "main" },
      testCommand: { command: process.execPath, args: ["--test", "repo.test.mjs", oracle], timeoutMs: 5000 } };
    const app = composeKeep({ ...config, developmentProvider: model });
    const started = await handleGatewayRequest(app, { method: "POST", path: "/project", query: {}, headers,
      body: JSON.stringify({ goal: "Fix add in calc.mjs to return the arithmetic sum of its two numeric arguments. Preserve all other files." }) }, { token });
    assert.equal(started.status, 200);
    const response = JSON.parse(started.body) as { runId: string; proposal: boolean };
    const view = await handleGatewayRequest(app, { method: "GET", path: "/project", query: { runId: response.runId }, headers, body: "" }, { token });
    const project = (JSON.parse(view.body) as { project: ProjectState }).project;
    const solve = (project.artifacts["implement"] as ProjectImplementationArtifact | undefined)?.solve;
    assert.equal(git(source, "rev-parse", "HEAD"), base);
    assert.equal(git(source, "status", "--porcelain"), "");
    assert.equal(readFileSync(join(source, "calc.mjs"), "utf8"), before);
    assert.equal(readFileSync(join(workspaceBase, "project", "unrelated.txt"), "utf8"), "unchanged\n");
    assert.ok(solve, "a known result survives the implement stage");
    assert.equal(generations, 2, "one proposal and one goal check; no blind retry");
    assert.ok((solve.recovery?.planningCalls ?? 0) > 0, "planning consumption is retained");
    if (variant === "control") {
      assert.equal(solve.solved, true); assert.equal(response.proposal, true);
      const checked = execFileSync(process.execPath, ["--test", oracle], { cwd: join(workspaceBase, "project"), timeout: 5000, env: childEnv, encoding: "utf8" });
      assert.match(checked, /# tests 4\b/); assert.match(checked, /# pass 4\b/);
    } else {
      assert.equal(readFileSync(join(workspaceBase, "project", "calc.mjs"), "utf8"), before, "even the valid first hunk was never committed");
      assert.equal(solve.solved, false); assert.equal(response.proposal, false);
      assert.equal(solve.projectEditReceipt, undefined); assert.equal(solve.prProposal, undefined);
      assert.notEqual(project.status, "waiting-reconciliation");
      assert.notEqual(solve.recovery?.status, "reconciliation");
      assert.match(solve.gaveUpReason ?? "", variant === "unmatched" ? /search block not found/ : /must be unique/);
      assert.throws(() => execFileSync(process.execPath, ["--test", oracle], { cwd: join(workspaceBase, "project"), timeout: 5000, env: childEnv }), "unchanged faulty arithmetic must fail the oracle");
    }
    await app.spine.seal();
    if (variant !== "control") {
      const events = app.spine.replay();
      assert.equal(events.some(event => event.payload["event"] === "reversible_recorded"), false, "refusal registers no inverse");
      const refusal = events.find(event => event.payload["classification"] === "non-applicable");
      assert.equal(refusal?.payload["effect"], "not-attempted");
      const edits = refusal?.payload["perEdit"] as { status: string }[];
      assert.equal(edits[0]?.status, "held", "matched prefix is not reported as an applied edit");
      assert.equal(edits.some(edit => edit.status === "applied"), false);
    }
    const restored = JSON.parse(execFileSync(process.execPath, ["--input-type=module", "-e", `
      import {composeKeep} from ${JSON.stringify(new URL("../src/compose.js", import.meta.url).href)};
      import {handleGatewayRequest} from ${JSON.stringify(new URL("../src/gateway/http_gateway.js", import.meta.url).href)};
      const app=composeKeep(JSON.parse(process.argv[1]));
      const r=await handleGatewayRequest(app,{method:'GET',path:'/project',query:{runId:process.argv[2]},headers:{authorization:'Bearer '+process.argv[3]},body:''},{token:process.argv[3]});
      if(r.status!==200)throw Error(r.body);console.log(r.body);
    `, JSON.stringify(config), response.runId, token], { encoding: "utf8", timeout: 10000, env: childEnv })) as { project: ProjectState };
    assert.deepEqual(restored.project.artifacts["implement"], project.artifacts["implement"], "fresh process preserves the exact structured result without model dispatch");
  });
}
