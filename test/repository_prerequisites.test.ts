/** Component runner controls below do not qualify host namespace execution or an installed archive. */
import test, { type TestContext } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { captureWorkspacePreparation, describeRepositoryReadiness, inspectRepositoryReadiness, prepareRepositoryWorkspace, validatePrerequisitePaths } from "../src/solve/repository_prerequisites.js";
import { captureRuntimeContract, gitChildHardening } from "../src/cli/runtime_config.js";
import { runInstanceCommand } from "../src/cli/instance.js";
import { SandboxedCommandRunner } from "../src/solve/sandboxed_runner.js";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest } from "../src/gateway/http_gateway.js";
import type { ModelProvider } from "../src/gateway/gateway.js";

function fixture(t: TestContext) {
  const root = mkdtempSync(join(tmpdir(), "keep-prerequisites-")), source = join(root, "source"), workspaces = join(root, "workspaces"), workspace = join(workspaces, "project");
  const toolchain = join(root, "selected-toolchain");
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(source); mkdirSync(workspaces); mkdirSync(join(toolchain, "bin"), { recursive: true }); mkdirSync(join(toolchain, "lib/node_modules/npm/bin"), { recursive: true });
  writeFileSync(join(toolchain, "bin/node"), "synthetic selected executable", { mode: 0o700 });
  writeFileSync(join(toolchain, "lib/node_modules/npm/bin/npm-cli.js"), "synthetic npm fixture");
  const hardening = gitChildHardening(process.platform, process.env);
  const git = (cwd: string, ...args: string[]) => execFileSync("git", [...hardening.configArgs, "-C", cwd, ...args], { env: hardening.env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  execFileSync("git", [...hardening.configArgs, "init", "-q", "-b", "main", source], { env: hardening.env });
  writeFileSync(join(source, "package.json"), JSON.stringify({ private: true, packageManager: "npm@10.9.4", dependencies: { "fixture-dependency": "1.0.0" } }));
  writeFileSync(join(source, "package-lock.json"), '{"name":"fixture","lockfileVersion":3}');
  writeFileSync(join(source, ".gitignore"), "node_modules/\n.keep-preparation-cache/\n");
  writeFileSync(join(source, "calc.js"), "exports.add = (a, b) => { return a - b; };\n");
  writeFileSync(join(source, "calc.test.cjs"), "const test=require('node:test'), assert=require('node:assert/strict'); require('fixture-dependency'); const {add}=require('./calc.js'); test('adds',()=>assert.equal(add(2,3),5));\n");
  git(source, "add", "."); git(source, "-c", "user.name=Keep", "-c", "user.email=keep@example.invalid", "commit", "-qm", "base");
  const commit = git(source, "rev-parse", "HEAD");
  const clone = () => execFileSync("git", [...hardening.configArgs, "clone", "--quiet", "--", source, workspace], { env: hardening.env, stdio: "pipe" });
  const supply = (dir: string) => { mkdirSync(join(dir, "node_modules/fixture-dependency"), { recursive: true }); writeFileSync(join(dir, "node_modules/fixture-dependency/package.json"), '{"name":"fixture-dependency","version":"1.0.0","main":"index.js"}'); writeFileSync(join(dir, "node_modules/fixture-dependency/index.js"), "module.exports=1;\n"); };
  const command = { command: process.execPath, args: ["--test", "calc.test.cjs"], timeoutMs: 10_000, cpuLimitSec: 5, maxOutputBytes: 65536, envAllowlist: [], namespaceJail: "required" as const, jailExecutable: join(root, "absent-helper") };
  const preparation = captureWorkspacePreparation(toolchain, source, workspaces);
  return { root, source, workspaces, workspace, toolchain, git, commit, clone, supply, command, preparation };
}
const componentSuccess = { results: [{ name: "offline prepare", passed: true }], processIsolation: { version: 1 as const, basis: "launcher-status" as const, namespacePolicy: "required" as const, namespaceSetup: "launcher-confirmed" as const,
  requestedNamespaces: ["mount-ns", "net-ns"], requestedRlimits: ["cpuLimit"], rlimitSetup: "launcher-confirmed" as const, degraded: [] } };

test("readiness names actual checker, lockfile and missing dependencies without importing source dependencies", t => {
  const f = fixture(t); f.supply(f.source);
  const before = inspectRepositoryReadiness(f.source, undefined, f.command);
  assert.equal(before.ready, false); assert.ok(before.missing.includes("node_modules/fixture-dependency/package.json"));
  assert.match(describeRepositoryReadiness(before), /Checker:.*calc.test.cjs.*\nPackage manager: npm@10.9.4; lockfile: package-lock.json/u);
  f.clone();
  assert.equal(inspectRepositoryReadiness(f.source, f.workspace, f.command).ready, false);
  f.supply(f.workspace);
  assert.equal(inspectRepositoryReadiness(f.source, f.workspace, f.command).ready, true);
  assert.equal(inspectRepositoryReadiness(f.source, f.workspace, { command: "absent-checker-command", args: [] }).ready, false);
  symlinkSync(f.source, join(f.workspace, "outside"));
  assert.equal(inspectRepositoryReadiness(f.source, f.workspace, f.command, { prerequisites: ["outside/package.json"] }).ready, false);
  for (const path of ["../outside", "/absolute", ".git/config", "node_modules/../bad"]) assert.throws(() => validatePrerequisitePaths([path]), /relative paths/u);
});

test("explicit preparation component uses selected toolchain and fixed offline recipe, preserving checker and other trees", async t => {
  const f = fixture(t); f.clone();
  const sibling = join(f.root, "sibling"); mkdirSync(sibling); writeFileSync(join(sibling, "unchanged"), "untouched");
  let runs = 0;
  const runner = (config: ConstructorParameters<typeof SandboxedCommandRunner>[0]) => ({ run: async () => {
    runs++; assert.equal(config.command, f.preparation.node); assert.equal(config.projectDir, f.workspace);
    assert.equal(config.namespaceJail, "required"); assert.equal(config.allowNet, false); assert.deepEqual(config.readOnlyPaths, [f.toolchain]);
    assert.ok(config.args.includes("--offline")); assert.ok(config.args.includes("--ignore-scripts")); assert.equal(config.args[0], f.preparation.npmCli);
    f.supply(f.workspace); return componentSuccess;
  } });
  const report = await prepareRepositoryWorkspace(f.source, f.workspace, f.command, { prerequisites: [], preparation: f.preparation }, runner);
  assert.equal(report.ready, true); assert.equal(runs, 1);
  await prepareRepositoryWorkspace(f.source, f.workspace, f.command, { prerequisites: [], preparation: f.preparation }, () => { throw new Error("prepared path must not reinstall"); });
  assert.equal(f.git(f.source, "status", "--porcelain"), ""); assert.equal(f.git(f.workspace, "diff", "HEAD"), "");
  assert.equal(readFileSync(join(sibling, "unchanged"), "utf8"), "untouched");
});

test("unsupported manager, lockfile, changed toolchain and real unavailable helper hold without fallback", async t => {
  const f = fixture(t); f.clone(); const setup = { prerequisites: [], preparation: f.preparation };
  const noRun = () => { throw new Error("preparation must not dispatch"); };
  writeFileSync(join(f.workspace, "package.json"), '{"packageManager":"pnpm@10.0.0","dependencies":{"fixture-dependency":"1.0.0"}}');
  await assert.rejects(prepareRepositoryWorkspace(f.source, f.workspace, f.command, setup, noRun), /no supported automatic preparation recipe/u);
  writeFileSync(join(f.workspace, "package.json"), readFileSync(join(f.source, "package.json")));
  rmSync(join(f.workspace, "package-lock.json"));
  await assert.rejects(prepareRepositoryWorkspace(f.source, f.workspace, f.command, setup, noRun), /requires package-lock/u);
  writeFileSync(join(f.workspace, "package-lock.json"), readFileSync(join(f.source, "package-lock.json")));
  await assert.rejects(prepareRepositoryWorkspace(f.source, f.workspace, { ...f.command, namespaceJail: false }, setup, noRun), /requires --test-namespace-jail=required/u);
  await assert.rejects(prepareRepositoryWorkspace(f.source, f.workspace, f.command, setup), /Offline workspace preparation held/u);
  assert.equal(existsSync(join(f.workspace, "node_modules")), false, "real unavailable helper did not execute synthetic toolchain");
  writeFileSync(f.preparation.node, "changed bytes");
  await assert.rejects(prepareRepositoryWorkspace(f.source, f.workspace, f.command, setup, noRun), /toolchain changed/u);
});

test("preparation that mutates the predefined checker is refused and preserved for inspection", async t => {
  const f = fixture(t); f.clone();
  await assert.rejects(prepareRepositoryWorkspace(f.source, f.workspace, f.command, { prerequisites: [], preparation: f.preparation }, () => ({ run: async () => {
    writeFileSync(join(f.workspace, "calc.test.cjs"), "process.exit(0)"); f.supply(f.workspace); return componentSuccess;
  } })), /changed tracked repository\/checker bytes/u);
  assert.equal(readFileSync(join(f.source, "calc.test.cjs"), "utf8").includes("assert.equal"), true);
  assert.equal(inspectRepositoryReadiness(f.source, f.workspace, f.command).ready, false, "checker mutation remains a hold even when package files exist");
  await assert.rejects(prepareRepositoryWorkspace(f.source, f.workspace, f.command, { prerequisites: [] }), /Restore the exact tracked/u);
  writeFileSync(join(f.workspace, "calc.test.cjs"), readFileSync(join(f.source, "calc.test.cjs")));
  assert.equal((await prepareRepositoryWorkspace(f.source, f.workspace, f.command, { prerequisites: [] })).ready, true, "explicit restored-byte recheck clears hold without reinstalling");
});

test("throwing preparation retains pre-dispatch hold until both source and workspace bytes are reconciled", async t => {
  const f = fixture(t); f.clone();
  const checker = readFileSync(join(f.source, "calc.test.cjs"), "utf8"), source = readFileSync(join(f.source, "calc.js"), "utf8");
  const hold = join(f.workspace, ".git/keep-preparation-hold.json");
  await assert.rejects(prepareRepositoryWorkspace(f.source, f.workspace, f.command, { prerequisites: [], preparation: f.preparation }, () => ({ run: async () => {
    assert.equal(existsSync(hold), true, "intent is present before runner effects");
    const pending = describeRepositoryReadiness(inspectRepositoryReadiness(f.source, f.workspace, f.command));
    assert.match(pending, /integrity is pending or unresolved/u);
    assert.doesNotMatch(pending, /bytes changed during preparation/u, "pending intent alone does not establish changed bytes");
    writeFileSync(join(f.workspace, "calc.test.cjs"), "process.exit(0)");
    writeFileSync(join(f.source, "calc.js"), "source changed by throwing component fixture");
    f.supply(f.workspace);
    throw new Error("component runner threw after effects");
  } })), /runner threw after effects/u);
  assert.equal(inspectRepositoryReadiness(f.source, f.workspace, f.command).ready, false);
  assert.equal(existsSync(hold), true);
  const prior = JSON.parse(readFileSync(hold, "utf8"));
  assert.match(prior.trackedStateSha256, /^[a-f0-9]{64}$/u); assert.match(prior.sourceStateSha256, /^[a-f0-9]{64}$/u);
  await assert.rejects(prepareRepositoryWorkspace(f.source, f.workspace, f.command, { prerequisites: [] }), /exact tracked source and workspace/u);
  writeFileSync(join(f.workspace, "calc.test.cjs"), checker);
  await assert.rejects(prepareRepositoryWorkspace(f.source, f.workspace, f.command, { prerequisites: [] }), /exact tracked source and workspace/u);
  assert.match(readFileSync(join(f.source, "calc.js"), "utf8"), /source changed/u, "recheck never restores source automatically");
  writeFileSync(join(f.source, "calc.js"), source);
  assert.equal((await prepareRepositoryWorkspace(f.source, f.workspace, f.command, { prerequisites: [] })).ready, true);
  assert.equal(existsSync(hold), false);
});

test("runtime captures preparation and prerequisite selections without executing the selected toolchain", t => {
  const f = fixture(t);
  const base = { KEEP_PROVIDER: "local", KEEP_REPOSITORY: f.source, KEEP_WORKSPACE_BASE: f.workspaces, KEEP_REVISION: f.commit, KEEP_BASE_BRANCH: "main", KEEP_REPO_REF: "project", KEEP_TEST_COMMAND: process.execPath };
  const setup = captureRuntimeContract({ ...base, KEEP_TEST_PREREQUISITES_JSON: '["node_modules/fixture-dependency/package.json"]', KEEP_WORKSPACE_PREPARATION: "npm-offline", KEEP_WORKSPACE_TOOLCHAIN: f.toolchain }, { cwd: f.root }, { projectRequired: true }).installedProject!;
  assert.deepEqual(setup.repositoryCheckSetup?.preparation, f.preparation);
  assert.deepEqual(setup.testCommand.readOnlyPaths, [f.toolchain]);
  assert.throws(() => captureRuntimeContract({ ...base, KEEP_WORKSPACE_PREPARATION: "online" }, { cwd: f.root }, { projectRequired: true }), /network permissions are unavailable/u);
  assert.throws(() => captureWorkspacePreparation(f.workspaces, f.source, f.workspaces), /disjoint/u);
});

test("instance prepare materializes only its workspace, supports no-install readback and refuses active ownership", async t => {
  const f = fixture(t), directory = join(f.root, "instance");
  const inherited = { ...process.env };
  for (const key of Object.keys(process.env)) if (key.startsWith("KEEP_")) delete process.env[key];
  t.after(() => { for (const key of Object.keys(process.env)) if (!(key in inherited)) delete process.env[key]; Object.assign(process.env, inherited); });
  const invoke = async (action: string) => { let output = ""; const code = await runInstanceCommand([action, directory, ...(action === "init" ? [`--repository=${f.source}`, `--test-command=${process.execPath}`, '--test-args=["--test","calc.test.cjs"]', '--test-prerequisites=["node_modules/fixture-dependency/package.json"]'] : [])], text => { output += text; }); return { code, output }; };
  assert.equal((await invoke("init")).code, 0);
  const failed = await invoke("prepare"); assert.equal(failed.code, 1); assert.match(failed.output, /Missing check prerequisites/u);
  const owned = join(directory, "workspaces/project"); assert.equal(existsSync(owned), true); assert.equal(existsSync(f.workspace), false);
  f.supply(owned);
  const prepared = await invoke("prepare"); assert.equal(prepared.code, 0, prepared.output); assert.match(prepared.output, /checker has not been run/u);
  assert.match((await invoke("status")).output, /Declared check prerequisites are present/u);
  writeFileSync(join(directory, "startup-pending.json"), "{}", { mode: 0o600 });
  assert.match((await invoke("prepare")).output, /startup is unresolved/u);
  rmSync(join(directory, "startup-pending.json"));
  const workerId = "01234567-89ab-4cde-8fab-0123456789ab";
  writeFileSync(join(directory, "current-worker.json"), JSON.stringify({ workerId, pid: process.pid, origin: "http://127.0.0.1:12345", tokenFile: join(directory, "data/gateway-token"), receipt: join(directory, "data/native-workers", `${workerId}.ready.json`) }), { mode: 0o600 });
  assert.match((await invoke("prepare")).output, /Stop this owned instance/u, "unresolved worker ownership refuses without probing or racing it");
  assert.equal(f.git(f.source, "status", "--porcelain"), "");
});

test("composed project holds before generation, then prepared no-install workspace yields a checked proposal", async t => {
  const f = fixture(t); let calls = 0;
  const provider: ModelProvider = { name: "scripted-prerequisite-fixture", isLocal: true, embed: async () => [], generate: async request => {
    calls++;
    const text = request.hints?.["taskRole"] === "goal_test" ? JSON.stringify({ body: "const {createRequire}=await import('node:module'); const require=createRequire(process.cwd()+'/goal.cjs'); const {add}=require('./calc.js'); assert.equal(add(2,3),5);" })
      : JSON.stringify({ rationale: "replace subtraction", edits: [{ file: "calc.js", search: "return a - b", replace: "return a + b", intent: "add the operands" }] });
    return { text, model: "fixture", tokensIn: 1, tokensOut: 1 };
  } };
  const app = composeKeep({ dataDir: join(f.root, "state"), developmentProvider: provider,
    repositoryMaterialization: { sourceDir: f.source, workspaceBase: f.workspaces, repoRef: "project", commit: f.commit },
    testCommand: { command: f.command.command, args: f.command.args, timeoutMs: f.command.timeoutMs, namespaceJail: false },
  });
  const request = async (path: string, body: unknown) => {
    const response = await handleGatewayRequest(app, { method: "POST", path, query: {}, headers: { authorization: "Bearer fixture-owner" }, body: JSON.stringify(body) }, { token: "fixture-owner" });
    assert.equal(response.status, 200, response.body); return JSON.parse(response.body) as { runId: string; status: string; note: string; proposal?: boolean };
  };
  const held = await request("/project", { goal: "fix add in calc.js so it adds", stepBudget: 50 });
  assert.equal(held.status, "waiting-capability"); assert.match(held.note, /fixture-dependency\/package.json/u); assert.equal(calls, 0);
  const again = await request("/project/resume", { runId: held.runId, capability: { capability: "repository-check-prerequisites", evidenceId: "still-missing" } });
  assert.equal(again.status, "waiting-capability"); assert.equal(calls, 0);
  f.supply(f.workspace);
  const result = await request("/project/resume", { runId: held.runId, capability: { capability: "repository-check-prerequisites", evidenceId: "owned-workspace-prepared" } });
  assert.equal(result.status, "completed", result.note); assert.equal(result.proposal, true); assert.ok(calls > 0);
  assert.match(f.git(f.workspace, "diff", "HEAD"), /return a \+ b/u);
  assert.match(readFileSync(join(f.source, "calc.js"), "utf8"), /return a - b/u); assert.equal(f.git(f.source, "status", "--porcelain"), "");
});
