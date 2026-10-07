/** CS002: installed CLI and controlled Codex executable; no live model qualification. */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const installed = process.env.KEEP_INSTALLED_PACKAGE_ROOT;
assert.ok(installed, "installed package required; no source fallback");
const root = process.argv[2]; assert.ok(root); mkdirSync(root, { recursive: true });
const entry = join(installed, "dist/src/main.js"), source = join(root, "source"), workspaces = join(root, "workspaces"), data = join(root, "data");
mkdirSync(source); mkdirSync(join(source, "src")); mkdirSync(workspaces);
writeFileSync(join(source, "src/retry.mjs"), "export const retryLimit = 0;\n");
writeFileSync(join(source, "retry.test.mjs"), "import test from 'node:test'; import assert from 'node:assert/strict'; import {retryLimit} from './src/retry.mjs'; test('limit',()=>assert.equal(retryLimit,7));\n");
const base = { PATH: process.env.PATH, HOME: root, TMPDIR: root, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0" };
function git(args) { const r = spawnSync("git", ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", ...args], { cwd: source, env: base, encoding: "utf8" }); assert.equal(r.status, 0, r.stderr); return r.stdout.trim(); }
git(["init", "--quiet", "--initial-branch=main"]); git(["add", "."]); git(["-c", "user.name=Keep Fixture", "-c", "user.email=keep@example.invalid", "commit", "--quiet", "-m", "fixture"]);
const revision = git(["rev-parse", "HEAD"]), errors = [];
const callFile = join(root,"fake-calls.json");
const calls = { get length() { return existsSync(callFile) ? JSON.parse(readFileSync(callFile,"utf8")).length : 0; } };
const fake = join(root,"codex-fixture");
writeFileSync(fake, `#!${process.execPath}
const fs=require('node:fs');
if(process.argv.includes('--version')) { console.log('codex-cli 0.159.3'); process.exit(0); }
if(process.argv.includes('login')) { console.error('Logged in using ChatGPT'); process.exit(0); }
let prompt='';process.stdin.setEncoding('utf8');process.stdin.on('data',x=>prompt+=x);process.stdin.on('end',()=>{
 const p=${JSON.stringify(callFile)};
 const calls=fs.existsSync(p)?JSON.parse(fs.readFileSync(p,'utf8')):[]; calls.push(prompt);fs.writeFileSync(p,JSON.stringify(calls));
 const value=calls.length===2?{body:"assert.equal((await import('./src/retry.mjs')).retryLimit,7);"}:{action:"plan",rationale:"Correct limit",edits:[{file:"src/retry.mjs",search:"retryLimit = 0",replace:"retryLimit = 7",intent:"Correct limit"}]};
 for(const event of [{type:'thread.started',thread_id:'fixture'},{type:'turn.started'},{type:'item.completed',item:{id:'1',type:'agent_message',text:JSON.stringify({text:JSON.stringify(value)})}},{type:'turn.completed',usage:{input_tokens:10,cached_input_tokens:0,output_tokens:5}}])console.log(JSON.stringify(event));
});
`, {mode:0o700});
const model={closeAllConnections(){},close(cb){cb();}};
const env = { ...base, KEEP_PROVIDER:"local", KEEP_PROJECT_MODEL:"codex", KEEP_CODEX_EXECUTABLE:fake, KEEP_CODEX_MODEL:"fixture-model", KEEP_CODEX_PROCESSING:"owner-public-repository", KEEP_CODEX_MAX_INVOCATIONS:"2", KEEP_CODEX_MAX_PROMPT_BYTES:"65536", KEEP_CODEX_MAX_OUTPUT_BYTES:"262144", KEEP_CODEX_TIMEOUT_MS:"5000", KEEP_REPOSITORY:source, KEEP_WORKSPACE_BASE:workspaces, KEEP_REVISION:revision, KEEP_REPO_REF:"project", KEEP_TEST_COMMAND:process.execPath, KEEP_TEST_ARGS_JSON:JSON.stringify(["--test","--test-reporter=tap","retry.test.mjs"]), KEEP_TEST_TIMEOUT_MS:"5000", KEEP_TEST_CPU_LIMIT_SEC:"2", KEEP_TEST_MAX_OUTPUT_BYTES:"16384", KEEP_DATA_DIR:data, KEEP_PROJECT_POSTURE:"autonomous" };
async function command(args, environment = env, expected = 0) {
  const child = spawn(process.execPath, [entry, ...args], { cwd: root, env: environment, stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "", stderr = ""; child.stdout.on("data", b => { stdout += b; }); child.stderr.on("data", b => { stderr += b; });
  const code = await new Promise((resolve, reject) => { const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("CLI timeout")); }, 45000); child.once("error", reject); child.once("exit", code => { clearTimeout(timer); resolve(code); }); });
  writeFileSync(join(root, `command-${command.count++}.json`), JSON.stringify({ args, code, stdout, stderr }, null, 2)); assert.equal(code, expected, stderr + stdout); return stdout;
}
command.count = 0;
let worker;
async function start() {
  worker = spawn(process.execPath, [entry, "serve", "--gateway", "--project-worker", "--port=0"], { cwd: root, env, stdio: ["ignore", "pipe", "pipe"] });
  let text = "", stderr = ""; worker.stderr.on("data", b => { stderr += b; writeFileSync(join(root,"worker-stderr.log"),stderr); });
  return new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error("worker setup: " + stderr + text)), 20000); worker.stdout.on("data", b => { text += b; const match = /http:\/\/127\.0\.0\.1:\d+/u.exec(text); if (match) { clearTimeout(timer); resolve(match[0]); } }); worker.once("exit", code => { clearTimeout(timer); reject(new Error("worker refused " + code + ": " + stderr + text)); }); });
}
async function stop() { if (!worker) return; const w = worker; worker = undefined; if(w.exitCode !== null || w.signalCode !== null) return; const ended = new Promise(resolve => w.once("exit", resolve)); w.kill("SIGTERM"); await ended; }
try {
  for (const args of [["solve"], ["solve", "fix", "--posture=autonomous"], ["solve", "fix"]]) {
    await command(args, { ...base, KEEP_DATA_DIR: join(root, "invalid-data") }, 2); assert.equal(existsSync(join(root, "invalid-data")), false);
  }
  const output = await command(["solve", "Correct retryLimit in src/retry.mjs to seven; preserve unrelated behavior."]);
  const runId = /Run: ([^\s]+)/u.exec(output)?.[1]; assert.ok(runId, output); assert.equal(calls.length, 0);
  let origin = await start(); const token = readFileSync(join(data, "owner-token"), "utf8").trim();
  const remote = () => ({ ...base, KEEP_GATEWAY_URL: origin, KEEP_GATEWAY_TOKEN: token });
  const observe = async () => { const response = await fetch(origin + "/project?runId=" + runId, { headers: { authorization: "Bearer " + token }, signal: AbortSignal.timeout(5000) }); assert.equal(response.status, 200); return response.json(); };
  const initial = await observe(); writeFileSync(join(root, "initial.json"), JSON.stringify(initial, null, 2));
  assert.equal(initial.project.status, "waiting-approval"); assert.equal(calls.length, 0);
  await command(["project", "resume", runId, "--approve=" + initial.project.wait.decisionId], remote());
  const result = await observe(); writeFileSync(join(root, "outcome.json"), JSON.stringify({ ...result, controlledCalls: calls.length, controlledErrors: errors }, null, 2));
  assert.deepEqual(errors, []); assert.equal(result.project.artifacts.implement.solve.solved, true, JSON.stringify(result));
  assert.ok(result.proposal, "reviewable proposal required"); assert.equal(readFileSync(join(source, "src/retry.mjs"), "utf8"), "export const retryLimit = 0;\n");
  assert.match(JSON.stringify(result.proposal), /retryLimit/u);
  assert.equal(result.proposal.checks.testsPassed, true); assert.equal(result.proposal.checks.vettingCleared, true);
  assert.deepEqual(result.proposal.checks.passedTests, ["limit", "goal: requested outcome"]);
  assert.equal(result.project.artifacts.vet_artifact.passed, true);
  assert.equal(readFileSync(join(workspaces, "project/src/retry.mjs"), "utf8"), "export const retryLimit = 7;\n");
  assert.match(result.proposal.diff, /\+export const retryLimit = 7;/u);
  const beforeRestart = calls.length; await stop(); origin = await start();
  const restored = await observe(); assert.equal(calls.length, beforeRestart); assert.deepEqual(restored.proposal, result.proposal);
  const denied = await command(["solve", "do not dispatch"], { ...remote(), KEEP_GATEWAY_TOKEN: "d".repeat(64) }, 1); assert.match(denied, /401|403/u); assert.equal(calls.length, beforeRestart);
  const digest = result.proposal.rollback.patchSha256;
  const decision = await command(["merge", runId, "veto", "--proposal=" + digest], remote());
  assert.equal(readFileSync(join(source, "src/retry.mjs"), "utf8"), "export const retryLimit = 0;\n");
  const receipt = { status: "PASS", root, runId, diff: result.proposal.diff, version: JSON.parse(readFileSync(join(installed, "package.json"))).version, installed, configuredPosture: "autonomous", solvePosture: "approval-required", localInstalledStart: true, explicitApprovalBeforeDispatch: true, reviewableProposal: true, passedTests: result.proposal.checks.passedTests, artifactVettingPassed: true, processIsolationEvidence: result.project.artifacts.vet_artifact.isolation, solved: true, controlledModelCalls: calls.length, sourceUnchanged: true, restartNoReplay: true, wrongTokenRefused: true, explicitVetoOutput: decision, paidCalls: 0, modelResponses: "scripted-codex-cli", operatorDecisions: "simulated approval then exact-proposal veto", limits: "Controlled model responses; same-agent Linux fixture with best-effort process isolation, not real-model quality or production qualification." };
  writeFileSync(join(root, "result.json"), JSON.stringify(receipt, null, 2)); console.log(JSON.stringify(receipt));
} finally { await stop(); model.closeAllConnections(); await new Promise(resolve => model.close(resolve)); }
