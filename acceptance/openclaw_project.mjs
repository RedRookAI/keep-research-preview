/** Installed Keep + real OpenClaw CLI/tool consumer. Both model routes are local
 * scripted fixtures. This does not authorize or qualify a genuine account call. */
import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { chmodSync, chownSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const installed = process.env.KEEP_INSTALLED_PACKAGE_ROOT, claw = process.env.KEEP_OPENCLAW_PACKAGE_ROOT;
const clawNode = process.env.KEEP_OPENCLAW_NODE, root = process.argv[2];
const uid = Number(process.env.KEEP_OPENCLAW_FIXTURE_UID);
assert.ok(installed && claw && clawNode && root, "explicit installed Keep/OpenClaw/Node paths and a new fixture directory required");
assert.equal(process.platform, "linux"); assert.equal(process.getuid(), 0, "fixture parent needs permission to drop only its child identity");
assert.ok(Number.isSafeInteger(uid) && uid > 0, "explicit unprivileged child UID required; no system user is created");
assert.equal(JSON.parse(readFileSync(join(claw, "package.json"))).version, "2026.10.5");
mkdirSync(root, { mode: 0o711 }); chmodSync(root, 0o711);
const keepRoot = join(root, "keep-private"), agentRoot = join(root, "openclaw-client");
mkdirSync(keepRoot, { mode: 0o700 }); mkdirSync(agentRoot, { mode: 0o700 }); chownSync(agentRoot, uid, uid);
const source = join(keepRoot, "source"), workspace = join(keepRoot, "workspaces"), data = join(keepRoot, "data");
mkdirSync(source); mkdirSync(workspace); mkdirSync(join(source, "src"));
writeFileSync(join(source, "src/retry.mjs"), "export const retryLimit = 0;\n");
writeFileSync(join(source, "retry.test.mjs"), "import test from 'node:test';import assert from 'node:assert/strict';import {retryLimit} from './src/retry.mjs';test('limit',()=>assert.equal(retryLimit,7));\n");
const git = args => { const r = spawnSync("git", ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", ...args], { cwd: source, encoding: "utf8", env: { PATH: process.env.PATH, HOME: keepRoot, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" } }); assert.equal(r.status, 0, r.stderr); return r.stdout.trim(); };
git(["init", "--quiet", "--initial-branch=main"]); git(["add", "."]); git(["-c", "user.name=Keep Fixture", "-c", "user.email=keep@example.invalid", "commit", "--quiet", "-m", "controlled source"]);
const callFile = join(keepRoot, "controlled-calls.json"), executable = join(keepRoot, "codex-fixture");
writeFileSync(executable, `#!${process.execPath}
const fs=require('node:fs');let prompt='';process.stdin.on('data',b=>prompt+=b);process.stdin.on('end',()=>{
const path=${JSON.stringify(callFile)},calls=fs.existsSync(path)?JSON.parse(fs.readFileSync(path,'utf8')):[];calls.push(prompt);fs.writeFileSync(path,JSON.stringify(calls));
const value=calls.length===2?{body:"assert.equal((await import('./src/retry.mjs')).retryLimit,7);"}:{action:"plan",rationale:"Correct limit",edits:[{file:"src/retry.mjs",search:"retryLimit = 0",replace:"retryLimit = 7",intent:"Correct limit"}]};
for(const e of [{type:'thread.started',thread_id:'controlled'},{type:'turn.started'},{type:'item.completed',item:{type:'agent_message',text:JSON.stringify({text:JSON.stringify(value)})}},{type:'turn.completed',usage:{input_tokens:10,cached_input_tokens:0,output_tokens:5}}])console.log(JSON.stringify(e));});`, { mode: 0o700 });
const { composeKeep } = await import(pathToFileURL(join(installed, "dist/src/compose.js")));
const { startGatewayServer } = await import(pathToFileURL(join(installed, "dist/src/gateway/http_gateway.js")));
const { runOpenClawClientCommand } = await import(pathToFileURL(join(installed, "dist/src/cli/openclaw_client.js")));
const profilePath = join(keepRoot, "client.json"), issuedToken = join(keepRoot, "client-token"), ownerToken = randomBytes(32).toString("hex");
const app = composeKeep({ dataDir: data, openclawClientProfile: profilePath, sourceLanding: true,
  repositoryMaterialization: { sourceDir: source, workspaceBase: workspace, repoRef: "project", commit: git(["rev-parse", "HEAD"]), baseBranch: "main" },
  runtimePaths: { repository: source, workspace }, projectPosture: "autonomous",
  testCommand: { command: process.execPath, args: ["--test", "--test-reporter=tap", "retry.test.mjs"], timeoutMs: 5000, cpuLimitSec: 2, maxOutputBytes: 16384, envAllowlist: [] },
  codexProject: { executable, executableSha256: createHash("sha256").update(readFileSync(executable)).digest("hex"), cliVersion: "codex-cli 0.163.0", model: "fixture-model", maxSubmittedPromptBytes: 65536, maxCapturedOutputBytes: 262144, maxElapsedMs: 5000, maxInvocations: 2, processing: "owner-public-repository" },
});
writeFileSync(join(keepRoot, "owner-token"), ownerToken, { mode: 0o600 });
writeFileSync(join(keepRoot, "codex-auth.fixture"), "controlled-private-marker", { mode: 0o600 });
assert.equal(await runOpenClawClientCommand(app, ["issue", `--profile=${profilePath}`, `--token-file=${issuedToken}`, "--agent-id=portfolio-client", `--expires-at=${new Date(Date.now() + 3600000).toISOString()}`], true, () => {}), 0);
const profile = JSON.parse(readFileSync(profilePath, "utf8")), clientToken = readFileSync(issuedToken, "utf8").trim();
const privateWrite = (path, value) => { writeFileSync(path, value, { mode: 0o600 }); chownSync(path, uid, uid); };
const privateDirectory = path => { mkdirSync(path, { mode: 0o700 }); chownSync(path, uid, uid); };
for (const directory of ["home", "state", "workspace", "journal", "tmp"]) privateDirectory(join(agentRoot, directory));
privateWrite(join(agentRoot, "client-token"), clientToken + "\n");
const goal = "Fix retryLimit in src/retry.mjs: expected value seven, actual value zero. Implement the smallest change and test it; preserve unrelated behavior.";
let action = "submit", issued = false, phase = "", gateway, runtimeIdentity;
const catalogs = [], toolResults = [], failures = [];
const model = createServer(async (request, response) => {
  try {
    let body = ""; for await (const part of request) body += part;
    assert.ok(!body.includes(clientToken) && !body.includes(ownerToken), "private credentials entered the model context");
    const responseId = "chatcmpl-" + randomUUID();
    const input = JSON.parse(body), names = (input.tools ?? []).map(tool => tool.function?.name ?? tool.name).sort();
    catalogs.push({ phase, names }); assert.deepEqual(names, ["keep_status", "keep_submit"]);
    for (const message of input.messages ?? []) if (message.role === "tool") toolResults.push({ phase, text: message.content });
    const tool = !issued; issued = true;
    const delta = tool ? { role: "assistant", tool_calls: [{ index: 0, id: `${phase}-tool`, type: "function", function: { name: action === "submit" ? "keep_submit" : "keep_status", arguments: JSON.stringify(action === "submit" ? { goal } : {}) } }] } : { role: "assistant", content: "The Keep tool observation has been returned. Human decisions remain in Keep." };
    if (input.stream) {
      response.writeHead(200, { "content-type": "text/event-stream" });
      const send = data => response.write(`data: ${JSON.stringify(data)}\n\n`);
      send({ id: responseId, object: "chat.completion.chunk", model: "fixture", choices: [{ index: 0, delta, finish_reason: null }] });
      send({ id: responseId, object: "chat.completion.chunk", model: "fixture", choices: [{ index: 0, delta: {}, finish_reason: tool ? "tool_calls" : "stop" }], usage: { prompt_tokens: 10, completion_tokens: 3, total_tokens: 13 } });
      response.end("data: [DONE]\n\n");
    } else {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ id: responseId, object: "chat.completion", model: "fixture", choices: [{ index: 0, message: delta, finish_reason: tool ? "tool_calls" : "stop" }], usage: { prompt_tokens: 10, completion_tokens: 3, total_tokens: 13 } }));
    }
  } catch (error) { failures.push(String(error)); response.writeHead(400, { "content-type": "application/json" }); response.end('{"error":{"message":"controlled fixture refused request"}}'); }
});
const sessionId = randomUUID(), configPath = join(agentRoot, "openclaw.json");
const environment = { PATH: `${resolve(clawNode, "..") }:/usr/bin:/bin`, HOME: join(agentRoot, "home"), TMPDIR: join(agentRoot, "tmp"), OPENCLAW_HOME: join(agentRoot, "home"), OPENCLAW_STATE_DIR: join(agentRoot, "state"), OPENCLAW_CONFIG_PATH: configPath, OPENCLAW_NO_RESPAWN: "1", NO_COLOR: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" };
async function command(args, name) {
  const child = spawn("/usr/bin/setpriv", [`--reuid=${uid}`, `--regid=${uid}`, "--clear-groups", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", clawNode, ...args], { cwd: agentRoot, env: environment, detached: true, stdio: ["ignore", "pipe", "pipe"] });
  let output = "", error = ""; child.stdout.on("data", part => { output += part; }); child.stderr.on("data", part => { error += part; });
  const code = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { try { process.kill(-child.pid, "SIGKILL"); } catch {} reject(Error("owned consumer deadline elapsed")); }, 45000);
    child.once("error", error => { clearTimeout(timer); reject(error); }); child.once("close", code => { clearTimeout(timer); resolve(code); });
  });
  writeFileSync(join(root, `${name}.json`), JSON.stringify({ args, code, stdout: output, stderr: error }, null, 2), { mode: 0o600 });
  assert.equal(code, 0, `owned OpenClaw ${name} failed; retained private command receipt`); return output;
}
async function agent(next, name) {
  action = next; issued = false; phase = name;
  await command([join(claw, "openclaw.mjs"), "agent", "--local", "--agent", "keep-portfolio", "--session-id", sessionId, "--message", next === "submit" ? goal : "Inspect the original Keep job; do not submit another goal.", "--json"], name);
  assert.equal(failures.length, 0, "scripted model contract failed");
}
const counts = () => existsSync(callFile) ? JSON.parse(readFileSync(callFile, "utf8")).length : 0;
try {
  await new Promise(resolve => model.listen(0, "127.0.0.1", resolve));
  gateway = await startGatewayServer(app, { port: 0, token: ownerToken, restrictedClientProfile: profilePath });
  const config = { agents: { defaults: { model: { primary: "fixture/fixture" }, sandbox: { mode: "off" } }, entries: { "keep-portfolio": { workspace: join(agentRoot, "workspace") } } },
    tools: { allow: ["keep_submit", "keep_status"], toolSearch: false, codeMode: false },
    models: { providers: { fixture: { baseUrl: `http://127.0.0.1:${model.address().port}/v1`, apiKey: "controlled-local-fixture-only", api: "openai-completions", models: [{ id: "fixture", name: "Controlled local fixture", reasoning: false, input: ["text"], contextWindow: 32768, maxTokens: 2048, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } }] } } },
    plugins: { load: { paths: [join(claw, "../@redrookai/openclaw-keep")] }, entries: { keep: { enabled: true, config: { endpoint: gateway.origin, clientId: profile.clientId, grantId: profile.grantId, commandBinding: profile.commandBinding, openclawAgentId: "keep-portfolio", tokenFile: join(agentRoot, "client-token"), stateDirectory: join(agentRoot, "journal"), requestTimeoutMs: 5000 } } } },
  };
  privateWrite(configPath, JSON.stringify(config, null, 2));
  runtimeIdentity = JSON.parse(await command(["--input-type=module", "-e", `import assert from 'node:assert/strict';import fs from 'node:fs';assert.equal(process.getuid(),${uid});for(const p of ${JSON.stringify([join(keepRoot, "owner-token"), join(keepRoot, "codex-auth.fixture")])})assert.throws(()=>fs.accessSync(p,fs.constants.R_OK));assert.throws(()=>fs.accessSync(${JSON.stringify(source)},fs.constants.W_OK));console.log(JSON.stringify({version:process.versions.node,versions:process.versions,privateAccessRefused:true}));`], "permissions"));
  const [nodeMajor, nodeMinor, nodePatch] = runtimeIdentity.version.split(".").map(Number);
  assert.ok((nodeMajor === 24 && (nodeMinor > 18 || (nodeMinor === 18 && nodePatch >= 1)))
    || (nodeMajor === 26 && (nodeMinor > 5 || (nodeMinor === 5 && nodePatch >= 1))) || nodeMajor > 26,
    "selected OpenClaw runtime predates the plugin's published-security-fix floor");
  await agent("submit", "submit");
  const projects = app.projectManager.list(); assert.equal(projects.length, 1);
  const projectId = projects[0].id;
  let state;
  for (let i = 0; i < 100; i++) { state = app.projectManager.session(projectId).lastCheckpoint(); if (state?.status === "waiting-approval") break; await new Promise(resolve => setTimeout(resolve, 10)); }
  assert.equal(state?.status, "waiting-approval"); assert.equal(counts(), 0);
  const runId = state.runId, original = app.projectRuntime.commandForJob(runId, projectId);
  assert.equal(original.principal.grantId, profile.grantId);
  const request = async (path, body) => { const response = await fetch(gateway.origin + path, { method: "POST", headers: { authorization: `Bearer ${ownerToken}`, "content-type": "application/json" }, body: JSON.stringify(body) }); assert.equal(response.status, 200); return response.json(); };
  await request("/project/resume", { runId, approval: { decisionId: state.wait.decisionId, approved: true } });
  state = app.projectManager.session(projectId).lastCheckpoint();
  const evidence = state.artifacts.implement?.solve?.proposalEvidence;
  assert.ok(evidence?.checks.testsPassed); assert.equal(counts(), 2);
  assert.equal(readFileSync(join(source, "src/retry.mjs"), "utf8"), "export const retryLimit = 0;\n");
  await agent("status", "status-fresh-process"); assert.equal(app.projectManager.list().length, 1); assert.equal(counts(), 2);
  assert.ok(toolResults.some(result => result.phase === "status-fresh-process" && String(result.text).includes(runId)), "actual tool observation must reach the native OpenClaw consumer");
  await request("/project/merge", { runId, decision: "veto", proposalDigest: evidence.rollback.patchSha256 });
  await agent("status", "status-after-veto"); assert.equal(counts(), 2);
  const receipt = { status: "PASS", keepVersion: JSON.parse(readFileSync(join(installed, "package.json"))).version, openclawVersion: "2026.10.5", nodeVersion: runtimeIdentity.version, nodeComponents: runtimeIdentity.versions, nodeExecutableSha256: createHash("sha256").update(readFileSync(clawNode)).digest("hex"), runtimeSecurityAdmission: "separate release-admission record required", consumerUid: uid, projectId, runId,
    effectiveModelTools: catalogs, actualNativeCliToolDispatch: true, originalGrantPreserved: true, sourceUnchanged: true, proposalChecksPassed: true, freshProcessSameJob: true, ownerVetoRecorded: true, controlledCodexCalls: 2, liveAccountCalls: 0,
    scope: "Controlled installed consumer, scripted local model routes and explicit simulated owner decisions; not genuine Codex quality, production isolation or final release qualification." };
  writeFileSync(join(root, "result.json"), JSON.stringify(receipt, null, 2), { mode: 0o600 }); console.log(JSON.stringify(receipt));
} finally {
  writeFileSync(join(root, "observations.json"), JSON.stringify({ catalogs, failures }, null, 2), { mode: 0o600 });
  if (gateway) await gateway.close(); model.closeAllConnections(); await new Promise(resolve => model.close(resolve));
}
