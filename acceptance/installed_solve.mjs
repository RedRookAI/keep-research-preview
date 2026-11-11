/** IS001: actual installed CLI, controlled loopback responses; no live model qualification. */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { createHash } from "node:crypto";
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
const revision = git(["rev-parse", "HEAD"]), calls = [], errors = [];
const model = createServer(async (req, res) => {
  try {
    assert.equal(req.url, "/chat/v1/chat/completions"); assert.equal(req.headers.authorization, "Bearer controlled-fixture-only");
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8")); assert.equal(body.model, "gpt-5.4-mini");
    const prompt = body.messages[0].content; calls.push(prompt); writeFileSync(join(root, "model-calls.json"), JSON.stringify(calls));
    const value = calls.length === 2
      ? { body: "assert.equal((await import('./src/retry.mjs')).retryLimit,7);" }
      : { action: "plan", rationale: "Correct the retry limit", edits: [{ file: "src/retry.mjs", search: "retryLimit = 0", replace: "retryLimit = 7", intent: "Correct limit" }] };
    assert.ok(calls.length <= 2, "no hidden retries");
    res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ model: body.model, choices: [{ message: { content: JSON.stringify(value) }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1 } }));
  } catch (e) { errors.push(String(e)); res.destroy(); }
});
await new Promise(resolve => model.listen(0, "127.0.0.1", resolve));
// A synthetic endpoint uses a pricing identity already known to the automated-solve ledger.
// No OpenAI request or price-quality claim: an unknown remote price correctly refuses before wire.
const env = { ...base, KEEP_PROVIDER: "openai-compatible", KEEP_PROVIDER_AUTHORITY: "owner", KEEP_PROVIDER_LOCATION: "local", KEEP_PROVIDER_BASE_URL: `http://127.0.0.1:${model.address().port}/chat`, KEEP_PROVIDER_MODEL: "gpt-5.4-mini", KEEP_PROVIDER_API_KEY: "controlled-fixture-only", KEEP_REMOTE_PROCESSING_PURPOSE: "software-development", KEEP_REMOTE_PROCESSING_REGION: "local", KEEP_REPOSITORY: source, KEEP_WORKSPACE_BASE: workspaces, KEEP_REVISION: revision, KEEP_REPO_REF: "project", KEEP_TEST_COMMAND: process.execPath, KEEP_TEST_ARGS_JSON: JSON.stringify(["--test", "--test-reporter=tap", "retry.test.mjs"]), KEEP_TEST_TIMEOUT_MS: "5000", KEEP_TEST_CPU_LIMIT_SEC: "2", KEEP_TEST_MAX_OUTPUT_BYTES: "16384", KEEP_DATA_DIR: data, KEEP_PROJECT_POSTURE: "autonomous" };
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
  let text = "", stderr = ""; worker.stderr.on("data", b => { stderr += b; });
  return new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error("worker setup: " + stderr + text)), 20000); worker.stdout.on("data", b => { text += b; const match = /http:\/\/127\.0\.0\.1:\d+/u.exec(text); if (match) { clearTimeout(timer); resolve(match[0]); } }); worker.once("exit", code => { clearTimeout(timer); reject(new Error("worker refused " + code + ": " + stderr + text)); }); });
}
async function stop() { if (!worker) return; const w = worker; worker = undefined; const ended = new Promise(resolve => w.once("exit", resolve)); w.kill("SIGTERM"); await ended; }
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
  // Reuse this retained proposal: export and offline inspection must never regenerate it.
  const sha256 = value => createHash("sha256").update(value).digest("hex");
  const exportPath = "/project/export?" + new URLSearchParams({ runId, proposalDigest: digest });
  const exportRequest = (path = exportPath, bearer = token) => fetch(origin + path, {
    headers: { authorization: "Bearer " + bearer }, signal: AbortSignal.timeout(5000),
  });
  const exportResponse = await exportRequest(); assert.equal(exportResponse.status, 200);
  assert.equal(exportResponse.headers.get("cache-control"), "no-store");
  const exportText = await exportResponse.text(), exported = JSON.parse(exportText);
  assert.equal(exported.schema, "keep.proposal-export/v1");
  assert.equal(exported.assurance, "unsigned-retained-evidence");
  assert.equal(exported.data.runId, runId); assert.equal(exported.data.projectId, result.projectId);
  assert.equal(exported.data.proposal.baseRevision, revision);
  assert.equal(exported.data.proposal.diff, result.proposal.diff);
  assert.equal(exported.data.proposal.patchSha256, digest); assert.equal(sha256(exported.data.proposal.diff), digest);
  assert.deepEqual(exported.data.proposal.checks, { testsPassed: true, vettingCleared: true,
    passedTests: result.proposal.checks.passedTests, failedTests: [] });
  assert.equal(exported.data.requester.kind, "human"); assert.equal(exported.data.requester.idSha256, sha256("owner"));
  assert.equal(exported.data.exporterIdSha256, sha256("owner"));
  for (const privateValue of [token, "controlled-fixture-only", root, source, workspaces, data]) assert.ok(!exportText.includes(privateValue), "portable export excludes fixture credentials and host paths");
  assert.equal((await exportRequest(exportPath, "d".repeat(64))).status, 401);
  const wrongDigest = digest === "0".repeat(64) ? "1".repeat(64) : "0".repeat(64);
  assert.equal((await exportRequest("/project/export?" + new URLSearchParams({ runId, proposalDigest: wrongDigest }))).status, 409);
  const cliExport = await command(["project", "export", runId, "--proposal=" + digest], remote());
  assert.deepEqual(JSON.parse(cliExport), exported);
  const savedExport = join(root, "proposal-export.json"); writeFileSync(savedExport, cliExport, { mode: 0o600 });

  // Use the browser's normal form login and cookie; no credential in a URL.
  const signIn = await fetch(origin + "/console/login", { method: "POST", redirect: "manual",
    headers: { origin, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token }), signal: AbortSignal.timeout(5000) });
  assert.equal(signIn.status, 303);
  const setCookie = signIn.headers.get("set-cookie"); assert.ok(setCookie);
  assert.match(setCookie, /HttpOnly/u); assert.match(setCookie, /SameSite=Strict/u);
  const cookie = setCookie.split(";")[0];
  const consolePage = await fetch(origin + "/console/project?" + new URLSearchParams({ projectId: result.projectId }), {
    headers: { cookie }, signal: AbortSignal.timeout(5000),
  });
  assert.equal(consolePage.status, 200); const consoleText = await consolePage.text();
  assert.ok(consoleText.includes("/console/export?runId=")); assert.ok(consoleText.includes(digest)); assert.ok(!consoleText.includes(token));
  const attachment = await fetch(origin + "/console/export?" + new URLSearchParams({ runId, proposalDigest: digest }), {
    headers: { cookie }, signal: AbortSignal.timeout(5000),
  });
  assert.equal(attachment.status, 200); assert.match(attachment.headers.get("content-disposition") ?? "", /attachment/u);
  assert.match(attachment.headers.get("content-type") ?? "", /application\/json/u);
  assert.equal(attachment.headers.get("cache-control"), "no-store");
  assert.deepEqual(JSON.parse(await attachment.text()), exported);

  // No provider/data configuration is supplied to these actual offline CLI commands.
  assert.equal(git(["status", "--porcelain"]), "");
  const indexBefore = readFileSync(join(source, ".git/index"));
  const verified = await command(["proposal", "verify", savedExport, "--repository=" + source], base);
  assert.match(verified, /recorded clean source and patch check match/u);
  const patch = await command(["proposal", "patch", savedExport], base);
  assert.deepEqual(Buffer.from(patch, "utf8"), Buffer.from(result.proposal.diff, "utf8"));
  assert.equal(sha256(patch), digest); writeFileSync(join(root, "proposal.patch"), patch, { mode: 0o600 });
  assert.deepEqual(readFileSync(join(source, ".git/index")), indexBefore, "offline verification preserves the index");
  const originalBytes = readFileSync(join(source, "src/retry.mjs"));
  try {
    writeFileSync(join(source, "src/retry.mjs"), "export const retryLimit = 1;\n");
    const refused = await command(["proposal", "verify", savedExport, "--repository=" + source], base, 2);
    assert.match(refused, /repository must be clean/u);
    assert.equal(readFileSync(join(source, "src/retry.mjs"), "utf8"), "export const retryLimit = 1;\n", "refused inspection leaves changed source untouched");
  } finally { writeFileSync(join(source, "src/retry.mjs"), originalBytes); }
  assert.equal(git(["rev-parse", "HEAD"]), revision); assert.equal(git(["status", "--porcelain"]), "");
  assert.deepEqual((await observe()).proposal, restored.proposal); assert.equal(calls.length, beforeRestart);
  const decision = await command(["merge", runId, "veto", "--proposal=" + digest], remote());
  const afterVetoResponse = await exportRequest(); assert.equal(afterVetoResponse.status, 200);
  const afterVeto = await afterVetoResponse.json();
  assert.ok(afterVeto.data.decisions.some(d => d.event === "project.human-proposal-decision" && d.decision === "veto"
    && d.proposalDigest === digest && d.humanIdSha256 === sha256("owner") && d.status === "refused"));
  assert.deepEqual(afterVeto.data.proposal, exported.data.proposal); assert.equal(calls.length, beforeRestart);
  assert.deepEqual(errors, []); assert.equal(calls.length, 2);
  assert.equal(readFileSync(join(source, "src/retry.mjs"), "utf8"), "export const retryLimit = 0;\n");
  const proposalExport = { status: "PASS", schema: exported.schema, proposalDigest: digest, baseRevision: revision,
    authenticatedHttp: true, wrongTokenRefused: true, wrongDigestRefused: true, installedCliExport: true,
    consoleFormLoginAttachment: true, offlineCleanSourceVerified: true, exactPatchBytes: true, changedSourceRefused: true,
    retainedSimulatedVetoAttribution: true, addedModelCalls: calls.length - beforeRestart, assurance: exported.assurance };
  const receipt = { status: "PASS", root, runId, diff: result.proposal.diff, version: JSON.parse(readFileSync(join(installed, "package.json"))).version, installed, configuredPosture: "autonomous", solvePosture: "approval-required", localInstalledStart: true, explicitApprovalBeforeDispatch: true, reviewableProposal: true, passedTests: result.proposal.checks.passedTests, artifactVettingPassed: true, processIsolationEvidence: result.project.artifacts.vet_artifact.isolation, solved: true, controlledModelCalls: calls.length, sourceUnchanged: true, restartNoReplay: true, wrongTokenRefused: true, explicitVetoOutput: decision, proposalExport, paidCalls: 0, modelResponses: "scripted-loopback", operatorDecisions: "simulated approval then exact-proposal veto", limits: "Controlled model responses and simulated owner decisions; same-agent Linux fixture with best-effort process isolation, not real-model quality, a genuine owner/account run or production qualification." };
  writeFileSync(join(root, "result.json"), JSON.stringify(receipt, null, 2)); console.log(JSON.stringify(receipt));
} finally { await stop(); model.closeAllConnections(); await new Promise(resolve => model.close(resolve)); }
