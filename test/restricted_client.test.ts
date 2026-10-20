import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest } from "../src/gateway/http_gateway.js";
import { runOpenClawClientCommand } from "../src/cli/openclaw_client.js";
import { readRestrictedClientProfile } from "../src/gateway/restricted_client.js";
import { LocalFsWorkspace } from "../src/solve/workspace.js";

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "keep-restricted-")), source = join(root, "source"), workspace = join(root, "workspaces"), data = join(root, "data");
  const profile = join(root, "client.json"), tokenFile = join(root, "client-token"), calls = join(root, "calls.json"), executable = join(root, "codex-fixture");
  mkdirSync(source); mkdirSync(workspace); mkdirSync(join(source, "src"));
  writeFileSync(join(source, "src/retry.mjs"), "export const retryLimit = 0;\n");
  writeFileSync(join(source, "retry.test.mjs"), "import test from 'node:test';import assert from 'node:assert/strict';import {retryLimit} from './src/retry.mjs';test('limit',()=>assert.equal(retryLimit,7));\n");
  const git = (args: string[]) => execFileSync("git", ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", ...args], { cwd: source, encoding: "utf8" }).trim();
  git(["init", "--quiet", "--initial-branch=main"]); git(["add", "."]); git(["-c", "user.name=Keep Fixture", "-c", "user.email=keep@example.invalid", "commit", "--quiet", "-m", "fixture"]);
  writeFileSync(executable, `#!${process.execPath}
const fs=require('node:fs');let prompt='';process.stdin.on('data',b=>prompt+=b);process.stdin.on('end',()=>{
 const path=${JSON.stringify(calls)},calls=fs.existsSync(path)?JSON.parse(fs.readFileSync(path,'utf8')):[];calls.push(prompt);fs.writeFileSync(path,JSON.stringify(calls));
 const value=calls.length===2?{body:"assert.equal((await import('./src/retry.mjs')).retryLimit,7);"}:{action:"plan",rationale:"Correct limit",edits:[{file:"src/retry.mjs",search:"retryLimit = 0",replace:"retryLimit = 7",intent:"Correct limit"}]};
 for(const e of [{type:'thread.started',thread_id:'fixture'},{type:'turn.started'},{type:'item.completed',item:{type:'agent_message',text:JSON.stringify({text:JSON.stringify(value)})}},{type:'turn.completed',usage:{input_tokens:10,cached_input_tokens:0,output_tokens:5}}])console.log(JSON.stringify(e));
});`, { mode: 0o700 });
  const config = { dataDir: data, openclawClientProfile: profile,
    repositoryMaterialization: { sourceDir: source, workspaceBase: workspace, repoRef: "project", commit: git(["rev-parse", "HEAD"]), baseBranch: "main" }, sourceLanding: true,
    runtimePaths: { repository: source, workspace }, projectPosture: "autonomous" as const,
    testCommand: { command: process.execPath, args: ["--test", "--test-reporter=tap", "retry.test.mjs"], timeoutMs: 5000, cpuLimitSec: 2, maxOutputBytes: 16384, envAllowlist: [] },
    codexProject: { executable, executableSha256: createHash("sha256").update(readFileSync(executable)).digest("hex"), cliVersion: "codex-cli 0.163.0", model: "fixture-model", maxSubmittedPromptBytes: 65536, maxCapturedOutputBytes: 262144, maxElapsedMs: 5000, maxInvocations: 2, processing: "owner-public-repository" as const } };
  const app = composeKeep(config), owner = "owner-fixture-token";
  const call = (token: string, method: string, path: string, body?: unknown, query: Record<string, string> = {}) => handleGatewayRequest(app, { method, path, body: body ? JSON.stringify(body) : "", query, headers: { authorization: `Bearer ${token}` } }, { token: owner, restrictedClientProfile: profile });
  const issue = () => runOpenClawClientCommand(app, ["issue", `--profile=${profile}`, `--token-file=${tokenFile}`, "--agent-id=openclaw-fixture", `--expires-at=${new Date(Date.now() + 60_000).toISOString()}`], true, () => {});
  const count = () => existsSync(calls) ? JSON.parse(readFileSync(calls, "utf8")).length : 0;
  return { root, source, data, config, app, owner, call, issue, profile, tokenFile, count };
}
async function waitForCheckpoint(f: ReturnType<typeof fixture>, projectId: string, runId: string) {
  for (let i = 0; i < 200; i++) {
    const response = await f.call(f.owner, "GET", "/project", undefined, { runId });
    if (response.status === 200 && f.app.projectRuntime!.job(runId)?.state === "completed") return JSON.parse(response.body);
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  throw new Error(`owned fixture did not reach a checkpoint: ${projectId}`);
}

test("restricted native submission, durable replay, exact human approval and own-work proposal use the original grant", async () => {
  const f = fixture();
  try {
    assert.equal(await f.issue(), 0);
    const token = readFileSync(f.tokenFile, "utf8").trim();
    const request = { goal: "Fix retryLimit in src/retry.mjs: expected value seven, actual value zero. Implement the smallest change and test it; preserve unrelated behavior.", idempotencyKey: "openclaw-controlled-submission-001" };
    for (const path of ["/project/resume", "/project/merge", "/project/revert", "/delegation/issue", "/worker/resume", "/config"]) assert.equal((await f.call(token, "POST", path, {})).status, 403);
    assert.equal((await f.call(token, "GET", "/projects")).status, 403);
    assert.equal((await f.call(token, "POST", "/project", { ...request, posture: "autonomous" })).status, 400);
    const declined = JSON.parse((await f.call(token, "POST", "/project", { ...request, idempotencyKey: "openclaw-declined-submission-001" })).body);
    const held = await waitForCheckpoint(f, declined.projectId, declined.runId);
    const decline = { runId: declined.runId, approval: { decisionId: held.project.wait.decisionId, approved: false } };
    assert.equal((await f.call(f.owner, "POST", "/project/resume", decline)).status, 200);
    assert.equal(JSON.parse((await f.call(token, "GET", "/project/jobs", undefined, { jobId: declined.jobId })).body).review.generationDecision, "declined");
    assert.equal((await f.call(f.owner, "POST", "/project/resume", { ...decline, approval: { ...decline.approval, approved: true } })).status, 409);
    assert.equal(f.count(), 0);
    const unrelated = JSON.parse((await f.call(f.owner, "POST", "/project", { ...request, background: true, posture: "approval-required", idempotencyKey: "owner-unrelated-submission-001" })).body);
    await waitForCheckpoint(f, unrelated.projectId, unrelated.runId);
    assert.equal((await f.call(token, "GET", "/project/jobs", undefined, { jobId: unrelated.jobId })).status, 404);
    const accepted = await f.call(token, "POST", "/project", request); assert.equal(accepted.status, 202);
    const job = JSON.parse(accepted.body), before = await waitForCheckpoint(f, job.projectId, job.runId);
    assert.equal(before.project.status, "waiting-approval"); assert.equal(f.count(), 0);
    const command = f.app.projectRuntime!.commandForJob(job.jobId, job.projectId), grant = readRestrictedClientProfile(f.profile);
    assert.equal(command.principal.kind, "agent"); assert.equal(command.principal.grantId, grant.grantId); assert.equal(command.posture, "approval-required");
    const replay = JSON.parse((await f.call(token, "POST", "/project", request)).body); assert.equal(replay.jobId, job.jobId); assert.equal(replay.replayed, true);
    assert.equal((await f.call(token, "POST", "/project", { ...request, goal: "Different request" })).status, 409);
    const own = await f.call(token, "GET", "/project/jobs", undefined, { jobId: job.jobId }); assert.equal(own.status, 200); assert.ok(!own.body.includes('"history"')); assert.ok(!own.body.includes(token));
    assert.equal(JSON.parse(own.body).review.generationDecision, null);
    const decision = { runId: job.runId, approval: { decisionId: before.project.wait.decisionId, approved: true } };
    assert.equal((await f.call(f.owner, "POST", "/project/resume", { ...decision, approval: { decisionId: "wrong-decision", approved: true } })).status, 409);
    assert.equal((await f.call(token, "POST", "/project/resume", decision)).status, 403);
    const approved = await f.call(f.owner, "POST", "/project/resume", decision); assert.equal(approved.status, 200, approved.body);
    const final = JSON.parse((await f.call(f.owner, "GET", "/project", undefined, { runId: job.runId })).body);
    assert.equal(final.requester.id, command.principal.id); assert.equal(final.decisionHistory.at(-1).humanPrincipalId, "owner");
    assert.ok(final.proposal, JSON.stringify(final)); assert.equal(final.proposal.checks.testsPassed, true); assert.equal(f.count(), 2);
    assert.equal(readFileSync(join(f.source, "src/retry.mjs"), "utf8"), "export const retryLimit = 0;\n");
    assert.deepEqual(f.app.projectRuntime!.commandForJob(job.jobId, job.projectId).principal, command.principal);
    assert.ok(f.app.spine.replay().some(e => e.actor === "openclaw-client" && e.payload["humanPrincipalId"] === "owner" && e.payload["grantId"] === grant.grantId));
    const status = JSON.parse((await f.call(token, "GET", "/project/jobs", undefined, { jobId: job.jobId })).body);
    assert.equal(status.proposal.available, true); assert.equal(status.proposal.digest, final.proposal.rollback.patchSha256);
    assert.equal(status.review.generationDecision, "approved");
    const wrongVeto = await f.call(f.owner, "POST", "/project/merge", { runId: job.runId, decision: "veto", proposalDigest: "b".repeat(64) });
    assert.equal(JSON.parse(wrongVeto.body).status, "refused");
    const afterWrong = JSON.parse((await f.call(token, "GET", "/project/jobs", undefined, { jobId: job.jobId })).body);
    assert.equal(afterWrong.review.vetoed, false, "wrong digest cannot become a durable veto");
    const veto = await f.call(f.owner, "POST", "/project/merge", { runId: job.runId, decision: "veto", proposalDigest: final.proposal.rollback.patchSha256 });
    assert.equal(JSON.parse(veto.body).decision, "veto");
    assert.equal(JSON.parse((await f.call(token, "GET", "/project/jobs", undefined, { jobId: job.jobId })).body).review.vetoed, true);
    const restarted = composeKeep(f.config);
    const observed = await handleGatewayRequest(restarted, { method: "POST", path: "/project", query: {}, body: JSON.stringify(request), headers: { authorization: `Bearer ${token}` } }, { token: f.owner, restrictedClientProfile: f.profile });
    assert.equal(JSON.parse(observed.body).jobId, job.jobId); assert.equal(f.count(), 2);
    const drifted = composeKeep({ ...f.config, codexProject: { ...f.config.codexProject, model: "changed-fixture-model" } });
    assert.equal((await handleGatewayRequest(drifted, { method: "GET", path: "/project/jobs", query: { jobId: job.jobId }, body: "", headers: { authorization: `Bearer ${token}` } }, { token: f.owner, restrictedClientProfile: f.profile })).status, 401);
    assert.equal(f.count(), 2);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("revocation, expiry, unrelated jobs and source drift refuse without generation; revocation needs no Codex login", async () => {
  const f = fixture();
  try {
    assert.equal(await f.issue(), 0); const token = readFileSync(f.tokenFile, "utf8").trim();
    const accepted = JSON.parse((await f.call(token, "POST", "/project", { goal: "Fix retryLimit in src/retry.mjs: expected seven, actual zero.", idempotencyKey: "restricted-drift-request-001" })).body);
    const before = await waitForCheckpoint(f, accepted.projectId, accepted.runId);
    assert.equal((await f.call(token, "GET", "/project/jobs", undefined, { jobId: "unrelated-job" })).status, 404);
    assert.equal((await f.call(token, "GET", "/project/jobs")).status, 400);
    writeFileSync(join(f.source, "src/retry.mjs"), "export const retryLimit = 9;\n");
    await f.call(f.owner, "POST", "/project/resume", { runId: accepted.runId, approval: { decisionId: before.project.wait.decisionId, approved: true } });
    assert.equal(f.count(), 0, "drifted source must not reach generation");
    const profile = readRestrictedClientProfile(f.profile); writeFileSync(f.profile, JSON.stringify({ ...profile, expiresAt: Date.now() - 1 }), { mode: 0o600 });
    assert.equal((await f.call(token, "GET", "/project/jobs", undefined, { jobId: accepted.jobId })).status, 401);
    writeFileSync(f.profile, JSON.stringify(profile), { mode: 0o600 });
    writeFileSync(join(f.data, "owner-token"), "a".repeat(64) + "\n", { mode: 0o600 });
    const revoked = spawnSync(process.execPath, [resolve("dist/src/main.js"), "openclaw-client", "revoke", `--profile=${f.profile}`], { encoding: "utf8", env: { PATH: process.env["PATH"], KEEP_DATA_DIR: f.data, KEEP_PROJECT_MODEL: "codex", KEEP_CODEX_EXECUTABLE: "/missing-must-not-preflight" } });
    assert.equal(revoked.status, 0, revoked.stdout + revoked.stderr);
    assert.equal((await f.call(token, "GET", "/project/jobs", undefined, { jobId: accepted.jobId })).status, 401);
    assert.equal(f.count(), 0);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("revocation during an awaited stage after human approval prevents native generation", async () => {
  const f = fixture(), originalFiles = LocalFsWorkspace.prototype.files;
  let revokeOnRead = false;
  try {
    assert.equal(await f.issue(), 0); const token = readFileSync(f.tokenFile, "utf8").trim();
    const accepted = JSON.parse((await f.call(token, "POST", "/project", { goal: "Fix retryLimit in src/retry.mjs: expected seven, actual zero.", idempotencyKey: "restricted-revocation-window-001" })).body);
    const before = await waitForCheckpoint(f, accepted.projectId, accepted.runId);
    assert.equal(before.project.status, "waiting-approval");
    // Fault injection inside this test process preserves the native composition and
    // real filesystem adapter; a custom localizer would intentionally disable that path.
    revokeOnRead = true;
    LocalFsWorkspace.prototype.files = async function (...args) {
      const files = await originalFiles.apply(this, args);
      if (revokeOnRead && this.authorityRoot().startsWith(f.root)) { revokeOnRead = false; await f.app.authorization.revoke(readRestrictedClientProfile(f.profile).grantId); }
      return files;
    };
    await f.call(f.owner, "POST", "/project/resume", { runId: accepted.runId, approval: { decisionId: before.project.wait.decisionId, approved: true } });
    assert.equal(revokeOnRead, false, "the revocation window was actually entered");
    assert.equal(f.count(), 0, "original grant is rechecked after the awaited stage, before generation");
    assert.ok(f.app.spine.replay().some(e => e.actor === "openclaw-client" && e.payload["approved"] === true));
  } finally { LocalFsWorkspace.prototype.files = originalFiles; rmSync(f.root, { recursive: true, force: true }); }
});
