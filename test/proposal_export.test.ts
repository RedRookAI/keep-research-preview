import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest, type GatewaySecurity } from "../src/gateway/http_gateway.js";
import { createProposalExport, verifyProposalExport } from "../src/audit/proposal_export.js";
import { runProposalCommand } from "../src/cli/proposal.js";
import { runGatewayCli, runStaticCli } from "../src/cli/cli_core.js";
import { handleProjectConsole } from "../src/review/project_console.js";

const hash = (s: string) => createHash("sha256").update(s).digest("hex");
const diff = "diff --git a/calc.mjs b/calc.mjs\n--- a/calc.mjs\n+++ b/calc.mjs\n@@ -1 +1 @@\n-export const sum = (a,b) => a-b;\n+export const sum = (a,b) => a+b;\n";
function sample(patch = diff) {
  return { projectId: "p1", runId: "r1", exporterId: "owner", evidence: { baseRevision: "a".repeat(40), diff: patch,
    rollback: { patchSha256: hash(patch) }, checks: { testsPassed: false, vettingCleared: false, passedTests: ["positive"], failures: ["negative"], detail: "PRIVATE DIAGNOSTIC" } },
    requester: { kind: "agent", id: "original-agent", secret: "PRIVATE SECRET" },
    decisions: [{ event: "local_merge.refused", decision: "veto" }, { event: "project.human-proposal-decision", decision: "veto", humanPrincipalId: "alice", proposalDigest: hash(patch) }],
    delivery: { workspace: { status: "unknown", path: "/private/workspace" }, source: { merge: { status: "refused" }, revert: { status: "unknown" } } }, forbiddenValues: ["PRIVATE SECRET"] };
}

test("portable projection preserves failed check names and attributable decisions without private diagnostics", () => {
  const bundle = createProposalExport(sample()), serialized = JSON.stringify(bundle);
  assert.deepEqual(bundle.data.proposal.checks.failedTests, ["negative"]);
  assert.equal(bundle.data.requester.idSha256, hash("original-agent"));
  assert.equal(bundle.data.decisions[0]!.humanIdSha256, null, "old unknown attribution remains unknown");
  assert.equal(bundle.data.decisions[1]!.humanIdSha256, hash("alice"));
  assert.equal(bundle.data.delivery.sourceMerge, "refused");
  assert.doesNotMatch(serialized, /PRIVATE|\/private|original-agent|alice/u);
  assert.deepEqual(verifyProposalExport(serialized), bundle);
  const changed = JSON.parse(serialized); changed.data.proposal.checks.testsPassed = true;
  assert.throws(() => verifyProposalExport(JSON.stringify(changed)), /integrity/u);
  const extra = JSON.parse(serialized); extra.data.privatePrompt = "unrecognized";
  assert.throws(() => verifyProposalExport(JSON.stringify(extra)), /integrity/u);
});

test("unsafe exact patches and mismatched retained identities refuse without redaction", () => {
  for (const privateText of ["PRIVATE SECRET", "/root/private/project", "/home/alice/secret", "Bearer synthetic-token", "-----BEGIN PRIVATE KEY-----", "C:\\private\\file", "password=secretvalue", "ghp_syntheticcredential"]) {
    assert.throws(() => createProposalExport(sample(diff + "+" + privateText + "\n")), /credential|host path/u);
  }
  const input = sample(); input.evidence.rollback.patchSha256 = "0".repeat(64);
  assert.throws(() => createProposalExport(input), /digest mismatch/u);
  for (const path of [".env", "../escape", ".git/config", "key.pem", '"quoted"']) {
    assert.throws(() => createProposalExport(sample(diff.replaceAll("calc.mjs", path))), /path/u);
  }
});

test("actual retained repository proposal exports read-only and verifies only its exact clean source", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-proposal-export-"));
  const source = join(root, "source"), workspaces = join(root, "workspaces"), token = "synthetic-export-owner-token";
  mkdirSync(source); mkdirSync(workspaces);
  const git = (...args: string[]): string => execFileSync("git", ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", ...args], {
    cwd: source, encoding: "utf8", timeout: 5000, env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_AUTHOR_NAME: "Fixture", GIT_AUTHOR_EMAIL: "fixture@example.invalid", GIT_COMMITTER_NAME: "Fixture", GIT_COMMITTER_EMAIL: "fixture@example.invalid" },
  }).trim();
  try {
    writeFileSync(join(source, "calc.mjs"), "export const sum = (a,b) => a-b;\n");
    writeFileSync(join(source, "repo.test.mjs"), "import test from 'node:test';import assert from 'node:assert/strict';import {sum} from './calc.mjs';test('arithmetic',()=>assert.equal(sum(2,3),5));\n");
    git("init", "-q", "-b", "main"); git("add", "-A"); git("commit", "-qm", "base");
    const base = git("rev-parse", "HEAD"); let generations = 0;
    const app = composeKeep({ dataDir: join(root, "state"), sourceLanding: true,
      repositoryMaterialization: { sourceDir: source, workspaceBase: workspaces, repoRef: "project", commit: base, baseBranch: "main" },
      testCommand: { command: process.execPath, args: ["--test", "repo.test.mjs"], timeoutMs: 5000 },
      developmentProvider: { name: "scripted-export-fixture", isLocal: true, embed: async () => [], generate: async request => {
        generations++; const goalTest = request.hints?.["taskRole"] === "goal_test";
        const value = goalTest ? { body: "const {pathToFileURL}=await import('node:url');const {join}=await import('node:path');const {sum}=await import(pathToFileURL(join(process.cwd(),'calc.mjs')));assert.equal(sum(2,3),5);" }
          : { action: "plan", rationale: "arithmetic correction", edits: [{ file: "calc.mjs", search: "a-b", replace: "a+b", intent: "add operands" }] };
        return { text: JSON.stringify(value), model: "scripted", tokensIn: 1, tokensOut: 1 };
      } } });
    const headers = { authorization: `Bearer ${token}` }, sec: GatewaySecurity = { token };
    const started = await handleGatewayRequest(app, { method: "POST", path: "/project", query: {}, headers, body: JSON.stringify({ goal: "Fix sum in calc.mjs to add its two numeric operands. Preserve all other files." }) }, sec);
    assert.equal(started.status, 200, started.body);
    const run = JSON.parse(started.body), project = app.projectManager!.session(run.projectId).inspect().checkpoint!;
    const evidence = (project.artifacts["implement"] as { solve: { proposalEvidence: { rollback: { patchSha256: string } } } }).solve.proposalEvidence;
    const proposalDigest = evidence.rollback.patchSha256;
    const exportRequest = { method: "GET", path: "/project/export", query: { runId: run.runId, proposalDigest }, headers, body: "" };
    const before = JSON.stringify(app.spine.currentEvents()), callsBefore = generations;
    const exported = await handleGatewayRequest(app, exportRequest, sec);
    assert.equal(exported.status, 200, exported.body);
    assert.equal(JSON.stringify(app.spine.currentEvents()), before, "export does not stage or seal evidence");
    const bundle = verifyProposalExport(exported.body);
    assert.equal(bundle.data.proposal.baseRevision, base);
    assert.equal(bundle.data.proposal.patchSha256, proposalDigest);
    assert.equal(bundle.data.proposal.checks.testsPassed, true);
    assert.equal(bundle.data.requester.kind, "human");
    assert.doesNotMatch(exported.body, new RegExp(token + "|" + root.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
    assert.equal((await handleGatewayRequest(app, { ...exportRequest, headers: {} }, sec)).status, 401);
    assert.equal((await handleGatewayRequest(app, { ...exportRequest, query: { ...exportRequest.query, proposalDigest: "0".repeat(64) } }, sec)).status, 409);
    assert.equal((await handleGatewayRequest(app, exportRequest, { token, principalFor: () => ({ id: "viewer", kind: "human", role: "viewer", tenant: "test" }) })).status, 403);
    assert.equal((await handleGatewayRequest(app, exportRequest, { token, principalFor: () => ({ id: "agent", kind: "agent", role: "owner", tenant: "test" }) })).status, 403);
    assert.equal((await handleGatewayRequest(app, exportRequest, { token, principalFor: () => ({ id: "foreign-owner", kind: "human", role: "owner", tenant: "foreign" }) })).status, 404);
    assert.equal((await handleGatewayRequest(app, { method: "POST", path: "/project/merge", query: {}, headers,
      body: JSON.stringify({ runId: run.runId, decision: "approve", proposalDigest }) }, { token, principalFor: () => ({ id: "agent", kind: "agent", role: "owner", tenant: "test" }) })).status, 403);
    const out: string[] = [], io = { write: (s: string) => { out.push(s); }, error: (s: string) => { out.push(s); }, prompt: async () => "" };
    const cli = await runGatewayCli(["project", "export", run.runId, `--proposal=${proposalDigest}`], io, {
      gateway: request => handleGatewayRequest(app, request, sec), gatewayToken: token,
    });
    assert.equal(cli.exitCode, 0); assert.deepEqual(verifyProposalExport(out.pop()!), bundle);
    const attachment = await handleProjectConsole({ method: "GET", path: "/console/export", query: exportRequest.query, headers: {}, body: "" }, "csrf", async (method, path, query) => handleGatewayRequest(app, { ...exportRequest, method, path, query: query ?? {} }, sec), { approve: true, decline: true });
    assert.equal(attachment.status, 200); assert.match(attachment.headers["Content-Disposition"]!, /attachment/u);
    const path = join(root, "export.json"), invoked = join(root, "repository-command-ran"), monitor = join(root, "monitor"); writeFileSync(path, exported.body);
    writeFileSync(monitor, `#!/bin/sh\ntouch '${invoked}'\n`, { mode: 0o700 });
    git("config", "core.fsmonitor", monitor);
    const index = join(source, ".git/index"), indexBefore = readFileSync(index), indexTime = statSync(index).mtimeMs;
    assert.equal(runProposalCommand(["verify", path, `--repository=${source}`], s => out.push(s)), 0);
    assert.deepEqual(readFileSync(index), indexBefore); assert.equal(statSync(index).mtimeMs, indexTime);
    assert.equal(existsSync(invoked), false, "local fsmonitor is not invoked");
    git("config", "--unset", "core.fsmonitor");
    git("config", "filter.fixture.clean", monitor);
    assert.equal(runProposalCommand(["verify", path, `--repository=${source}`], s => out.push(s)), 2);
    assert.match(out.pop()!, /clean filters require separate inspection/u);
    assert.equal(existsSync(invoked), false, "filter commands are refused before repository inspection");
    git("config", "--remove-section", "filter.fixture");
    assert.equal(git("status", "--porcelain"), ""); assert.equal(git("rev-parse", "HEAD"), base);
    assert.equal(runStaticCli(["proposal", "patch", path], s => out.push(s))?.exitCode, 0);
    assert.equal(out.pop(), bundle.data.proposal.diff);
    writeFileSync(join(source, "untracked"), "changed");
    assert.equal(runProposalCommand(["verify", path, `--repository=${source}`], s => out.push(s)), 2);
    git("add", "-A"); git("commit", "-qm", "another revision");
    assert.equal(runProposalCommand(["verify", path, `--repository=${source}`], s => out.push(s)), 2);
    assert.match(out.pop()!, /HEAD differs/u);
    const veto = await handleGatewayRequest(app, { method: "POST", path: "/project/merge", query: {}, headers,
      body: JSON.stringify({ runId: run.runId, decision: "veto", proposalDigest }) }, sec);
    assert.equal(veto.status, 200);
    const afterVeto = verifyProposalExport((await handleGatewayRequest(app, exportRequest, sec)).body);
    assert.ok(afterVeto.data.decisions.some(d => d.decision === "veto" && d.humanIdSha256 === hash("owner")));
    assert.equal(afterVeto.data.delivery.sourceMerge, "unknown");
    assert.equal(generations, callsBefore, "export/inspection/decision never regenerate");
    assert.equal(readFileSync(join(source, "calc.mjs"), "utf8"), "export const sum = (a,b) => a-b;\n");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
