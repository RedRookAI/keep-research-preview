/** Actual local composed native command admission; no live issuer/model or release qualification. */
import test, { type TestContext } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest } from "../src/gateway/http_gateway.js";
import { OidcCodeFlow, captureOidcLoginConfig } from "../src/identity/oidc_code_flow.js";
import { PrincipalRegistry } from "../src/identity/identity_provider.js";
import { SessionStore } from "../src/identity/session_store.js";
import type { ModelProvider } from "../src/gateway/gateway.js";

const issuer = "https://issuer.fixture.invalid/", token = "synthetic-gateway", original = "export function add(a,b){return a - b;}\n";
const principal = { id: "alice", kind: "human" as const, role: "maintainer" as const, tenant: "alpha" };
function git(cwd: string, ...args: string[]) { return execFileSync("git", ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", ...args], { cwd, encoding: "utf8", timeout: 5000,
  env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_AUTHOR_NAME: "Fixture", GIT_AUTHOR_EMAIL: "fixture@example.invalid", GIT_COMMITTER_NAME: "Fixture", GIT_COMMITTER_EMAIL: "fixture@example.invalid" } }).trim(); }
function fixture(t: TestContext, mode: "control" | "revoke-inflight" | "queued" | "custom" | "strong-boundary" = "control") {
  const root = mkdtempSync(join(tmpdir(), "keep-org-admission-")), source = join(root, "source"), workspaceBase = join(root, "workspaces"); mkdirSync(source); mkdirSync(workspaceBase);
  t.after(() => rmSync(root, { recursive: true, force: true })); writeFileSync(join(source, "calc.mjs"), original);
  writeFileSync(join(source, "repo.test.mjs"), "import test from 'node:test'; import assert from 'node:assert/strict'; import {add} from './calc.mjs'; test('sum',()=>assert.equal(add(2,3),5));\n");
  git(source, "init", "-q", "-b", "main"); git(source, "add", "-A"); git(source, "commit", "-qm", "base");
  const secretFile = join(root, "secret"); writeFileSync(secretFile, "synthetic", { mode: 0o600 });
  const login = captureOidcLoginConfig({ clientId: "fixture", authorizationEndpoint: `${issuer}authorize`, tokenEndpoint: `${issuer}token`, jwksUri: `${issuer}keys`, publicOrigin: "https://keep.fixture.invalid", redirectUri: "https://keep.fixture.invalid/auth/oidc/callback", clientSecretFile: secretFile,
    transactionTtlMs: 60000, maxTransactions: 4, requestTimeoutMs: 1000, maxResponseBytes: 8192, leewaySec: 0, sessionIdleMs: 60000, sessionAbsoluteMs: 120000, maxSessions: 4 }, "fixture");
  const registry = new PrincipalRegistry([{ id: "alice", subject: "oidc|alice", role: "maintainer", tenant: "alpha" }]), sessions = new SessionStore();
  const provider = { verify: async () => null }; const codeFlow = new OidcCodeFlow(login, issuer, "alpha", sessions, { principal: identity => registry.resolve(identity), verify: async () => null });
  const identity = { registry, sessions, provider, codeFlow }; const mint = () => sessions.reserve(Date.now()).create(principal, Date.now(), { issuer, subject: "oidc|alice", tenantId: "alpha" }); const session = mint();
  let generations = 0, release!: () => void, entered!: () => void; const dispatched = new Promise<void>(r => { entered = r; }), gate = new Promise<void>(r => { release = r; });
  const model: ModelProvider = { name: "organization-admission-fixture", isLocal: true, async embed() { throw Error("unexpected embedding"); }, async generate(request) {
    generations++; request.assertAuthority?.(); if (mode === "revoke-inflight" && generations === 1) { entered(); await gate; }
    const result = request.hints?.["taskRole"] === "goal_test" ? { body: "const {pathToFileURL}=await import('node:url');const {join}=await import('node:path');const {add}=await import(pathToFileURL(join(process.cwd(),'calc.mjs')));assert.equal(add(2,3),5);" }
      : { action: "plan", rationale: "repair sum", edits: [{ file: "calc.mjs", search: "return a - b", replace: "return a + b", intent: "sum" }] };
    return { text: JSON.stringify(result), model: "fixture", tokensIn: 1, tokensOut: 1 };
  } };
  const app = composeKeep({ dataDir: join(root, "state"), identity, developmentProvider: model, sourceLanding: mode !== "custom",
    ...(mode === "strong-boundary" ? { projectTestRequiredTier: "microvm" as const } : {}),
    ...(mode === "custom" ? { solve: async () => { throw Error("unfenced solver must not execute"); } } : {
      repositoryMaterialization: { sourceDir: source, workspaceBase, repoRef: "project", commit: git(source, "rev-parse", "HEAD"), baseBranch: "main" },
      testCommand: { command: process.execPath, args: ["--test", "repo.test.mjs"], timeoutMs: 5000 } }) });
  const submit = (body: Record<string, unknown> = {}, sid = session.id) => handleGatewayRequest(app, { method: "POST", path: "/project", query: {}, headers: { authorization: `Bearer ${token}`, "x-keep-session": sid },
    body: JSON.stringify({ goal: "Fix add in calc.mjs to return the arithmetic sum. Preserve other files.", ...body }) }, { token, identity });
  return { app, identity, session, mint, submit, source, workspaceBase, generations: () => generations, dispatched, release: () => release() };
}

test("allowed code-mode native command executes and persists a non-bearer reference without cookie/CSRF", async t => {
  const f = fixture(t); const response = await f.submit(); assert.equal(response.status, 200, response.body); assert.equal(f.generations(), 2);
  const job = f.app.projectRuntime!.job(JSON.parse(response.body).runId)!, command = f.app.projectRuntime!.commandForJob(job.id, job.projectId);
  assert.deepEqual(command.principal.sessionAuthority, f.session.authority); assert.doesNotMatch(JSON.stringify(command), new RegExp(`${f.session.id}|${f.session.csrfToken}`));
  assert.equal(readFileSync(join(f.workspaceBase, "project", "calc.mjs"), "utf8"), original.replace("a - b", "a + b"));
  assert.equal(readFileSync(join(f.source, "calc.mjs"), "utf8"), original);
  f.identity.sessions.revoke(f.session.id); assert.throws(() => f.app.projectRuntime!.assertCommandForJob(job.id, job.projectId));
});

test("revocation while first model call is dispatched retains that fact and prevents later model/edit effects", async t => {
  const f = fixture(t, "revoke-inflight"); const pending = f.submit(); await f.dispatched; f.identity.sessions.revoke(f.session.id); f.release(); await pending;
  assert.equal(f.generations(), 1, "already dispatched first model response does not authorize another call");
  assert.equal(readFileSync(join(f.workspaceBase, "project", "calc.mjs"), "utf8"), original);
  assert.ok(f.app.spine.currentEvents().some(e => e.payload["event"] === "session.admission-refused"));
});

test("queued command loses admission on rotation; fresh login cannot reauthorize the persisted command", async t => {
  const f = fixture(t, "queued"); f.app.projectRuntime!.pauseDispatch(); const response = await f.submit({ background: true }); assert.equal(response.status, 202, response.body);
  const job = f.app.projectRuntime!.jobs()[0]!, command = f.app.projectRuntime!.commandForJob(job.id, job.projectId);
  const rotated = f.identity.sessions.rotate(f.session.id, Date.now()); assert.notEqual(rotated.authority!.authorityId, command.principal.sessionAuthority!.authorityId);
  assert.throws(() => f.app.projectRuntime!.assertCommandForJob(job.id, job.projectId)); f.mint(); assert.throws(() => f.app.projectRuntime!.assertCommandForJob(job.id, job.projectId));
  f.app.projectRuntime!.resumeDispatch(); await new Promise<void>(r => setImmediate(r)); assert.equal(f.generations(), 0);
});

test("custom code-mode human path refuses and a trusted resolver cannot manufacture a missing session reference", async t => {
  const f = fixture(t, "custom"); assert.equal((await f.submit()).status, 409); assert.equal(f.generations(), 0);
  const response = await handleGatewayRequest(f.app, { method: "POST", path: "/project", query: {}, headers: { authorization: `Bearer ${token}` }, body: JSON.stringify({ goal: "Fix arithmetic" }) }, { token, principalFor: () => principal });
  assert.equal(response.status, 409); assert.equal(f.generations(), 0);
});

test("goal API retains original authority and revocation prevents advancing or creating a child", async t => {
  const f = fixture(t); f.app.projectRuntime!.pauseDispatch();
  const response = await handleGatewayRequest(f.app, { method: "POST", path: "/project/goal", query: {}, headers: { authorization: `Bearer ${token}`, "x-keep-session": f.session.id },
    body: JSON.stringify({ idempotencyKey: "goal-session-binding-fixture", active: true, definition: { objective: "Repair arithmetic and preserve source", maxTaskStarts: 1,
      tasks: [{ id: "repair", goal: "Fix arithmetic", kind: "goal", dependsOn: [], requires: [], due: "development", acceptance: "tested-proposal" }] } }) }, { token, identity: f.identity });
  assert.equal(response.status, 202, response.body); const goal = JSON.parse(response.body);
  assert.deepEqual(goal.document.principal.sessionAuthority, f.session.authority); assert.doesNotMatch(response.body, new RegExp(`${f.session.id}|${f.session.csrfToken}`));
  f.identity.sessions.revoke(f.session.id); f.mint(); await assert.rejects(f.app.projectRuntime!.advanceGoalWork(goal.projectId));
  assert.equal(f.app.projectRuntime!.goalWork(goal.projectId).document.startsUsed, 0); assert.equal(f.generations(), 0);
});


test("unverified stronger boundary remains held before model dispatch and never downgrades configured isolation", async t => {
  const f = fixture(t, "strong-boundary"); const response = await f.submit(); assert.equal(response.status, 409, response.body); assert.equal(f.generations(), 0);
});
