import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import { KeepClient, KeepClientError, type ClientTransport } from "../src/client/client_core.js";
import { startGatewayServer } from "../src/gateway/http_gateway.js";
import type { ModelProvider } from "../src/gateway/gateway.js";
import type { Principal } from "../src/identity/rbac.js";
import type { ProjectJobActivity } from "../src/session/project_job_journal.js";

const token = "synthetic-client-contract";
// No field/path translation: the real listener receives precisely the client request.
const transport: ClientTransport = async request => {
  const response = await fetch(request.url, { method: request.method, headers: request.headers,
    ...(request.body === undefined ? {} : { body: request.body }) });
  return { status: response.status, body: await response.text() };
};
function client(port: number, credential = token) {
  return new KeepClient({ origin: `http://127.0.0.1:${port}`, token: credential, transport });
}
const statusError = (status: number) => (error: unknown) => error instanceof KeepClientError && error.status === status;

for (const organization of [false, true]) {
  test(`client foreground/background reaches tenant-scoped durable state: ${organization ? "organization" : "personal"}`, async () => {
    const dataDir = mkdtempSync(join(tmpdir(), "keep-client-selection-"));
    const app = composeKeep({ dataDir });
    const manager = app.projectManager!;
    const tenant = organization ? "alpha" : undefined;
    const first = manager.create({ name: "first", ...(tenant === undefined ? {} : { tenant }) });
    const second = manager.create({ name: "second", ...(tenant === undefined ? {} : { tenant }) });
    const foreign = manager.create({ name: "foreign", tenant: "beta" });
    manager.switch(foreign.id);
    let principal: Principal = { id: "alpha-owner", kind: "human", role: "owner", tenant: "alpha" };
    const server = await startGatewayServer(app, { token, host: "127.0.0.1", port: 0,
      ...(organization ? { principalFor: () => principal } : {}) });
    try {
      const api = client(server.port);
      await api.switchProject(first.id);
      assert.equal((await api.projects()).active, first.id);
      assert.equal(manager.lifecycle(foreign.id), "active");
      manager.session(first.id).append("assistant", "history survives presentation changes");
      await api.switchProject(second.id);
      assert.equal((await api.projects()).active, second.id);
      assert.equal(manager.lifecycle(first.id), "background");
      assert.equal(manager.session(first.id).history()[0]?.text, "history survives presentation changes");
      assert.equal(manager.session(first.id).compactions().length, 0, "HTTP selection does not implicitly summarize history");
      await api.backgroundProject(second.id);
      assert.equal((await api.projects()).active, null);
      assert.equal(manager.lifecycle(second.id), "background");
      await assert.rejects(api.switchProject("malformed"), statusError(400));
      await assert.rejects(client(server.port, "wrong").switchProject(first.id), statusError(401));
      if (organization) {
        await assert.rejects(api.switchProject(foreign.id), statusError(404));
        await assert.rejects(api.backgroundProject(foreign.id), statusError(404));
        principal = { ...principal, role: "viewer" };
        await assert.rejects(api.switchProject(first.id), statusError(403));
        principal = { ...principal, role: "owner" };
      }
      manager.archive(first.id);
      await assert.rejects(api.switchProject(first.id), statusError(409));
      await assert.rejects(api.backgroundProject(first.id), statusError(409));
      const restored = composeKeep({ dataDir }).projectManager!;
      assert.equal(restored.lifecycle(first.id), "archived");
      assert.equal(restored.lifecycle(second.id), "background");
      assert.equal(restored.lifecycle(foreign.id), "active");
    } finally { await server.close(); }
  });
}
function git(cwd: string, ...args: string[]) {
  return execFileSync("git", ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", ...args], {
    cwd, encoding: "utf8", timeout: 5000, env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_AUTHOR_NAME: "Synthetic fixture", GIT_AUTHOR_EMAIL: "fixture@example.invalid",
      GIT_COMMITTER_NAME: "Synthetic fixture", GIT_COMMITTER_EMAIL: "fixture@example.invalid" },
  }).trim();
}

test("KEEP-13A-001: client top-up advances the actual paused checkpoint", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-client-resume-")),
    solve: async issue => ({ solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0,
      validation: { testsPassed: true, detail: "scripted control" } } }) as never });
  const project = app.projectManager!.create({ name: "bounded client task" });
  const paused = await app.autonomyLoop!.runManagedProject(project.id, "Fix add in calc.mjs to return the arithmetic sum.", { stepBudget: 1 });
  assert.equal(paused.state.status, "paused-budget");
  const revision = paused.state.revision;
  const server = await startGatewayServer(app, { token, host: "127.0.0.1", port: 0 });
  try {
    const api = client(server.port);
    await assert.rejects(client(server.port, "wrong").resumeProject(paused.state.runId, 2), statusError(401));
    assert.equal(app.projectManager!.session(project.id).lastCheckpoint()!.revision, revision);
    const read = await api.project(paused.state.runId) as { project: { revision: number } };
    assert.equal(read.project.revision, revision);
    for (const amount of [undefined, -1, 0, 0.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity]) {
      const held = await api.resumeProject(paused.state.runId, amount);
      assert.equal(held.status, "paused-budget");
      assert.equal(app.projectManager!.session(project.id).lastCheckpoint()!.revision, revision);
    }
    await api.resumeProject(paused.state.runId, 2);
    assert.ok(app.projectManager!.session(project.id).lastCheckpoint()!.revision > revision, "top-up changes durable checkpoint, not only HTTP status");
    await assert.rejects(api.project("missing-client-project"), statusError(404));
  } finally { await server.close(); }
});

for (const organization of [false, true]) {
  test(`KEEP-13A-001: client jobs and optional filter preserve ${organization ? "tenant" : "personal"} scope`, async () => {
    const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-client-jobs-")) });
    const a = app.projectManager!.create({ name: "a", ...(organization ? { tenant: "alpha" } : {}) });
    const b = app.projectManager!.create({ name: "b", ...(organization ? { tenant: "alpha" } : {}) });
    const foreign = app.projectManager!.create({ name: "foreign", tenant: "beta" });
    let release!: () => void;
    const pending = new Promise<void>(resolve => { release = resolve; });
    const jobs = [a, b, foreign].map(project => app.projectRuntime!.submit(project.id, 1, async () => pending));
    await new Promise<void>(resolve => setImmediate(resolve));
    // Trusted configured resolver exercises the real HTTP path, not an external IdP.
    const principal: Principal = { id: "alpha-owner", kind: "human", role: "owner", tenant: "alpha" };
    const server = await startGatewayServer(app, { token, host: "127.0.0.1", port: 0,
      ...(organization ? { principalFor: () => principal } : {}) });
    try {
      const api = client(server.port);
      const listed = await api.backgroundJobs() as { jobs: { id: string; projectId: string }[] };
      assert.deepEqual(new Set(listed.jobs.map(job => job.projectId)), new Set((organization ? [a, b] : [a, b, foreign]).map(project => project.id)));
      const selected = await api.backgroundJobs(a.id) as { jobs: { projectId: string }[]; status: { running: number; queued: number } };
      assert.deepEqual(selected.jobs.map(job => job.projectId), [a.id]);
      assert.deepEqual(selected.status, { running: 1, queued: 0 });
      const selectedJob = listed.jobs.find(job => job.projectId === a.id)!;
      const otherJob = listed.jobs.find(job => job.projectId === b.id)!;
      for (const [jobId, expectedStatus] of [[selectedJob.id, 200], [otherJob.id, 404]] as const) {
        const response = await transport({ method: "GET", url: `${server.origin}/project/jobs?projectId=${encodeURIComponent(a.id)}&jobId=${encodeURIComponent(jobId)}`, headers: { authorization: `Bearer ${token}` } });
        assert.equal(response.status, expectedStatus, response.body);
        if (expectedStatus === 200) {
          const result = JSON.parse(response.body) as { job: { projectId: string }; activities: ProjectJobActivity[] };
          assert.equal(result.job.projectId, a.id);
          assert.ok(result.activities.length > 0);
          assert.ok(result.activities.every(activity => activity.jobId === selectedJob.id));
        }
      }
      await assert.rejects(api.backgroundJobs("missing-client-project"), statusError(404));
      if (organization) await assert.rejects(api.backgroundJobs(foreign.id), statusError(404));
      await assert.rejects(client(server.port, "wrong").backgroundJobs(), statusError(401));
    } finally { release(); await Promise.all(jobs); await server.close(); }
  });
}

for (const decision of ["approve", "veto"] as const) {
  test(`KEEP-13A-001: client ${decision} binds the actual checked proposal`, async () => {
    const root = mkdtempSync(join(tmpdir(), "keep-client-merge-"));
    const source = join(root, "source"), workspaceBase = join(root, "workspaces");
    mkdirSync(source); mkdirSync(workspaceBase);
    const before = "export function add(a,b) { return a - b; }\n";
    writeFileSync(join(source, "calc.mjs"), before);
    writeFileSync(join(source, "repo.test.mjs"), "import test from 'node:test';import assert from 'node:assert/strict';import {add} from './calc.mjs';test('sum',()=>{for(const [a,b,c] of [[2,3,5],[-4,2,-2],[0,0,0]])assert.equal(add(a,b),c)});\n");
    git(source, "init", "-q", "-b", "main"); git(source, "add", "-A"); git(source, "commit", "-qm", "synthetic base");
    const base = git(source, "rev-parse", "HEAD");
    let calls = 0;
    const model: ModelProvider = { name: "client-contract-scripted", isLocal: true,
      async embed() { throw new Error("unexpected embedding"); },
      async generate(req) {
        calls++;
        assert.ok(req.hints?.["taskRole"] === "goal_test" || req.hints?.["taskRole"] === "repository_edit");
        const value = req.hints?.["taskRole"] === "goal_test"
          ? { body: "const {pathToFileURL}=await import('node:url');const {join}=await import('node:path');const {add}=await import(pathToFileURL(join(process.cwd(),'calc.mjs')));assert.equal(add(2,3),5);" }
          : { action: "plan", rationale: "repair addition", edits: [{ file: "calc.mjs", search: "return a - b", replace: "return a + b", intent: "sum" }] };
        return { text: JSON.stringify(value), model: "scripted", tokensIn: 1, tokensOut: 1 };
      },
    };
    const app = composeKeep({ dataDir: join(root, "state"), developmentProvider: model, sourceLanding: true,
      repositoryMaterialization: { sourceDir: source, workspaceBase, repoRef: "project", commit: base, baseBranch: "main" },
      testCommand: { command: process.execPath, args: ["--test", "repo.test.mjs"], timeoutMs: 5000 } });
    const server = await startGatewayServer(app, { token, host: "127.0.0.1", port: 0 });
    try {
      const api = client(server.port);
      const proposed = await api.startProject("Fix add in calc.mjs to return the arithmetic sum. Preserve other files.");
      const { runId, proposalDigest } = proposed;
      assert.ok(runId); assert.ok(proposalDigest);
      assert.match(proposalDigest, /^[0-9a-f]{64}$/u); assert.equal(calls, 2);
      const decide = (digest: string) => api.mergeProject(runId, decision, digest) as Promise<{ status: string; reason?: string; mergeId?: string }>;
      await assert.rejects(decide(undefined as unknown as string), statusError(400));
      await assert.rejects(decide("malformed"), statusError(400));
      const wrong = await decide(proposalDigest === "0".repeat(64) ? "1".repeat(64) : "0".repeat(64));
      assert.equal(wrong.status, "refused"); assert.match(wrong.reason ?? "", /digest/);
      assert.equal(readFileSync(join(source, "calc.mjs"), "utf8"), before);
      await assert.rejects(client(server.port, "wrong").mergeProject(runId, decision, proposalDigest), statusError(401));
      const result = await decide(proposalDigest);
      if (decision === "approve") {
        assert.equal(result.status, "merged", result.reason);
        assert.equal(git(source, "rev-parse", "HEAD"), result.mergeId);
        assert.match(readFileSync(join(source, "calc.mjs"), "utf8"), /return a \+ b/);
        const env = { ...process.env }; delete env["NODE_TEST_CONTEXT"];
        assert.match(execFileSync(process.execPath, ["--test", "repo.test.mjs"], { cwd: source, encoding: "utf8", env, timeout: 5000 }), /# pass 1\b/);
      } else {
        assert.equal(result.status, "refused"); assert.match(result.reason ?? "", /veto/);
        assert.equal(git(source, "rev-parse", "HEAD"), base);
        assert.equal(readFileSync(join(source, "calc.mjs"), "utf8"), before);
      }
    } finally { await server.close(); }
  });
}
