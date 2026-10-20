import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest } from "node:http";
import { composeKeep } from "../src/compose.js";
import { startGatewayServer, handleGatewayRequest } from "../src/gateway/http_gateway.js";
import { handleProjectConsole, type ConsoleApi } from "../src/review/project_console.js";

test("native console signs in without a URL credential, shows real waits and consumes only an exact decision", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-console-")), token = "owned-console-fixture-credential";
  const app = composeKeep({ dataDir: root, projectPosture: "approval-required", solve: async () => { throw new Error("declined work must not solve"); } });
  const server = await startGatewayServer(app, { port: 0, token });
  try {
    const started = await handleGatewayRequest(app, { method: "POST", path: "/project", query: {}, headers: { authorization: `Bearer ${token}` }, body: JSON.stringify({ goal: "email the report to the team <script>alert(1)</script>" }) }, { token });
    assert.equal(started.status, 200);
    const project = JSON.parse(started.body);
    assert.equal(project.status, "waiting-approval");
    const loginPage = await fetch(server.origin + "/console");
    assert.equal(loginPage.status, 200); assert.ok(!(await loginPage.text()).includes(token));
    const signedIn = await fetch(server.origin + "/console/login", { method: "POST", redirect: "manual", headers: { origin: server.origin, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token }) });
    assert.equal(signedIn.status, 303);
    const setCookie = signedIn.headers.get("set-cookie")!;
    assert.match(setCookie, /HttpOnly; SameSite=Strict/);
    const cookie = setCookie.split(";")[0]!;
    const list = await (await fetch(server.origin + "/console", { headers: { cookie } })).text();
    assert.ok(list.includes(project.projectId)); assert.ok(!list.includes(token)); assert.ok(!list.includes("<script>alert"));
    const detail = await (await fetch(server.origin + `/console/project?projectId=${project.projectId}`, { headers: { cookie } })).text();
    assert.match(detail, /No repository check result is recorded yet/);
    assert.match(detail, /&lt;script&gt;/); assert.ok(!detail.includes(token));
    const csrf = /name="csrf" value="([^"]+)"/u.exec(detail)![1]!;
    const decide = (decisionId: string, origin = server.origin, csrfValue = csrf) => fetch(server.origin + "/console/resume", { method: "POST", headers: { cookie, origin, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: csrfValue, projectId: project.projectId, runId: project.runId, decisionId, action: "decline" }) });
    assert.equal((await decide(project.wait.decisionId, "https://foreign.invalid")).status, 403);
    assert.equal((await decide(project.wait.decisionId, server.origin, token)).status, 403);
    assert.equal((await decide("stale-decision")).status, 409);
    const result = await decide(project.wait.decisionId);
    assert.equal(result.status, 200); assert.match(await result.text(), /waiting-capability/);
    assert.equal((await decide(project.wait.decisionId)).status, 409);
    assert.equal((await fetch(server.origin + "/project", { headers: { cookie } })).status, 401, "browser cookie does not authorize raw API routes");
    const hostileStatus = await new Promise<number | undefined>((resolve, reject) => {
      const request = httpRequest(server.origin + "/console", { headers: { host: "rebound.invalid", cookie } }, response => { response.resume(); response.on("end", () => resolve(response.statusCode)); });
      request.on("error", reject); request.end();
    });
    assert.equal(hostileStatus, 403);
  } finally { await server.close(); rmSync(root, { recursive: true, force: true }); }
});

test("proposal console escapes diff, preserves exact digest and displays a held landing truthfully", async () => {
  const digest = "a".repeat(64), calls: unknown[] = [];
  const api: ConsoleApi = async (method, path, _query, body) => {
    calls.push({ method, path, body });
    const data = path === "/projects" ? { projects: [{ id: "p1", name: "Owned project", runId: "r1", lifecycle: "active", proposal: true }] }
      : path === "/project/jobs" ? { jobs: [] }
      : method === "GET" ? { projectId: "p1", project: { stage: "done", status: "completed", consumedSignals: ["approval:exact:approved"] }, proposal: { diff: "+++ b/readme.md\n+<img src=x onerror=alert(1)>", rollback: { patchSha256: digest }, checks: { testsPassed: false, vettingCleared: false, detail: "fixture failure" } }, repository: { workspace: { status: "merged" }, source: { merge: { status: "refused" } } } }
      : { status: "refused", reason: "source changed; no landing occurred" };
    return { status: 200, headers: {}, body: JSON.stringify(data) };
  };
  const request = { method: "GET", path: "/console/project", query: { projectId: "p1" }, headers: {}, body: "" };
  const detail = await handleProjectConsole(request, "csrf", api, { approve: true, decline: true });
  assert.match(detail.body, /Tests failed/); assert.match(detail.body, /&lt;img/); assert.ok(!detail.body.includes("<img src=x"));
  assert.ok(detail.body.includes(`value="${digest}"`));
  const result = await handleProjectConsole({ ...request, method: "POST", path: "/console/merge", body: new URLSearchParams({ projectId: "p1", runId: "r1", action: "approve", proposalDigest: digest }).toString() }, "csrf", api, { approve: true, decline: true });
  assert.match(result.body, /refused/); assert.match(result.body, /no landing occurred/);
  assert.deepEqual(calls.at(-1), { method: "POST", path: "/project/merge", body: { runId: "r1", decision: "approve", proposalDigest: digest } });
});

test("console cancellation targets one queued job and preserves another project's useful work", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-console-cancel-")), token = "owned-cancellation-fixture";
  const app = composeKeep({ dataDir: root, projectRuntimePaused: true });
  const runtime = app.projectRuntime!, manager = app.projectManager!;
  const projectA = manager.create({ name: "Cancel this job" }), projectB = manager.create({ name: "Keep this work" });
  let callsA = 0, callsB = 0;
  const a = runtime.submitTracked(projectA.id, 1, async () => { callsA++; return "unexpected"; });
  const aSettled = a.completion.then(() => "completed", () => "cancelled");
  const b = runtime.submitTracked(projectB.id, 1, async () => { callsB++; return "useful control result"; });
  // Attach immediately so assertion failures still leave owned cleanup safe.
  const bSettled = b.completion.catch(() => "cancelled during cleanup");
  const server = await startGatewayServer(app, { port: 0, token });
  try {
    const login = await fetch(server.origin + "/console/login", { method: "POST", redirect: "manual", headers: { origin: server.origin }, body: new URLSearchParams({ token }) });
    assert.equal(login.status, 303);
    const cookie = login.headers.get("set-cookie")!.split(";")[0]!;
    const detailUrl = server.origin + `/console/project?projectId=${projectA.id}`;
    const detail = await (await fetch(detailUrl, { headers: { cookie } })).text();
    assert.match(detail, /Request cancellation/);
    const csrf = /name="csrf" value="([^"]+)"/u.exec(detail)![1]!;
    const cancel = (jobId: string, csrfValue = csrf, origin = server.origin) => fetch(server.origin + "/console/cancel", {
      method: "POST", headers: { cookie, origin }, body: new URLSearchParams({ csrf: csrfValue, projectId: projectA.id, jobId }),
    });
    assert.equal((await cancel(a.jobId, "wrong-csrf")).status, 403);
    assert.equal((await cancel(a.jobId, csrf, "https://foreign.invalid")).status, 403);
    assert.equal((await cancel(b.jobId)).status, 404, "a forged project/job pair cannot target another visible project");
    assert.equal(runtime.job(a.jobId)?.cancellationRequested, undefined);
    assert.equal(runtime.job(b.jobId)?.cancellationRequested, undefined);
    const result = await cancel(a.jobId);
    assert.equal(result.status, 200);
    const resultPage = await result.text();
    assert.match(resultPage, /Cancellation request recorded/);
    assert.match(resultPage, /does not prove/);
    assert.equal(await aSettled, "cancelled");
    assert.equal(runtime.job(a.jobId)?.state, "stopped");
    assert.equal(runtime.job(b.jobId)?.state, "queued");
    assert.equal(callsA, 0); assert.equal(callsB, 0);
    assert.equal((await cancel(a.jobId)).status, 409, "a stale form cannot reopen a stopped job");
    const refreshed = await (await fetch(detailUrl, { headers: { cookie } })).text();
    assert.match(refreshed, /Cancellation was requested/);
    assert.doesNotMatch(refreshed, /<button[^>]*>Request cancellation/);
    runtime.resumeDispatch();
    assert.equal(await bSettled, "useful control result");
    assert.equal(callsB, 1); assert.equal(callsA, 0);
  } finally {
    await runtime.cancel(a.jobId); await runtime.cancel(b.jobId);
    await Promise.all([aSettled, bSettled]);
    await server.close(); rmSync(root, { recursive: true, force: true });
  }
});

test("console cancellation requires its own solve permission before any API effect", async () => {
  const api: ConsoleApi = async () => { throw new Error("unauthorized cancellation must not call an API"); };
  const response = await handleProjectConsole({ method: "POST", path: "/console/cancel", query: {}, headers: {}, body: "" }, "csrf", api, { approve: true, decline: true, cancel: false });
  assert.equal(response.status, 403);
});
