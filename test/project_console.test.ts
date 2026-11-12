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
    assert.equal(loginPage.headers.get("referrer-policy"), "same-origin", "native form POSTs must retain their same-origin Origin header");
    assert.equal(loginPage.status, 200); assert.ok(!(await loginPage.text()).includes(token));
    const signedIn = await fetch(server.origin + "/console/login", { method: "POST", redirect: "manual", headers: { origin: server.origin, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token }) });
    assert.equal(signedIn.status, 303);
    const setCookie = signedIn.headers.get("set-cookie")!;
    assert.match(setCookie, /HttpOnly; SameSite=Strict/);
    const cookie = setCookie.split(";")[0]!;
    const list = await (await fetch(server.origin + "/console", { headers: { cookie } })).text();
    assert.ok(list.includes(project.projectId)); assert.ok(!list.includes(token)); assert.ok(!list.includes("<script>alert"));
    const detailResponse = await fetch(server.origin + `/console/project?projectId=${project.projectId}`, { headers: { cookie } });
    assert.equal(detailResponse.headers.get("referrer-policy"), "same-origin");
    const detail = await detailResponse.text();
    assert.match(detail, /No repository check result is recorded yet/);
    assert.match(detail, /&lt;script&gt;/); assert.ok(!detail.includes(token));
    const csrf = /name="csrf" value="([^"]+)"/u.exec(detail)![1]!;
    const decide = (decisionId: string, origin = server.origin, csrfValue = csrf) => fetch(server.origin + "/console/resume", { method: "POST", headers: { cookie, origin, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: csrfValue, projectId: project.projectId, runId: project.runId, decisionId, action: "decline" }) });
    assert.equal((await decide(project.wait.decisionId, "https://foreign.invalid")).status, 403);
    assert.equal((await decide(project.wait.decisionId, "null")).status, 403, "opaque origins remain refused");
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

test("browser goal submission keeps one durable identity across refresh, duplicate POST and a lost response", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-console-submit-")), token = "owned-submission-fixture";
  let solves = 0;
  const app = composeKeep({ dataDir: root, projectRuntimePaused: true, solve: async () => { solves++; throw new Error("paused job must never execute"); } });
  const server = await startGatewayServer(app, { port: 0, token });
  try {
    const login = await fetch(server.origin + "/console/login", { method: "POST", redirect: "manual", headers: { origin: server.origin }, body: new URLSearchParams({ token }) });
    const cookie = login.headers.get("set-cookie")!.split(";")[0]!;
    const entry = await fetch(server.origin + "/console/new", { headers: { cookie }, redirect: "manual" });
    assert.equal(entry.status, 303);
    const url = server.origin + entry.headers.get("location")!;
    const html = await (await fetch(url, { headers: { cookie } })).text();
    assert.match(html, /dispatch is paused/); assert.ok(!html.includes(token));
    const key = /name="idempotencyKey" value="([^"]+)"/u.exec(html)![1]!;
    const csrf = /name="csrf" value="([^"]+)"/u.exec(html)![1]!;
    assert.ok((await (await fetch(url, { headers: { cookie } })).text()).includes(key));
    assert.equal(app.projectManager!.list().length, 0, "reading/refreshing never creates a project");
    const goal = "Fix the bounded repository arithmetic <script>bad()</script>";
    const send = (overrides: { cookie?: string; csrf?: string; origin?: string; goal?: string } = {}) => fetch(server.origin + "/console/submit", {
      method: "POST", redirect: "manual", headers: { cookie: overrides.cookie ?? cookie, origin: overrides.origin ?? server.origin },
      body: new URLSearchParams({ csrf: overrides.csrf ?? csrf, idempotencyKey: key, goal: overrides.goal ?? goal, repoDir: "/forged/path", command: "forged" }),
    });
    assert.equal((await send({ cookie: "keep_token=foreign-session" })).status, 401);
    for (const badCsrf of ["", "incorrect", token]) assert.equal((await send({ csrf: badCsrf })).status, 403);
    assert.equal((await send({ origin: "https://foreign.invalid" })).status, 403);
    assert.equal(app.projectManager!.list().length, 0);
    const [first, duplicate] = await Promise.all([send(), send()]);
    assert.equal(first.status, 303); assert.equal(duplicate.status, 303);
    assert.equal(first.headers.get("location"), duplicate.headers.get("location"));
    assert.equal(app.projectManager!.list().length, 1); assert.equal(solves, 0);
    const projectId = app.projectManager!.list()[0]!.id;
    assert.equal(app.projectRuntime!.jobs(new Set([projectId])).length, 1);
    const changed = await send({ goal: "Different goal" });
    assert.equal(changed.status, 409); assert.match(await changed.text(), new RegExp(key));
    assert.equal(app.projectManager!.list().length, 1);
    // Simulate the bridge losing its response after the canonical gateway committed.
    const api: ConsoleApi = async (method, path, query = {}, body) => {
      const response = await handleGatewayRequest(app, { method, path, query, headers: { authorization: `Bearer ${token}` }, body: JSON.stringify(body) }, { token });
      if (method === "POST") throw new Error("response lost after commit");
      return response;
    };
    const lost = await handleProjectConsole({ method: "POST", path: "/console/submit", query: {}, headers: {}, body: new URLSearchParams({ idempotencyKey: key, goal }).toString() }, csrf, api, { approve: true, decline: true, submit: true });
    assert.equal(lost.status, 503); assert.match(lost.body, /outcome is uncertain/); assert.ok(lost.body.includes(key));
    assert.match(lost.body, /&lt;script&gt;/); assert.ok(!lost.body.includes("<script>"));
    const recovered = await send();
    assert.equal(recovered.status, 303); assert.equal(recovered.headers.get("location"), first.headers.get("location"));
    const detail = await (await fetch(server.origin + first.headers.get("location")!, { headers: { cookie } })).text();
    assert.match(detail, /queued/); assert.match(detail, /dispatch is paused/); assert.match(detail, /Request cancellation/);
    assert.equal(app.projectRuntime!.jobs(new Set([projectId])).length, 1);
    assert.equal(solves, 0);
  } finally {
    for (const project of app.projectManager!.list()) for (const job of app.projectRuntime!.jobs(new Set([project.id]))) await app.projectRuntime!.cancel(job.id);
    await server.close(); rmSync(root, { recursive: true, force: true });
  }
});

test("submission permission and unconfigured worker refuse without a job; held setup retains the original goal", async () => {
  const req = { method: "POST", path: "/console/submit", query: {}, headers: {}, body: "" };
  const denied = await handleProjectConsole(req, "csrf", async () => { throw new Error("must not call"); }, { approve: true, decline: true, submit: false });
  assert.equal(denied.status, 403);
  const root = mkdtempSync(join(tmpdir(), "keep-console-unconfigured-"));
  const app = composeKeep({ dataDir: root }), token = "unconfigured-owner";
  const api: ConsoleApi = (method, path, query = {}, body) => handleGatewayRequest(app, { method, path, query, body: body === undefined ? "" : JSON.stringify(body), headers: { authorization: `Bearer ${token}` } }, { token });
  try {
    const form = await handleProjectConsole({ ...req, method: "GET", path: "/console/new", query: { submissionKey: "unconfigured-key-1234" } }, "csrf", api, { approve: true, decline: true, submit: true });
    assert.match(form.body, /solver is unconfigured/);
    const result = await handleProjectConsole({ ...req, body: new URLSearchParams({ idempotencyKey: "unconfigured-key-1234", goal: "Repair missing dependencies <img>" }).toString() }, "csrf", api, { approve: true, decline: true, submit: true });
    assert.equal(result.status, 501); assert.match(result.body, /unconfigured-key-1234/); assert.match(result.body, /&lt;img&gt;/);
    assert.equal(app.projectManager!.list().length, 0);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("revoking solve permission after the form was read prevents browser submission", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-console-revoked-")), token = "revocation-owner-fixture";
  let allowed = true;
  const app = composeKeep({ dataDir: root, projectRuntimePaused: true, solve: async () => { throw new Error("must not dispatch"); },
    authorization: { authorize: (_principal, action) => ({ allow: action !== "change.solve" || allowed, reason: "mutable fixture policy" }) } });
  const server = await startGatewayServer(app, { port: 0, token });
  try {
    const login = await fetch(server.origin + "/console/login", { method: "POST", redirect: "manual", headers: { origin: server.origin }, body: new URLSearchParams({ token }) });
    const cookie = login.headers.get("set-cookie")!.split(";")[0]!;
    const form = await (await fetch(server.origin + "/console/new?submissionKey=revocation-key-12345", { headers: { cookie } })).text();
    const csrf = /name="csrf" value="([^"]+)"/u.exec(form)![1]!;
    allowed = false;
    const denied = await fetch(server.origin + "/console/submit", { method: "POST", headers: { cookie, origin: server.origin }, body: new URLSearchParams({ csrf, idempotencyKey: "revocation-key-12345", goal: "Fix arithmetic" }) });
    assert.equal(denied.status, 403); assert.equal(app.projectManager!.list().length, 0); assert.equal(app.projectRuntime!.jobs().length, 0);
  } finally { await server.close(); rmSync(root, { recursive: true, force: true }); }
});

test("retained console jobs show the recorded terminal failure after active capacity is released", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-console-failed-")), token = "failed-job-owner";
  const app = composeKeep({ dataDir: root });
  const project = app.projectManager!.create({ name: "Dependency failure" });
  const tracked = app.projectRuntime!.submitTracked(project.id, 1, async () => { throw new Error("Missing dependency: checker executable unavailable; owner must correct setup"); }, "repository checker");
  await assert.rejects(tracked.completion, /Missing dependency/);
  assert.equal(app.projectRuntime!.jobs(new Set([project.id])).length, 0, "terminal job consumes no active capacity");
  const api: ConsoleApi = (method, path, query = {}, body) => handleGatewayRequest(app, { method, path, query, body: body === undefined ? "" : JSON.stringify(body), headers: { authorization: `Bearer ${token}` } }, { token });
  try {
    const detail = await handleProjectConsole({ method: "GET", path: "/console/project", query: { projectId: project.id }, headers: {}, body: "" }, "csrf", api, { approve: true, decline: true });
    assert.equal(detail.status, 200); assert.match(detail.body, /failed/); assert.match(detail.body, /callback failed/);
    assert.ok(detail.body.includes(tracked.jobId)); assert.doesNotMatch(detail.body, /<button[^>]*>Request cancellation/);
    const foreign = await handleGatewayRequest(app, { method: "GET", path: "/project/jobs", query: { includeTerminal: "true" }, headers: { authorization: `Bearer ${token}` }, body: "" }, { token, principalFor: () => ({ id: "foreign-owner", kind: "human", role: "owner", tenant: "foreign" }) });
    assert.equal(foreign.status, 200); assert.deepEqual(JSON.parse(foreign.body).jobs, [], "retained history preserves tenant filtering");
    const reopened = composeKeep({ dataDir: root });
    assert.equal(reopened.projectRuntime!.retainedJobs(new Set([project.id]))[0]!.state, "failed", "retained navigation survives runtime reconstruction");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("console projects missing prerequisites, uncertain work and a pre-checkpoint queued job without dispatch", async () => {
  for (const state of ["missing-prerequisites", "reconciliation-required", "queued"]) {
    const jobId = "33333333-3333-4333-8333-333333333333";
    const jobState = state === "missing-prerequisites" ? "completed" : state;
    const reason = state === "missing-prerequisites" ? "Missing check prerequisites: node_modules/fixture/package.json. Ask the owner to prepare the workspace." : "Interrupted work; reconcile effects before retrying.";
    let writes = 0;
    const api: ConsoleApi = async (method, path, query) => {
      if (method === "POST") writes++;
      const data = path === "/projects" ? { projects: [{ id: "p1", name: "Bounded goal", runId: "r1" }] }
        : path === "/project/jobs" ? query?.jobId ? { job: { id: jobId, projectId: "p1", state: jobState }, activities: [] } : { jobs: [{ id: jobId, projectId: "p1", label: "retained work", state: jobState, reason }] }
        : { projectId: "p1", project: { status: "waiting-capability", wait: { kind: "capability", reason } } };
      return { status: path === "/project" && state === "queued" ? 404 : 200, headers: {}, body: JSON.stringify(data) };
    };
    const response = await handleProjectConsole({ method: "GET", path: "/console/project", query: { projectId: "p1" }, headers: {}, body: "" }, "csrf", api, { approve: true, decline: true });
    assert.equal(response.status, 200); assert.ok(response.body.includes(reason)); assert.equal(writes, 0);
    assert.match(response.body, /No repository check result is recorded yet/);
  }
});
