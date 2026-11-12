/** Plain loopback HTTP simulates trusted TLS termination headers here.
 * These tests do not establish actual public HTTPS deployment. */
import test from "node:test";
import assert from "node:assert/strict";
import { request } from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, readFileSync, statSync, existsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import { createBrowserProjectFixture, SAMPLE_GOAL } from "../src/demo/browser_project_fixture.js";
import { SAMPLE_NOTICE } from "../src/review/reviewer_sample.js";
import { startGatewayServer, type GatewayServerHandle, type GatewayServerOptions } from "../src/gateway/http_gateway.js";

function http(server: GatewayServerHandle, path: string, options: { method?: string; headers?: Record<string, string>; form?: Record<string, string> } = {}): Promise<{ status: number; headers: import("node:http").IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request(server.origin + path, { method: options.method ?? "GET", headers: { ...options.headers, ...(options.form ? { "content-type": "application/x-www-form-urlencoded" } : {}) } }, response => {
      let body = ""; response.setEncoding("utf8"); response.on("data", chunk => { body += chunk; });
      response.on("end", () => resolve({ status: response.statusCode!, headers: response.headers, body }));
    });
    req.on("error", reject); req.end(options.form ? new URLSearchParams(options.form).toString() : undefined);
  });
}
const input = (html: string, name: string): string => new RegExp(`name="${name}" value="([^"]+)"`, "u").exec(html)![1]!;

test("local appliance resume retains the same source and refuses changed source without resetting it", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-appliance-resume-"));
  const hosted = mkdtempSync(join(tmpdir(), "keep-hosted-unchanged-"));
  try {
    const ordinary = createBrowserProjectFixture(hosted);
    ordinary.app.projectRuntime!.pauseDispatch();
    assert.equal(existsSync(join(hosted, 'fixture.json')), false, 'hosted default does not acquire local metadata');
    const first = createBrowserProjectFixture(root, { localAppliance: true });
    first.app.projectRuntime!.pauseDispatch();
    const resumed = createBrowserProjectFixture(root, { localAppliance: true, resume: true });
    resumed.app.projectRuntime!.pauseDispatch();
    assert.equal(resumed.baseRevision, first.baseRevision);
    assert.equal(resumed.source, first.source);
    assert.equal(resumed.generations(), 0);
    writeFileSync(join(first.source, 'calc.mjs'), 'owner changed this\n');
    assert.throws(() => createBrowserProjectFixture(root, { localAppliance: true, resume: true }), /sample source changed/);
    assert.equal(readFileSync(join(first.source, 'calc.mjs'), 'utf8'), 'owner changed this\n');
    assert.throws(() => createBrowserProjectFixture(root, { resume: true }), /must be explicit/);
  } finally {
    rmSync(root, { recursive: true, force: true }); rmSync(hosted, { recursive: true, force: true });
  }
});

test("public personal browser origin rejects invalid origins, nonloopback and ambiguous identity modes before listen", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-public-options-"));
  const app = composeKeep({ dataDir: root });
  try {
    for (const origin of ["http://a.example", "https://a.example/", "https://a.example/path", "https://user:pass@a.example", "https://a.example?q=1", "https://a.example#frag", "https://A.example", "https://a.example:443", "broken"])
      assert.throws(() => startGatewayServer(app, { publicBrowserOrigin: origin }), /canonical HTTPS/);
    for (const options of [{ host: "0.0.0.0" }, { host: "localhost" }, { restrictedClientProfile: "/unused/profile" }, { principalFor: () => undefined }, { identity: {} }, { worker: { id: "unused", onStopped() {} } }])
      assert.throws(() => startGatewayServer(app, { publicBrowserOrigin: "https://a.example", ...options } as GatewayServerOptions));
    for (const addition of [{ identity: {} }, { tenantDeployment: {} }])
      assert.throws(() => startGatewayServer({ ...app, ...addition } as typeof app, { publicBrowserOrigin: "https://a.example" }), /cannot replace/);
    assert.throws(() => startGatewayServer(app, { reviewerSample: true }), /controlled synthetic fixture/);
    const local = await startGatewayServer(app, { port: 0, token: "local-compatibility" });
    try {
      assert.match(local.origin, /^http:\/\/127\.0\.0\.1:/);
      assert.equal((await http(local, "/health")).status, 200);
      const login = await http(local, "/console/login", { method: "POST", headers: { origin: local.origin }, form: { token: "local-compatibility" } });
      assert.equal(login.status, 303); assert.ok(!login.headers["set-cookie"]![0]!.includes("Secure"));
    } finally { await local.close(); }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("simulated TLS sample ingress keeps exact Host/Origin, Secure cookie and fixed one-submission authority across isolated instances", async () => {
  const roots = [mkdtempSync(join(tmpdir(), "keep-sample-a-")), mkdtempSync(join(tmpdir(), "keep-sample-b-"))];
  const fixtures = roots.map(root => createBrowserProjectFixture(root));
  fixtures.forEach(f => f.app.projectRuntime!.pauseDispatch());
  const origins = ["https://a.sample.invalid", "https://b.sample.invalid"], tokens = ["a-private-invitation-fixture", "b-private-invitation-fixture"];
  const servers: GatewayServerHandle[] = [];
  try {
    for (let i = 0; i < fixtures.length; i++) servers.push(await startGatewayServer(fixtures[i]!.app, { port: 0, token: tokens[i]!, publicBrowserOrigin: origins[i]!, reviewerSample: true }));
    const call = (index: number, path: string, extra: Parameters<typeof http>[2] = {}) => http(servers[index]!, path, { ...extra, headers: { host: new URL(origins[index]!).host, ...extra.headers } });
    assert.equal((await http(servers[0]!, "/console", { headers: { "x-forwarded-host": "a.sample.invalid", "x-forwarded-proto": "https" } })).status, 403, "forwarded headers cannot substitute for Host");
    assert.equal((await call(0, "/", { headers: { host: "foreign.invalid", "x-forwarded-host": "a.sample.invalid" } })).status, 403);
    assert.equal((await call(0, "/")).status, 303);
    assert.match((await call(0, "/console")).body, /two scripted responses/);
    const login = async (index: number, token = tokens[index]!, origin = origins[index]!) => call(index, "/console/login", { method: "POST", headers: { origin }, form: { token } });
    assert.equal((await login(0, tokens[0], "https://foreign.invalid")).status, 403);
    assert.equal((await login(0, tokens[0], "null")).status, 403);
    assert.equal((await login(0, tokens[0], servers[0]!.origin)).status, 403, "private origin is not rewritten to public HTTPS");
    assert.equal((await login(0, tokens[1])).status, 401);
    const cookies: string[] = [], csrf: string[] = [];
    for (let i = 0; i < 2; i++) {
      const signed = await login(i); assert.equal(signed.status, 303);
      assert.match(signed.headers["set-cookie"]![0]!, /Path=\/console; HttpOnly; SameSite=Strict; Secure/);
      assert.ok(!signed.headers["set-cookie"]![0]!.includes("Domain="));
      cookies.push(signed.headers["set-cookie"]![0]!.split(";")[0]!);
      const form = await call(i, "/console/new?submissionKey=initial-form-key-1234", { headers: { cookie: cookies[i]! } });
      assert.match(form.body, /readonly/); assert.ok(form.body.includes(SAMPLE_GOAL)); assert.ok(form.body.includes(SAMPLE_NOTICE));
      assert.ok(!form.body.includes(tokens[i]!)); csrf.push(input(form.body, "csrf"));
    }
    assert.notEqual(csrf[0], csrf[1]);
    const submit = (index: number, values: Record<string, string> = {}, cookie = cookies[index]!, origin = origins[index]!) => call(index, "/console/submit", {
      method: "POST", headers: { cookie, origin }, form: { csrf: csrf[index]!, goal: SAMPLE_GOAL, idempotencyKey: "another-form-key-1234", ...values },
    });
    for (const values of [{ goal: "Run another repository" }, { repoDir: "/other" }, { command: "arbitrary" }, { provider: "live" }, { domainWorkflowKind: "social-video" }, { memoryContext: "private" }])
      assert.equal((await submit(0, values)).status, 400);
    assert.equal((await submit(0, { csrf: csrf[1]! })).status, 403);
    assert.equal((await submit(0, {}, cookies[1]!)).status, 401);
    assert.equal((await submit(0, {}, cookies[0]!, origins[1]!)).status, 403);
    assert.equal(fixtures[0]!.app.projectManager!.list().length, 0);
    const accepted = await submit(0); assert.equal(accepted.status, 303);
    for (const key of ["fresh-form-key-1234", "fresh-form-key-5678"]) {
      const replay = await submit(0, { idempotencyKey: key }); assert.equal(replay.status, 303); assert.equal(replay.headers.location, accepted.headers.location);
    }
    assert.equal(fixtures[0]!.app.projectManager!.list().length, 1); assert.equal(fixtures[0]!.app.projectRuntime!.retainedJobs().length, 1);
    assert.equal(fixtures[0]!.generations(), 0); assert.equal(fixtures[1]!.app.projectManager!.list().length, 0);
    for (const path of ["/health", "/projects", "/project", "/project/jobs", "/worker/status", "/login", "/auth/oidc/start", "/console/future", "/?token=" + tokens[0]]) {
      assert.equal((await call(0, path, { headers: { authorization: `Bearer ${tokens[0]}`, cookie: cookies[0]! } })).status, 404, path);
      assert.equal((await call(0, path, { headers: { cookie: cookies[0]! } })).status, 404, "cookie cannot open " + path);
    }
    assert.equal((await call(0, "/project", { method: "POST", headers: { authorization: `Bearer ${tokens[0]}` }, form: { goal: SAMPLE_GOAL } })).status, 404);
    const second = await submit(1); assert.equal(second.status, 303); assert.notEqual(second.headers.location, accepted.headers.location);
    const foreignProject = accepted.headers.location!;
    assert.equal((await call(1, foreignProject, { headers: { cookie: cookies[1]! } })).status, 404);
    const originalJob = fixtures[0]!.app.projectRuntime!.retainedJobs()[0]!;
    for (const path of [`/console/export?runId=${originalJob.id}&proposalDigest=${"a".repeat(64)}`, `/console/project?projectId=${originalJob.projectId}`])
      assert.equal((await call(1, path, { headers: { cookie: cookies[1]! } })).status, 404);
    for (const path of ["/console/resume", "/console/merge", "/console/cancel"]) {
      const response = await call(1, path, { method: "POST", headers: { cookie: cookies[1]!, origin: origins[1]! }, form: { csrf: csrf[1]!, projectId: originalJob.projectId, jobId: originalJob.id, runId: originalJob.id, decisionId: "foreign", proposalDigest: "a".repeat(64), action: "approve" } });
      assert.equal(response.status, 404, path);
    }
    assert.equal(fixtures[0]!.generations(), 0); assert.equal(fixtures[1]!.generations(), 0);
  } finally {
    for (const f of fixtures) for (const job of f.app.projectRuntime!.retainedJobs()) await f.app.projectRuntime!.cancel(job.id);
    for (const server of servers) await server.close();
    for (const root of roots) rmSync(root, { recursive: true, force: true });
  }
});

test("foreground launcher owns a new private root and retains it on stop without printing credentials", { timeout: 20000 }, async () => {
  const parent = mkdtempSync(join(tmpdir(), "keep-sample-launcher-")), root = join(parent, "new-instance");
  const child = spawn(process.execPath, ["tools/reviewer_sample.mjs", root, "https://launcher.sample.invalid"], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, KEEP_PROVIDER_API_KEY: "inherited-secret-must-not-enter-sample" } });
  let output = "", errors = "";
  const exited = new Promise<number | null>(resolve => child.once("exit", resolve));
  child.stderr.on("data", chunk => { errors += String(chunk); });
  try {
    const ready = await new Promise<Record<string, unknown>>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("launcher startup timeout: " + errors)), 10000);
      child.once("error", error => { clearTimeout(timer); reject(error); });
      child.once("exit", code => { clearTimeout(timer); reject(new Error(`launcher exited ${code}: ${errors}`)); });
      child.stdout.on("data", chunk => {
        output += String(chunk);
        const line = output.split("\n").find(line => line.startsWith('{"event":"sample-ready"'));
        if (line) { clearTimeout(timer); resolve(JSON.parse(line)); }
      });
    });
    const token = readFileSync(join(root, "invitation-token"), "utf8").trim();
    assert.equal(statSync(root).mode & 0o777, 0o700); assert.equal(statSync(join(root, "invitation-token")).mode & 0o777, 0o600);
    assert.equal(statSync(join(root, "home")).mode & 0o777, 0o700); assert.equal(statSync(join(root, "tmp")).mode & 0o777, 0o700);
    assert.equal(ready.publicBrowserOrigin, "https://launcher.sample.invalid"); assert.equal(ready.scripted, true);
    assert.ok(!output.includes(token)); assert.ok(!output.includes("inherited-secret-must-not-enter-sample"));
    const childPid = readFileSync(`/proc/${child.pid}/task/${child.pid}/children`, "utf8").trim().split(/\s+/u)[0]!;
    const childEnv = readFileSync(`/proc/${childPid}/environ`, "utf8").split("\0");
    assert.ok(childEnv.includes(`HOME=${join(root, "home")}`)); assert.ok(childEnv.includes(`TMPDIR=${join(root, "tmp")}`));
    assert.ok(!childEnv.some(value => value.startsWith("KEEP_PROVIDER_API_KEY=")));
    child.kill("SIGTERM"); assert.equal(await exited, 0, errors);
    assert.match(output, /sample-stopped/); assert.ok(!output.includes(token)); assert.ok(existsSync(join(root, "state"))); assert.ok(existsSync(join(root, "source")));
    const duplicate = spawn(process.execPath, ["tools/reviewer_sample.mjs", root, "https://launcher.sample.invalid"], { stdio: "ignore" });
    assert.notEqual(await new Promise(resolve => duplicate.once("exit", resolve)), 0, "existing instance is never reset or replaced");
    assert.equal(readFileSync(join(root, "invitation-token"), "utf8").trim(), token);
  } finally {
    if (child.exitCode === null) { child.kill("SIGTERM"); await exited; }
    rmSync(parent, { recursive: true, force: true });
  }
});
