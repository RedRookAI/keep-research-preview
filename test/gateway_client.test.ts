import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest } from "../src/gateway/http_gateway.js";
import { createGatewayClient } from "../src/cli/gateway_client.js";
import { launchNativeWorker } from "../src/cli/native_worker.js";

const request = { method: "GET", path: "/project/jobs", query: { jobId: "exact-job" }, headers: { authorization: "Bearer test-token" }, body: "" };

test("remote client needs only a gateway and preserves exact job query and enterprise session", async t => {
  const session = "a".repeat(64);
  const server = createServer((req, res) => {
    assert.equal(req.url, "/project/jobs?jobId=exact-job"); assert.equal(req.headers.authorization, "Bearer test-token"); assert.equal(req.headers["x-keep-session"], session);
    res.writeHead(200, { "content-type": "application/json" }); res.end('{"job":{"id":"exact-job"}}');
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve)); t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const address = server.address(); assert.ok(address && typeof address === "object");
  const response = await createGatewayClient(`http://127.0.0.1:${address.port}`, session)(request);
  assert.equal(response.status, 200); assert.equal(JSON.parse(response.body).job.id, "exact-job");
});

test("client refuses insecure remote origins, credential-bearing URLs and path escapes before dispatch", async () => {
  for (const url of ["http://example.com", "https://user:secret@example.com", "https://example.com/base", "https://example.com?token=x"]) assert.throws(() => createGatewayClient(url), /origin/u);
  await assert.rejects(createGatewayClient("https://example.com")({ ...request, path: "//foreign.example/path" }), /boundary/u);
  await assert.rejects(createGatewayClient("https://example.com")({ ...request, body: "x".repeat(1_000_001) }), /boundary/u);
});

test("client never follows redirects or retries a mutation", async t => {
  let calls = 0;
  const server = createServer((_req, res) => { calls++; res.writeHead(307, { location: "/redirected" }); res.end(); });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve)); t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const address = server.address(); assert.ok(address && typeof address === "object");
  await assert.rejects(createGatewayClient(`http://127.0.0.1:${address.port}`)({ ...request, method: "POST", body: "{}" }));
  assert.equal(calls, 1);
});

test("client bounds response bytes instead of buffering an unbounded stream", async t => {
  const server = createServer((_req, res) => { res.end("x".repeat(1_048_577)); });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve)); t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const address = server.address(); assert.ok(address && typeof address === "object");
  await assert.rejects(createGatewayClient(`http://127.0.0.1:${address.port}`)(request), /1 MiB/u);
});

test("detached launch refuses stdin credentials and arbitrary launch arguments before spawning", async () => {
  await assert.rejects(launchNativeWorker(["serve", "--gateway", "--project-worker", "--detach"], { KEEP_PROVIDER_API_KEY_STDIN: "1" }), /stdin/u);
  await assert.rejects(launchNativeWorker(["serve", "--gateway", "--project-worker", "--detach", "--host=0.0.0.0"], {}), /literal loopback/u);
});

test("worker control preserves role authorization and requires the exact worker identity", async t => {
  const root = mkdtempSync(join(tmpdir(), "keep-worker-control-")); t.after(() => rmSync(root, { recursive: true, force: true }));
  const app = composeKeep({ dataDir: root }); let stops = 0;
  let paused = false;
  const workerControl = { id: "exact-worker", state: () => paused ? "paused" as const : "running" as const, requestStop: () => { stops++; return true; }, setPaused: (value: boolean) => { paused = value; return true; } };
  const security = { token: "test-token", workerControl };
  const stop = { ...request, method: "POST", path: "/worker/stop", query: {}, body: '{"workerId":"exact-worker"}' };
  const denied = await handleGatewayRequest(app, stop, { ...security, principalFor: () => ({ id: "viewer", kind: "human", role: "viewer", tenant: "alpha" }) });
  assert.equal(denied.status, 403); assert.equal(stops, 0);
  assert.equal((await handleGatewayRequest(app, { ...stop, body: '{"workerId":"stale-worker"}' }, security)).status, 409); assert.equal(stops, 0);
  assert.equal((await handleGatewayRequest(app, stop, security)).status, 202); assert.equal(stops, 1);
  const pause = { ...stop, path: "/worker/pause" };
  assert.equal((await handleGatewayRequest(app, pause, { ...security, principalFor: () => ({ id: "viewer", kind: "human", role: "viewer", tenant: "alpha" }) })).status, 403);
  assert.equal(paused, false);
  assert.equal((await handleGatewayRequest(app, { ...pause, body: '{"workerId":"stale-worker"}' }, security)).status, 409);
  assert.equal((await handleGatewayRequest(app, pause, security)).status, 202); assert.equal(paused, true);
  assert.equal((await handleGatewayRequest(app, { ...stop, path: "/worker/resume" }, security)).status, 202); assert.equal(paused, false);
});
