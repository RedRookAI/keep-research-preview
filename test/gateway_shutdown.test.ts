/** Real owned loopback connections; no VM, model, external service or force-exit. */
import test, { type TestContext } from "node:test";
import assert from "node:assert/strict";
import { Agent, request, type IncomingMessage } from "node:http";
import { connect, type Socket } from "node:net";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import { startGatewayServer, type GatewayServerHandle } from "../src/gateway/http_gateway.js";

// Reuse the guest owner's existing 30s stop-confirmation bound as a failure guard.
const stopBound = { timeout: 30_000 };
const token = "owned-gateway-shutdown-token";

async function fixture(t: TestContext, worker?: { id: string; onStopped: () => void }) {
  const root = mkdtempSync(join(tmpdir(), "keep-shutdown-"));
  const app = composeKeep({ dataDir: root });
  const server = await startGatewayServer(app, { port: 0, token, ...(worker ? { worker } : {}) });
  const sockets: Socket[] = [];
  const cleanup: Array<() => void | Promise<void>> = [];
  t.after(async () => {
    for (const close of cleanup) await close();
    for (const socket of sockets) socket.destroy();
    app.projectRuntime!.pauseDispatch();
    await server.close();
    rmSync(root, { recursive: true, force: true });
  });
  async function raw() {
    const socket = connect({ host: "127.0.0.1", port: server.port }); sockets.push(socket);
    await once(socket, "connect");
    return socket;
  }
  return { app, server, raw, cleanup };
}

function http(server: GatewayServerHandle, path: string, options: { agent?: Agent; stop?: boolean } = {}) {
  return new Promise<{ status: number; body: string }>((resolve, reject) => {
    const req = request(server.origin + path, { method: options.stop ? "POST" : "GET",
      ...(options.agent ? { agent: options.agent } : {}),
      headers: options.stop ? { authorization: `Bearer ${token}`, "content-type": "application/json" } : {} }, res => {
      let body = ""; res.setEncoding("utf8"); res.on("data", chunk => { body += chunk; });
      res.once("end", () => resolve({ status: res.statusCode!, body }));
    });
    req.once("error", reject);
    req.end(options.stop ? JSON.stringify({ workerId: "owned-worker" }) : undefined);
  });
}

test("handle.close closes an owned TCP socket with no HTTP headers", stopBound, async t => {
  const { server, raw } = await fixture(t);
  const socket = await raw(), disconnected = once(socket, "close");
  await server.close();
  await disconnected;
  assert.equal(socket.destroyed, true);
});

test("handle.close still drains completed HTTP keepalive connections", stopBound, async t => {
  const { server } = await fixture(t);
  const agent = new Agent({ keepAlive: true }); t.after(() => agent.destroy());
  assert.equal((await http(server, "/", { agent })).status, 303);
  await server.close();
});

test("handle.close preserves an admitted HTTP body until its response completes", stopBound, async t => {
  const { server, cleanup } = await fixture(t);
  let responseResolve!: (value: { status: number; body: string }) => void, responseReject!: (reason: unknown) => void;
  const response = new Promise<{ status: number; body: string }>((resolve, reject) => { responseResolve = resolve; responseReject = reject; });
  const req = request(server.origin + "/", { method: "GET", headers: { expect: "100-continue", "content-length": "2", connection: "close" } });
  req.on("response", (res: IncomingMessage) => {
    let body = ""; res.setEncoding("utf8"); res.on("data", chunk => { body += chunk; });
    res.once("end", () => responseResolve({ status: res.statusCode!, body }));
  });
  req.once("error", responseReject);
  cleanup.push(async () => { req.destroy(); await response.catch(() => undefined); });
  const admitted = once(req, "continue"); req.flushHeaders(); await admitted;
  let closed = false;
  const closing = server.close().then(() => { closed = true; });
  await new Promise<void>(resolve => setImmediate(resolve));
  assert.equal(closed, false, "shutdown cannot terminate the admitted request");
  req.end("{}");
  const result = await response;
  assert.equal(result.status, 303); assert.equal(result.body, "");
  await closing;
});

test("worker stop retains queued/running refusal and closes only unused sockets after work settles", stopBound, async t => {
  let stoppedResolve!: () => void, stops = 0;
  const stopped = new Promise<void>(resolve => { stoppedResolve = resolve; });
  const { app, server, raw, cleanup } = await fixture(t, { id: "owned-worker", onStopped: () => { stops++; stoppedResolve(); } });
  const runtime = app.projectRuntime!, project = app.projectManager!.create({ name: "owned paused job" });
  runtime.pauseDispatch();
  let release!: () => void, startedResolve!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const started = new Promise<void>(resolve => { startedResolve = resolve; });
  const job = runtime.submitTracked(project.id, 1, async () => { startedResolve(); await gate; });
  cleanup.push(async () => { release(); await runtime.cancel(job.jobId); await job.completion.catch(() => undefined); });
  assert.equal(runtime.status().queued, 1);
  assert.equal((await http(server, "/worker/stop", { stop: true })).status, 409);
  runtime.resumeDispatch(); await started;
  assert.equal(runtime.status().running, 1);
  assert.equal((await http(server, "/worker/stop", { stop: true })).status, 409);
  assert.equal(stops, 0);
  release(); await job.completion;
  const socket = await raw(), disconnected = once(socket, "close");
  assert.equal((await http(server, "/worker/stop", { stop: true })).status, 202);
  await stopped; await disconnected;
  assert.equal(stops, 1); assert.equal(socket.destroyed, true);
});
