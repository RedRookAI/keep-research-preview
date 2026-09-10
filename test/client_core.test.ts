import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { KeepClient, KeepClientError, connectClientShell, normalizeGatewayOrigin, prepareClientShell, type ClientTransport, type ClientTransportRequest } from "../src/client/client_core.js";
import { composeKeep } from "../src/compose.js";
import { startGatewayServer } from "../src/gateway/http_gateway.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { MemoryStore } from "../src/memory/store.js";

test("X6 client core is runtime-neutral, authenticates API calls, and leaves health public", async () => {
  const seen: ClientTransportRequest[] = [];
  const client = new KeepClient({
    origin: "http://127.0.0.1:7788/",
    token: "private-token",
    transport: async (request) => {
      seen.push(request);
      if (request.url.endsWith("/health")) return { status: 200, body: '{"ok":true}' };
      return { status: 200, body: '{"projects":[],"active":null}' };
    },
  });

  assert.deepEqual(await client.health(), { ok: true });
  assert.deepEqual(await client.projects(), { projects: [], active: null });
  assert.equal(seen[0]!.headers["authorization"], undefined);
  assert.equal(seen[1]!.headers["authorization"], "Bearer private-token");
  assert.equal(seen[1]!.url, "http://127.0.0.1:7788/projects");
});

test("X6 client posts shared project and decision behavior through the gateway contract", async () => {
  const seen: ClientTransportRequest[] = [];
  const client = new KeepClient({ origin: "https://keep.internal", token: "t", transport: async (request) => {
    seen.push(request);
    return { status: 200, body: request.url.endsWith("/project") ? '{"status":"review","note":null}' : '{"ok":true,"runnable":true}' };
  } });

  assert.deepEqual(await client.startProject("repair the parser"), { status: "review", note: null });
  assert.deepEqual(await client.approve("decision-1"), { ok: true, runnable: true });
  assert.equal(seen[0]!.body, '{"goal":"repair the parser"}');
  assert.equal(seen[1]!.body, '{"id":"decision-1"}');
});

test("SURF-08: lifecycle request serialization (not gateway acceptance)", async () => {
  const seen: ClientTransportRequest[] = [];
  const client = new KeepClient({ origin: "https://keep.internal", token: "t", transport: async (request) => { seen.push(request); return { status: 200, body: "{}" }; } });
  await client.switchProject("p1"); await client.archiveProject("p1"); await client.deleteProject("p1", "p1");
  assert.deepEqual(seen.map((request) => JSON.parse(request.body!)), [
    { projectId: "p1" }, { projectId: "p1" }, { projectId: "p1", confirmProjectId: "p1" },
  ]);
});

test("X6 client rejects unsafe origins and exposes typed gateway failures", async () => {
  for (const origin of ["file:///tmp/keep", "http://example.test", "https://token@example.test", "https://example.test/api", "https://example.test/?token=x"]) {
    assert.throws(() => normalizeGatewayOrigin(origin));
  }
  const client = new KeepClient({ origin: "https://example.test", token: "t", transport: async () => ({ status: 401, body: '{"error":"unauthorized"}' }) });
  await assert.rejects(client.projects(), (error: unknown) => error instanceof KeepClientError && error.status === 401 && error.message === "unauthorized");
});

test("SURF-08: client shell requires secure credentials and shares the installed gateway contract", async () => {
  const transport: ClientTransport = async (request) => { const response = await fetch(request.url, { method: request.method, headers: request.headers, ...(request.body === undefined ? {} : { body: request.body }) }); return { status: response.status, body: await response.text() }; };
  await assert.rejects(connectClientShell({ platform: "desktop", origin: "http://127.0.0.1:1", transport }), /requires platform secure credential storage/);
  await assert.rejects(connectClientShell({ platform: "desktop", origin: "http://127.0.0.1:1", transport, credentialStore: { kind: "platform-secure-store", read: async () => null } }), /token is missing/);

  const memoryDir = mkdtempSync(join(tmpdir(), "keep-client-memory-"));
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-client-")), frontDoorMemory: new MemoryStore(new Spine(new FileSpineStore(memoryDir), new InProcessLock(), new SchemaRegistry()), new ModelGateway(new LocalProvider())), solve: async (issue: { id: string }) => ({ solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, detail: "ok" } } } as never) });
  const gateway = await startGatewayServer(app, { token: "secure-token", host: "127.0.0.1", port: 0 });
  try {
    const client = await connectClientShell({ platform: "desktop", origin: `http://127.0.0.1:${gateway.port}`, transport, credentialStore: { kind: "platform-secure-store", read: async (key) => key === "keep.gateway.token" ? "secure-token" : null } });
    const started = await client.startProject("project created by installed client core");
    assert.ok(started.runId);
    const detail = await client.project(started.runId!) as { projectId: string; session: { history: readonly { role: string; text: string }[] } };
    assert.ok((await client.projects()).projects.some((project) => project.id === detail.projectId));
    assert.ok(detail.session.history.some((turn) => turn.role === "user" && turn.text === "project created by installed client core"));
  } finally { await gateway.close(); }
});

test("X6 shell preparation is explicitly unsigned and requires platform credential storage", () => {
  for (const platform of ["desktop", "ios", "android"] as const) {
    assert.deepEqual(prepareClientShell(platform), {
      platform,
      mode: "development-unsigned",
      clientModule: "keep/client-core",
      gatewayTransport: "injected-http",
      credentialStorage: "platform-secure-store-required",
      signing: "not-configured",
      distribution: "private-development-only",
    });
  }
});
