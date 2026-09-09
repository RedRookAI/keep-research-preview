import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { composeKeep } from "../dist/src/compose.js";
import { startGatewayServer } from "../dist/src/gateway/http_gateway.js";
import { MemoryStore } from "../dist/src/memory/store.js";
import { Spine } from "../dist/src/spine/spine.js";
import { FileSpineStore } from "../dist/src/spine/store.js";
import { InProcessLock } from "../dist/src/lock/lock.js";
import { SchemaRegistry } from "../dist/src/spine/upcaster.js";
import { ModelGateway } from "../dist/src/gateway/gateway.js";
import { LocalProvider } from "../dist/src/gateway/local_provider.js";

test("CLIENT-01: the packaged private shell uses the same client core, gateway, and secure-store authority", async () => {
  const shell = await import("keep/client-shell");
  const core = await import("keep/client-core");
  assert.equal(shell.KeepClient, core.KeepClient, "shell package aliases the verified core instead of creating a second client or gateway");
  assert.deepEqual(shell.prepareClientShell("desktop"), {
    platform: "desktop", mode: "development-unsigned", clientModule: "keep/client-core",
    gatewayTransport: "injected-http", credentialStorage: "platform-secure-store-required",
    signing: "not-configured", distribution: "private-development-only",
  });
  const transport = async (request) => { const response = await fetch(request.url, { method: request.method, headers: request.headers, ...(request.body === undefined ? {} : { body: request.body }) }); return { status: response.status, body: await response.text() }; };
  await assert.rejects(shell.connectClientShell({ platform: "desktop", origin: "http://127.0.0.1:1", transport }), /platform secure credential storage/u);

  const memoryDir = mkdtempSync(join(tmpdir(), "keep-private-client-memory-"));
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-private-client-")), frontDoorMemory: new MemoryStore(new Spine(new FileSpineStore(memoryDir), new InProcessLock(), new SchemaRegistry()), new ModelGateway(new LocalProvider())), solve: async (issue) => ({ solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, detail: "ok" } } }) });
  const gateway = await startGatewayServer(app, { token: "credential-vault-token", host: "127.0.0.1", port: 0 });
  try {
    const client = await shell.connectClientShell({ platform: "desktop", origin: `http://127.0.0.1:${gateway.port}`, transport, credentialStore: { kind: "platform-secure-store", read: async () => "credential-vault-token" } });
    const started = await client.startProject("one gateway from packaged private shell");
    assert.ok(started.runId);
    assert.ok((await client.projects()).projects.some((project) => project.name === "one gateway from packaged private shell"));
  } finally { await gateway.close(); }
});
