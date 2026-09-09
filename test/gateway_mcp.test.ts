import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { composeKeep, type KeepApp } from "../src/compose.js";
import { handleGatewayRequest } from "../src/gateway/http_gateway.js";
import { handleMcpToolCall, listGatewayMcpTools, type McpToolCall } from "../src/mcp/gateway_mcp.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { MemoryStore } from "../src/memory/store.js";

const TOKEN = "mcp-token";
const SEC = { token: TOKEN };
function callOf(name: string, args: Record<string, unknown> = {}, token = TOKEN): McpToolCall { return { name, args, token }; }

function newMemory(): MemoryStore {
  return new MemoryStore(new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-mcp-mem-"))), new InProcessLock(), new SchemaRegistry()), new ModelGateway(new LocalProvider()));
}
function newApp(): KeepApp {
  return composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-mcp-")),
    projectPosture: "approval-required",
    frontDoorMemory: newMemory(),
    solve: async (issue: { id: string }) => ({ solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, detail: "ok" } } } as never),
  });
}
async function parkOne(app: KeepApp): Promise<string> {
  await handleGatewayRequest(app, { method: "POST", path: "/project", query: {}, headers: { authorization: `Bearer ${TOKEN}` }, body: JSON.stringify({ goal: "email the report to the team" }) }, { token: TOKEN });
  return app.vetoQueue!.parked()[0]!.id;
}

test("MCP: keep_message returns Keep's real reply", async () => {
  const r = await handleMcpToolCall(newApp(), callOf("keep_message", { message: "add a login button to the homepage" }), SEC);
  assert.ok(r.ok, "the tool dispatched");
  const content = r.content as { result: { say: string } };
  assert.ok(content.result.say.length > 0, "a real handled reply");
});

test("MCP: an unauthed tool call is refused and drives no gateway call", async () => {
  const app = newApp();
  const id = await parkOne(app);
  const r = await handleMcpToolCall(app, callOf("keep_approve", { id }, "WRONG"), SEC);
  assert.equal(r.ok, false, "the call is refused");
  assert.match(r.error ?? "", /unauthorized/);
  assert.equal(app.vetoQueue!.runnable(id), false, "an unauthed approve drove NO /veto/approve call");
});

test("MCP: keep_approve maps to /veto/approve and makes the item runnable", async () => {
  const app = newApp();
  const id = await parkOne(app);
  const r = await handleMcpToolCall(app, callOf("keep_approve", { id }), SEC);
  assert.ok(r.ok);
  assert.equal(app.vetoQueue!.runnable(id), true, "explicit MCP approve → runnable");
});

test("MCP: list_tools advertises EXACTLY the tools that dispatch (schema-honest)", async () => {
  const app = newApp();
  const advertised = listGatewayMcpTools().map((t) => t.name);
  assert.ok(advertised.includes("keep_message") && advertised.includes("keep_approve"), "advertises the core tools");
  // Every advertised tool actually dispatches (no phantom): calling it never returns "no tool".
  for (const name of advertised) {
    const r = await handleMcpToolCall(app, callOf(name, name === "keep_approve" || name === "keep_veto" ? { id: "nope" } : { message: "hi", goal: "write a parser" }), SEC);
    assert.ok(!/no tool/.test(r.error ?? ""), `advertised tool "${name}" dispatches`);
  }
});
