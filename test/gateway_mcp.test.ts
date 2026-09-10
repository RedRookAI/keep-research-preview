import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { composeKeep, type KeepApp } from "../src/compose.js";
import { handleGatewayRequest } from "../src/gateway/http_gateway.js";
import { buildGatewayMcpServer, handleMcpToolCall, listGatewayMcpTools, type McpToolCall } from "../src/mcp/gateway_mcp.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { MemoryStore } from "../src/memory/store.js";
import { HmacAssertionProvider, PrincipalRegistry } from "../src/identity/identity_provider.js";
import { SessionStore } from "../src/identity/session_store.js";

const TOKEN = "mcp-token";
const SEC = { token: TOKEN };
function callOf(name: string, args: Record<string, unknown> = {}, token = TOKEN): McpToolCall { return { name, args, token }; }

function newMemory(): MemoryStore {
  return new MemoryStore(new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-mcp-mem-"))), new InProcessLock(), new SchemaRegistry()), new ModelGateway(new LocalProvider()));
}
function newApp(identity?: KeepApp["identity"]): KeepApp {
  return composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-mcp-")),
    ...(identity === undefined ? {} : { identity }),
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

function tenantIdentity() {
  return {
    provider: new HmacAssertionProvider("synthetic-mcp-identity-key"),
    registry: new PrincipalRegistry([
      { subject: "alice-sub", id: "alice", role: "maintainer", tenant: "alpha" },
      { subject: "bob-sub", id: "bob", role: "maintainer", tenant: "beta" },
    ]),
    sessions: new SessionStore(),
  };
}

test("KEEP-12C-001: token-only MCP cannot select owner access on an identity-aware app", async () => {
  const identity = tenantIdentity(), app = newApp(identity);
  const alpha = app.projectManager!.create({ name: "private alpha project", tenant: "alpha" });
  const beta = app.projectManager!.create({ name: "private beta project", tenant: "beta" });
  const direct = await handleGatewayRequest(app, {
    method: "GET", path: "/projects", query: {}, headers: { authorization: `Bearer ${TOKEN}` }, body: "",
  }, { token: TOKEN, identity });
  assert.equal(direct.status, 403, "ordinary identity-aware gateway refuses missing session");
  const result = await handleMcpToolCall(app, callOf("keep_projects"), SEC);
  assert.equal(result.ok, false, "MCP must not drop app.identity and select OWNER");
  for (const project of [alpha, beta]) assert.ok(!JSON.stringify(result).includes(project.id));
});

test("KEEP-12C-002: gateway input failure is not successful MCP execution", async () => {
  const result = await handleMcpToolCall(newApp(), callOf("keep_project", { goal: "" }), SEC);
  assert.equal(result.ok, false);
});

test("KEEP-12C-002: business refusal under HTTP 200 is not successful MCP execution", async () => {
  const app = newApp(), id = await parkOne(app);
  const result = await handleMcpToolCall(app, callOf("keep_approve", { id: "unknown-approval" }), SEC);
  assert.equal(result.ok, false);
  assert.equal(app.vetoQueue!.runnable(id), false, "unrelated parked work stays unapproved");
});

async function login(app: KeepApp, identity: ReturnType<typeof tenantIdentity>, subject: string): Promise<string> {
  const response = await handleGatewayRequest(app, {
    method: "POST", path: "/auth/session", query: {}, headers: { authorization: `Bearer ${TOKEN}` },
    body: JSON.stringify({ assertion: identity.provider.sign({ sub: subject, exp: Date.now() + 60_000 }) }),
  }, { token: TOKEN, identity });
  assert.equal(response.status, 200, response.body);
  return (JSON.parse(response.body) as { session: string }).session;
}

test("KEEP-12C-001: authenticated MCP sessions preserve both tenants and ignore identity claims in args", async () => {
  const identity = tenantIdentity(), app = newApp(identity);
  const alpha = app.projectManager!.create({ name: "alpha-only", tenant: "alpha" });
  const beta = app.projectManager!.create({ name: "beta-only", tenant: "beta" });
  const alice = await login(app, identity, "alice-sub"), bob = await login(app, identity, "bob-sub");
  for (const [session, own, foreign] of [[alice, alpha, beta], [bob, beta, alpha]] as const) {
    const result = await handleMcpToolCall(app, {
      ...callOf("keep_projects", { tenant: foreign.tenant, role: "owner", session: session === alice ? bob : alice }), session,
    }, SEC);
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.ok(JSON.stringify(result.content).includes(own.id), "own project remains useful");
    assert.ok(!JSON.stringify(result).includes(foreign.id), "foreign project excluded");
    assert.ok(!JSON.stringify(result).includes(session), "session credential not returned");
  }
  for (const call of [
    callOf("keep_projects", { session: alice, tenant: "alpha", role: "owner" }),
    { ...callOf("keep_projects"), session: "wrong-session" },
    { ...callOf("keep_projects", {}, "wrong-token"), session: alice },
  ]) {
    const result = await handleMcpToolCall(app, call, SEC);
    assert.equal(result.ok, false);
    assert.equal(result.isError, true);
    assert.ok(!JSON.stringify(result).includes(alpha.id));
    assert.ok(!JSON.stringify(result).includes(beta.id));
  }
});

test("KEEP-12C-001: cached handlers recheck revocation and expiry without switching to owner", async () => {
  const identity = tenantIdentity(), app = newApp(identity);
  const session = await login(app, identity, "alice-sub");
  const server = buildGatewayMcpServer(app, SEC, session);
  assert.equal((await server.callTool("keep_projects", {})).ok, true);
  identity.sessions.revoke(session);
  assert.equal((await server.callTool("keep_projects", {})).ok, false);
  const expired = identity.sessions.create({ id: "alice", kind: "human", role: "maintainer", tenant: "alpha" }, 0);
  const result = await handleMcpToolCall(app, { ...callOf("keep_projects"), session: expired.id }, SEC);
  assert.equal(result.ok, false);
  assert.match(result.error ?? "", /HTTP 403/);
});

test("KEEP-12C-001: explicit gateway identity and principal resolver work without implicit owner substitution", async () => {
  const identity = tenantIdentity(), app = newApp();
  const alpha = app.projectManager!.create({ name: "alpha", tenant: "alpha" });
  const beta = app.projectManager!.create({ name: "beta", tenant: "beta" });
  const session = await login(app, identity, "alice-sub");
  const sessionResult = await handleMcpToolCall(app, { ...callOf("keep_projects"), session }, { ...SEC, identity });
  assert.equal(sessionResult.ok, true);
  assert.ok(JSON.stringify(sessionResult).includes(alpha.id));
  assert.ok(!JSON.stringify(sessionResult).includes(beta.id));
  const principalFor = (request: { headers: Record<string, string> }) => request.headers["x-keep-session"] === "trusted-resolver-proof"
    ? { id: "bob", kind: "human" as const, role: "viewer" as const, tenant: "beta" } : undefined;
  const resolved = await handleMcpToolCall(app, { ...callOf("keep_projects"), session: "trusted-resolver-proof" }, { ...SEC, principalFor });
  assert.equal(resolved.ok, true);
  assert.ok(JSON.stringify(resolved).includes(beta.id));
  assert.ok(!JSON.stringify(resolved).includes(alpha.id));
  assert.equal((await handleMcpToolCall(app, callOf("keep_projects"), { ...SEC, principalFor })).ok, false);
});

test("KEEP-12C-001: conflicting or replaced application identity cannot reuse bound handlers", async () => {
  const identity = tenantIdentity(), other = tenantIdentity(), app = newApp(identity);
  const session = await login(app, identity, "alice-sub");
  const call = { ...callOf("keep_projects"), session };
  assert.equal((await handleMcpToolCall(app, call, { ...SEC, identity: other })).ok, false);
  assert.equal((await handleMcpToolCall(app, call, { ...SEC, principalFor: () => ({ id: "spoof", kind: "human", role: "owner", tenant: "beta" }) })).ok, false);
  const server = buildGatewayMcpServer(app, SEC, session);
  Object.defineProperty(app, "identity", { value: other });
  const result = await server.callTool("keep_projects", {});
  assert.equal(result.ok, false);
  assert.match(result.error ?? "", /configuration changed/);
});

test("KEEP-12C-002: direct registry and wrapped calls agree on API and business failures", async () => {
  const app = newApp(), server = buildGatewayMcpServer(app, TOKEN);
  for (const [name, args, status] of [
    ["keep_project", { goal: "" }, 400],
    ["keep_approve", { id: "missing" }, 200],
    ["keep_veto", { id: "missing" }, 200],
  ] as const) {
    const direct = await server.callTool(name, args), wrapped = await handleMcpToolCall(app, callOf(name, args), SEC);
    assert.equal(direct.ok, false);
    assert.equal(wrapped.ok, false);
    assert.equal(wrapped.isError, true);
    assert.match(direct.error ?? "", new RegExp(`HTTP ${status}`));
    assert.equal(wrapped.error, direct.error);
  }
  const conflict = await handleMcpToolCall(app, callOf("keep_projects"), { ...SEC, identity: tenantIdentity(), principalFor: () => undefined });
  assert.equal(conflict.ok, false);
  assert.match(conflict.error ?? "", /HTTP 500/);
  const useful = await server.callTool("keep_projects", {});
  assert.equal(useful.ok, true);
  assert.equal((await server.callTool("unknown-tool", {})).ok, false);
});

test("MCP: blank tokens and unexpected exceptions never become success or expose raw diagnostics", async () => {
  const app = newApp();
  assert.equal((await handleMcpToolCall(app, callOf("keep_projects", {}, ""), { token: "" })).ok, false);
  assert.equal((await buildGatewayMcpServer(app, " ").callTool("keep_projects", {})).ok, false);
  const privateDiagnostic = `credential:${TOKEN}:private-provider-detail`;
  const badInput = { toString() { throw new Error(privateDiagnostic); } };
  const failure = await handleMcpToolCall(app, callOf("keep_project", { goal: badInput }), SEC);
  assert.equal(failure.ok, false);
  assert.equal(failure.isError, true);
  assert.match(failure.error ?? "", /outcome not established/);
  assert.ok(!JSON.stringify(failure).includes(privateDiagnostic));
});
