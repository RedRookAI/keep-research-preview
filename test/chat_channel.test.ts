import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHmac } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";

import { composeKeep, type KeepApp } from "../src/compose.js";
import { handleGatewayRequest, startGatewayServer } from "../src/gateway/http_gateway.js";
import { handleChannelEvent, type ChannelEvent, type ChannelSecurity, type InboundEnvelope } from "../src/channel/chat_channel.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { MemoryStore } from "../src/memory/store.js";

const TOKEN = "chan-token";
const SEC: ChannelSecurity = { token: TOKEN, verify: (_raw, sig) => sig === "good" };
function signed(event: ChannelEvent): InboundEnvelope { return { event, signature: "good", raw: JSON.stringify(event) }; }
function unsigned(event: ChannelEvent): InboundEnvelope { return { event, signature: "bad", raw: JSON.stringify(event) }; }

function newMemory(): MemoryStore {
  const dir = mkdtempSync(join(tmpdir(), "keep-chan-mem-"));
  return new MemoryStore(new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry()), new ModelGateway(new LocalProvider()));
}
function newApp(projectPosture: "autonomous" | "approval-required" = "approval-required"): KeepApp {
  return composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-chan-")),
    projectPosture,
    frontDoorMemory: newMemory(),
    solve: async (issue: { id: string }) => ({ solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, detail: "ok" } } } as never),
  });
}
async function parkOne(app: KeepApp): Promise<string> {
  await handleGatewayRequest(app, { method: "POST", path: "/project", query: {}, headers: { authorization: `Bearer ${TOKEN}` }, body: JSON.stringify({ goal: "email the report to the team" }) }, { token: TOKEN });
  return app.vetoQueue!.parked()[0]!.id;
}

test("CHANNEL: an inbound chat message returns Keep's real reply", async () => {
  const app = newApp();
  const r = await handleChannelEvent(app, signed({ kind: "message", text: "add a login button to the homepage" }), SEC);
  assert.ok(r.text.length > 0 && !/couldn't handle/.test(r.text), "a real handled reply comes back over the channel");
});

test("CHANNEL: signed project operations share the durable gateway while unsigned creation is inert", async () => {
  const app = newApp();
  assert.match((await handleChannelEvent(app, unsigned({ kind: "project", goal: "must not exist" }), SEC)).text, /couldn't be verified/);
  assert.equal(app.autonomyLoop!.manager.list().length, 0);
  assert.match((await handleChannelEvent(app, signed({ kind: "project", goal: "write and test a markdown parser" }), SEC)).text, /Project status:/);
  assert.match((await handleChannelEvent(app, signed({ kind: "projects" }), SEC)).text, /write and test a markdown parser/);
});

test("CHANNEL: an unsigned event is REFUSED and drives no gateway call", async () => {
  const app = newApp();
  const id = await parkOne(app);
  const r = await handleChannelEvent(app, unsigned({ kind: "approve", id }), SEC);
  assert.match(r.text, /couldn't be verified/, "the event is refused");
  assert.equal(app.vetoQueue!.runnable(id), false, "an unsigned approve drove NO /veto/approve call");
});

test("CHANNEL: an 'approve {id}' action maps to /veto/approve and makes the item runnable", async () => {
  const app = newApp();
  const id = await parkOne(app);
  const r = await handleChannelEvent(app, signed({ kind: "approve", id }), SEC);
  assert.match(r.text, /Approved/, "the chat action confirms approval");
  assert.equal(app.vetoQueue!.runnable(id), true, "explicit chat approve → runnable");
});

test("CHANNEL: a 'veto {id}' action removes the parked item", async () => {
  const app = newApp();
  const id = await parkOne(app);
  const r = await handleChannelEvent(app, signed({ kind: "veto", id }), SEC);
  assert.match(r.text, /Vetoed/, "the chat action confirms the veto");
  assert.equal(app.vetoQueue!.parked().length, 0, "the parked item is removed");
});

test("CHANNEL: a 'digest' request lists parked items as an actionable list", async () => {
  const app = newApp();
  await parkOne(app);
  const r = await handleChannelEvent(app, signed({ kind: "digest" }), SEC);
  assert.match(r.text, /awaiting your OK/, "the digest summarises parked items");
  assert.match(r.text, /approve .+ \/  veto/, "each item is actionable from chat");
});

async function startInstalledChat(env: NodeJS.ProcessEnv): Promise<{ child: ChildProcessWithoutNullStreams; origin: string }> {
  const child = spawn(process.execPath, [join(process.cwd(), "dist/src/channel/chat_server.js")], { env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] });
  const origin = await new Promise<string>((resolve, reject) => { let stdout = ""; let stderr = ""; child.stderr.on("data", (chunk) => { stderr += String(chunk); }); child.once("exit", (code) => reject(new Error(`chat adapter exited ${code}: ${stderr}`))); child.stdout.on("data", (chunk) => { stdout += String(chunk); const newline = stdout.indexOf("\n"); if (newline < 0) return; const ready = JSON.parse(stdout.slice(0, newline)) as { host: string; port: number }; resolve(`http://${ready.host}:${ready.port}`); }); });
  return { child, origin };
}
async function stopChild(child: ChildProcessWithoutNullStreams): Promise<void> { if (child.exitCode !== null) return; child.kill("SIGTERM"); await new Promise<void>((resolve) => child.once("exit", () => resolve())); }
function signedChatRequest(origin: string, secret: string, id: string, event: ChannelEvent): Promise<Response> { const raw = JSON.stringify(event); const timestamp = String(Math.floor(Date.now() / 1000)); const signature = createHmac("sha256", secret).update(`${timestamp}.${raw}`).digest("hex"); return fetch(`${origin}/event`, { method: "POST", headers: { "content-type": "application/json", "x-webhook-id": id, "x-webhook-timestamp": timestamp, "x-webhook-signature": `sha256=${signature}` }, body: raw }); }

test("packaged signed chat entry shares gateway state and rejects replay across restart", async () => {
  const pkg = JSON.parse(readFileSync(join(process.cwd(), "package.json"), "utf8")) as { bin: Record<string, string> }; assert.equal(pkg.bin["keep-chat"], "dist/src/channel/chat_server.js");
  const app = newApp("autonomous"); const gateway = await startGatewayServer(app, { token: TOKEN, host: "127.0.0.1", port: 0 }); const secret = "development-chat-secret"; const replayFile = join(mkdtempSync(join(tmpdir(), "keep-chat-replay-")), "window.jsonl"); const env = { KEEP_GATEWAY_ORIGIN: `http://127.0.0.1:${gateway.port}`, KEEP_GATEWAY_TOKEN: TOKEN, KEEP_CHAT_SECRET: secret, KEEP_CHAT_REPLAY_FILE: replayFile, KEEP_CHAT_PORT: "0" }; let installed = await startInstalledChat(env);
  try {
    assert.equal((await fetch(`${installed.origin}/event`, { method: "POST", body: JSON.stringify({ kind: "project", goal: "must not exist" }) })).status, 401);
    assert.equal((await signedChatRequest(installed.origin, secret, "delivery-1", { kind: "project", goal: "shared installed chat project" })).status, 200);
    assert.equal((await signedChatRequest(installed.origin, secret, "delivery-1", { kind: "project", goal: "shared installed chat project" })).status, 409);
    await stopChild(installed.child); installed = await startInstalledChat(env);
    assert.equal((await signedChatRequest(installed.origin, secret, "delivery-1", { kind: "project", goal: "shared installed chat project" })).status, 409);
    assert.equal(app.autonomyLoop!.manager.list().length, 1, "the signed delivery created exactly one durable project and replay created none");
  } finally { await stopChild(installed.child); await gateway.close(); }
});
