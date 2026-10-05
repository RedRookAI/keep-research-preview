import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { composeKeep, type KeepConfig } from "../src/compose.js";
import { FileSpineStore } from "../src/spine/store.js";
import { FileSystemLock } from "../src/lock/lock.js";
import type { AuthorizationEnvelope } from "../src/scheduler/authorization_envelope.js";
import { handleGatewayRequest, type GatewayRequest } from "../src/gateway/http_gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { HmacAssertionProvider, PrincipalRegistry } from "../src/identity/identity_provider.js";
import { SessionStore } from "../src/identity/session_store.js";
import type { Principal } from "../src/identity/rbac.js";

const model = "text-embedding-3-small", note = "deploy window", token = "SYNTHETIC_ONLY";
const projectionBytes = Buffer.byteLength(JSON.stringify({ model, input: [note] })), projectedUsd = projectionBytes * 0.02 / 1_000_000;
function root(t: TestContext) { const d = mkdtempSync(join(tmpdir(), "keep-write-money-")); t.after(() => rmSync(d, { recursive: true, force: true })); return d; }
function events(dir: string) { const s = new FileSpineStore(dir); return [...new Map([...s.readBlocks().flatMap(b => [...b.events]), ...s.readStaged()].map(e => [e.id, e])).values()]; }
function money(dir: string) { return events(dir).filter(e => e.actor === "monetary-ledger").map(e => e.payload); }
function budget(cap = 1): AuthorizationEnvelope { return { id: "manual-write-test", projectId: "manual-write-test", allowedClasses: ["auto-research"], allowedTiers: [], dailyCapUsd: cap, perRunCapUsd: cap, perCallTokenCeiling: 0, expiresAt: Number.MAX_SAFE_INTEGER, grantedReason: "synthetic document fixture; zero paid requests" }; }
function owner(dataDir: string, cap = 1): KeepConfig { return { dataDir, ownerProvider: { mode: "openai-compatible", baseUrl: "https://api.openai.com", model, apiKey: token }, remoteProcessing: { purpose: "query", region: "test" }, embeddingProcessing: { query: { purpose: "query", region: "test" }, document: { purpose: "document", region: "test" } }, residency: { allowedPurposes: ["query", "document"], allowedRegions: ["test"], egressAllowlist: ["api.openai.com"], airGapped: false }, memoryRecallPricing: { inputPerMillion: 0.02, observedAtMs: Date.now(), maxAgeMs: 60_000 }, memoryStorePricing: { inputPerMillion: 0.02, observedAtMs: Date.now(), maxAgeMs: 60_000 }, autonomyBudget: budget(cap) }; }
function response(usage: unknown = { prompt_tokens: 2, total_tokens: 2 }, selected = model) { return { model: selected, data: [{ index: 0, embedding: [1, 0] }], ...(usage === undefined ? {} : { usage }) }; }
function post(content = note, extra: Record<string, unknown> = {}, sessionId?: string): GatewayRequest { return { method: "POST", path: "/memory", query: {}, headers: { authorization: `Bearer ${token}`, ...(sessionId === undefined ? {} : { "x-keep-session": sessionId }) }, body: JSON.stringify({ content, processing: "configured-provider", ...extra }) }; }
async function sink(t: TestContext, handle: (req: IncomingMessage, res: ServerResponse) => void) {
  const s = createServer(handle); await new Promise<void>((resolve, reject) => { s.once("error", reject); s.listen(0, "127.0.0.1", resolve); });
  const a = s.address(); assert.ok(a && typeof a !== "string"); const saved = globalThis.fetch;
  globalThis.fetch = (input, init) => { const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url; return saved(url.startsWith("https://api.openai.com/") ? url.replace("https://api.openai.com", `http://127.0.0.1:${a.port}`) : input, init); };
  t.after(() => { globalThis.fetch = saved; return new Promise<void>(resolve => s.close(() => resolve())); });
}

test("manual write actual POST stores then recalls with distinct document/query reservations", async t => {
  const dir = root(t); let calls = 0;
  await sink(t, (req, res) => { let body = ""; req.on("data", b => body += String(b)); req.on("end", () => {
    calls++; assert.equal(req.url, "/v1/embeddings"); assert.equal(req.headers.authorization, `Bearer ${token}`);
    assert.deepEqual(JSON.parse(body), { model, input: [note] });
    assert.equal(money(dir).filter(e => e["op"] === "reserve").length, calls);
    assert.equal(money(dir).filter(e => e["op"] === "settle").length, calls - 1);
    if (calls === 1) assert.equal(events(dir).filter(e => e.actor === "memory" && e.payload["event"] === "lesson_ingested").length, 0);
    res.end(JSON.stringify(response()));
  }); });
  const c = owner(dir); Object.assign(c.memoryRecallPricing!, { inputPerMillion: 0.07 }); const app = composeKeep(c);
  app.gateway.embed = async () => { throw new Error("manual write bypassed bounded operation capability"); };
  const write = await handleGatewayRequest(app, post(), { token }); assert.equal(write.status, 200, write.body);
  assert.equal(app.secondBrain.memory.all().length, 1); assert.equal(app.secondBrain.memory.all()[0]!.content, note);
  const recall = await handleGatewayRequest(app, { method: "GET", path: "/memory", query: { q: note }, headers: { authorization: `Bearer ${token}` }, body: "" }, { token });
  assert.equal(recall.status, 200); assert.equal(JSON.parse(recall.body).hits[0].id, JSON.parse(write.body).id); assert.equal(calls, 2);
  assert.deepEqual(money(dir).filter(e => e["op"] === "settle").map(e => e["amount"]), [2 * 0.02 / 1_000_000, 2 * 0.07 / 1_000_000]);
  assert.deepEqual(events(dir).filter(e => e.payload["event"] === "price_selected").map(e => e.payload["role"]), ["document", "query"]);
});

for (const mode of ["no-consent", "bad-consent", "no-document-price", "expired-price", "future-price", "no-document-purpose", "blocked-host", "no-budget", "unknown-model", "oversized", "serialized-bound", "rejected-ingestion"] as const) {
  test(`manual write ${mode} makes no HTTP request or lesson`, async t => {
    const dir = root(t); let calls = 0; await sink(t, (_req, res) => { calls++; res.end(); });
    const c = owner(dir) as KeepConfig & { memoryStorePricing?: KeepConfig["memoryStorePricing"]; residency: NonNullable<KeepConfig["residency"]>; autonomyBudget: AuthorizationEnvelope; ownerProvider: NonNullable<KeepConfig["ownerProvider"]> };
    if (mode === "no-document-price") delete c.memoryStorePricing;
    if (mode === "expired-price") c.memoryStorePricing = { ...c.memoryStorePricing!, observedAtMs: Date.now() - 120_000 };
    if (mode === "future-price") c.memoryStorePricing = { ...c.memoryStorePricing!, observedAtMs: Date.now() + 120_000 };
    if (mode === "no-document-purpose") c.residency = { ...c.residency, allowedPurposes: ["query"] };
    if (mode === "blocked-host") c.residency = { ...c.residency, egressAllowlist: [] };
    if (mode === "no-budget") c.autonomyBudget = budget(0);
    if (mode === "unknown-model") c.ownerProvider = { ...c.ownerProvider, model: "chat-model" };
    const app = composeKeep(c), content = mode === "oversized" ? "x".repeat(8001) : mode === "serialized-bound" ? "\"".repeat(5000) : mode === "rejected-ingestion" ? "Licensed under the GNU GPL v3" : note;
    const res = await handleGatewayRequest(app, post(content, mode === "no-consent" ? { processing: undefined } : mode === "bad-consent" ? { processing: "other" } : {}), { token });
    assert.ok([400, 409, 422].includes(res.status), res.body); assert.equal(calls, 0); assert.equal(app.secondBrain.memory.all().length, 0);
    assert.equal(money(dir).filter(e => e["op"] === "reserve").length, 0);
  });
}

for (const mode of ["missing-usage", "negative-usage", "wrong-model", "lost-ack", "server-error"] as const) {
  test(`manual write ${mode} holds one charged opportunity across fresh process without lesson`, async t => {
    const dir = root(t); let calls = 0;
    await sink(t, (req, res) => { req.resume(); req.on("end", () => { calls++;
      if (mode === "lost-ack") { req.socket.destroy(); return; }
      if (mode === "server-error") { res.statusCode = 503; res.end("unavailable"); return; }
      res.end(JSON.stringify(response(mode === "missing-usage" ? null : mode === "negative-usage" ? { prompt_tokens: -1, total_tokens: -1 } : { prompt_tokens: 2, total_tokens: 2 }, mode === "wrong-model" ? "wrong" : model)));
    }); });
    const c = owner(dir, projectedUsd), app = composeKeep(c), result = await handleGatewayRequest(app, post(), { token });
    assert.equal(result.status, 409); assert.equal(calls, 1); assert.equal(app.secondBrain.memory.all().length, 0);
    const held = money(dir).filter(e => e["op"] === "reserve"); assert.equal(held.length, 1);
    const script = `import {composeKeep} from './dist/src/compose.js';globalThis.fetch=async()=>{throw new Error('unexpected-wire')};try{await composeKeep(JSON.parse(process.argv[1])).memoryStore({content:'deploy window'},{processing:'configured-provider'});process.exitCode=9}catch(e){console.log(e.message);process.exitCode=/per-run-cap|daily-cap/.test(e.message)?0:8}`;
    const child = spawn(process.execPath, ["--input-type=module", "--eval", script, JSON.stringify(c)], { cwd: process.cwd(), env: { PATH: process.env["PATH"], LANG: "C", NODE_OPTIONS: process.env["NODE_OPTIONS"] ?? "" }, stdio: ["ignore", "pipe", "pipe"] });
    let out = ""; child.stdout.on("data", b => out += String(b)); child.stderr.on("data", b => out += String(b));
    const exit = await new Promise<number | null>((resolve, reject) => { child.once("error", reject); child.once("close", resolve); }); assert.equal(exit, 0, out);
    assert.deepEqual(money(dir).filter(e => e["op"] === "reserve"), held); assert.equal(money(dir).filter(e => e["op"] === "settle" || e["op"] === "void").length, 0); assert.equal(calls, 1);
  });
}

test("manual write captures document price and scope; other ingestion/correction remains separate", async t => {
  const dir = root(t); let calls = 0, enter!: () => void, finish!: () => void; const seen = new Promise<void>(r => enter = r);
  await sink(t, (req, res) => { req.resume(); req.on("end", () => { calls++; if (calls === 1) { finish = () => res.end(JSON.stringify(response())); enter(); } else res.end(JSON.stringify(response())); }); });
  const c = owner(dir), app = composeKeep(c), args = { content: note, scope: "project" as const, projectId: "alpha" };
  Object.assign(c.memoryStorePricing!, { inputPerMillion: 99, observedAtMs: 0 });
  const pending = app.memoryStore(args, { processing: "configured-provider" }); await seen; args.projectId = "beta"; finish(); assert.ok(await pending);
  assert.equal(app.secondBrain.memory.allForProject("alpha").length, 1); assert.equal(app.secondBrain.memory.allForProject("beta").length, 0);
  assert.equal(money(dir).find(e => e["op"] === "settle")!["amount"], 2 * 0.02 / 1_000_000);
  const lesson = await app.secondBrain.memory.ingest("other note", { origin: "external" }); assert.ok(lesson);
  assert.ok(await app.secondBrain.memory.correct(lesson.id, "corrected note"));
  assert.equal(calls, 3); assert.equal(money(dir).filter(e => e["op"] === "reserve").length, 1);
});

test("manual write concurrent pending reservation refuses second write without a second lesson", async t => {
  const dir = root(t); let calls = 0, enter!: () => void, finish!: () => void; const seen = new Promise<void>(r => enter = r);
  await sink(t, (req, res) => { req.resume(); req.on("end", () => { calls++; finish = () => res.end(JSON.stringify(response())); enter(); }); });
  const app = composeKeep(owner(dir, projectedUsd)), pending = handleGatewayRequest(app, post(), { token }); await seen;
  try { assert.equal((await handleGatewayRequest(app, post(), { token })).status, 409); assert.equal(calls, 1); }
  finally { finish(); assert.equal((await pending).status, 200); }
  assert.equal(app.secondBrain.memory.all().length, 1);
});

for (const mode of ["permission-before-wire", "permission-before-publication", "publication-error", "overrun"] as const) {
  test(`manual write ${mode} preserves actual accounting and withholds lesson`, async t => {
    const dir = root(t); let calls = 0, writeAllowed = true;
    await sink(t, (req, res) => { req.resume(); req.on("end", () => { calls++; if (mode === "permission-before-publication") writeAllowed = false; res.end(JSON.stringify(response(mode === "overrun" ? { prompt_tokens: projectionBytes + 1, total_tokens: projectionBytes + 1 } : undefined))); }); });
    const c = owner(dir), lock = new FileSystemLock(join(dir, ".locks"));
    const app = composeKeep({ ...c, authorization: { authorize: (_principal, permission) => ({ allow: permission !== "memory.write" || writeAllowed, reason: "synthetic" }) },
      ...(mode === "permission-before-wire" ? { lock: { withLock: async (key, fn) => lock.withLock(key, async () => { const v = await fn(); if (money(dir).some(e => e["op"] === "reserve")) writeAllowed = false; return v; }) } } : {}),
    });
    if (mode === "publication-error") { const stage = app.spine.stage.bind(app.spine); app.spine.stage = input => { if (input.actor === "memory" && input.payload["event"] === "lesson_ingested") throw new Error("synthetic publication failure"); return stage(input); }; }
    assert.equal((await handleGatewayRequest(app, post(), { token })).status, 409); assert.equal(app.secondBrain.memory.all().length, 0);
    assert.equal(calls, mode === "permission-before-wire" ? 0 : 1); assert.equal(money(dir).filter(e => e["op"] === "reserve").length, 1);
    assert.equal(money(dir).filter(e => e["op"] === "settle").length, mode === "permission-before-wire" ? 0 : 1); assert.equal(money(dir).filter(e => e["op"] === "void").length, 0);
    if (mode === "overrun") { assert.equal(money(dir).find(e => e["op"] === "settle")!["amount"], (projectionBytes + 1) * 0.02 / 1_000_000); assert.equal((await handleGatewayRequest(app, post(), { token })).status, 409); assert.equal(calls, 1); }
  });
}

test("manual write local organization HTTP checks live write session and confines tenant", async t => {
  const dir = root(t), sessions = new SessionStore(), principal: Principal = { id: "writer", kind: "human", role: "operator", tenant: "alpha" };
  const identity = { provider: new HmacAssertionProvider(token), registry: new PrincipalRegistry([]), sessions }, local = new LocalProvider(), original = local.embed.bind(local); let calls = 0;
  local.embed = async texts => { calls++; return original(texts); };
  const app = composeKeep({ dataDir: dir, provider: local, identity, delegationParentFor: (id, tenant) => id === principal.id && tenant === principal.tenant ? principal : undefined });
  await assert.rejects(app.memoryStore({ content: note }, { subject: "alpha" }), /live admitted/); assert.equal(calls, 0);
  const session = sessions.create(principal, Date.now()), res = await handleGatewayRequest(app, post(note, {}, session.id), { token, identity });
  assert.equal(res.status, 200, res.body); assert.equal(app.secondBrain.memory.allForProject("alpha").length, 1); assert.equal(app.secondBrain.memory.allForProject("beta").length, 0);
  await assert.rejects(app.memoryStore({ content: note, projectId: "beta" }, { subject: "alpha", sessionId: session.id }), /outside the resolved tenant/);
  sessions.revoke(session.id); await assert.rejects(app.memoryStore({ content: note }, { subject: "alpha", sessionId: session.id }), /live admitted/); assert.equal(calls, 1);
  const borrowed = composeKeep({ ...owner(root(t)), identity, delegationParentFor: () => principal }), active = sessions.create(principal, Date.now());
  await assert.rejects(borrowed.memoryStore({ content: note }, { subject: "alpha", sessionId: active.id, processing: "configured-provider" }), /no owner fallback/);
});

test("manual write local personal needs neither price nor remote consent; query-only permission cannot write", async t => {
  const app = composeKeep({ dataDir: root(t) }); const allowed = await handleGatewayRequest(app, post(note, { processing: undefined }), { token }); assert.equal(allowed.status, 200);
  const denied = await handleGatewayRequest(app, post(), { token, principalFor: () => ({ id: "reader", kind: "human", role: "viewer", tenant: "alpha" }) }); assert.equal(denied.status, 403); assert.equal(app.secondBrain.memory.all().length, 1);
});


test("manual local injected store retains its own embedding representation", async t => {
  const backingProvider = new LocalProvider(); let backingCalls = 0;
  backingProvider.embed = async texts => { backingCalls++; return texts.map(() => [1, 0]); };
  const backing = composeKeep({ dataDir: root(t), provider: backingProvider });
  const outerProvider = new LocalProvider(); outerProvider.embed = async () => { throw new Error("manual write changed injected store encoder"); };
  const app = composeKeep({ dataDir: root(t), provider: outerProvider, frontDoorMemory: backing.secondBrain.memory });
  const write = await handleGatewayRequest(app, post(note, { processing: undefined }), { token }); assert.equal(write.status, 200, write.body);
  assert.equal((await app.memoryRecall(note))[0]!.id, JSON.parse(write.body).id); assert.equal(backingCalls, 2);
});


test("manual write enforces owner local write policy before embedding and again before publication", async t => {
  const provider = new LocalProvider(); let calls = 0, allowed = false;
  provider.embed = async texts => { calls++; allowed = false; return texts.map(() => [1, 0]); };
  const app = composeKeep({ dataDir: root(t), provider, authorization: { authorize: () => ({ allow: allowed, reason: "synthetic local policy" }) } });
  await assert.rejects(app.memoryStore({ content: note }), /not authorized/); assert.equal(calls, 0);
  allowed = true; await assert.rejects(app.memoryStore({ content: note }), /not authorized/); assert.equal(calls, 1);
  assert.equal(app.secondBrain.memory.all().length, 0);
});
