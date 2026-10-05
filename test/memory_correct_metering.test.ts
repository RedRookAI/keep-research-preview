import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { composeKeep, type KeepConfig, type KeepApp } from "../src/compose.js";
import { FileSpineStore } from "../src/spine/store.js";
import { FileSystemLock } from "../src/lock/lock.js";
import type { AuthorizationEnvelope } from "../src/scheduler/authorization_envelope.js";
import { handleGatewayRequest, type GatewayRequest } from "../src/gateway/http_gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { HmacAssertionProvider, PrincipalRegistry } from "../src/identity/identity_provider.js";
import { SessionStore } from "../src/identity/session_store.js";
import type { Principal } from "../src/identity/rbac.js";

const model = "text-embedding-3-small", note = "corrected deploy window", token = "SYNTHETIC_ONLY";
const projectionBytes = Buffer.byteLength(JSON.stringify({ model, input: [note] })), projectedUsd = projectionBytes * 0.02 / 1_000_000;
function root(t: TestContext) { const d = mkdtempSync(join(tmpdir(), "keep-correct-money-")); t.after(() => rmSync(d, { recursive: true, force: true })); return d; }
function events(dir: string) { const s = new FileSpineStore(dir); return [...new Map([...s.readBlocks().flatMap(b => [...b.events]), ...s.readStaged()].map(e => [e.id, e])).values()]; }
function money(dir: string) { return events(dir).filter(e => e.actor === "monetary-ledger").map(e => e.payload); }
function budget(cap = 1): AuthorizationEnvelope { return { id: "manual-write-test", projectId: "manual-write-test", allowedClasses: ["auto-research"], allowedTiers: [], dailyCapUsd: cap, perRunCapUsd: cap, perCallTokenCeiling: 0, expiresAt: Number.MAX_SAFE_INTEGER, grantedReason: "synthetic document fixture; zero paid requests" }; }
function owner(dataDir: string, cap = 1): KeepConfig { return { dataDir, ownerProvider: { mode: "openai-compatible", baseUrl: "https://api.openai.com", model, apiKey: token }, remoteProcessing: { purpose: "query", region: "test" }, embeddingProcessing: { query: { purpose: "query", region: "test" }, document: { purpose: "document", region: "test" } }, residency: { allowedPurposes: ["query", "document"], allowedRegions: ["test"], egressAllowlist: ["api.openai.com"], airGapped: false }, memoryRecallPricing: { inputPerMillion: 0.02, observedAtMs: Date.now(), maxAgeMs: 60_000 }, memoryStorePricing: { inputPerMillion: 0.02, observedAtMs: Date.now(), maxAgeMs: 60_000 }, autonomyBudget: budget(cap) }; }
function response(usage: unknown = { prompt_tokens: 2, total_tokens: 2 }, selected = model) { return { model: selected, data: [{ index: 0, embedding: [1, 0] }], ...(usage === undefined ? {} : { usage }) }; }
function post(id: string, content = note, extra: Record<string, unknown> = {}, sessionId?: string): GatewayRequest { return { method: "POST", path: "/memory/correct", query: {}, headers: { authorization: `Bearer ${token}`, ...(sessionId === undefined ? {} : { "x-keep-session": sessionId }) }, body: JSON.stringify({ id, content, processing: "configured-provider", ...extra }) }; }
async function seed(app: KeepApp, projectId?: string) {
  app.gateway.embed = async () => [[1, 0]]; // Existing fixture note; no unmetered vendor setup call.
  const old = await app.secondBrain.memory.ingest("old deploy window", { origin: "self", ...(projectId === undefined ? {} : { scope: "project", projectId }) });
  assert.ok(old); app.gateway.embed = async () => { throw new Error("correction bypassed bounded manual capability"); }; return old;
}
async function sink(t: TestContext, handle: (req: IncomingMessage, res: ServerResponse) => void) {
  const s = createServer(handle); await new Promise<void>((resolve, reject) => { s.once("error", reject); s.listen(0, "127.0.0.1", resolve); });
  const a = s.address(); assert.ok(a && typeof a !== "string"); const saved = globalThis.fetch;
  globalThis.fetch = (input, init) => { const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url; return saved(url.startsWith("https://api.openai.com/") ? url.replace("https://api.openai.com", `http://127.0.0.1:${a.port}`) : input, init); };
  t.after(() => { globalThis.fetch = saved; return new Promise<void>(resolve => s.close(() => resolve())); });
}

test("manual correction actual HTTP create-correct-recall binds charge and supersedes lineage", async t => {
  const dir = root(t); let calls = 0, oldId = ""; const bodies: string[] = [];
  await sink(t, (req, res) => { let body = ""; req.on("data", b => body += String(b)); req.on("end", () => {
    calls++; bodies.push(JSON.parse(body).input[0]); assert.equal(req.url, "/v1/embeddings");
    assert.equal(money(dir).filter(e => e["op"] === "reserve").length, calls);
    assert.equal(money(dir).filter(e => e["op"] === "settle").length, calls - 1);
    if (calls === 2) { assert.equal(events(dir).filter(e => e.payload["event"] === "lesson_corrected").length, 0); assert.equal(app.secondBrain.memory.get(oldId)!.tier, "candidate"); }
    res.end(JSON.stringify(response()));
  }); });
  const c = owner(dir); Object.assign(c.memoryRecallPricing!, { inputPerMillion: 0.07 }); const app = composeKeep(c);
  app.gateway.embed = async () => { throw new Error("manual memory bypassed bounded admission"); };
  const create = await handleGatewayRequest(app, { ...post(""), path: "/memory", body: JSON.stringify({ content: "old deploy window", processing: "configured-provider" }) }, { token });
  assert.equal(create.status, 200, create.body); oldId = JSON.parse(create.body).id;
  const result = await handleGatewayRequest(app, post(oldId), { token }); assert.equal(result.status, 200, result.body);
  const ids = JSON.parse(result.body); assert.equal(ids.oldId, oldId); assert.notEqual(ids.newId, oldId);
  assert.equal(app.secondBrain.memory.get(oldId)!.tier, "retired");
  const fresh = app.secondBrain.memory.get(ids.newId)!; assert.equal(fresh.content, note); assert.equal(fresh.citation, `supersedes:${oldId}`);
  const recall = await handleGatewayRequest(app, { method: "GET", path: "/memory", query: { q: note }, headers: { authorization: `Bearer ${token}` }, body: "" }, { token });
  assert.equal(recall.status, 200); assert.equal(JSON.parse(recall.body).hits[0].id, ids.newId); assert.equal(calls, 3);
  assert.deepEqual(bodies, ["old deploy window", note, note]);
  assert.deepEqual(money(dir).filter(e => e["op"] === "settle").map(e => e["amount"]), [2 * 0.02 / 1_000_000, 2 * 0.02 / 1_000_000, 2 * 0.07 / 1_000_000]);
  assert.deepEqual(events(dir).filter(e => e.payload["event"] === "price_selected").map(e => [e.actor, e.payload["role"]]), [["memory-store", "document"], ["memory-correct", "document"], ["memory-recall", "query"]]);
});

for (const mode of ["no-consent", "bad-consent", "no-document-price", "expired-price", "future-price", "no-document-purpose", "blocked-host", "no-budget", "unknown-model", "oversized", "serialized-bound", "rejected-ingestion"] as const) {
  test(`manual correction ${mode} has zero wire and preserves original`, async t => {
    const dir = root(t); let calls = 0; await sink(t, (_req, res) => { calls++; res.end(); });
    const c = owner(dir) as KeepConfig & { memoryStorePricing?: KeepConfig["memoryStorePricing"]; residency: NonNullable<KeepConfig["residency"]>; autonomyBudget: AuthorizationEnvelope; ownerProvider: NonNullable<KeepConfig["ownerProvider"]> };
    if (mode === "no-document-price") delete c.memoryStorePricing;
    if (mode === "expired-price") c.memoryStorePricing = { ...c.memoryStorePricing!, observedAtMs: Date.now() - 120_000 };
    if (mode === "future-price") c.memoryStorePricing = { ...c.memoryStorePricing!, observedAtMs: Date.now() + 120_000 };
    if (mode === "no-document-purpose") c.residency = { ...c.residency, allowedPurposes: ["query"] };
    if (mode === "blocked-host") c.residency = { ...c.residency, egressAllowlist: [] };
    if (mode === "no-budget") c.autonomyBudget = budget(0);
    if (mode === "unknown-model") c.ownerProvider = { ...c.ownerProvider, model: "chat-model" };
    const app = composeKeep(c), old = await seed(app), content = mode === "oversized" ? "x".repeat(8001) : mode === "serialized-bound" ? "\"".repeat(5000) : mode === "rejected-ingestion" ? "Licensed under the GNU GPL v3" : note;
    const res = await handleGatewayRequest(app, post(old.id, content, mode === "no-consent" ? { processing: undefined } : mode === "bad-consent" ? { processing: "other" } : {}), { token });
    assert.ok([400, 404, 409].includes(res.status), res.body); assert.equal(calls, 0); assert.deepEqual(app.secondBrain.memory.get(old.id), old); assert.equal(app.secondBrain.memory.all().length, 1);
    assert.equal(money(dir).filter(e => e["op"] === "reserve").length, 0);
  });
}

test("manual correction missing retired and foreign IDs dispatch nothing", async t => {
  const dir = root(t); let calls = 0; await sink(t, (_req, res) => { calls++; res.end(); });
  const app = composeKeep(owner(dir)), old = await seed(app, "alpha");
  assert.equal(await app.memoryCorrect({ id: "missing", content: note }, { processing: "configured-provider" }), null);
  // Trusted per-operation seam confirms foreign lookup rejects before invoking an encoder.
  const foreign = await app.secondBrain.memory.correct(old.id, note, "beta", { embedDocument: async () => { throw new Error("foreign note reached encoder"); } }); assert.equal(foreign, null);
  assert.deepEqual(app.secondBrain.memory.getForProject("alpha", old.id), old);
  assert.ok(app.secondBrain.memory.retireForProject("alpha", old.id, "fixture"));
  assert.equal(await app.memoryCorrect({ id: old.id, content: note }, { processing: "configured-provider" }), null);
  assert.equal(calls, 0); assert.equal(money(dir).length, 0);
});

for (const mode of ["missing-usage", "negative-usage", "wrong-model", "lost-ack", "server-error"] as const) {
  test(`manual correction ${mode} retains original and durable hold across fresh process`, async t => {
    const dir = root(t); let calls = 0;
    await sink(t, (req, res) => { req.resume(); req.on("end", () => { calls++;
      if (mode === "lost-ack") { req.socket.destroy(); return; }
      if (mode === "server-error") { res.statusCode = 503; res.end("unavailable"); return; }
      res.end(JSON.stringify(response(mode === "missing-usage" ? null : mode === "negative-usage" ? { prompt_tokens: -1, total_tokens: -1 } : { prompt_tokens: 2, total_tokens: 2 }, mode === "wrong-model" ? "wrong" : model)));
    }); });
    const c = owner(dir, projectedUsd), app = composeKeep(c), old = await seed(app);
    assert.equal((await handleGatewayRequest(app, post(old.id), { token })).status, 409); assert.equal(calls, 1); assert.deepEqual(app.secondBrain.memory.get(old.id), old); assert.equal(app.secondBrain.memory.all().length, 1);
    const held = money(dir).filter(e => e["op"] === "reserve"); assert.equal(held.length, 1);
    const script = `import {composeKeep} from './dist/src/compose.js';globalThis.fetch=async()=>{throw new Error('unexpected-wire')};const app=composeKeep(JSON.parse(process.argv[1]));app.gateway.embed=async()=>[[1,0]];const old=await app.secondBrain.memory.ingest('old deploy window',{origin:'self'});app.gateway.embed=async()=>{throw new Error('unmetered-wire')};try{await app.memoryCorrect({id:old.id,content:'corrected deploy window'},{processing:'configured-provider'});process.exitCode=9}catch(e){console.log(e.message);process.exitCode=/per-run-cap|daily-cap/.test(e.message)?0:8}`;
    const child = spawn(process.execPath, ["--input-type=module", "--eval", script, JSON.stringify(c)], { cwd: process.cwd(), env: { PATH: process.env["PATH"], LANG: "C", NODE_OPTIONS: process.env["NODE_OPTIONS"] ?? "" }, stdio: ["ignore", "pipe", "pipe"] });
    let out = ""; child.stdout.on("data", b => out += String(b)); child.stderr.on("data", b => out += String(b));
    const exit = await new Promise<number | null>((resolve, reject) => { child.once("error", reject); child.once("close", resolve); }); assert.equal(exit, 0, out);
    assert.deepEqual(money(dir).filter(e => e["op"] === "reserve"), held); assert.equal(money(dir).filter(e => e["op"] === "settle" || e["op"] === "void").length, 0); assert.equal(calls, 1);
  });
}

for (const mode of ["permission-before-wire", "permission-before-publication", "publication-error", "overrun"] as const) {
  test(`manual correction ${mode} retains original and actual accounting`, async t => {
    const dir = root(t); let calls = 0, allowed = true;
    await sink(t, (req, res) => { req.resume(); req.on("end", () => { calls++; if (mode === "permission-before-publication") allowed = false; res.end(JSON.stringify(response(mode === "overrun" ? { prompt_tokens: projectionBytes + 1, total_tokens: projectionBytes + 1 } : undefined))); }); });
    const lock = new FileSystemLock(join(dir, ".locks")), app = composeKeep({ ...owner(dir), authorization: { authorize: (_p, permission) => ({ allow: permission !== "memory.write" || allowed, reason: "synthetic" }) },
      ...(mode === "permission-before-wire" ? { lock: { withLock: async (key, fn) => lock.withLock(key, async () => { const result = await fn(); if (money(dir).some(e => e["op"] === "reserve")) allowed = false; return result; }) } } : {}),
    });
    const old = await seed(app);
    if (mode === "publication-error") { const stage = app.spine.stage.bind(app.spine); app.spine.stage = input => { if (input.actor === "memory" && input.payload["event"] === "lesson_corrected") throw new Error("synthetic replacement publication failure"); return stage(input); }; }
    assert.equal((await handleGatewayRequest(app, post(old.id), { token })).status, 409); assert.deepEqual(app.secondBrain.memory.get(old.id), old); assert.equal(app.secondBrain.memory.all().length, 1);
    assert.equal(calls, mode === "permission-before-wire" ? 0 : 1); assert.equal(money(dir).filter(e => e["op"] === "reserve").length, 1);
    assert.equal(money(dir).filter(e => e["op"] === "settle").length, mode === "permission-before-wire" ? 0 : 1); assert.equal(money(dir).filter(e => e["op"] === "void").length, 0);
    if (mode === "overrun") { assert.equal(money(dir).find(e => e["op"] === "settle")!["amount"], (projectionBytes + 1) * 0.02 / 1_000_000); assert.equal((await handleGatewayRequest(app, post(old.id), { token })).status, 409); assert.equal(calls, 1); }
  });
}

for (const mutation of ["reweight", "retire", "competing-correction"] as const) {
  test(`manual correction ${mutation} during embedding preserves winning state and paid charge`, async t => {
    const dir = root(t); let calls = 0, enter!: () => void, finish!: () => void; const seen = new Promise<void>(r => enter = r);
    await sink(t, (req, res) => { req.resume(); req.on("end", () => { calls++; if (calls === 1) { finish = () => res.end(JSON.stringify(response())); enter(); } else res.end(JSON.stringify(response())); }); });
    const app = composeKeep(owner(dir)), old = await seed(app), pending = handleGatewayRequest(app, post(old.id), { token }); await seen;
    try {
      if (mutation === "reweight") assert.ok(app.secondBrain.memory.reweight(old.id, 0.93));
      if (mutation === "retire") assert.ok(app.secondBrain.memory.retire(old.id, "concurrent fixture"));
      if (mutation === "competing-correction") { const winner = await app.memoryCorrect({ id: old.id, content: "winning correction" }, { processing: "configured-provider" }); assert.ok(winner); assert.equal(app.secondBrain.memory.get(winner.newId)!.content, "winning correction"); }
    } finally { finish(); assert.equal((await pending).status, 404); }
    const state = app.secondBrain.memory.all(); assert.equal(state.filter(x => x.content === note).length, 0);
    assert.equal(app.secondBrain.memory.get(old.id)!.tier, mutation === "reweight" ? "candidate" : "retired");
    if (mutation === "reweight") assert.equal(app.secondBrain.memory.get(old.id)!.importance, 0.93);
    assert.equal(calls, mutation === "competing-correction" ? 2 : 1); assert.equal(money(dir).filter(e => e["op"] === "settle").length, calls); assert.equal(money(dir).filter(e => e["op"] === "void").length, 0);
  });
}

test("manual correction captures args consent price and retains original tenant scope", async t => {
  const dir = root(t); let enter!: () => void, finish!: () => void; const seen = new Promise<void>(r => enter = r);
  await sink(t, (req, res) => { req.resume(); req.on("end", () => { finish = () => res.end(JSON.stringify(response())); enter(); }); });
  const c = owner(dir), app = composeKeep(c), old = await seed(app, "alpha"), other = await seed(app, "beta"), args = { id: old.id, content: note }, options = { processing: "configured-provider" as const };
  Object.assign(c.memoryStorePricing!, { inputPerMillion: 99, observedAtMs: 0 });
  const pending = app.memoryCorrect(args, options); await seen; args.id = other.id; args.content = "mutated"; Object.assign(options, { processing: "other", subject: "beta" }); finish();
  const result = await pending; assert.ok(result); assert.equal(result.oldId, old.id); assert.equal(app.secondBrain.memory.getForProject("alpha", result.newId)!.content, note); assert.deepEqual(app.secondBrain.memory.getForProject("beta", other.id), other);
  assert.equal(money(dir).find(e => e["op"] === "settle")!["amount"], 2 * 0.02 / 1_000_000);
});

test("manual correction pending monetary cap excludes concurrent replacement", async t => {
  const dir = root(t); let calls = 0, enter!: () => void, finish!: () => void; const seen = new Promise<void>(r => enter = r);
  await sink(t, (req, res) => { req.resume(); req.on("end", () => { calls++; finish = () => res.end(JSON.stringify(response())); enter(); }); });
  const app = composeKeep(owner(dir, projectedUsd)), old = await seed(app), pending = handleGatewayRequest(app, post(old.id), { token }); await seen;
  try { assert.equal((await handleGatewayRequest(app, post(old.id), { token })).status, 409); assert.equal(calls, 1); assert.deepEqual(app.secondBrain.memory.get(old.id), old); }
  finally { finish(); assert.equal((await pending).status, 200); }
});

test("manual local correction checks organization session tenant and revocation", async t => {
  const sessions = new SessionStore(), principal: Principal = { id: "writer", kind: "human", role: "operator", tenant: "alpha" };
  const identity = { provider: new HmacAssertionProvider(token), registry: new PrincipalRegistry([]), sessions }, provider = new LocalProvider(), original = provider.embed.bind(provider); let calls = 0, revoke = false;
  const app = composeKeep({ dataDir: root(t), provider, identity, delegationParentFor: (id, tenant) => id === principal.id && tenant === principal.tenant ? principal : undefined });
  const old = await seed(app, "alpha"), foreign = await seed(app, "beta"), session = sessions.create(principal, Date.now());
  provider.embed = async texts => { calls++; if (revoke) sessions.revoke(session.id); return original(texts); };
  await assert.rejects(app.memoryCorrect({ id: old.id, content: note }, { subject: "alpha" }), /live admitted/);
  await assert.rejects(app.memoryCorrect({ id: old.id, content: note }, { subject: "beta", sessionId: session.id }), /live admitted/);
  assert.equal((await handleGatewayRequest(app, post(foreign.id, note, {}, session.id), { token, identity })).status, 404); assert.equal(calls, 0);
  const res = await handleGatewayRequest(app, post(old.id, note, {}, session.id), { token, identity }); assert.equal(res.status, 200, res.body);
  assert.ok(app.secondBrain.memory.getForProject("alpha", JSON.parse(res.body).newId)); assert.deepEqual(app.secondBrain.memory.getForProject("beta", foreign.id), foreign);
  revoke = true; const newest = app.secondBrain.memory.get(JSON.parse(res.body).newId)!;
  assert.equal((await handleGatewayRequest(app, post(newest.id, "withheld", {}, session.id), { token, identity })).status, 409); assert.deepEqual(app.secondBrain.memory.get(newest.id), newest);
  const borrowed = composeKeep({ ...owner(root(t)), identity, delegationParentFor: () => principal }), active = sessions.create(principal, Date.now());
  await assert.rejects(borrowed.memoryCorrect({ id: "fixture", content: note }, { subject: "alpha", sessionId: active.id, processing: "configured-provider" }), /no owner fallback/);
});

test("manual local correction preserves injected encoder and rejects query-only caller", async t => {
  const backingProvider = new LocalProvider(); let calls = 0; backingProvider.embed = async texts => { calls++; return texts.map(() => [1, 0]); };
  const backing = composeKeep({ dataDir: root(t), provider: backingProvider }), old = await backing.secondBrain.memory.ingest("old deploy window", { origin: "self" }); assert.ok(old);
  const outer = new LocalProvider(); outer.embed = async () => { throw new Error("changed injected encoder"); };
  const app = composeKeep({ dataDir: root(t), provider: outer, frontDoorMemory: backing.secondBrain.memory });
  const deny = await handleGatewayRequest(app, post(old.id), { token, principalFor: () => ({ id: "reader", kind: "human", role: "viewer" }) }); assert.equal(deny.status, 403); assert.equal(calls, 1);
  const res = await handleGatewayRequest(app, post(old.id, note, { processing: undefined }), { token }); assert.equal(res.status, 200, res.body);
  assert.equal((await app.memoryRecall(note))[0]!.id, JSON.parse(res.body).newId); assert.equal(calls, 3);
  const remote = composeKeep({ ...owner(root(t)), frontDoorMemory: backing.secondBrain.memory }); await assert.rejects(remote.memoryCorrect({ id: old.id, content: note }, { processing: "configured-provider" }), /built-in store/);
});

test("manual local correction owner permission precedes embedding and publication", async t => {
  const provider = new LocalProvider(); let calls = 0, allowed = false;
  const app = composeKeep({ dataDir: root(t), provider, authorization: { authorize: () => ({ allow: allowed, reason: "synthetic" }) } }), old = await seed(app);
  provider.embed = async texts => { calls++; allowed = false; return texts.map(() => [1, 0]); };
  await assert.rejects(app.memoryCorrect({ id: old.id, content: note }), /not authorized/); assert.equal(calls, 0);
  allowed = true; await assert.rejects(app.memoryCorrect({ id: old.id, content: note }), /not authorized/); assert.equal(calls, 1); assert.deepEqual(app.secondBrain.memory.get(old.id), old);
});
