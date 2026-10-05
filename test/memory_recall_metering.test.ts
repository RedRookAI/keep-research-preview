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
import { SessionStore } from "../src/identity/session_store.js";
import { HmacAssertionProvider, PrincipalRegistry } from "../src/identity/identity_provider.js";
import type { Principal } from "../src/identity/rbac.js";

const model = "text-embedding-3-small", query = "deploy window", token = "SYNTHETIC_ONLY";
const projected = Buffer.byteLength(JSON.stringify({ model, input: [query] }));
const projectionUsd = projected * 0.02 / 1_000_000;
function root(t: TestContext) {
  const dir = mkdtempSync(join(tmpdir(), "keep-recall-money-"));
  t.after(() => rmSync(dir, { recursive: true, force: true })); return dir;
}
function money(dir: string) {
  const s = new FileSpineStore(dir);
  return [...new Map([...s.readBlocks().flatMap(b => [...b.events]), ...s.readStaged()].map(e => [e.id, e])).values()]
    .filter(e => e.actor === "monetary-ledger").map(e => e.payload);
}
function budget(cap = 1): AuthorizationEnvelope {
  return { id: "recall-test", projectId: "recall-test", allowedClasses: ["auto-research"], allowedTiers: [],
    dailyCapUsd: cap, perRunCapUsd: cap, perCallTokenCeiling: 65_536, expiresAt: Number.MAX_SAFE_INTEGER,
    grantedReason: "synthetic recall fixture; zero paid calls" };
}
function owner(dataDir: string, cap = 1): KeepConfig {
  return { dataDir, ownerProvider: { mode: "openai-compatible", baseUrl: "https://api.openai.com", model, apiKey: token },
    remoteProcessing: { purpose: "recall", region: "test" },
    embeddingProcessing: { query: { purpose: "recall", region: "test" }, document: { purpose: "document", region: "test" } },
    residency: { allowedPurposes: ["recall", "document"], allowedRegions: ["test"], egressAllowlist: ["api.openai.com"], airGapped: false },
    memoryRecallPricing: { inputPerMillion: 0.02, observedAtMs: Date.now(), maxAgeMs: 60_000 }, autonomyBudget: budget(cap) };
}
function reply(usage: unknown = { prompt_tokens: 2, total_tokens: 2 }, selected = model) {
  return { model: selected, data: [{ index: 0, embedding: [1, 0] }], ...(usage === undefined ? {} : { usage }) };
}
function request(sessionId?: string): GatewayRequest {
  return { method: "GET", path: "/memory", query: { q: query }, headers: { authorization: `Bearer ${token}`,
    ...(sessionId === undefined ? {} : { "x-keep-session": sessionId }) }, body: "" };
}
async function sink(t: TestContext, handle: (req: IncomingMessage, res: ServerResponse) => void) {
  const s = createServer(handle);
  await new Promise<void>((resolve, reject) => { s.once("error", reject); s.listen(0, "127.0.0.1", resolve); });
  const a = s.address(); assert.ok(a && typeof a !== "string");
  const saved = globalThis.fetch;
  globalThis.fetch = (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    return saved(url.startsWith("https://api.openai.com/") ? url.replace("https://api.openai.com", `http://127.0.0.1:${a.port}`) : input, init);
  };
  t.after(() => { globalThis.fetch = saved; return new Promise<void>(resolve => s.close(() => resolve())); });
}

test("memory recall preserves useful local HTTP results and tenant candidate isolation", async t => {
  const app = composeKeep({ dataDir: root(t) });
  await app.secondBrain.memory.ingest(query, { origin: "external", scope: "project", projectId: "alpha" });
  await app.secondBrain.memory.ingest("foreign lesson", { origin: "external", scope: "project", projectId: "beta" });
  const res = await handleGatewayRequest(app, request(), { token, principalFor: () => ({ id: "reader", kind: "human", role: "viewer", tenant: "alpha" }) });
  assert.equal(res.status, 200, res.body);
  const hits = JSON.parse(res.body).hits;
  assert.equal(hits.length, 1); assert.equal(hits[0].content, query); assert.equal(typeof hits[0].id, "string");
});

test("memory recall actual HTTP reserves complete outbound body before wire and settles valid input usage", async t => {
  const dir = root(t); let calls = 0, queryCalls = 0;
  await sink(t, (req, res) => {
    let text = ""; req.on("data", c => text += String(c)); req.on("end", () => {
      calls++; assert.equal(req.url, "/v1/embeddings"); assert.equal(req.headers.authorization, `Bearer ${token}`);
      if (calls > 1) {
        queryCalls++; assert.equal(Buffer.byteLength(text), projected);
        assert.equal(money(dir).filter(e => e["op"] === "reserve").length, 1);
        assert.equal(money(dir).filter(e => e["op"] === "settle").length, 0);
        assert.equal((money(dir).find(e => e["op"] === "reserve")!["reservation"] as { amount: number }).amount, projectionUsd);
      }
      res.setHeader("content-type", "application/json"); res.end(JSON.stringify(reply()));
    });
  });
  const app = composeKeep(owner(dir));
  await app.secondBrain.memory.ingest(query, { origin: "external" }); // document path remains separate
  app.gateway.embed = async () => { throw new Error("query bypassed governed bounded capability"); };
  const result = await handleGatewayRequest(app, request(), { token });
  assert.equal(result.status, 200); assert.equal(JSON.parse(result.body).hits[0].content, query); assert.equal(queryCalls, 1);
  assert.equal(money(dir).find(e => e["op"] === "settle")!["amount"], 2 * 0.02 / 1_000_000);
});

for (const mode of ["missing-price", "expired-price", "future-price", "unknown-model", "other-endpoint", "zero-cap", "missing-purpose", "blocked-host", "oversize", "privacy-transform"] as const) {
  test(`memory recall ${mode} refuses with zero HTTP`, async t => {
    const dir = root(t); let calls = 0;
    await sink(t, (_req, res) => { calls++; res.end(JSON.stringify(reply())); });
    const c = owner(dir), mutable = c as { memoryRecallPricing?: KeepConfig["memoryRecallPricing"]; ownerProvider: NonNullable<KeepConfig["ownerProvider"]>; autonomyBudget: AuthorizationEnvelope; embeddingProcessing?: KeepConfig["embeddingProcessing"]; residency: NonNullable<KeepConfig["residency"]> };
    if (mode === "missing-price") delete mutable.memoryRecallPricing;
    if (mode === "expired-price") mutable.memoryRecallPricing = { ...c.memoryRecallPricing!, observedAtMs: Date.now() - 120_000 };
    if (mode === "future-price") mutable.memoryRecallPricing = { ...c.memoryRecallPricing!, observedAtMs: Date.now() + 120_000 };
    if (mode === "unknown-model") mutable.ownerProvider = { ...c.ownerProvider!, model: "chat-or-unknown" };
    if (mode === "other-endpoint") mutable.ownerProvider = { ...c.ownerProvider!, baseUrl: "https://untrusted.example" };
    if (mode === "zero-cap") mutable.autonomyBudget = budget(0);
    if (mode === "missing-purpose") delete mutable.embeddingProcessing;
    if (mode === "blocked-host") mutable.residency = { ...c.residency!, egressAllowlist: [] };
    const app = composeKeep(c);
    await assert.rejects(app.memoryRecall(mode === "oversize" ? "x".repeat(65_001) : mode === "privacy-transform" ? "Contact person@example.com" : query));
    assert.equal(calls, 0); assert.equal(money(dir).filter(e => e["op"] === "reserve").length, 0);
  });
}

for (const mode of ["missing-usage", "negative-usage", "inconsistent-usage", "wrong-model", "lost-ack", "server-error"] as const) {
  test(`memory recall ${mode} keeps one durable hold across a fresh process`, async t => {
    const dir = root(t); let calls = 0;
    await sink(t, (req, res) => { req.resume(); req.on("end", () => {
      calls++;
      if (mode === "lost-ack") { req.socket.destroy(); return; }
      if (mode === "server-error") { res.statusCode = 503; res.end("unavailable"); return; }
      const usage = mode === "missing-usage" ? null : mode === "negative-usage" ? { prompt_tokens: -1, total_tokens: -1 }
        : mode === "inconsistent-usage" ? { prompt_tokens: 2, total_tokens: 3 }
        : { prompt_tokens: 2, total_tokens: 2 };
      res.setHeader("content-type", "application/json"); res.end(JSON.stringify(reply(usage, mode === "wrong-model" ? "wrong" : model)));
    }); });
    const c = owner(dir, projectionUsd), app = composeKeep(c);
    await assert.rejects(app.memoryRecall(query)); assert.equal(calls, 1);
    const holds = money(dir).filter(e => e["op"] === "reserve"); assert.equal(holds.length, 1);
    const script = `import {composeKeep} from './dist/src/compose.js'; globalThis.fetch=async()=>{throw new Error('unexpected-wire')}; try{await composeKeep(JSON.parse(process.argv[1])).memoryRecall('deploy window');process.exitCode=9;}catch(e){console.log(e.message);process.exitCode=/per-run-cap|daily-cap/.test(e.message)?0:8;}`;
    const child = spawn(process.execPath, ["--input-type=module", "--eval", script, JSON.stringify(c)], {
      cwd: process.cwd(), env: { PATH: process.env["PATH"], LANG: "C", NODE_OPTIONS: process.env["NODE_OPTIONS"] ?? "" }, stdio: ["ignore", "pipe", "pipe"],
    });
    let output = ""; child.stdout.on("data", b => output += String(b)); child.stderr.on("data", b => output += String(b));
    const exit = await new Promise<number | null>((resolve, reject) => { child.once("error", reject); child.once("close", resolve); });
    assert.equal(exit, 0, output); assert.equal(calls, 1); assert.deepEqual(money(dir).filter(e => e["op"] === "reserve"), holds);
    assert.equal(money(dir).filter(e => e["op"] === "settle" || e["op"] === "void").length, 0);
  });
}

test("memory recall pending exposure blocks concurrent admission", async t => {
  const dir = root(t); let calls = 0, entered!: () => void, finish!: () => void;
  const seen = new Promise<void>(resolve => entered = resolve);
  await sink(t, (req, res) => { req.resume(); req.on("end", () => { calls++; finish = () => res.end(JSON.stringify(reply())); entered(); }); });
  const app = composeKeep(owner(dir, projectionUsd)), first = app.memoryRecall(query); await seen;
  try { await assert.rejects(app.memoryRecall(query), /per-run-cap|daily-cap/); assert.equal(calls, 1); } finally { finish(); assert.deepEqual(await first, []); }
});

test("memory recall captures price fields and rechecks permission after reservation", async t => {
  const dir = root(t); let calls = 0, allow = true;
  await sink(t, (req, res) => { req.resume(); req.on("end", () => { calls++; res.end(JSON.stringify(reply())); }); });
  const c = owner(dir), lock = new FileSystemLock(join(dir, ".locks"));
  const app = composeKeep({ ...c, authorization: { authorize: () => ({ allow, reason: "synthetic" }) }, lock: { withLock: async (key, fn) => lock.withLock(key, async () => {
    const v = await fn(); if (money(dir).some(e => e["op"] === "reserve")) allow = false; return v;
  }) } });
  Object.assign(c.memoryRecallPricing!, { inputPerMillion: 99, observedAtMs: 0, maxAgeMs: 1 });
  await assert.rejects(app.memoryRecall(query), /not authorized/); assert.equal(calls, 0);
  const held = money(dir).find(e => e["op"] === "reserve")!["reservation"] as { amount: number };
  assert.equal(held.amount, projectionUsd); assert.equal(money(dir).filter(e => e["op"] === "settle" || e["op"] === "void").length, 0);
});

test("memory recall price expiring after reservation refuses dispatch and keeps the hold", async t => {
  const dir = root(t); let calls = 0;
  await sink(t, (_req, res) => { calls++; res.end(); });
  const c = owner(dir), clock = Date.now, lock = new FileSystemLock(join(dir, ".locks"));
  const app = composeKeep({ ...c, lock: { withLock: async (key, fn) => lock.withLock(key, async () => {
    const v = await fn(); if (money(dir).some(e => e["op"] === "reserve")) Date.now = () => clock() + 120_000; return v;
  }) } });
  try { await assert.rejects(app.memoryRecall(query), /expired/); } finally { Date.now = clock; }
  assert.equal(calls, 0); assert.equal(money(dir).filter(e => e["op"] === "reserve").length, 1);
  assert.equal(money(dir).filter(e => e["op"] === "settle" || e["op"] === "void").length, 0);
});

test("memory recall organization HTTP carries live session and denies missing, revoked and wrong-tenant authority", async t => {
  const dir = root(t), sessions = new SessionStore();
  const principal: Principal = { id: "human", kind: "human", role: "viewer", tenant: "alpha" };
  const identity = { provider: new HmacAssertionProvider(token), registry: new PrincipalRegistry([]), sessions };
  const local = new LocalProvider(), original = local.embed.bind(local); let calls = 0;
  local.embed = async texts => { calls++; return original(texts); };
  const app = composeKeep({ dataDir: dir, provider: local, identity, delegationParentFor: (id, tenant) => id === principal.id && tenant === principal.tenant ? principal : undefined });
  await app.secondBrain.memory.ingest(query, { origin: "external", scope: "project", projectId: "alpha" }); calls = 0;
  await assert.rejects(app.memoryRecall(query, { subject: "alpha" }), /live admitted/); assert.equal(calls, 0);
  const session = sessions.create(principal, Date.now());
  const res = await handleGatewayRequest(app, request(session.id), { token, identity });
  assert.equal(res.status, 200, res.body); assert.equal(JSON.parse(res.body).hits[0].content, query); assert.equal(calls, 1);
  await assert.rejects(app.memoryRecall(query, { sessionId: session.id, subject: "beta" }), /live admitted/);
  sessions.revoke(session.id); await assert.rejects(app.memoryRecall(query, { sessionId: session.id, subject: "alpha" }), /live admitted/); assert.equal(calls, 1);
  const borrowed = composeKeep({ ...owner(root(t)), identity, delegationParentFor: () => principal });
  const active = sessions.create(principal, Date.now());
  await assert.rejects(borrowed.memoryRecall(query, { sessionId: active.id, subject: "alpha" }), /no owner fallback/);
});


test("memory recall rejects invalid captured price declarations and unavailable monetary grants", async t => {
  for (const patch of [{ inputPerMillion: 0 }, { inputPerMillion: Number.NaN }, { observedAtMs: -1 }, { maxAgeMs: 0 }]) {
    const c = owner(root(t));
    assert.throws(() => composeKeep({ ...c, memoryRecallPricing: { ...c.memoryRecallPricing!, ...patch } }), /invalid memory-recall price/);
  }
  let calls = 0;
  await sink(t, (_req, res) => { calls++; res.end(); });
  for (const grant of [{ ...budget(), expiresAt: 0 }, { ...budget(), allowedClasses: [] }]) {
    await assert.rejects(composeKeep({ ...owner(root(t)), autonomyBudget: grant }).memoryRecall(query), /expired|class-not-authorized/);
  }
  assert.equal(calls, 0);
});

test("memory recall HTTP refusal is bounded and a zero output ceiling still permits input-only embeddings", async t => {
  const dir = root(t); let calls = 0;
  await sink(t, (req, res) => { req.resume(); req.on("end", () => { calls++; res.end(JSON.stringify(reply())); }); });
  const denied = composeKeep(owner(root(t), 0));
  const refusal = await handleGatewayRequest(denied, request(), { token });
  assert.equal(refusal.status, 409); assert.equal(calls, 0); assert.match(refusal.body, /pending accounting/);
  const c = owner(dir), app = composeKeep({ ...c, autonomyBudget: { ...budget(), perCallTokenCeiling: 0 } });
  assert.deepEqual(await app.memoryRecall(query), []); assert.equal(calls, 1);
  assert.equal(money(dir).find(e => e["op"] === "settle")!["amount"], 2 * 0.02 / 1_000_000);
});


test("memory recall observed usage overrun settles actual spend and blocks further paid admission", async t => {
  const dir = root(t); let calls = 0;
  await sink(t, (req, res) => { req.resume(); req.on("end", () => { calls++; res.end(JSON.stringify(reply({ prompt_tokens: projected + 1, total_tokens: projected + 1 }))); }); });
  const app = composeKeep(owner(dir));
  await assert.rejects(app.memoryRecall(query), /exceeded its projection/); assert.equal(calls, 1);
  const settlement = money(dir).find(e => e["op"] === "settle")!;
  assert.equal(settlement["amount"], (projected + 1) * 0.02 / 1_000_000); assert.equal(settlement["exceededReservation"], true);
  await assert.rejects(app.memoryRecall(query), /projection-exceeded/); assert.equal(calls, 1);
});
