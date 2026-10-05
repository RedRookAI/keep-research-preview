import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { spawn } from "node:child_process";
import { composeKeep, type KeepConfig } from "../src/compose.js";
import { handleGatewayRequest, type GatewayRequest, type GatewaySecurity } from "../src/gateway/http_gateway.js";
import { FileSpineStore } from "../src/spine/store.js";
import { BudgetLedger, type AuthorizationEnvelope } from "../src/scheduler/authorization_envelope.js";
import { CostModel } from "../src/observability/cost_model.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { HmacAssertionProvider, PrincipalRegistry } from "../src/identity/identity_provider.js";
import { SessionStore } from "../src/identity/session_store.js";
import { RbacAuthorizer, type Principal } from "../src/identity/rbac.js";
import { FileSystemLock } from "../src/lock/lock.js";

const model = "gpt-5.4-mini"; // Existing configured rates; no live model/price claim.
const token = "SYNTHETIC_GATEWAY_ONLY";
const message = "Project notes: a tiny task queue.";
const multipleChunks = "A".repeat(2400); // Existing chunker makes two chunks.
const cap = 0.0018; // Allows one 256-output projection, excludes two outstanding projections.
function root(t: TestContext): string {
  const dir = mkdtempSync(join(tmpdir(), "keep-frontdoor-money-"));
  t.after(() => rmSync(dir, { recursive: true, force: true })); return dir;
}
function events(dir: string) {
  const store = new FileSpineStore(dir);
  return [...new Map([...store.readBlocks().flatMap(b => [...b.events]), ...store.readStaged()]
    .map(event => [event.id, event])).values()];
}
function money(dir: string) { return events(dir).filter(e => e.actor === "monetary-ledger").map(e => e.payload); }
function budget(amount = 1): AuthorizationEnvelope {
  return { id: "frontdoor-fixture", projectId: "frontdoor-fixture", allowedClasses: ["auto-research"], allowedTiers: [],
    dailyCapUsd: amount, perRunCapUsd: amount, perCallTokenCeiling: 20_000,
    expiresAt: Number.MAX_SAFE_INTEGER, grantedReason: "synthetic FrontDoor admission; zero paid calls" };
}
function request(text = message, sessionId?: string, extra: Record<string, unknown> = {}): GatewayRequest {
  return { method: "POST", path: "/message", query: {}, headers: { authorization: `Bearer ${token}`,
    ...(sessionId === undefined ? {} : { "x-keep-session": sessionId }) },
    body: JSON.stringify({ message: text, hasAttachments: true, attachmentCount: 1, ...extra }) };
}
function useful(response: { status: number; body: string } | { kind: string; say: string }) {
  if ("status" in response) assert.equal(response.status, 200, response.body);
  const result = "status" in response ? JSON.parse(response.body).result as { kind: string; say: string } : response;
  assert.equal(result.kind, "understand"); assert.match(result.say, /I went through [12] sections? across 1 file/u);
}
function response(usage: unknown = { prompt_tokens: 1, completion_tokens: 1 }) {
  return { model, choices: [{ message: { content: "A task queue with durable jobs." }, finish_reason: "stop" }],
    ...(usage === undefined ? {} : { usage }) };
}
async function endpoint(t: TestContext, handle: (req: IncomingMessage, res: ServerResponse) => void): Promise<string> {
  const server = createServer(handle);
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const address = server.address(); assert.ok(address && typeof address !== "string"); return `http://127.0.0.1:${address.port}`;
}
function owner(dataDir: string, baseUrl: string, amount = 1, modelName = model): KeepConfig {
  return { dataDir, ownerProvider: { mode: "openai-compatible", baseUrl, model: modelName, apiKey: "SYNTHETIC_ONLY" },
    remoteProcessing: { purpose: "frontdoor-fixture", region: "test" },
    residency: { allowedPurposes: ["frontdoor-fixture"], allowedRegions: ["test"], egressAllowlist: ["127.0.0.1"], airGapped: false },
    autonomyBudget: budget(amount) };
}
function organization(t: TestContext, tenants = ["alpha", "alpha"]) {
  const dir = root(t), sessions = new SessionStore(), provider = new HmacAssertionProvider("SYNTHETIC_IDP_ONLY");
  const registry = new PrincipalRegistry(tenants.map((tenant, i) => ({ subject: `sub-${i}`, id: `person-${i}`, role: "viewer" as const, tenant })));
  const principals = tenants.map((_, i) => registry.resolve({ subject: `sub-${i}` })!);
  const roster = new Map<string, Principal>(principals.map(p => [p.id, p]));
  const local = new LocalProvider(), original = local.generate.bind(local), calls: string[] = [];
  local.generate = async req => { calls.push(req.prompt); return original(req); };
  const identity = { provider, registry, sessions };
  const config: KeepConfig = { dataDir: dir, provider: local, identity, autonomyBudget: budget(),
    delegationParentFor: (id, tenant) => { const p = roster.get(id); return p?.tenant === tenant ? p : undefined; } };
  return { dir, identity, principals, roster, calls, config, security: { token, identity } satisfies GatewaySecurity };
}

test("FrontDoor gateway reaches local summarization with zero-fee monetary admission", async t => {
  const dir = root(t), app = composeKeep({ dataDir: dir });
  app.gateway.generate = async () => { throw new Error("plain gateway bypass"); };
  useful(await handleGatewayRequest(app, request(), { token }));
  const records = money(dir); assert.equal(records.filter(e => e["op"] === "reserve").length, 1);
  assert.equal(records.filter(e => e["op"] === "settle").length, 1);
  assert.equal((records.find(e => e["op"] === "reserve")!["reservation"] as { amount: number }).amount, 0);
});

test("FrontDoor actual HTTP reserves each chunk before wire and settles matching usage", async t => {
  const dir = root(t); let hits = 0;
  const baseUrl = await endpoint(t, (req, res) => {
    let body = ""; req.on("data", b => { body += String(b); }); req.on("end", () => {
      hits++; const sent = JSON.parse(body); assert.equal(sent.max_tokens, 256); assert.equal(sent.model, model);
      const records = money(dir), reservations = records.filter(e => e["op"] === "reserve");
      assert.equal(reservations.length, hits); assert.equal(records.filter(e => e["op"] === "settle").length, hits - 1);
      assert.equal((reservations.at(-1)!["reservation"] as { amount: number }).amount,
        (Math.ceil(sent.messages[0].content.length / 4) * 0.75 + 256 * 4.5) / 1_000_000);
      res.setHeader("content-type", "application/json"); res.end(JSON.stringify(response()));
    });
  });
  const app = composeKeep(owner(dir, baseUrl)); app.gateway.generate = async () => { throw new Error("plain gateway bypass"); };
  useful(await handleGatewayRequest(app, request(multipleChunks), { token })); assert.equal(hits, 2);
  const records = money(dir), reservations = records.filter(e => e["op"] === "reserve");
  const settled = records.filter(e => e["op"] === "settle"); assert.equal(settled.length, 2);
  for (const [i, entry] of settled.entries()) {
    assert.equal(entry["reservationId"], (reservations[i]!["reservation"] as { id: string }).id);
    assert.equal(typeof entry["amount"], "number");
    assert.ok(Math.abs((entry["amount"] as number) - (0.75 + 4.5) / 1_000_000) < 1e-15);
  }
});

test("FrontDoor unknown pricing refuses wire and keeps deterministic understanding useful", async t => {
  const dir = root(t); let hits = 0;
  const baseUrl = await endpoint(t, (_req, res) => { hits++; res.end(); });
  useful(await handleGatewayRequest(composeKeep(owner(dir, baseUrl, 1, "unknown-frontdoor-price")), request(multipleChunks), { token }));
  assert.equal(hits, 0); assert.equal(money(dir).filter(e => e["op"] === "reserve").length, 0);
});

test("FrontDoor malformed attachment metadata refuses before any model call", async t => {
  const dir = root(t), app = composeKeep({ dataDir: dir });
  for (const extra of [{ hasAttachments: "true" }, { attachmentCount: -1 }, { attachmentCount: 1.5 }, { attachmentCount: "1" }, { attachmentCount: null }]) {
    assert.equal((await handleGatewayRequest(app, request(message, undefined, extra), { token })).status, 400);
  }
  assert.equal(money(dir).length, 0);
  useful(await handleGatewayRequest(app, request(message, undefined, { hasAttachments: false, attachmentCount: 1 }), { token }));
});

test("FrontDoor exhausted, expired, revoked and disallowed grants refuse wire", async t => {
  let hits = 0; const baseUrl = await endpoint(t, (_req, res) => { hits++; res.end(); });
  for (const state of ["exhausted", "expired", "revoked", "class", "token-ceiling"]) {
    const dir = root(t), envelope = { ...budget(state === "exhausted" ? 0 : 1),
      ...(state === "expired" ? { expiresAt: 0 } : {}), ...(state === "class" ? { allowedClasses: [] } : {}),
      ...(state === "token-ceiling" ? { perCallTokenCeiling: 1 } : {}) };
    const config = { ...owner(dir, baseUrl), autonomyBudget: envelope };
    const app = composeKeep(config);
    if (state === "revoked") {
      const ledger = new BudgetLedger(app.spine, new CostModel());
      await ledger.grant(envelope); await ledger.beginRun("autonomy-subsystem", envelope.id);
      await ledger.revoke(envelope.id, "synthetic revocation");
    }
    useful(await handleGatewayRequest(app, request(multipleChunks), { token }));
    assert.equal(money(dir).filter(e => e["op"] === "reserve").length, 0, state);
  }
  assert.equal(hits, 0);
});

for (const invalid of ["missing-usage", "malformed-usage", "lost-ack", "provider-error"]) {
  test(`FrontDoor ${invalid}: one attempt per message, durable hold across fresh process`, async t => {
    const dir = root(t); let hits = 0;
    const baseUrl = await endpoint(t, (req, res) => {
      hits++; req.resume();
      if (invalid === "lost-ack") { req.socket.destroy(); return; }
      res.setHeader("content-type", "application/json");
      if (invalid === "provider-error") { res.statusCode = 503; res.end('{"error":"synthetic"}'); return; }
      const body = response(); if (invalid === "missing-usage") delete (body as { usage?: unknown }).usage;
      else body.usage = { prompt_tokens: "unknown", completion_tokens: -1 };
      res.end(JSON.stringify(body));
    });
    const config = owner(dir, baseUrl, cap);
    useful(await handleGatewayRequest(composeKeep(config), request(multipleChunks), { token }));
    assert.equal(hits, 1); const held = money(dir).filter(e => e["op"] === "reserve"); assert.equal(held.length, 1);
    const amount = (held[0]!["reservation"] as { amount: number }).amount; assert.ok(amount <= cap && amount * 2 > cap);
    assert.equal(money(dir).filter(e => e["op"] === "settle" || e["op"] === "void").length, 0);
    const code = `import {composeKeep} from './dist/src/compose.js';import {handleGatewayRequest} from './dist/src/gateway/http_gateway.js';
      const result=await handleGatewayRequest(composeKeep(JSON.parse(process.argv[1])),JSON.parse(process.argv[2]),{token:process.argv[3]});
      console.log(result.status);`;
    const child = spawn(process.execPath, ["--input-type=module", "-e", code, JSON.stringify(config), JSON.stringify(request(multipleChunks)), token],
      { cwd: process.cwd(), env: process.env, stdio: ["ignore", "pipe", "pipe"] });
    let output = "", error = ""; child.stdout.on("data", b => { output += String(b); }); child.stderr.on("data", b => { error += String(b); });
    const exit = await new Promise<number | null>((resolve, reject) => { child.once("error", reject); child.once("exit", resolve); });
    assert.equal(exit, 0, error); assert.equal(output.trim(), "200"); assert.equal(hits, 1);
    assert.deepEqual(money(dir).filter(e => e["op"] === "reserve"), held);
    assert.equal(money(dir).filter(e => e["op"] === "settle" || e["op"] === "void").length, 0);
  });
}

test("FrontDoor pending actual HTTP exposure excludes a concurrent message", async t => {
  const dir = root(t); let hits = 0, entered!: () => void, finish!: () => void;
  const started = new Promise<void>(resolve => { entered = resolve; });
  const baseUrl = await endpoint(t, (req, res) => {
    hits++; req.resume(); finish = () => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify(response())); }; entered();
  });
  const app = composeKeep(owner(dir, baseUrl, cap));
  const first = handleGatewayRequest(app, request(), { token }); await started;
  try { useful(await handleGatewayRequest(app, request(), { token })); assert.equal(hits, 1); }
  finally { finish(); }
  useful(await first); assert.equal(money(dir).filter(e => e["op"] === "reserve").length, 1);
});

test("FrontDoor uses an authenticated viewer session and review permission, distinct from provider-check", async t => {
  const f = organization(t), app = composeKeep(f.config);
  const assertion = f.identity.provider.sign({ sub: "sub-0", exp: Date.now() + 60_000 });
  const login = await handleGatewayRequest(app, { ...request(), path: "/auth/session", body: JSON.stringify({ assertion }) }, f.security);
  assert.equal(login.status, 200, login.body); const sessionId = JSON.parse(login.body).session as string;
  useful(await handleGatewayRequest(app, request(message, sessionId, { tenant: "forged", sessionId: "forged" }), f.security));
  assert.equal(f.calls.length, 1); await assert.rejects(app.providerCheck("probe", sessionId), /not authorized/u);
  assert.equal(f.calls.length, 1);
  useful(await app.frontDoorMessage(message, { subject: "other", sessionId, hasAttachments: true }));
  assert.equal(f.calls.length, 1, "foreign tenant label cannot borrow session");
});

for (const tenants of [["alpha", "alpha"], ["alpha", "beta"]]) {
  test(`FrontDoor concurrent ${tenants[0] === tenants[1] ? "same-tenant sessions" : "different tenants"} retain separate authority`, async t => {
    const f = organization(t, tenants), firstSession = f.identity.sessions.create(f.principals[0]!, Date.now());
    const secondSession = f.identity.sessions.create(f.principals[1]!, Date.now());
    const lock = new FileSystemLock(join(f.dir, ".locks")); let pause = true, entered!: () => void, release!: () => void;
    const waiting = new Promise<void>(resolve => { entered = resolve; }), resume = new Promise<void>(resolve => { release = resolve; });
    const app = composeKeep({ ...f.config, lock: { withLock: async (key, fn) => {
      const result = await lock.withLock(key, fn);
      if (pause && money(f.dir).some(e => e["op"] === "reserve")) { pause = false; entered(); await resume; }
      return result;
    } } });
    const first = handleGatewayRequest(app, request("First person's project notes.", firstSession.id), f.security); await waiting;
    try {
      useful(await handleGatewayRequest(app, request("Second person's project notes.", secondSession.id), f.security));
      f.identity.sessions.revoke(firstSession.id);
    } finally { release(); }
    useful(await first); assert.equal(f.calls.length, 1); assert.match(f.calls[0]!, /Second person's/u);
    assert.equal(money(f.dir).filter(e => e["op"] === "reserve").length, 2);
    assert.equal(money(f.dir).filter(e => e["op"] === "settle").length, 1);
    useful(await app.frontDoorForSubject!(tenants[1]!).handle(message, { hasAttachments: true }));
    assert.equal(f.calls.length, 1, "completed request leaves no reusable session context");
  });
}

test("FrontDoor rejects lost roster/role/session and missing live context without new reservations", async t => {
  const f = organization(t), app = composeKeep(f.config), session = f.identity.sessions.create(f.principals[0]!, Date.now());
  useful(await handleGatewayRequest(app, request(message, session.id), f.security)); assert.equal(f.calls.length, 1);
  f.roster.delete(f.principals[0]!.id);
  useful(await handleGatewayRequest(app, request(message, session.id), f.security));
  f.roster.set(f.principals[0]!.id, { ...f.principals[0]!, role: "operator" });
  useful(await handleGatewayRequest(app, request(message, session.id), f.security));
  f.roster.set(f.principals[0]!.id, f.principals[0]!);
  f.identity.sessions.revoke(session.id);
  assert.equal((await handleGatewayRequest(app, request(message, session.id), f.security)).status, 403);
  assert.equal((await handleGatewayRequest(app, request(), f.security)).status, 403);
  const expired = f.identity.sessions.create(f.principals[0]!, 0);
  assert.equal((await handleGatewayRequest(app, request(message, expired.id), f.security)).status, 403);
  useful(await app.frontDoorMessage(message, { subject: "alpha", hasAttachments: true }));
  assert.equal(f.calls.length, 1); assert.equal(money(f.dir).filter(e => e["op"] === "reserve").length, 1);
});

test("FrontDoor permission loss after reservation refuses entry and retains its hold", async t => {
  const f = organization(t), session = f.identity.sessions.create(f.principals[0]!, Date.now());
  const lock = new FileSystemLock(join(f.dir, ".locks")), rbac = new RbacAuthorizer(); let denied = false;
  const app = composeKeep({ ...f.config, authorization: { authorize: (p, permission) =>
    denied && permission === "review.view" ? { allow: false, reason: "synthetic revocation" } : rbac.authorize(p, permission) },
    lock: { withLock: async (key, fn) => { const value = await lock.withLock(key, fn);
      if (money(f.dir).some(e => e["op"] === "reserve")) denied = true; return value; } } });
  useful(await handleGatewayRequest(app, request(message, session.id), f.security));
  assert.equal(f.calls.length, 0); assert.equal(money(f.dir).filter(e => e["op"] === "reserve").length, 1);
  assert.equal(money(f.dir).filter(e => e["op"] === "settle" || e["op"] === "void").length, 0);
});

test("FrontDoor organization session cannot borrow an owner remote route or forged body authority", async t => {
  const f = organization(t); let hits = 0;
  const baseUrl = await endpoint(t, (_req, res) => { hits++; res.end(); });
  const app = composeKeep({ ...owner(f.dir, baseUrl), identity: f.identity, delegationParentFor: f.config.delegationParentFor! });
  const session = f.identity.sessions.create(f.principals[0]!, Date.now());
  useful(await handleGatewayRequest(app, request(message, session.id), f.security));
  const personalApp = composeKeep(owner(root(t), baseUrl));
  useful(await handleGatewayRequest(personalApp, request(message, undefined, { sessionId: session.id }),
    { token, principalFor: () => f.principals[0] }));
  assert.equal(hits, 0); assert.equal(money(f.dir).filter(e => e["op"] === "reserve").length, 0);
});
