import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { spawn } from "node:child_process";
import { composeKeep, type KeepConfig } from "../src/compose.js";
import { runCli, type CliIO } from "../src/cli/cli_core.js";
import { FileSpineStore } from "../src/spine/store.js";
import { BudgetLedger, type AuthorizationEnvelope } from "../src/scheduler/authorization_envelope.js";
import { CostModel } from "../src/observability/cost_model.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { HmacAssertionProvider, PrincipalRegistry } from "../src/identity/identity_provider.js";
import { SessionStore } from "../src/identity/session_store.js";
import type { Principal } from "../src/identity/rbac.js";
import { FileSystemLock } from "../src/lock/lock.js";

import { priceHtml, priceTransport } from "./fixtures/provider_check_price_source.js";

const model = "deepseek-flash"; // Synthetic current source/transport, no paid request.
const prompt = "probe";
const projectedUsd = (2 * 0.3 + 64 * 1.2) / 1_000_000;
function root(t: TestContext): string {
  const dir = mkdtempSync(join(tmpdir(), "keep-provider-check-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}
function money(dir: string) {
  const store = new FileSpineStore(dir);
  const events = [...store.readBlocks().flatMap(block => [...block.events]), ...store.readStaged()];
  return [...new Map(events.map(event => [event.id, event])).values()]
    .filter(event => event.actor === "monetary-ledger").map(event => event.payload);
}
function budget(cap = 1): AuthorizationEnvelope {
  return { id: "diagnostic-test", projectId: "diagnostic-test", allowedClasses: ["auto-research"], allowedTiers: [],
    dailyCapUsd: cap, perRunCapUsd: cap, perCallTokenCeiling: 64, expiresAt: Number.MAX_SAFE_INTEGER,
    grantedReason: "synthetic diagnostic fixture; no paid calls" };
}
function io(): CliIO & { output: string[] } {
  const output: string[] = [];
  return { output, write: text => output.push(text), prompt: async () => "" };
}
function reply(usage: unknown = { prompt_tokens: 2, completion_tokens: 1 }) {
  return { model, choices: [{ message: { content: "diagnostic-ok" }, finish_reason: "stop" }], ...(usage === undefined ? {} : { usage }) };
}
async function endpoint(t: TestContext, handle: (request: IncomingMessage, response: ServerResponse) => void) {
  const server = createServer(handle);
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const address = server.address(); assert.ok(address && typeof address !== "string");
  priceTransport(t, `http://127.0.0.1:${address.port}`);
  return "https://api.deepseek.com";
}
function owner(dataDir: string, baseUrl: string, modelName = model, cap = 1): KeepConfig {
  return { dataDir, ownerProvider: { mode: "openai-compatible", baseUrl, model: modelName, apiKey: "SYNTHETIC_ONLY" },
    remoteProcessing: { purpose: "diagnostic", region: "test" },
    residency: { allowedPurposes: ["diagnostic"], allowedRegions: ["test"], egressAllowlist: ["api.deepseek.com", "api-docs.deepseek.com"], airGapped: false },
    providerCheckPricing: { maxAgeMs: 60000 }, autonomyBudget: budget(cap) };
}

test("provider-check local CLI uses monetary admission and remains credential-free", async t => {
  const dir = root(t), app = composeKeep({ dataDir: dir }), output = io();
  // A plain-gateway bypass must fail this test rather than produce a false pass.
  app.gateway.generate = async () => { throw new Error("diagnostic bypassed monetary capability"); };
  const result = await runCli(["provider-check", prompt], output, { app });
  assert.equal(result.exitCode, 0, output.output.join("\n"));
  const events = money(dir), reservation = events.find(event => event["op"] === "reserve");
  assert.ok(reservation); assert.equal((reservation["reservation"] as { amount: number }).amount, 0);
  assert.equal(events.filter(event => event["op"] === "settle").length, 1);
});

test("provider-check known configured price reserves durably before actual HTTP and settles reported usage", async t => {
  const dir = root(t); let hits = 0;
  const baseUrl = await endpoint(t, (request, response) => {
    let body = ""; request.on("data", chunk => { body += String(chunk); }); request.on("end", () => {
      hits++;
      assert.equal(request.headers.authorization, "Bearer SYNTHETIC_ONLY");
      const sent = JSON.parse(body); assert.equal(sent.max_tokens, 64); assert.equal(sent.model, model);
      const events = money(dir); assert.equal(events.filter(event => event["op"] === "reserve").length, 1);
      assert.equal(events.filter(event => event["op"] === "settle").length, 0);
      assert.equal((events.find(event => event["op"] === "reserve")!["reservation"] as { amount: number }).amount, projectedUsd);
      response.setHeader("content-type", "application/json"); response.end(JSON.stringify(reply()));
    });
  });
  const app = composeKeep(owner(dir, baseUrl)), output = io();
  assert.equal((await runCli(["provider-check", prompt], output, { app })).exitCode, 0, output.output.join("\n"));
  assert.equal(hits, 1); assert.match(output.output.join("\n"), /diagnostic-ok/u);
  const events = money(dir), held = events.find(event => event["op"] === "reserve")!["reservation"] as { id: string };
  const settled = events.find(event => event["op"] === "settle")!;
  assert.equal(settled["reservationId"], held.id); assert.equal(settled["amount"], (2 * 0.3 + 1.2) / 1_000_000);
});

test("provider-check unknown pricing refuses without HTTP or a reservation", async t => {
  const dir = root(t); let hits = 0;
  const baseUrl = await endpoint(t, (_request, response) => { hits++; response.end(); });
  const app = composeKeep(owner(dir, baseUrl, "unpriced-synthetic-model")), output = io();
  assert.equal((await runCli(["provider-check", prompt], output, { app })).exitCode, 1);
  assert.match(output.output.join("\n"), /price-unknown/u); assert.equal(hits, 0);
  assert.equal(money(dir).filter(event => event["op"] === "reserve").length, 0);
});

for (const invalid of ["missing", "malformed", "lost-ack", "server-error"] as const) {
  test(`provider-check ${invalid}: one actual attempt, unresolved hold survives a fresh process`, async t => {
    const dir = root(t); let hits = 0;
    const baseUrl = await endpoint(t, (request, response) => {
      request.resume(); request.on("end", () => {
        hits++;
        if (invalid === "lost-ack") { request.socket.destroy(); return; }
        if (invalid === "server-error") { response.statusCode = 503; response.end("unavailable"); return; }
        response.setHeader("content-type", "application/json");
        const body = invalid === "missing" ? { ...reply(), usage: undefined } : reply({ prompt_tokens: -1, completion_tokens: 1 });
        response.end(JSON.stringify(body));
      });
    });
    const config = owner(dir, baseUrl, model, projectedUsd), app = composeKeep(config), output = io();
    assert.equal((await runCli(["provider-check", prompt], output, { app })).exitCode, 1);
    assert.equal(hits, 1); assert.equal(money(dir).filter(event => event["op"] === "settle").length, 0);
    const held = money(dir).filter(event => event["op"] === "reserve"); assert.equal(held.length, 1);
    // Real separate Node process: configured startup must neither reset exposure nor replay the ambiguous request.
    const script = `const saved=globalThis.fetch; globalThis.fetch=async(input,init)=> {
      const url=String(input);
      if(url==='https://api-docs.deepseek.com/quick_start/pricing/') {
        const r=new Response(${JSON.stringify(priceHtml())},{headers:{'content-type':'text/html',date:new Date().toUTCString()}});
        Object.defineProperty(r,'url',{value:url});return r;
      } return saved(input,init);
    }; import { composeKeep } from './dist/src/compose.js'; import { runCli } from './dist/src/cli/cli_core.js';
      const app = composeKeep(JSON.parse(process.argv[1])); const result = await runCli(['provider-check','probe'],
        {write: text => process.stdout.write(text+'\\n'), prompt: async () => ''}, {app}); process.exitCode=result.exitCode;`;
    const child = spawn(process.execPath, ["--input-type=module", "--eval", script, JSON.stringify(config)],
      { cwd: process.cwd(), env: { PATH: process.env["PATH"], LANG: "C", NODE_OPTIONS: process.env["NODE_OPTIONS"] ?? "" }, stdio: ["ignore", "pipe", "pipe"] });
    let childOutput = ""; child.stdout.on("data", data => { childOutput += String(data); }); child.stderr.on("data", data => { childOutput += String(data); });
    const code = await new Promise<number | null>((resolve, reject) => { child.once("error", reject); child.once("close", resolve); });
    assert.equal(code, 1, childOutput); assert.match(childOutput, /per-run-cap|daily-cap/u);
    assert.equal(hits, 1); assert.deepEqual(money(dir).filter(event => event["op"] === "reserve"), held);
    assert.equal(money(dir).filter(event => event["op"] === "settle" || event["op"] === "void").length, 0);
  });
}

test("provider-check pending exposure excludes a concurrent second call", async t => {
  const dir = root(t); let hits = 0, entered!: () => void, finish!: () => void;
  const seen = new Promise<void>(resolve => { entered = resolve; });
  const baseUrl = await endpoint(t, (request, response) => {
    request.resume(); request.on("end", () => { hits++; finish = () => { response.setHeader("content-type", "application/json"); response.end(JSON.stringify(reply())); }; entered(); });
  });
  const app = composeKeep(owner(dir, baseUrl, model, projectedUsd)), first = app.providerCheck(prompt);
  await seen;
  try { await assert.rejects(app.providerCheck(prompt), /per-run-cap|daily-cap/u); assert.equal(hits, 1); }
  finally { finish(); }
  assert.equal((await first).text, "diagnostic-ok");
});

test("provider-check revoked or expired monetary grant refuses before HTTP and restart cannot revive it", async t => {
  for (const kind of ["revoked", "expired", "missing-class"] as const) {
    const dir = root(t); let hits = 0;
    const baseUrl = await endpoint(t, (request, response) => { request.resume(); request.on("end", () => { hits++; response.setHeader("content-type", "application/json"); response.end(JSON.stringify(reply())); }); });
    const config = owner(dir, baseUrl);
    if (kind === "expired") (config as { autonomyBudget: AuthorizationEnvelope }).autonomyBudget = { ...budget(), expiresAt: 0 };
    if (kind === "missing-class") (config as { autonomyBudget: AuthorizationEnvelope }).autonomyBudget = { ...budget(), allowedClasses: [] };
    const app = composeKeep(config);
    if (kind === "revoked") {
      await app.providerCheck(prompt); assert.equal(hits, 1);
      await new BudgetLedger(app.spine, new CostModel()).revoke(budget().id, "synthetic revocation");
    }
    await assert.rejects(composeKeep(config).providerCheck(prompt), /expired|class-not-authorized/u);
    assert.equal(hits, kind === "revoked" ? 1 : 0);
  }
});

function organization(t: TestContext) {
  const dir = root(t), sessions = new SessionStore();
  const principal: Principal = { id: "synthetic-human", kind: "human", role: "operator", tenant: "synthetic-tenant" };
  let current: Principal | undefined = principal, calls = 0;
  const provider = new LocalProvider(), generate = provider.generate.bind(provider);
  provider.generate = async request => { calls++; return generate(request); };
  const config: KeepConfig = { dataDir: dir, provider,
    identity: { provider: new HmacAssertionProvider("SYNTHETIC_ONLY"), registry: new PrincipalRegistry([]), sessions },
    delegationParentFor: (id, tenant) => current?.id === id && current.tenant === tenant ? current : undefined };
  return { dir, sessions, principal, config, calls: () => calls, parent: (value: Principal | undefined) => { current = value; } };
}

test("provider-check organization uses a live subject, refuses session/roster/permission loss, and never falls back to OWNER", async t => {
  const f = organization(t), app = composeKeep(f.config);
  await assert.rejects(app.providerCheck(prompt), /live admitted organization subject/u);
  const session = f.sessions.create(f.principal, Date.now());
  assert.equal((await runCli(["provider-check", prompt], io(), { app, providerCheckSession: session.id })).exitCode, 0);
  assert.equal(f.calls(), 1);
  f.sessions.revoke(session.id); await assert.rejects(app.providerCheck(prompt, session.id), /live admitted organization subject/u);
  const expired = f.sessions.create(f.principal, 0); await assert.rejects(app.providerCheck(prompt, expired.id), /live admitted organization subject/u);
  const foreign = f.sessions.create({ ...f.principal, tenant: "foreign-tenant" }, Date.now());
  await assert.rejects(app.providerCheck(prompt, foreign.id), /live admitted organization subject/u);
  const valid = f.sessions.create(f.principal, Date.now());
  f.parent(undefined); await assert.rejects(app.providerCheck(prompt, valid.id), /live admitted organization subject/u);
  f.parent({ ...f.principal, role: "viewer" }); await assert.rejects(app.providerCheck(prompt, valid.id), /live admitted organization subject/u);
  const viewer = f.sessions.create({ ...f.principal, role: "viewer" }, Date.now()); await assert.rejects(app.providerCheck(prompt, viewer.id), /not authorized/u);
  assert.equal(f.calls(), 1, "denied subjects never reach even the synthetic local provider");
  assert.equal(money(f.dir).filter(event => event["op"] === "reserve").length, 1);
});

test("provider-check organization revocation after reservation is rechecked at provider entry", async t => {
  const f = organization(t), session = f.sessions.create(f.principal, Date.now());
  const lock = new FileSystemLock(join(f.dir, ".locks"));
  const app = composeKeep({ ...f.config, lock: { withLock: async (key, fn) => lock.withLock(key, async () => {
    const value = await fn();
    if (money(f.dir).some(event => event["op"] === "reserve")) f.sessions.revoke(session.id);
    return value;
  }) } });
  await assert.rejects(app.providerCheck(prompt, session.id), /live admitted organization subject/u);
  assert.equal(f.calls(), 0); assert.equal(money(f.dir).filter(event => event["op"] === "reserve").length, 1);
  assert.equal(money(f.dir).filter(event => event["op"] === "settle" || event["op"] === "void").length, 0);
});

test("provider-check refuses using an owner remote route as organization authority", async t => {
  const f = organization(t); let hits = 0;
  const baseUrl = await endpoint(t, (_request, response) => { hits++; response.end(); });
  const app = composeKeep({ ...owner(f.dir, baseUrl), identity: f.config.identity!, delegationParentFor: f.config.delegationParentFor! });
  const session = f.sessions.create(f.principal, Date.now());
  await assert.rejects(app.providerCheck(prompt, session.id), /no owner fallback/u); assert.equal(hits, 0);
});
