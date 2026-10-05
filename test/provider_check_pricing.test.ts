import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import { composeKeep, type KeepConfig } from "../src/compose.js";
import { FileSpineStore } from "../src/spine/store.js";
import { FileSystemLock } from "../src/lock/lock.js";
import { parseProviderCheckPrice, fetchProviderCheckPrice, PROVIDER_CHECK_PRICE_URL } from "../src/reference/provider_check_pricing.js";
import { captureRuntimeContract, resolveRuntimeIntent } from "../src/cli/runtime_config.js";
import { priceHtml, priceResponse, priceTransport } from "./fixtures/provider_check_price_source.js";

function money(dir: string) {
  const store = new FileSpineStore(dir);
  return [...store.readBlocks().flatMap(block => [...block.events]), ...store.readStaged()]
    .filter(event => event.actor === "monetary-ledger").map(event => event.payload);
}
function clock(t: TestContext) {
  const saved = Date.now; let now = saved(); Date.now = () => now;
  t.after(() => { Date.now = saved; }); return (ms: number) => { now += ms; };
}
async function fixture(t: TestContext) {
  const dir = mkdtempSync(join(tmpdir(), "keep-fresh-price-")); t.after(() => rmSync(dir, { recursive: true, force: true }));
  let hits = 0; const replies: Array<() => void> = []; let defer = false;
  const server = createServer((request, response) => {
    let body = ""; request.on("data", chunk => { body += String(chunk); }); request.on("end", () => {
      hits++; assert.equal(JSON.parse(body).model, "deepseek-flash");
      assert.equal(JSON.parse(body).max_tokens, 64);
      assert.ok(money(dir).some(event => event["op"] === "reserve"), "real durable reservation before wire");
      const reply = () => { response.setHeader("content-type", "application/json"); response.end(JSON.stringify({ model: "deepseek-flash",
        choices: [{ message: { content: "ok" }, finish_reason: "stop" }], usage: { prompt_tokens: 2, completion_tokens: 1 } })); };
      replies.push(reply); if (!defer) reply();
    });
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const address = server.address(); assert.ok(address && typeof address !== "string");
  const transport = priceTransport(t, `http://127.0.0.1:${address.port}`);
  const config: KeepConfig = { dataDir: dir,
    ownerProvider: { mode: "openai-compatible", baseUrl: "https://api.deepseek.com", model: "deepseek-flash", apiKey: "SYNTHETIC_ONLY" },
    remoteProcessing: { purpose: "diagnostic", region: "test" },
    residency: { allowedPurposes: ["diagnostic"], allowedRegions: ["test"], egressAllowlist: ["api.deepseek.com", "api-docs.deepseek.com"] },
    providerCheckPricing: { maxAgeMs: 60000 } };
  return { dir, config, transport, hits: () => hits, replies, defer: () => { defer = true; } };
}
function close(a: number, b: number) { assert.ok(Math.abs(a - b) < 1e-15, `${a} != ${b}`); }
function reserved(dir: string) { return money(dir).filter(e => e["op"] === "reserve").map(e => e["reservation"] as { amount: number; id: string; rates: { input: number; output: number } }); }

test("price parser binds the exact model/endpoint and peak uncached tier, refuses unsupported schema", () => {
  assert.deepEqual(parseProviderCheckPrice(priceHtml()), { model: "deepseek-flash", inputPerM: 0.3, outputPerM: 1.2 });
  for (const body of ["", priceHtml().replace("deepseek-flash", "other-model"), priceHtml().replace("https://api.deepseek.com", "https://other.test"),
    priceHtml().replace("$0.3", "$NaN"), priceHtml().replace("$1.2", "$0"), priceHtml().replace("CACHE MISS", "OTHER TIER"),
    priceHtml().replace("Concurrency Limit", "Added request fee"), priceHtml() + priceHtml()]) assert.throws(() => parseProviderCheckPrice(body), /price-unverifiable/u);
});

test("metadata fetch preserves source/hash and honors Date plus Age rather than retrieval date", async () => {
  const start = Date.now(); let captured: RequestInit | undefined;
  const quote = (await fetchProviderCheckPrice(async (_url, init) => { captured = init; return priceResponse(priceHtml(), { age: "120" }); }))[0]!;
  assert.equal(quote.source, PROVIDER_CHECK_PRICE_URL); assert.match(quote.sourceDigest, /^[0-9a-f]{64}$/u);
  assert.ok(quote.verifiedAtMs <= start - 120000); assert.equal(captured?.redirect, "error"); assert.equal(captured?.credentials, "omit");
  assert.equal(captured?.body, undefined); assert.equal(new Headers(captured?.headers).has("authorization"), false);
});

test("metadata rejects malformed dates, age, future clocks, redirects, HTTP errors and oversized bodies", async () => {
  for (const make of [() => priceResponse(priceHtml(), { date: "unknown" }), () => priceResponse(priceHtml(), { age: "-1" }),
    () => priceResponse(priceHtml(), { age: "1e6" }), () => priceResponse(priceHtml(), { date: new Date(Date.now() + 3600000).toUTCString() }),
    () => priceResponse(priceHtml(), {}, 503), () => priceResponse("x".repeat(524289)),
    () => { const r = priceResponse(); Object.defineProperty(r, "redirected", { value: true }); return r; },
    () => { const r = new Response(priceHtml(), { headers: { "content-type": "text/html", date: new Date().toUTCString() } }); return r; }]) {
    await assert.rejects(fetchProviderCheckPrice(async () => make()), /price-unverifiable/u);
  }
  await assert.rejects(fetchProviderCheckPrice(async () => { throw new Error("synthetic timeout"); }), /timeout/u);
});

test("provider-check reuses fresh evidence and updates actual reserved rates after expiry", async t => {
  const advance = clock(t), f = await fixture(t), app = composeKeep(f.config);
  await app.providerCheck("probe"); await app.providerCheck("probe"); assert.equal(f.hits(), 2); assert.equal(f.transport.metadataHits, 1);
  advance(61000); f.transport.metadata = () => priceResponse(priceHtml(0.6, 2.4));
  await app.providerCheck("probe"); assert.equal(f.transport.metadataHits, 2); assert.equal(f.hits(), 3);
  const held = reserved(f.dir); close(held[0]!.amount, (2 * 0.3 + 64 * 1.2) / 1000000);
  close(held[2]!.amount, (2 * 0.6 + 64 * 2.4) / 1000000);
  const settled = money(f.dir).filter(e => e["op"] === "settle"); close(settled[2]!["amount"] as number, (2 * 0.6 + 2.4) / 1000000);
});

test("stale cached source and malformed source refuse before provider wire or monetary reserve", async t => {
  const f = await fixture(t);
  for (const metadata of [() => priceResponse(priceHtml(), { age: "61" }), () => priceResponse(priceHtml(), { date: new Date(Date.now() - 120000).toUTCString() }),
    () => priceResponse("schema changed"), () => priceResponse(priceHtml(), {}, 503), async () => { throw new Error("offline"); }]) {
    f.transport.metadata = metadata; await assert.rejects(composeKeep(f.config).providerCheck("probe"), /price-unverifiable/u);
  }
  assert.equal(f.hits(), 0); assert.equal(reserved(f.dir).length, 0); assert.equal(f.transport.metadataHits, 5);
});

test("failed refresh keeps historical value but never authorizes another paid diagnostic", async t => {
  const advance = clock(t), f = await fixture(t), app = composeKeep(f.config); await app.providerCheck("probe");
  advance(61000); f.transport.metadata = async () => { throw new Error("offline"); };
  await assert.rejects(app.providerCheck("probe"), /price-unverifiable/u); assert.equal(f.hits(), 1); assert.equal(reserved(f.dir).length, 1);
  f.transport.metadata = () => priceResponse(); await app.providerCheck("probe"); assert.equal(f.hits(), 2);
});

test("price expiry while awaiting durable reservation refuses entry and preserves unresolved exposure", async t => {
  const advance = clock(t), f = await fixture(t), lock = new FileSystemLock(join(f.dir, ".locks"));
  const app = composeKeep({ ...f.config, lock: { withLock: (key, fn) => lock.withLock(key, async () => {
    const result = await fn(); if (reserved(f.dir).length) advance(61000); return result;
  }) } });
  await assert.rejects(app.providerCheck("probe"), /expired or changed/u); assert.equal(f.hits(), 0); assert.equal(reserved(f.dir).length, 1);
  assert.equal(money(f.dir).filter(e => e["op"] === "void" || e["op"] === "settle").length, 0);
});

test("concurrent paid calls settle with their own captured rates even after a newer source refresh", async t => {
  const advance = clock(t), f = await fixture(t), app = composeKeep(f.config); f.defer();
  const first = app.providerCheck("probe");
  while (f.hits() === 0) await new Promise<void>(resolve => setImmediate(resolve));
  advance(61000); f.transport.metadata = () => priceResponse(priceHtml(0.6, 2.4));
  const second = app.providerCheck("probe");
  while (f.hits() < 2) await new Promise<void>(resolve => setImmediate(resolve));
  f.replies[1]!(); await second; f.replies[0]!(); await first;
  const held = reserved(f.dir); close(held[0]!.rates.input, 0.3 / 1000000); close(held[1]!.rates.input, 0.6 / 1000000);
  const settled = money(f.dir).filter(e => e["op"] === "settle");
  const amount = (id: string) => settled.find(e => e["reservationId"] === id)!["amount"] as number;
  close(amount(held[0]!.id), (2 * 0.3 + 1.2) / 1000000); close(amount(held[1]!.id), (2 * 0.6 + 2.4) / 1000000);
});

test("missing policy, unsupported routes, models, dialects and external routing cannot borrow seed prices", async t => {
  const f = await fixture(t), { providerCheckPricing: _policy, ...withoutPolicy } = f.config;
  for (const config of [withoutPolicy, { ...f.config, ownerProvider: { ...f.config.ownerProvider!, model: "deepseek-v4-flash" } },
    { ...f.config, ownerProvider: { ...f.config.ownerProvider!, baseUrl: "https://aggregator.example.test" } },
    { ...f.config, ownerProvider: { ...f.config.ownerProvider!, mode: "anthropic-compatible" as const } },
    { ...f.config, externalRouting: { providers: ["DeepSeek"], allowFallbacks: false as const, dataCollection: "deny" as const, zeroDataRetention: true as const } }]) {
    await assert.rejects(composeKeep(config).providerCheck("probe"), /price-unknown/u);
  }
  assert.equal(f.transport.metadataHits, 0); assert.equal(f.hits(), 0); assert.equal(reserved(f.dir).length, 0);
});

test("air-gap or missing metadata egress grant refuses even the metadata request", async t => {
  const f = await fixture(t);
  for (const policy of [{ ...f.config.residency!, airGapped: true }, { ...f.config.residency!, egressAllowlist: ["api.deepseek.com"] }]) {
    await assert.rejects(composeKeep({ ...f.config, residency: policy }).providerCheck("probe"), /egress denied/u);
  }
  assert.equal(f.transport.metadataHits, 0); assert.equal(f.hits(), 0);
});

test("explicit CLI freshness capture is immutable, owner grants one metadata host and organization does not", () => {
  const env = { KEEP_PROVIDER: "openai-compatible", KEEP_PROVIDER_AUTHORITY: "owner", KEEP_PROVIDER_BASE_URL: "https://api.deepseek.com",
    KEEP_PROVIDER_MODEL: "deepseek-flash", KEEP_PROVIDER_API_KEY: "SYNTHETIC_ONLY", KEEP_REMOTE_PROCESSING_PURPOSE: "diagnostic",
    KEEP_REMOTE_PROCESSING_REGION: "test", KEEP_PROVIDER_CHECK_PRICE_MAX_AGE_MS: "60000" };
  const intent = resolveRuntimeIntent(env, { repositoryRequired: false }); assert.equal(intent.providerCheckPricing?.maxAgeMs, 60000);
  assert.ok(Object.isFrozen(intent.providerCheckPricing)); assert.deepEqual(intent.residency?.egressAllowlist, ["api.deepseek.com", "api-docs.deepseek.com"]);
  const contract = captureRuntimeContract(env, { cwd: process.cwd(), repositoryRequired: false });
  assert.deepEqual(contract.providerCheckPricing, intent.providerCheckPricing);
  const org = resolveRuntimeIntent({ ...env, KEEP_PROVIDER_AUTHORITY: "organization" }, { repositoryRequired: false });
  assert.deepEqual(org.residency?.egressAllowlist, ["api.deepseek.com"]);
  for (const raw of ["", "0", "-1", "1.5", " 1000", "Infinity", "9007199254740992"]) {
    assert.throws(() => resolveRuntimeIntent({ ...env, KEEP_PROVIDER_CHECK_PRICE_MAX_AGE_MS: raw }, { repositoryRequired: false }), /MAX_AGE/u);
  }
  assert.throws(() => resolveRuntimeIntent({ KEEP_PROVIDER: "local", KEEP_PROVIDER_CHECK_PRICE_MAX_AGE_MS: "60000" }), /remote-only/u);
});
