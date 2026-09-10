import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, renameSync, mkdirSync, rmdirSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { NODE_IO } from "../src/spine/durable_fs.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { ModelGateway, type ModelProvider, type GenerateResult } from "../src/gateway/gateway.js";
import { HttpProvider } from "../src/gateway/http_provider.js";
import { buildDefaultBrokeredEgress } from "../src/gateway/brokered_egress.js";
import { openAiDialect, anthropicDialect } from "../src/gateway/wire_dialect.js";
import { CostModel } from "../src/observability/cost_model.js";
import { BudgetLedger, type AuthorizationEnvelope } from "../src/scheduler/authorization_envelope.js";
import { MeteredGateway, TokenVelocityBreaker } from "../src/scheduler/metered_gateway.js";
import { MeteredProvider } from "../src/scheduler/metered_provider.js";

const now = Date.UTC(2026, 0, 1, 12);
const result: GenerateResult = { text: "useful", model: "synthetic", tokensIn: 1, tokensOut: 1 };
const envelope = (cap: number): AuthorizationEnvelope => ({ id: "synthetic-envelope", projectId: "synthetic-project",
  allowedClasses: ["auto-research"], allowedTiers: [], dailyCapUsd: cap, perRunCapUsd: cap,
  perCallTokenCeiling: 512, expiresAt: Number.MAX_SAFE_INTEGER, grantedReason: "synthetic audit fixture; no paid work" });
async function fixture(provider: ModelProvider, cap: number, root = mkdtempSync(join(tmpdir(), "keep-money-audit-"))) {
  const spine = new Spine(new FileSpineStore(root, { fsync: true }), new InProcessLock(), new SchemaRegistry());
  const cost = new CostModel(); cost.registerPricing({ model: provider.name, inputPerMillion: 1_000_000, outputPerMillion: 1_000_000 });
  const ledger = new BudgetLedger(spine, cost, () => now), env = envelope(cap);
  await ledger.grant(env); await ledger.beginRun("run", env.id);
  const gateway = new MeteredGateway(new ModelGateway(provider), ledger,
    new TokenVelocityBreaker(spine, { maxUsdPerMinute: 1_000_000, maxRepeatedIdentical: 100 }, () => now), spine);
  return { root, spine, cost, ledger, env, provider: new MeteredProvider(provider, gateway, { runId: "run", cls: "auto-research", tier: "small" }) };
}
function scripted(generate: ModelProvider["generate"]): ModelProvider {
  return { name: "synthetic", isLocal: true, generate, embed: async () => [] };
}

for (const dialect of [openAiDialect, anthropicDialect]) for (const complete of [false, true]) {
  test(`supplied SSE accounting port ${dialect.name}: ${complete ? "complete usage settles" : "missing usage stays reserved across reconstruction"}`, async () => {
    let entries = 0;
    const frame = (event: unknown) => `data: ${JSON.stringify(event)}\n\n`;
    const server = createServer((request, response) => {
      request.resume(); request.on("end", () => {
        entries++;
        response.setHeader("content-type", "text/event-stream");
        if (dialect === openAiDialect) {
          response.end(frame({ choices: [{ delta: { content: "useful" }, finish_reason: "stop" }] })
            + (complete ? frame({ choices: [], usage: { prompt_tokens: 1, completion_tokens: 1 } }) : "") + "data: [DONE]\n\n");
        } else {
          response.end((complete ? frame({ type: "message_start", message: { usage: { input_tokens: 1 } } }) : "")
            + frame({ type: "content_block_delta", delta: { text: "useful" } })
            + (complete ? frame({ type: "message_delta", usage: { output_tokens: 1 } }) : "") + frame({ type: "message_stop" }));
        }
      });
    });
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    const address = server.address(); assert.ok(address && typeof address !== "string");
    const raw = new HttpProvider({ baseUrl: `http://127.0.0.1:${address.port}`, model: "synthetic", apiKey: "SYNTHETIC_ONLY", dialect });
    // Explicit supplied library port, not the default composed metered streaming
    // route (which falls back to nonstream generate). Exercise returned metadata.
    const f = await fixture(scripted(req => raw.generateStream(req)), complete ? 4 : 2);
    try {
      if (complete) {
        assert.equal((await f.provider.generate({ prompt: "xxxx", maxTokens: 1 })).text, "useful");
        assert.equal(f.ledger.runSpend("run")!.spentUsd, 2);
        assert.equal(f.ledger.runSpend("run")!.reservedUsd, 0);
        assert.equal((await f.provider.generate({ prompt: "xxxx", maxTokens: 1 })).text, "useful");
        assert.equal(entries, 2);
      } else {
        await assert.rejects(f.provider.generate({ prompt: "xxxx", maxTokens: 1 }), /usage incomplete/);
        assert.equal(f.ledger.runSpend("run")!.spentUsd, 0);
        assert.equal(f.ledger.runSpend("run")!.reservedUsd, 2);
        await f.spine.seal();
        const restored = await fixture(scripted(req => raw.generateStream(req)), 2, f.root);
        await assert.rejects(restored.provider.generate({ prompt: "xxxx", maxTokens: 1 }));
        assert.equal(restored.ledger.runSpend("run")!.reservedUsd, 2);
        assert.equal(entries, 1, "unknown usage must not cause an automatic replay or reuse its reserved capacity");
      }
    } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
  });
}
async function receiver(usage: (index: number) => { prompt_tokens: number; completion_tokens: number }) {
  const bodies: Record<string, unknown>[] = [];
  const server = createServer((request, response) => {
    let body = ""; request.on("data", chunk => { body += chunk; if (body.length > 65536) request.destroy(); });
    request.on("end", () => {
      bodies.push(JSON.parse(body) as Record<string, unknown>);
      response.end(JSON.stringify({ model: "synthetic", choices: [{ message: { content: "useful" } }], usage: usage(bodies.length) }));
    });
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address(); assert.ok(address && typeof address !== "string");
  return { bodies, provider: new HttpProvider({ baseUrl: `http://127.0.0.1:${address.port}`, model: "synthetic",
    apiKey: "SYNTHETIC_TEST_ONLY", dialect: openAiDialect, requestTimeoutMs: 1000, retry: { maxAttempts: 1 } }),
    async close() { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); } };
}

test("KEEP-12B-001 omitted output bound cannot dispatch beyond the admitted ceiling", async () => {
  const r = await receiver(() => ({ prompt_tokens: 1, completion_tokens: 1 }));
  try {
    const f = await fixture(r.provider, 10_000);
    assert.equal((await f.provider.generate({ prompt: "xxxx" })).text, "useful");
    assert.equal(r.bodies.length, 1);
    assert.ok(typeof r.bodies[0]!["max_tokens"] === "number" && r.bodies[0]!["max_tokens"] <= 512,
      `receiver got output limit ${String(r.bodies[0]!["max_tokens"])} beyond ceiling512`);
  } finally { await r.close(); }
});

for (const cap of [3, 4]) test(`KEEP-12B-002 outstanding monetary capacity is reserved (cap${cap})`, { timeout: 5000 }, async () => {
  let release!: () => void, firstEntered!: () => void, secondEntered!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  const firstEntry = new Promise<void>(resolve => { firstEntered = resolve; });
  const secondEntry = new Promise<void>(resolve => { secondEntered = resolve; });
  let entries = 0;
  const f = await fixture(scripted(async () => { if (++entries === 1) firstEntered(); else secondEntered(); await held; return result; }), cap);
  const first = f.provider.generate({ prompt: "xxxx", maxTokens: 1 });
  await firstEntry;
  const second = f.provider.generate({ prompt: "yyyy", maxTokens: 1 });
  const secondSettled = second.then(() => "success", () => "refused");
  await Promise.race([secondEntry, secondSettled]);
  const pendingEntries = entries; release();
  const results = await Promise.allSettled([first, second]);
  assert.equal(pendingEntries, cap === 3 ? 1 : 2, "dispatched entries must include the outstanding reservation in admission");
  assert.equal(results.filter(value => value.status === "fulfilled").length, cap === 3 ? 1 : 2);
  assert.equal(f.ledger.dailySpend(f.env.id), cap === 3 ? 2 : 4);
});

test("KEEP-12B-003 negative HTTP usage cannot refund earlier consumption", async () => {
  const r = await receiver(index => ({ prompt_tokens: 1, completion_tokens: index === 2 ? -3 : 1 }));
  try {
    const f = await fixture(r.provider, 4);
    assert.equal((await f.provider.generate({ prompt: "xxxx", maxTokens: 1 })).text, "useful");
    assert.equal(f.ledger.dailySpend(f.env.id), 2);
    await f.provider.generate({ prompt: "yyyy", maxTokens: 1 }).catch(() => undefined);
    assert.equal(r.bodies.length, 2, "the malformed response was received after actual local HTTP dispatch");
    assert.ok(f.ledger.dailySpend(f.env.id) >= 2, "malformed usage must not subtract previous consumption");
    assert.ok(f.ledger.runSpend("run")!.spentUsd >= 2);
  } finally { await r.close(); }
});

test("KEEP-12B-004 same-authorization spend survives fresh-process reconstruction", async () => {
  const f = await fixture(scripted(async () => result), 2);
  await f.provider.generate({ prompt: "xxxx", maxTokens: 1 });
  await assert.rejects(f.provider.generate({ prompt: "yyyy", maxTokens: 1 }));
  await f.spine.seal();
  const output = execFileSync(process.execPath, ["--input-type=module", "-e", `
    const base = process.argv[1], input = JSON.parse(process.argv[2]);
    const load = path => import(new URL(path + '.js', base));
    const { Spine } = await load('spine/spine'), { FileSpineStore } = await load('spine/store');
    const { InProcessLock } = await load('lock/lock'), { SchemaRegistry } = await load('spine/upcaster');
    const { CostModel } = await load('observability/cost_model'), { ModelGateway } = await load('gateway/gateway');
    const { BudgetLedger } = await load('scheduler/authorization_envelope');
    const { MeteredGateway, TokenVelocityBreaker } = await load('scheduler/metered_gateway');
    const { MeteredProvider } = await load('scheduler/metered_provider');
    const spine = new Spine(new FileSpineStore(input.root, { fsync: true }), new InProcessLock(), new SchemaRegistry());
    const cost = new CostModel(); cost.registerPricing({ model: 'synthetic', inputPerMillion: 1000000, outputPerMillion: 1000000 });
    const ledger = new BudgetLedger(spine, cost, () => input.now); await ledger.grant(input.env); await ledger.beginRun('run', input.env.id);
    let entries = 0; const inner = { name: 'synthetic', isLocal: true, async generate() { entries++; return input.result; }, async embed() { return []; } };
    const gateway = new MeteredGateway(new ModelGateway(inner), ledger, new TokenVelocityBreaker(spine), spine);
    const provider = new MeteredProvider(inner, gateway, { runId: 'run', cls: 'auto-research', tier: 'small' });
    let error; try { await provider.generate({ prompt: 'zzzz', maxTokens: 1 }); } catch (e) { error = String(e); }
    process.stdout.write(JSON.stringify({ entries, error, pid: process.pid, daily: ledger.dailySpend(input.env.id) }));
  `, new URL("../src/", import.meta.url).href, JSON.stringify({ root: f.root, env: f.env, now, result })], { encoding: "utf8", timeout: 10_000, maxBuffer: 128 * 1024 });
  const child = JSON.parse(output) as { entries: number; error?: string; pid: number; daily: number };
  assert.notEqual(child.pid, process.pid); assert.equal(child.entries, 0, "unchanged authorization cannot buy a new allowance by restarting");
  assert.ok(child.error); assert.equal(child.daily, 2);
});

const usage = { freshInputTokens: 1, cachedInputTokens: 0, outputTokens: 1 };
const reserve = (ledger: BudgetLedger, runId = "run") => ledger.reserve(runId, "auto-research", "small", "synthetic", usage);

test("monetary settlement pins prices, is idempotent by usage, and never erases consumption on regrant", async () => {
  const f = await fixture(scripted(async () => result), 10);
  const held = (await reserve(f.ledger)).reservation!;
  f.cost.registerPricing({ model: "synthetic", inputPerMillion: 99_000_000, outputPerMillion: 99_000_000 });
  assert.equal(await f.ledger.settle(held.id, usage), 2);
  assert.equal(await f.ledger.settle(held.id, usage), 2);
  await assert.rejects(f.ledger.settle(held.id, { ...usage, freshInputTokens: 0, outputTokens: 2 }), /already resolved/);
  await f.ledger.grant({ ...f.env, dailyCapUsd: 20 }); await f.ledger.beginRun("run", f.env.id);
  assert.equal(f.ledger.runSpend("run")!.spentUsd, 2); assert.equal(f.ledger.runSpend("run")!.calls, 1);
});

test("unknown prices refuse admission, explicit zero prices work, invalid rates never enter the registry", async () => {
  const f = await fixture(scripted(async () => result), 4);
  const cost = new CostModel(), ledger = new BudgetLedger(f.spine, cost, () => now);
  assert.equal((await reserve(ledger)).breach.kind, "price-unknown");
  for (const n of [-1, NaN, Infinity]) assert.throws(() => cost.registerPricing({ model: "synthetic", inputPerMillion: n, outputPerMillion: 0 }), /invalid/);
  assert.equal(cost.hasPricing("synthetic"), false);
  const pricing = { model: "synthetic", inputPerMillion: 0, outputPerMillion: 0 };
  cost.registerPricing(pricing); pricing.outputPerMillion = -100;
  const held = (await reserve(ledger)).reservation!;
  assert.equal(held.amount, 0); assert.equal(await ledger.settle(held.id, usage), 0);
});

test("a cancellation before provider entry voids only its own reservation", async () => {
  let entries = 0;
  const f = await fixture(scripted(async () => { entries++; return result; }), 4);
  const earlier = (await reserve(f.ledger)).reservation!;
  const controller = new AbortController(), realReserve = f.ledger.reserve.bind(f.ledger);
  // Instrument precisely between the completed reservation and the dispatcher's entry check.
  f.ledger.reserve = async (...args) => { const admission = await realReserve(...args); controller.abort(); return admission; };
  await assert.rejects(f.provider.generate({ prompt: "xxxx", maxTokens: 1, signal: controller.signal }));
  assert.equal(entries, 0); assert.equal(f.ledger.runSpend("run")!.reservedUsd, 2);
  assert.equal(await f.ledger.settle(earlier.id, usage), 2);
});

test("invalid usage cannot clear a reservation or subtract consumption", async () => {
  const f = await fixture(scripted(async () => result), 4);
  await f.provider.generate({ prompt: "xxxx", maxTokens: 1 });
  const held = (await reserve(f.ledger)).reservation!;
  for (const n of [-1, NaN, Infinity, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
    await assert.rejects(f.ledger.settle(held.id, { ...usage, outputTokens: n }), /invalid/);
    assert.equal(f.ledger.runSpend("run")!.reservedUsd, 2);
    assert.equal(f.ledger.runSpend("run")!.spentUsd, 2);
  }
  await f.spine.seal();
  const restored = new BudgetLedger(f.spine, f.cost, () => now); await restored.refresh();
  assert.equal(restored.dailySpend(f.env.id), 4);
  assert.equal((await reserve(restored)).breach.wouldBreach, true);
});

test("durable revoked authority is not revived by bootstrap; configuration changes require explicit grant", async () => {
  const f = await fixture(scripted(async () => result), 4);
  await f.provider.generate({ prompt: "xxxx", maxTokens: 1 });
  const changed = { ...f.env, perRunCapUsd: 8 };
  const boot = new BudgetLedger(f.spine, f.cost, () => now, { bootstrap: { envelope: changed, runId: "run" } });
  await assert.rejects(boot.refresh(), /explicit grant revision/);
  await boot.grant(changed); await boot.refresh();
  assert.equal(boot.runSpend("run")!.spentUsd, 2);
  await f.ledger.revoke(f.env.id, "synthetic owner revoke");
  const revoked = new BudgetLedger(f.spine, f.cost, () => now, { bootstrap: { envelope: f.env, runId: "run" } });
  assert.equal((await reserve(revoked)).breach.kind, "expired");
  assert.equal(revoked.runSpend("run")!.spentUsd, 2);
});

test("reservation settles on its admission day while its run survives midnight", async () => {
  const f = await fixture(scripted(async () => result), 4);
  let clock = now;
  const ledger = new BudgetLedger(f.spine, f.cost, () => clock);
  const held = (await reserve(ledger)).reservation!;
  clock += 24 * 60 * 60 * 1000;
  await ledger.settle(held.id, usage);
  assert.equal(ledger.dailySpend(f.env.id, now), 2);
  assert.equal(ledger.dailySpend(f.env.id), 0);
  assert.equal(ledger.runSpend("run")!.spentUsd, 2);
});

test("legacy grant evidence cannot create a fresh paid allowance; an explicit distinct allowance works", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-money-legacy-"));
  const spine = new Spine(new FileSpineStore(root, { fsync: true }), new InProcessLock(), new SchemaRegistry());
  spine.stage({ type: "identity.action", actor: "scheduler", payload: { event: "envelope_granted", envelopeId: envelope(4).id } });
  const cost = new CostModel(); cost.registerPricing({ model: "synthetic", inputPerMillion: 1_000_000, outputPerMillion: 1_000_000 });
  const ledger = new BudgetLedger(spine, cost, () => now, { bootstrap: { envelope: envelope(4), runId: "run" } });
  assert.equal((await reserve(ledger)).breach.kind, "legacy-accounting");
  await ledger.grant(envelope(4));
  assert.equal((await reserve(ledger)).breach.kind, "legacy-accounting");
  await ledger.grant({ ...envelope(4), id: "explicit-new-allowance" });
  await ledger.beginRun("new-run", "explicit-new-allowance");
  assert.equal((await reserve(ledger, "new-run")).breach.wouldBreach, false);
});

test("a received usage overrun is recorded and blocks further paid admissions", async () => {
  const f = await fixture(scripted(async () => ({ ...result, tokensOut: 3 })), 20);
  await f.provider.generate({ prompt: "xxxx", maxTokens: 1 });
  assert.equal(f.ledger.runSpend("run")!.spentUsd, 4);
  assert.equal((await reserve(f.ledger)).breach.kind, "projection-exceeded");
  await f.spine.seal();
  const restored = new BudgetLedger(f.spine, f.cost, () => now);
  assert.equal((await reserve(restored)).breach.kind, "projection-exceeded");
});

test("legacy revocation blocks automatic reconstruction even for a zero-price route", async () => {
  const f = await fixture(scripted(async () => result), 4);
  const env = { ...f.env, id: "legacy-revoked" };
  f.spine.stage({ type: "identity.action", actor: "scheduler", payload: { event: "envelope_revoked", envelopeId: env.id } });
  const free = new CostModel(); free.registerPricing({ model: "synthetic", inputPerMillion: 0, outputPerMillion: 0 });
  const ledger = new BudgetLedger(f.spine, free, () => now, { bootstrap: { envelope: env, runId: "legacy-run" } });
  await assert.rejects(reserve(ledger, "legacy-run"), /was revoked/);
  await ledger.grant(env);
  assert.equal((await reserve(ledger, "legacy-run")).breach.wouldBreach, false, "explicit owner regrant can authorize free work without inventing known paid history");
});

test("storage read failure refuses dispatch and later reload preserves the previous ledger", async () => {
  let entries = 0;
  const f = await fixture(scripted(async () => { entries++; return result; }), 4);
  const path = join(f.root, "staging.jsonl"), preserved = join(f.root, "staging.preserved");
  renameSync(path, preserved); mkdirSync(path);
  try {
    await assert.rejects(f.provider.generate({ prompt: "xxxx", maxTokens: 1 }));
    assert.equal(entries, 0);
  } finally { rmdirSync(path); renameSync(preserved, path); }
  assert.equal((await f.provider.generate({ prompt: "xxxx", maxTokens: 1 })).text, "useful");
  assert.equal(entries, 1); assert.equal(f.ledger.dailySpend(f.env.id), 2);
});

test("closed monetary replay refuses unknown fields rather than silently clearing state", async () => {
  const f = await fixture(scripted(async () => result), 4);
  f.spine.stage({ type: "identity.action", actor: "monetary-ledger", payload: {
    schema: "keep.monetary/v1", op: "run", runId: "bad", envelopeId: f.env.id, dayKey: "2026-01-01", reset: true,
  } });
  await assert.rejects(reserve(f.ledger), /record shape/);
  assert.throws(() => f.ledger.runSpend("run"), /durable reload/);
});

test("replay counts an identical sealed/staged event once and rejects a conflicting duplicate", async () => {
  const f = await fixture(scripted(async () => result), 4);
  await f.provider.generate({ prompt: "xxxx", maxTokens: 1 });
  const settled = f.spine.currentEvents().find(e => e.actor === "monetary-ledger" && e.payload["op"] === "settle")!;
  await f.spine.seal();
  const store = new FileSpineStore(f.root, { fsync: true });
  store.appendStaged(settled);
  await f.ledger.refresh(); assert.equal(f.ledger.dailySpend(f.env.id), 2); assert.equal(f.ledger.runSpend("run")!.calls, 1);
  const conflicting = { ...settled, payload: { ...settled.payload, amount: 999 } };
  assert.throws(() => store.appendStaged(conflicting), /different content/, "the ordinary writer already refuses this corruption");
  // Deliberately corrupt only this fixture to exercise the additional reader defense.
  appendFileSync(join(f.root, "staging.jsonl"), JSON.stringify(conflicting) + "\n");
  await assert.rejects(f.ledger.refresh(), /conflicting duplicate/);
});

test("an injected error after actual reservation bytes are written cannot buy a retry allowance", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-money-append-error-"));
  let inject = false, affected = false;
  const io = { ...NODE_IO, writeSync(fd: number, bytes: Uint8Array, offset: number, length: number) {
    const n = NODE_IO.writeSync(fd, bytes, offset, length);
    if (inject && Buffer.from(bytes.subarray(offset, offset + length)).toString().includes('"op":"reserve"')) {
      inject = false; affected = true;
      throw Object.assign(new Error("synthetic acknowledgment failure after real write"), { code: "EIO" });
    }
    return n;
  } };
  const spine = new Spine(new FileSpineStore(root, { fsync: true, io }), new InProcessLock(), new SchemaRegistry());
  const cost = new CostModel(); cost.registerPricing({ model: "synthetic", inputPerMillion: 1_000_000, outputPerMillion: 1_000_000 });
  const ledger = new BudgetLedger(spine, cost, () => now);
  await ledger.grant(envelope(2)); await ledger.beginRun("run", envelope(2).id);
  inject = true;
  await assert.rejects(reserve(ledger), /synthetic acknowledgment/); assert.equal(affected, true);
  assert.throws(() => ledger.runSpend("run"), /durable reload/);
  const retry = await reserve(ledger);
  assert.equal(retry.breach.kind, "per-run-cap"); assert.equal(ledger.runSpend("run")!.reservedUsd, 2);
  assert.equal(spine.currentEvents().filter(e => e.actor === "monetary-ledger" && e.payload["op"] === "reserve").length, 1);
});

test("concurrent fresh processes share the actual filesystem reservation lock", async () => {
  const f = await fixture(scripted(async () => result), 3);
  const source = `
    const base=process.argv[1], root=process.argv[2], now=Number(process.argv[3]);
    const load=p=>import(new URL(p+'.js',base));
    const {Spine}=await load('spine/spine'), {FileSpineStore}=await load('spine/store');
    const {FileSystemLock}=await load('lock/lock'), {SchemaRegistry}=await load('spine/upcaster');
    const {CostModel}=await load('observability/cost_model'), {BudgetLedger}=await load('scheduler/authorization_envelope');
    const spine=new Spine(new FileSpineStore(root,{fsync:true}),new FileSystemLock(root+'/locks'),new SchemaRegistry());
    const cost=new CostModel();cost.registerPricing({model:'synthetic',inputPerMillion:1000000,outputPerMillion:1000000});
    const ledger=new BudgetLedger(spine,cost,()=>now);
    const admission=await ledger.reserve('run','auto-research','small','synthetic',{freshInputTokens:1,cachedInputTokens:0,outputTokens:1});
    process.stdout.write(JSON.stringify({pid:process.pid,allowed:!admission.breach.wouldBreach}));
  `;
  const outputs = await Promise.all([0, 1].map(() => promisify(execFile)(process.execPath,
    ["--input-type=module", "-e", source, new URL("../src/", import.meta.url).href, f.root, String(now)],
    { timeout: 10_000, maxBuffer: 128 * 1024 })));
  const rows = outputs.map(o => JSON.parse(o.stdout) as { pid: number; allowed: boolean });
  assert.notEqual(rows[0]!.pid, rows[1]!.pid);
  assert.equal(rows.filter(r => r.allowed).length, 1);
  await f.ledger.refresh(); assert.equal(f.ledger.runSpend("run")!.reservedUsd, 2);
});

test("metered HTTP allows one attempt; ordinary HTTP retains its configured retry allowance", async () => {
  let entries = 0;
  const server = createServer((_req, res) => { entries++; res.writeHead(503); res.end("synthetic transient failure"); });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address(); assert.ok(address && typeof address !== "string");
  const raw = new HttpProvider({ baseUrl: `http://127.0.0.1:${address.port}`, model: "synthetic", apiKey: "SYNTHETIC_TEST_ONLY",
    dialect: openAiDialect, retry: { maxAttempts: 2, baseBackoffMs: 1 } });
  try {
    const brokered = buildDefaultBrokeredEgress(raw, { write() {} }, { transportClass: "remote", ownerAuthority: true });
    const f = await fixture(brokered, 4);
    await assert.rejects(f.provider.generate({ prompt: "xxxx", maxTokens: 1 }));
    assert.equal(entries, 1); assert.equal(f.ledger.runSpend("run")!.reservedUsd, 2);
    await assert.rejects(raw.generate({ prompt: "ordinary", maxTokens: 1 }));
    assert.equal(entries, 3);
  } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
});
