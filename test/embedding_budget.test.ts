import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { spawnSync } from "node:child_process";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { FileSystemLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { RecoveryBudget, type RecoveryLimits } from "../src/solve/recovery_budget.js";
import { HttpProvider } from "../src/gateway/http_provider.js";
import { openAiDialect, openAiDialectWithRouting } from "../src/gateway/wire_dialect.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { buildDefaultBrokeredEgress } from "../src/gateway/brokered_egress.js";
import { GovernedRemoteProvider, type EmbeddingProcessingDeclaration } from "../src/gateway/governed_remote_provider.js";
import { TracingModelProvider } from "../src/gateway/tracing_provider.js";
import { TraceRecorder } from "../src/observability/tracing.js";
import { SpineDurableWitness } from "../src/witness/pre_effect_witness.js";
import { ResidencyEnforcer } from "../src/governance/residency.js";
import { interceptEgress } from "../src/privacy/egress_interceptor.js";
import { DataClassifier } from "../src/ingest/data_classifier.js";
import { RedactionGateway } from "../src/privacy/redaction_gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";

function fixture(t: TestContext, embedding = { requests: 8, inputBytes: 8192, windows: 16 }) {
  const root = mkdtempSync(join(tmpdir(), "keep-embedding-budget-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const limits: RecoveryLimits = { maxAttempts: 4, maxElapsedMs: 10_000, embedding };
  const makeSpine = () => new Spine(new FileSpineStore(join(root, "spine")), new FileSystemLock(join(root, "locks")), new SchemaRegistry());
  const make = (id = "embedding-job", chosen = limits) => new RecoveryBudget(makeSpine(), id, chosen);
  return { root, limits, make, makeSpine };
}
async function serve(t: TestContext, handler: (req: IncomingMessage, res: ServerResponse, body: string) => Promise<void> | void) {
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", chunk => { body += chunk; });
    req.on("end", () => { void Promise.resolve().then(() => handler(req, res, body)).catch(error => { res.destroy(error as Error); }); });
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return `http://127.0.0.1:${address.port}`;
}
function provider(baseUrl: string, maxAttempts = 2, requestTimeoutMs = 2000) {
  return new HttpProvider({ baseUrl, model: "embedding-fixture", apiKey: "fixture-only", dialect: openAiDialect,
    retry: { maxAttempts, baseBackoffMs: 0 }, requestTimeoutMs });
}

test("embedding batches reserve exact worst-case JSON exposure before real HTTP; retries and restart never refund", async t => {
  const f = fixture(t), budget = f.make(), permit = await budget.reserve();
  const bodies: string[] = [], durable: unknown[] = [];
  const url = await serve(t, async (_req, res, body) => {
    bodies.push(body);
    durable.push((await f.make().snapshot()).embedding);
    if (bodies.length === 1) { res.writeHead(429, { "retry-after": "0" }); res.end(); return; }
    const { input } = JSON.parse(body) as { input: string[] };
    res.end(JSON.stringify({ data: input.map((text, index) => ({ index, embedding: [text.length, 1] })).reverse() }));
  });
  const texts = ["one", "二", "three"];
  const expectedBytes = [texts.slice(0, 2), texts.slice(2)].reduce((n, input) => n + Buffer.byteLength(JSON.stringify({ model: "embedding-fixture", input })), 0) * 2;
  const result = await provider(url).embedBounded(texts, { maxBatchWindows: 2, reserve: plan => budget.reserveEmbeddingWork(permit, plan) });
  assert.deepEqual(result.vectors, [[3, 1], [1, 1], [5, 1]]);
  assert.deepEqual(result.reserved, { requests: 4, inputBytes: expectedBytes, windows: 6 });
  assert.deepEqual(result.dispatched, { requests: 3, inputBytes: bodies.reduce((n, body) => n + Buffer.byteLength(body), 0), windows: 5 });
  for (const state of durable) {
    assert.deepEqual((state as { reserved: unknown }).reserved, result.reserved);
    assert.ok((state as { pendingWorkId: string }).pendingWorkId);
  }
  await budget.finish(permit);
  // Read the persisted reservation in a fresh process, not just a new JS instance.
  const script = `import { Spine } from ${JSON.stringify(new URL("../src/spine/spine.js", import.meta.url).href)};
    import { FileSpineStore } from ${JSON.stringify(new URL("../src/spine/store.js", import.meta.url).href)};
    import { FileSystemLock } from ${JSON.stringify(new URL("../src/lock/lock.js", import.meta.url).href)};
    import { SchemaRegistry } from ${JSON.stringify(new URL("../src/spine/upcaster.js", import.meta.url).href)};
    import { RecoveryBudget } from ${JSON.stringify(new URL("../src/solve/recovery_budget.js", import.meta.url).href)};
    const b = new RecoveryBudget(new Spine(new FileSpineStore(${JSON.stringify(join(f.root, "spine"))}), new FileSystemLock(${JSON.stringify(join(f.root, "locks"))}), new SchemaRegistry()), "embedding-job", ${JSON.stringify(f.limits)});
    console.log(JSON.stringify(await b.snapshot()));`;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8", timeout: 5000 });
  assert.equal(child.status, 0, child.stderr);
  assert.deepEqual(JSON.parse(child.stdout).embedding.reserved, result.reserved);
  assert.equal(JSON.parse(child.stdout).embedding.pendingWorkId, undefined);
  const resumed = f.make(), next = await resumed.reserve();
  await assert.rejects(resumed.reserveEmbeddingWork(next, { requests: 5, inputBytes: 1, windows: 1 }), /exhausted/);
  await resumed.finish(next);
  assert.equal(bodies.length, 3);
});

test("embedding aggregate rejection, malformed bounds and disabled historical budgets send no HTTP", async t => {
  const f = fixture(t, { requests: 1, inputBytes: 8192, windows: 16 }), budget = f.make(), permit = await budget.reserve();
  let requests = 0;
  const url = await serve(t, (_req, res) => { requests++; res.end("{}"); });
  const options = { reserve: (plan: Parameters<RecoveryBudget["reserveEmbeddingWork"]>[1]) => budget.reserveEmbeddingWork(permit, plan) };
  await assert.rejects(provider(url).embedBounded(["a"], options), /aggregate embedding budget exhausted/);
  await assert.rejects(provider(url, Infinity).embedBounded(["a"], options), /finite/);
  await assert.rejects(provider(url).embedBounded(["a"], { ...options, maxBatchBytes: 1 }), /serialized batch bound/);
  await assert.rejects(provider(url).embedBounded([{} as string], options), /nonempty strings/);
  assert.deepEqual((await budget.snapshot()).embedding?.reserved, { requests: 0, inputBytes: 0, windows: 0 });
  const old = f.make("historical", { maxAttempts: 2, maxElapsedMs: 10_000 }), oldPermit = await old.reserve();
  await assert.rejects(old.reserveEmbeddingWork(oldPermit, { requests: 1, inputBytes: 1, windows: 1 }), /disabled/);
  await old.finish(oldPermit);
  assert.equal((await f.make("historical", { maxAttempts: 2, maxElapsedMs: 10_000 }).snapshot()).embedding, undefined);
  await assert.rejects(f.make("historical", { maxAttempts: 2, maxElapsedMs: 10_000, embedding: f.limits.embedding! }).snapshot(), /embedding identity\/limits/);
  for (const [id, embedding] of Object.entries({ bytes: { requests: 8, inputBytes: 1, windows: 16 }, windows: { requests: 8, inputBytes: 8192, windows: 1 } })) {
    const limited = f.make(id, { ...f.limits, embedding }), p = await limited.reserve();
    await assert.rejects(provider(url).embedBounded(["a"], { reserve: plan => limited.reserveEmbeddingWork(p, plan) }), /aggregate embedding budget exhausted/);
    await limited.finish(p);
  }
  assert.equal(requests, 0);
  await budget.finish(permit);
});

test("embedding uncertain socket outcome is not retried or cleared by finish/restart; reconciliation retains usage", async t => {
  const f = fixture(t), budget = f.make(), permit = await budget.reserve();
  let requests = 0;
  const url = await serve(t, (req, _res) => { requests++; req.socket.destroy(); });
  await assert.rejects(provider(url).embedBounded(["private document"], { reserve: plan => budget.reserveEmbeddingWork(permit, plan) }));
  await budget.finish(permit);
  const restarted = f.make(), state = await restarted.snapshot();
  assert.equal(requests, 1);
  assert.equal(state.status, "reconciliation");
  assert.equal(state.embedding?.reserved.requests, 2);
  assert.ok(state.embedding?.pendingWorkId);
  await assert.rejects(restarted.reserve(), /reconcile|reconciliation/);
  await assert.rejects(restarted.reservePlanningCall(permit, 1), /reconcile|owned/);
  await restarted.reconcile(permit.id, "trusted-host-fixture-quiescence-evidence");
  const reconciled = await restarted.snapshot();
  assert.equal(reconciled.embedding?.pendingWorkId, undefined);
  assert.deepEqual(reconciled.embedding?.reserved, state.embedding?.reserved);
});

test("embedding known HTTP refusal closes observed work but keeps the whole non-refundable reservation", async t => {
  const f = fixture(t), budget = f.make(), permit = await budget.reserve();
  let requests = 0;
  const url = await serve(t, (_req, res) => { requests++; res.writeHead(403); res.end(); });
  await assert.rejects(provider(url).embedBounded(["a"], { reserve: plan => budget.reserveEmbeddingWork(permit, plan) }), /HTTP 403/);
  assert.equal(requests, 1);
  assert.equal((await budget.snapshot()).embedding?.pendingWorkId, undefined);
  await budget.finish(permit);
  assert.equal((await f.make().snapshot()).status, "ready");
  assert.equal((await f.make().snapshot()).embedding?.reserved.requests, 2);
});

test("embedding rejects corrupted, mismatched, zero, duplicate-index and oversized responses without another batch", async t => {
  const bad = [
    { data: [{ embedding: ["not-a-number", 1] }, { embedding: [1, 2] }] },
    { data: [{ embedding: [1] }, { embedding: [1, 2] }] },
    { data: [{ embedding: [0, 0] }, { embedding: [1, 2] }] },
    { data: [{ index: 0, embedding: [1, 2] }, { index: 0, embedding: [2, 1] }] },
    { data: [{ embedding: [1, 2] }] },
    { padding: "x".repeat(1024) },
  ];
  const f = fixture(t);
  for (const [i, body] of bad.entries()) {
    let requests = 0;
    const url = await serve(t, (_req, res) => { requests++; res.end(JSON.stringify(body)); });
    const budget = f.make(`malformed-${i}`), permit = await budget.reserve();
    await assert.rejects(provider(url).embedBounded(["a", "b", "c"], { maxBatchWindows: 2, maxResponseBytes: 512, reserve: plan => budget.reserveEmbeddingWork(permit, plan) }));
    assert.equal(requests, 1);
    await budget.finish(permit);
    assert.equal((await f.make(`malformed-${i}`).snapshot()).status, "reconciliation");
  }
});

test("embedding response-body timeout is held without blind retry", async t => {
  const f = fixture(t), budget = f.make(), permit = await budget.reserve();
  let requests = 0;
  const url = await serve(t, (_req, res) => { requests++; res.writeHead(200, { "content-type": "application/json" }); res.write('{"data":['); });
  await assert.rejects(provider(url, 2, 200).embedBounded(["a"], { reserve: plan => budget.reserveEmbeddingWork(permit, plan) }));
  assert.equal(requests, 1);
  await budget.finish(permit);
  assert.equal((await f.make().snapshot()).status, "reconciliation");
});

test("embedding cancellation before dispatch spends nothing; in-flight cancellation remains held", async t => {
  const f = fixture(t), budget = f.make(), permit = await budget.reserve();
  const controller = new AbortController();
  let requests = 0;
  const url = await serve(t, (_req, _res) => { requests++; controller.abort(); });
  const options = { reserve: (plan: Parameters<RecoveryBudget["reserveEmbeddingWork"]>[1]) => budget.reserveEmbeddingWork(permit, plan) };
  await assert.rejects(provider(url).embedBounded(["a"], { ...options, signal: AbortSignal.abort() }));
  assert.equal((await budget.snapshot()).embedding?.reserved.requests, 0);
  await assert.rejects(provider(url).embedBounded(["a"], { ...options, signal: controller.signal }));
  assert.equal(requests, 1);
  await budget.finish(permit);
  assert.equal((await f.make().snapshot()).status, "reconciliation");
});

test("embedding control serializes its admitted work and cannot be replayed or replace pending planning work", async t => {
  const f = fixture(t), budget = f.make(), permit = await budget.reserve();
  const control = await budget.reserveEmbeddingWork(permit, { requests: 2, inputBytes: 100, windows: 2 });
  await assert.rejects(budget.reservePlanningCall(permit, 1), /owned and live/);
  await assert.rejects(budget.reserveEmbeddingWork(permit, { requests: 1, inputBytes: 1, windows: 1 }), /unresolved embedding/);
  let release!: () => void;
  const wait = new Promise<void>(resolve => { release = resolve; });
  const request = control.runRequest(50, 1, async () => { await wait; return "observed"; });
  await assert.rejects(control.runRequest(50, 1, async () => "duplicate"), /busy/);
  await assert.rejects(control.complete(), /busy/);
  release();
  assert.equal(await request, "observed");
  await assert.rejects(control.runRequest(51, 1, async () => "oversized"), /exceeds reservation/);
  await control.complete();
  await assert.rejects(control.runRequest(1, 1, async () => "replay"), /closed/);
  assert.equal(await budget.reservePlanningCall(permit, 1), true);
  await budget.finish(permit);
  await assert.rejects(f.make("embedding-job", { ...f.limits, embedding: { requests: 9, inputBytes: 8192, windows: 16 } }).snapshot(), /identity\/limits/);
});

test("unfinished aggregate reservation survives executor loss even before its first dispatch", async t => {
  const f = fixture(t), budget = f.make(), permit = await budget.reserve();
  await budget.reserveEmbeddingWork(permit, { requests: 2, inputBytes: 100, windows: 2 });
  const nextExecutor = f.make();
  await assert.rejects(nextExecutor.reserve(), /unresolved attempt/);
  await budget.finish(permit);
  const state = await nextExecutor.snapshot();
  assert.equal(state.status, "reconciliation");
  assert.ok(state.pendingAttemptId);
  assert.ok(state.embedding?.pendingWorkId);
  assert.deepEqual(state.embedding?.reserved, { requests: 2, inputBytes: 100, windows: 2 });
});

const embeddingProcessing: EmbeddingProcessingDeclaration = {
  query: { purpose: "memory-query-embedding", region: "eu" }, document: { purpose: "memory-document-embedding", region: "eu" },
};

test("routed bounded embeddings carry captured privacy restrictions on every HTTP attempt and reserve full JSON", async t => {
  const f = fixture(t), budget = f.make(), permit = await budget.reserve(), bodies: string[] = [];
  const providers = ["AdmittedEncoder"];
  const policy = { zeroDataRetention:true, dataCollection:"deny" as const, allowFallbacks:false as const, providers } as const;
  const expected = {zdr:true,data_collection:"deny",allow_fallbacks:false,only:["AdmittedEncoder"]};
  const dialect = openAiDialectWithRouting(policy);
  providers[0] = "NotAdmitted";
  const url = await serve(t, (_req, res, body) => {
    bodies.push(body); const parsed = JSON.parse(body); assert.deepEqual(parsed.provider, expected);
    if(bodies.length===1){res.writeHead(429,{"retry-after":"0"});res.end();return;}
    res.end(JSON.stringify({data:parsed.input.map((text:string,index:number)=>({index,embedding:[text.length,1]}))}));
  });
  const input = ["document one","document two"];
  const result = await new HttpProvider({baseUrl:url,model:"routed-encoder",apiKey:"fixture-only",dialect,retry:{maxAttempts:2,baseBackoffMs:0}})
    .embedBounded(input,{role:"document",maxBatchWindows:1,reserve:work=>budget.reserveEmbeddingWork(permit,work)});
  assert.equal(bodies.length,3);
  const bytes = input.reduce((n,text)=>n+Buffer.byteLength(JSON.stringify({model:"routed-encoder",input:[text],provider:expected})),0);
  assert.deepEqual(result.reserved,{requests:4,inputBytes:bytes*2,windows:4});
  assert.deepEqual(result.dispatched,{requests:3,inputBytes:bodies.reduce((n,b)=>n+Buffer.byteLength(b),0),windows:3});
  assert.deepEqual(dialect.buildGenerate("fixture","public",1,false).body.provider,expected);
  await budget.finish(permit);
});
function governedFixture(f: ReturnType<typeof fixture>, url: string, options: {
  processing?: EmbeddingProcessingDeclaration; gate?: () => boolean;
} = {}) {
  const spine = f.makeSpine(), audit: unknown[] = [], purposes: Readonly<Record<string, string>>[] = [];
  const brokered = buildDefaultBrokeredEgress(provider(url), { write: row => { audit.push(row); } }, {
    transportClass: "remote", ownerAuthority: true, witness: new SpineDurableWitness(spine, "embedding-egress"),
  });
  const governed = new GovernedRemoteProvider(brokered,
    new ResidencyEnforcer({ allowedRegions: ["eu"], egressAllowlist: ["127.0.0.1"], allowedPurposes: ["chat", "memory-query-embedding", "memory-document-embedding"] }),
    "127.0.0.1", { purpose: "chat", region: "eu" },
    (prompt, target) => interceptEgress(prompt, target, { classifier: new DataClassifier(), session: () => new RedactionGateway() }),
    (_operation, context) => { purposes.push(context); return { allowed: options.gate?.() ?? true }; }, options.processing);
  return { gateway: new ModelGateway(new TracingModelProvider(governed, new TraceRecorder(spine), () => undefined)), audit, purposes };
}

test("bounded embeddings cross the actual gateway, tracing, privacy, broker and durable witness before HTTP", async t => {
  const f = fixture(t), budget = f.make(), permit = await budget.reserve();
  let requests = 0;
  const observations: { witnessed: boolean; reserved: number | undefined }[] = [];
  const url = await serve(t, async (_req, res, body) => {
    requests++;
    observations.push({ witnessed: f.makeSpine().replay().some(e => e.type === "effect.intent"), reserved: (await f.make().snapshot()).embedding?.reserved.requests });
    if (requests === 1) { res.writeHead(429, { "retry-after": "0" }); res.end(); return; }
    const { input } = JSON.parse(body) as { input: string[] };
    res.end(JSON.stringify({ data: input.map((text, index) => ({ index, embedding: [text.length, 1] })) }));
  });
  const g = governedFixture(f, url, { processing: embeddingProcessing });
  const result = await g.gateway.embedBounded(["orchard", "garden", "maple"], { role: "document", maxBatchWindows: 2, reserve: work => budget.reserveEmbeddingWork(permit, work) });
  assert.deepEqual(result.vectors, [[7, 1], [6, 1], [5, 1]]);
  assert.equal(result.dispatched.requests, 3);
  assert.equal(result.reserved.requests, 4);
  assert.deepEqual(observations, Array(3).fill({ witnessed: true, reserved: 4 }));
  assert.ok(g.audit.length > 0);
  assert.ok(g.purposes.length >= 4);
  assert.ok(g.purposes.every(c => c.purpose === "memory-document-embedding" && c.role === "document"));
  await budget.finish(permit);
  assert.equal((await f.make().snapshot()).embedding?.pendingWorkId, undefined);
});

test("bounded gateway refuses chat-only purpose, missing role and incompatible privacy transformation before reservation", async t => {
  const f = fixture(t), budget = f.make(), permit = await budget.reserve();
  let requests = 0;
  const url = await serve(t, (_req, res) => { requests++; res.end("{}"); });
  const reserve = (work: Parameters<RecoveryBudget["reserveEmbeddingWork"]>[1]) => budget.reserveEmbeddingWork(permit, work);
  await assert.rejects(governedFixture(f, url).gateway.embedBounded(["orchard"], { role: "document", reserve }), /explicit query\/document/);
  const g = governedFixture(f, url, { processing: embeddingProcessing });
  await assert.rejects(g.gateway.embedBounded(["orchard"], { reserve }), /explicit query\/document/);
  await assert.rejects(g.gateway.embedBounded(["Contact test.person@example.com"], { role: "document", reserve }), /transformation identity|privacy boundary/);
  const denied = governedFixture(f, url, { processing: { ...embeddingProcessing, query: { purpose: "not-admitted", region: "eu" } } });
  await assert.rejects(denied.gateway.embedBounded(["orchard"], { role: "query", reserve }), /purpose/);
  assert.equal((await budget.snapshot()).embedding?.reserved.requests, 0);
  assert.equal(requests, 0);
  assert.throws(() => new ModelGateway(new LocalProvider()).embedBounded(["orchard"], { reserve }), /no unmetered fallback/);
  await budget.finish(permit);
});

test("governed embedding rechecks live purpose authority between batches and retains its aggregate on withdrawal", async t => {
  const f = fixture(t), budget = f.make(), permit = await budget.reserve();
  let requests = 0, live = true;
  const url = await serve(t, (_req, res) => {
    requests++; live = false;
    res.end(JSON.stringify({ data: [{ embedding: [1, 2] }] }));
  });
  const g = governedFixture(f, url, { processing: embeddingProcessing, gate: () => live });
  await assert.rejects(g.gateway.embedBounded(["orchard", "garden"], { role: "query", maxBatchWindows: 1, reserve: work => budget.reserveEmbeddingWork(permit, work) }), /denied|broker/);
  assert.equal(requests, 1);
  await budget.finish(permit);
  const state = await f.make().snapshot();
  assert.equal(state.status, "reconciliation");
  assert.equal(state.embedding?.reserved.requests, 4);
  assert.ok(state.embedding?.pendingWorkId);
});
