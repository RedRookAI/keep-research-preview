import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingHttpHeaders, type ServerResponse } from "node:http";
import { networkInterfaces, tmpdir } from "node:os";
import { mkdtempSync, readlinkSync } from "node:fs";
import { join } from "node:path";
import { HttpProvider, ProviderError } from "../src/gateway/http_provider.js";
import { openAiDialect, anthropicDialect, type WireDialect } from "../src/gateway/wire_dialect.js";
import { composeKeep } from "../src/index.js";
import { RecoveryBudget } from "../src/solve/recovery_budget.js";

// Builder runs set this to the outer inode and use PrivateNetwork=yes. Ordinary
// developers may run the same finite loopback-only tests without claiming isolation.
if (process.env["KEEP_TEST_HOST_NETNS"]) {
  assert.notEqual(readlinkSync("/proc/self/ns/net"), process.env["KEEP_TEST_HOST_NETNS"]);
  assert.ok(Object.keys(networkInterfaces()).every(name => name === "lo"));
}

const textResponse = (dialect: WireDialect) => dialect.name === anthropicDialect.name
  ? { model: "synthetic", content: [{ type: "text", text: "useful" }], usage: { input_tokens: 2, output_tokens: 1 } }
  : { model: "synthetic", choices: [{ message: { content: "useful" } }], usage: { prompt_tokens: 2, completion_tokens: 1 } };
const streamed = (dialect: WireDialect) => dialect.name === anthropicDialect.name
  ? 'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"text":"useful"}}\n\nevent: message_stop\ndata: {"type":"message_stop"}\n\n'
  : 'data: {"choices":[{"delta":{"content":"useful"}}]}\n\ndata: [DONE]\n\n';

async function receiver(host: "127.0.0.1" | "127.0.0.2", handle: (res: ServerResponse) => void) {
  const requests: { body: string; headers: IncomingHttpHeaders; url: string | undefined }[] = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", chunk => { body += chunk; if (body.length > 65536) req.destroy(); });
    req.on("end", () => { requests.push({ body, headers: { ...req.headers }, url: req.url }); handle(res); });
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, host, resolve); });
  const address = server.address(); assert.ok(address && typeof address !== "string");
  return { url: `http://${host}:${address.port}`, requests,
    async close() { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); } };
}

for (const dialect of [openAiDialect, anthropicDialect]) for (const streaming of [false, true]) {
  test(`KEEP-12A-001 ${dialect.name} ${streaming ? "stream" : "ordinary"}: useful response and cross-host redirect refusal`, async () => {
    const forbidden = await receiver("127.0.0.2", res => res.end(streaming ? streamed(dialect) : JSON.stringify(textResponse(dialect))));
    let redirect = false;
    const allowed = await receiver("127.0.0.1", res => {
      if (redirect) { res.writeHead(307, { location: forbidden.url + "/destination" }); res.end(); }
      else res.end(streaming ? streamed(dialect) : JSON.stringify(textResponse(dialect)));
    });
    try {
      const provider = new HttpProvider({ baseUrl: allowed.url, model: "synthetic", apiKey: "SYNTHETIC_ONLY_KEY", dialect,
        retry: { maxAttempts: 2, baseBackoffMs: 0 }, requestTimeoutMs: 1000 });
      const run = () => streaming ? provider.generateStream({ prompt: "synthetic useful task" }) : provider.generate({ prompt: "synthetic useful task" });
      assert.equal((await run()).text, "useful");
      redirect = true;
      let error: unknown;
      try { await run(); } catch (e) { error = e; }
      assert.equal(forbidden.requests.length, 0, "unadmitted receiver must get neither request body nor custom authentication");
      assert.ok(error instanceof ProviderError && error.permanent && error.status === 307);
      assert.equal(allowed.requests.length, 2, "a known redirect is not retried");
      assert.ok(allowed.requests.every(r => r.body.includes("synthetic useful task")));
    } finally { await allowed.close(); await forbidden.close(); }
  });
}

test("KEEP-12A-001 personal composed broker/residency/privacy refuses redirected buffered generation", async () => {
  let redirect = false;
  const forbidden = await receiver("127.0.0.2", res => res.end(JSON.stringify(textResponse(anthropicDialect))));
  const allowed = await receiver("127.0.0.1", res => {
    if (redirect) { res.writeHead(307, { location: forbidden.url + "/v1/messages" }); res.end(); }
    else res.end(JSON.stringify(textResponse(anthropicDialect)));
  });
  try {
    const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-12a-owner-")),
      ownerProvider: { mode: "anthropic-compatible", baseUrl: allowed.url, model: "synthetic", apiKey: "SYNTHETIC_OWNER_KEY" },
      remoteProcessing: { purpose: "code", region: "audit" },
      residency: { allowedPurposes: ["code"], allowedRegions: ["audit"], egressAllowlist: ["127.0.0.1"] } });
    assert.equal((await app.gateway.generate({ prompt: "Useful synthetic task" })).text, "useful");
    redirect = true;
    const callbacks: string[] = [];
    let failed = false;
    try { await app.egressProvider!.generateStream!({ prompt: "Another synthetic task" }, text => callbacks.push(text)); } catch { failed = true; }
    assert.equal(forbidden.requests.length, 0);
    assert.equal(failed, true); assert.deepEqual(callbacks, []);
    assert.equal(allowed.requests.length, 2);
    await app.spine.seal();
    assert.ok(app.spine.replay().some(e => JSON.stringify(e.payload).includes('"stage":"dispatch"') && JSON.stringify(e.payload).includes("provider redirect refused")), "durable dispatch failure remains observable");
  } finally { await allowed.close(); await forbidden.close(); }
});

for (const kind of ["generation", "embedding", "error-text"] as const) {
  test(`KEEP-12A-002 ${kind}: timeout covers prompt headers followed by delayed body`, async () => {
    let delayed = false;
    const server = await receiver("127.0.0.1", res => {
      const body = kind === "embedding" ? JSON.stringify({ data: [{ embedding: [1, 0] }], usage: { prompt_tokens: 1 } })
        : kind === "error-text" && delayed ? "synthetic refusal" : JSON.stringify(textResponse(openAiDialect));
      res.writeHead(kind === "error-text" && delayed ? 400 : 200, { "content-type": "application/json" }); res.flushHeaders();
      if (!delayed) { res.end(body); return; }
      const timer = setTimeout(() => res.end(body), 500);
      res.once("close", () => clearTimeout(timer));
    });
    try {
      let aborted = false;
      const observedFetch: typeof fetch = (input, init) => {
        init?.signal?.addEventListener("abort", () => { aborted = true; }, { once: true });
        return fetch(input, init);
      };
      const provider = new HttpProvider({ baseUrl: server.url, model: "synthetic", apiKey: "SYNTHETIC_KEY", dialect: openAiDialect,
        requestTimeoutMs: 60, retry: { maxAttempts: 3, baseBackoffMs: 0 }, fetchImpl: observedFetch });
      const run = () => kind === "embedding" ? provider.embed(["synthetic input"]) : provider.generate({ prompt: "synthetic task" });
      await run();
      delayed = true;
      await assert.rejects(run(), (error: unknown) => error instanceof ProviderError && error.permanent);
      assert.equal(aborted, true, "the attempt's deadline must still be armed during body reading");
      assert.equal(server.requests.length, 2);
    } finally { await server.close(); }
  });
}

test("redirect fixture calibration: native follow forwards the synthetic custom key and body", async () => {
  const destination = await receiver("127.0.0.2", res => res.end("calibrated"));
  const initial = await receiver("127.0.0.1", res => { res.writeHead(307, { location: destination.url }); res.end(); });
  try {
    const response = await fetch(initial.url, { method: "POST", redirect: "follow", signal: AbortSignal.timeout(1000),
      headers: { "x-api-key": "SYNTHETIC_CALIBRATION_ONLY", authorization: "Bearer SYNTHETIC_CALIBRATION_ONLY" }, body: "synthetic-body" });
    assert.equal(await response.text(), "calibrated");
    assert.equal(initial.requests.length, 1); assert.equal(destination.requests.length, 1);
    assert.equal(destination.requests[0]!.headers["x-api-key"], "SYNTHETIC_CALIBRATION_ONLY");
    assert.equal(destination.requests[0]!.headers["authorization"], undefined);
    assert.equal(destination.requests[0]!.body, "synthetic-body");
  } finally { await initial.close(); await destination.close(); }
});

for (const status of [301, 302, 303, 304, 307, 308]) for (const mode of ["ordinary", "stream", "embed"] as const) {
  test(`KEEP-12A-001 ${status} ${mode}: same-host redirects and missing Location are not retried`, async () => {
    const target = await receiver("127.0.0.1", res => res.end("must not arrive"));
    const initial = await receiver("127.0.0.1", res => { res.writeHead(status, status === 304 ? {} : { location: target.url }); res.end(); });
    try {
      const provider = new HttpProvider({ baseUrl: initial.url, model: "synthetic", apiKey: "SYNTHETIC_ONLY", dialect: openAiDialect,
        retry: { maxAttempts: 3, baseBackoffMs: 0 }, requestTimeoutMs: 1000 });
      const run = () => mode === "embed" ? provider.embed(["synthetic"]) : mode === "stream"
        ? provider.generateStream({ prompt: "synthetic" }) : provider.generate({ prompt: "synthetic" });
      await assert.rejects(run(), (e: unknown) => e instanceof ProviderError && e.permanent && e.status === status);
      assert.equal(initial.requests.length, 1); assert.equal(target.requests.length, 0);
    } finally { await initial.close(); await target.close(); }
  });
}

test("KEEP-12A-001 opaque redirect and cancelling unread rejected body stay contained", async () => {
  for (const response of [new Response(null), new Response(new ReadableStream({ cancel() { throw new Error("synthetic cleanup failure"); } }), { status: 307 })]) {
    if (response.status === 200) Object.defineProperty(response, "type", { value: "opaqueredirect" });
    let calls = 0;
    const provider = new HttpProvider({ baseUrl: "http://127.0.0.1:1", model: "synthetic", apiKey: "SYNTHETIC_ONLY", dialect: openAiDialect,
      fetchImpl: async () => { calls++; return response; } });
    await assert.rejects(provider.generate({ prompt: "synthetic" }), (e: unknown) => e instanceof ProviderError && e.permanent);
    assert.equal(calls, 1);
  }
  // node:test reports any uncaught exception or unhandled rejection as a failure.
  await new Promise<void>(resolve => setImmediate(resolve));
});

test("KEEP-12A bounded embedding already refuses redirects without retry and preserves its recovery hold", async () => {
  const target = await receiver("127.0.0.2", res => res.end(JSON.stringify({ data: [{ embedding: [1, 0] }] })));
  const initial = await receiver("127.0.0.1", res => { res.writeHead(307, { location: target.url }); res.end(); });
  try {
    const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-12a-bounded-")) });
    const budget = new RecoveryBudget(app.spine, "redirect-embedding", { maxAttempts: 3, maxElapsedMs: 5000,
      embedding: { requests: 3, inputBytes: 8192, windows: 3 } });
    const permit = await budget.reserve();
    const provider = new HttpProvider({ baseUrl: initial.url, model: "synthetic", apiKey: "SYNTHETIC_ONLY", dialect: openAiDialect,
      retry: { maxAttempts: 3, baseBackoffMs: 0 }, requestTimeoutMs: 1000 });
    await assert.rejects(provider.embedBounded(["synthetic"], { reserve: work => budget.reserveEmbeddingWork(permit, work) }));
    assert.equal(initial.requests.length, 1); assert.equal(target.requests.length, 0);
    assert.ok((await budget.snapshot()).embedding?.pendingWorkId, "a redirect fetch failure does not establish remote no-effect finality");
  } finally { await initial.close(); await target.close(); }
});

for (const status of [429, 503]) {
  test(`KEEP-12A-002 ${status}: unread stalled transient body does not block the existing retry`, async () => {
    let hits = 0;
    const server = await receiver("127.0.0.1", res => {
      if (++hits === 1) { res.writeHead(status, { "retry-after": "0" }); res.flushHeaders(); }
      else res.end(JSON.stringify(textResponse(openAiDialect)));
    });
    try {
      const provider = new HttpProvider({ baseUrl: server.url, model: "synthetic", apiKey: "SYNTHETIC_ONLY", dialect: openAiDialect,
        retry: { maxAttempts: 2, baseBackoffMs: 0 }, requestTimeoutMs: 200 });
      assert.equal((await provider.generate({ prompt: "synthetic" })).text, "useful"); assert.equal(hits, 2);
    } finally { await server.close(); }
  });
}

test("KEEP-12A-002 caller cancellation during response body is permanent and never replayed", async () => {
  const controller = new AbortController();
  let bodyStarted!: () => void;
  const started = new Promise<void>(resolve => { bodyStarted = resolve; });
  const server = await receiver("127.0.0.1", res => { res.writeHead(200); res.flushHeaders(); });
  try {
    const provider = new HttpProvider({ baseUrl: server.url, model: "synthetic", apiKey: "SYNTHETIC_ONLY", dialect: openAiDialect,
      requestTimeoutMs: 1000, retry: { maxAttempts: 3, baseBackoffMs: 0 },
      fetchImpl: async (input, init) => { const response = await fetch(input, init); bodyStarted(); return response; } });
    const pending = provider.generate({ prompt: "synthetic", signal: controller.signal });
    await started; controller.abort();
    await assert.rejects(pending, (e: unknown) => e instanceof ProviderError && e.permanent && /cancelled/u.test(e.message));
    assert.equal(server.requests.length, 1);
  } finally { await server.close(); }
});

test("KEEP-12A retry wait reacts to cancellation without waiting for supplied sleep or another HTTP attempt", async () => {
  let entered!: () => void, finishSleep!: () => void;
  const sleeping = new Promise<void>(resolve => { entered = resolve; });
  const server = await receiver("127.0.0.1", res => { res.writeHead(429); res.end(); });
  try {
    const controller = new AbortController();
    const provider = new HttpProvider({ baseUrl: server.url, model: "synthetic", apiKey: "SYNTHETIC_ONLY", dialect: openAiDialect,
      sleep: () => { entered(); return new Promise<void>(resolve => { finishSleep = resolve; }); } });
    const pending = provider.generate({ prompt: "synthetic", signal: controller.signal });
    await sleeping; controller.abort();
    await assert.rejects(pending, (e: unknown) => e instanceof ProviderError && e.permanent && /cancelled/u.test(e.message));
    assert.equal(server.requests.length, 1);
    finishSleep(); await new Promise<void>(resolve => setImmediate(resolve)); assert.equal(server.requests.length, 1);
  } finally { finishSleep?.(); await server.close(); }
});

for (const dialect of [openAiDialect, anthropicDialect]) {
  test(`KEEP-12A-003/004 ${dialect.name}: actual HTTP errors fail and post-terminal text is excluded`, async () => {
    let mode: "useful" | "error" | "tail" = "useful";
    const terminal = dialect === anthropicDialect ? 'event: message_stop\ndata: {"type":"message_stop"}\n\n' : 'data: [DONE]\n\n';
    const prefix = dialect === anthropicDialect ? 'data: {"type":"content_block_delta","delta":{"text":"useful"}}\n\n'
      : 'data: {"choices":[{"delta":{"content":"useful"}}]}\n\n';
    const server = await receiver("127.0.0.1", res => {
      res.setHeader("content-type", "text/event-stream");
      res.end(prefix + (mode === "error" ? 'event: error\ndata: {"error":{"message":"synthetic failure"}}\n\n' : "")
        + terminal + (mode === "tail" ? prefix.replace("useful", "forbidden tail") : ""));
    });
    try {
      const make = () => new HttpProvider({ baseUrl: server.url, model: "synthetic", apiKey: "SYNTHETIC_ONLY", dialect,
        retry: { maxAttempts: 3 }, requestTimeoutMs: 1000 });
      assert.equal((await make().generateStream({ prompt: "synthetic" })).text, "useful");
      mode = "error";
      const failed = make(), partial: string[] = [];
      await assert.rejects(failed.generateStream({ prompt: "synthetic" }, t => partial.push(t)),
        (e: unknown) => e instanceof ProviderError && e.permanent);
      assert.deepEqual(partial, ["useful"]); assert.equal(failed.lastUsage.value, undefined);
      mode = "tail";
      const callbacks: string[] = [];
      assert.equal((await make().generateStream({ prompt: "synthetic" }, t => callbacks.push(t))).text, "useful");
      assert.deepEqual(callbacks, ["useful"]); assert.equal(server.requests.length, 3);
    } finally { await server.close(); }
  });
}

test("direct streaming keeps its lifetime deadline after a partial HTTP body", async () => {
  const server = await receiver("127.0.0.1", res => {
    res.setHeader("content-type", "text/event-stream");
    res.write('data: {"choices":[{"delta":{"content":"partial"}}]}\n\n');
  });
  try {
    const provider = new HttpProvider({ baseUrl: server.url, model: "synthetic", apiKey: "SYNTHETIC_ONLY", dialect: openAiDialect,
      requestTimeoutMs: 100, retry: { maxAttempts: 3 } });
    const callbacks: string[] = [];
    await assert.rejects(provider.generateStream({ prompt: "synthetic" }, t => callbacks.push(t)));
    assert.deepEqual(callbacks, ["partial"]); assert.equal(server.requests.length, 1);
    assert.equal(provider.lastUsage.value, undefined);
  } finally { await server.close(); }
});
