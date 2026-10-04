import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHmac } from "node:crypto";
import { mkdtempSync, appendFileSync, readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";

const SECRET = "owned-replay-fixture", WINDOW = 300_000, INITIAL = 1_760_000_000_000;
async function fixture() {
  const root = mkdtempSync(join(tmpdir(), "keep-replay-identity-")), outbox = join(root, "outbox.jsonl"), replayFile = join(root, "replay.jsonl");
  const sink = createServer(async (req, res) => {
    let raw = ""; for await (const chunk of req) raw += chunk;
    appendFileSync(outbox, JSON.stringify({ path: req.url, raw }) + "\n");
    res.writeHead(200, { "content-type": "application/json" }); res.end(req.url === "/projects" ? '{"projects":[]}' : '{"accepted":true}');
  });
  sink.listen(0, "127.0.0.1"); await once(sink, "listening");
  const address = sink.address(); assert.ok(address && typeof address === "object");
  const port = address.port;
  const children: ChildProcess[] = [];
  const count = () => { try { return readFileSync(outbox, "utf8").trim().split("\n").filter(Boolean).length; } catch { return 0; } };
  async function start(now = INITIAL) {
    const moduleUrl = new URL("../src/channel/chat_server.js", import.meta.url).href;
    const script = `Date.now=()=>${now}; process.on("message",m=>{ if(m.type==="clock"){Date.now=()=>m.now; process.send({type:"clock"});} }); const adapter=await import(${JSON.stringify(moduleUrl)}); await adapter.main();`;
    const env: NodeJS.ProcessEnv = { ...process.env, KEEP_GATEWAY_ORIGIN: `http://127.0.0.1:${port}`, KEEP_GATEWAY_TOKEN: "owned-gateway", KEEP_CHAT_SECRET: SECRET, KEEP_CHAT_REPLAY_FILE: replayFile, KEEP_CHAT_PORT: "0" }; delete env["NODE_TEST_CONTEXT"];
    const child = spawn(process.execPath, ["--input-type=module", "--eval", script], { env, stdio: ["ignore", "pipe", "pipe", "ipc"] }); children.push(child);
    let stdout = "", stderr = ""; child.stderr?.on("data", data => { stderr += data; });
    const closed = new Promise<void>(resolve => child.once("close", () => resolve()));
    const origin = await new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("owned adapter startup deadline")); }, 3_000);
      child.once("error", error => { clearTimeout(timer); reject(error); });
      child.once("exit", code => { clearTimeout(timer); reject(new Error(`adapter exited ${code}: ${stderr}`)); });
      child.stdout?.on("data", data => { stdout += data; if (!stdout.includes("\n")) return; clearTimeout(timer); const ready = JSON.parse(stdout.split("\n")[0]!); resolve(`http://${ready.host}:${ready.port}`); });
    });
    return { child, origin, async clock(next: number) { const ack = once(child, "message"); child.send({ type: "clock", now: next }); await ack; }, async stop() { child.kill("SIGTERM"); await closed; } };
  }
  async function send(origin: string, raw: string, timestamp: number | string, id: string, valid = true) {
    const signature = createHmac("sha256", SECRET).update(`${Number(timestamp)}.${raw}`).digest("hex");
    const response = await fetch(`${origin}/event`, { method: "POST", headers: { "content-type": "application/json", "x-webhook-id": id, "x-webhook-timestamp": String(timestamp), "x-webhook-signature": `sha256=${valid ? signature : "0".repeat(64)}` }, body: raw });
    const body = await response.text(); return { status: response.status, body };
  }
  async function cleanup() {
    for (const child of children) if (child.exitCode === null && child.signalCode === null) { const closed = once(child, "close"); child.kill("SIGKILL"); await closed; }
    await new Promise<void>((resolve, reject) => sink.close(error => error ? reject(error) : resolve()));
    rmSync(root, { recursive: true, force: true });
  }
  return { root, replayFile, outbox, count, start, send, cleanup };
}

test("same authenticated envelope dispatches once across varied metadata, concurrency and restart", { timeout: 10_000 }, async () => {
  const f = await fixture();
  try {
    let adapter = await f.start(); const raw = JSON.stringify({ kind: "project", goal: "owned single dispatch", eventId: "owner-1" }), ts = INITIAL / 1000;
    const results = await Promise.all(Array.from({ length: 5 }, (_, i) => f.send(adapter.origin, raw, ts, `metadata-${i}`)));
    assert.equal(results.filter(r => r.status === 200).length, 1); assert.equal(results.filter(r => r.status === 409).length, 4);
    assert.equal(f.count(), 1); await adapter.stop(); adapter = await f.start();
    assert.equal((await f.send(adapter.origin, raw, ts, "metadata-after-restart")).status, 409);
    assert.equal(f.count(), 1);
  } finally { await f.cleanup(); }
});

test("distinct signed event material in the same second admits both scoped intents", { timeout: 10_000 }, async () => {
  const f = await fixture();
  try {
    const adapter = await f.start();
    for (const eventId of ["owner-1", "organization-tenant-a-1"]) {
      assert.equal((await f.send(adapter.origin, JSON.stringify({ kind: "project", goal: "same useful operation", eventId }), INITIAL / 1000, "same-unsigned-metadata")).status, 200);
    }
    assert.equal(f.count(), 2);
  } finally { await f.cleanup(); }
});

test("bad signature and stale authenticated envelope never reach the outbox", { timeout: 10_000 }, async () => {
  const f = await fixture();
  try {
    const adapter = await f.start(), raw = JSON.stringify({ kind: "projects" });
    assert.equal((await f.send(adapter.origin, raw, INITIAL / 1000, "bad", false)).status, 401);
    assert.equal((await f.send(adapter.origin, raw, (INITIAL - WINDOW - 1) / 1000, "stale")).status, 401);
    assert.equal(f.count(), 0);
    assert.equal(readFileSync(`${f.replayFile}.authenticated-v2.jsonl`, "utf8").trim().split("\n").length, 1);
  } finally { await f.cleanup(); }
});

test("future timestamp protection lasts to its last eligible instant across receipt age and restart", { timeout: 10_000 }, async () => {
  const f = await fixture();
  try {
    let adapter = await f.start(); const raw = JSON.stringify({ kind: "project", goal: "future envelope", eventId: "future-1" }), ts = (INITIAL + WINDOW) / 1000;
    assert.equal((await f.send(adapter.origin, raw, ts, "first")).status, 200);
    await adapter.clock(INITIAL + WINDOW + 1);
    assert.equal((await f.send(adapter.origin, raw, ts, "later")).status, 409);
    await adapter.stop(); adapter = await f.start(INITIAL + 2 * WINDOW);
    assert.equal((await f.send(adapter.origin, raw, ts, "inclusive-boundary")).status, 409);
    await adapter.clock(INITIAL + 2 * WINDOW + 1);
    assert.equal((await f.send(adapter.origin, raw, ts, "stale-now")).status, 401);
    assert.equal(f.count(), 1);
  } finally { await f.cleanup(); }
});


test("numeric-canonical timestamp spellings have one authenticated identity", { timeout: 10_000 }, async () => {
  const f = await fixture();
  try { const adapter = await f.start(), raw = JSON.stringify({ kind: "projects" });
    assert.equal((await f.send(adapter.origin, raw, INITIAL / 1000, "first")).status, 200);
    assert.equal((await f.send(adapter.origin, raw, `${INITIAL / 1000}.0`, "other")).status, 409); assert.equal(f.count(), 1);
  } finally { await f.cleanup(); }
});

test("legacy migration preserves bytes, requires explicit quiet cutoff and detects later activity", { timeout: 10_000 }, async () => {
  const { recordReplayMigration } = await import("../src/channel/chat_server.js");
  for (const legacy of ["", JSON.stringify({ id: "unsigned-legacy", at: INITIAL }) + "\n"]) {
    const f = await fixture();
    try {
      writeFileSync(f.replayFile, legacy); await assert.rejects(f.start(), /record-replay-cutoff/);
      assert.equal(readFileSync(f.replayFile, "utf8"), legacy); assert.equal(existsSync(`${f.replayFile}.authenticated-v2.jsonl`), false);
      recordReplayMigration(f.replayFile, INITIAL);
      await assert.rejects(f.start(INITIAL + 2 * WINDOW), /quiet window/);
      assert.equal(readFileSync(f.replayFile, "utf8"), legacy);
      let adapter = await f.start(INITIAL + 2 * WINDOW + 1);
      const raw = JSON.stringify({ kind: "projects" });
      assert.equal((await f.send(adapter.origin, raw, (INITIAL + 2 * WINDOW + 1) / 1000, "new")).status, 200);
      await adapter.stop(); assert.equal(readFileSync(f.replayFile, "utf8"), legacy);
      writeFileSync(f.replayFile, legacy); // Same bytes still constitute later legacy activity.
      await assert.rejects(f.start(INITIAL + 2 * WINDOW + 2), /changed legacy/); assert.equal(f.count(), 1);
    } finally { await f.cleanup(); }
  }
});

test("malformed legacy or new state refuses startup without rewriting evidence", { timeout: 10_000 }, async () => {
  const { recordReplayMigration } = await import("../src/channel/chat_server.js");
  const f = await fixture();
  try {
    const malformed = '{"id":"old","at":"invalid"}\n'; writeFileSync(f.replayFile, malformed);
    assert.throws(() => recordReplayMigration(f.replayFile, INITIAL), /malformed legacy/);
    await assert.rejects(f.start(INITIAL + 3 * WINDOW), /malformed legacy/); assert.equal(readFileSync(f.replayFile, "utf8"), malformed);
    rmSync(f.replayFile); const sidecar = `${f.replayFile}.authenticated-v2.jsonl`, corrupt = '{"schema":"wrong"}\n'; writeFileSync(sidecar, corrupt);
    await assert.rejects(f.start(), /invalid authenticated/); assert.equal(readFileSync(sidecar, "utf8"), corrupt); assert.equal(f.count(), 0);
  } finally { await f.cleanup(); }
});
