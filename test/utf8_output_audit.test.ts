import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ProcessIsolationAdapter } from "../src/infra/process_isolation.js";
import { SandboxedCommandRunner } from "../src/solve/sandboxed_runner.js";
import { InstalledEffectAdmission } from "../src/control/installed_effect_admission.js";
import { StdioMcpTransport } from "../src/infra/mcp_stdio_transport.js";
import { once } from "node:events";
import type { ChildProcess } from "node:child_process";

// Real finite child smoke tests; pipe chunking is OS-controlled. The failed-before
// run observed separate chunks, but later runs do not claim exhaustive scheduling.
// The fix's single final decode plus raw-byte equality makes presentation invariant
// to chunking; the stdio component separately exercises every byte partition.
const splitOutput = `
const out = Buffer.from(process.argv[1], 'hex'), err = Buffer.from(process.argv[2], 'hex');
const cut = Number(process.argv[3]);
process.stdout.write(out.subarray(0, cut)); process.stderr.write(err.subarray(0, cut));
setTimeout(() => { process.stdout.write(out.subarray(cut)); process.stderr.write(err.subarray(cut)); }, 30);
`;

test("KEEP-11A-002: real process stdout/stderr preserve a character split across writes", async () => {
  const adapter = new ProcessIsolationAdapter();
  const expected = Buffer.from("€🦉");
  const result = await adapter.run(process.execPath, ["-e", splitOutput, expected.toString("hex"), expected.toString("hex"), "1"], { cwd: tmpdir(), timeoutMs: 2000, maxOutputBytes: 1024 });
  assert.equal(result.code, 0); assert.equal(result.truncated, false);
  assert.deepEqual(result.stdoutBytes, expected); assert.deepEqual(result.stderrBytes, expected);
  assert.equal(result.stdout, "€🦉"); assert.equal(result.stderr, "€🦉");
});

test("KEEP-11A-002: the command runner retains the exact UTF8 TAP test name", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-utf8-runner-"));
  const tap = Buffer.from("TAP version 13\nok 1 - €🦉\n1..1\n");
  const cut = tap.indexOf(Buffer.from("€")) + 1;
  const runner = new SandboxedCommandRunner({ command: process.execPath,
    args: ["-e", splitOutput, tap.toString("hex"), "", String(cut)], projectDir: dir,
    timeoutMs: 2000, namespaceJail: false, effectAdmission: new InstalledEffectAdmission(() => {}) });
  const result = await runner.run(dir);
  assert.equal(result.runnerError, undefined);
  assert.deepEqual(result.results.map(({ name, passed }) => ({ name, passed })), [{ name: "€🦉", passed: true }]);
});

// Explicit component hook: exercise every stream partition without depending on
// OS pipe coalescing. This is not a peer process or public transport qualification.
type FramePort = {
  onData(bytes: Buffer): void;
  buffer: Buffer;
  pending: Map<number, { resolve(value: unknown): void; reject(error: Error): void; timer: NodeJS.Timeout }>;
};
function frames(maxResponseBytes = 4096) {
  const transport = new StdioMcpTransport("not-started", [], { maxResponseBytes });
  const port = transport as unknown as FramePort;
  const values: { id: number; result?: unknown; error?: string }[] = [];
  const watch = (id: number) => {
    const timer = setTimeout(() => {}, 1000); timer.unref();
    port.pending.set(id, {
      resolve(result) { clearTimeout(timer); values.push({ id, result }); },
      reject(error) { clearTimeout(timer); values.push({ id, error: error.message }); }, timer,
    });
  };
  return { port, values, watch };
}

test("KEEP-11A-002 stdio extension: every byte split preserves UTF8 and matching response identity", () => {
  const expected = { content: "A¢€二🦉B" };
  const encoded = Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: 7, result: expected }) + "\n");
  for (let cut = 1; cut < encoded.length; cut++) {
    const f = frames(); f.watch(7);
    f.port.onData(encoded.subarray(0, cut)); assert.deepEqual(f.values, []);
    f.port.onData(encoded.subarray(cut));
    assert.deepEqual(f.values, [{ id: 7, result: expected }], `split at byte ${cut}`);
    assert.equal(f.port.pending.size, 0);
  }
});

test("process output preserves all interior splits of two-, three- and four-byte characters", async () => {
  const expected = Buffer.from("¢€🦉"), adapter = new ProcessIsolationAdapter();
  for (const cut of [1, 3, 4, 6, 7, 8]) {
    const result = await adapter.run(process.execPath, ["-e", splitOutput, expected.toString("hex"), expected.toString("hex"), String(cut)], { cwd: tmpdir(), timeoutMs: 2000, maxOutputBytes: 1024 });
    assert.equal(result.code, 0); assert.equal(result.truncated, false);
    assert.deepEqual(result.stdoutBytes, expected); assert.deepEqual(result.stderrBytes, expected);
    assert.equal(result.stdout, "¢€🦉", `stdout split ${cut}`);
    assert.equal(result.stderr, "¢€🦉", `stderr split ${cut}`);
  }
});

test("process byte caps preserve exact prefixes and explicitly render incomplete UTF8 with replacement", async () => {
  const bytes = Buffer.from("¢€🦉"), adapter = new ProcessIsolationAdapter();
  for (const cap of [1, 2, 4, 5, 8, 9, 10]) {
    const result = await adapter.run(process.execPath, ["-e", splitOutput, bytes.toString("hex"), bytes.toString("hex"), "1"], { cwd: tmpdir(), timeoutMs: 2000, maxOutputBytes: cap });
    const prefix = bytes.subarray(0, cap);
    assert.equal(result.code, 0); assert.equal(result.truncated, cap < bytes.length);
    assert.deepEqual(result.stdoutBytes, prefix); assert.deepEqual(result.stderrBytes, prefix);
    assert.equal(result.stdout, prefix.toString("utf8")); assert.equal(result.stderr, prefix.toString("utf8"));
  }
});

test("timeout and spawn failure retain accurate partial presentation and diagnostics", async () => {
  const adapter = new ProcessIsolationAdapter();
  const result = await adapter.run(process.execPath, ["-e", "process.stdout.write(Buffer.from([0xe2,0x82]));process.stderr.write(Buffer.from([0xf0,0x9f]));setTimeout(()=>{},1000)"], { cwd: tmpdir(), timeoutMs: 250 });
  assert.equal(result.timedOut, true); assert.equal(result.signal, "SIGKILL");
  assert.deepEqual(result.stdoutBytes, Buffer.from([0xe2, 0x82]));
  assert.deepEqual(result.stderrBytes, Buffer.from([0xf0, 0x9f]));
  assert.equal(result.stdout, "�"); assert.equal(result.stderr, "�");
  const missing = await adapter.run("/definitely/missing/keep-utf8-child", [], { cwd: tmpdir(), timeoutMs: 1000 });
  assert.equal(missing.completion, "not-started");
  assert.match(missing.stderr, /spawn error:.*ENOENT/);
  assert.deepEqual(missing.stderrBytes, Buffer.alloc(0), "parent diagnostic is not child output");
});

test("stdio byte framing retains ID ordering, CRLF, multiple frames and malformed/unknown controls", () => {
  const f = frames(); f.watch(1); f.watch(2);
  const msg = (id: number, result: unknown) => JSON.stringify({ jsonrpc: "2.0", id, result });
  const batch = Buffer.from(" \r\nnot-json\n" + msg(99, "unknown") + "\n" + msg(2, "二") + "\r\n" + msg(1, "🦉") + "\n" + msg(2, "duplicate") + "\n");
  for (const byte of batch) f.port.onData(Buffer.from([byte]));
  assert.deepEqual(f.values, [{ id: 2, result: "二" }, { id: 1, result: "🦉" }]);
  assert.equal(f.port.pending.size, 0);
  f.watch(3);
  f.port.onData(Buffer.from('{"jsonrpc":"2.0","id":3,"error":{"code":-1,"message":"controlled"}}\n'));
  assert.deepEqual(f.values.at(-1), { id: 3, error: "MCP error -1: controlled" });
});

test("UTF8 review regression: JSON-valid non-message values cannot throw or settle a request", () => {
  const f = frames(); f.watch(1);
  for (const value of [null, 123, "text", true, [], {}, { id: "1" }, { id: null }]) {
    assert.doesNotThrow(() => f.port.onData(Buffer.from(JSON.stringify(value) + "\n")));
    assert.equal(f.values.length, 0);
  }
  f.port.onData(Buffer.from('{"jsonrpc":"2.0","id":1,"result":"useful"}\n'));
  assert.deepEqual(f.values, [{ id: 1, result: "useful" }]);
});

test("stdio counts raw buffered bytes including incomplete characters and newline", () => {
  const message = Buffer.from('{"jsonrpc":"2.0","id":1,"result":"🦉"}\n');
  const exact = frames(message.length); exact.watch(1);
  for (const byte of message) exact.port.onData(Buffer.from([byte]));
  assert.deepEqual(exact.values, [{ id: 1, result: "🦉" }]);
  const short = frames(message.length - 1); short.watch(1);
  short.port.onData(message.subarray(0, -1)); assert.equal(short.values.length, 0);
  short.port.onData(message.subarray(-1));
  assert.match(short.values[0]!.error ?? "", /exceeded configured byte bound/);
  assert.equal(short.port.pending.size, 0);
  const incomplete = frames(2); incomplete.watch(9);
  incomplete.port.onData(Buffer.from([0xf0, 0x9f])); assert.equal(incomplete.values.length, 0);
  incomplete.port.onData(Buffer.from([0xa6]));
  assert.match(incomplete.values[0]!.error ?? "", /exceeded configured byte bound/);
  const batch = frames(message.length); batch.watch(1);
  batch.port.onData(Buffer.concat([message, message]));
  assert.match(batch.values[0]!.error ?? "", /exceeded configured byte bound/, "existing cap covers the pending batch before splitting, not each line independently");
});

test("stdio owns partial bytes and compacts a small residual after a large complete line", () => {
  const f = frames(65536); f.watch(1);
  const first = Buffer.from('{"jsonrpc":"2.0","id":1,"result":"');
  f.port.onData(first); first.fill(0x20);
  const rest = Buffer.from("x".repeat(20000) + '"}\n{"jsonrpc"');
  f.port.onData(rest);
  assert.deepEqual(f.values, [{ id: 1, result: "x".repeat(20000) }]);
  assert.equal(f.port.buffer.toString("utf8"), '{"jsonrpc"');
  assert.ok(f.port.buffer.buffer.byteLength < 20000, "small residual does not pin the large consumed allocation");
  rest.fill(0x20);
  assert.equal(f.port.buffer.toString("utf8"), '{"jsonrpc"');
});

const peer = `
const readline = require('node:readline');
readline.createInterface({input:process.stdin}).on('line', line => {
  const req=JSON.parse(line), send=result=>process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:req.id,result})+'\\n');
  if(req.method==='initialize') return send({protocolVersion:'2026-07-28'});
  if(req.params.name==='hang') return;
  if(req.params.name==='partial') return process.stdout.write(Buffer.from('{"jsonrpc":"2.0","id":'+req.id+',"result":{"content":"'),()=>process.exit(0));
  const bytes=Buffer.from(JSON.stringify({jsonrpc:'2.0',id:req.id,result:{content:'A二🦉B'}})+'\\n');
  const cut=bytes.indexOf(Buffer.from('二'))+1;
  process.stdout.write(bytes.subarray(0,cut));setTimeout(()=>process.stdout.write(bytes.subarray(cut)),30);
});`;
async function closePeer(transport: StdioMcpTransport) {
  const child = (transport as unknown as { child?: ChildProcess }).child;
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const closed = once(child, "close", { signal: AbortSignal.timeout(2000) });
  await transport.stop(); await closed;
}

test("real stdio peer preserves split tool output and stays useful after request timeout", async () => {
  const transport = new StdioMcpTransport(process.execPath, ["-e", peer], { timeoutMs: 300, env: { PATH: "/usr/bin:/bin" } });
  try {
    await transport.start();
    assert.equal(await transport.callTool("read", {}), "A二🦉B");
    await assert.rejects(transport.callTool("hang", {}), /timed out/);
    assert.equal(await transport.callTool("read", {}), "A二🦉B");
  } finally { await closePeer(transport); }
});

test("stdio EOF does not turn a partial response into success", async () => {
  const transport = new StdioMcpTransport(process.execPath, ["-e", peer], { timeoutMs: 1000, env: { PATH: "/usr/bin:/bin" } });
  try {
    await transport.start();
    await assert.rejects(transport.callTool("partial", {}), /server closed/);
    assert.equal((transport as unknown as FramePort).pending.size, 0);
  } finally { await closePeer(transport); }
});
