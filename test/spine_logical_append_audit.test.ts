import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { FileSpineStore } from "../src/spine/store.js";
import { NODE_IO, type DurableIO } from "../src/spine/durable_fs.js";
import { Spine } from "../src/spine/spine.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";

const fixture = () => fs.mkdtempSync(join(tmpdir(), "keep-logical-append-"));
const core = (store: FileSpineStore) => new Spine(store, new InProcessLock(), new SchemaRegistry(), () => 1234);
const input = (label: string, tenant?: string) => ({ type: "generic" as const, actor: tenant ? "alpha-agent" : "owner", payload: { label, data: "x".repeat(40000), ...(tenant ? { tenant } : {}) } });
function faultIO(target: string, afterShort: () => void): DurableIO {
  const paths = new Map<number, string>(); let step = 0;
  return {
    openSync(path, flags) { const fd = fs.openSync(path, flags); paths.set(fd, path); return fd; },
    writeSync(fd, buffer, offset, length) {
      if (basename(paths.get(fd) ?? "") === target && step === 0) {
        step++; const written = fs.writeSync(fd, buffer, offset, Math.min(17, length)); afterShort(); return written;
      }
      return fs.writeSync(fd, buffer, offset, length);
    },
    fsyncSync: fs.fsyncSync,
    closeSync(fd) { paths.delete(fd); fs.closeSync(fd); },
  };
}

if (process.argv[2] === "--append-worker") {
  const dir = process.argv[3]!, label = process.argv[4]!, mode = process.argv[5]!;
  const io = mode === "short" ? faultIO("staging.jsonl", () => {
    fs.writeFileSync(join(dir, `${label}.partial`), String(process.pid));
    const deadline = Date.now() + 10_000;
    while (!fs.existsSync(join(dir, `${label}.resume`))) {
      if (Date.now() > deadline) throw new Error("owned short-write barrier timeout");
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
    }
  }) : NODE_IO;
  const spine = core(new FileSpineStore(dir, { fsync: true, io }));
  fs.writeFileSync(join(dir, `${label}.started`), "ready");
  const id = spine.stage(input(label));
  fs.writeFileSync(join(dir, `${label}.done`), id);
  console.log(JSON.stringify({ id, label }));
} else if (process.argv[2] === "--append-read") {
  const spine = core(new FileSpineStore(process.argv[3]!, { fsync: true }));
  if (process.argv[4] === "seal") await spine.seal();
  console.log(JSON.stringify({ ok: spine.verify().ok, sealed: spine.replay().map(e => e.payload.label), pending: spine.pending().map(e => e.payload.label) }));
} else {
  const restart = (dir: string, seal = false) => {
    const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url), "--append-read", dir, seal ? "seal" : "read"], { encoding: "utf8", timeout: 15000, maxBuffer: 65536 });
    assert.equal(child.status, 0, child.stderr.slice(-2000) + child.stdout);
    return JSON.parse(child.stdout) as { ok: boolean; sealed: string[]; pending: string[] };
  };
  const worker = (dir: string, label: string, mode = "normal") => {
    const child = spawn(process.execPath, [fileURLToPath(import.meta.url), "--append-worker", dir, label, mode], { stdio: ["ignore", "pipe", "pipe"] });
    let output = "", error = "";
    child.stdout.on("data", (b: Buffer) => { output += b.toString(); }); child.stderr.on("data", (b: Buffer) => { error += b.toString(); });
    const timer = setTimeout(() => child.kill("SIGKILL"), 15_000);
    const done = new Promise<{ code: number | null; signal: string | null; output: string; error: string }>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => { clearTimeout(timer); resolve({ code, signal, output, error }); });
    });
    return { child, done };
  };
  const waitFile = async (path: string) => {
    const deadline = Date.now() + 5000;
    while (!fs.existsSync(path)) { if (Date.now() > deadline) throw new Error(`missing owned barrier ${path}`); await new Promise(r => setTimeout(r, 5)); }
  };

  for (const tenant of [undefined, "alpha"]) test(`KEEP-09A-002 failed stage tail recovers before later acknowledgment (${tenant ?? "personal"})`, async () => {
    const dir = fixture(); let fail = true;
    const io = faultIO("staging.jsonl", () => { if (fail) { fail = false; throw Object.assign(new Error("controlled EIO after17bytes"), { code: "EIO" }); } });
    const spine = core(new FileSpineStore(dir, { fsync: true, io }));
    assert.throws(() => spine.stage(input("failed", tenant)), /controlled EIO/);
    const torn = fs.readFileSync(join(dir, "staging.jsonl")); assert.equal(torn.length, 17);
    assert.deepEqual(spine.pending(), []); assert.deepEqual(fs.readFileSync(join(dir, "staging.jsonl")), torn, "reader must not truncate");
    spine.stage(input("later", tenant));
    const restored = restart(dir, true); assert.equal(restored.ok, true); assert.deepEqual(restored.sealed, ["later"]);
    const saved = fs.readdirSync(dir).filter(n => n.startsWith("staging.jsonl.torn-"));
    assert.equal(saved.length, 1); assert.deepEqual(fs.readFileSync(join(dir, saved[0]!)), torn);
  });

  test("partial block append cannot corrupt the next acknowledged seal or consume its pending records", async () => {
    const dir = fixture(), base = core(new FileSpineStore(dir, { fsync: true }));
    base.stage(input("first")); await base.seal(); base.stage(input("second"));
    const before = fs.readFileSync(join(dir, "chain.jsonl"));
    const spine = core(new FileSpineStore(dir, { fsync: true, io: faultIO("chain.jsonl", () => { throw new Error("controlled block EIO"); }) }));
    await assert.rejects(() => spine.seal(), /controlled block EIO/);
    assert.deepEqual(spine.pending().map(e => e.payload.label), ["second"]);
    const torn = fs.readFileSync(join(dir, "chain.jsonl")).subarray(before.length); assert.equal(torn.length, 17);
    const recovered = core(new FileSpineStore(dir, { fsync: true })); recovered.stage(input("third")); await recovered.seal();
    const restored = restart(dir); assert.equal(restored.ok, true); assert.deepEqual(restored.sealed, ["first", "second", "third"]); assert.deepEqual(restored.pending, []);
    assert.equal(fs.readFileSync(join(dir, "chain.jsonl")).subarray(0, before.length).equals(before), true);
  });

  for (const short of [false, true]) test(`paired writers preserve both acknowledged records (short=${short})`, async () => {
    const dir = fixture(), a = worker(dir, "a", short ? "short" : "normal");
    if (short) await waitFile(join(dir, "a.partial"));
    const b = worker(dir, "b");
    let readerFailure: unknown;
    try {
      if (short) {
        await waitFile(join(dir, "b.started"));
        await new Promise(r => setTimeout(r, 60));
        const before = fs.readFileSync(join(dir, "staging.jsonl"));
        try { core(new FileSpineStore(dir, { fsync: true })).pending(); } catch (error) { readerFailure = error; }
        assert.deepEqual(fs.readFileSync(join(dir, "staging.jsonl")), before);
        fs.writeFileSync(join(dir, "a.resume"), "continue");
      }
      const results = await Promise.all([a.done, b.done]); for (const result of results) assert.equal(result.code, 0, result.error);
      assert.equal(readerFailure, undefined, "the reader may not see an interleaved complete record even though both writers acknowledged");
      const restored = restart(dir, true); assert.equal(restored.ok, true); assert.deepEqual([...restored.sealed].sort(), ["a", "b"]);
    } finally { a.child.kill("SIGKILL"); b.child.kill("SIGKILL"); await Promise.all([a.done, b.done]); }
  });

  test("two recovery contenders drain after an actual child dies inside a partial append", async () => {
    const dir = fixture(), dead = worker(dir, "dead", "short");
    await waitFile(join(dir, "dead.partial"));
    const torn = fs.readFileSync(join(dir, "staging.jsonl"));
    dead.child.kill("SIGKILL"); assert.equal((await dead.done).signal, "SIGKILL");
    const b = worker(dir, "b"), c = worker(dir, "c");
    try {
      for (const result of await Promise.all([b.done, c.done])) assert.equal(result.code, 0, result.error);
      assert.deepEqual(restart(dir, true).sealed.sort(), ["b", "c"]);
      const saved = fs.readdirSync(dir).filter(n => n.startsWith("staging.jsonl.torn-"));
      assert.equal(saved.length, 1); assert.deepEqual(fs.readFileSync(join(dir, saved[0]!)), torn);
    } finally { b.child.kill("SIGKILL"); c.child.kill("SIGKILL"); await Promise.all([b.done, c.done]); }
  });

  test("exclusive seal preparation preserves a complete JSON tail whose newline is missing", async () => {
    const dir = fixture(), spine = core(new FileSpineStore(dir, { fsync: true }));
    const id = spine.stage(input("complete-tail"));
    const path = join(dir, "staging.jsonl"), bytes = fs.readFileSync(path);
    fs.writeFileSync(path, bytes.subarray(0, -1));
    assert.equal(spine.pending().length, 0, "ordinary readers do not publish an unframed write");
    assert.deepEqual(fs.readFileSync(path), bytes.subarray(0, -1));
    await spine.seal();
    assert.deepEqual(spine.replay().map(e => e.id), [id]); assert.deepEqual(fs.readFileSync(path), bytes);
    assert.deepEqual(restart(dir).sealed, ["complete-tail"]);
  });

  test("complete block without newline is repaired before deriving the next head or consuming staging", async () => {
    const dir = fixture(), store = new FileSpineStore(dir, { fsync: true }), spine = core(store);
    spine.stage(input("first")); await spine.seal();
    const path = join(dir, "chain.jsonl"), before = fs.readFileSync(path);
    fs.writeFileSync(path, before.subarray(0, -1)); fs.writeFileSync(join(dir, "staging.cursor"), "0\n");
    await spine.seal();
    assert.equal(fs.readFileSync(path).equals(before), true); assert.deepEqual(restart(dir).sealed, ["first"]);
    assert.deepEqual(spine.pending(), []);
  });

  test("malformed complete staging line is retained and prevents a later successful acknowledgment", () => {
    const dir = fixture(), spine = core(new FileSpineStore(dir, { fsync: true }));
    spine.stage(input("first")); fs.appendFileSync(join(dir, "staging.jsonl"), "{malformed}\n");
    const before = fs.readFileSync(join(dir, "staging.jsonl"));
    assert.throws(() => spine.stage(input("later")));
    assert.throws(() => spine.pending(), { code: "KEEP_SPINE_LOG_RECOVERY_REQUIRED" });
    assert.deepEqual(fs.readFileSync(join(dir, "staging.jsonl")), before);
  });

  test("an invalid complete chain cannot receive a new block or advance its staging cursor", async () => {
    const dir = fixture(), store = new FileSpineStore(dir, { fsync: true }), spine = core(store);
    spine.stage(input("first")); await spine.seal(); spine.stage(input("pending"));
    const path = join(dir, "chain.jsonl"), block = JSON.parse(fs.readFileSync(path, "utf8"));
    block.events[0].payload.label = "altered"; fs.writeFileSync(path, JSON.stringify(block) + "\n");
    const before = fs.readFileSync(path), cursor = fs.readFileSync(join(dir, "staging.cursor"));
    await assert.rejects(() => spine.seal());
    assert.deepEqual(fs.readFileSync(path), before); assert.deepEqual(fs.readFileSync(join(dir, "staging.cursor")), cursor);
  });

  test("unframed non-object JSON and invalid chain tails cannot be promoted as records", async () => {
    const dir = fixture(), spine = core(new FileSpineStore(dir, { fsync: true }));
    const path = join(dir, "staging.jsonl"); fs.writeFileSync(path, "12");
    await assert.rejects(() => spine.seal(), /invalid staged record/);
    assert.equal(fs.readFileSync(path, "utf8"), "12");
    fs.writeFileSync(path, ""); spine.stage(input("first")); await spine.seal();
    const chain = join(dir, "chain.jsonl"), before = fs.readFileSync(chain);
    // A duplicate genesis block is valid JSON but does not link to the head.
    fs.appendFileSync(chain, before.subarray(0, -1));
    const invalid = fs.readFileSync(chain);
    await assert.rejects(() => spine.seal(), /invalid chain record/);
    assert.equal(fs.readFileSync(chain).equals(invalid), true);
  });

  test("same staged identity retries after complete unframed write without duplication", async () => {
    const dir = fixture(), store = new FileSpineStore(dir, { fsync: true }), spine = core(store);
    spine.stage(input("first")); const event = store.readStaged()[0]!;
    const path = join(dir, "staging.jsonl"), bytes = fs.readFileSync(path);
    fs.writeFileSync(path, bytes.subarray(0, -1));
    store.appendStaged(event); store.appendStaged(event);
    assert.equal(fs.readFileSync(path).equals(bytes), true);
    assert.throws(() => store.appendStaged({ ...event, actor: "changed" }), /different content/);
    await spine.seal(); const block = store.lastBlock()!, chain = join(dir, "chain.jsonl"), original = fs.readFileSync(chain);
    fs.writeFileSync(chain, original.subarray(0, -1)); store.appendBlock(block); store.appendBlock(block);
    assert.equal(fs.readFileSync(chain).equals(original), true);
    assert.deepEqual(restart(dir).sealed, ["first"]);
  });

  test("failed quarantine write preserves original bytes and a later recovery remains usable", async () => {
    const dir = fixture(), base = new FileSpineStore(dir, { fsync: true });
    const path = join(dir, "staging.jsonl"), torn = Buffer.from('{"id":"incomplete'); fs.writeFileSync(path, torn);
    const paths = new Map<number, string>();
    const io: DurableIO = {
      openSync(p, flags) { const fd = fs.openSync(p, flags); paths.set(fd, p); return fd; },
      writeSync(fd, bytes, offset, length) {
        if (paths.get(fd)?.includes(".recovery-")) { fs.writeSync(fd, bytes, offset, 3); throw new Error("controlled recovery EIO"); }
        return fs.writeSync(fd, bytes, offset, length);
      },
      fsyncSync: fs.fsyncSync,
      closeSync(fd) { paths.delete(fd); fs.closeSync(fd); },
    };
    assert.throws(() => core(new FileSpineStore(dir, { fsync: true, io })).stage(input("failed")), /controlled recovery EIO/);
    assert.equal(fs.readFileSync(path).equals(torn), true);
    assert.equal(fs.readdirSync(dir).filter(n => n.startsWith("staging.jsonl.torn-")).length, 0);
    const resumed = core(base); resumed.stage(input("later")); await resumed.seal();
    assert.deepEqual(restart(dir).sealed, ["later"]);
    const saved = fs.readdirSync(dir).find(n => n.startsWith("staging.jsonl.torn-"))!;
    assert.equal(fs.readFileSync(join(dir, saved)).equals(torn), true);
    assert.equal(fs.statSync(join(dir, saved)).mode & 0o077, 0);
  });

  test("short cursor-temp write leaves the old cursor and reconstructs the committed block exactly once", async () => {
    const dir = fixture(), paths = new Map<number, string>();
    const io: DurableIO = {
      openSync(p, flags) { const fd = fs.openSync(p, flags); paths.set(fd, p); return fd; },
      writeSync(fd, bytes, offset, length) {
        if (paths.get(fd)?.includes("staging.cursor.tmp-")) { fs.writeSync(fd, bytes, offset, 1); throw new Error("controlled cursor EIO"); }
        return fs.writeSync(fd, bytes, offset, length);
      },
      fsyncSync: fs.fsyncSync,
      closeSync(fd) { paths.delete(fd); fs.closeSync(fd); },
    };
    const spine = core(new FileSpineStore(dir, { fsync: true, io })); spine.stage(input("committed"));
    await assert.rejects(() => spine.seal(), /controlled cursor EIO/);
    assert.equal(fs.readFileSync(join(dir, "staging.cursor"), "utf8"), "0\n");
    const chain = fs.readFileSync(join(dir, "chain.jsonl")); assert.ok(chain.length > 0);
    assert.deepEqual(restart(dir, true), { ok: true, sealed: ["committed"], pending: [] });
    assert.equal(fs.readFileSync(join(dir, "chain.jsonl")).equals(chain), true);
    assert.equal(fs.readFileSync(join(dir, "staging.cursor"), "utf8"), "1\n");
  });
}
