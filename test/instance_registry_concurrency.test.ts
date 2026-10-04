import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, type ChildProcess } from "node:child_process";
import { registerInstance, deregisterInstance, listInstances, type RegistryEntry } from "../src/instance/registry.js";
import { withLogicalAppendLock } from "../src/spine/logical_append_lock.js";

const entry = (base: string, id: string, pid = process.pid): RegistryEntry =>
  ({ id, home: join(base, id), run: { kind: "unix-socket", socketPath: join(base, id, "keep.sock"), pid, startedAt: 1 } });
const pause = (ms: number) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

if (process.argv[2] === "--registry-worker") {
  const base = process.argv[3]!, action = process.argv[4]!, id = process.argv[5]!;
  const original = fs.readFileSync;
  // Stretch the actual read/modify window in each independent process. Under a transaction
  // lock these reads serialize; without it both succeed using the same stale snapshot.
  fs.readFileSync = ((...args: Parameters<typeof original>) => {
    try { return original(...args); }
    finally { if (args[0] === join(base, "registry.json")) pause(100); }
  }) as typeof original;
  process.on("message", message => {
    if (message !== "go") return;
    try {
      if (action === "hold") {
        withLogicalAppendLock(join(base, "registry.json"), () => { process.send?.({ type: "held" }); pause(Infinity); });
      } else if (action === "register") registerInstance(entry(base, id), base);
      else if (action === "remove") deregisterInstance(id, base);
      else if (action === "list") listInstances(base);
      else throw new Error("unknown fixture action");
      process.send?.({ type: "done", ok: true });
    } catch (error) { process.send?.({ type: "done", ok: false, code: (error as { code?: string }).code, message: String(error) }); }
  });
  process.send?.({ type: "ready" });
} else {
  type Message = { type: string; ok?: boolean; code?: string; message?: string };
  function message(child: ChildProcess, type: string): Promise<Message> {
    return new Promise((resolve, reject) => {
      const cleanup = () => { child.off("message", onMessage); child.off("exit", onExit); child.off("error", onError); clearTimeout(timer); };
      const onMessage = (value: unknown) => { const m = value as Message; if (m.type === type) { cleanup(); resolve(m); } };
      const onExit = () => { cleanup(); reject(new Error("fixture child exited early")); };
      const onError = (error: Error) => { cleanup(); reject(error); };
      const timer = setTimeout(() => { cleanup(); child.kill("SIGKILL"); reject(new Error("fixture deadline")); }, 12_000);
      child.on("message", onMessage); child.once("exit", onExit); child.once("error", onError);
    });
  }
  function worker(base: string, action: string, id: string) {
    const env = { ...process.env }; delete env["NODE_TEST_CONTEXT"];
    const child = spawn(process.execPath, [fileURLToPath(import.meta.url), "--registry-worker", base, action, id], { env, stdio: ["ignore", "ignore", "pipe", "ipc"] });
    child.stderr?.resume();
    const ready = message(child, "ready");
    const closed = new Promise<void>(resolve => child.once("close", () => resolve()));
    return { child, ready, closed };
  }
  async function stop(workers: ReturnType<typeof worker>[]) {
    for (const w of workers) if (w.child.exitCode === null && w.child.signalCode === null) w.child.kill("SIGKILL");
    await Promise.all(workers.map(w => w.closed));
  }
  async function race(base: string, actions: [string, string][], inspect: () => void) {
    const workers = actions.map(([action, id]) => worker(base, action, id));
    try {
      await Promise.all(workers.map(w => w.ready));
      const done = workers.map(w => message(w.child, "done"));
      for (const w of workers) w.child.send("go");
      for (const result of await Promise.all(done)) assert.equal(result.ok, true, result.message);
      inspect(); // All registrant children are still alive at the actual persisted-state oracle.
    } finally { await stop(workers); }
  }
  const fixture = () => fs.mkdtempSync(join(tmpdir(), "keep-registry-race-"));
  const ids = (base: string) => (JSON.parse(fs.readFileSync(join(base, "registry.json"), "utf8")) as RegistryEntry[]).map(e => e.id).sort();

  test("two successful independent live registrations both persist", { timeout: 15_000 }, async () => {
    const base = fixture();
    try {
      fs.writeFileSync(join(base, "registry.json"), JSON.stringify([entry(base, "owner")]));
      await race(base, [["register", "owner-project"], ["register", "organization-project"]], () =>
        assert.deepEqual(ids(base), ["organization-project", "owner", "owner-project"]));
    } finally { fs.rmSync(base, { recursive: true, force: true }); }
  });

  test("register races remove and prune without losing unrelated live entries", { timeout: 15_000 }, async () => {
    const base = fixture();
    try {
      fs.writeFileSync(join(base, "registry.json"), JSON.stringify([entry(base, "keep"), entry(base, "remove"), entry(base, "dead", 2 ** 22)]));
      await race(base, [["register", "fresh"], ["remove", "remove"], ["list", "unused"]], () => assert.deepEqual(ids(base), ["fresh", "keep"]));
    } finally { fs.rmSync(base, { recursive: true, force: true }); }
  });

  test("registry refuses a live lock owner then recovers its killed owned child", { timeout: 20_000 }, async () => {
    const base = fixture(), target = join(base, "registry.json"), holder = worker(base, "hold", "holder");
    const workers = [holder];
    try {
      fs.writeFileSync(target, JSON.stringify([entry(base, "keep")]));
      await holder.ready; const held = message(holder.child, "held"); holder.child.send("go"); await held;
      const ownerPath = `${target}.append-lock/owner-0`, before = fs.readFileSync(ownerPath);
      const contender = worker(base, "register", "contender"); workers.push(contender); await contender.ready;
      const done = message(contender.child, "done"); contender.child.send("go"); const result = await done;
      assert.equal(result.ok, false); assert.equal(result.code, "KEEP_LOGICAL_APPEND_BUSY");
      assert.ok(fs.readFileSync(ownerPath).equals(before)); assert.deepEqual(ids(base), ["keep"]);
      holder.child.kill("SIGKILL"); await holder.closed;
      registerInstance(entry(base, "recovered"), base);
      assert.deepEqual(ids(base), ["keep", "recovered"]);
      assert.equal(fs.existsSync(`${target}.append-lock/retired-0`), true);
      assert.equal(fs.existsSync(`${target}.append-lock/drained-0`), true);
      assert.ok(fs.readFileSync(ownerPath).equals(before), "recovery fences dead ownership rather than deleting it");
    } finally { await stop(workers); fs.rmSync(base, { recursive: true, force: true }); }
  });
}
