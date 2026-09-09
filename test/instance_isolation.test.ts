import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, existsSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { bindListener, defaultBindFor } from "../src/instance/bind_strategy.js";
import { acquireInstanceHome, isInstanceRunning } from "../src/instance/instance_home.js";
import { writeRunfile, readRunfile, registerInstance, deregisterInstance, listInstances, mintInstanceId } from "../src/instance/registry.js";

function tmpBase(): string {
  return mkdtempSync(join(tmpdir(), "keep-inst-"));
}

// --- Bind strategy: never squat a fixed port ---

test("ephemeral-loopback binds a real dynamic port on a live server (no squatting)", async () => {
  const b = await bindListener({ kind: "ephemeral-loopback" });
  assert.equal(b.kind, "ephemeral-loopback");
  assert.ok(typeof b.port === "number" && b.port > 0);
  assert.equal(b.host, "127.0.0.1");
  await b.close();
});

test("two ephemeral binds get DIFFERENT ports (the anti-collision property)", async () => {
  const a = await bindListener({ kind: "ephemeral-loopback" });
  const b = await bindListener({ kind: "ephemeral-loopback" });
  assert.notEqual(a.port, b.port);
  await a.close();
  await b.close();
});

test("a unix socket binds with NO TCP port", async () => {
  const dir = tmpBase();
  const socketPath = join(dir, "keep.sock");
  const b = await bindListener({ kind: "unix-socket", socketPath });
  assert.equal(b.kind, "unix-socket");
  assert.equal(b.port, undefined); // no port at all
  assert.ok(existsSync(socketPath));
  await b.close();
});

test("fixed binds the requested port when the operator opts in", async () => {
  // Ask the OS for a free port first, then bind it explicitly as 'fixed'.
  const probe = await bindListener({ kind: "ephemeral-loopback" });
  const port = probe.port!;
  await probe.close();
  const b = await bindListener({ kind: "fixed", fixedPort: port });
  assert.equal(b.port, port);
  await b.close();
});

test("defaultBindFor prefers a unix socket under the instance home", () => {
  const req = defaultBindFor("/home/x/.keep/instances/proj-abc");
  assert.equal(req.kind, "unix-socket");
  assert.ok(req.socketPath!.includes("proj-abc"));
});

// --- Instance home + ownership lock ---

test("acquire creates the home and writes a PID ownership lock", () => {
  const base = tmpBase();
  const home = acquireInstanceHome("proj-1", base);
  assert.ok(existsSync(home.stateDir));
  assert.ok(existsSync(home.lockPath));
  const lock = JSON.parse(readFileSync(home.lockPath, "utf8"));
  assert.equal(lock.pid, process.pid);
  home.release();
});

test("a second boot on an already-held home refuses with a clear message (the double-boot guard)", () => {
  const base = tmpBase();
  const home = acquireInstanceHome("proj-2", base);
  // Re-acquiring the same home (as a real double-boot would attempt) must refuse.
  assert.throws(() => acquireInstanceHome("proj-2", base), /already running/i);
  home.release();
});

test("after release, the home can be legitimately re-acquired", () => {
  const base = tmpBase();
  const h1 = acquireInstanceHome("proj-2b", base);
  h1.release();
  const h2 = acquireInstanceHome("proj-2b", base); // now allowed
  assert.equal(h2.id, "proj-2b");
  h2.release();
});

test("a stale lock (dead PID) is reclaimed", () => {
  const base = tmpBase();
  const home = acquireInstanceHome("proj-3", base);
  home.release(); // simulate the prior process exiting (clears in-process hold)
  // A crashed prior owner leaves a lock with a now-dead PID behind.
  const deadPid = 2 ** 22; // absurdly high, not a running process
  writeFileSync(home.lockPath, JSON.stringify({ pid: deadPid, startedAt: Date.now(), instanceId: "proj-3" }));
  // A fresh process reacquiring should succeed (reclaim the stale lock), not throw.
  const reclaimed = acquireInstanceHome("proj-3", base);
  assert.equal(reclaimed.id, "proj-3");
  reclaimed.release();
});

test("isInstanceRunning reflects live ownership", () => {
  const base = tmpBase();
  const home = acquireInstanceHome("proj-4", base);
  assert.equal(isInstanceRunning("proj-4", base), true); // we (a live pid) own it
  home.release();
  assert.equal(isInstanceRunning("proj-4", base), false); // lock gone
});

// --- Registry + runfile: discovery ---

test("runfile round-trips the bind info for discovery", async () => {
  const base = tmpBase();
  const home = acquireInstanceHome("proj-5", base);
  const b = await bindListener({ kind: "ephemeral-loopback" });
  const run = writeRunfile(home.root, b);
  const read = readRunfile(home.root);
  assert.equal(read!.port, run.port);
  assert.equal(read!.kind, "ephemeral-loopback");
  await b.close();
  home.release();
});

test("registry tracks instances and prunes dead ones", () => {
  const base = tmpBase();
  registerInstance({ id: "live-1", home: "/h/live-1", projectName: "A", run: { kind: "unix-socket", socketPath: "/h/live-1/keep.sock", pid: process.pid, startedAt: Date.now() } }, base);
  registerInstance({ id: "dead-1", home: "/h/dead-1", projectName: "B", run: { kind: "ephemeral-loopback", port: 5000, pid: 2 ** 22, startedAt: Date.now() } }, base);
  const live = listInstances(base);
  assert.ok(live.some((e) => e.id === "live-1"));
  assert.ok(!live.some((e) => e.id === "dead-1")); // dead pruned
});

test("deregister removes an instance from the catalog", () => {
  const base = tmpBase();
  registerInstance({ id: "gone", home: "/h/gone", run: { kind: "unix-socket", socketPath: "/h/gone/keep.sock", pid: process.pid, startedAt: Date.now() } }, base);
  deregisterInstance("gone", base);
  assert.ok(!listInstances(base).some((e) => e.id === "gone"));
});

test("mintInstanceId yields unique, slugged ids", () => {
  const a = mintInstanceId("My Bakery Site");
  const b = mintInstanceId("My Bakery Site");
  assert.ok(a.startsWith("my-bakery-site-"));
  assert.notEqual(a, b); // random suffix
});
