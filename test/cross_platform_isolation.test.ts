import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { hostIsolationRoute, selectPlatformIsolation } from "../src/infra/isolation_backend.js";
import { ProcessIsolationAdapter } from "../src/infra/process_isolation.js";

test("SELECTION: win32 → Windows backend, everything else → POSIX", () => {
  assert.equal(selectPlatformIsolation("win32").platform, "win32");
  assert.equal(selectPlatformIsolation("linux").platform, "posix");
  assert.equal(selectPlatformIsolation("darwin").platform, "posix", "macOS is POSIX");
  assert.equal(selectPlatformIsolation("freebsd").platform, "posix");
});

test("MATRIX: Linux, macOS, Job Object, WSL2, and unsupported Windows have distinct honest routes", () => {
  assert.equal(hostIsolationRoute("linux"), "linux-namespaces");
  assert.equal(hostIsolationRoute("darwin"), "macos-posix");
  assert.equal(hostIsolationRoute("win32", { jobObject: true, wsl2: true }), "windows-job-object");
  assert.equal(hostIsolationRoute("win32", { wsl2: true }), "windows-wsl2");
  assert.equal(hostIsolationRoute("win32"), "windows-degraded");
});

test("CAPABILITY HONESTY: Windows declares cpuLimit UNavailable (no Job Objects zero-dep); POSIX declares it available", () => {
  const win = new ProcessIsolationAdapter(() => 0, "win32");
  const posix = new ProcessIsolationAdapter(() => 0, "linux");
  // The controls Windows CAN enforce are all true...
  for (const k of ["confinedCwd", "scrubbedEnv", "wallClockKill", "processTreeKill", "outputCap", "realpathJail"] as const) {
    assert.equal(win.capabilities[k], true, `windows enforces ${k}`);
  }
  // ...but a hard CPU rlimit is honestly NOT available on Windows zero-dep.
  assert.equal(win.capabilities.cpuLimit, false, "windows cannot hard-cap CPU without a native addon — declared false");
  assert.equal(posix.capabilities.cpuLimit, true, "POSIX enforces a CPU rlimit via ulimit -t");
});

test("NO SILENT UNDER-ENFORCEMENT: a CPU limit requested on Windows is planned as DEGRADED, not silently ignored", () => {
  const win = selectPlatformIsolation("win32");
  const plan = win.planSpawn("node", ["--test"], 5);
  assert.deepEqual(plan.degraded, ["cpuLimit"], "the unenforceable control is surfaced as degraded");
  assert.equal(plan.cmd, "node", "Windows spawns the command directly (no bash/ulimit wrapper)");
  assert.equal(plan.detached, false, "Windows does not use POSIX process groups");
});

test("POSIX plan: a CPU limit uses the ulimit wrapper with argv-safe passing; no degradation", () => {
  const posix = selectPlatformIsolation("linux");
  const plan = posix.planSpawn("node", ["--test"], 3);
  assert.equal(plan.cmd, "/usr/bin/bash");
  assert.ok(plan.args.includes("node") && plan.args.includes("--test"), "command+args passed as positional argv");
  assert.equal(plan.degraded.length, 0, "POSIX enforces the CPU limit — nothing degraded");
  assert.equal(plan.detached, true);
});

test("POSIX minimal env vs Windows minimal env (a resolvable PATH on each platform)", () => {
  assert.match(selectPlatformIsolation("linux").minimalEnv()["PATH"]!, /\/usr\/bin/);
  const winEnv = selectPlatformIsolation("win32").minimalEnv();
  assert.match(winEnv["PATH"]!, /System32/i, "Windows PATH includes System32 (so node + taskkill resolve)");
  assert.ok(winEnv["SystemRoot"], "Windows env carries SystemRoot");
});

test("REAL POSIX enforcement still works through the refactored adapter (host platform)", async () => {
  const adapter = new ProcessIsolationAdapter(); // host = linux here
  const dir = mkdtempSync(join(tmpdir(), "keep-xplat-"));
  const r = await adapter.run("node", ["-e", "process.stdout.write('ok')"], { cwd: dir, timeoutMs: 5000 });
  assert.equal(r.stdout, "ok");
  assert.equal(r.degraded, undefined, "no degradation on POSIX");
});
