import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ProcessIsolationAdapter, resolvedWithinProject } from "../src/infra/process_isolation.js";

const adapter = new ProcessIsolationAdapter();
const dir = () => mkdtempSync(join(tmpdir(), "keep-sbx-"));

test("DEADLINE: a running finite-memory workload is terminated, without claiming a hard memory cap", async () => {
  // This adapter offers a deadline, not an RSS limit. Deliberately exhausting the
  // host or its outer cgroup tests that outer boundary and may kill the test runner.
  // Keep the workload allocation finite and prove it actually started before timeout.
  const r = await adapter.run(process.execPath, ["-e", "const a=Buffer.alloc(16*1024*1024,1); process.stdout.write('allocated:'+a.length+'\\n'); while(true){ a.fill(1); }"], {
    cwd: dir(), timeoutMs: 1_000,
  });
  assert.match(r.stdout, /allocated:16777216/u);
  assert.notEqual(r.code, 0);
  assert.equal(r.timedOut, true, "an unrelated OOM kill is not deadline enforcement evidence");
});

test("DEADLINE benign control: a finite-memory task completes with its output", async () => {
  const r = await adapter.run(process.execPath, ["-e", "const a=Buffer.alloc(16*1024*1024,7); process.stdout.write(String(a[0]+a[a.length-1]));"], {
    cwd: dir(), timeoutMs: 5_000,
  });
  assert.equal(r.code, 0, r.stderr);
  assert.equal(r.stdout, "14");
  assert.equal(r.timedOut, false);
});

test("CPU (adversarial): a CPU spinner is bounded by the CPU rlimit", async () => {
  const r = await adapter.run("node", ["-e", "while(true){ Math.sqrt(Math.random()); }"], {
    cwd: dir(), timeoutMs: 20_000, cpuLimitSec: 2,
  });
  assert.notEqual(r.code, 0, "the CPU spinner was terminated");
  assert.equal(r.timedOut, false, "terminated by the CPU rlimit, not the wall-clock timeout");
});

test("TIMEOUT (adversarial): a hang is killed at the wall-clock deadline (process-group kill)", async () => {
  const r = await adapter.run("node", ["-e", "setTimeout(()=>{}, 60000)"], { cwd: dir(), timeoutMs: 500 });
  assert.equal(r.timedOut, true, "the hang was killed at the deadline");
});

test("ENV SCRUB: a secret in the parent env does NOT reach the child (only the allowlist passes)", async () => {
  process.env["KEEP_TEST_SECRET"] = "topsecret";
  const r = await adapter.run("node", ["-e", "process.stdout.write(process.env.KEEP_TEST_SECRET ?? 'ABSENT')"], {
    cwd: dir(), timeoutMs: 5000, // no allowlist → secret scrubbed
  });
  delete process.env["KEEP_TEST_SECRET"];
  assert.equal(r.stdout.trim(), "ABSENT", "the secret was scrubbed from the child environment");
});

test("ARGV INJECTION: shell metacharacters in args are inert (no shell parses them)", async () => {
  const r = await adapter.run("node", ["-e", "process.stdout.write(process.argv[1] ?? '')", "; echo PWNED"], {
    cwd: dir(), timeoutMs: 5000, cpuLimitSec: 10, // through the ulimit wrapper — still argv-safe
  });
  assert.match(r.stdout, /; echo PWNED/, "the metacharacter string was passed as a literal arg");
  assert.doesNotMatch(r.stdout, /^PWNED/m, "no shell executed the injected command");
});

test("OUTPUT CAP: a stdout bomb is truncated (disk/memory-bomb mitigation)", async () => {
  const r = await adapter.run("node", ["-e", "const s='x'.repeat(1000); for(let i=0;i<100000;i++) process.stdout.write(s);"], {
    cwd: dir(), timeoutMs: 10_000, maxOutputBytes: 4096,
  });
  assert.equal(r.truncated, true, "output beyond the cap was truncated");
  assert.ok(r.stdout.length <= 8192, "captured output is bounded");
});

// ── realpath jail ──
test("REALPATH JAIL: a symlink escaping the project is REJECTED (defeats string-only checks)", () => {
  const base = dir();
  mkdirSync(join(base, "src"));
  writeFileSync(join(base, "src", "ok.ts"), "x");
  // a symlink inside the project that points OUT to /etc
  symlinkSync("/etc", join(base, "escape"));
  assert.equal(resolvedWithinProject(base, "src/ok.ts"), true, "a real in-project path is allowed");
  assert.equal(resolvedWithinProject(base, "escape/passwd"), false, "a symlink-out is rejected (realpath-resolved)");
  assert.equal(resolvedWithinProject(base, "../../etc/passwd"), false, "traversal is rejected");
  assert.equal(resolvedWithinProject(base, "src/new_file.ts"), true, "a not-yet-existing in-project write path is allowed");
});
