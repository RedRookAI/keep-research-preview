/**
 * BUILD-ORDER 1.3 (BIND-DEFAULT-RESOURCE-NAMESPACE) — the DEFAULT execution path bounds the untrusted test PROCESS
 * with REAL kernel controls: a mount+net+PID namespace jail (`unshare`) + rlimits. Proven by DISPROOF, asserted on
 * real kernel/filesystem effects (bytes on disk, an actual connect() errno) — never on logs.
 *
 * With NO configuration, a `SandboxedCommandRunner` child:
 *   (a) cannot write an absolute path OUTSIDE the project (refused by the read-only mount namespace — the file is
 *       never created on the real filesystem),
 *   (b) can still write IN-project and pass a normal test (no false containment),
 *   (c) is bounded by an rlimit (RLIMIT_FSIZE) — an oversized write is capped / surfaced as a failure, never a green,
 *   (d) cannot reach the network (the net namespace has no route — connect() fails).
 * Plus a WIRING assertion (ledger 298): the DEFAULT runner SELECTS the bounded spawn plan.
 *
 * HONEST SEAM: where the kernel does not grant a namespace (no unprivileged userns; `unprivileged_userns_clone=0`;
 * an AppArmor userns restriction — puppeteer#12818 / edera 2026), the real-effect assertions are SKIPPED and the
 * test instead asserts the HONEST degraded label (`planNamespaceSpawn` reports `["mount-ns", ...]`). It never claims
 * a namespace that did not apply.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, existsSync, mkdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SandboxedCommandRunner } from "../src/solve/sandboxed_runner.js";
import { ProcessIsolationAdapter, type IsolationPolicy, type IsolatedRunResult } from "../src/infra/process_isolation.js";
import { detectNamespaceSupport, planNamespaceSpawn, type NamespaceSupport } from "../src/infra/isolation_backend.js";

const SUP = detectNamespaceSupport();

/** A fresh { root, proj } where proj is a child of root (so `root/escape` is OUTSIDE the project). */
function scratch(): { root: string; proj: string } {
  const root = mkdtempSync(join(tmpdir(), "keep-nsjail-"));
  const proj = join(root, "proj");
  mkdirSync(proj, { recursive: true });
  return { root, proj };
}

// ── (a) filesystem jail — the mount namespace refuses an absolute-path write OUTSIDE the project ──────────────
test("(a) DEFAULT: an absolute-path write OUTSIDE the project is refused by the mount namespace (asserted on bytes)", async () => {
  const { root, proj } = scratch();
  const outside = join(root, "escape-OUTSIDE.txt"); // sibling of proj → outside the jail island
  const runner = new SandboxedCommandRunner({
    command: "node",
    args: ["-e", `require('fs').writeFileSync(${JSON.stringify(outside)}, 'pwned')`],
    projectDir: proj, timeoutMs: 20_000,
  });
  await runner.run(".");
  if (SUP.mountNs) {
    // Real kernel effect: the file must not exist on the host filesystem.
    assert.equal(existsSync(outside), false, "the out-of-project write must NOT land on the real filesystem");
  } else {
    // Honest seam: no mount namespace here → the plan declares it degraded rather than falsely claiming the jail.
    const plan = planNamespaceSpawn("node", [], undefined, { projectDir: proj, support: SUP });
    assert.ok(plan.degraded.includes("mount-ns"), "no mount ns → must be labelled degraded, not silently unenforced");
  }
});

// ── (b) no false containment — an in-project write + a passing test stay green ────────────────────────────────
test("(b) DEFAULT: an in-project write + a normal passing test stay GREEN (jail is not a blanket refusal)", async () => {
  const { proj } = scratch();
  const runner = new SandboxedCommandRunner({
    command: "node",
    // write a file INSIDE the project, then a passing assertion — exit 0.
    args: ["-e", `const fs=require('fs');fs.writeFileSync('in.txt','ok');process.stdout.write('ok 1 - inproject write\\n')`],
    projectDir: proj, timeoutMs: 20_000,
  });
  const r = await runner.run(".");
  assert.equal(r.runnerError, undefined, "a legitimate in-project run has no runner error");
  assert.ok(r.results.length > 0 && r.results.every((c) => c.passed), "the in-project run is green");
  if (SUP.mountNs) assert.equal(existsSync(join(proj, "in.txt")), true, "the in-project write landed");
});

// ── (c) resource bound bites — RLIMIT_FSIZE caps an oversized write; never a green ────────────────────────────
test("(c) DEFAULT: an oversized write is bounded by RLIMIT_FSIZE — capped on disk, surfaced as a failure, never green", async () => {
  const { proj } = scratch();
  const CAP = 64 * 1024; // 64 KiB fsize cap
  const big = join(proj, "big.bin");
  const runner = new SandboxedCommandRunner({
    command: "node",
    // uncaught oversized write → EFBIG throws → non-zero exit (never a green); the bytes on disk are capped.
    args: ["-e", `require('fs').writeFileSync(${JSON.stringify(big)}, Buffer.alloc(4*1024*1024).fill(65))`],
    projectDir: proj, timeoutMs: 20_000, maxFileSizeBytes: CAP,
  });
  const r = await runner.run(".");
  if (SUP.mountNs || SUP.userNs) {
    // Never a green: the bomb did not complete cleanly.
    const green = !r.runnerError && r.results.length > 0 && r.results.every((c) => c.passed);
    assert.equal(green, false, "an oversized write must NOT be reported as a passing run");
    if (existsSync(big)) {
      const sz = statSync(big).size;
      assert.ok(sz <= CAP * 2, `the file on disk (${sz}B) is bounded by the rlimit (~${CAP}B), not the requested 4 MiB`);
    }
  } else {
    const plan = planNamespaceSpawn("node", [], undefined, { projectDir: proj, maxFileSizeBytes: CAP, support: SUP });
    // rlimits ride the same bash wrapper even without namespaces — the fsize arg is present, not dropped.
    assert.ok(plan.args.includes(String(Math.ceil(CAP / 1024))), "the RLIMIT_FSIZE (blocks) must be wired into the plan");
  }
});

// ── (d) network egress refused by the net namespace ───────────────────────────────────────────────────────────
test("(d) DEFAULT: network egress from the child is refused by the net namespace (connect fails)", async () => {
  const { proj } = scratch();
  const runner = new SandboxedCommandRunner({
    command: "node",
    // Distinctive tokens NOT present in the source echoed back as the case name, so we assert on child OUTPUT only.
    args: ["-e", `const s=require('net').connect(80,'1.1.1.1');s.setTimeout(4000);s.on('connect',()=>{console.log('EGRESS_REACHED');process.exit(0)});s.on('timeout',()=>{console.log('EGRESS_TIMEOUT');process.exit(2)});s.on('error',e=>{console.log('EGRESS_DENIED_'+e.code);process.exit(3)})`],
    projectDir: proj, timeoutMs: 20_000,
  });
  const r = await runner.run(".");
  // Build the observed string from child OUTPUT only (not the case NAME, which echoes the command source).
  const out = r.results.map((c) => c.output ?? "").join(" ") + (r.runnerError ?? "");
  if (SUP.netNs) {
    assert.match(out, /EGRESS_DENIED|ENETUNREACH|EHOSTUNREACH/, `net-denied child must fail to connect; got: ${out.slice(0, 160)}`);
    assert.doesNotMatch(out, /EGRESS_REACHED/, "the child must NOT reach the network by default");
  } else {
    const plan = planNamespaceSpawn("node", [], undefined, { projectDir: proj, support: SUP });
    assert.ok(plan.degraded.includes("net-ns"), "no net ns → labelled degraded, not a false network-deny claim");
  }
});

// ── WIRING (ledger 298): the DEFAULT runner selects the bounded spawn plan ─────────────────────────────────────
test("WIRING: with NO configuration the SandboxedCommandRunner binds the namespace jail (net-denied, project-jailed)", async () => {
  const { proj } = scratch();
  let captured: IsolationPolicy | undefined;
  // A recording adapter: capture the policy the DEFAULT runner builds, without spawning.
  const spy = new ProcessIsolationAdapter();
  (spy as unknown as { run: (c: string, a: readonly string[], p: IsolationPolicy) => Promise<IsolatedRunResult> }).run =
    async (_c, _a, p) => { captured = p; return { code: 0, signal: null, stdout: "ok 1 - x\n", stderr: "", timedOut: false, truncated: false, durationMs: 1 }; };
  const runner = new SandboxedCommandRunner({ command: "node", args: ["--test"], projectDir: proj, adapter: spy });
  await runner.run(".");
  // The wiring: neutering it (sandboxed_runner drops `namespaceJail` from the policy) makes this undefined → RED.
  assert.ok(captured?.namespaceJail, "the DEFAULT policy must carry a namespaceJail spec");
  assert.equal(captured?.namespaceJail?.projectDir, proj, "the jail is scoped to the project dir");
  assert.equal(captured?.namespaceJail?.allowNet, undefined, "network is DENIED by default (allowNet unset)");
});

// ── opt-IN allowance is additive, never a weakened default ────────────────────────────────────────────────────
test("ALLOWANCE (opt-in): allowNet skips the net namespace; the hard default stays net-denied", () => {
  const proj = scratch().proj;
  const denied = planNamespaceSpawn("node", ["--test"], undefined, { projectDir: proj, support: { userNs: true, mountNs: true, netNs: true, pidNs: true } });
  const allowed = planNamespaceSpawn("node", ["--test"], undefined, { projectDir: proj, allowNet: true, support: { userNs: true, mountNs: true, netNs: true, pidNs: true } });
  assert.ok(denied.args.includes("--net"), "default: the net namespace is applied (network denied)");
  assert.ok(!allowed.args.includes("--net"), "operator opt-in: allowNet drops the net namespace (additive allowance)");
  // A declared write path is re-opened read-write (opt-in), passed through the plan.
  const withWrite = planNamespaceSpawn("node", [], undefined, { projectDir: proj, allowWritePaths: ["/srv/cache"], support: { userNs: true, mountNs: true, netNs: true, pidNs: true } });
  assert.ok(withWrite.args.includes("/srv/cache"), "an operator-declared writable path is wired into the jail");
});

// ── HONEST DEGRADE: a host without unprivileged userns gets rlimits, and every namespace labelled degraded ────
test("HONEST SEAM: no user namespace → rlimit-only plan, every namespace declared degraded (never a false claim)", () => {
  const none: NamespaceSupport = { userNs: false, mountNs: false, netNs: false, pidNs: false };
  const plan = planNamespaceSpawn("node", ["--test"], 5, { projectDir: "/x", maxFileSizeBytes: 65536, support: none });
  assert.equal(plan.cmd, "/usr/bin/bash", "no userns → falls back to the rlimit-only bash wrapper, not unshare");
  assert.ok(!plan.args.includes("--mount") && !plan.args.includes("--net"), "no namespace flags are claimed");
  for (const ns of ["mount-ns", "net-ns", "pid-ns"]) assert.ok(plan.degraded.includes(ns), `${ns} must be declared degraded`);
});
