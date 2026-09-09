/**
 * BUILD-ORDER 1.3c (BIND-STRONG-TIER-BOUNDARY) — the STRONG-tier boundary proven against the SAME
 * default-path containment contract round 1.3 (BIND-DEFAULT-RESOURCE-NAMESPACE) established, one tier up.
 *
 * The `BoundaryExecutor` strong tier (gVisor `runsc`, else a HARDENED container runtime with
 * `--network none` + read-only rootfs + a single rw project bind + `--ulimit fsize`/`--pids-limit` +
 * `--cap-drop ALL`) runs the untrusted test PROCESS behind the SAME `IsolatedExecutor` port and is proven
 * to satisfy the EXACT contract: a child cannot write outside the project on the filesystem, cannot reach
 * the network, and is resource-bounded — asserted on REAL kernel/filesystem effects (bytes on the HOST
 * disk, an actual denied egress), never on logs.
 *
 * DETECT-AND-SELECT, honest: `detectContainerRuntime()` MEASURES what is present. In THIS environment
 * gVisor `runsc` is ABSENT (a VERIFIED-SEAM, proven by the contract-enforcing fake + the real absence
 * probe) but Docker is present — so (a)-(d) assert REAL container effects where the runtime is available,
 * and fall to the honest seam (plan flags + the pure containment contract) where it is not.
 *
 * Proven by DISPROOF: each real-effect assertion has a paired neuter of `planContainerRun` (the fs bind
 * scope / the fsize ulimit / `--network none`) or of the honesty/wiring point — RED bytes captured under
 * redrook-ops/.round-artifacts/BIND-STRONG-TIER-BOUNDARY/.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, existsSync, mkdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { spawnSync } from "node:child_process";

import {
  detectContainerRuntime, planContainerRun, buildContainerBoundaryRun, containmentDecision,
  buildContractEnforcingFakeBoundary, type ContainerRuntimeInfo,
} from "../src/infra/container_boundary.js";
import { selectExecutor, BoundaryExecutor, type ExecutionSpec } from "../src/isolation/isolated_executor.js";
import type { IsolationCapabilities } from "../src/isolation/isolation_tier.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";

const RT = detectContainerRuntime();
/** A real container run needs the daemon AND a small local image. busybox is the round's probe image. */
const BUSYBOX_PRESENT = (() => {
  try { const r = spawnSync("docker", ["image", "inspect", "busybox:latest"], { stdio: "ignore", timeout: 8000 }); return r.status === 0; }
  catch { return false; }
})();
const DOCKER_OK = RT.available && RT.tier === "container" && BUSYBOX_PRESENT;
const caps = (o: Partial<IsolationCapabilities>): IsolationCapabilities => ({ kvmAvailable: false, gvisorAvailable: false, containerRuntime: false, canScopeProcess: false, ...o });
const noopRunner: TestRunner = { async run(): Promise<TestRunResult> { return { results: [{ name: "t", passed: true }] }; } };

/** A fresh { root, proj }: proj is a child of root, so `root/escape` is OUTSIDE the project bind. */
function scratch(): { root: string; proj: string } {
  const root = mkdtempSync(join(tmpdir(), "keep-strongtier-"));
  const proj = join(root, "proj");
  mkdirSync(proj, { recursive: true });
  return { root, proj };
}
function execSpec(projectDir: string): ExecutionSpec { return { projectDir, repoRef: projectDir, patchRisk: "medium" }; }

// ── (a) filesystem jail — a write OUTSIDE the project is refused by the read-only rootfs / narrow bind ──
test("(a) STRONG TIER: an absolute-path write OUTSIDE the project does NOT land on the host (real bytes)", async () => {
  const { root, proj } = scratch();
  const outside = join(root, "escape-OUTSIDE.txt"); // sibling of proj → outside the single rw project bind
  if (DOCKER_OK) {
    const boundaryRun = buildContainerBoundaryRun(RT, {
      projectDir: proj, image: "busybox:latest", command: "sh",
      args: ["-c", `echo pwned > ${outside} 2>/dev/null; echo 'ok 1 - tried'`], timeoutMs: 30_000,
    });
    await boundaryRun(noopRunner, execSpec(proj));
    // REAL kernel/filesystem effect: the out-of-project write must NOT exist on the HOST filesystem.
    assert.equal(existsSync(outside), false, "the out-of-project write must NOT land on the host (contained by ro rootfs + narrow bind)");
  } else {
    // Honest seam (no container runtime here): the pure contract refuses the out-of-jail write, and the
    // plan encodes the confinement (read-only rootfs + only the project bound rw).
    const d = containmentDecision({ projectDir: proj }, { writePath: outside });
    assert.equal(d.allowed, false, "the containment contract refuses an out-of-project write");
    const plan = planContainerRun(RT.tier === "none" ? { kind: "docker", available: true, tier: "container", detail: "seam" } : RT, { projectDir: proj, image: "x", command: "sh", args: [] });
    assert.ok(plan.args.includes("--read-only"), "the plan encodes a read-only rootfs (fs-jail)");
    assert.ok(plan.args.includes(`${proj}:${proj}:rw`), "ONLY the project dir is bound read-write");
  }
});

// ── (b) no false containment — an in-project write + a passing test stays green ────────────────────────
test("(b) STRONG TIER: an in-project write + a normal passing test stay GREEN (no false containment)", async () => {
  const { proj } = scratch();
  if (DOCKER_OK) {
    const boundaryRun = buildContainerBoundaryRun(RT, {
      projectDir: proj, image: "busybox:latest", command: "sh",
      args: ["-c", "echo hi > ./in.txt && echo 'ok 1 - inproject write'"], timeoutMs: 30_000,
    });
    const r = await boundaryRun(noopRunner, execSpec(proj));
    assert.equal(r.runnerError, undefined, "a legitimate in-project run has no runner error");
    assert.ok(r.results.length > 0 && r.results.every((c) => c.passed), "the in-project run is green");
    assert.equal(existsSync(join(proj, "in.txt")), true, "the in-project write landed (the bind is genuinely rw)");
  } else {
    // Seam: the contract ALLOWS an in-project write (never a blanket refusal).
    const d = containmentDecision({ projectDir: proj }, { writePath: join(proj, "in.txt") });
    assert.equal(d.allowed, true, "an in-project write is within the contract (no false containment)");
  }
});

// ── (c) resource bound bites — RLIMIT_FSIZE (--ulimit fsize) caps an oversized write; never a green ────
test("(c) STRONG TIER: an oversized write is bounded by --ulimit fsize — capped, surfaced as failure, never green", async () => {
  const { proj } = scratch();
  const CAP = 64 * 1024;
  if (DOCKER_OK) {
    const big = join(proj, "big.bin");
    const boundaryRun = buildContainerBoundaryRun(RT, {
      projectDir: proj, image: "busybox:latest", command: "sh",
      // an oversized write → SIGXFSZ (File size limit exceeded) → non-zero pipeline exit (the failing write is
      // the LAST command, so its status is the run's); the bytes on disk are capped by RLIMIT_FSIZE.
      args: ["-c", `head -c 4000000 /dev/zero | tr '\\0' A > ${big}`], timeoutMs: 30_000,
      maxFileSizeBytes: CAP,
    });
    const r = await boundaryRun(noopRunner, execSpec(proj));
    const green = !r.runnerError && r.results.length > 0 && r.results.every((c) => c.passed);
    assert.equal(green, false, "an oversized write must NOT be reported as a passing run");
    if (existsSync(big)) assert.ok(statSync(big).size <= CAP * 2, `the file on disk is bounded by the rlimit (~${CAP}B), not 4 MiB`);
  } else {
    const plan = planContainerRun(RT.tier === "none" ? { kind: "docker", available: true, tier: "container", detail: "seam" } : RT, { projectDir: proj, image: "x", command: "sh", args: [], maxFileSizeBytes: CAP });
    assert.ok(plan.args.includes(`fsize=${CAP}`), "the RLIMIT_FSIZE (--ulimit fsize) must be wired into the plan");
    const d = containmentDecision({ projectDir: proj, maxFileSizeBytes: CAP }, { writePath: join(proj, "big.bin"), writeBytes: 4_000_000 });
    assert.equal(d.allowed, false, "the contract refuses a write beyond the fsize cap");
  }
});

// ── (d) network egress refused by --network none ──────────────────────────────────────────────────────
test("(d) STRONG TIER: network egress from the child is refused (--network none; real connect fails)", async () => {
  const { proj } = scratch();
  if (DOCKER_OK) {
    const boundaryRun = buildContainerBoundaryRun(RT, {
      projectDir: proj, image: "busybox:latest", command: "sh",
      args: ["-c", "wget -T 4 -q -O- http://1.1.1.1 >/dev/null 2>&1 && echo 'ok 1 - EGRESS_REACHED' || echo 'ok 1 - EGRESS_DENIED'"], timeoutMs: 30_000,
    });
    const r = await boundaryRun(noopRunner, execSpec(proj));
    const out = r.results.map((c) => c.name + " " + (c.output ?? "")).join(" ");
    assert.match(out, /EGRESS_DENIED/, `net-denied child must fail to connect; got: ${out.slice(0, 160)}`);
    assert.doesNotMatch(out, /EGRESS_REACHED/, "the child must NOT reach the network by default");
  } else {
    const plan = planContainerRun(RT.tier === "none" ? { kind: "docker", available: true, tier: "container", detail: "seam" } : RT, { projectDir: proj, image: "x", command: "sh", args: [] });
    assert.ok(plan.args.join(" ").includes("--network none"), "the plan denies the network by default");
    const d = containmentDecision({ projectDir: proj }, { connectOut: true });
    assert.equal(d.allowed, false, "the contract refuses egress by default");
  }
});

// ── (e) TIER-HONESTY — selectExecutor claims the strong tier ONLY when the runtime is really present ───
test("(e) TIER-HONESTY: selectExecutor does NOT claim the strong tier when the probe reports it ABSENT", () => {
  const absent: () => ContainerRuntimeInfo = () => ({ kind: "none", available: false, tier: "none", detail: "probed absent" });
  const present: () => ContainerRuntimeInfo = () => ({ kind: "docker", available: true, tier: "container", detail: "probed present" });
  const container = { image: "busybox:latest", command: "sh", args: [] as string[] };
  // Runtime ABSENT: caps CLAIM a container tier, but the probe is evidence — must fall to the process floor.
  const eAbsent = selectExecutor(caps({ containerRuntime: true }), { detectRuntime: absent, container });
  assert.equal(eAbsent.tier, "process", "a claim the probe does not back must NOT yield a container-tier executor");
  // Runtime PRESENT: the strong BoundaryExecutor engages.
  const ePresent = selectExecutor(caps({ containerRuntime: true }), { detectRuntime: present, container });
  assert.equal(ePresent.tier, "container", "a probe-backed runtime engages the strong tier");
  assert.ok(ePresent instanceof BoundaryExecutor, "the strong tier is the BoundaryExecutor (same port)");
});

test("(e2) TIER-HONESTY: an explicitly wired boundaryRun engages the strong tier (host wiring / VERIFIED-SEAM)", () => {
  const e = selectExecutor(caps({ gvisorAvailable: true }), { boundaryRun: async () => ({ results: [{ name: "t", passed: true }] }) });
  assert.equal(e.tier, "gvisor", "an explicitly wired boundary engages the declared strong tier");
});

// ── The pure containment CONTRACT — one source of truth (the seam/gVisor proof; the neuterable point) ──
test("CONTRACT: containmentDecision is the single source of truth (allows in-jail, refuses escape/egress/oversize)", () => {
  const proj = scratch().proj;
  assert.equal(containmentDecision({ projectDir: proj }, { writePath: join(proj, "ok.txt") }).allowed, true, "in-jail write allowed");
  assert.equal(containmentDecision({ projectDir: proj }, { writePath: join(dirname(proj), "escape.txt") }).allowed, false, "out-of-jail write refused");
  assert.equal(containmentDecision({ projectDir: proj }, { connectOut: true }).allowed, false, "egress refused by default");
  assert.equal(containmentDecision({ projectDir: proj, allowNet: true }, { connectOut: true }).allowed, true, "allowNet opt-in permits egress (additive)");
  assert.equal(containmentDecision({ projectDir: proj, maxFileSizeBytes: 1024 }, { writeBytes: 4096 }).allowed, false, "oversized write refused");
});

// ── gVisor VERIFIED-SEAM (runsc ABSENT here) — the contract-enforcing fake refuses out-of-jail effects ──
test("SEAM (gVisor): the contract-enforcing fake boundary refuses an out-of-jail write on REAL effects (runsc absent)", async () => {
  const { root, proj } = scratch();
  const outside = join(root, "escape-OUTSIDE.txt");
  const fake = buildContractEnforcingFakeBoundary({ projectDir: proj });
  let performed = false;
  const out = await fake({ effect: { writePath: outside }, perform: async () => { performed = true; return { results: [{ name: "x", passed: true }] }; } }, execSpec(proj));
  assert.equal(performed, false, "the disallowed write is refused BEFORE any byte lands (perform never runs)");
  assert.match(out.runnerError ?? "", /escapes the project jail|VERIFIED-SEAM/, "refused, labelled as a seam boundary");
  assert.equal(existsSync(outside), false, "the out-of-jail file genuinely never lands on the real filesystem");
  // The other half: an in-jail write is PERFORMED for real (no false containment).
  const inpath = join(proj, "ok.txt");
  const ok = await fake({ effect: { writePath: inpath }, perform: async () => ({ results: [{ name: "in", passed: true }] }) }, execSpec(proj));
  assert.ok(ok.results.length > 0 && ok.results.every((c) => c.passed), "an in-jail effect is allowed through");
});

// ── DISCONFIRMING CASE (gVisor partial syscalls): a boundary run that cannot COMPLETE is a runnerError, never green ──
test("DISCONFIRMING: a strong-tier run that cannot complete surfaces a runnerError, never a false green", async () => {
  const { proj } = scratch();
  // A runtime that does not exist stands in for a boundary that fails to run (e.g. a suite broken by
  // gVisor's partial syscall surface). It must degrade to a runnerError — never be reported as a pass.
  const brokenRt: ContainerRuntimeInfo = { kind: "docker", available: true, tier: "container", detail: "x" };
  const boundaryRun = buildContainerBoundaryRun(brokenRt, { projectDir: proj, image: "busybox:latest", command: "keep-nonexistent-runtime-xyz", args: ["run"], timeoutMs: 10_000 });
  const r = await boundaryRun(noopRunner, execSpec(proj));
  const green = !r.runnerError && r.results.length > 0 && r.results.every((c) => c.passed);
  assert.equal(green, false, "a boundary run that cannot complete is NEVER a false green (routes to a weaker-but-honest tier)");
});
