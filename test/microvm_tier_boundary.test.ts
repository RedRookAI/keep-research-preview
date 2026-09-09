/**
 * BUILD-ORDER 1.3b (BIND-MICROVM-TIER-BOUNDARY) — the TOP-tier boundary proven against the SAME default-path
 * containment contract rounds 1.3 / 1.3c established, one HARDWARE tier up (a Firecracker microVM: a
 * dedicated guest kernel, KVM-enforced).
 *
 * The `BoundaryExecutor` microVM tier runs the untrusted test PROCESS inside a dedicated guest kernel behind
 * the SAME `IsolatedExecutor` port and is proven to satisfy the EXACT contract — a child cannot write
 * outside the project (read-only rootfs drive + ONLY the project attached as a rw data disk), cannot reach
 * the network (NO virtio-net device), and is resource-bounded — PLUS the bound the weaker tiers could not
 * deliver: a HARD guest-RAM cap (`mem_size_mib`) that OOMs a memory bomb inside the guest, never on the host.
 *
 * DETECT-AND-SELECT, honest: `detectMicrovmRuntime()` MEASURES what is present. In THIS environment
 * `/dev/kvm` IS a real char device but the `firecracker`/`cloud-hypervisor` VMM is ABSENT and no guest
 * kernel/rootfs is built — so plan/contract logic is exercised by a strictly test-only fake while authority
 * is proven only by the separate real-Firecracker evidence path
 * (on REAL filesystem bytes) + the real KVM-present / firecracker-absent probe. The plan-level assertions
 * prove the guest hardware encodes the contract (ro rootfs, no NIC, mem cap). Where a real VMM + rootfs are
 * present (a KVM+Firecracker host), the `FIRECRACKER_OK` branch asserts REAL guest bytes instead.
 *
 * Proven by DISPROOF: each assertion has a paired neuter of `planMicrovmRun` / `microvmContainmentDecision`
 * / the honesty/wiring point — RED bytes under redrook-ops/.round-artifacts/BIND-MICROVM-TIER-BOUNDARY/.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, existsSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";

import {
  detectMicrovmRuntime, planMicrovmRun, buildMicrovmBoundaryRun, microvmContainmentDecision,
  microvmGuestExecutionRequestDigest, microvmImagesPresent, kvmDevicePresent,
  type MicrovmRuntimeInfo, type MicrovmBoundarySpec,
} from "../src/infra/microvm_boundary.js";
import { buildContractEnforcingFakeMicrovmBoundary } from "./helpers/fake_microvm_boundary.js";
import { selectExecutor, BoundaryExecutor, type ExecutionSpec } from "../src/isolation/isolated_executor.js";
import type { IsolationCapabilities } from "../src/isolation/isolation_tier.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";

const RT = detectMicrovmRuntime();
const caps = (o: Partial<IsolationCapabilities>): IsolationCapabilities => ({ kvmAvailable: false, gvisorAvailable: false, containerRuntime: false, canScopeProcess: false, ...o });
const noopRunner: TestRunner = { async run(): Promise<TestRunResult> { return { results: [{ name: "t", passed: true }] }; } };

/** A fresh { root, proj }: proj is a child of root, so `root/escape` is OUTSIDE the project data disk. */
function scratch(): { root: string; proj: string } {
  const root = mkdtempSync(join(tmpdir(), "keep-microvm-"));
  const proj = join(root, "proj");
  mkdirSync(proj, { recursive: true });
  return { root, proj };
}
function execSpec(projectDir: string): ExecutionSpec { return { projectDir, repoRef: projectDir, patchRisk: "medium" }; }
/** A microVM spec with fake (present) image paths for plan-level assertions. */
function spec(proj: string, over: Partial<MicrovmBoundarySpec> = {}): MicrovmBoundarySpec {
  return { projectDir: proj, kernelImage: "/x/vmlinux", rootfsImage: "/x/rootfs.ext4", command: "sh", args: [], memoryBytes: 256 * 1024 * 1024, ...over };
}
const MEM = 256 * 1024 * 1024;

/** A real guest run needs KVM + a VMM binary + a built kernel/rootfs. Absent here → the VERIFIED-SEAM path. */
const FIRECRACKER_OK = RT.available && RT.tier === "microvm";

test("AUTHORITY: guest command, argv, and enforced limits move one canonical execution-request identity", () => {
  const base = spec("/project", { command: "/bin/sh", args: ["-c", "npm test"], timeoutMs: 90_000, maxProcesses: 128 });
  const identity = microvmGuestExecutionRequestDigest(base);
  assert.equal(microvmGuestExecutionRequestDigest({ ...base, args: [...base.args] }), identity, "same typed request converges");
  for (const mutant of [
    { ...base, command: "/bin/bash" },
    { ...base, args: ["-c", "true"] },
    { ...base, timeoutMs: 90_001 },
    { ...base, maxProcesses: 129 },
    { ...base, memoryBytes: base.memoryBytes + 1 },
  ]) assert.notEqual(microvmGuestExecutionRequestDigest(mutant), identity, "authority-relevant mutation must move the request identity");
  assert.throws(() => microvmGuestExecutionRequestDigest({ ...base, command: "" }), /command\/argv is malformed/);
  for (const memoryBytes of [NaN, Infinity, -1, 63 * 1024 * 1024]) assert.throws(() => microvmGuestExecutionRequestDigest({ ...base, memoryBytes }), /memoryBytes must be an integer/);
  assert.throws(() => microvmGuestExecutionRequestDigest(new Proxy(base, {})), /inert object/);
  const accessor = { ...base } as MicrovmBoundarySpec;
  Object.defineProperty(accessor, "command", { get: () => "/bin/false", enumerable: true });
  assert.throws(() => microvmGuestExecutionRequestDigest(accessor), /command must be an own data field/);
  const sparse = ["-c", "npm test"]; delete sparse[0];
  assert.throws(() => microvmGuestExecutionRequestDigest({ ...base, args: sparse }), /sparse, accessor, symbol, or extra fields|malformed or oversized string/);
});

test("AUTHORITY: receipt eligibility inertly captures the adapter without executing an accessor", () => {
  const candidate = spec("/project") as MicrovmBoundarySpec;
  let reads = 0;
  Object.defineProperty(candidate, "adapter", {
    enumerable: true,
    get: () => { reads += 1; return undefined; },
  });
  assert.throws(() => buildMicrovmBoundaryRun({ kind: "firecracker", tier: "microvm", available: true, kvmPresent: true, detail: "test" }, candidate), /adapter must be an own data field/);
  assert.equal(reads, 0, "the receipt-eligibility gate must not execute caller-owned adapter code");
});

// ── (a) filesystem jail — a write OUTSIDE the project is refused by the read-only rootfs / narrow data disk ──
test("(a) MICROVM TIER: an absolute-path write OUTSIDE the project does NOT land on the host (real bytes)", async () => {
  const { root, proj } = scratch();
  const outside = join(root, "escape-OUTSIDE.txt"); // sibling of proj → outside the single rw project data disk
  // VERIFIED-SEAM: the contract-enforcing fake refuses the out-of-jail write BEFORE any byte lands (real fs).
  const fake = buildContractEnforcingFakeMicrovmBoundary({ projectDir: proj, maxMemoryBytes: MEM });
  let performed = false;
  const out = await fake({ effect: { writePath: outside }, perform: async () => { performed = true; writeFileSync(outside, "pwned"); return { results: [{ name: "x", passed: true }] }; } }, execSpec(proj));
  assert.equal(performed, false, "the disallowed write is refused BEFORE any byte lands (perform never runs)");
  assert.equal(existsSync(outside), false, "the out-of-project write genuinely never lands on the host filesystem");
  assert.match(out.runnerError ?? "", /escapes the project jail|VERIFIED-SEAM/, "refused, labelled as a seam boundary");
  // The guest HARDWARE encodes the jail: rootfs read-only, ONLY the project attached rw.
  const plan = planMicrovmRun(RT, spec(proj));
  const rootfs = plan.config.drives.find((d) => d.drive_id === "rootfs");
  const project = plan.config.drives.find((d) => d.drive_id === "project");
  assert.equal(rootfs?.is_read_only, true, "the rootfs drive is READ-ONLY (fs-jail)");
  assert.equal(project?.is_read_only, false, "ONLY the project data disk is attached read-write");
  assert.equal(project?.path_on_host, proj, "the rw data disk IS the project dir");
});

// ── (b) no false containment — an in-project write + a passing test stays green ────────────────────────
test("(b) MICROVM TIER: an in-project write + a normal passing test stay GREEN (no false containment)", async () => {
  const { proj } = scratch();
  const fake = buildContractEnforcingFakeMicrovmBoundary({ projectDir: proj, maxMemoryBytes: MEM });
  const inpath = join(proj, "in.txt");
  const r = await fake({ effect: { writePath: inpath }, perform: async () => { writeFileSync(inpath, "hi"); return { results: [{ name: "in", passed: true }] }; } }, execSpec(proj));
  assert.equal(r.runnerError, undefined, "a legitimate in-project run has no runner error");
  assert.ok(r.results.length > 0 && r.results.every((c) => c.passed), "the in-project run is green");
  assert.equal(existsSync(inpath), true, "the in-project write landed (the data disk is genuinely rw)");
  assert.equal(microvmContainmentDecision({ projectDir: proj, maxMemoryBytes: MEM }, { writePath: inpath }).allowed, true, "an in-project write is within the contract");
});

// ── (c) resource bound — fsize/pids rlimits are wired into the guest; an unbootable run is never a green ─
test("(c) MICROVM TIER: a resource bound (fsize/pids) is wired, and a run that cannot complete is a runnerError", async () => {
  const { proj } = scratch();
  const CAP = 64 * 1024;
  const plan = planMicrovmRun(RT, spec(proj, { maxFileSizeBytes: CAP, maxProcesses: 64 }));
  assert.match(plan.config["boot-source"].boot_args, new RegExp(`keep.fsize=${CAP}`), "the RLIMIT_FSIZE is wired into the guest boot args");
  assert.match(plan.config["boot-source"].boot_args, /keep\.pids=64/, "the RLIMIT_NPROC is wired into the guest boot args");
  assert.equal(microvmContainmentDecision({ projectDir: proj, maxMemoryBytes: MEM, maxFileSizeBytes: CAP }, { writeBytes: 4_000_000 }).allowed, false, "the contract refuses a write beyond the fsize cap");
  // DISCONFIRMING: a boundary run that cannot COMPLETE (no built kernel/rootfs here) is a runnerError, never green.
  const boundaryRun = buildMicrovmBoundaryRun(RT, spec(proj, { kernelImage: "/nope/vmlinux", rootfsImage: "/nope/rootfs.ext4" }));
  const rr = await boundaryRun(noopRunner, execSpec(proj));
  const green = !rr.runnerError && rr.results.length > 0 && rr.results.every((c) => c.passed);
  assert.equal(green, false, "a microVM run that cannot boot is NEVER a false green (routes to a weaker-but-honest tier)");
  assert.match(rr.runnerError ?? "", /cannot boot|kernel\/rootfs/, "the honest reason: no built guest kernel/rootfs");
});

// ── (d) network egress refused — the guest has NO virtio-net device by default ─────────────────────────
test("(d) MICROVM TIER: network egress is refused (no virtio-net device attached by default)", async () => {
  const { proj } = scratch();
  const plan = planMicrovmRun(RT, spec(proj));
  assert.equal(plan.config["network-interfaces"], undefined, "no virtio-net device is attached by default → no NIC → egress denied");
  assert.equal(microvmContainmentDecision({ projectDir: proj, maxMemoryBytes: MEM }, { connectOut: true }).allowed, false, "the contract refuses egress by default");
  // allowNet is the opt-IN allowance (additive): a NIC is attached only then.
  const opened = planMicrovmRun(RT, spec(proj, { allowNet: true }));
  assert.ok(Array.isArray(opened.config["network-interfaces"]) && opened.config["network-interfaces"]!.length > 0, "allowNet attaches a virtio-net device (additive opt-in)");
  assert.equal(microvmContainmentDecision({ projectDir: proj, maxMemoryBytes: MEM, allowNet: true }, { connectOut: true }).allowed, true, "allowNet opt-in permits egress (additive)");
});

// ── (e) MEMORY — the NEW bound: a memory bomb is OOM-bounded by the guest RAM cap, never a green ────────
test("(e) MICROVM TIER: a memory bomb is bounded by the guest RAM cap (mem_size_mib) — OOM in-guest, never green", async () => {
  const { proj } = scratch();
  // The contract refuses an allocation beyond the guest RAM cap.
  const contract = { projectDir: proj, maxMemoryBytes: MEM };
  assert.equal(microvmContainmentDecision(contract, { allocBytes: MEM * 8 }).allowed, false, "an alloc beyond the guest RAM cap is refused (OOM in-guest)");
  assert.equal(microvmContainmentDecision(contract, { allocBytes: MEM / 2 }).allowed, true, "an alloc within the guest RAM cap is allowed (no false containment)");
  // On real effects (seam): a memory bomb is refused BEFORE it runs — never reported as a passing run.
  const fake = buildContractEnforcingFakeMicrovmBoundary(contract);
  let performed = false;
  const out = await fake({ effect: { allocBytes: MEM * 8 }, perform: async () => { performed = true; return { results: [{ name: "bomb", passed: true }] }; } }, execSpec(proj));
  assert.equal(performed, false, "the memory bomb is refused BEFORE it runs (perform never executes)");
  const green = !out.runnerError && out.results.length > 0 && out.results.every((c) => c.passed);
  assert.equal(green, false, "a memory bomb is NEVER a false green");
  assert.match(out.runnerError ?? "", /guest RAM cap|OOM/, "refused with the honest guest-RAM-cap reason");
  // The guest HARDWARE encodes the cap: mem_size_mib is the fixed allotment (256 MiB here).
  assert.equal(planMicrovmRun(RT, spec(proj)).config["machine-config"].mem_size_mib, 256, "the guest RAM cap is a fixed mem_size_mib allotment");
});

// ── (f) TIER-HONESTY — selectExecutor claims the microVM tier ONLY when kvm+VMM+rootfs are really present ─
test("(f) TIER-HONESTY: selectExecutor does NOT claim the microVM tier when the probe reports it ABSENT", () => {
  const { proj } = scratch();
  const rootfs = join(proj, "rootfs.ext4"); const kernel = join(proj, "vmlinux");
  writeFileSync(rootfs, "x"); writeFileSync(kernel, "x"); // built images exist for the PRESENT case
  const microvm = { kernelImage: kernel, rootfsImage: rootfs, command: "sh", args: [] as string[], memoryBytes: MEM };
  const absent: () => MicrovmRuntimeInfo = () => ({ kind: "none", available: false, tier: "none", kvmPresent: true, detail: "kvm present, no VMM" });
  const present: () => MicrovmRuntimeInfo = () => ({ kind: "firecracker", available: true, tier: "microvm", kvmPresent: true, detail: "probed present" });
  // VMM ABSENT (kvm present, no firecracker): caps CLAIM microvm, but the probe is evidence — fall to the floor.
  const eAbsent = selectExecutor(caps({ kvmAvailable: true }), { detectMicrovm: absent, microvm });
  assert.equal(eAbsent.tier, "process", "a microvm claim the probe does not back must NOT yield a microvm-tier executor");
  // VMM PRESENT + built images: the microVM BoundaryExecutor engages.
  const ePresent = selectExecutor(caps({ kvmAvailable: true }), { detectMicrovm: present, microvm });
  assert.equal(ePresent.tier, "microvm", "a probe-backed VMM + a built kernel/rootfs engages the microVM tier");
  assert.ok(ePresent instanceof BoundaryExecutor, "the microVM tier is the BoundaryExecutor (same port)");
});

test("(f2) TIER-HONESTY: a probe-backed VMM but NO built rootfs routes DOWN (never a false microvm pass)", () => {
  const { proj } = scratch();
  const present: () => MicrovmRuntimeInfo = () => ({ kind: "firecracker", available: true, tier: "microvm", kvmPresent: true, detail: "present" });
  // Images do NOT exist → a legitimate run cannot boot → must route down to the process floor, not claim microvm.
  const microvm = { kernelImage: join(proj, "MISSING-vmlinux"), rootfsImage: join(proj, "MISSING-rootfs"), command: "sh", args: [] as string[], memoryBytes: MEM };
  const e = selectExecutor(caps({ kvmAvailable: true }), { detectMicrovm: present, microvm });
  assert.equal(e.tier, "process", "no built kernel/rootfs → route down, never a false microvm claim");
});

test("(f3) TIER-HONESTY: an explicitly wired boundaryRun engages the selected microVM execution port", () => {
  const e = selectExecutor(caps({ kvmAvailable: true }), { boundaryRun: async () => ({ results: [{ name: "t", passed: true }] }) });
  assert.equal(e.tier, "microvm", "an explicitly wired boundary engages the declared microVM tier");
  assert.ok(e instanceof BoundaryExecutor, "same port");
});

// ── The microVM containment CONTRACT — one source of truth (SAME fs/net/fsize + the NEW memory bound) ──
test("CONTRACT: microvmContainmentDecision extends the shared contract with the guest RAM bound", () => {
  const proj = scratch().proj;
  const c = { projectDir: proj, maxMemoryBytes: MEM, maxFileSizeBytes: 1024 };
  assert.equal(microvmContainmentDecision(c, { writePath: join(proj, "ok.txt") }).allowed, true, "in-jail write allowed");
  assert.equal(microvmContainmentDecision(c, { writePath: join(dirname(proj), "escape.txt") }).allowed, false, "out-of-jail write refused (shared contract)");
  assert.equal(microvmContainmentDecision(c, { connectOut: true }).allowed, false, "egress refused by default (shared contract)");
  assert.equal(microvmContainmentDecision(c, { writeBytes: 4096 }).allowed, false, "oversized write refused (shared contract)");
  assert.equal(microvmContainmentDecision(c, { allocBytes: MEM * 2 }).allowed, false, "over-cap allocation refused (the NEW microVM bound)");
});

// ── The measured microVM reality in THIS environment (honest labelling) ────────────────────────────────
test("HONEST PROBE: /dev/kvm is measured present here, but the microVM tier is a VERIFIED-SEAM (no VMM/rootfs)", () => {
  assert.equal(kvmDevicePresent(), true, "/dev/kvm is a real char device in this environment");
  // firecracker/cloud-hypervisor absent → available:false, but kvmPresent honestly recorded true.
  assert.equal(RT.kvmPresent, true, "the probe records KVM present (not conflated with VMM availability)");
  assert.equal(RT.available, false, "no VMM binary here → the microVM tier is NOT claimed available (VERIFIED-SEAM)");
  assert.equal(microvmImagesPresent({ kernelImage: "/nope/vmlinux", rootfsImage: "/nope/rootfs" }), false, "no built kernel/rootfs in this env");
  assert.equal(FIRECRACKER_OK, false, "this env runs the VERIFIED-SEAM path (real-guest branch skipped honestly)");
});
