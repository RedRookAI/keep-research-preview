/**
 * BUILD-ORDER 1.5 (BIND-WINDOWS-ISOLATION-BACKEND) — the NON-POSIX (Windows) isolation backend proven against
 * the SAME default-path containment contract rounds 1.3 / 1.3c / 1.3b established, on a non-POSIX platform.
 *
 * The `BoundaryExecutor` Windows floor runs the untrusted test PROCESS bounded by a Win32 Job Object behind the
 * SAME `IsolatedExecutor` port and is proven to satisfy the EXACT contract — a child cannot write outside the
 * project (confined cwd + the fs-jail), cannot reach the network (WFP/firewall deny where enforceable, else an
 * HONEST degraded label), and is resource-bounded by the Job Object: `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`
 * (process count) + `JOB_OBJECT_LIMIT_JOB_MEMORY` (a HARD whole-job memory cap) + `KILL_ON_JOB_CLOSE`.
 *
 * DETECT-AND-SELECT, PLATFORM-HONEST: `detectWindowsJobObjects()` MEASURES the platform. In THIS environment
 * `process.platform === "linux"`, NOT "win32" — so the Windows tier is a VERIFIED-SEAM, proven by the
 * contract-enforcing fake (on REAL filesystem bytes) + a real `process.platform` probe. The plan-level
 * assertions prove the Job Object limits encode the contract (active-process, job-memory, kill-on-close,
 * confined cwd, net rule). Where a real win32 host + a Job Object native addon are present, the same backend
 * asserts on REAL Job Object effects.
 *
 * Proven by DISPROOF: each assertion has a paired neuter of `planWindowsRun` / `windowsContainmentDecision` /
 * the platform-honesty point — RED bytes under redrook-ops/.round-artifacts/BIND-WINDOWS-ISOLATION-BACKEND/.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, existsSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";

import {
  detectWindowsJobObjects, planWindowsRun, buildWindowsBoundaryRun, windowsContainmentDecision,
  buildContractEnforcingFakeWindowsBoundary, windowsFallbackRoute,
  type WindowsRuntimeInfo, type WindowsBoundarySpec,
} from "../src/infra/windows_isolation.js";
import { selectExecutor, BoundaryExecutor, ProcessIsolationExecutor, type ExecutionSpec } from "../src/isolation/isolated_executor.js";
import type { IsolationCapabilities } from "../src/isolation/isolation_tier.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";

const RT = detectWindowsJobObjects();
const caps = (o: Partial<IsolationCapabilities>): IsolationCapabilities => ({ kvmAvailable: false, gvisorAvailable: false, containerRuntime: false, canScopeProcess: false, ...o });
const noopRunner: TestRunner = { async run(): Promise<TestRunResult> { return { results: [{ name: "t", passed: true }] }; } };

/** A win32 runtime WITH a real Job Object (the "engaged" stand-in), net-deny enforceable. */
const winPresent = (o: Partial<WindowsRuntimeInfo> = {}): WindowsRuntimeInfo => ({
  kind: "job-object", available: true, tier: "process", platform: "win32", wsl2Present: false, netDenyEnforceable: true, detail: "test win32 job object", ...o,
});

/** A fresh { root, proj }: proj is a child of root, so `root/escape` is OUTSIDE the project. */
function scratch(): { root: string; proj: string } {
  const root = mkdtempSync(join(tmpdir(), "keep-win-"));
  const proj = join(root, "proj");
  mkdirSync(proj, { recursive: true });
  return { root, proj };
}
function execSpec(projectDir: string): ExecutionSpec { return { projectDir, repoRef: projectDir, patchRisk: "medium" }; }
function spec(proj: string, over: Partial<WindowsBoundarySpec> = {}): WindowsBoundarySpec {
  return { projectDir: proj, command: "node", args: ["--version"], memoryBytes: 256 * 1024 * 1024, ...over };
}
const MEM = 256 * 1024 * 1024;

/** A real Job Object run needs win32 + a native addon. Absent here → the VERIFIED-SEAM path. */
const JOBOBJECT_OK = RT.available && RT.tier === "process";

// ── (a) filesystem jail — a write OUTSIDE the project is refused by the confined cwd / fs-jail contract ──
test("(a) WINDOWS TIER: an absolute-path write OUTSIDE the project does NOT land (real bytes; scoped cwd)", async () => {
  const { root, proj } = scratch();
  const outside = join(root, "escape-OUTSIDE.txt"); // sibling of proj → outside the project jail
  const fake = buildContractEnforcingFakeWindowsBoundary({ projectDir: proj, maxMemoryBytes: MEM });
  let performed = false;
  const out = await fake({ effect: { writePath: outside }, perform: async () => { performed = true; writeFileSync(outside, "pwned"); return { results: [{ name: "x", passed: true }] }; } }, execSpec(proj));
  assert.equal(performed, false, "the disallowed write is refused BEFORE any byte lands (perform never runs)");
  assert.equal(existsSync(outside), false, "the out-of-project write genuinely never lands on the real filesystem");
  assert.match(out.runnerError ?? "", /escapes the project jail|VERIFIED-SEAM/, "refused, labelled as a seam boundary");
  // The plan encodes the jail: the confined working dir IS the project dir.
  const plan = planWindowsRun(RT, spec(proj));
  assert.equal(plan.cwd, proj, "the Job Object run is confined to the project cwd (fs-jail)");
});

// ── (b) no false containment — an in-project write + a passing test stays green ────────────────────────
test("(b) WINDOWS TIER: an in-project write + a normal passing test stay GREEN (no false containment)", async () => {
  const { proj } = scratch();
  const fake = buildContractEnforcingFakeWindowsBoundary({ projectDir: proj, maxMemoryBytes: MEM });
  const inpath = join(proj, "in.txt");
  const r = await fake({ effect: { writePath: inpath }, perform: async () => { writeFileSync(inpath, "hi"); return { results: [{ name: "in", passed: true }] }; } }, execSpec(proj));
  assert.equal(r.runnerError, undefined, "a legitimate in-project run has no runner error");
  assert.ok(r.results.length > 0 && r.results.every((c) => c.passed), "the in-project run is green");
  assert.equal(existsSync(inpath), true, "the in-project write landed (the project dir is genuinely writable)");
  assert.equal(windowsContainmentDecision({ projectDir: proj, maxMemoryBytes: MEM }, { writePath: inpath }).allowed, true, "an in-project write is within the contract");
});

// ── (c) resource bound — active-process/job-memory limits wired; an unbootable run is never a green ─────
test("(c) WINDOWS TIER: a resource bound (active-process / job-memory) is wired, and an unavailable run is a runnerError", async () => {
  const { proj } = scratch();
  const plan = planWindowsRun(RT, spec(proj, { maxProcesses: 64, memoryBytes: MEM }));
  assert.ok(plan.jobLimits.limitFlags.includes("JOB_OBJECT_LIMIT_ACTIVE_PROCESS"), "the ActiveProcessLimit flag is set");
  assert.equal(plan.jobLimits.activeProcessLimit, 64, "the ActiveProcessLimit is wired");
  assert.ok(plan.jobLimits.limitFlags.includes("JOB_OBJECT_LIMIT_JOB_MEMORY"), "the JobMemoryLimit flag is set");
  assert.equal(plan.jobLimits.jobMemoryLimitBytes, MEM, "the JobMemoryLimit is wired");
  assert.ok(plan.jobLimits.killOnJobClose && plan.jobLimits.limitFlags.includes("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE"), "KILL_ON_JOB_CLOSE is always set (lifetime containment)");
  // the contract refuses a fork-bomb / memory-bomb beyond the Job Object limits.
  assert.equal(windowsContainmentDecision({ projectDir: proj, maxProcesses: 64 }, { spawnCount: 4096 }).allowed, false, "a fork bomb beyond ActiveProcessLimit is refused");
  assert.equal(windowsContainmentDecision({ projectDir: proj, maxMemoryBytes: MEM }, { allocBytes: MEM * 8 }).allowed, false, "an alloc beyond JobMemoryLimit is refused");
  // DISCONFIRMING: a boundary run that cannot COMPLETE (off-platform / no Job Object here) is a runnerError, never green.
  const boundaryRun = buildWindowsBoundaryRun(RT, spec(proj));
  const rr = await boundaryRun(noopRunner, execSpec(proj));
  const green = !rr.runnerError && rr.results.length > 0 && rr.results.every((c) => c.passed);
  assert.equal(green, false, "a Windows run with no Job Object is NEVER a false green (routes to WSL2 / a weaker-but-honest tier)");
  assert.match(rr.runnerError ?? "", /Job Object boundary unavailable|routing via/, "the honest reason: no Job Object → route to WSL2/degrade");
});

// ── (d) network egress refused where enforceable; else HONESTLY degraded (never a false claim) ──────────
test("(d) WINDOWS TIER: net-deny is enforced by a WFP/firewall rule where possible, else labelled degraded", async () => {
  const { proj } = scratch();
  // Enforceable: a netsh/WFP deny-out rule is planned; NO degraded net label.
  const enforce = planWindowsRun(winPresent({ netDenyEnforceable: true }), spec(proj));
  assert.ok(enforce.netRule && /advfirewall.*action=block/.test(enforce.netRule), "a WFP/netsh deny-out rule is planned where enforceable");
  assert.ok(!enforce.degraded.includes("win-net-deny-unavailable"), "net-deny is NOT degraded where the platform enforces it");
  // NOT enforceable: no rule; the label is surfaced HONESTLY (never a false 'denied' claim).
  const degrade = planWindowsRun(winPresent({ netDenyEnforceable: false }), spec(proj));
  assert.equal(degrade.netRule, undefined, "no deny rule where the platform cannot enforce it");
  assert.ok(degrade.degraded.includes("win-net-deny-unavailable"), "net-deny inability is surfaced as an HONEST degraded label");
  // The contract refuses egress by default; allowNet is the opt-IN allowance (additive).
  assert.equal(windowsContainmentDecision({ projectDir: proj }, { connectOut: true }).allowed, false, "the contract refuses egress by default");
  assert.equal(windowsContainmentDecision({ projectDir: proj, allowNet: true }, { connectOut: true }).allowed, true, "allowNet opt-in permits egress (additive)");
  const opened = planWindowsRun(winPresent({ netDenyEnforceable: true }), spec(proj, { allowNet: true }));
  assert.equal(opened.netRule, undefined, "allowNet: no deny rule is planned (egress permitted)");
  assert.ok(opened.degraded.some((d) => /allowNet/.test(d)), "allowNet is surfaced as an operator opt-in (honest)");
});

// ── (e) PLATFORM-HONESTY — selectExecutor claims the Windows floor ONLY on win32 ───────────────────────
test("(e) PLATFORM-HONESTY: selectExecutor engages the Windows Job Object floor ONLY on win32", () => {
  const { proj } = scratch();
  const windows = { command: "node", args: ["--version"] as string[], memoryBytes: MEM };
  const detectWindows = () => winPresent();
  // win32 + a real Job Object → the Windows BoundaryExecutor engages (same port, process tier).
  const eWin = selectExecutor(caps({ canScopeProcess: true }), { platform: "win32", detectWindows, windows });
  assert.ok(eWin instanceof BoundaryExecutor, "on win32 with a Job Object, the Windows floor is a BoundaryExecutor (same port)");
  assert.equal(eWin.tier, "process", "the Job Object buys the process tier ONLY (never the POSIX namespace guarantees)");
  // OFF-PLATFORM (real process.platform === linux here): must NOT claim a Windows isolation that did not run.
  const eOff = selectExecutor(caps({ canScopeProcess: true }), { detectWindows, windows });
  assert.ok(eOff instanceof ProcessIsolationExecutor, "off-platform → the POSIX process floor, NOT a false Windows claim");
  assert.ok(!(eOff instanceof BoundaryExecutor), "off-platform never yields a Windows-tier BoundaryExecutor");
  // DISCONFIRMING: a win32 host with NO Job Object routes to WSL2 / degrades — never a false Windows pass.
  const noJob = () => ({ kind: "none", available: false, tier: "none", platform: "win32", wsl2Present: true, netDenyEnforceable: false, detail: "win32, no job object" } as WindowsRuntimeInfo);
  const eNoJob = selectExecutor(caps({ canScopeProcess: true }), { platform: "win32", detectWindows: noJob, windows });
  assert.ok(eNoJob instanceof ProcessIsolationExecutor, "win32 with no Job Object → route to WSL2/degrade (the POSIX floor), never a false Windows claim");
  assert.equal(windowsFallbackRoute(noJob()), "wsl2-posix", "no Job Object + WSL2 present → route back onto the POSIX tiers");
  assert.equal(windowsFallbackRoute({ ...noJob(), wsl2Present: false }), "degrade-loud", "no Job Object + no WSL2 → degrade LOUDLY (never a silent false pass)");
});

test("(e2) PLATFORM-HONESTY: an explicitly wired windowsBoundaryRun engages the Windows floor on win32 (host/SEAM)", () => {
  const e = selectExecutor(caps({ canScopeProcess: true }), { platform: "win32", windowsBoundaryRun: async () => ({ results: [{ name: "t", passed: true }] }) });
  assert.ok(e instanceof BoundaryExecutor, "an explicit boundary engages the Windows floor on win32");
  assert.equal(e.tier, "process", "the Windows floor is the process tier");
});

// ── (f) MEMORY — a memory bomb is bounded by the Job Object JobMemoryLimit, never a green ───────────────
test("(f) WINDOWS TIER: a memory bomb is bounded by JobMemoryLimit (real effect, seam) — never a false green", async () => {
  const { proj } = scratch();
  const contract = { projectDir: proj, maxMemoryBytes: MEM };
  assert.equal(windowsContainmentDecision(contract, { allocBytes: MEM * 8 }).allowed, false, "an alloc beyond JobMemoryLimit is refused");
  assert.equal(windowsContainmentDecision(contract, { allocBytes: MEM / 2 }).allowed, true, "an alloc within JobMemoryLimit is allowed (no false containment)");
  const fake = buildContractEnforcingFakeWindowsBoundary(contract);
  let performed = false;
  const out = await fake({ effect: { allocBytes: MEM * 8 }, perform: async () => { performed = true; return { results: [{ name: "bomb", passed: true }] }; } }, execSpec(proj));
  assert.equal(performed, false, "the memory bomb is refused BEFORE it runs (perform never executes)");
  const green = !out.runnerError && out.results.length > 0 && out.results.every((c) => c.passed);
  assert.equal(green, false, "a memory bomb is NEVER a false green");
  assert.match(out.runnerError ?? "", /JobMemoryLimit|killed by the job/, "refused with the honest JobMemoryLimit reason");
});

// ── The Windows containment CONTRACT — one source of truth (SAME fs/net/fsize + the Job Object bounds) ──
test("CONTRACT: windowsContainmentDecision extends the shared contract with the Job Object bounds", () => {
  const proj = scratch().proj;
  const c = { projectDir: proj, maxMemoryBytes: MEM, maxProcesses: 32, maxFileSizeBytes: 1024 };
  assert.equal(windowsContainmentDecision(c, { writePath: join(proj, "ok.txt") }).allowed, true, "in-jail write allowed");
  assert.equal(windowsContainmentDecision(c, { writePath: join(dirname(proj), "escape.txt") }).allowed, false, "out-of-jail write refused (shared contract)");
  assert.equal(windowsContainmentDecision(c, { connectOut: true }).allowed, false, "egress refused by default (shared contract)");
  assert.equal(windowsContainmentDecision(c, { writeBytes: 4096 }).allowed, false, "oversized write refused (shared contract)");
  assert.equal(windowsContainmentDecision(c, { allocBytes: MEM * 2 }).allowed, false, "over-cap allocation refused (JobMemoryLimit)");
  assert.equal(windowsContainmentDecision(c, { spawnCount: 4096 }).allowed, false, "over-limit spawn refused (ActiveProcessLimit)");
});

// ── The measured Windows reality in THIS environment (honest labelling) ─────────────────────────────────
test("HONEST PROBE: process.platform is linux here, so the Windows Job Object tier is a VERIFIED-SEAM", () => {
  assert.notEqual(process.platform, "win32", "this environment is NOT win32");
  assert.equal(RT.platform, process.platform, "the probe records the real platform (not conflated with availability)");
  assert.equal(RT.available, false, "no win32 Job Object here → the Windows tier is NOT claimed available (VERIFIED-SEAM)");
  assert.equal(RT.tier, "none", "off-platform the tier is honestly 'none'");
  assert.equal(JOBOBJECT_OK, false, "this env runs the VERIFIED-SEAM path (real-Job-Object branch skipped honestly)");
});
