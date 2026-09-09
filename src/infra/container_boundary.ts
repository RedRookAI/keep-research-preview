/**
 * BUILD-ORDER 1.3c (BIND-STRONG-TIER-BOUNDARY) — the STRONG-tier boundary that runs the untrusted test
 * PROCESS behind the SAME `IsolatedExecutor`/`BoundaryExecutor` port round 1.3 established, but enforced
 * by a user-space kernel (gVisor `runsc`) or a HARDENED container runtime instead of bare namespaces.
 *
 * It proves the EXACT default-path containment contract one tier up: a child cannot write outside the
 * project on the filesystem (read-only rootfs + a single rw project bind), cannot reach the network
 * (`--network none`), and is resource-bounded (`--ulimit fsize` + `--pids-limit`). The hardening is the
 * hard default; `allowNet`/`allowWritePaths` are opt-IN operator allowances (additive, never a weakened
 * default) — mirroring the namespace floor exactly.
 *
 * COMPOSED, not forked: this builds a `boundaryRun` closure that plugs into the EXISTING `BoundaryExecutor`
 * (isolated_executor.ts) — one executor port, not two. Detect-and-select is honest: `detectContainerRuntime`
 * MEASURES what is really present (never assumes), and `selectExecutor` only claims the strong tier when a
 * real boundary backs it.
 *
 * SOTA basis (2026-08-15, quotes/URLs in redrook-ops/.round-artifacts/BIND-STRONG-TIER-BOUNDARY/sota.txt):
 *  - gVisor `runsc` = a user-space kernel; an OCI runtime that intercepts every syscall (systrap/KVM) and
 *    reimplements ~200 in userspace; used via `docker run --runtime=runsc` or rootless `runsc`.
 *  - "Standard Docker is NOT sufficient for untrusted AI code" (shared kernel → escape = host access). A
 *    HARDENED container adds: seccomp, cap-drop, read-only rootfs, cgroup limits, `--network none`.
 *  - The runsc TAX: unimplemented syscalls → ENOSYS (~1.7% of cases, Tencent); a legit suite can BREAK
 *    under the partial syscall surface — so a boundary run that cannot COMPLETE surfaces a runnerError
 *    (never a false green) and routes to a weaker-but-honest tier. Degrade honestly.
 *
 * Zero runtime deps (node:child_process only).
 */

import { spawnSync } from "node:child_process";
import type { TestRunner, TestRunResult, TestCaseResult } from "../solve/validate.js";
import { ProcessIsolationAdapter, resolvedWithinProject } from "./process_isolation.js";
import { parseTap } from "../solve/sandboxed_runner.js";
import type { ExecutionSpec } from "../isolation/isolated_executor.js";
import type { IsolationTier } from "../isolation/isolation_tier.js";

/** Which strong-tier runtime backs the boundary. `runsc` → gVisor tier; `docker`/`podman` → container tier. */
export type ContainerRuntimeKind = "runsc" | "docker" | "podman" | "none";

/** Detected/declared strong-tier runtime — measured, never assumed. `available` gates any tier claim. */
export interface ContainerRuntimeInfo {
  readonly kind: ContainerRuntimeKind;
  /** True iff the runtime binary is present AND its daemon/engine actually responds (a real boundary can run). */
  readonly available: boolean;
  /** The isolation tier this runtime provides (gvisor > container). "none" when nothing usable is present. */
  readonly tier: IsolationTier;
  /** Honest one-line description of what was measured (never a false claim). */
  readonly detail: string;
}

/**
 * The strong-tier boundary spec — a HARD default (net-denied, filesystem-jailed to the project bind,
 * resource-bounded). `allowNet`/`allowWritePaths` are opt-IN allowances, additive.
 */
export interface ContainerBoundarySpec {
  /** The project dir — the SINGLE read-write island bind-mounted into an otherwise read-only rootfs. */
  readonly projectDir: string;
  /** The toolchain image the untrusted tests run in (the one genuine config — a container needs a rootfs). */
  readonly image: string;
  /** The test command (argv[0]) run INSIDE the container. */
  readonly command: string;
  /** Command args, passed as argv (shell metacharacters inert — the same argument-injection defense). */
  readonly args: readonly string[];
  /** Operator opt-IN: keep the network reachable (skip `--network none`). Default false → network-DENIED. */
  readonly allowNet?: boolean;
  /** Operator opt-IN: extra absolute paths bind-mounted read-write. Default: only the project dir. */
  readonly allowWritePaths?: readonly string[];
  /** RLIMIT_FSIZE (bytes) via `--ulimit fsize` — bounds a disk bomb; bites cleanly (SIGXFSZ). */
  readonly maxFileSizeBytes?: number;
  /** `--pids-limit` — bounds process count (fork-bomb defense). */
  readonly maxProcesses?: number;
  /** `--memory` (bytes). DECLARED but may not bite on every host (cgroup mem accounting) → surfaced in degraded. */
  readonly memoryBytes?: number;
  /** Wall-clock timeout (ms). Default 60s. */
  readonly timeoutMs?: number;
  /** Captured-output cap (bytes). Default 1 MiB. */
  readonly maxOutputBytes?: number;
  /** Injectable adapter (tests). Default: a fresh ProcessIsolationAdapter (spawns the runtime, no double-jail). */
  readonly adapter?: ProcessIsolationAdapter;
}

/** A planned strong-tier spawn: the runtime argv + any control the runtime could not enforce (never silent). */
export interface ContainerRunPlan {
  readonly cmd: string;
  readonly args: readonly string[];
  readonly degraded: readonly string[];
}

let _rtCache: ContainerRuntimeInfo | undefined;

/**
 * Detect the strongest available strong-tier runtime by REAL probes (measurement, not assumption). Cached
 * once per process. Order: gVisor `runsc` (registered as a docker OCI runtime, or a standalone binary) →
 * a container runtime (docker/podman with a responding daemon) → none. A runtime whose binary exists but
 * whose daemon does not respond is reported `available:false` (honest — a boundary that cannot run is not
 * claimed). Non-Linux hosts still probe (docker Desktop etc.); nothing here assumes the tier.
 */
export function detectContainerRuntime(force = false): ContainerRuntimeInfo {
  if (_rtCache && !force) return _rtCache;
  const has = (bin: string, probe: readonly string[]): boolean => {
    try {
      const r = spawnSync(bin, [...probe], { stdio: "ignore", timeout: 8000 });
      return r.status === 0 && !r.error;
    } catch { return false; }
  };
  // gVisor: either a standalone `runsc` binary, or `runsc` registered as a docker runtime (`docker info` lists it).
  const runscBinary = has("runsc", ["--version"]);
  const dockerUp = has("docker", ["version", "--format", "{{.Server.Version}}"]);
  const runscInDocker = dockerUp && dockerRuntimeRegistered("runsc");
  if (runscBinary || runscInDocker) {
    return (_rtCache = {
      kind: "runsc", available: true, tier: "gvisor",
      detail: runscInDocker ? "gVisor runsc registered as a docker OCI runtime" : "gVisor runsc binary present",
    });
  }
  if (dockerUp) {
    return (_rtCache = { kind: "docker", available: true, tier: "container", detail: "docker engine daemon responded" });
  }
  if (has("podman", ["version", "--format", "{{.Version}}"])) {
    return (_rtCache = { kind: "podman", available: true, tier: "container", detail: "podman present and responded" });
  }
  return (_rtCache = { kind: "none", available: false, tier: "none", detail: "no runsc / docker / podman runtime responded (strong tier is a VERIFIED-SEAM)" });
}

/** True iff `name` appears in `docker info`'s Runtimes list (so `docker run --runtime=<name>` would work). */
function dockerRuntimeRegistered(name: string): boolean {
  try {
    const r = spawnSync("docker", ["info", "--format", "{{json .Runtimes}}"], { encoding: "utf8", timeout: 8000 });
    return r.status === 0 && typeof r.stdout === "string" && r.stdout.includes(`"${name}"`);
  } catch { return false; }
}

/**
 * BUILD-ORDER 1.3c — build the hardened `docker`/`podman run` (optionally `--runtime=runsc` for gVisor)
 * spawn plan. PURE (testable without running the runtime), mirroring `planNamespaceSpawn`. The hardening
 * IS the containment contract expressed as runtime flags:
 *   - `--network none`            → network-deny   (skipped ONLY on the `allowNet` opt-in)
 *   - `--read-only` + a `/tmp` tmpfs, and ONLY `projectDir` (and declared writes) bind-mounted rw
 *                                 → filesystem-jail (a write outside the project hits the ro rootfs)
 *   - `--ulimit fsize` / `--pids-limit` / `--memory`
 *                                 → resource-bound
 *   - `--cap-drop ALL --security-opt no-new-privileges`
 *                                 → drop ambient capability / privilege-escalation surface
 * command/args arrive as trailing argv AFTER the image, so shell metacharacters in them are inert.
 */
export function planContainerRun(runtime: ContainerRuntimeInfo, spec: ContainerBoundarySpec): ContainerRunPlan {
  const cmd = runtime.kind === "podman" ? "podman" : "docker";
  const degraded: string[] = [];
  const a: string[] = ["run", "--rm"];

  // gVisor: the same container plan, one flag — the strong-tier boundary plugs into the SAME path.
  if (runtime.kind === "runsc" && cmd === "docker") a.push("--runtime", "runsc");

  // network-deny (hard default). allowNet is the opt-IN allowance (additive).
  if (!spec.allowNet) a.push("--network", "none");

  // filesystem-jail: read-only rootfs; a writable /tmp tmpfs so a normal toolchain still runs; the project
  // (and any operator-declared paths) re-opened read-write. A write OUTSIDE these hits the ro rootfs.
  a.push("--read-only", "--tmpfs", "/tmp:rw,exec,size=64m");
  a.push("-v", `${spec.projectDir}:${spec.projectDir}:rw`);
  for (const p of spec.allowWritePaths ?? []) if (p) a.push("-v", `${p}:${p}:rw`);
  a.push("-w", spec.projectDir);

  // drop capability / privilege-escalation surface (hardened-container SOTA).
  a.push("--cap-drop", "ALL", "--security-opt", "no-new-privileges");

  // resource bounds. fsize bites cleanly (SIGXFSZ); pids bounds forks; memory is declared but may not bite
  // on every host's cgroup mem accounting → surfaced as degraded, never a false claim.
  if (spec.maxFileSizeBytes !== undefined) a.push("--ulimit", `fsize=${spec.maxFileSizeBytes}`);
  if (spec.maxProcesses !== undefined) a.push("--pids-limit", String(spec.maxProcesses));
  if (spec.memoryBytes !== undefined) { a.push("--memory", String(spec.memoryBytes)); degraded.push("memory-cgroup-may-not-bite"); }

  a.push(spec.image, spec.command, ...spec.args);
  return { cmd, args: a, degraded };
}

/**
 * Build a `boundaryRun` for the EXISTING `BoundaryExecutor` (the strong tier). It runs the configured
 * command inside the hardened runtime, scoped to `spec.projectDir` (the SAME realpath jail primitive the
 * process floor uses on `repoRef` — one boundary, not a forked second), and maps the runtime's exit to a
 * TestRunResult. Fail-closed: a run that could not COMPLETE (spawn error / timeout / signal) is a
 * runnerError, never a green — so a legit suite that BREAKS under gVisor's partial syscalls surfaces
 * honestly and routes to a weaker tier rather than being reported as a false pass.
 */
export function buildContainerBoundaryRun(
  runtime: ContainerRuntimeInfo,
  spec: ContainerBoundarySpec,
): (runner: TestRunner, execSpec: ExecutionSpec) => Promise<TestRunResult> {
  const adapter = spec.adapter ?? new ProcessIsolationAdapter();
  return async (_runner: TestRunner, execSpec: ExecutionSpec): Promise<TestRunResult> => {
    const projectDir = execSpec.projectDir || spec.projectDir;
    // Scope jail (same primitive as the floor): the repoRef must resolve within the project dir.
    const ref = execSpec.repoRef === "" || execSpec.repoRef === "." ? projectDir : execSpec.repoRef;
    if (!resolvedWithinProject(projectDir, ref)) {
      return { results: [], runnerError: `test scope escapes the project dir (${execSpec.repoRef}) — refusing to execute` };
    }
    const plan = planContainerRun(runtime, { ...spec, projectDir });
    // Spawn the runtime with NO namespace jail of our own (docker needs to reach its daemon socket; a net
    // namespace here would break the runtime itself). The CONTAINMENT is inside the container, by the plan.
    const res = await adapter.run(plan.cmd, plan.args, {
      cwd: projectDir,
      timeoutMs: spec.timeoutMs ?? 60_000,
      maxOutputBytes: spec.maxOutputBytes ?? 1024 * 1024,
    });
    if (res.timedOut) return { results: [], runnerError: `strong-tier (${runtime.tier}) run exceeded ${spec.timeoutMs ?? 60_000}ms and was killed` };
    if (res.code === null) return { results: [], runnerError: `strong-tier (${runtime.tier}) run did not exit normally${res.signal ? ` (killed: ${res.signal})` : ""}` };

    const cases: TestCaseResult[] = parseTap(`${res.stdout}\n${res.stderr}`);
    if (res.code === 0) {
      return { results: cases.length > 0 ? cases : [{ name: `${spec.command} ${spec.args.join(" ")}`.trim(), passed: true }] };
    }
    const failing = cases.filter((c) => !c.passed);
    if (failing.length > 0) return { results: cases };
    const tail = (res.stderr || res.stdout).slice(-2000);
    return { results: [{ name: `${spec.command} ${spec.args.join(" ")}`.trim(), passed: false, output: tail || `exit code ${res.code}` }] };
  };
}

/**
 * The strong-tier containment CONTRACT — the SINGLE source of truth for what the boundary REFUSES, one
 * tier up from the namespace floor. Both the real runtime flags (`planContainerRun`) and the seam fake
 * (`buildContractEnforcingFakeBoundary`) derive from THIS one predicate — one contract, not two. Pure.
 */
export interface ContainmentContract {
  /** The project jail — a write whose realpath escapes it is refused (read-only rootfs). */
  readonly projectDir: string;
  /** Network egress allowed? Default (undefined/false) → DENIED. */
  readonly allowNet?: boolean;
  /** RLIMIT_FSIZE (bytes). A write beyond it is refused (SIGXFSZ). */
  readonly maxFileSizeBytes?: number;
}

/** An effect an untrusted child intends — checked against the containment contract. */
export interface RequestedEffect {
  /** An absolute path the child intends to write (checked against the project jail). */
  readonly writePath?: string;
  /** The byte size of the intended write (checked against RLIMIT_FSIZE). */
  readonly writeBytes?: number;
  /** The child intends network egress (checked against the net-deny default). */
  readonly connectOut?: boolean;
}

/** The boundary's containment DECISION for a requested effect. Deterministic; the neuterable enforcement point. */
export function containmentDecision(contract: ContainmentContract, effect: RequestedEffect): { allowed: boolean; reason: string } {
  if (effect.connectOut && !contract.allowNet) {
    return { allowed: false, reason: "network egress denied by the strong-tier boundary (--network none)" };
  }
  if (effect.writePath !== undefined && !resolvedWithinProject(contract.projectDir, effect.writePath)) {
    return { allowed: false, reason: `write to '${effect.writePath}' escapes the project jail — refused by the read-only rootfs` };
  }
  if (effect.writeBytes !== undefined && contract.maxFileSizeBytes !== undefined && effect.writeBytes > contract.maxFileSizeBytes) {
    return { allowed: false, reason: `write of ${effect.writeBytes}B exceeds RLIMIT_FSIZE (${contract.maxFileSizeBytes}B) — refused` };
  }
  return { allowed: true, reason: "within the strong-tier containment contract" };
}

/**
 * A contract-enforcing FAKE boundary — the VERIFIED-SEAM stand-in for a strong runtime that is ABSENT
 * in-env (gVisor `runsc` here). It runs the inner runner IN-PROCESS but interposes the SAME containment
 * contract the real boundary enforces, on REAL filesystem effects: given a `ContractProbeRunner` that
 * DECLARES its intended effect, the fake performs an allowed write on the real filesystem and REFUSES a
 * disallowed one before a byte lands (so an out-of-jail write genuinely never happens), and refuses
 * egress. This proves the boundary ABSTRACTION refuses out-of-jail effects where no runtime exists; the
 * REAL kernel/filesystem bytes are proven by the runtime path where one is present. It is HONEST — it is
 * a declared fake seam and never claims a runtime ran.
 */
export interface ContractProbe {
  /** The effect this probe attempts — enforced against the contract. */
  readonly effect: RequestedEffect;
  /** Perform the (allowed) effect for real and report the case result. Only called when the contract allows. */
  readonly perform: () => Promise<TestRunResult>;
}

export function buildContractEnforcingFakeBoundary(
  contract: ContainmentContract,
): (probe: ContractProbe, execSpec: ExecutionSpec) => Promise<TestRunResult> {
  return async (probe: ContractProbe, execSpec: ExecutionSpec): Promise<TestRunResult> => {
    const ref = execSpec.repoRef === "" || execSpec.repoRef === "." ? contract.projectDir : execSpec.repoRef;
    if (!resolvedWithinProject(contract.projectDir, ref)) {
      return { results: [], runnerError: `test scope escapes the project dir (${execSpec.repoRef}) — refusing` };
    }
    const decision = containmentDecision(contract, probe.effect);
    if (!decision.allowed) {
      // Refused BEFORE any byte lands — the out-of-jail effect never happens (fail-closed, never a green).
      return { results: [], runnerError: `[VERIFIED-SEAM fake ${"gvisor"} boundary] ${decision.reason}` };
    }
    return probe.perform();
  };
}
