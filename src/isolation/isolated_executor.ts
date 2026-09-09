/**
 * IsolatedExecutor (Increment 17) — the seam that wraps untrusted AI-generated code execution.
 *
 * The solve pipeline runs the project's tests on a patch Keep wrote. That execution must happen inside the
 * selected isolation tier. This defines the port + a runnable process-isolation FLOOR (the back-of-house
 * default) + declared VERIFIED-SEAM backends (microVM/gVisor/container — same port, need Hetzner + KVM /
 * gVisor / a runtime to run for real).
 *
 * SOTA basis (2026-08-05): scope the filesystem to the PROJECT dir only, never home; resist path traversal
 * (agents bypass path-based matching — bunnyshell 2026). Every isolated execution emits a signed audit
 * artifact (defense-in-depth — northflank/zylos 2026). Zero deps.
 */

import type { Spine } from "../spine/spine.js";
import { realpathSync } from "node:fs";
import { selectTier, executionAllowed, TIER_STRENGTH, type IsolationTier, type IsolationCapabilities } from "./isolation_tier.js";
import type { TestRunner, TestRunResult } from "../solve/validate.js";
import { resolvedWithinProject } from "../infra/process_isolation.js";
import { SandboxedCommandRunner, verifiedSandboxedCommandConfig } from "../solve/sandboxed_runner.js";
import type { FileTree } from "../solve/patch.js";
import { detectContainerRuntime, buildContainerBoundaryRun, type ContainerRuntimeInfo, type ContainerBoundarySpec } from "../infra/container_boundary.js";
import { detectMicrovmRuntime, buildMicrovmBoundaryRun, microvmImagesPresent, verifiedMicrovmRunReceipt, verifiedMicrovmRunReceiptDigest, verifiedMicrovmTestRunResultDigest, type MicrovmRuntimeInfo, type MicrovmBoundarySpec } from "../infra/microvm_boundary.js";
import { detectWindowsJobObjects, buildWindowsBoundaryRun, type WindowsRuntimeInfo, type WindowsBoundarySpec } from "../infra/windows_isolation.js";
import { processFloorEvidence, seamEvidenceForTier, type IsolationAttestor, type IsolationAttestation, type IsolationEvidence } from "./isolation_attestation.js";

export interface ExecutionSpec {
  /** The project root the execution is scoped to (never escapes this). */
  readonly projectDir: string;
  /** The repo ref / working ref the tests run against. */
  readonly repoRef: string;
  /** The patch's assessed risk (drives whether execution is allowed under the tier). */
  readonly patchRisk: "low" | "medium" | "high";
}

export interface IsolatedRunOutcome {
  readonly tier: IsolationTier;
  readonly executed: boolean;
  readonly result?: TestRunResult;
  /** If not executed, why (e.g. tier forbids this risk). */
  readonly refusedReason?: string;
}

/** The isolation port: run untrusted code inside a boundary. Backends implement it per tier. */
export interface IsolatedExecutor {
  readonly tier: IsolationTier;
  /** Run the given TestRunner inside the isolation boundary. */
  runIsolated(runner: TestRunner, spec: ExecutionSpec): Promise<IsolatedRunOutcome>;
  /**
   * BUILD-ORDER 1.7 (BIND-EXECUTOR-TIER-ATTESTATION) — EMIT a signed attestation of the tier this executor
   * really ran, with its MEASURED evidence, using the run's attestor. The oversight router VERIFIES it
   * (signature valid AND evidence recomputes to at least the claimed tier) before the tier grants an
   * autonomy ceiling — so `tier` is no longer trusted as the executor's word (Z193). An executor that does
   * NOT implement this → the router sees an ABSENT attestation → the weakest tier, no autonomy (fail-closed).
   */
  attest?(attestor: IsolationAttestor, projectDir: string, ts: number): IsolationAttestation | undefined;
}

const CANONICAL_EXECUTORS = new WeakSet<object>();
const LIVE_ISOLATED_OUTCOMES = new WeakMap<object, { readonly projectDir: string; readonly result?: TestRunResult; readonly tier: IsolationTier }>();

/** One-time join proving an outcome came through a built-in enforcing executor for this exact project root. */
export function consumeVerifiedIsolatedRunOutcome(outcome: IsolatedRunOutcome, projectDir: string): boolean {
  const evidence = LIVE_ISOLATED_OUTCOMES.get(outcome);
  if (!evidence) return false;
  LIVE_ISOLATED_OUTCOMES.delete(outcome);
  let expected: string;
  let actual: string;
  try { expected = realpathSync(projectDir); actual = realpathSync(evidence.projectDir); } catch { return false; }
  return expected === actual && evidence.tier === outcome.tier && evidence.result === outcome.result;
}

/**
 * A drop-in TestRunner that routes EVERY execution through an IsolatedExecutor — so the untrusted AI-generated
 * patch's tests always run scoped to the project dir and audited, inside the selected isolation tier. Fail-closed:
 * if the tier refuses execution (weak isolation for a risky patch, or a scope escape), it returns a runner error
 * rather than a green — a non-run can never look like a pass.
 */
export class IsolatedTestRunner implements TestRunner {
  constructor(
    private readonly inner: TestRunner,
    private readonly executor: IsolatedExecutor,
    private readonly projectDir: string,
    private readonly patchRisk: () => "low" | "medium" | "high" = () => "medium",
  ) {}
  /** Verifier-owned argv/cwd identity for the exact built-in inner runner this boundary executes. */
  verifiedCommandConfig(): Readonly<{ command: string; args: readonly string[]; projectDir: string }> | undefined {
    return this.inner instanceof SandboxedCommandRunner ? verifiedSandboxedCommandConfig(this.inner) : undefined;
  }
  /** Execute exactly once and expose the measured tier/refusal outcome for durable evidence. */
  async runWithEvidence(_repoRef: string, requireVerifierOwned = false): Promise<IsolatedRunOutcome> {
    // The inner runner executes the exact locally resolved project root. A ticket/provider repository
    // identifier is routing metadata, not an executable cwd, and must never select different bytes.
    if (requireVerifierOwned && !CANONICAL_EXECUTORS.has(this.executor)) return { tier: "none", executed: false, refusedReason: "isolated execution refused: executor is not a canonical enforcing implementation" };
    if (requireVerifierOwned && TIER_STRENGTH[this.executor.tier] <= TIER_STRENGTH.process && !(this.inner instanceof SandboxedCommandRunner)) {
      return { tier: "none", executed: false, refusedReason: "isolated execution refused: process-tier evidence requires the canonical argv-only sandboxed command runner" };
    }
    const outcome = await this.executor.runIsolated(this.inner, { projectDir: this.projectDir, repoRef: this.projectDir, patchRisk: this.patchRisk() });
    if (requireVerifierOwned) LIVE_ISOLATED_OUTCOMES.set(outcome, { projectDir: this.projectDir, ...(outcome.result ? { result: outcome.result } : {}), tier: outcome.tier });
    return outcome;
  }
  async run(repoRef: string): Promise<TestRunResult> {
    const outcome = await this.runWithEvidence(repoRef);
    if (!outcome.executed || !outcome.result) {
      return { results: [], runnerError: outcome.refusedReason ?? "isolated execution refused" };
    }
    return outcome.result;
  }
}

/**
 * Preserve the measured executor identity while enforcing an operator-required minimum tier.
 * Selection may degrade to the strongest boundary this host can actually run, but a requirement is
 * authority, not a preference: execution below it is refused before the inner runner is called.
 */
export class MinimumTierExecutor implements IsolatedExecutor {
  readonly tier: IsolationTier;
  constructor(
    private readonly inner: IsolatedExecutor,
    private readonly requiredTier: IsolationTier,
    private readonly spine?: Spine,
  ) {
    this.tier = inner.tier;
    if (CANONICAL_EXECUTORS.has(inner)) CANONICAL_EXECUTORS.add(this);
  }

  attest(attestor: IsolationAttestor, projectDir: string, ts: number): IsolationAttestation | undefined {
    return this.inner.attest?.(attestor, projectDir, ts);
  }

  async runIsolated(runner: TestRunner, spec: ExecutionSpec): Promise<IsolatedRunOutcome> {
    if (TIER_STRENGTH[this.tier] < TIER_STRENGTH[this.requiredTier]) {
      const reason = `required ${this.requiredTier} isolation is unavailable; strongest measured enforcing tier is ${this.tier} — refusing execution`;
      this.spine?.stage({
        type: "identity.action", actor: "keep-isolation",
        payload: { event: "isolated_execution", tier: this.tier, requiredTier: this.requiredTier, projectDir: spec.projectDir, patchRisk: spec.patchRisk, executed: false, detail: reason },
      });
      return { tier: this.tier, executed: false, refusedReason: reason };
    }
    return this.inner.runIsolated(runner, spec);
  }
}

/** Reject a path that would escape the project dir (traversal-resistant; never touches home). */
export function isPathWithinProject(projectDir: string, candidate: string): boolean {
  // Normalize without importing node:path resolve semantics that could follow symlinks; string-level guard.
  const norm = candidate.replace(/\\/g, "/");
  if (norm.includes("..")) return false; // no parent traversal
  if (norm.startsWith("~") || norm.startsWith("/root") || norm.startsWith("/home")) {
    // Only allowed if it is UNDER the (already project-scoped) projectDir.
    return norm.startsWith(projectDir.replace(/\\/g, "/") + "/") || norm === projectDir.replace(/\\/g, "/");
  }
  const base = projectDir.replace(/\\/g, "/").replace(/\/+$/, "");
  const abs = norm.startsWith("/") ? norm : `${base}/${norm}`;
  return abs === base || abs.startsWith(base + "/");
}

/**
 * The BUILT back-of-house floor: process isolation. Scopes execution to the project dir, refuses execution
 * the tier forbids, and audits every run. Runnable in-box now (no KVM/container required).
 */
export class ProcessIsolationExecutor implements IsolatedExecutor {
  readonly tier: IsolationTier = "process";
  /** BUILD-ORDER 1.7 — the process-floor evidence this executor attests to (recomputes to `process`). */
  private readonly evidence: IsolationEvidence;
  private completedEvidence: IsolationEvidence | undefined;
  constructor(private readonly spine?: Spine, private readonly opts: { readonly timeoutMs?: number; readonly evidence?: IsolationEvidence } = {}) {
    CANONICAL_EXECUTORS.add(this);
    this.evidence = opts.evidence ?? processFloorEvidence();
  }

  /** BUILD-ORDER 1.7 — emit the signed attestation of the process floor it really runs (evidence → process). */
  attest(attestor: IsolationAttestor, projectDir: string, ts: number): IsolationAttestation | undefined {
    return this.completedEvidence
      ? attestor.attest({ tier: this.tier, evidence: this.completedEvidence, projectDir, ts, mechanism: "hmac-run-key" })
      : undefined;
  }

  async runIsolated(runner: TestRunner, spec: ExecutionSpec): Promise<IsolatedRunOutcome> {
    this.completedEvidence = undefined;
    const gate = executionAllowed(this.tier, spec.patchRisk);
    if (!gate.allowed) {
      this.audit(spec, false, gate.reason);
      return { tier: this.tier, executed: false, refusedReason: gate.reason };
    }
    // Scope guard: realpath-resolved jail (authoritative — defeats a symlink-out that a string check misses). A cheap
    // string pre-check runs first so an obvious traversal is rejected without touching the filesystem.
    const ref = spec.repoRef === "" || spec.repoRef === "." ? spec.projectDir : spec.repoRef;
    if (!isPathWithinProject(spec.projectDir, spec.repoRef) || !resolvedWithinProject(spec.projectDir, ref)) {
      const reason = `execution scope escapes the project dir (${spec.repoRef}) — refusing`;
      this.audit(spec, false, reason);
      return { tier: this.tier, executed: false, refusedReason: reason };
    }
    // Bound the run ONLY when a timeout is CONFIGURED — then even an OPAQUE in-process runner cannot hang
    // forever (fail-closed on timeout). With NO configured timeout (`this.opts.timeoutMs === undefined` — the
    // DEFAULT production construction; no production caller passes one) the in-process branch runs UNBOUNDED:
    // the inner runner is the operator's OWN test runner (an opaque long integration suite is legitimate and
    // Keep cannot know its bound), so Keep does not impose a universal kill that would murder correct work.
    // The honesty invariant (Z189): the audit records the bound ACTUALLY applied, never "time-bounded" on a
    // run where no timeout was armed — a log that overstates the control is worse than no log. A command-based
    // inner runner (SandboxedCommandRunner) is resource-bounded by its OWN wall-clock/CPU limits (default 60s)
    // regardless of this executor's timeout, so that path is honestly "resource-bounded command" either way.
    // An operator who WANTS the in-process kill passes `timeoutMs` (reusing the SAME raceTimeout seam below) —
    // and only THEN does the audit truthfully say "time-bounded".
    const commandBounded = runner instanceof SandboxedCommandRunner;
    const timeBounded = this.opts.timeoutMs !== undefined; // was a bound ACTUALLY applied by this executor?
    let result: TestRunResult;
    if (timeBounded) {
      const raced = await raceTimeout(runner.run(spec.repoRef), this.opts.timeoutMs!);
      if (raced === TIMED_OUT) {
        const reason = `isolated execution exceeded ${this.opts.timeoutMs}ms — killed (fail-closed)`;
        this.audit(spec, false, reason);
        return { tier: this.tier, executed: false, refusedReason: reason };
      }
      result = raced;
    } else {
      result = await runner.run(spec.repoRef);
    }
    const passed = !result.runnerError && result.results.length > 0 && result.results.every((r) => r.passed);
    // HONEST label: branch on the bound actually applied, NEVER on command-vs-in-process. A command runner is
    // self-bounded; an in-process runner is "time-bounded" ONLY when this executor armed a timeout, else
    // "UNBOUNDED" — so the tamper-evident audit can never record a bound that did not exist.
    const boundLabel = commandBounded
      ? "resource-bounded command"
      : (timeBounded ? "in-process, time-bounded" : "in-process, UNBOUNDED (no timeout configured)");
    this.audit(spec, true, `ran under process isolation (${boundLabel}); testsPassed=${passed}`);
    const runtimeDegradations = [
      ...this.evidence.degraded,
      ...(!commandBounded ? ["in-process"] : []),
      ...(!commandBounded && !timeBounded ? ["unbounded"] : []),
    ];
    this.completedEvidence = { ...this.evidence, degraded: [...new Set(runtimeDegradations)] };
    return { tier: this.tier, executed: true, result };
  }

  private audit(spec: ExecutionSpec, executed: boolean, detail: string): void {
    this.spine?.stage({
      type: "identity.action", actor: "keep-isolation",
      payload: { event: "isolated_execution", tier: this.tier, projectDir: spec.projectDir, patchRisk: spec.patchRisk, executed, detail },
    });
  }
}

const TIMED_OUT = Symbol("timed-out");
async function raceTimeout<T>(p: Promise<T>, ms: number): Promise<T | typeof TIMED_OUT> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<typeof TIMED_OUT>((resolve) => { timer = setTimeout(() => resolve(TIMED_OUT), ms); });
  try { return await Promise.race([p, timeout]); }
  finally { if (timer) clearTimeout(timer); }
}

/**
 * The fully-enforcing runner path: an IsolatedTestRunner (tier gate + realpath jail + audit + time-bound) wrapping a
 * SandboxedCommandRunner (argv-only spawn, confined cwd, scrubbed env, wall-clock + CPU limits, process-group kill,
 * output caps) — so an untrusted patch's tests run resource-bounded AND scope-jailed AND audited. This is the BUILT
 * in-environment enforcement; a microVM/gVisor boundary plugs in above via the same IsolatedExecutor port.
 */
export function buildEnforcingRunner(
  projectDir: string,
  command: string,
  args: readonly string[],
  opts: { spine?: Spine; timeoutMs?: number; cpuLimitSec?: number; envAllowlist?: readonly string[]; allowNet?: boolean; allowWritePaths?: readonly string[]; patchRisk?: () => "low" | "medium" | "high" } = {},
): TestRunner {
  const inner = new SandboxedCommandRunner({
    command, args, projectDir,
    ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
    ...(opts.cpuLimitSec !== undefined ? { cpuLimitSec: opts.cpuLimitSec } : {}),
    ...(opts.envAllowlist ? { envAllowlist: opts.envAllowlist } : {}),
    // BUILD-ORDER 1.3 — the kernel namespace jail is default-ON inside SandboxedCommandRunner; opt-in allowances only.
    ...(opts.allowNet ? { allowNet: opts.allowNet } : {}),
    ...(opts.allowWritePaths ? { allowWritePaths: opts.allowWritePaths } : {}),
  });
  const executor = new ProcessIsolationExecutor(opts.spine, opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs + 5_000 } : {});
  return new IsolatedTestRunner(inner, executor, projectDir, opts.patchRisk ?? (() => "medium"));
}

/**
 * A VERIFIED-SEAM backend for a hardware/kernel-isolated tier (microVM / gVisor / container). It declares
 * the tier and the same port; the actual boundary is provided by the host (Firecracker/Kata/runsc/runtime)
 * on Hetzner. Here it delegates to a provided real-boundary runner (the seam) or refuses if none is wired.
 */
export class BoundaryExecutor implements IsolatedExecutor {
  private completedRunEvidence: IsolationEvidence | undefined;
  constructor(
    readonly tier: IsolationTier,
    /** The host-provided boundary that actually runs code inside the VM/sandbox. Absent → seam not live. */
    private readonly boundaryRun: ((runner: TestRunner, spec: ExecutionSpec) => Promise<TestRunResult>) | undefined,
    private readonly spine?: Spine,
    /**
     * BUILD-ORDER 1.5 — the boundary MECHANISM label used in the audit detail (defaults to the tier). Two
     * boundaries can share a tier but differ by mechanism — e.g. the Windows Job Object floor is the "process"
     * tier but a distinct backend from the POSIX process floor. The label makes the audit (and the wiring
     * proof) name WHICH backend actually ran, so a Windows-tier claim is checkable, not conflated.
     */
    private readonly label: string = tier,
    /**
     * BUILD-ORDER 1.7 — the MEASURED evidence backing this tier (from the `detect*` probe on the default
     * path, or a VERIFIED-SEAM host's report). DEFAULT = the process floor, so a strong-tier claim with NO
     * backing evidence recomputes DOWN to `process` at the verifier: a claim earns its ceiling only when
     * real evidence backs it, never on the constructed `.tier` label alone (the Z193 hole this closes).
     */
    private readonly evidence: IsolationEvidence = processFloorEvidence(),
  ) {}

  /** BUILD-ORDER 1.7 — emit the signed attestation of the tier + the measured evidence that backs it. */
  attest(attestor: IsolationAttestor, projectDir: string, ts: number): IsolationAttestation | undefined {
    const evidence = TIER_STRENGTH[this.tier] > TIER_STRENGTH.process ? this.completedRunEvidence : this.evidence;
    if (!evidence) return undefined;
    return attestor.attest({ tier: this.tier, evidence, projectDir, ts, mechanism: "hmac-run-key" });
  }

  async runIsolated(runner: TestRunner, spec: ExecutionSpec): Promise<IsolatedRunOutcome> {
    this.completedRunEvidence = undefined;
    const gate = executionAllowed(this.tier, spec.patchRisk);
    if (!gate.allowed) {
      this.audit(spec, false, gate.reason);
      return { tier: this.tier, executed: false, refusedReason: gate.reason };
    }
    if (!this.boundaryRun) {
      const reason = `${this.tier} isolation declared but no host boundary wired (VERIFIED-SEAM: needs Hetzner + ${this.tier}) — refusing rather than running unisolated`;
      this.audit(spec, false, reason);
      return { tier: this.tier, executed: false, refusedReason: reason };
    }
    const result = await this.boundaryRun(runner, spec);
    if (this.tier === "microvm") {
      const receipt = verifiedMicrovmRunReceipt(result);
      this.completedRunEvidence = receipt && verifiedMicrovmTestRunResultDigest(result) === receipt.testRunResultSha256
        ? {
            platform: process.platform, runtimeKind: receipt.runtimeKind, kvmPresent: true, imagesPresent: true,
            jobObjectSupport: false, degraded: [...receipt.degraded],
            completedRunReceiptDigest: verifiedMicrovmRunReceiptDigest(receipt),
            completedRunExecutionSpecDigest: receipt.executionSpecSha256,
            completedRunGuestExecutionRequestDigest: receipt.guestExecutionRequestSha256,
            completedRunProjectManifestDigest: receipt.projectSourceManifestSha256,
            completedRunResultDigest: receipt.testRunResultSha256,
            completedRunMeasurementPolicyDigest: receipt.measurementPolicyCanonicalSha256,
          }
        : undefined;
    }
    const passed = !result.runnerError && result.results.length > 0 && result.results.every((r) => r.passed);
    this.audit(spec, true, `ran under ${this.label} boundary; testsPassed=${passed}`);
    return { tier: this.tier, executed: true, result };
  }

  private audit(spec: ExecutionSpec, executed: boolean, detail: string): void {
    this.spine?.stage({
      type: "identity.action", actor: "keep-isolation",
      payload: { event: "isolated_execution", tier: this.tier, projectDir: spec.projectDir, patchRisk: spec.patchRisk, executed, detail },
    });
  }
}

/** Refused when a FileTree read/write's canonical (realpath) location escapes the project jail. */
export class JailEscapeError extends Error {
  constructor(readonly op: "read" | "write", readonly path: string, readonly projectDir: string) {
    super(`project-jail refused ${op} of '${path}' — it resolves OUTSIDE the project dir (${projectDir})`);
    this.name = "JailEscapeError";
  }
}

const JAILED = Symbol("keep.jailedTree");

/** True iff `tree` is already a project-jail membrane (so jailedTree is a no-op on it). */
export function isJailed(tree: FileTree): boolean {
  return (tree as unknown as Record<symbol, unknown>)[JAILED] === true;
}

/**
 * BIND-DEFAULT-EXECUTION-PATH (BUILD-ORDER 1.1) — the byte-level project jail on the FileTree surface.
 *
 * Wrap a FileTree so EVERY read/write is realpath-jailed to `projectDir`: a path whose canonical
 * (symlink-resolved) location escapes the project dir is REFUSED before any byte is read or written —
 * it throws `JailEscapeError`, so a refused write does not create a file on the real filesystem and a
 * refused read returns no outside content. This defeats the `..` / absolute-path / symlink-out escape
 * classes (the recurring 2026 working-tree-escape surface) because it composes the SAME
 * `resolvedWithinProject` (realpath on both base and candidate) the isolation executor already uses on
 * `repoRef` — ONE boundary, not a forked second one. A path that does not exist yet is jailed via its
 * nearest existing ancestor, so writes to NEW paths are contained too.
 *
 * This is the boundary the pipeline binds BY DEFAULT (see `KeepPipeline.executionTree`): with no
 * configuration a solve/apply cannot read or write outside the project dir. The `FileTree` port is
 * Keep's read/write of REPO CONTENT — it never legitimately targets outside the project — so this is a
 * HARD default, not a weakened one; an operator-declared outside-project allowance (the scope/WriteGrant
 * path) is additive and lives at the execution/namespace layer, never here. Idempotent (symbol-tagged).
 */
export function jailedTree(inner: FileTree, projectDir: string): FileTree {
  if (isJailed(inner)) return inner;
  const isGitControlPath = (path: string): boolean => {
    const normalized = path.replaceAll("\\", "/");
    return normalized.split("/").some((part) => part === ".git");
  };
  const within = (path: string): boolean => {
    // Repository control data is not product source. It contains hooks, config, excludes,
    // alternates and mutable refs, and therefore may never be read or written by the model-facing tree.
    if (isGitControlPath(path)) return false;
    // Resolve "" / "." to the project root itself; everything else is checked as-is (realpath-jailed).
    const cand = path === "" || path === "." ? projectDir : path;
    return resolvedWithinProject(projectDir, cand);
  };
  const m: FileTree = {
    async read(path: string): Promise<string | undefined> {
      // Refuse an out-of-jail read by DENYING the content (no outside byte reaches the agent). A refused
      // read is indistinguishable from a missing file to the caller, so it degrades gracefully — the
      // patch engine treats it as not-found rather than exfiltrating an outside file into the diff.
      if (!within(path)) return undefined;
      return inner.read(path);
    },
    async write(path: string, content: string): Promise<void> {
      // Refuse an out-of-jail write LOUDLY: reject before any byte is written, so the file is not created
      // on the real filesystem (the enterprise byte-level control) and the escape cannot pass silently.
      if (!within(path)) throw new JailEscapeError("write", path, projectDir);
      return inner.write(path, content);
    },
  };
  (m as unknown as Record<symbol, unknown>)[JAILED] = true;
  return m;
}

/**
 * Pick the executor for the strongest available tier. Back-of-house → ProcessIsolationExecutor.
 *
 * BUILD-ORDER 1.3c (BIND-STRONG-TIER-BOUNDARY) — TIER-HONESTY. A strong tier (gvisor/container/microvm)
 * is CLAIMED by `caps`, but a claim is not evidence (Z156 confused-deputy: an autonomy-buying tier claim
 * derived from the thing it governs). So the strong `BoundaryExecutor` is returned ONLY when a REAL
 * boundary backs the claim — either an explicitly wired `boundaryRun`, OR a runtime the probe ACTUALLY
 * detects (+ an image to run the tests in). When no real boundary is available, this does NOT claim the
 * tier: it falls to the process floor, labelled honestly (`tier === "process"`), never a false tier
 * claim that would buy a higher autonomy ceiling with nothing enforcing it.
 *
 * BUILD-ORDER 1.3b (BIND-MICROVM-TIER-BOUNDARY) extends the SAME honesty to the TOP tier: the microvm
 * `BoundaryExecutor` engages ONLY when the `/dev/kvm`+firecracker probe backs the claim AND a built guest
 * kernel/rootfs exist; a KVM-less / no-rootfs host routes down to the weaker-but-honest tier — never a
 * false microvm claim buying the `full` ceiling with no HW boundary behind it.
 */
export function selectExecutor(caps: IsolationCapabilities, opts: {
  spine?: Spine;
  /** Host-provided boundary runner for the strong tiers (VERIFIED-SEAM / an explicit host wiring). */
  boundaryRun?: (runner: TestRunner, spec: ExecutionSpec) => Promise<TestRunResult>;
  /** Injectable strong-tier runtime probe (default: the real measured `detectContainerRuntime`). */
  detectRuntime?: () => ContainerRuntimeInfo;
  /** Auto-wire config: the toolchain image + command the untrusted tests run under, when a runtime is detected. */
  container?: Omit<ContainerBoundarySpec, "projectDir">;
  /** Injectable microVM runtime probe (default: the real measured `detectMicrovmRuntime`). */
  detectMicrovm?: () => MicrovmRuntimeInfo;
  /** Auto-wire config: the guest kernel/rootfs + command the untrusted tests run under, when KVM+VMM present. */
  microvm?: Omit<MicrovmBoundarySpec, "projectDir">;
  /** BUILD-ORDER 1.5 — the host platform (default: `process.platform`). Injectable so a POSIX in-env run can
   * exercise the win32 selection path in tests. The Windows floor engages ONLY when this is "win32". */
  platform?: string;
  /** Injectable Windows runtime probe (default: the real measured `detectWindowsJobObjects`). */
  detectWindows?: () => WindowsRuntimeInfo;
  /** Auto-wire config: the command + Job Object limits the untrusted tests run under, when win32 + Job Object present. */
  windows?: Omit<WindowsBoundarySpec, "projectDir">;
  /** Host-provided / VERIFIED-SEAM Windows boundary runner (bypasses the auto-wire; still win32-gated). */
  windowsBoundaryRun?: (runner: TestRunner, spec: ExecutionSpec) => Promise<TestRunResult>;
  /** Minimum acceptable enforcing tier. An unavailable tier refuses rather than silently degrading. */
  requiredTier?: IsolationTier;
} = {}): IsolatedExecutor {
  const sel = selectTier(caps);
  const enforceMinimum = (executor: IsolatedExecutor): IsolatedExecutor =>
    opts.requiredTier ? new MinimumTierExecutor(executor, opts.requiredTier, opts.spine) : executor;
  const selectedBoundary = (tier: IsolationTier, run: (runner: TestRunner, spec: ExecutionSpec) => Promise<TestRunResult>, label: string, evidence: IsolationEvidence): IsolatedExecutor => {
    const executor = new BoundaryExecutor(tier, run, opts.spine, label, evidence);
    // Only this measured selector can mint verifier ownership. A caller-created BoundaryExecutor remains unowned.
    CANONICAL_EXECUTORS.add(executor);
    return executor;
  };
  if (sel.tier === "process" || sel.tier === "none") {
    // BUILD-ORDER 1.5 — the PLATFORM-NATIVE floor. On win32 a Win32 Job Object backs the process tier (a real
    // resource/lifetime container); off-platform, or on a win32 host with no Job Object (routes to WSL2/degrade),
    // the POSIX process floor stays. PLATFORM-HONESTY: a Windows-backed "process" claim is made ONLY on win32.
    const win = resolveWindowsBoundary(sel.tier, opts);
    // BUILD-ORDER 1.7 — carry the probe-MEASURED evidence into the executor so its attestation recomputes to
    // the tier the Job Object really backs (not the constructed label).
    if (win) return enforceMinimum(selectedBoundary(sel.tier, win.run, "windows-job-object (process tier)", win.evidence));
    return enforceMinimum(new ProcessIsolationExecutor(opts.spine));
  }
  const strong = resolveStrongBoundary(sel.tier, opts);
  // HONESTY: no real boundary for the claimed strong tier → do NOT claim it; use the process floor, labelled.
  if (!strong) return enforceMinimum(new ProcessIsolationExecutor(opts.spine));
  // BUILD-ORDER 1.7 — thread the probe-measured evidence so the attestation recomputes to the claimed strong
  // tier; a probe that did NOT back the tier never reaches here (resolveStrongBoundary returned undefined).
  return enforceMinimum(selectedBoundary(sel.tier, strong.run, sel.tier, strong.evidence));
}

/**
 * Resolve a REAL strong-tier boundary for `tier`, or `undefined` if none is honestly available. The single
 * point the TIER-HONESTY disproof neuters: forcing this to return a boundary regardless of the probe makes
 * `selectExecutor` claim a tier no runtime backs → RED.
 */
function resolveStrongBoundary(tier: IsolationTier, opts: {
  boundaryRun?: (runner: TestRunner, spec: ExecutionSpec) => Promise<TestRunResult>;
  detectRuntime?: () => ContainerRuntimeInfo;
  container?: Omit<ContainerBoundarySpec, "projectDir">;
  detectMicrovm?: () => MicrovmRuntimeInfo;
  microvm?: Omit<MicrovmBoundarySpec, "projectDir">;
}): { run: (runner: TestRunner, spec: ExecutionSpec) => Promise<TestRunResult>; evidence: IsolationEvidence } | undefined {
  // Explicit host wiring / VERIFIED-SEAM: the operator vouches for the tier by supplying a real boundary
  // runner, so the attestation carries the evidence a host of that tier measures (confused-not-compromised).
  if (opts.boundaryRun) return { run: opts.boundaryRun, evidence: seamEvidenceForTier(tier) };
  // BUILD-ORDER 1.3b — the microVM (TOP) tier. Engage ONLY when the kvm+VMM probe backs the claim AND a
  // built guest kernel+rootfs exist; otherwise route DOWN (no false microvm claim). Neutering the probe
  // check (or the images check) makes selectExecutor claim `microvm` with no HW boundary → RED.
  if (tier === "microvm") {
    if (!opts.microvm) return undefined;
    const rt = opts.detectMicrovm
      ? opts.detectMicrovm()
      : detectMicrovmRuntime(false, { ...(opts.microvm.vmmBin ? { vmmBin: opts.microvm.vmmBin } : {}), ...(opts.microvm.jailerBin ? { jailerBin: opts.microvm.jailerBin } : {}) });
    if (!rt.available || rt.tier !== "microvm") return undefined;
    const spec = { projectDir: ".", ...opts.microvm };
    if (!microvmImagesPresent(spec)) return undefined; // no built kernel/rootfs → route down, never a false pass
    // BUILD-ORDER 1.7 — the attestation evidence IS the probe measurement (kvm + VMM kind + images present).
    return { run: buildMicrovmBoundaryRun(rt, spec), evidence: { platform: process.platform, runtimeKind: rt.kind, kvmPresent: rt.kvmPresent, imagesPresent: true, jobObjectSupport: false, degraded: [] } };
  }
  if (!opts.container) return undefined;
  const rt = (opts.detectRuntime ?? detectContainerRuntime)();
  // ONLY when the probe reports a runtime that really backs THIS tier do we build a real boundary.
  if (!rt.available || rt.tier !== tier) return undefined;
  return { run: buildContainerBoundaryRun(rt, { projectDir: ".", ...opts.container }), evidence: { platform: process.platform, runtimeKind: rt.kind, kvmPresent: false, imagesPresent: true, jobObjectSupport: false, degraded: [] } };
}

/**
 * BUILD-ORDER 1.5 — resolve a REAL Windows Job Object boundary for the process-tier floor, or `undefined` if
 * none is honestly available (→ the caller uses the POSIX floor, i.e. WSL2/degrade). PLATFORM-HONESTY: the
 * `platform === "win32"` guard is the point the disproof neuters — forcing it to pass off-platform makes
 * `selectExecutor` claim a Windows Job Object isolation that did not run (no Job Object on linux) → RED. The
 * Job Object floor is a `process`-tier backend, so it engages ONLY when the ladder resolved to process/none;
 * a win32 host with no Job Object support returns `undefined` (routes to WSL2 / degrades LOUDLY), never a
 * false Windows-isolated pass.
 */
function resolveWindowsBoundary(tier: IsolationTier, opts: {
  platform?: string;
  detectWindows?: () => WindowsRuntimeInfo;
  windows?: Omit<WindowsBoundarySpec, "projectDir">;
  windowsBoundaryRun?: (runner: TestRunner, spec: ExecutionSpec) => Promise<TestRunResult>;
}): { run: (runner: TestRunner, spec: ExecutionSpec) => Promise<TestRunResult>; evidence: IsolationEvidence } | undefined {
  if (tier !== "process" && tier !== "none") return undefined; // the Job Object floor is a process-tier backend
  const platform = opts.platform ?? process.platform;
  if (platform !== "win32") return undefined; // PLATFORM-HONESTY: engage ONLY on win32 (the neuter point)
  // BUILD-ORDER 1.7 — the Job Object evidence recomputes to `process` (win32 + jobObjectSupport). Never
  // claims kvm/images, so it can only ever back the process floor, never a stronger tier.
  const jobEvidence = (degraded: readonly string[]): IsolationEvidence => ({ platform, runtimeKind: "windows-job-object", kvmPresent: false, imagesPresent: false, jobObjectSupport: true, degraded });
  if (opts.windowsBoundaryRun) return { run: opts.windowsBoundaryRun, evidence: jobEvidence([]) }; // explicit host wiring / VERIFIED-SEAM stand-in
  if (!opts.windows) return undefined;
  const rt = (opts.detectWindows ?? (() => detectWindowsJobObjects(platform)))();
  // ONLY when the probe reports a real Job Object (win32 + native support) do we build a real boundary; a
  // win32 host with no Job Object → undefined → the caller routes to WSL2 / degrades (never a false claim).
  if (!rt.available || rt.tier !== "process") return undefined;
  return { run: buildWindowsBoundaryRun(rt, { projectDir: ".", ...opts.windows }), evidence: jobEvidence(rt.netDenyEnforceable ? [] : ["net-deny-degraded"]) };
}
