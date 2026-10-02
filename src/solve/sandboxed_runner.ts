/**
 * SandboxedCommandRunner — a TestRunner for actual argv-only subprocesses with
 * scoped cwd, scrubbed env, lifetime controls and output caps. Optional namespace
 * setup is best-effort by default; explicit required mode refuses unsupported
 * setup. processIsolation records the selected boundary alongside results.
 *
 * Declared TAP must provide complete, eligible test evidence. Skips and TODOs are
 * not passing executions. Other reporters provide a named command-exit check,
 * not a measured test count. See command_test_evidence.ts for the shared contract.
 *
 * Fail-safe: a run that could not COMPLETE (spawn error, timeout, signal-kill) returns a runnerError — never a green.
 */

import type { TestRunner, TestRunResult, TestExecutionContext } from "./validate.js";
import { interpretCommandTests } from "./command_test_evidence.js";
export { parseTap } from "./command_test_evidence.js";
import { executionStopReason } from "../infra/execution_lifetime.js";
import { copyProcessIsolationObservation, processPlanObservation, readProcessIsolationObservation } from "../infra/isolation_backend.js";
import { ProcessIsolationAdapter, resolvedWithinProject, type IsolationPolicy } from "../infra/process_isolation.js";
import { installedEffectAdmission, INSTALLED_EFFECT_OWNERS, type InstalledEffectAdmission } from "../control/installed_effect_admission.js";

export interface SandboxedCommandConfig {
  /** The test command (argv[0]) — e.g. "node", "npm", "npx", "python". */
  readonly command: string;
  /** Command args — e.g. ["--test"], ["test"], ["-m", "pytest", "-q"]. */
  readonly args: readonly string[];
  /** The confined project directory the command runs in (the real repo working tree). */
  readonly projectDir: string;
  /** Wall-clock timeout (ms). Default 60s. */
  readonly timeoutMs?: number;
  /** CPU-time cap (seconds). Optional. */
  readonly cpuLimitSec?: number;
  /** Captured-output cap (bytes). Default 1 MB. */
  readonly maxOutputBytes?: number;
  /** Env vars allowed through to the child (secrets scoping). Default: none (only a minimal PATH). */
  readonly envAllowlist?: readonly string[];
  /**
   * Request best-effort namespaces by default. false explicitly selects process
   * fallback. Neither policy guarantees filesystem/network containment; inspect
   * processIsolation. "required" selects the qualified-binary Linux backend and
   * refuses unsupported/unsafe setup instead of falling back.
   */
  readonly namespaceJail?: boolean | "required";
  /** Explicit readonly inputs/tool roots for the required Linux backend. */
  readonly readOnlyPaths?: readonly string[];
  /** Operator opt-IN allowance: keep the network reachable for the child (default: network-DENIED). */
  readonly allowNet?: boolean;
  /** Operator opt-IN allowance: extra absolute paths the child may write to (default: only the project dir). */
  readonly allowWritePaths?: readonly string[];
  /** Per-file RLIMIT_FSIZE. Default 1 GiB; required mode rounds down to KiB. Not a total disk quota. */
  readonly maxFileSizeBytes?: number;
  /** RLIMIT_NPROC. Default: 512 (fork-bomb defense-in-depth; may not bite inside a user namespace — see backend). */
  readonly maxProcesses?: number;
  /** RLIMIT_NOFILE. Default: 8192. */
  readonly maxOpenFiles?: number;
  /** Injectable adapter (for tests/instrumentation). Default: a fresh ProcessIsolationAdapter. */
  readonly adapter?: ProcessIsolationAdapter;
  readonly effectAdmission?: InstalledEffectAdmission;
}

/** Per-process/per-file limits, not aggregate memory, disk or process-tree quotas. */
const DEFAULT_FSIZE_BYTES = 1024 * 1024 * 1024; // 1 GiB
const DEFAULT_NPROC = 512;
const DEFAULT_NOFILE = 8192;
const VERIFIED_COMMAND_CONFIG = new WeakMap<SandboxedCommandRunner, Readonly<{ command: string; args: readonly string[]; projectDir: string }>>();

/** Verifier-owned identity of the immutable argv/cwd captured by the built-in command runner. */
export function verifiedSandboxedCommandConfig(runner: SandboxedCommandRunner): Readonly<{ command: string; args: readonly string[]; projectDir: string }> | undefined {
  return VERIFIED_COMMAND_CONFIG.get(runner);
}

export class SandboxedCommandRunner implements TestRunner {
  private readonly adapter: ProcessIsolationAdapter;
  private readonly cfg: SandboxedCommandConfig;
  constructor(cfg: SandboxedCommandConfig) {
    this.adapter = cfg.adapter ?? new ProcessIsolationAdapter();
    this.cfg = Object.freeze({ ...cfg, args: Object.freeze([...cfg.args]),
      ...(cfg.envAllowlist ? { envAllowlist: Object.freeze([...cfg.envAllowlist]) } : {}),
      ...(cfg.readOnlyPaths ? { readOnlyPaths: Object.freeze([...cfg.readOnlyPaths]) } : {}),
      ...(cfg.allowWritePaths ? { allowWritePaths: Object.freeze([...cfg.allowWritePaths]) } : {}) });
    VERIFIED_COMMAND_CONFIG.set(this, Object.freeze({ command: this.cfg.command, args: this.cfg.args, projectDir: this.cfg.projectDir }));
  }

  async run(repoRef: string, execution?: TestExecutionContext): Promise<TestRunResult> {
    if (this.cfg.namespaceJail !== undefined && typeof this.cfg.namespaceJail !== "boolean" && this.cfg.namespaceJail !== "required") {
      const missing = processPlanObservation(undefined, undefined, [], "policy-refusal");
      return { results: [], runnerError: "unsupported namespaceJail policy: expected true, false or required",
        failureKind: "harness", processCompletion: "not-started",
        processIsolation: copyProcessIsolationObservation({ ...missing, namespacePolicy: "unsupported", namespaceSetup: "unverified" }) };
    }
    const precheck = executionStopReason(execution);
    if (precheck) return { results: [], runnerError: `${precheck} before test dispatch`, failureKind: "harness", processCompletion: "not-started" };
    if (this.cfg.namespaceJail === "required" && this.cfg.allowNet !== undefined && typeof this.cfg.allowNet !== "boolean") {
      return { results: [], runnerError: "required-jail allowNet must be boolean", failureKind: "harness", processCompletion: "not-started" };
    }
    // Jail: the repoRef must resolve within the confined project dir (realpath-resolved; defeats symlink-out/traversal).
    if (!resolvedWithinProject(this.cfg.projectDir, repoRef === "" || repoRef === "." ? this.cfg.projectDir : repoRef)) {
      return { results: [], runnerError: `test scope escapes the project dir (${repoRef}) — refusing to execute` };
    }

    // Availability and setup are distinct; selecting this request does not prove
    // that a child's filesystem or network access was confined.
    const jailOn = this.cfg.namespaceJail !== false;
    const policy: IsolationPolicy = {
      ...execution,
      cwd: this.cfg.projectDir,
      timeoutMs: Math.min(this.cfg.timeoutMs ?? 60_000, execution?.deadline === undefined ? 60_000_000 : Math.max(1, execution.deadline - Date.now())),
      maxOutputBytes: this.cfg.maxOutputBytes ?? 1024 * 1024,
      ...(this.cfg.cpuLimitSec !== undefined ? { cpuLimitSec: this.cfg.cpuLimitSec } : {}),
      ...(this.cfg.envAllowlist ? { envAllowlist: this.cfg.envAllowlist } : {}),
      ...(jailOn ? { namespaceJail: {
        projectDir: this.cfg.projectDir,
        ...(this.cfg.namespaceJail === "required" ? { mode: "required" as const } : {}),
        ...(this.cfg.readOnlyPaths ? { readOnlyPaths: this.cfg.readOnlyPaths } : {}),
        ...(this.cfg.allowNet ? { allowNet: true } : {}),
        ...(this.cfg.allowWritePaths ? { allowWritePaths: this.cfg.allowWritePaths } : {}),
        maxFileSizeBytes: this.cfg.maxFileSizeBytes ?? DEFAULT_FSIZE_BYTES,
        maxProcesses: this.cfg.maxProcesses ?? DEFAULT_NPROC,
        maxOpenFiles: this.cfg.maxOpenFiles ?? DEFAULT_NOFILE,
      } } : {}),
    };

    (this.cfg.effectAdmission ?? installedEffectAdmission).admit(INSTALLED_EFFECT_OWNERS.testProcess.id);
    const admittedStop = executionStopReason(execution);
    if (admittedStop) return { results: [], runnerError: `${admittedStop} before test dispatch`, failureKind: "harness", processCompletion: "not-started" };
    const res = await this.adapter.run(this.cfg.command, this.cfg.args, policy);
    const rawObservation = readProcessIsolationObservation(res.processIsolation);
    const legacyDegraded = Array.isArray(res.degraded) ? res.degraded.filter(v => typeof v === "string").slice(0, 32).map(v => v.slice(0, 128)) : [];
    const processIsolation = rawObservation ? copyProcessIsolationObservation({ ...rawObservation,
      degraded: [...new Set([...rawObservation.degraded, ...legacyDegraded])] })
      : processPlanObservation(policy.namespaceJail, policy.cpuLimitSec, legacyDegraded, "missing-adapter-observation");
    const observed = { processIsolation, ...(res.completion ? { processCompletion: res.completion } : {}) };

    // Could-not-complete → runnerError (never a false green).
    if (res.timedOut || res.cancelled || res.terminationError || res.completion === "unconfirmed" || executionStopReason(execution)) return {
      ...observed, results: [], failureKind: "harness",
      runnerError: `${res.timedOut ? `test run exceeded ${this.cfg.timeoutMs ?? 60_000}ms or earlier caller deadline` : res.terminationError ? "test process error" : "test run cancelled"}; ${res.completion === "direct-child-closed" ? "direct child closed; descendant termination unverified" : res.completion === "not-started" ? "process not started" : "termination unconfirmed; work may continue"}${res.terminationError ? ` (${res.terminationError})` : ""}`,
    };
    if (res.code === null) return { ...observed, results: [], failureKind: "harness", runnerError: `test process did not exit normally${res.signal ? ` (signal: ${res.signal})` : ""}` };
    if (this.cfg.namespaceJail === "required" && (processIsolation.namespacePolicy !== "required" ||
        processIsolation.basis !== "launcher-status" || processIsolation.namespaceSetup !== "launcher-confirmed" ||
        processIsolation.rlimitSetup !== "launcher-confirmed" || processIsolation.degraded.length !== 0)) {
      return { ...observed, results: [], failureKind: "harness", runnerError: "required-jail setup was not confirmed; command may have run" };
    }

    return { ...observed, ...interpretCommandTests(`${this.cfg.command} ${this.cfg.args.join(" ")}`.trim(), { ...res, code: res.code }) };
  }
}

/**
 * Build a solver `runnerFor(repoRef, tree)` that runs the given test command inside the sandbox, jailed to
 * `projectDirOf(repoRef)`. Pair with LocalFsWorkspace (a real working tree). This RETIRES the fail-closed default on the
 * real-repo path: the solver's tests now actually execute inside the isolation boundary.
 */
export function sandboxedRunnerFor(
  projectDirOf: (repoRef: string) => string,
  command: string,
  args: readonly string[],
  opts: { timeoutMs?: number; cpuLimitSec?: number; maxOutputBytes?: number; envAllowlist?: readonly string[]; namespaceJail?: boolean | "required"; readOnlyPaths?: readonly string[]; allowNet?: boolean; allowWritePaths?: readonly string[]; adapter?: ProcessIsolationAdapter } = {},
): (repoRef: string) => TestRunner {
  return (repoRef: string) =>
    new SandboxedCommandRunner({
      command, args, projectDir: projectDirOf(repoRef),
      ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
      ...(opts.cpuLimitSec !== undefined ? { cpuLimitSec: opts.cpuLimitSec } : {}),
      ...(opts.maxOutputBytes !== undefined ? { maxOutputBytes: opts.maxOutputBytes } : {}),
      ...(opts.envAllowlist ? { envAllowlist: opts.envAllowlist } : {}),
      // BUILD-ORDER 1.3 — jail is default-ON; opt-out and opt-in allowances flow through unchanged.
      ...(opts.namespaceJail !== undefined ? { namespaceJail: opts.namespaceJail } : {}),
      ...(opts.readOnlyPaths ? { readOnlyPaths: opts.readOnlyPaths } : {}),
      ...(opts.allowNet ? { allowNet: opts.allowNet } : {}),
      ...(opts.allowWritePaths ? { allowWritePaths: opts.allowWritePaths } : {}),
      ...(opts.adapter ? { adapter: opts.adapter } : {}),
    });
}
