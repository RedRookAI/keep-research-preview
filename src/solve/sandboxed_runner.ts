/**
 * SandboxedCommandRunner (Increment 2.2) — a TestRunner that runs a REAL test command inside the hardened process
 * isolation boundary (confined cwd, scrubbed env, wall-clock + CPU limits, process-group kill, output caps, realpath
 * jail) and maps the result to a TestRunResult the solve pipeline consumes.
 *
 * SOTA basis (2026-08-08): the process EXIT CODE is the universal, framework-agnostic pass/fail contract (node:test,
 * pytest, jest, vitest all exit non-zero on failure); TAP v13 is the zero-config structured format node:test emits when
 * stdout is piped (our case), so we parse `ok`/`not ok` lines for per-CASE detail — but the exit code decides the overall
 * verdict. What would change it: a project whose runner needs a JSON/JUnit reporter for detail can supply a different
 * parser behind the same seam; the exit-code contract still governs pass/fail.
 *
 * Fail-safe: a run that could not COMPLETE (spawn error, timeout, signal-kill) returns a runnerError — never a green.
 */

import type { TestRunner, TestRunResult, TestCaseResult } from "./validate.js";
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
   * BUILD-ORDER 1.3 — the kernel namespace jail is ON BY DEFAULT (net-denied, filesystem-jailed to projectDir,
   * resource-bounded). Set `false` to opt OUT (e.g. a trusted local run that must reach the network AND write
   * outside the project — but prefer the narrower `allowNet`/`allowWritePaths` allowances). Default: true.
   */
  readonly namespaceJail?: boolean;
  /** Operator opt-IN allowance: keep the network reachable for the child (default: network-DENIED). */
  readonly allowNet?: boolean;
  /** Operator opt-IN allowance: extra absolute paths the child may write to (default: only the project dir). */
  readonly allowWritePaths?: readonly string[];
  /** RLIMIT_FSIZE (bytes) the child may create. Default: 1 GiB (bounds a disk bomb; normal artifacts unaffected). */
  readonly maxFileSizeBytes?: number;
  /** RLIMIT_NPROC. Default: 512 (fork-bomb defense-in-depth; may not bite inside a user namespace — see backend). */
  readonly maxProcesses?: number;
  /** RLIMIT_NOFILE. Default: 8192. */
  readonly maxOpenFiles?: number;
  /** Injectable adapter (for tests/instrumentation). Default: a fresh ProcessIsolationAdapter. */
  readonly adapter?: ProcessIsolationAdapter;
  readonly effectAdmission?: InstalledEffectAdmission;
}

/** Default resource bounds for the namespace jail — generous enough for real builds, tight enough to bound a bomb. */
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
      ...(cfg.allowWritePaths ? { allowWritePaths: Object.freeze([...cfg.allowWritePaths]) } : {}) });
    VERIFIED_COMMAND_CONFIG.set(this, Object.freeze({ command: this.cfg.command, args: this.cfg.args, projectDir: this.cfg.projectDir }));
  }

  async run(repoRef: string, execution?: { readonly signal?: AbortSignal; readonly deadline?: number }): Promise<TestRunResult> {
    if (execution?.signal?.aborted || (execution?.deadline !== undefined && Date.now() >= execution.deadline)) return { results: [], runnerError: "recovery deadline exhausted before test dispatch", failureKind: "harness" };
    // Jail: the repoRef must resolve within the confined project dir (realpath-resolved; defeats symlink-out/traversal).
    if (!resolvedWithinProject(this.cfg.projectDir, repoRef === "" || repoRef === "." ? this.cfg.projectDir : repoRef)) {
      return { results: [], runnerError: `test scope escapes the project dir (${repoRef}) — refusing to execute` };
    }

    // BUILD-ORDER 1.3 — WIRING (ledger 298): the DEFAULT execution path binds the KERNEL namespace jail. With no
    // configuration the child is network-denied, filesystem-jailed to the project dir, and resource-bounded. Neuter
    // this (drop `namespaceJail` from the policy) → the child can write outside the project + reach the network again.
    const jailOn = this.cfg.namespaceJail !== false;
    const policy: IsolationPolicy = {
      cwd: this.cfg.projectDir,
      timeoutMs: Math.min(this.cfg.timeoutMs ?? 60_000, execution?.deadline === undefined ? 60_000_000 : Math.max(1, execution.deadline - Date.now())),
      maxOutputBytes: this.cfg.maxOutputBytes ?? 1024 * 1024,
      ...(this.cfg.cpuLimitSec !== undefined ? { cpuLimitSec: this.cfg.cpuLimitSec } : {}),
      ...(this.cfg.envAllowlist ? { envAllowlist: this.cfg.envAllowlist } : {}),
      ...(jailOn ? { namespaceJail: {
        projectDir: this.cfg.projectDir,
        ...(this.cfg.allowNet ? { allowNet: true } : {}),
        ...(this.cfg.allowWritePaths ? { allowWritePaths: this.cfg.allowWritePaths } : {}),
        maxFileSizeBytes: this.cfg.maxFileSizeBytes ?? DEFAULT_FSIZE_BYTES,
        maxProcesses: this.cfg.maxProcesses ?? DEFAULT_NPROC,
        maxOpenFiles: this.cfg.maxOpenFiles ?? DEFAULT_NOFILE,
      } } : {}),
    };

    (this.cfg.effectAdmission ?? installedEffectAdmission).admit(INSTALLED_EFFECT_OWNERS.testProcess.id);
    const res = await this.adapter.run(this.cfg.command, this.cfg.args, policy);

    // Could-not-complete → runnerError (never a false green).
    if (res.timedOut) return { results: [], runnerError: `test run exceeded ${policy.timeoutMs}ms and was killed` };
    if (res.code === null) return { results: [], runnerError: `test process did not exit normally${res.signal ? ` (killed: ${res.signal})` : ""}` };

    const cases = parseTap(`${res.stdout}\n${res.stderr}`);

    // The EXIT CODE is authoritative for the overall verdict.
    if (res.code === 0) {
      // Passed. Use parsed cases if any; otherwise a single synthetic pass (results must be non-empty to count as passed).
      return { results: cases.length > 0 ? cases : [{ name: `${this.cfg.command} ${this.cfg.args.join(" ")}`.trim(), passed: true }] };
    }

    // Non-zero exit → failed. Prefer the parsed failing cases; else a synthetic failure carrying the output tail.
    const failing = cases.filter((c) => !c.passed);
    if (failing.length > 0) return { results: cases };
    const tail = (res.stderr || res.stdout).slice(-2000);
    return { results: [{ name: `${this.cfg.command} ${this.cfg.args.join(" ")}`.trim(), passed: false, output: tail || `exit code ${res.code}` }] };
  }
}

/**
 * Parse TAP v13 `ok` / `not ok` lines into per-case results. Lenient: ignores non-TAP noise, treats `# SKIP`/`# TODO`
 * directives as non-failing, and returns [] when the output isn't TAP (the caller falls back to the exit code).
 */
export function parseTap(output: string): TestCaseResult[] {
  const cases: TestCaseResult[] = [];
  for (const raw of output.split(/\r?\n/)) {
    const line = raw.trim();
    const m = /^(ok|not ok)\b\s*(\d+)?\s*-?\s*(.*)$/.exec(line);
    if (!m) continue;
    const isOk = m[1] === "ok";
    let name = (m[3] ?? "").trim();
    // A `# SKIP` / `# TODO` directive on a `not ok` is not a real failure.
    const directive = /#\s*(SKIP|TODO)\b/i.test(name);
    name = name.replace(/\s*#\s*(SKIP|TODO)\b.*$/i, "").trim() || "test";
    const passed = isOk || directive;
    cases.push({ name, passed, ...(passed ? {} : { output: line })});
  }
  return cases;
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
  opts: { timeoutMs?: number; cpuLimitSec?: number; maxOutputBytes?: number; envAllowlist?: readonly string[]; namespaceJail?: boolean; allowNet?: boolean; allowWritePaths?: readonly string[]; adapter?: ProcessIsolationAdapter } = {},
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
      ...(opts.allowNet ? { allowNet: opts.allowNet } : {}),
      ...(opts.allowWritePaths ? { allowWritePaths: opts.allowWritePaths } : {}),
      ...(opts.adapter ? { adapter: opts.adapter } : {}),
    });
}
