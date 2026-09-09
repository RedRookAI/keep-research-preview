/**
 * Process-execution fallback with argv spawning, environment scrubbing, deadlines
 * and bounded captured output. See SECURITY.md for the deployment claim boundary.
 *
 *   - argv-only spawning (never a caller-built shell command string),
 *   - an explicit working directory, which alone is NOT a filesystem jail,
 *   - a SCRUBBED environment (secrets scoping — only an explicit allowlist passes),
 *   - a wall-clock timeout using the selected platform's process-tree termination,
 *   - OUTPUT byte caps (memory/disk-bomb mitigation).
 *
 * These controls do not impose a hard resident-memory limit or guarantee that
 * hostile descendants cannot escape a process group. Namespace/stronger isolation
 * depends on the explicitly configured backend and its reported enforcement.
 *
 * Provides a kill-switch-compatible terminate() so the Phase 2 KillSwitch can stop a
 * running sandboxed process out-of-band.
 */

import { spawn } from "node:child_process";
import { selectPlatformIsolation, type PlatformIsolation, type PlatformCapabilities, type NamespaceJailSpec } from "./isolation_backend.js";
import { realpathSync } from "node:fs";
import { isAbsolute as pathIsAbsolute, join as pathJoin, relative as pathRelative, resolve as pathResolve, dirname as pathDirname, basename as pathBasename } from "node:path";

export interface IsolationPolicy {
  /** Working directory; setting cwd alone does not restrict filesystem access. */
  readonly cwd: string;
  /** Wall-clock timeout (ms) before the process group is killed. */
  readonly timeoutMs: number;
  /** Environment variables allowed through (secrets scoping). Default: none. */
  readonly envAllowlist?: readonly string[];
  /** Max bytes captured from stdout/stderr before truncation (bomb mitigation). */
  readonly maxOutputBytes?: number;
  /**
   * CPU-time cap in seconds — enforced via `ulimit -t`. Bounds a CPU spinner independent of wall-clock.
   * (A hard per-process MEMORY cap is deliberately NOT offered here: `ulimit -v` kills common runtimes like Node at
   * startup because V8 reserves large virtual address ranges. A deadline and captured-output cap do not bound
   * arbitrary child allocations. Hard memory containment requires a separately configured and qualified kernel
   * boundary; an OS OOM kill is not evidence that this adapter enforced a memory policy.)
   */
  readonly cpuLimitSec?: number;
  /**
   * BUILD-ORDER 1.3 — bound the child with a KERNEL mount+net+PID namespace jail (`unshare`) plus rlimits
   * (RLIMIT_FSIZE/NPROC/NOFILE). These specific controls do not imply a hard memory cap or complete host-resource
   * protection. Applied ONLY where the kernel grants the namespaces;
   * whatever does not apply is surfaced in `degraded` (honest-seam), never a silent under-enforcement. The
   * network/filesystem jail is a HARD default; `allowNet`/`allowWritePaths` are opt-IN operator allowances.
   */
  readonly namespaceJail?: NamespaceJailSpec;
}

export interface IsolatedRunResult {
  readonly code: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly stdout: string;
  readonly stderr: string;
  /** Exact captured bytes, before UTF-8 presentation decoding. Authority protocols must use these. */
  readonly stdoutBytes?: Buffer;
  readonly stderrBytes?: Buffer;
  readonly timedOut: boolean;
  readonly truncated: boolean;
  readonly durationMs: number;
  /** Controls the caller requested that this platform could not enforce (e.g. ["cpuLimit"] on Windows). Never silent. */
  readonly degraded?: readonly string[];
}

/** A running isolated process with an out-of-band terminate() (for the kill-switch). */
export interface IsolatedProcess {
  readonly pid: number | undefined;
  /** Kill the whole process group (out-of-band; does not call into the process). */
  terminate: () => void;
  readonly done: Promise<IsolatedRunResult>;
}

export class ProcessIsolationAdapter {
  private readonly iso: PlatformIsolation;
  constructor(private readonly clock: () => number = () => Date.now(), platform?: string) {
    this.iso = selectPlatformIsolation(platform);
  }

  /** What this platform's backend actually ENFORCES (reported honestly; never assumed). */
  get capabilities(): PlatformCapabilities { return this.iso.capabilities; }
  /** The selected backend's platform label. */
  get platform(): string { return this.iso.platform; }

  /** Build the scrubbed environment: only allowlisted vars pass through. */
  private scrubEnv(allowlist: readonly string[] = []): NodeJS.ProcessEnv {
    const env: NodeJS.ProcessEnv = {};
    for (const key of allowlist) {
      const v = process.env[key];
      if (v !== undefined) env[key] = v;
    }
    // Platform-appropriate minimal baseline (a safe PATH etc.) so the binary + kill tools resolve — nothing else.
    for (const [k, v] of Object.entries(this.iso.minimalEnv())) if (env[k] === undefined && v !== undefined) env[k] = v;
    return env;
  }

  /**
   * Start `command` with `args` (argv-only — no shell). Returns an IsolatedProcess
   * whose `done` resolves with the captured result. On timeout the whole process
   * group is killed. `command`/`args` are passed as an argv array, so shell
   * metacharacters in args are inert (argument-injection defense).
   */
  start(command: string, args: readonly string[], policy: IsolationPolicy): IsolatedProcess {
    const start = this.clock();
    const maxBytes = policy.maxOutputBytes ?? 1024 * 1024;

    // Platform-native spawn plan: POSIX applies a ulimit CPU wrapper; Windows spawns direct and reports cpuLimit as
    // degraded (no Job Objects without a native addon). Either way, argv-only (shell:false) keeps metacharacters inert.
    const plan = this.iso.planSpawn(command, args, policy.cpuLimitSec, policy.namespaceJail);

    const child = spawn(plan.cmd, [...plan.args], {
      cwd: policy.cwd,
      env: this.scrubEnv(policy.envAllowlist),
      // POSIX process-group termination; this alone does not prevent a hostile child from leaving that group.
      detached: plan.detached,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
      shell: false, // NEVER a shell string — argv only (the POSIX wrapper script is a fixed constant, not caller input).
    });

    let stdout = "";
    let stderr = "";
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutByteLength = 0;
    let stderrByteLength = 0;
    let truncated = false;
    let timedOut = false;

    const capture = (buf: Buffer, which: "out" | "err") => {
      const cur = which === "out" ? stdoutByteLength : stderrByteLength;
      if (cur >= maxBytes) {
        truncated = true;
        return;
      }
      const room = maxBytes - cur;
      const captured = Buffer.from(buf.subarray(0, Math.min(buf.length, room)));
      const text = captured.toString("utf8");
      if (buf.length > room) truncated = true;
      if (which === "out") { stdoutChunks.push(captured); stdoutByteLength += captured.length; stdout += text; }
      else { stderrChunks.push(captured); stderrByteLength += captured.length; stderr += text; }
    };
    child.stdout?.on("data", (b: Buffer) => capture(b, "out"));
    child.stderr?.on("data", (b: Buffer) => capture(b, "err"));

    const killGroup = () => this.iso.killTree(child);

    const timer = setTimeout(() => {
      timedOut = true;
      killGroup();
    }, policy.timeoutMs);

    const done = new Promise<IsolatedRunResult>((resolve) => {
      child.on("close", (code, signal) => {
        clearTimeout(timer);
        resolve({
          code,
          signal: signal ?? null,
          stdout,
          stderr,
          stdoutBytes: Buffer.concat(stdoutChunks),
          stderrBytes: Buffer.concat(stderrChunks),
          timedOut,
          truncated,
          durationMs: this.clock() - start,
          ...(plan.degraded.length ? { degraded: plan.degraded } : {}),
        });
      });
      child.on("error", (err) => {
        clearTimeout(timer);
        resolve({
          code: null,
          signal: null,
          stdout,
          stderr: stderr + `\n[spawn error: ${(err as Error).message}]`,
          stdoutBytes: Buffer.concat(stdoutChunks),
          stderrBytes: Buffer.concat(stderrChunks),
          timedOut,
          truncated,
          durationMs: this.clock() - start,
        });
      });
    });

    return { pid: child.pid, terminate: killGroup, done };
  }

  /** Convenience: run to completion and return the result. */
  async run(command: string, args: readonly string[], policy: IsolationPolicy): Promise<IsolatedRunResult> {
    return this.start(command, args, policy).done;
  }
}

/**
 * Realpath-resolved project jail: resolve symlinks on BOTH the project dir and the candidate, then require containment.
 * Stronger than a string-level check — it defeats symlink-out escapes (a `link → /etc` inside the project). A candidate
 * that does not exist yet is resolved via its nearest existing ancestor (so writes to new paths are still jailed).
 */
export function resolvedWithinProject(projectDir: string, candidate: string): boolean {
  const realBase = safeRealpath(projectDir);
  const abs = pathIsAbsolute(candidate) ? candidate : pathJoin(projectDir, candidate);
  const realCand = safeRealpath(abs);
  const rel = pathRelative(realBase, realCand);
  return rel === "" || (!rel.startsWith("..") && !pathIsAbsolute(rel));
}

function safeRealpath(p: string): string {
  let cur = pathResolve(p);
  const tail: string[] = [];
  for (;;) {
    try { return pathJoin(realpathSync(cur), ...tail.reverse()); }
    catch {
      const parent = pathDirname(cur);
      if (parent === cur) return pathResolve(p);
      tail.push(pathBasename(cur));
      cur = parent;
    }
  }
}
