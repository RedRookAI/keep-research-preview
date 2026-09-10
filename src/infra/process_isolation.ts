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
import { Writable, type Readable } from "node:stream";
import { prepareRequiredJail, type RequiredJailLaunch } from "./required_project_jail.js";
import { selectPlatformIsolation, processPlanObservation, type ProcessIsolationObservation, type PlatformIsolation, type PlatformCapabilities, type NamespaceJailSpec } from "./isolation_backend.js";
import { realpathSync } from "node:fs";
import { atDeadline, executionStopReason, type ExecutionContext } from "./execution_lifetime.js";
import { isAbsolute as pathIsAbsolute, join as pathJoin, relative as pathRelative, resolve as pathResolve, dirname as pathDirname, basename as pathBasename, sep as pathSep } from "node:path";

export interface IsolationPolicy extends ExecutionContext {
  /** Working directory; setting cwd alone does not restrict filesystem access. */
  readonly cwd: string;
  /** Wall-clock timeout (ms) before requesting process-tree termination. */
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
   * Omitted mode requests legacy best-effort setup. Explicit required mode uses
   * the qualified Linux launcher or refuses; setup observations remain local.
   */
  readonly namespaceJail?: NamespaceJailSpec;
}

export interface IsolatedRunResult {
  readonly code: number | null;
  readonly signal: NodeJS.Signals | null;
  /** UTF8 presentation of captured bytes; an incomplete terminal character uses U+FFFD. */
  readonly stdout: string;
  /** Same presentation rule, with a separate parent-side spawn diagnostic when applicable. */
  readonly stderr: string;
  /** Exact captured bytes, before UTF-8 presentation decoding. Authority protocols must use these. */
  readonly stdoutBytes?: Buffer;
  readonly stderrBytes?: Buffer;
  readonly timedOut: boolean;
  readonly truncated: boolean;
  readonly durationMs: number;
  readonly cancelled?: boolean;
  /** Direct child only; neither close nor a group signal proves all descendants stopped. */
  readonly completion?: "not-started" | "direct-child-closed" | "unconfirmed";
  readonly terminationError?: string;
  /** Controls the caller requested that this platform could not enforce (e.g. ["cpuLimit"] on Windows). Never silent. */
  readonly degraded?: readonly string[];
  readonly processIsolation?: ProcessIsolationObservation;
}

/** A running isolated process with an out-of-band terminate() (for the kill-switch). */
export interface IsolatedProcess {
  readonly pid: number | undefined;
  /** Request process-tree termination; inspect done for the observed outcome. */
  terminate: () => void;
  readonly done: Promise<IsolatedRunResult>;
}

export class ProcessIsolationAdapter {
  private readonly iso: PlatformIsolation;
  private readonly requestedPlatform: string;
  constructor(private readonly clock: () => number = () => Date.now(), platform?: string) {
    this.requestedPlatform = platform ?? process.platform;
    this.iso = selectPlatformIsolation(platform);
  }

  /** Backend features/probe availability, not proof of this run's setup. */
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
   * whose `done` resolves with the captured result. Timeout requests process-tree
   * termination and bounds observation, without claiming escaped descendants stopped.
   * `command`/`args` are passed as an argv array, so shell
   * metacharacters in args are inert (argument-injection defense).
   */
  start(command: string, args: readonly string[], policy: IsolationPolicy): IsolatedProcess {
    const start = this.clock();
    const maxBytes = policy.maxOutputBytes ?? 1024 * 1024;
    let processIsolation: ProcessIsolationObservation | undefined;
    const refuse = (reason: string, cancelled = false): IsolatedProcess => ({ pid: undefined, terminate() {}, done: Promise.resolve({
      code: null, signal: null, stdout: "", stderr: reason, stdoutBytes: Buffer.alloc(0), stderrBytes: Buffer.alloc(0), timedOut: false, cancelled, terminationError: reason,
      completion: "not-started", truncated: false, durationMs: this.clock() - start,
      ...(processIsolation ? { processIsolation, degraded: processIsolation.degraded } : {}),
    }) });
    const invalidTimeout = !Number.isFinite(policy.timeoutMs) || policy.timeoutMs < 0;
    const precheck = executionStopReason(policy);
    if (invalidTimeout || precheck) return refuse(precheck ?? "invalid execution timeout", policy.signal?.aborted === true);
    const deadline = Math.min(Date.now() + policy.timeoutMs, policy.deadline ?? Infinity);

    // Platform-native spawn plan: POSIX applies a ulimit CPU wrapper; Windows spawns direct and reports cpuLimit as
    // degraded (no Job Objects without a native addon). Either way, argv-only (shell:false) keeps metacharacters inert.
    let required: RequiredJailLaunch | undefined;
    processIsolation = processPlanObservation(policy.namespaceJail, policy.cpuLimitSec, [], "policy-refusal");
    if (policy.namespaceJail?.mode !== undefined && policy.namespaceJail.mode !== "required") return refuse("unsupported namespace-jail mode");
    if (policy.namespaceJail?.mode === "required") {
      if (this.requestedPlatform !== "linux") return refuse("required project jail needs the Linux backend");
      try { required = prepareRequiredJail(command, args, policy.namespaceJail, policy.cpuLimitSec, this.scrubEnv(policy.envAllowlist), deadline); }
      catch (error) { return refuse(error instanceof Error ? error.message : "required-jail preparation failed"); }
    }
    const plan = required ? { cmd: required.cmd, args: required.args, detached: true, degraded: [] as readonly string[] }
      : this.iso.planSpawn(command, args, policy.cpuLimitSec, policy.namespaceJail);
    processIsolation = processPlanObservation(policy.namespaceJail, policy.cpuLimitSec, plan.degraded);
    if (required) processIsolation = required.observation;

    const preparedStop = executionStopReason({ ...policy, deadline });
    if (preparedStop) { required?.close(); return refuse(preparedStop, policy.signal?.aborted === true); }

    let child: ReturnType<typeof spawn>;
    try { child = spawn(plan.cmd, [...plan.args], {
      cwd: required ? "/" : policy.cwd,
      env: required ? { PATH: "/usr/bin:/bin", LANG: "C" } : this.scrubEnv(policy.envAllowlist),
      // POSIX process-group termination; this alone does not prevent a hostile child from leaving that group.
      detached: plan.detached,
      stdio: required ? ["ignore", "pipe", "pipe", "pipe", "pipe", "pipe", ...required.mounts] : ["ignore", "pipe", "pipe"],
      windowsHide: true,
      shell: false, // NEVER a shell string — argv only (the POSIX wrapper script is a fixed constant, not caller input).
    }); } catch (error) { required?.close(); return refuse(error instanceof Error ? error.message : "spawn failed"); }

    let stderrDiagnostic = "";
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
      if (buf.length > room) truncated = true;
      if (which === "out") { stdoutChunks.push(captured); stdoutByteLength += captured.length; }
      else { stderrChunks.push(captured); stderrByteLength += captured.length; }
    };
    const captureOut = (b: Buffer) => capture(b, "out");
    const captureErr = (b: Buffer) => capture(b, "err");
    child.stdout?.on("data", captureOut);
    child.stderr?.on("data", captureErr);

    let cancelled = false;
    let stopped = false;
    let completed = false;
    let terminationError: string | undefined;
    let cancelTimer = () => {};
    let cancelGrace = () => {};
    const statusChunks: Buffer[] = [];
    let statusBytes = 0, statusEnded = false;
    let finish!: (code: number | null, signal: NodeJS.Signals | null, completion: "direct-child-closed" | "unconfirmed" | "not-started") => void;
    const stop = (timeout: boolean, cancellation = !timeout) => {
      if (completed || stopped) return;
      stopped = true; timedOut = timeout; cancelled = cancellation;
      cancelGrace = atDeadline(Date.now() + (policy.terminationGraceMs ?? 1000), () => finish(null, null, "unconfirmed"));
      try { this.iso.killTree(child); }
      catch (error) { terminationError = error instanceof Error ? error.message : String(error); }
    };
    const onAbort = () => stop(false);
    const done = new Promise<IsolatedRunResult>((resolve) => {
      finish = (code, signal, completion) => {
        if (completed) return;
        if (completion === "direct-child-closed" && Date.now() >= deadline) timedOut = true;
        completed = true;
        required?.close();
        cancelTimer(); cancelGrace(); policy.signal?.removeEventListener("abort", onAbort);
        child.stdout?.off("data", captureOut); child.stderr?.off("data", captureErr);
        if (completion === "unconfirmed") {
          // Release only our pipes/handle. Work may still continue; this is not
          // termination evidence and cannot revise the terminal result later.
          child.stdout?.destroy(); child.stderr?.destroy(); child.unref();
          if (required) for (const stream of child.stdio.slice(3)) {
            if (stream && typeof stream !== "number") stream.destroy();
          }
        }
        // A pipe read can end inside a UTF8 character. Decode each retained
        // byte stream once, including after truncation or interrupted completion.
        const stdoutBytes = Buffer.concat(stdoutChunks);
        const stderrBytes = Buffer.concat(stderrChunks);
        if (required && completion === "direct-child-closed" && !stopped && !timedOut && !terminationError) {
          processIsolation = required.completed(Buffer.concat(statusChunks), statusEnded, code, signal);
        }
        resolve({
          code,
          signal: signal ?? null,
          stdout: stdoutBytes.toString("utf8"),
          stderr: stderrBytes.toString("utf8") + stderrDiagnostic,
          stdoutBytes,
          stderrBytes,
          timedOut,
          cancelled,
          completion,
          ...(terminationError ? { terminationError } : {}),
          truncated,
          durationMs: this.clock() - start,
          ...(processIsolation ? { processIsolation } : {}),
          ...(plan.degraded.length ? { degraded: plan.degraded } : {}),
        });
      };
      child.on("close", (code, signal) => finish(code, signal ?? null, child.pid === undefined ? "not-started" : "direct-child-closed"));
      child.on("error", (err) => {
        terminationError = err.message;
        // A post-spawn error can mean a failed kill. Wait for close or bounded
        // observation expiry; never classify a still-live child as not started.
        if (child.pid === undefined) { stderrDiagnostic = `\n[spawn error: ${err.message}]`; finish(null, null, "not-started"); }
        else stop(false, false);
      });
    });
    if (required) {
      // Node supports arbitrary extra stdio slots; its overload tuple only names
      // the first five. Widen that tuple without inventing stream methods.
      const pipes: readonly (Readable | Writable | null | undefined)[] = child.stdio;
      const status = pipes[4];
      status?.on("data", (chunk: Buffer) => {
        required.close(); // The pinned launcher has executed; it owns its mount FDs now.
        const kept = Buffer.from(chunk.subarray(0, Math.max(0, 8193 - statusBytes)));
        statusChunks.push(kept); statusBytes += kept.length;
        if (statusBytes > 8192) { terminationError = "required-jail status exceeds bound"; stop(false, false); }
      });
      status?.once("end", () => { statusEnded = true; });
      for (const slot of [3,4,5]) pipes[slot]?.on("error", () => { terminationError = `required-jail control pipe ${slot} failed`; stop(false, false); });
      const filterInput = pipes[3], argumentInput = pipes[5];
      if (!(filterInput instanceof Writable) || !(argumentInput instanceof Writable) || !status) {
        terminationError = "required-jail control pipes unavailable"; stop(false, false);
      } else { filterInput.end(required.filterBytes); argumentInput.end(required.argumentBytes); }
    }
    policy.signal?.addEventListener("abort", onAbort, { once: true });
    // Abort may have occurred while synchronous spawn preparation acquired the handle.
    if (policy.signal?.aborted) stop(false);
    if (!completed) cancelTimer = atDeadline(deadline, () => stop(true));
    return { pid: child.pid, terminate: () => stop(false), done };
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
  // Only a complete parent component escapes; '..cache' is an ordinary child.
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${pathSep}`) && !pathIsAbsolute(rel));
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
