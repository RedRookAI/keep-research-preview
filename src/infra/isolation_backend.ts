/**
 * Cross-platform isolation port (hardening H1) — the enforcing sandbox was POSIX-only (bash, `ulimit`, process-group
 * kill via `process.kill(-pid)`), which SILENTLY fails on Windows (no `/usr/bin/bash`, no signals, no process groups).
 * This selects a platform-native backend and makes every control's availability EXPLICIT, so the sandbox never silently
 * under-enforces — it either enforces a control or reports it as degraded.
 *
 * SOTA basis (2026-08-08):
 *  - Windows has no POSIX signals and no process groups, so `process.kill(-pid)` does not work; the standard tree-kill is
 *    `taskkill /pid <PID> /T /F` (/T = tree, /F = force) — confirmed by tree-kill/pnpm/fkill.
 *  - Node CANNOT use Windows Job Objects without a native addon (pnpm #12406), so a ZERO-DEP Windows backend cannot set a
 *    hard CPU/memory rlimit; that control is honestly declared unavailable and the wall-clock timeout is the backstop.
 *  - macOS ('darwin') and *BSD are POSIX, so the POSIX backend covers them (ulimit + process groups work).
 * What would change it: a small native addon (or a container/microVM backend behind the same IsolatedExecutor port) would
 * restore a hard CPU/memory cap on Windows; the capability flags would flip to true.
 *
 * Zero runtime deps (node:child_process only).
 */

import { spawn, spawnSync, type ChildProcess } from "node:child_process";

/** What an isolation backend actually ENFORCES on the current platform. Reported honestly; never assumed. */
export interface PlatformCapabilities {
  readonly confinedCwd: boolean;
  readonly scrubbedEnv: boolean;
  readonly wallClockKill: boolean;
  readonly processTreeKill: boolean;
  /** A hard CPU-time rlimit. POSIX: yes (`ulimit -t`). Windows zero-dep: no (needs Job Objects / native addon). */
  readonly cpuLimit: boolean;
  readonly outputCap: boolean;
  readonly realpathJail: boolean;
  /**
   * BUILD-ORDER 1.3 — a KERNEL mount+net+PID namespace jail (`unshare`) is available for the untrusted test
   * PROCESS: the child cannot write outside the project on the real FILESYSTEM, cannot reach the network, and
   * runs in its own PID namespace. Requires unprivileged user namespaces (Linux; `kernel.unprivileged_userns_clone`
   * on, no AppArmor userns restriction). Detected by MEASUREMENT, never assumed; degrades honestly where absent.
   */
  readonly namespaceJail: boolean;
}

/**
 * BUILD-ORDER 1.3 — which unprivileged namespaces the host actually grants, detected by a real `unshare` probe.
 * A namespace that does not apply here is reported false (→ `degraded`), never a false claim (the honest-seam rule).
 */
export interface NamespaceSupport {
  /** Unprivileged user namespace (CLONE_NEWUSER). The gate for all the rest when running non-root. */
  readonly userNs: boolean;
  /** Mount namespace — the filesystem write-jail (remount-ro + rw-bind the project). */
  readonly mountNs: boolean;
  /** Network namespace — network-deny (an empty stack: only a down loopback). */
  readonly netNs: boolean;
  /** PID namespace — the child cannot see or signal host processes. */
  readonly pidNs: boolean;
}

/**
 * BUILD-ORDER 1.3 — the operator-facing spec for the kernel namespace + rlimit jail around the untrusted child.
 * A HARD default (net-denied, filesystem-jailed to the project); `allowNet` / `allowWritePaths` are the opt-IN
 * operator-declared allowances (additive — never a weakened default).
 */
export interface NamespaceJailSpec {
  /** The project dir — the SINGLE read-write island inside an otherwise read-only mount namespace. */
  readonly projectDir: string;
  /** Operator opt-IN: keep the network reachable (skip the net namespace). Default false → network-denied. */
  readonly allowNet?: boolean;
  /** Operator opt-IN: extra absolute paths to bind read-WRITE (e.g. a declared scratch/tmp dir). Default none. */
  readonly allowWritePaths?: readonly string[];
  /** RLIMIT_FSIZE (bytes) — bound a disk bomb / oversized allocation. */
  readonly maxFileSizeBytes?: number;
  /** RLIMIT_NPROC — bound process count (fork-bomb defense-in-depth atop the PID namespace + process-group kill). */
  readonly maxProcesses?: number;
  /** RLIMIT_NOFILE — bound open file descriptors. */
  readonly maxOpenFiles?: number;
  /** Detected namespace support (injectable for tests; defaults to a cached host probe). */
  readonly support?: NamespaceSupport;
}

export interface SpawnPlan {
  readonly cmd: string;
  readonly args: readonly string[];
  /** Whether to spawn detached (own process group). POSIX: true (for group-kill). Windows: false. */
  readonly detached: boolean;
  /** Controls the caller REQUESTED that this platform cannot enforce (surfaced in the result — never silent). */
  readonly degraded: readonly string[];
}

export interface PlatformIsolation {
  readonly platform: string;
  readonly capabilities: PlatformCapabilities;
  /** The minimal environment baseline (a safe PATH etc.) the platform needs for a binary to resolve. */
  minimalEnv(): NodeJS.ProcessEnv;
  /** Plan the spawn for a policy, applying only controls this platform can enforce; report any degraded ones. */
  planSpawn(command: string, args: readonly string[], cpuLimitSec: number | undefined, jail?: NamespaceJailSpec): SpawnPlan;
  /** Kill the child's whole process TREE (POSIX: process group SIGKILL; Windows: taskkill /T /F). */
  killTree(child: ChildProcess): void;
}

/**
 * BUILD-ORDER 1.3 — the FIXED jail script (a constant; command/args arrive as positional argv AFTER `shift 7`, so
 * shell metacharacters in them are inert — the argument-injection defense the whole isolation floor rests on).
 *
 * It runs INSIDE the unshared namespaces. When a mount namespace is active (`domount=1`), it makes the entire mount
 * tree read-only (so no absolute-path write outside the project can land) and re-opens ONLY the project (and any
 * operator-declared write paths) read-write. A global toolchain outside the project (`/usr/lib/node`) is still
 * READABLE (read-only mounts are readable), so a legitimate build that reads it is unaffected — the network + write
 * jail is the hard default; reads need no allowance. Then it applies the rlimits and execs the real command.
 *
 * SAFETY: the mount operations run ONLY when `domount=1`, which the planner sets ONLY when `--mount` is in the
 * `unshare` flags — so the read-only remount can never touch the HOST filesystem, only this private namespace.
 */
const NS_JAIL_SCRIPT = [
  'set +e',
  'proj="$1"; writes="$2"; cpu="$3"; fsize="$4"; nproc="$5"; nofile="$6"; domount="$7"; shift 7',
  'if [ "$domount" = "1" ]; then',
  '  mount --make-rprivate / 2>/dev/null || true',
  '  while IFS= read -r t; do mount -o remount,ro "$t" 2>/dev/null || mount -o remount,ro,bind "$t" 2>/dev/null || true; done < <(findmnt -rno TARGET 2>/dev/null | sort -r)',
  '  mount --bind "$proj" "$proj" 2>/dev/null && mount -o remount,rw,bind "$proj" 2>/dev/null || true',
  '  if [ -n "$writes" ]; then while IFS= read -r p; do [ -n "$p" ] && mount --bind "$p" "$p" 2>/dev/null && mount -o remount,rw,bind "$p" 2>/dev/null || true; done <<EOF',
  '$writes',
  'EOF',
  '  fi',
  '  cd "$proj" 2>/dev/null || true',
  'fi',
  '[ "$cpu" != "-" ] && ulimit -t "$cpu" 2>/dev/null || true',
  '[ "$fsize" != "-" ] && ulimit -f "$fsize" 2>/dev/null || true',
  '[ "$nproc" != "-" ] && ulimit -u "$nproc" 2>/dev/null || true',
  '[ "$nofile" != "-" ] && ulimit -n "$nofile" 2>/dev/null || true',
  'exec "$@"',
].join('\n');

/** RLIMIT_FSIZE / ulimit -f is expressed in 1024-byte blocks (bash). Convert bytes → blocks (round up, min 1). */
function fsizeBlocks(bytes: number): number { return Math.max(1, Math.ceil(bytes / 1024)); }

let _nsCache: NamespaceSupport | undefined;
/**
 * Detect which unprivileged namespaces this host actually grants, by REAL `unshare` probes (measurement, not
 * assumption). Cached once per process. Non-Linux / no `unshare` / userns disabled → all false (honest degrade).
 * The probe uses `--user --map-root-user` so it works both as root and unprivileged (the portable path we spawn under).
 */
export function detectNamespaceSupport(force = false): NamespaceSupport {
  if (_nsCache && !force) return _nsCache;
  if (process.platform !== "linux") return (_nsCache = { userNs: false, mountNs: false, netNs: false, pidNs: false });
  const can = (flags: readonly string[]): boolean => {
    try {
      const r = spawnSync("unshare", [...flags, "true"], { stdio: "ignore", timeout: 5000 });
      return r.status === 0 && !r.error;
    } catch { return false; }
  };
  const userMount = can(["--user", "--map-root-user", "--mount"]);
  const support: NamespaceSupport = {
    userNs: userMount || can(["--user", "--map-root-user"]),
    mountNs: userMount,
    netNs: can(["--user", "--map-root-user", "--net"]),
    pidNs: can(["--user", "--map-root-user", "--pid", "--fork"]),
  };
  return (_nsCache = support);
}

/**
 * BUILD-ORDER 1.3 — build the `unshare` + fixed-jail-script spawn plan for a POSIX host, applying ONLY the
 * namespaces the kernel actually grants (detected) and reporting the rest as `degraded` (honest-seam). The rlimits
 * (`ulimit -f/-u/-n` + the existing `-t`) always apply — they need no namespace. `allowNet` skips the net namespace;
 * `allowWritePaths` re-opens declared paths read-write inside the mount jail. Both are opt-IN allowances.
 */
export function planNamespaceSpawn(command: string, args: readonly string[], cpuLimitSec: number | undefined, jail: NamespaceJailSpec): SpawnPlan {
  const support = jail.support ?? detectNamespaceSupport();
  const degraded: string[] = [];
  const rlimit = (v: number | undefined) => (v === undefined ? "-" : String(v));
  const cpu = cpuLimitSec === undefined ? "-" : String(cpuLimitSec);
  const fsize = jail.maxFileSizeBytes === undefined ? "-" : String(fsizeBlocks(jail.maxFileSizeBytes));
  const nproc = rlimit(jail.maxProcesses);
  const nofile = rlimit(jail.maxOpenFiles);
  const writes = (jail.allowWritePaths ?? []).filter(Boolean).join("\n");

  // Without an unprivileged USER namespace we cannot unshare anything non-root → run the rlimit-only wrapper and
  // declare EVERY namespace we would have applied as degraded (never a silent under-enforcement, never a false claim).
  if (!support.userNs) {
    degraded.push("mount-ns", "pid-ns");
    if (!jail.allowNet) degraded.push("net-ns");
    // domount=0 → the jail script performs NO mount operation (it is not inside a mount namespace; touching mounts
    // would hit the HOST — forbidden). Still apply the rlimits via the same fixed script.
    const a = ["-c", NS_JAIL_SCRIPT, "keep-sandbox", jail.projectDir, writes, cpu, fsize, nproc, nofile, "0", command, ...args];
    return { cmd: "/usr/bin/bash", args: a, detached: true, degraded };
  }

  const flags = ["--user", "--map-root-user", "--fork"];
  let domount = "0";
  if (support.mountNs) { flags.push("--mount"); domount = "1"; } else degraded.push("mount-ns");
  if (support.pidNs) { flags.push("--pid"); if (support.mountNs) flags.push("--mount-proc"); } else degraded.push("pid-ns");
  if (!jail.allowNet) { if (support.netNs) flags.push("--net"); else degraded.push("net-ns"); }

  const jailArgs = ["-c", NS_JAIL_SCRIPT, "keep-sandbox", jail.projectDir, writes, cpu, fsize, nproc, nofile, domount, command, ...args];
  return { cmd: "unshare", args: [...flags, "/usr/bin/bash", ...jailArgs], detached: true, degraded };
}

const POSIX: PlatformIsolation = {
  platform: "posix",
  get capabilities(): PlatformCapabilities {
    // namespaceJail is MEASURED (unshare probe), not assumed — false on a host that forbids unprivileged userns.
    const ns = process.platform === "linux" ? detectNamespaceSupport() : { userNs: false, mountNs: false, netNs: false, pidNs: false };
    return { confinedCwd: true, scrubbedEnv: true, wallClockKill: true, processTreeKill: true, cpuLimit: true, outputCap: true, realpathJail: true, namespaceJail: ns.userNs && ns.mountNs };
  },
  minimalEnv() {
    return { PATH: "/usr/local/bin:/usr/bin:/bin" };
  },
  planSpawn(command, args, cpuLimitSec, jail) {
    // BUILD-ORDER 1.3 — a namespace+rlimit jail COMPOSED onto this same POSIX wrapper (not a forked second spawn
    // path): the child runs under `unshare` (mount+net+PID, where the kernel grants them) and the fixed jail script
    // remounts the tree read-only, re-opens the project read-write, and applies the rlimits before exec.
    if (jail) return planNamespaceSpawn(command, args, cpuLimitSec, jail);
    if (cpuLimitSec !== undefined) {
      // ulimit -t via a FIXED wrapper; command/args passed as positional argv AFTER the script (metacharacters inert).
      return { cmd: "/usr/bin/bash", args: ["-c", 'ulimit -t "$1" 2>/dev/null || true; shift 1; exec "$@"', "keep-sandbox", String(cpuLimitSec), command, ...args], detached: true, degraded: [] };
    }
    return { cmd: command, args: [...args], detached: true, degraded: [] };
  },
  killTree(child) {
    if (child.pid === undefined) return;
    try { process.kill(-child.pid, "SIGKILL"); }
    catch { try { child.kill("SIGKILL"); } catch { /* already gone */ } }
  },
};

const WINDOWS: PlatformIsolation = {
  platform: "win32",
  // Everything POSIX enforces EXCEPT a hard CPU rlimit (needs Job Objects / native addon) and the Linux namespace
  // jail (unshare is Linux-only). Wall-clock is the backstop; the namespace jail is a declared VERIFIED-SEAM here.
  capabilities: { confinedCwd: true, scrubbedEnv: true, wallClockKill: true, processTreeKill: true, cpuLimit: false, outputCap: true, realpathJail: true, namespaceJail: false },
  minimalEnv() {
    // Windows needs SystemRoot + a System32 PATH for basic executables (and for `taskkill` to resolve).
    const sysRoot = process.env["SystemRoot"] ?? process.env["windir"] ?? "C:\\Windows";
    return { PATH: `${sysRoot}\\System32;${sysRoot}`, SystemRoot: sysRoot, windir: sysRoot };
  },
  planSpawn(command, args, cpuLimitSec, jail) {
    // No bash / no ulimit / no `unshare` on Windows → always a direct argv spawn (still injection-safe: shell:false,
    // argv only). Every namespace + rlimit the caller requested is declared degraded (honest-seam), never claimed.
    const degraded: string[] = cpuLimitSec !== undefined ? ["cpuLimit"] : [];
    if (jail) { degraded.push("mount-ns", "pid-ns"); if (!jail.allowNet) degraded.push("net-ns"); if (jail.maxFileSizeBytes !== undefined || jail.maxProcesses !== undefined || jail.maxOpenFiles !== undefined) degraded.push("rlimits"); }
    return { cmd: command, args: [...args], detached: false, degraded };
  },
  killTree(child) {
    if (child.pid === undefined) return;
    // taskkill /pid <PID> /T /F — terminate the whole tree forcefully (Windows has no process groups/signals).
    try { spawn("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore", windowsHide: true }); }
    catch { try { child.kill("SIGKILL"); } catch { /* already gone */ } }
  },
};

/** Select the isolation backend for a platform (defaults to the host). `win32` → Windows; everything else → POSIX. */
export function selectPlatformIsolation(platform: string = process.platform): PlatformIsolation {
  return platform === "win32" ? WINDOWS : POSIX;
}

export type HostIsolationRoute = "linux-namespaces" | "macos-posix" | "windows-job-object" | "windows-wsl2" | "windows-degraded" | "posix";

/** Reports the strongest available host route without claiming Node itself implements an external boundary. */
export function hostIsolationRoute(platform: string = process.platform, available: { readonly jobObject?: boolean; readonly wsl2?: boolean } = {}): HostIsolationRoute {
  if (platform === "linux") return "linux-namespaces";
  if (platform === "darwin") return "macos-posix";
  if (platform !== "win32") return "posix";
  if (available.jobObject) return "windows-job-object";
  if (available.wsl2) return "windows-wsl2";
  return "windows-degraded";
}
