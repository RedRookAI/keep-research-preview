/** Explicit Linux project boundary, using the already qualified Bubblewrap binary.
 * Host kernel/runtime and quiescent caller-owned trees remain trusted. This is not
 * a VM, a general syscall allowlist, or protection from same-uid host mutators.
 */
import { constants, openSync, closeSync, fstatSync, lstatSync, readFileSync, readlinkSync, readdirSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import type { NamespaceJailSpec, ProcessIsolationObservation } from "./isolation_backend.js";

const BWRAP_SHA256 = "52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712";
const MAX_ENTRIES = 100_000, MAX_ARGS_BYTES = 64 * 1024;
const WRAPPER = 'set -eu; cpu="$1"; size="$2"; procs="$3"; files="$4"; ' +
  'if [ "$cpu" != "-" ]; then ulimit -S -t "$cpu"; ulimit -H -t "$cpu"; fi; ' +
  'if [ "$size" != "-" ]; then ulimit -S -f "$size"; ulimit -H -f "$size"; fi; ' +
  'if [ "$procs" != "-" ]; then ulimit -S -u "$procs"; ulimit -H -u "$procs"; fi; ' +
  'if [ "$files" != "-" ]; then ulimit -S -n "$files"; ulimit -H -n "$files"; fi; ' +
  'launcher="$5"; shift 5; exec "$launcher" --args 5 -- "$@"';

function inside(root: string, path: string): boolean {
  const r = relative(root, path); return r === "" || (!isAbsolute(r) && r !== ".." && !r.startsWith(".." + sep));
}
function text(value: string): string {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) throw new Error("invalid required-jail string");
  return value;
}
function limit(value: number | undefined, blocks = false): string {
  if (value === undefined) return "-";
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("invalid required-jail resource limit");
  // Bash expresses file limits in KiB; never round above the approved bytes.
  if (blocks && value > 0 && value < 1024) throw new Error("required-jail positive file-size limit must be at least 1024 bytes");
  return String(blocks ? Math.floor(value / 1024) : value);
}
function protectedAncestors(path: string, invokingUid: number): void {
  for (let p = path; ; p = dirname(p)) {
    const s = lstatSync(p);
    if (!s.isDirectory() || (s.uid !== 0 && s.uid !== invokingUid) ||
        ((s.mode & 0o022) !== 0 && !(s.uid === 0 && (s.mode & 0o1000) !== 0))) {
      throw new Error("required-jail root has unprotected ancestry");
    }
    if (p === dirname(p)) break;
  }
}

// x86_64 only: reject other ABIs, asynchronous alternate socket dispatch, Unix
// socket creation and all Unix socketpair types except private STREAM/SEQPACKET.
// Keep bind/connect available for the operator's explicit network opt-in.
function filter(): Buffer {
  const rows = [[0x20,0,0,4],[0x15,1,0,0xc000003e],[0x06,0,0,0x80000000],
    [0x20,0,0,0],[0x45,0,1,0x40000000],[0x06,0,0,0x00050026],
    [0x15,0,1,425],[0x06,0,0,0x00050001],[0x15,0,1,426],[0x06,0,0,0x00050001],
    [0x15,0,1,427],[0x06,0,0,0x00050001],[0x15,0,3,41],
    [0x20,0,0,16],[0x15,0,1,1],[0x06,0,0,0x00050001],
    [0x20,0,0,0],[0x15,0,7,53],[0x20,0,0,16],[0x15,0,5,1],
    [0x20,0,0,24],[0x54,0,0,15],[0x15,2,0,1],[0x15,1,0,5],
    [0x06,0,0,0x00050001],[0x06,0,0,0x7fff0000]];
  const bytes = Buffer.alloc(rows.length * 8);
  rows.forEach(([op,jt,jf,k], i) => { bytes.writeUInt16LE(op!,i*8); bytes[i*8+2]=jt!; bytes[i*8+3]=jf!; bytes.writeUInt32LE(k!,i*8+4); });
  return bytes;
}

export interface RequiredJailLaunch {
  readonly cmd: string;
  readonly args: readonly string[];
  /** Child slots3/4/5 are filter/status/options pipes; source roots start at6.
   * Launcher descriptors stay in the parent until status/termination, not the task.
   */
  readonly mounts: readonly number[];
  readonly filterBytes: Buffer;
  readonly argumentBytes: Buffer;
  readonly observation: ProcessIsolationObservation;
  close(): void;
  completed(status: Buffer, ended: boolean, code: number | null, signal: NodeJS.Signals | null): ProcessIsolationObservation;
}

export function prepareRequiredJail(command: string, args: readonly string[], jail: NamespaceJailSpec,
  cpuLimitSec: number | undefined, env: NodeJS.ProcessEnv, deadline: number): RequiredJailLaunch {
  if (process.platform !== "linux" || process.arch !== "x64") throw new Error("required project jail needs the qualified Linux x64 backend");
  const descriptors: number[] = [];
  let closed = false;
  const close = () => { if (closed) return; closed = true; for (const fd of descriptors) closeSync(fd); };
  const checkTime = () => { if (Date.now() >= deadline) throw new Error("required-jail admission deadline elapsed"); };
  const pin = (path: string, directory: boolean) => {
    const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | (directory ? constants.O_DIRECTORY : 0));
    descriptors.push(fd); return fd;
  };
  try {
    checkTime(); text(command);
    if (jail.allowNet !== undefined && typeof jail.allowNet !== "boolean") throw new Error("required-jail allowNet must be boolean");
    for (const arg of args) if (typeof arg !== "string" || arg.includes("\0")) throw new Error("invalid required-jail argument");
    const limits = [limit(cpuLimitSec), limit(jail.maxFileSizeBytes, true), limit(jail.maxProcesses), limit(jail.maxOpenFiles)];
    const uid = process.getuid!();
    const trustedBinary = (path: string) => {
      const p = realpathSync(path); protectedAncestors(dirname(p), 0);
      const fd = pin(p, false), s = fstatSync(fd);
      if (!s.isFile() || s.uid !== 0 || (s.mode & 0o6022) !== 0 || (s.mode & 0o111) === 0) throw new Error("untrusted required-jail launcher");
      return fd;
    };
    const shell = trustedBinary("/usr/bin/bash"), launcher = trustedBinary("/usr/bin/bwrap");
    if (createHash("sha256").update(readFileSync(launcher)).digest("hex") !== BWRAP_SHA256) throw new Error("required-jail launcher identity mismatch");
    for (const [alias, target] of [["/bin", "usr/bin"], ["/lib", "usr/lib"], ["/lib64", "usr/lib64"]]) {
      if (readlinkSync(alias!) !== target) throw new Error("required jail needs the qualified merged-/usr layout");
    }
    const canonical = (p: string) => {
      text(p); if (!isAbsolute(p)) throw new Error("required-jail roots must be absolute");
      const real = realpathSync(p);
      if (real !== resolve(p)) throw new Error("required-jail root must name its canonical directory");
      return real;
    };
    const writes = [...new Set([jail.projectDir, ...(jail.allowWritePaths ?? [])].map(canonical))];
    const reads = [...new Set((jail.readOnlyPaths ?? []).map(canonical))].filter(p => !inside("/usr", p));
    if (writes.length + reads.length > 32) throw new Error("too many required-jail roots");
    const protectedRoots = ["/usr", "/proc", "/dev", "/sys"];
    const module = fileURLToPath(import.meta.url);
    for (const p of [...writes, ...reads]) {
      if (["/", "/tmp", "/run"].includes(p) || protectedRoots.some(r => inside(r, p) || inside(p, r))) throw new Error("required-jail root conflicts with trusted layout");
    }
    for (const p of writes) if (inside(p, module)) throw new Error("required-jail writable root contains Keep's own runtime");
    for (const r of reads) if (writes.some(w => inside(r, w) || inside(w, r))) throw new Error("required-jail read/write roots overlap");
    const writeRoots = writes.filter(p => !writes.some(other => other !== p && inside(other, p)));
    const readRoots = reads.filter(p => !reads.some(other => other !== p && inside(other, p)));
    const mountPoints = readFileSync("/proc/self/mountinfo", "utf8").trim().split("\n").map(line =>
      line.split(" ")[4]!.replace(/\\([0-7]{3})/gu, (_, n: string) => String.fromCharCode(parseInt(n, 8))));
    let entries = 0;
    const mountFds: number[] = [];
    const mountArgs: string[] = [];
    const usr = pin("/usr", true); mountFds.push(usr); mountArgs.push("--ro-bind-fd", "6", "/usr");
    const captured: { path: string; fd: number }[] = [];
    for (const [roots, writable] of [[writeRoots, true], [readRoots, false]] as const) for (const path of roots) {
      checkTime();
      // An explicitly selected volume root is pinned and scanned just like an
      // ordinary directory. Mounts below that root remain outside this contract.
      if (mountPoints.some(point => point !== path && inside(path, point))) throw new Error("required-jail input has a nested host mount");
      const fd = pin(path, true), s = fstatSync(fd);
      if (writable) {
        protectedAncestors(path, uid);
        if (s.uid !== uid || (s.mode & 0o022) !== 0) throw new Error("required-jail writable root must be owned and protected");
      }
      const walk = (dir: string): void => {
        checkTime();
        for (const name of readdirSync(dir)) {
          checkTime(); if (++entries > MAX_ENTRIES) throw new Error("required-jail input exceeds admission entry bound");
          const child = join(dir, name), st = lstatSync(child);
          if (st.isSymbolicLink()) continue;
          if (!st.isDirectory() && !st.isFile()) throw new Error("required-jail input has a socket, FIFO or device");
          if (writable && ((st.uid !== uid && st.uid !== 0) || (st.mode & 0o022) !== 0)) throw new Error("required-jail input has an unprotected writer");
          if (writable && st.isFile() && st.nlink !== 1) throw new Error("required-jail input has a shared inode (hard link)");
          if (st.isDirectory()) walk(child);
        }
      };
      walk(`/proc/self/fd/${fd}`);
      const slot = 6 + mountFds.length; mountFds.push(fd);
      mountArgs.push(writable ? "--bind-fd" : "--ro-bind-fd", String(slot), path);
      captured.push({ path, fd });
    }
    for (const { path, fd } of captured) {
      const named = lstatSync(path), pinned = fstatSync(fd);
      if (!named.isDirectory() || named.dev !== pinned.dev || named.ino !== pinned.ino) throw new Error("required-jail root changed during admission");
    }
    const argv = ["--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
      ...(!jail.allowNet ? ["--unshare-net"] : []), "--disable-userns", "--assert-userns-disabled",
      "--cap-drop", "ALL", "--new-session", "--die-with-parent",
      ...mountArgs.slice(0,3), "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
      "--tmpfs", "/tmp", "--tmpfs", "/run", "--dir", "/tmp/home", "--proc", "/proc", "--dev", "/dev",
      ...mountArgs.slice(3), "--chdir", canonical(jail.projectDir), "--json-status-fd", "4", "--seccomp", "3",
      "--clearenv"];
    for (const [key, value] of Object.entries(env)) if (value !== undefined) {
      text(key); if (key.includes("=") || value.includes("\0")) throw new Error("invalid required-jail environment");
      argv.push("--setenv", key, value);
    }
    // HOME belongs to this layout, even when the caller allowlists its host HOME.
    argv.push("--setenv", "HOME", "/tmp/home");
    // Bubblewrap's recursive --args parser consumes setup options only. Keep the
    // command in its ordinary argv, with no shell interpolation. Environment
    // values remain in the private options pipe, not the launcher command line.
    const argumentBytes = Buffer.from(argv.join("\0") + "\0");
    if (argumentBytes.length > MAX_ARGS_BYTES) throw new Error("required-jail arguments exceed bound");
    checkTime();
    const requestedRlimits = [cpuLimitSec !== undefined ? "cpuLimit" : "", jail.maxFileSizeBytes !== undefined ? "file-size" : "",
      jail.maxProcesses !== undefined ? "process-count" : "", jail.maxOpenFiles !== undefined ? "open-files" : ""].filter(Boolean);
    const observation: ProcessIsolationObservation = Object.freeze({ version: 1, basis: "launcher-status", namespacePolicy: "required",
      requestedNamespaces: Object.freeze(["mount-ns", "pid-ns", "ipc-ns", "uts-ns", ...(!jail.allowNet ? ["net-ns"] : [])]),
      degraded: Object.freeze(["required-setup-unverified"]), namespaceSetup: "unverified",
      requestedRlimits: Object.freeze(requestedRlimits), rlimitSetup: requestedRlimits.length ? "unverified" : "not-requested" });
    // Refer to pinned parent descriptors during launcher startup. Passing them
    // through stdio would clear CLOEXEC and leak them to the eventual task.
    // The parent retains custody until the status pipe proves bwrap started, or
    // the launch terminates. No pathname reopening or post-hash substitution.
    const parentFd = (fd: number) => `/proc/${process.pid}/fd/${fd}`;
    return { cmd: parentFd(shell), args: ["--noprofile", "--norc", "-c", WRAPPER, "keep-required-jail", ...limits, parentFd(launcher), command, ...args],
      mounts: mountFds, filterBytes: filter(), argumentBytes, observation, close,
      completed(status, ended, code, signal) {
        if (!ended || code === null || signal !== null || status.length > 8192) return observation;
        try {
          // The pinned launcher's private setup-finished pipe suppresses exit-code
          // on setup/exec failure. child-pid alone is insufficient. Task-controlled
          // stderr is not a substitute for that protocol, including on exit 1.
          const lines = status.toString("utf8").trim().split("\n").map(line => JSON.parse(line) as Record<string, unknown>);
          if (lines.length !== 2 || !Number.isSafeInteger(lines[0]?.["child-pid"]) || Number(lines[0]?.["child-pid"]) <= 0 ||
              Object.keys(lines[1]!).length !== 1 || lines[1]?.["exit-code"] !== code) return observation;
          return Object.freeze({ ...observation, degraded: Object.freeze([]), namespaceSetup: "launcher-confirmed",
            rlimitSetup: requestedRlimits.length ? "launcher-confirmed" : "not-requested" });
        } catch { return observation; }
      } };
  } catch (error) { close(); throw error; }
}
