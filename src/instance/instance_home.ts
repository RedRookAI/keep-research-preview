/**
 * Theme 1 (Instance Isolation), Part 2 — InstanceHome + ownership lock.
 *
 * Two Keep instances sharing one home fight over the same state/lock files and fail in
 * boot-order-dependent ways (the OpenClaw "failures look random" trap). Fix: each
 * instance owns its own home directory, and startup ownership is enforced by a lockfile
 * carrying the owner PID + start time. A second boot on the same home REFUSES clearly
 * instead of racing.
 *
 * Stale-lock reclaim: if the lock's PID is no longer alive, the home is reclaimable — a
 * crashed instance never wedges its home forever. The lock is written atomically
 * (temp-then-rename). Zero deps (node:fs/os/path).
 */

import fs from "node:fs";
import path from "node:path";
import os from "node:os";

export interface InstanceLock {
  readonly pid: number;
  readonly startedAt: number;
  readonly instanceId: string;
}

export interface InstanceHome {
  readonly id: string;
  readonly root: string;
  readonly stateDir: string;
  readonly configPath: string;
  readonly lockPath: string;
  /** Release ownership (removes the lock if we own it). */
  release(): void;
}

/** The base directory holding all Keep instances (override for tests). */
export function keepBaseDir(override?: string): string {
  return override ?? path.join(os.homedir(), ".keep", "instances");
}

/** Homes currently held by THIS process (catches in-process double-acquire). */
const heldInProcess = new Set<string>();

/** Is a process alive? (signal 0 probes without sending a real signal.) */
function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    // ESRCH => no such process (dead). EPERM => alive but not ours (still alive).
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

function readLock(lockPath: string): InstanceLock | null {
  try {
    return JSON.parse(fs.readFileSync(lockPath, "utf8")) as InstanceLock;
  } catch {
    return null;
  }
}

/** Atomically write the lockfile (temp-then-rename so a reader never sees a partial). */
function writeLockAtomic(lockPath: string, lock: InstanceLock): void {
  const tmp = `${lockPath}.tmp.${process.pid}.${Date.now()}`;
  fs.writeFileSync(tmp, JSON.stringify(lock), { encoding: "utf8", mode: 0o600 });
  fs.renameSync(tmp, lockPath);
}

/**
 * Acquire (or create) an instance home and claim ownership. Throws a clear error if the
 * home is already owned by a LIVE instance; reclaims it if the prior owner is dead.
 */
export function acquireInstanceHome(instanceId: string, baseDirOverride?: string, now = Date.now()): InstanceHome {
  const base = keepBaseDir(baseDirOverride);
  const root = path.join(base, instanceId);
  const stateDir = path.join(root, "state");
  const configPath = path.join(root, "config.json");
  const lockPath = path.join(root, "owner.lock");

  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });

  const existing = readLock(lockPath);
  if (existing) {
    // Held by a live process (ours or another) -> refuse. A real double-boot is two
    // different processes, but re-acquiring an already-held home in-process is also a
    // bug we should surface, not silently allow. Only a DEAD prior owner is reclaimable.
    if (pidAlive(existing.pid) || heldInProcess.has(lockPath)) {
      throw new Error(
        `Keep instance "${instanceId}" is already running (pid ${existing.pid}, since ${new Date(existing.startedAt).toISOString()}). ` +
          `Each instance needs its own id — start a new project with a different id, or stop the running one first.`,
      );
    }
    // Prior owner is dead and not held here: reclaim the home (stale lock).
  }

  const lock: InstanceLock = { pid: process.pid, startedAt: now, instanceId };
  writeLockAtomic(lockPath, lock);
  heldInProcess.add(lockPath);

  return {
    id: instanceId,
    root,
    stateDir,
    configPath,
    lockPath,
    release() {
      const cur = readLock(lockPath);
      if (cur && cur.pid === process.pid) {
        try {
          fs.rmSync(lockPath, { force: true });
        } catch {
          /* best-effort */
        }
      }
      heldInProcess.delete(lockPath);
    },
  };
}

/** Whether an instance home is currently owned by a live process. */
export function isInstanceRunning(instanceId: string, baseDirOverride?: string): boolean {
  const lockPath = path.join(keepBaseDir(baseDirOverride), instanceId, "owner.lock");
  const lock = readLock(lockPath);
  return lock !== null && pidAlive(lock.pid);
}
