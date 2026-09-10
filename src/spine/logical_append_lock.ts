import { closeSync, constants, existsSync, fstatSync, fsyncSync, linkSync, mkdirSync, openSync, readFileSync, readlinkSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { ensureDurableDir, fsyncDir, NODE_IO } from "./durable_fs.js";

export class LogicalAppendBusyError extends Error {
  readonly code = "KEEP_LOGICAL_APPEND_BUSY";
}
export class LogicalAppendRecoveryError extends Error {
  readonly code = "KEEP_LOGICAL_APPEND_RECOVERY_REQUIRED";
}
export class LogicalAppendScanLimitError extends Error {
  readonly code = "KEEP_LOGICAL_APPEND_SCAN_LIMIT";
}

interface Owner {
  schema: "keep.logical-append-owner/v1";
  token: string;
  pid: number;
  boot: string | null;
  namespace: string | null;
  start: string | null;
}
const readText = (path: string): string | null => { try { return readFileSync(path, "utf8").trim(); } catch { return null; } };
function startOf(pid: number): string | null {
  const stat = readText(`/proc/${pid}/stat`);
  return stat === null ? null : stat.slice(stat.lastIndexOf(")") + 2).split(" ")[19] ?? null;
}
function namespaceOfSelf(): string | null { try { return readlinkSync("/proc/self/ns/pid"); } catch { return null; } }
function readOwner(path: string): Owner | undefined {
  let fd: number;
  try { fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw error; }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > 4096 || (stat.mode & 0o077) !== 0) throw new LogicalAppendRecoveryError("logical append owner carrier kind/size/mode invalid");
    let value: Owner;
    try { value = JSON.parse(readFileSync(fd, "utf8")) as Owner; }
    catch { throw new LogicalAppendRecoveryError("logical append owner identity JSON is malformed"); }
    if (value?.schema !== "keep.logical-append-owner/v1" || !/^[a-f0-9]{64}$/.test(value.token)
      || !Number.isSafeInteger(value.pid) || value.pid < 1
      || !(value.boot === null || (typeof value.boot === "string" && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value.boot)))
      || !(value.namespace === null || (typeof value.namespace === "string" && /^pid:\[[0-9]+\]$/.test(value.namespace)))
      || !(value.start === null || (typeof value.start === "string" && /^[0-9]+$/.test(value.start)))) {
      throw new LogicalAppendRecoveryError("logical append owner identity is malformed");
    }
    return value;
  } finally { closeSync(fd); }
}
function dead(owner: Owner, self: Owner): boolean {
  // Valid only on the declared single-host, coherent local-filesystem substrate.
  if (owner.boot !== null && self.boot !== null && owner.boot !== self.boot) return true;
  if (process.platform === "linux" && (owner.boot === null || self.boot === null
    || owner.namespace === null || owner.namespace !== self.namespace)) {
    throw new LogicalAppendBusyError("logical append owner process domain cannot be verified");
  }
  try { process.kill(owner.pid, 0); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ESRCH") return true;
    throw new LogicalAppendBusyError("logical append owner liveness cannot be verified");
  }
  const start = startOf(owner.pid);
  return owner.start !== null && start !== null && owner.start !== start;
}

/**
 * Serialize a complete FileSpineStore logical write, including recovery. Requires
 * one coherent local filesystem and a common host/process-identity domain. This
 * is synchronous polling (blocks the calling thread), not an async/distributed lock.
 * A live owner is never stolen on timeout. Same-process reentrancy is refused.
 *
 * Only an owner removes its own carrier. Recovery permanently fences a dead slot,
 * rereads its owner AFTER the fence, and advances only after quiescence. Delayed
 * old-slot contenders must check that fence before entry. Drained certificates
 * permit a validated floor hint; a fence alone does NOT permit skipping an owner.
 * Sidecars are persistent runtime state; do not remove/recycle them while in use.
 */
export function withLogicalAppendLock<T>(target: string, fn: () => T, options: { waitMs?: number; durable?: boolean } = {}): T {
  const waitMs = options.waitMs ?? 30_000;
  if (!Number.isSafeInteger(waitMs) || waitMs < 0 || waitMs > 300_000) throw new Error("logical append wait must be 0..300000 milliseconds");
  const dir = `${target}.append-lock`;
  const durable = options.durable !== false;
  if (durable) ensureDurableDir(NODE_IO, dir);
  else mkdirSync(dir, { recursive: true, mode: 0o700 });
  const syncDir = (): void => { if (durable) fsyncDir(NODE_IO, dir); };
  if (!statSync(dir).isDirectory()) throw new Error("logical append lock directory invalid");
  const self: Owner = { schema: "keep.logical-append-owner/v1", token: randomBytes(32).toString("hex"), pid: process.pid,
    boot: readText("/proc/sys/kernel/random/boot_id"), namespace: namespaceOfSelf(), start: startOf(process.pid) };
  const candidate = join(dir, `candidate-${self.token}`);
  writeFileSync(candidate, JSON.stringify(self) + "\n", { flag: "wx", mode: 0o600 });
  if (durable) { const fd = openSync(candidate, "r"); try { fsyncSync(fd); } finally { closeSync(fd); } }
  if (statSync(candidate).dev !== statSync(dir).dev) throw new Error("logical append carrier crosses filesystem device");
  const deadline = performance.now() + waitMs;
  const sleep = new Int32Array(new SharedArrayBuffer(4));
  let waitedOnOwner = false;
  const pause = (owner?: Owner): void => {
    waitedOnOwner = true;
    if (owner?.pid === self.pid && owner.start === self.start && owner.boot === self.boot) throw new LogicalAppendBusyError("logical append reentrant ownership refused");
    const remaining = deadline - performance.now();
    if (remaining <= 0) throw new LogicalAppendBusyError("logical append contention deadline reached; no owner displaced");
    Atomics.wait(sleep, 0, 0, Math.min(10, remaining));
  };
  const marker = (path: string): void => {
    let markerFd: number;
    try { markerFd = openSync(path, "wx", 0o600); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; markerFd = openSync(path, "r"); }
    try { if (durable) fsyncSync(markerFd); } finally { closeSync(markerFd); }
    syncDir();
  };
  const floorPath = join(dir, "floor");
  const hintedSlot = (): number => {
    const hint = readText(floorPath);
    if (hint !== null && /^(0|[1-9][0-9]*)$/.test(hint)) {
      const value = Number(hint);
      if (Number.isSafeInteger(value) && value < Number.MAX_SAFE_INTEGER
        && existsSync(join(dir, `retired-${value}`)) && existsSync(join(dir, `drained-${value}`))) return value + 1;
    }
    return 0;
  };
  let slot = hintedSlot(), iterations = 0;
  let held: string | undefined;
  try {
    for (;;) {
      if (iterations++ > 0 && performance.now() > deadline) {
        if (waitedOnOwner) throw new LogicalAppendBusyError("logical append contention deadline reached; no owner displaced");
        throw new LogicalAppendScanLimitError("logical append generation scan deadline reached; retained progress is retryable");
      }
      waitedOnOwner = false;
      slot = Math.max(slot, hintedSlot());
      const ownerPath = join(dir, `owner-${slot}`), retired = join(dir, `retired-${slot}`);
      if (existsSync(retired)) {
        marker(retired); // Make a just-observed fence durable before certifying drainage.
        const owner = readOwner(ownerPath);
        if (owner !== undefined && !dead(owner, self)) { pause(owner); continue; }
        marker(join(dir, `drained-${slot}`));
        if (hintedSlot() <= slot) {
          const temp = join(dir, `floor-${self.token}`);
          try {
            writeFileSync(temp, `${slot}\n`, { flag: "wx", mode: 0o600 });
            if (durable) { const floorFd = openSync(temp, "r"); try { fsyncSync(floorFd); } finally { closeSync(floorFd); } }
            // Advisory only: a concurrent lower rename can still win this race.
            // Reconsult the certified hint on every step; this is not a CAS.
            if (hintedSlot() <= slot) { renameSync(temp, floorPath); syncDir(); }
          } finally { try { unlinkSync(temp); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; } }
        }
        if (slot === Number.MAX_SAFE_INTEGER) throw new Error("logical append generation exhausted");
        slot++;
        continue;
      }
      try { linkSync(candidate, ownerPath); held = ownerPath; }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        const owner = readOwner(ownerPath);
        if (owner === undefined) continue;
        if (dead(owner, self)) {
          // An ordinary release followed by process exit must not burn a slot.
          if (readOwner(ownerPath)?.token === owner.token) marker(retired);
          continue;
        }
        pause(owner); continue;
      }
      syncDir();
      if (existsSync(retired)) { unlinkSync(ownerPath); held = undefined; syncDir(); continue; }
      return fn();
    }
  } finally {
    try {
      if (held !== undefined) {
        if (readOwner(held)?.token !== self.token) throw new Error("logical append ownership changed before release");
        unlinkSync(held); syncDir();
      }
    } finally {
      try { unlinkSync(candidate); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    }
  }
}
