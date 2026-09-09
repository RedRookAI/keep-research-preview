import { closeSync, constants, existsSync, fstatSync, fsyncSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { randomBytes } from "node:crypto";
import { ensureDurableDir, fsyncDir, NODE_IO } from "./durable_fs.js";

export class SyncFileMutationBusyError extends Error {
  readonly code = "KEEP_FILE_MUTATION_BUSY";
}

/**
 * Fail-fast cross-process exclusion for synchronous read/modify/write stores. A live contender
 * is refused rather than allowing stale state to overwrite newer authority. Dead owners are
 * quarantined and retried once; the random token prevents releasing another owner's carrier.
 */
export function withSyncFileMutationLock<T>(targetPath: string, fn: () => T, options: { readonly allowStaleTakeover?: boolean } = {}): T {
  const lockPath = `${targetPath}.mutation.lock`;
  const dir = dirname(lockPath);
  ensureDurableDir(NODE_IO, dir);
  const token = randomBytes(32).toString("hex");
  const readProcessStart = (pid: number): string | null => {
    try { const stat = readFileSync(`/proc/${pid}/stat`, "utf8"); const close = stat.lastIndexOf(")"); return stat.slice(close + 2).split(" ")[19] ?? null; }
    catch { return null; }
  };
  const processStart = readProcessStart(process.pid);
  const alive = (pid: number, expectedStart: unknown): boolean => {
    if (!Number.isSafeInteger(pid) || pid < 1) return false;
    try { process.kill(pid, 0); const actual = readProcessStart(pid); return typeof expectedStart !== "string" || actual === null || actual === expectedStart; }
    catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM"; }
  };
  const acquire = (): number => {
    let acquiredFd: number | undefined;
    try {
      acquiredFd = openSync(lockPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
      writeFileSync(acquiredFd, `${JSON.stringify({ schema: "keep.sync-file-lock/v1", pid: process.pid, processStart, token })}\n`);
      fsyncSync(acquiredFd); fsyncDir(NODE_IO, dir);
      return acquiredFd;
    } catch (error) {
      if (acquiredFd !== undefined) {
        try { closeSync(acquiredFd); } catch { /* preserve acquisition failure */ }
        try { unlinkSync(lockPath); fsyncDir(NODE_IO, dir); } catch { /* preserve acquisition failure */ }
      }
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      // Custody callers cannot infer exclusive ownership from a stale-carrier
      // read/rename race. Preserve the carrier for explicit reconciliation.
      if (options.allowStaleTakeover === false) throw new SyncFileMutationBusyError("file mutation is held by an existing carrier; takeover disabled");
      let owner: { schema?: unknown; pid?: unknown; processStart?: unknown; token?: unknown } | undefined;
      try {
        const ownerFd = openSync(lockPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
        try { const stat = fstatSync(ownerFd); if (!stat.isFile() || (stat.mode & 0o077) !== 0) throw new Error("file mutation lock carrier kind/mode refused"); owner = JSON.parse(readFileSync(ownerFd, "utf8")) as typeof owner; }
        finally { closeSync(ownerFd); }
      } catch (readError) { throw new Error(`file mutation lock carrier cannot be verified: ${(readError as Error).message}`); }
      if (owner === undefined || owner.schema !== "keep.sync-file-lock/v1" || typeof owner.pid !== "number" || typeof owner.token !== "string") throw new Error("file mutation lock is malformed or still being acquired");
      if (alive(owner.pid, owner.processStart)) throw new Error("file mutation is owned by a live process");
      const stalePath = `${lockPath}.stale-${process.pid}-${randomBytes(6).toString("hex")}`;
      renameSync(lockPath, stalePath); fsyncDir(NODE_IO, dir);
      unlinkSync(stalePath); fsyncDir(NODE_IO, dir);
      return acquire();
    }
  };
  const fd = acquire();
  let result: T | undefined; let primary: unknown;
  try { result = fn(); } catch (error) { primary = error; }
  let releaseFailure: unknown;
  try {
    closeSync(fd);
    const owner = JSON.parse(readFileSync(lockPath, "utf8")) as { schema?: unknown; pid?: unknown; processStart?: unknown; token?: unknown };
    if (owner.schema !== "keep.sync-file-lock/v1" || owner.pid !== process.pid || owner.processStart !== processStart || owner.token !== token) throw new Error("file mutation lock ownership changed before release");
    if (existsSync(lockPath)) unlinkSync(lockPath);
    fsyncDir(NODE_IO, dir);
  } catch (error) { releaseFailure = error; }
  if (primary !== undefined) throw primary;
  if (releaseFailure !== undefined) throw releaseFailure;
  return result as T;
}
