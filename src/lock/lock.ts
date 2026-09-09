/**
 * DistributedLock port (Phase 0.5) — the coordination seam.
 *
 * The sealer (Round 8) and leader election require single-writer coordination.
 * This port abstracts it so the implementation is swappable:
 *  - Filesystem (below): atomic cross-process ownership for the durable single-host tier.
 *  - In-process (below): an async mutex only for explicitly ephemeral/test stores.
 *  - Postgres (future impl behind this port): transaction-level
 *    `pg_advisory_xact_lock` — self-cleans on commit/rollback (no leaked locks from
 *    crashed workers) and is safe under PgBouncer transaction pooling. This was the
 *    Aug-2026 SOTA re-verification refinement; the port makes it a drop-in.
 */

export interface DistributedLock {
  /**
   * Run `fn` while holding the named lock exclusively. Other callers of the same
   * key wait (FIFO) until the lock is released. The lock is always released, even
   * if `fn` throws.
   */
  withLock<T>(key: string, fn: () => Promise<T>): Promise<T>;
}

import { closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { join } from "node:path";

/** In-process FIFO async mutex keyed by lock name. Single-node tier. */
export class InProcessLock implements DistributedLock {
  private readonly tails = new Map<string, Promise<void>>();

  async withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.tails.get(key) ?? Promise.resolve();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    // The next waiter chains after this gate resolves.
    this.tails.set(
      key,
      prev.then(() => gate),
    );
    // Wait for all prior holders to finish.
    await prev;
    try {
      return await fn();
    } finally {
      release();
      // Clean up the map entry if we were the last in line.
      // (Best-effort; correctness does not depend on it.)
      queueMicrotask(() => {
        if (this.tails.get(key) === prev.then(() => gate)) {
          // no-op: reference identity won't match after chaining; left intentionally simple
        }
      });
    }
  }
}

/**
 * Zero-dependency cross-process lock for the filesystem Spine tier. `wx` is the ownership CAS; a crashed owner's
 * record is quarantined before reacquisition. Live contention waits boundedly and then refuses rather than allowing
 * two sealers. PostgreSQL deployments should continue to provide their advisory-lock implementation through the port.
 */
export class FileSystemLock implements DistributedLock {
  private readonly local = new InProcessLock();
  private readonly processStart = this.readProcessStart(process.pid);
  constructor(private readonly directory: string, private readonly timeoutMs = 30_000, private readonly pollMs = 25) {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const stat = lstatSync(directory);
    const expectedUid = typeof process.getuid === "function" ? process.getuid() : stat.uid;
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== expectedUid || (stat.mode & 0o077) !== 0) {
      throw new Error("filesystem lock directory kind, owner, or mode refused");
    }
  }

  private syncDirectory(): void {
    const fd = openSync(this.directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try { fsyncSync(fd); } finally { closeSync(fd); }
  }

  private path(key: string): string {
    return join(this.directory, `${createHash("sha256").update("keep.lock/v1\0").update(key).digest("hex")}.lock`);
  }

  private readProcessStart(pid: number): string | null {
    try {
      const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
      const close = stat.lastIndexOf(")");
      const fields = stat.slice(close + 2).split(" ");
      return fields[19] ?? null; // field 22 overall; slice begins at field 3.
    } catch { return null; }
  }

  private alive(pid: number, expectedStart: unknown): boolean {
    if (!Number.isSafeInteger(pid) || pid < 1) return false;
    try {
      process.kill(pid, 0);
      const actualStart = this.readProcessStart(pid);
      return typeof expectedStart !== "string" || actualStart === null || actualStart === expectedStart;
    }
    catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM"; }
  }

  private async acquire(path: string, token: string): Promise<void> {
    const started = Date.now();
    while (true) {
      try {
        const fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
        try { writeFileSync(fd, `${JSON.stringify({ schema: "keep.filesystem-lock/v1", pid: process.pid, processStart: this.processStart, token })}\n`); fsyncSync(fd); }
        finally { closeSync(fd); }
        this.syncDirectory();
        return;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      }
      let owner: { schema?: unknown; pid?: unknown; processStart?: unknown; token?: unknown } | undefined;
      try {
        const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
        try {
          const stat = fstatSync(fd);
          if (!stat.isFile() || (stat.mode & 0o077) !== 0) throw new Error("filesystem lock carrier kind/mode refused");
          owner = JSON.parse(readFileSync(fd, "utf8")) as { schema?: unknown; pid?: unknown; processStart?: unknown; token?: unknown };
        } finally { closeSync(fd); }
      } catch (error) {
        // A disappearing carrier may be a competing release. A present but hostile carrier is never stale-lock
        // evidence and must not become stealable after a timeout.
        if ((error as Error).message === "filesystem lock carrier kind/mode refused") throw error;
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
          if (existsSync(path)) throw new Error(`filesystem lock carrier cannot be verified: ${(error as Error).message}`);
        }
      }
      if (typeof owner?.pid === "number" && this.alive(owner.pid, owner.processStart)) {
        if (Date.now() - started >= this.timeoutMs) throw new Error("filesystem lock remained owned by a live process");
        await new Promise((resolve) => setTimeout(resolve, this.pollMs));
        continue;
      }
      // O_EXCL establishes ownership before the owner record is written. An empty/partial carrier may therefore be
      // a live acquirer, not a stale lock; never steal it until the full bounded acquisition window has elapsed.
      if (owner === undefined && Date.now() - started < this.timeoutMs) {
        await new Promise((resolve) => setTimeout(resolve, this.pollMs));
        continue;
      }
      try { renameSync(path, `${path}.stale-${process.pid}-${randomBytes(6).toString("hex")}`); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    }
  }

  async withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
    return await this.local.withLock(key, async () => {
      const path = this.path(key); const token = randomBytes(32).toString("hex");
      await this.acquire(path, token);
      let value: T | undefined;
      let primaryError: unknown;
      try { value = await fn(); }
      catch (error) { primaryError = error; }
      try {
        let current: { schema?: unknown; pid?: unknown; processStart?: unknown; token?: unknown };
        try {
          const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
          try {
            const stat = fstatSync(fd);
            if (!stat.isFile() || (stat.mode & 0o077) !== 0) throw new Error("filesystem lock carrier kind/mode refused");
            current = JSON.parse(readFileSync(fd, "utf8")) as typeof current;
          } finally { closeSync(fd); }
        }
        catch { throw new Error("filesystem lock ownership carrier disappeared before release"); }
        if (current.schema !== "keep.filesystem-lock/v1" || current.pid !== process.pid || current.processStart !== this.processStart || current.token !== token) throw new Error("filesystem lock ownership changed before release");
        unlinkSync(path);
        this.syncDirectory();
      }
      catch (releaseError) {
        if (primaryError !== undefined) throw new AggregateError([primaryError, releaseError], "locked operation and lock release both failed", { cause: primaryError });
        throw releaseError;
      }
      if (primaryError !== undefined) throw primaryError;
      return value as T;
    });
  }
}
