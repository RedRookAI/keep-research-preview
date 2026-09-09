/**
 * durable_fs — the shared, hardened durable-append + durable-directory primitives (Increment 12a/12b).
 *
 * ONE implementation of "write this line and make it survive a crash" so FileSpineStore (the chain) and
 * DurableWitnessExport (the exported root) cannot drift. Division of labor: `durableAppend` appends to an ALREADY-
 * EXISTING file (its write LOOPS to completion — a short write under ENOSPC/RLIMIT can never fsync-persist a torn line
 * and return success — then fsyncs the file DATA); making the file's/dir's DIRECTORY ENTRY durable on first creation is
 * the CALLER's job via `ensureDurableDir` + `fsyncDir` (both FileSpineStore and DurableWitnessExport pre-create their
 * files that way). `ensureDurableDir` handles the `mkdir -p` case: the PARENT of EVERY newly-created directory is
 * fsync'd (POSIX: fsyncing a file does not persist its just-created dir entry). Directory-fsync errors are CLASSIFIED —
 * only genuine "this platform does not support fsync on a directory" codes (EINVAL/EISDIR/ENOTSUP/EOPNOTSUPP) are
 * tolerated, everything else (EACCES/EPERM/EIO/ENOSPC) propagates fail-closed.
 * HONEST LIMIT: fsync's power-loss guarantee is the OS/filesystem contract (a lying drive / network FS weakens it) — a
 * named substrate seam, not something a zero-dep library can enforce.
 */
import { openSync, writeSync, fsyncSync, closeSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

/** The filesystem primitives the durable path uses — injectable so a test can pin that fsync runs and that a short
 *  write loops to completion. */
export interface DurableIO {
  openSync(path: string, flags: string): number;
  writeSync(fd: number, buffer: Uint8Array, offset: number, length: number): number;
  fsyncSync(fd: number): void;
  closeSync(fd: number): void;
}
export const NODE_IO: DurableIO = { openSync, writeSync, fsyncSync, closeSync };

/** Append a line fsync-durably: open('a') → write-ALL (loop) → fsync → close. Throws if a write makes no progress. */
export function durableAppend(io: DurableIO, path: string, line: string): void {
  const buf = Buffer.from(line, "utf8");
  const fd = io.openSync(path, "a");
  try {
    let off = 0;
    while (off < buf.length) {
      const n = io.writeSync(fd, buf, off, buf.length - off);
      if (!(n > 0)) throw new Error(`durableAppend made no write progress (wrote ${n} of ${buf.length - off} remaining bytes)`);
      off += n;
    }
    io.fsyncSync(fd);
  } finally { io.closeSync(fd); }
}

/** fsync a directory so a just-created entry within it is durable (POSIX). Best-effort ONLY for genuine platform
 *  "directory fsync unsupported" codes; an operational/permission failure (EACCES/EPERM/EIO/ENOSPC) PROPAGATES fail-closed. */
export function fsyncDir(io: DurableIO, dir: string): void {
  let fd: number | undefined;
  try { fd = io.openSync(dir, "r"); io.fsyncSync(fd); }
  catch (e) {
    const code = (e as { code?: string } | null)?.code;
    if (code !== "EINVAL" && code !== "EISDIR" && code !== "ENOTSUP" && code !== "EOPNOTSUPP") throw e;
  }
  finally { if (fd !== undefined) { try { io.closeSync(fd); } catch { /* ignore */ } } }
}

/** Create `dir` (recursive) and fsync the PARENT of every directory the creation actually made — walking from `dir` up
 *  to the first pre-existing ancestor — so a freshly `mkdir -p`'d tree's new entries are durable, not just the leaf. */
export function ensureDurableDir(io: DurableIO, dir: string): void {
  if (existsSync(dir)) return;
  const created: string[] = [];
  for (let cur = dir; !existsSync(cur); ) { created.push(cur); const parent = dirname(cur); if (parent === cur) break; cur = parent; }
  mkdirSync(dir, { recursive: true });
  for (const d of created) fsyncDir(io, dirname(d));
}
