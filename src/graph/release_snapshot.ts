/** Closed-world release snapshots: total regular-file inventory with no ignore rules or link/special-file ambiguity. */
import { constants, closeSync, copyFileSync, fstatSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, readdirSync, rmSync, chmodSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";

export const RELEASE_SNAPSHOT_LIMITS = Object.freeze({ files: 100_000, bytes: 4 * 1024 * 1024 * 1024, pathBytes: 4_096 } as const);
export interface ReleaseSnapshotEntry { readonly path: string; readonly mode: "100644" | "100755"; readonly size: number; readonly digest: string; }
export interface ReleaseSnapshot { readonly root: string; readonly digest: string; readonly entries: readonly ReleaseSnapshotEntry[]; readonly dispose: () => void; }
export class ReleaseSnapshotError extends Error { constructor(message: string) { super(`release snapshot: ${message}`); this.name = "ReleaseSnapshotError"; } }

const sha = (bytes: Uint8Array | string): string => createHash("sha256").update(bytes).digest("hex");
const byteOrder = (a: string, b: string): number => Buffer.compare(Buffer.from(a), Buffer.from(b));
function disposeTree(root: string): void {
  try {
    const thaw = (dir: string): void => { chmodSync(dir, 0o755); for (const name of readdirSync(dir)) { const path = join(dir, name); const st = lstatSync(path); if (st.isDirectory()) thaw(path); else chmodSync(path, 0o600); } };
    thaw(root); rmSync(root, { recursive: true, force: true });
  } catch { /* best-effort cleanup only */ }
}
function safeName(name: string, siblings: Set<string>, rel: string): void {
  if (name === "." || name === ".." || name.includes("/") || name.includes("\\") || name.normalize("NFC") !== name || Buffer.byteLength(name) === 0) throw new ReleaseSnapshotError(`non-canonical entry name at ${rel || "."}`);
  for (const ch of name) { const cp = ch.codePointAt(0)!; if (cp <= 0x1f || cp === 0x7f || /\p{Cf}|\p{Cs}|\p{Co}|\p{Cn}/u.test(ch)) throw new ReleaseSnapshotError(`unsafe entry name at ${rel || "."}`); }
  const folded = name.normalize("NFKC").toLocaleLowerCase("und"); if (siblings.has(folded)) throw new ReleaseSnapshotError(`case/Unicode-colliding entries at ${rel || "."}`); siblings.add(folded);
}
function stableFile(path: string): { bytes: Buffer; mode: "100644" | "100755"; stat: ReturnType<typeof fstatSync> } {
  let fd = -1;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const before = fstatSync(fd, { bigint: true }); if (!before.isFile()) throw new ReleaseSnapshotError(`unsupported non-regular entry ${path}`);
    const bytes = readFileSync(fd); const after = fstatSync(fd, { bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs || before.mode !== after.mode || BigInt(bytes.length) !== after.size) throw new ReleaseSnapshotError(`file changed while captured: ${path}`);
    return { bytes, mode: Number(after.mode) & 0o111 ? "100755" : "100644", stat: after as ReturnType<typeof fstatSync> };
  } finally { if (fd >= 0) closeSync(fd); }
}

/** Materialize the exact bytes that are subsequently scanned. Nothing is ignored; VCS metadata, links and specials refuse. */
export function captureReleaseSnapshot(sourceRoot: string): ReleaseSnapshot {
  const rootStat = lstatSync(sourceRoot); if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new ReleaseSnapshotError("sourceRoot must be a real directory");
  const snapshotRoot = mkdtempSync(join(tmpdir(), "keep-release-snapshot-")); const entries: ReleaseSnapshotEntry[] = []; let total = 0;
  const walk = (dir: string, relDir: string): void => {
    const before = lstatSync(dir, { bigint: true }); if (!before.isDirectory() || before.isSymbolicLink()) throw new ReleaseSnapshotError(`directory changed before capture: ${relDir || "."}`);
    const names = readdirSync(dir).sort(byteOrder); const siblings = new Set<string>();
    for (const name of names) {
      safeName(name, siblings, relDir); const rel = relDir === "" ? name : `${relDir}/${name}`; if (Buffer.byteLength(rel) > RELEASE_SNAPSHOT_LIMITS.pathBytes) throw new ReleaseSnapshotError(`path exceeds limit: ${rel}`);
      if (rel === ".git" || rel.startsWith(".git/")) throw new ReleaseSnapshotError("release package must not contain VCS metadata");
      const source = join(dir, name); const st = lstatSync(source, { bigint: true });
      if (st.isSymbolicLink()) throw new ReleaseSnapshotError(`symbolic links are not admitted: ${rel}`);
      if (st.isDirectory()) {
        const targetDirectory = join(snapshotRoot, rel);
        mkdirSync(targetDirectory, { recursive: false, mode: 0o755 });
        walk(source, rel);
        chmodSync(targetDirectory, 0o555);
        continue;
      }
      if (!st.isFile()) throw new ReleaseSnapshotError(`special filesystem entry is not admitted: ${rel}`);
      const stable = stableFile(source); if (stable.stat.dev !== st.dev || stable.stat.ino !== st.ino) throw new ReleaseSnapshotError(`entry changed before capture: ${rel}`);
      total += stable.bytes.length; if (entries.length + 1 > RELEASE_SNAPSHOT_LIMITS.files || total > RELEASE_SNAPSHOT_LIMITS.bytes) throw new ReleaseSnapshotError("release tree exceeds bounded inventory limits");
      const target = join(snapshotRoot, rel); mkdirSync(dirname(target), { recursive: true }); copyFileSync(source, target, constants.COPYFILE_EXCL); // overwritten below from captured bytes check
      const copied = readFileSync(target); if (!copied.equals(stable.bytes)) throw new ReleaseSnapshotError(`source changed during materialization: ${rel}`);
      chmodSync(target, stable.mode === "100755" ? 0o555 : 0o444); entries.push(Object.freeze({ path: rel, mode: stable.mode, size: stable.bytes.length, digest: sha(stable.bytes) }));
    }
    const finalNames = readdirSync(dir).sort(byteOrder); const after = lstatSync(dir, { bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs || names.length !== finalNames.length || names.some((name, index) => name !== finalNames[index])) throw new ReleaseSnapshotError(`directory entry set changed while captured: ${relDir || "."}`);
  };
  try {
    walk(sourceRoot, ""); entries.sort((a, b) => byteOrder(a.path, b.path));
    const digest = sha(`keep.release-snapshot/v1\0${entries.map((e) => `${e.path}\0${e.mode}\0${e.size}\0${e.digest}\0`).join("")}`);
    chmodSync(snapshotRoot, 0o555);
    return Object.freeze({ root: snapshotRoot, digest, entries: Object.freeze(entries), dispose: () => disposeTree(snapshotRoot) });
  } catch (error) { disposeTree(snapshotRoot); throw error; }
}
