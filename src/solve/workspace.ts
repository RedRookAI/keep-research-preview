/**
 * Workspace — the repo surface a solve runs against: read the files, get a write-through tree for applying edits.
 *
 * Two backends behind ONE port (front and back of house):
 *  - InMemoryWorkspace: deterministic, air-gapped, zero-dep — the default for in-environment proofs and N=1 laptops
 *    working on an in-memory snapshot.
 *  - LocalFsWorkspace: a real on-disk repo (node:fs), project-jailed so a repoRef can never escape its base dir — the
 *    production backend for a checked-out working tree.
 *
 * Test EXECUTION is a separate concern (the TestRunner seam), because running untrusted repo tests must be sandboxed
 * (that hardening lands in the isolation increment); the Workspace only owns repo content.
 */

import { closeSync, constants, fstatSync, ftruncateSync, lstatSync, openSync, readFileSync, realpathSync, writeFileSync, readdirSync, mkdirSync } from "node:fs";
import { join, relative, resolve, sep, dirname, isAbsolute, basename } from "node:path";
import type { RepoFile } from "./localize.js";
import type { FileTree } from "./patch.js";
import { InMemoryFileTree } from "./patch.js";
import { installedEffectAdmission, INSTALLED_EFFECT_OWNERS, type InstalledEffectAdmission } from "../control/installed_effect_admission.js";

export interface Workspace {
  /** The repo's files (content the localizer + planner read). */
  files(repoRef: string, limits?: WorkspaceReadLimits): Promise<readonly RepoFile[]>;
  /** A write-through tree the patch engine applies edits into. */
  tree(repoRef: string): FileTree;
  /** The confined on-disk directory for a repoRef, when the workspace is disk-backed (enables the sandbox runner). */
  dir?(repoRef: string): string;
}

export interface WorkspaceReadLimits {
  readonly maxFiles: number;
  readonly maxFileBytes: number;
  readonly maxTotalBytes: number;
}

/** In-memory workspace: a map of repoRef → { path → content }. Deterministic, zero-dep, air-gap safe. */
export class InMemoryWorkspace implements Workspace {
  private readonly trees = new Map<string, InMemoryFileTree>();
  constructor(private readonly repos: Record<string, Record<string, string>> = {}) {}

  async files(repoRef: string, limits?: WorkspaceReadLimits): Promise<readonly RepoFile[]> {
    const tree = this.tree(repoRef) as InMemoryFileTree;
    const files = Object.entries(tree.snapshot()).map(([path, content]) => ({ path, content }));
    enforceReadLimits(files, limits);
    return files;
  }

  tree(repoRef: string): FileTree {
    let t = this.trees.get(repoRef);
    if (!t) {
      t = new InMemoryFileTree(this.repos[repoRef] ?? {});
      this.trees.set(repoRef, t);
    }
    return t;
  }
}

/** True if `candidate` resolves to a path inside `base` (traversal-resistant). */
function withinBase(base: string, candidate: string): boolean {
  const rel = relative(resolve(base), resolve(base, candidate));
  return rel === "" || (!rel.startsWith("..") && !rel.startsWith(sep) && !isAbsolute(rel));
}

/**
 * Real on-disk workspace. Each repoRef is a directory under `baseDir`; every read/write is project-jailed so a
 * malicious repoRef or edit path can never escape (no `..`, no absolute escape, no symlink-out). Production backend.
 */
export class LocalFsWorkspace implements Workspace {
  constructor(
    private readonly baseDir: string,
    /** Files to include when listing (extensions); default common source/text types. */
    private readonly includeExt: readonly string[] = [".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx", ".py", ".go", ".rs", ".java", ".json", ".md", ".txt", ".yml", ".yaml"],
    private readonly effectAdmission: InstalledEffectAdmission = installedEffectAdmission,
  ) {}

  /** The complete filesystem authority held by this adapter, not merely one selected repository below it. */
  authorityRoot(): string { return realpathSync(this.baseDir); }

  private repoDir(repoRef: string): string {
    const dir = resolve(this.baseDir, repoRef);
    if (!withinBase(this.baseDir, repoRef)) throw new Error(`repoRef escapes the workspace base: ${repoRef}`);
    return dir;
  }

  /** The confined on-disk directory for a repoRef (the sandbox runner's cwd). Jailed to the workspace base. */
  dir(repoRef: string): string {
    return this.repoDir(repoRef);
  }

  async files(repoRef: string, limits?: WorkspaceReadLimits): Promise<readonly RepoFile[]> {
    this.effectAdmission.admit(INSTALLED_EFFECT_OWNERS.workspaceRead.id);
    const root = this.repoDir(repoRef);
    const rootStatus = lstatSync(root);
    if (!rootStatus.isDirectory() || rootStatus.isSymbolicLink()) throw new Error("workspace repository root must be a real directory");
    const rootReal = realpathSync(root);
    const out: RepoFile[] = [];
    const walk = (dir: string): void => {
      let entries: string[] = [];
      try { entries = readdirSync(dir); } catch { return; }
      for (const name of entries) {
        if (name === "node_modules" || name === ".git" || name === "dist") continue;
        const full = join(dir, name);
        let st;
        try { st = lstatSync(full); } catch { continue; }
        if (st.isSymbolicLink()) continue;
        if (st.isDirectory()) walk(full);
        else if (this.includeExt.some((e) => name.endsWith(e))) {
          let fd: number | undefined;
          try {
            fd = openSync(full, constants.O_RDONLY | constants.O_NOFOLLOW);
            const before = fstatSync(fd, { bigint: true });
            if (!before.isFile() || before.nlink !== 1n) continue;
            if (limits !== undefined && before.size > BigInt(limits.maxFileBytes)) throw new WorkspaceReadLimitError(`workspace file exceeds read bound: ${relative(root, full)}`);
            const descriptorPath = process.platform === "linux" ? `/proc/self/fd/${fd}` : full;
            const openedReal = realpathSync(descriptorPath);
            const rel = relative(rootReal, openedReal);
            if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) continue;
            const content = readFileSync(fd, "utf8");
            const after = fstatSync(fd, { bigint: true });
            if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs) continue;
            out.push({ path: relative(root, full).split(sep).join("/"), content });
            enforceReadLimits(out, limits);
          } catch (error) {
            if (error instanceof WorkspaceReadLimitError) throw error;
            /* skip unreadable, raced, linked, or escaped entries */
          }
          finally { if (fd !== undefined) try { closeSync(fd); } catch { /* best effort close */ } }
        }
      }
    };
    walk(root);
    return out;
  }

  tree(repoRef: string): FileTree {
    const root = this.repoDir(repoRef);
    const rootStatus = lstatSync(root);
    if (!rootStatus.isDirectory() || rootStatus.isSymbolicLink()) throw new Error("workspace repository root must be a real directory");
    const rootReal = realpathSync(root);
    const jail = (p: string): string => {
      const full = resolve(root, p);
      if (!withinBase(root, p)) throw new Error(`edit path escapes the repo: ${p}`);
      return full;
    };
    const openedInside = (fd: number, fallback: string): boolean => {
      const openedReal = realpathSync(process.platform === "linux" ? `/proc/self/fd/${fd}` : fallback);
      const rel = relative(rootReal, openedReal);
      return rel === "" || (!rel.startsWith("..") && !rel.startsWith(sep) && !isAbsolute(rel));
    };
    const readOne = (path: string): string | undefined => {
        this.effectAdmission.admit(INSTALLED_EFFECT_OWNERS.workspaceRead.id);
        let fd: number | undefined;
        const full = jail(path);
        try {
          fd = openSync(full, constants.O_RDONLY | constants.O_NOFOLLOW);
          const status = fstatSync(fd);
          if (!status.isFile() || status.nlink !== 1 || !openedInside(fd, full)) return undefined;
          return readFileSync(fd, "utf8");
        } catch { return undefined; }
        finally { if (fd !== undefined) try { closeSync(fd); } catch { /* best effort close */ } }
      };
    const writeOne = (path: string, content: string): void => {
        this.effectAdmission.admit(INSTALLED_EFFECT_OWNERS.workspaceWrite.id);
        const full = jail(path);
        const parent = dirname(full);
        ensureRealDirectories(root, parent);
        let parentFd: number | undefined;
        let fd: number | undefined;
        try {
          parentFd = openSync(parent, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
          if (!fstatSync(parentFd).isDirectory() || !openedInside(parentFd, parent)) throw new Error(`edit parent escapes the repo: ${path}`);
          const target = process.platform === "linux" ? `/proc/self/fd/${parentFd}/${basename(full)}` : full;
          try { fd = openSync(target, constants.O_WRONLY | constants.O_NOFOLLOW); }
          catch (error) {
            const code = (error as { code?: string }).code;
            if (code === "ELOOP" || code === "EMULTIHOP") throw new Error(`edit target is a symlink: ${path}`, { cause: error });
            if (code !== "ENOENT") throw error;
            fd = openSync(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
          }
          const targetStatus = fstatSync(fd);
          if (!targetStatus.isFile() || targetStatus.nlink !== 1 || !openedInside(fd, full)) throw new Error(`edit target escapes the repo: ${path}`);
          ftruncateSync(fd, 0);
          writeFileSync(fd, content, "utf8");
        } finally {
          if (fd !== undefined) try { closeSync(fd); } catch { /* best effort close */ }
          if (parentFd !== undefined) try { closeSync(parentFd); } catch { /* best effort close */ }
        }
      };
    return {
      async read(path: string): Promise<string | undefined> { return readOne(path); },
      async write(path: string, content: string): Promise<void> { writeOne(path, content); },
      async commitBatchIfUnchanged(expected, writes): Promise<boolean> {
        // No await occurs inside this method: cooperating work in this process cannot interleave
        // between comparison and the batch. The isolated workspace is the external-process belt.
        for (const [path, content] of Object.entries(expected)) if (readOne(path) !== content) return false;
        const attempted: string[] = [];
        try {
          for (const write of writes) { attempted.push(write.path); writeOne(write.path, write.content); }
          return true;
        } catch (writeError) {
          try { for (const path of attempted.reverse()) writeOne(path, expected[path]!); }
          catch (restoreError) { throw new AggregateError([writeError, restoreError], "filesystem CAS batch failed and restoration also failed"); }
          throw writeError;
        }
      },
    };
  }
}

function enforceReadLimits(files: readonly RepoFile[], limits?: WorkspaceReadLimits): void {
  if (limits === undefined) return;
  if (files.length > limits.maxFiles) throw new WorkspaceReadLimitError(`workspace exceeds ${limits.maxFiles} readable files`);
  let total = 0;
  for (const file of files) {
    const bytes = Buffer.byteLength(file.content, "utf8");
    if (bytes > limits.maxFileBytes) throw new WorkspaceReadLimitError(`workspace file exceeds ${limits.maxFileBytes} bytes: ${file.path}`);
    total += bytes;
    if (!Number.isSafeInteger(total) || total > limits.maxTotalBytes) throw new WorkspaceReadLimitError(`workspace exceeds ${limits.maxTotalBytes} readable bytes`);
  }
}

class WorkspaceReadLimitError extends Error {}

function ensureRealDirectories(root: string, parent: string): void {
  const rel = relative(root, parent);
  if (rel === "" || rel === ".") return;
  let cursor = root;
  for (const part of rel.split(sep)) {
    cursor = join(cursor, part);
    try {
      const status = lstatSync(cursor);
      if (!status.isDirectory() || status.isSymbolicLink()) throw new Error(`edit directory is not a real directory: ${cursor}`);
    } catch (error) {
      if ((error as { code?: string }).code !== "ENOENT") throw error;
      mkdirSync(cursor, 0o700);
      const created = lstatSync(cursor);
      if (!created.isDirectory() || created.isSymbolicLink()) throw new Error(`edit directory creation was substituted: ${cursor}`);
    }
  }
}
