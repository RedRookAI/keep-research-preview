/**
 * Real git adapter (infra) — makes Phase 2 rollback's git seam executable.
 *
 * Wraps a real git repository via node:child_process (zero runtime deps). Each
 * mutating operation makes a real commit and returns a ReversibleAction whose
 * undo() runs `git revert --no-edit <sha>`.
 *
 * Design (SOTA, Aug 2026): revert, NOT reset. Revert creates a new commit that
 * reverses the change and PRESERVES history; reset rewrites it. Keep's premise is a
 * tamper-evident, auditable trail, so history-rewriting rollback is disqualified —
 * revert is the only safe default. (What would change it: a purely-local, never-
 * shared scratch branch could reset; revert stays the default everywhere else.)
 * Operates in an injectable cwd so it composes with git-worktree isolation.
 *
 * All git calls use argument arrays (never a shell string), so paths/messages can't
 * inject shell.
 */

import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import type { ReversibleAction } from "../control/rollback.js";
import { installedEffectAdmission, INSTALLED_EFFECT_OWNERS, type InstalledEffectAdmission } from "../control/installed_effect_admission.js";

const execFileAsync = promisify(execFile);

const CLOSED_GIT_CONFIG = [
  "-c", "core.hooksPath=/dev/null",
  "-c", "core.fsmonitor=false",
  "-c", "credential.interactive=false",
  "-c", "commit.gpgSign=false",
  "-c", "protocol.allow=never",
  "-c", "protocol.file.allow=always",
  "-c", "protocol.ssh.allow=always",
  "-c", "protocol.https.allow=always",
  "-c", "protocol.version=2",
] as const;

function closedGitEnvironment(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: "/nonexistent",
    XDG_CONFIG_HOME: "/nonexistent",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_ATTR_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
    LC_ALL: "C",
  };
  // An explicitly provisioned SSH agent is an authentication capability, not Git configuration.
  // Preserve only its socket; every GIT_*/askpass/config injection route stays absent.
  if (process.env.SSH_AUTH_SOCK) env.SSH_AUTH_SOCK = process.env.SSH_AUTH_SOCK;
  return env;
}

export interface GitResult {
  readonly stdout: string;
  readonly stderr: string;
}

export interface GitInputOptions {
  readonly stdin?: Uint8Array;
  readonly timeoutMs?: number;
  readonly maxOutputBytes?: number;
  /** Required for a fence-held network effect: terminate Git and transport helpers as one POSIX group. */
  readonly killProcessGroup?: boolean;
}

export interface GitBinaryResult {
  readonly stdout: Buffer;
  readonly stderr: Buffer;
}

export class GitAdapter {
  /**
   * @param cwd  the repository working directory (an isolated worktree in prod).
   */
  constructor(private readonly cwd: string, private readonly effectAdmission: InstalledEffectAdmission = installedEffectAdmission) {}

  /** Stable construction root for operator-side transport appraisal and tests; never derived from repository data. */
  workingDirectory(): string { return this.cwd; }

  /** Run a git subcommand with safe argument passing. */
  async git(args: readonly string[]): Promise<GitResult> {
    this.effectAdmission.admit(INSTALLED_EFFECT_OWNERS.gitCommand.id);
    const { stdout, stderr } = await execFileAsync("git", [...CLOSED_GIT_CONFIG, ...args], {
      cwd: this.cwd,
      env: closedGitEnvironment(),
      maxBuffer: 32 * 1024 * 1024,
    });
    return { stdout: stdout.toString(), stderr: stderr.toString() };
  }

  /**
   * Closed Git invocation for plumbing that consumes exact bytes, or for a hard-bounded transport.
   * Existing callers stay on git(); this narrower operation adds no ambient environment or shell.
   */
  async gitInput(args: readonly string[], options: GitInputOptions = {}): Promise<GitBinaryResult> {
    this.effectAdmission.admit(INSTALLED_EFFECT_OWNERS.gitCommand.id);
    const stdin = options.stdin === undefined ? Buffer.alloc(0) : Buffer.from(options.stdin);
    const maxOutputBytes = options.maxOutputBytes ?? 32 * 1024 * 1024;
    const timeoutMs = options.timeoutMs;
    if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes <= 0 || maxOutputBytes > 64 * 1024 * 1024)
      throw new RangeError("git maxOutputBytes must be between 1 and 67108864");
    if (timeoutMs !== undefined && (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 300_000))
      throw new RangeError("git timeoutMs must be between 1 and 300000");
    if (options.killProcessGroup === true && process.platform === "win32")
      throw new Error("git process-group termination is unavailable on this platform");

    return await new Promise<GitBinaryResult>((resolve, reject) => {
      const grouped = options.killProcessGroup === true;
      const child = spawn("git", [...CLOSED_GIT_CONFIG, ...args], {
        cwd: this.cwd,
        env: closedGitEnvironment(),
        detached: grouped,
        stdio: ["pipe", "pipe", "pipe"],
      });
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let outputBytes = 0;
      let terminalError: Error | undefined;
      let timer: NodeJS.Timeout | undefined;
      const terminate = (reason: Error): void => {
        terminalError ??= reason;
        try {
          if (grouped && child.pid !== undefined) process.kill(-child.pid, "SIGKILL");
          else child.kill("SIGKILL");
        } catch { /* close/error still settles the invocation */ }
      };
      const collect = (target: Buffer[], chunk: Buffer): void => {
        outputBytes += chunk.length;
        if (outputBytes > maxOutputBytes) terminate(new Error("git command output exceeded its bound"));
        else target.push(Buffer.from(chunk));
      };
      child.stdout.on("data", (chunk: Buffer) => collect(stdout, chunk));
      child.stderr.on("data", (chunk: Buffer) => collect(stderr, chunk));
      child.once("error", (error) => { terminalError ??= error; });
      child.once("close", (code, signal) => {
        if (timer !== undefined) clearTimeout(timer);
        if (terminalError !== undefined) { reject(terminalError); return; }
        if (code !== 0) { reject(new Error(`git command failed (${code ?? signal ?? "unknown"})`)); return; }
        resolve({ stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) });
      });
      if (timeoutMs !== undefined) timer = setTimeout(() => terminate(new Error("git command timed out")), timeoutMs);
      child.stdin.once("error", (error) => terminate(error));
      // An empty chunk still issues a write and can race a successful short-lived
      // Git command that has already closed stdin. With no bytes owed, send EOF
      // only; nonempty input errors must continue to fail the operation.
      if (stdin.length === 0) child.stdin.end();
      else child.stdin.end(stdin);
    });
  }

  /** Current HEAD commit SHA. */
  async head(): Promise<string> {
    return (await this.git(["rev-parse", "HEAD"])).stdout.trim();
  }

  /** Whether the working tree is clean (no staged/unstaged changes). */
  async isClean(): Promise<boolean> {
    return (await this.git(["status", "--porcelain"])).stdout.trim().length === 0;
  }

  /** The one-line log, newest first (for verification/tests). */
  async logOneline(max = 20): Promise<string[]> {
    const out = (await this.git(["log", `--max-count=${max}`, "--oneline"])).stdout.trim();
    return out.length === 0 ? [] : out.split("\n");
  }

  /**
   * Stage all changes and commit with `message`, returning a ReversibleAction whose
   * artifact is the new commit SHA and whose undo() reverts THAT commit (history-
   * preserving). Author/committer identity should be Keep's scoped identity in prod.
   */
  async commitAll(message: string, actionId: string): Promise<ReversibleAction> {
    await this.git(["add", "-A"]);
    await this.git(["commit", "-m", message, "--no-verify"]);
    const sha = await this.head();
    return {
      id: actionId,
      artifact: sha,
      undo: async () => {
        // Revert the specific commit; --no-edit keeps it non-interactive.
        await this.git(["revert", "--no-edit", sha]);
      },
    };
  }

  /**
   * Revert a specific commit immediately (out-of-band rollback), returning the new
   * revert commit's SHA. For a merge commit, pass `mainline` (usually 1).
   */
  async revert(sha: string, mainline?: number): Promise<string> {
    const args = mainline ? ["revert", "--no-edit", "-m", String(mainline), sha] : ["revert", "--no-edit", sha];
    await this.git(args);
    return this.head();
  }

  /** Create an isolated worktree at `path` on a new branch (isolation primitive). */
  async addWorktree(path: string, branch: string): Promise<void> {
    await this.git(["worktree", "add", "-b", branch, path]);
  }

  async removeWorktree(path: string): Promise<void> {
    await this.git(["worktree", "remove", "--force", path]);
  }
}
