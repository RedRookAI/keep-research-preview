/**
 * Remote git operations (Increment 15a).
 *
 * SOTA basis (2026-08-05): the #1 rule for autonomous-agent git is BRANCH-PER-TASK, never commit to a
 * shared branch (buildmvpfast 2026: "never let an agent commit to a shared branch, every single
 * time"). The branch prefix is load-bearing — it flags machine-generated work before a reviewer opens
 * the diff and lets branch-protection rules target agent branches. Attribution trailers keep the audit
 * trail explicit ("responsibility stays with the engineer who hit commit" — marketingagent 2026).
 * Read-only ops (fetch/status) are separated from state-changing ops (push) as distinct actions
 * (GitHub community 2026). Tested against a real local bare remote. Zero deps.
 *
 * What would change it: nothing structural — the protected-branch refusal + branch-per-task are
 * permanent invariants; hosted PR adapters are additive (15b).
 */

import { GitAdapter } from "../infra/git_adapter.js";
import type { ReversibleAction } from "../control/rollback.js";
import { appraiseGitMutationControlPlane, pinnedFetchOperand, pinnedPushOperand, resolvePinnedRemoteTransport } from "./pinned_remote.js";

/** Branches Keep will NEVER push to directly — the human owns these. */
export const PROTECTED_BRANCHES: readonly string[] = ["main", "master", "develop", "release", "production", "trunk"];

/** The branch prefix that flags Keep-generated work (filterable: git branch --list 'keep/*'). */
export const KEEP_BRANCH_PREFIX = "keep/";

export interface RemoteConfig {
  /** Remote name (default "origin"). */
  readonly remote?: string;
  /** SHA-256 over `keep.git-fetch-url/v1\0` plus the exact operator-approved fetch URL. */
  readonly expectedFetchUrlSha256?: string;
  /** SHA-256 over `keep.git-push-url/v1\0` plus the exact operator-approved push URL. */
  readonly expectedPushUrlSha256?: string;
  /** Keep's run/identity id, stamped into commit attribution trailers. */
  readonly runId?: string;
  /** Attribution identity (name <email>) for the Co-authored-by trailer. */
  readonly attribution?: string;
}

export class ProtectedBranchError extends Error {
  constructor(readonly branch: string) {
    super(`refusing to push to protected branch '${branch}' — Keep never pushes to a shared branch (human owns merge)`);
    this.name = "ProtectedBranchError";
  }
}

export class GitRemote {
  private readonly remote: string;
  constructor(private readonly git: GitAdapter, private readonly config: RemoteConfig = {}) {
    this.remote = config.remote ?? "origin";
  }

  /** Is this a protected (shared) branch Keep must never push to? */
  static isProtected(branch: string): boolean {
    const bare = branch.replace(/^refs\/heads\//, "").trim();
    return PROTECTED_BRANCHES.includes(bare) || PROTECTED_BRANCHES.some((p) => bare === p || bare.startsWith(`${p}/`));
  }

  /** Is this a well-formed Keep task branch (keep/ prefix)? */
  static isKeepBranch(branch: string): boolean {
    if (!branch.startsWith(KEEP_BRANCH_PREFIX)) return false;
    // Defense-in-depth: reject path-traversal / malformed refs that could resolve elsewhere
    // (e.g. "keep/../main"). A well-formed keep branch has no "..", no leading/trailing slash noise,
    // and only ref-safe characters.
    if (branch.includes("..") || branch.includes("//") || /[\s~^:?*\[\\]/.test(branch)) return false;
    const rest = branch.slice(KEEP_BRANCH_PREFIX.length);
    return rest.length > 0 && !rest.startsWith("/");
  }

  /** Create + checkout a task branch. Rejects a name that isn't a keep/ branch (branch-per-task). */
  async createTaskBranch(branch: string): Promise<void> {
    if (!GitRemote.isKeepBranch(branch)) {
      throw new Error(`task branch must use the '${KEEP_BRANCH_PREFIX}' prefix (got '${branch}') — branch-per-task convention`);
    }
    if (GitRemote.isProtected(branch)) throw new ProtectedBranchError(branch);
    await appraiseGitMutationControlPlane(this.git);
    await this.git.git(["checkout", "-b", branch]);
  }

  /** Fetch from the remote (read-only). */
  async fetch(): Promise<void> {
    const transport = await this.transport();
    await appraiseGitMutationControlPlane(this.git);
    await this.git.git(["fetch", pinnedFetchOperand(transport), `+refs/heads/*:refs/remotes/${this.remote}/*`]);
  }

  /** Pull a specific branch (read + integrate). Refuses protected branches implicitly via caller intent. */
  async pull(branch: string): Promise<void> {
    await appraiseGitMutationControlPlane(this.git);
    const transport = await this.transport();
    await appraiseGitMutationControlPlane(this.git);
    await this.git.git(["pull", "--ff-only", pinnedFetchOperand(transport), branch]);
  }

  /**
   * Push a task branch to the remote. REFUSES protected/shared branches (the core safety invariant).
   * Returns a ReversibleAction whose undo deletes the remote branch (best-effort cleanup).
   */
  async pushTaskBranch(branch: string, actionId: string): Promise<ReversibleAction> {
    if (GitRemote.isProtected(branch)) throw new ProtectedBranchError(branch);
    if (!GitRemote.isKeepBranch(branch)) {
      throw new Error(`refusing to push non-keep branch '${branch}' — only keep/* task branches are pushed`);
    }
    const transport = await this.transport();
    await appraiseGitMutationControlPlane(this.git);
    await this.git.git(["push", "-u", pinnedPushOperand(transport), branch]);
    return {
      id: actionId,
      artifact: `${this.remote}/${branch}`,
      undo: async () => {
        // Delete the remote branch (best-effort — the human may already have acted on it).
        try {
          await appraiseGitMutationControlPlane(this.git);
          await this.git.git(["push", pinnedPushOperand(transport), "--delete", branch]);
        } catch { /* already gone */ }
      },
    };
  }

  /** The attribution trailer block for a Keep commit (auditability). */
  attributionTrailer(): string {
    const lines: string[] = [];
    if (this.config.runId) lines.push(`Keep-Run-Id: ${this.config.runId}`);
    if (this.config.attribution) lines.push(`Co-authored-by: ${this.config.attribution}`);
    return lines.join("\n");
  }

  /** Commit staged changes with an attribution trailer appended (auditable machine authorship). */
  async commitWithAttribution(message: string, actionId: string): Promise<ReversibleAction> {
    const trailer = this.attributionTrailer();
    const full = trailer ? `${message}\n\n${trailer}` : message;
    await appraiseGitMutationControlPlane(this.git);
    return this.git.commitAll(full, actionId);
  }

  /** List branches matching the keep/ prefix (filterable audit surface). */
  async listKeepBranches(): Promise<string[]> {
    const out = (await this.git.git(["branch", "--list", `${KEEP_BRANCH_PREFIX}*`])).stdout;
    return out.split("\n").map((l) => l.replace(/^[*+]?\s*/, "").trim()).filter((l) => l.length > 0);
  }

  /** Resolve both independently pinned directions before any candidate-branch mutation or network effect. */
  async transport(): Promise<import("./pinned_remote.js").PinnedRemoteTransport> {
    return resolvePinnedRemoteTransport(this.git, this.remote, this.config.expectedFetchUrlSha256, this.config.expectedPushUrlSha256);
  }
}
