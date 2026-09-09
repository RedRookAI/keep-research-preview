/**
 * Real git merge port (Increment AM2b) — the physical capability behind the AM2 autonomous-merge executor. It runs
 * actual git: a working-tree-safe conflict check, a real `--no-ff` merge into the base (whose merge commit is the
 * idempotent rollback id), and a real `revert -m 1` of that merge commit.
 *
 * This is the deliberate, governed exception to Keep's "never push to a protected branch" rule (GitRemote): Keep
 * normally never touches a shared base, because a human owns the merge. Autonomous merge is the one path allowed to
 * land on the base — but ONLY reachable through the AM2 executor, which merges only what AM1 cleared as
 * `autonomous-merge` (verified + reversible + low-blast + within the owner's envelope). So the base is touched only
 * for changes that are safe to auto-revert, and every step is audited.
 *
 * SOTA basis (2026-08-07): revert, not reset — a merge is undone with a new revert commit that preserves history
 * (Keep's trail is tamper-evident, so history-rewriting rollback is disqualified). `merge-tree --write-tree`
 * (git ≥2.38) computes the merge result and reports conflicts without mutating the working tree, so the pre-merge
 * check is side-effect-free. A remote push after merge is optional and off by default (auto-merge lands in the repo;
 * pushing to a shared remote/deploy stays a separate, owner-gated concern).
 */

import type { GitAdapter } from "../infra/git_adapter.js";
import { computeMicrovmProjectSourceManifestSha256 } from "../infra/microvm_boundary.js";
import { consumePreparedPublicationAuthority, makePublicationAttempt, parsePublicationAttempt, publicationAttemptDigest, sealPreparedPublication, type MergePort, type MergeSpec, type MergeOutcome, type MergePreflightIdentity, type PreparedPublicationAuthority, type PublishedMergeIdentity, type PublicationAttemptV1, type PublicationObservation, type RevertOutcome } from "../oversight/merge_executor.js";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, readlinkSync, realpathSync } from "node:fs";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import type { Spine } from "../spine/spine.js";
import { appraiseGitMutationControlPlane, pinnedFetchOperand, pinnedPushOperand, resolvePinnedRemoteTransport, type PinnedRemoteTransport } from "./pinned_remote.js";

interface ResolvedPublicationTarget {
  readonly target: string;
  readonly transport?: PinnedRemoteTransport;
}

export interface GitMergePortOptions {
  /** If set, push the base branch to this remote after a successful merge/revert. The governed exception to the
   *  protected-branch guard — only ever reached via the autonomous-merge executor. Omit for local-only merges. */
  readonly pushRemote?: string;
  /** Independently pinned inbound/observation transport identity. */
  readonly expectedFetchUrlSha256?: string;
  /** Operator-pinned transport identity held outside repository configuration. Required for every remote effect. */
  readonly expectedPushUrlSha256?: string;
  /** Canonical durable publication journal selected by composition. An actuator without it cannot merge. */
  readonly publicationSpine?: Spine;
}

export class GitMergePort implements MergePort {
  constructor(private readonly git: GitAdapter, private readonly opts: GitMergePortOptions = {}) {}

  /** Explicit helper for low-level callers/tests; it writes to the same canonical journal the actuator consumes. */
  preparePublication(attempt: PublicationAttemptV1): Promise<PreparedPublicationAuthority> {
    if (!this.opts.publicationSpine) return Promise.reject(new Error("Git publication actuator has no canonical durable Spine"));
    return sealPreparedPublication(this.opts.publicationSpine, attempt);
  }

  publicationTarget(spec: MergeSpec): string {
    if (!this.opts.pushRemote) return `local:project-dir-sha256:${createHash("sha256").update(resolve(spec.projectDir)).digest("hex")}:refs/heads/${spec.baseBranch}`;
    this.assertRemoteOperand(this.opts.pushRemote);
    if (!/^[0-9a-f]{64}$/u.test(this.opts.expectedFetchUrlSha256 ?? "")) throw new Error("remote publication requires an operator-pinned fetch URL digest");
    if (!/^[0-9a-f]{64}$/u.test(this.opts.expectedPushUrlSha256 ?? "")) throw new Error("remote publication requires an operator-pinned push URL digest");
    return `remote:${this.opts.pushRemote}:fetch-url-sha256:${this.opts.expectedFetchUrlSha256}:push-url-sha256:${this.opts.expectedPushUrlSha256}:refs/heads/${spec.baseBranch}`;
  }

  private async resolvedPublicationTarget(spec: MergeSpec): Promise<ResolvedPublicationTarget> {
    const project = await this.projectRoot(spec);
    await appraiseGitMutationControlPlane(this.git, project);
    if (!this.opts.pushRemote) return { target: `local:project-dir-sha256:${createHash("sha256").update(resolve(spec.projectDir)).digest("hex")}:refs/heads/${spec.baseBranch}` };
    const transport = await resolvePinnedRemoteTransport(this.git, this.opts.pushRemote, this.opts.expectedFetchUrlSha256, this.opts.expectedPushUrlSha256);
    return {
      target: `remote:${transport.remote}:fetch-url-sha256:${transport.fetchUrlSha256}:push-url-sha256:${transport.pushUrlSha256}:refs/heads/${spec.baseBranch}`,
      transport,
    };
  }

  private assertRemoteOperand(remote: string): void {
    // Configuration selects only the operator-named remote whose complete URL lists are appraised. Network commands
    // never consume this name; they consume the independently pinned exact URL operands instead.
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(remote)) {
      throw new Error("remote publication target is not one canonical configured-remote name");
    }
  }

  private async commit(ref: string): Promise<string> {
    return (await this.git.git(["rev-parse", "--verify", `${ref}^{commit}`])).stdout.trim();
  }

  private async tree(ref: string): Promise<string> {
    return (await this.git.git(["rev-parse", "--verify", `${ref}^{tree}`])).stdout.trim();
  }

  private async projectRoot(spec: MergeSpec): Promise<string> {
    const top = realpathSync((await this.git.git(["rev-parse", "--show-toplevel"])).stdout.trim());
    const project = realpathSync(resolve(spec.projectDir));
    if (project !== top) throw new Error("measured projectDir must equal the complete Git worktree root");
    return project;
  }

  private auxiliaryRoots(spec: MergeSpec): readonly string[] {
    const rows = [...(spec.executionAuxiliaryRoots ?? [])];
    if (rows.length > 32 || new Set(rows).size !== rows.length) throw new Error("execution auxiliary roots are duplicated or exceed the bound");
    for (const row of rows) {
      if (!/^[A-Za-z0-9._-]{1,128}$/.test(row) || row === "." || row === ".." || row === ".git") {
        throw new Error("execution auxiliary root is not one canonical top-level path");
      }
    }
    return rows.sort();
  }

  /**
   * Prove the checked-out source is exactly the named Git tree. `status clean` alone is insufficient:
   * ignored files and clean/smudge/EOL filters can make executed bytes differ from committed blobs.
   */
  private async assertTreeMatchesWorktree(commit: string, project: string, spec: MergeSpec): Promise<void> {
    const status = (await this.git.git(["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=matching"])).stdout;
    const auxiliary = this.auxiliaryRoots(spec);
    for (const row of status.split("\0").filter(Boolean)) {
      const code = row.slice(0, 2);
      const path = row.slice(3).replace(/\/$/u, "");
      const admittedAuxiliary = code === "!!" && auxiliary.some((root) => path === root || path.startsWith(`${root}/`));
      if (!admittedAuxiliary) throw new Error("worktree contains changed, untracked, or unadmitted ignored bytes outside the Git tree");
    }
    const raw = (await this.git.git(["ls-tree", "-r", "-z", "--full-tree", commit])).stdout;
    const rows = raw.split("\0").filter((row) => row.length > 0);
    if (rows.length === 0) throw new Error("Git tree contains no source files");
    for (const row of rows) {
      const match = /^(100644|100755|120000) blob ((?:[0-9a-f]{40}|[0-9a-f]{64}))\t(.+)$/u.exec(row);
      if (!match) throw new Error("Git tree contains an unsupported object kind or mode");
      const [, mode, expectedOid, path] = match;
      if (!path || path.startsWith("/") || path.split("/").some((part) => part === "" || part === "." || part === ".." || part === ".git")) {
        throw new Error("Git tree contains a noncanonical source path");
      }
      const absolute = resolve(project, path);
      const stat = lstatSync(absolute);
      if (mode === "120000") {
        if (!stat.isSymbolicLink()) throw new Error(`Git symlink kind differs from worktree: ${path}`);
        const target = Buffer.from(readlinkSync(absolute));
        const algorithm = expectedOid!.length === 64 ? "sha256" : "sha1";
        const actualOid = createHash(algorithm).update(`blob ${target.length}\0`).update(target).digest("hex");
        if (actualOid !== expectedOid!) throw new Error(`Git symlink target differs from worktree: ${path}`);
        continue;
      } else {
        if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`Git blob kind differs from worktree: ${path}`);
        const executable = (stat.mode & 0o111) !== 0;
        if ((mode === "100755") !== executable) throw new Error(`Git executable mode differs from worktree: ${path}`);
      }
      const fd = openSync(absolute, constants.O_RDONLY | constants.O_NOFOLLOW);
      let bytes: Buffer;
      try {
        const opened = fstatSync(fd);
        if (!opened.isFile() || opened.dev !== stat.dev || opened.ino !== stat.ino || opened.mode !== stat.mode || opened.size !== stat.size) {
          throw new Error(`Git blob changed while its execution identity was captured: ${path}`);
        }
        bytes = readFileSync(fd);
        const after = fstatSync(fd);
        if (after.dev !== opened.dev || after.ino !== opened.ino || after.mode !== opened.mode || after.size !== opened.size) {
          throw new Error(`Git blob changed during execution identity capture: ${path}`);
        }
      } finally { closeSync(fd); }
      const algorithm = expectedOid!.length === 64 ? "sha256" : "sha1";
      const actualOid = createHash(algorithm).update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
      if (actualOid !== expectedOid) throw new Error(`Git blob bytes differ from worktree: ${path}`);
    }
  }

  private async remoteCommit(transport: PinnedRemoteTransport, branch: string): Promise<string> {
    const ref = `refs/heads/${branch}`;
    await appraiseGitMutationControlPlane(this.git);
    const lines = (await this.git.git(["ls-remote", "--exit-code", pinnedFetchOperand(transport), ref])).stdout.trim().split("\n").filter(Boolean);
    const [commit, observedRef, ...extra] = lines[0]!.split(/\s+/);
    if (extra.length !== 0 || observedRef !== ref || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(commit ?? "")) throw new Error(`remote publication ref malformed for ${ref}`);
    return commit!;
  }

  /** Observation variant that distinguishes an absent authoritative ref from transport failure. */
  private async observeRemoteCommit(transport: PinnedRemoteTransport, branch: string): Promise<string | undefined> {
    const ref = `refs/heads/${branch}`;
    await appraiseGitMutationControlPlane(this.git);
    const lines = (await this.git.git(["ls-remote", pinnedFetchOperand(transport), ref])).stdout.trim().split("\n").filter(Boolean);
    if (lines.length === 0) return undefined;
    if (lines.length !== 1) throw new Error(`remote publication ref cardinality mismatch for ${ref}`);
    const [commit, observedRef, ...extra] = lines[0]!.split(/\s+/);
    if (extra.length !== 0 || observedRef !== ref || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(commit ?? "")) throw new Error(`remote publication ref malformed for ${ref}`);
    return commit!;
  }

  async dryRun(spec: MergeSpec): Promise<{ clean: boolean; identity?: MergePreflightIdentity; reason?: string }> {
    try {
      const resolved = await this.resolvedPublicationTarget(spec);
      await this.git.git(["check-ref-format", "--branch", spec.branch]);
      await this.git.git(["check-ref-format", "--branch", spec.baseBranch]);
      const candidateCommit = await this.commit(spec.branch);
      const head = await this.git.head();
      if (candidateCommit !== spec.expectedCandidateCommit || head !== candidateCommit) {
        return { clean: false, reason: "published candidate branch/HEAD does not equal the tested candidate commit" };
      }
      const project = await this.projectRoot(spec);
      await this.assertTreeMatchesWorktree(candidateCommit, project, spec);
      const candidateProjectManifestDigest = await computeMicrovmProjectSourceManifestSha256(project);
      if (candidateProjectManifestDigest !== spec.expectedCandidateProjectManifestDigest) {
        return { clean: false, reason: "published candidate bytes do not equal the completed Firecracker run manifest" };
      }
      const baseCommit = await this.commit(spec.baseBranch);
      // Appraise the exact actuator target before any checkout/merge mutation. It is reappraised again at effect time.
      if (resolved.transport && await this.remoteCommit(resolved.transport, spec.baseBranch) !== baseCommit) {
        return { clean: false, reason: "remote base ref does not equal the locally appraised base commit" };
      }
      const candidateTree = await this.tree(candidateCommit);
      const baseTree = await this.tree(baseCommit);
      // merge-tree --write-tree (git ≥2.38): computes the merge without touching the working tree; nonzero exit = conflict.
      const expectedMergedTree = (await this.git.git(["merge-tree", "--write-tree", baseCommit, candidateCommit])).stdout.trim().split(/\s+/)[0] ?? "";
      if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(expectedMergedTree)) return { clean: false, reason: "merge-tree did not return one exact result tree" };
      return { clean: true, identity: { candidateCommit, candidateTree, candidateProjectManifestDigest, baseCommit, baseTree, expectedMergedTree } };
    } catch (error) {
      return { clean: false, reason: `candidate/base identity or conflict preflight refused: ${(error as Error).message}`.slice(0, 240) };
    }
  }

  async merge(spec: MergeSpec, preflight: MergePreflightIdentity, preparePublication: (attempt: PublicationAttemptV1) => Promise<PreparedPublicationAuthority>): Promise<MergeOutcome> {
    // Recompute every load-bearing preflight field while the candidate is still checked out. The
    // preflight object is structural transport, not authority; caller substitution must buy nothing.
    let resolved: ResolvedPublicationTarget;
    try {
      resolved = await this.resolvedPublicationTarget(spec);
      const project = await this.projectRoot(spec);
      await this.assertTreeMatchesWorktree(preflight.candidateCommit, project, spec);
      if (await this.git.head() !== preflight.candidateCommit ||
          await this.commit(spec.branch) !== preflight.candidateCommit ||
          await this.tree(preflight.candidateCommit) !== preflight.candidateTree ||
          await computeMicrovmProjectSourceManifestSha256(project) !== preflight.candidateProjectManifestDigest ||
          preflight.candidateCommit !== spec.expectedCandidateCommit ||
          preflight.candidateProjectManifestDigest !== spec.expectedCandidateProjectManifestDigest) {
        return { merged: false, mergeId: "", reason: "candidate identity moved or was substituted after preflight" };
      }
    } catch (error) {
      return { merged: false, mergeId: "", reason: `candidate reappraisal failed: ${(error as Error).message}`.slice(0, 220) };
    }
    try {
      await this.git.git(["checkout", spec.baseBranch]);
    } catch (e) {
      return { merged: false, mergeId: "", reason: `checkout ${spec.baseBranch} failed: ${(e as Error).message}`.slice(0, 200) };
    }
    const before = await this.git.head();
    const candidateNow = await this.commit(spec.branch).catch(() => "");
    const baseTreeNow = await this.tree(before).catch(() => "");
    const candidateTreeNow = await this.tree(candidateNow).catch(() => "");
    const expectedTreeNow = (await this.git.git(["merge-tree", "--write-tree", before, candidateNow]).catch(() => ({ stdout: "", stderr: "" }))).stdout.trim().split(/\s+/)[0] ?? "";
    const remoteBaseNow = resolved.transport ? await this.remoteCommit(resolved.transport, spec.baseBranch).catch(() => "") : before;
    if (before !== preflight.baseCommit || baseTreeNow !== preflight.baseTree || candidateNow !== preflight.candidateCommit ||
        candidateTreeNow !== preflight.candidateTree || expectedTreeNow !== preflight.expectedMergedTree || candidateNow !== spec.expectedCandidateCommit ||
        remoteBaseNow !== before) {
      return { merged: false, mergeId: "", reason: "base or candidate moved after preflight" };
    }
    try {
      // Merge the frozen commit, never the mutable branch name checked above.
      const issue = spec.issueId.replace(/[^\x20-\x7e]/gu, "?").slice(0, 120);
      await this.git.git(["merge", "--no-ff", "-m", `keep: autonomous-merge ${issue} (${spec.branch})`, preflight.candidateCommit]);
    } catch (e) {
      try {
        await this.git.git(["merge", "--abort"]); // leave the base pristine on any conflict
        return { merged: false, mergeId: before, reason: `merge failed and was aborted: ${(e as Error).message}`.slice(0, 240) };
      } catch (abortError) {
        return { merged: false, mergeId: before, rollbackFailed: true, reason: `merge failed and abort failed: ${(e as Error).message}; ${(abortError as Error).message}`.slice(0, 300) };
      }
    }
    const mergeId = await this.git.head();
    if (mergeId === before) return { merged: false, mergeId: "", reason: "no-op merge (base already up to date)" };
    let publicationPreparationBegan = false;
    const compensate = async (reason: string): Promise<MergeOutcome> => {
      try {
        await appraiseGitMutationControlPlane(this.git, await this.projectRoot(spec));
        await this.git.revert(mergeId, 1);
        return { merged: false, mergeId, ...(publicationPreparationBegan ? { compensatedPublicationAbsent: true as const } : {}), reason: `${reason}; local merge was reverted`.slice(0, 300) };
      } catch (error) {
        return { merged: false, mergeId, rollbackFailed: true, reason: `${reason}; rollback failed: ${(error as Error).message}`.slice(0, 300) };
      }
    };
    let mergedTree: string;
    let publishedProjectManifestDigest: string;
    let project: string;
    try {
      mergedTree = await this.tree(mergeId);
      if (mergedTree !== preflight.expectedMergedTree) return await compensate("actual merge tree differs from preflight result tree");
      project = await this.projectRoot(spec);
      await this.assertTreeMatchesWorktree(mergeId, project, spec);
      publishedProjectManifestDigest = await computeMicrovmProjectSourceManifestSha256(project);
    } catch (error) {
      return await compensate(`post-merge identity appraisal failed: ${(error as Error).message}`);
    }
    let publishedCommit = this.opts.pushRemote ? "" : mergeId;
    let publicationTarget: string;
    try {
      resolved = await this.resolvedPublicationTarget(spec);
      publicationTarget = resolved.target;
    } catch (error) { return await compensate(`publication transport identity appraisal failed: ${(error as Error).message}`); }
    const preparedIdentity: PublishedMergeIdentity = {
      ...preflight, mergedCommit: mergeId, mergedTree, publishedCommit: mergeId, publishedTree: mergedTree,
      publishedProjectManifestDigest, publicationTarget,
    };
    try {
      publicationPreparationBegan = true;
      const attempt = makePublicationAttempt(spec, preparedIdentity);
      const authority = await preparePublication(attempt);
      if (!consumePreparedPublicationAuthority(authority, attempt, this.opts.publicationSpine)) {
        throw new Error("publication preparation authority is absent, forged, replayed, or bound to different bytes");
      }
    } catch (error) {
      return await compensate(`publication attempt was not durably prepared before effect: ${(error as Error).message}`);
    }
    if (resolved.transport) {
      try {
        const ref = `refs/heads/${spec.baseBranch}`;
        await appraiseGitMutationControlPlane(this.git, project);
        await this.git.git(["push", "--atomic", `--force-with-lease=${ref}:${before}`, "--", pinnedPushOperand(resolved.transport), `${mergeId}:${ref}`]);
      } catch (e) {
        // A transport error does not prove the push had no effect. Reconcile the authoritative ref before deciding.
        try {
          const observed = await this.remoteCommit(resolved.transport, spec.baseBranch);
          if (observed === mergeId) publishedCommit = observed;
          else if (observed === before) {
            return await compensate(`remote publication was observed unchanged after transport failure: ${(e as Error).message}`);
          } else {
            return { merged: false, mergeId, uncertainPublication: {
              attemptedCommit: mergeId,
              priorPublishedCommit: before,
              publicationTarget,
              reason: `push failed and remote ref moved to unexpected commit ${observed}`,
            } };
          }
        } catch (reconcileError) {
          return { merged: false, mergeId, uncertainPublication: {
            attemptedCommit: mergeId,
            priorPublishedCommit: before,
            publicationTarget,
            reason: `push result could not be observed: ${(e as Error).message}; reconciliation failed: ${(reconcileError as Error).message}`.slice(0, 300),
          } };
        }
      }
      // Even a zero-exit push is not promotion evidence until the exact remote ref is observed.
      if (publishedCommit !== mergeId) {
        try { publishedCommit = await this.remoteCommit(resolved.transport, spec.baseBranch); }
        catch (error) {
          return { merged: false, mergeId, uncertainPublication: {
            attemptedCommit: mergeId,
            priorPublishedCommit: before,
            publicationTarget,
            reason: `push returned success but confirmation failed: ${(error as Error).message}`.slice(0, 260),
          } };
        }
      }
      if (publishedCommit !== mergeId) {
        return { merged: false, mergeId, uncertainPublication: {
          attemptedCommit: mergeId,
          priorPublishedCommit: before,
          publicationTarget,
          reason: `remote ref identifies unexpected commit ${publishedCommit}`,
        } };
      }
    }
    const identity: PublishedMergeIdentity = {
      ...preflight,
      mergedCommit: mergeId,
      mergedTree,
      publishedCommit,
      publishedTree: mergedTree,
      publishedProjectManifestDigest,
      publicationTarget,
    };
    return { merged: true, mergeId, identity };
  }

  async observePublication(attemptValue: PublicationAttemptV1): Promise<PublicationObservation> {
    let attempt: PublicationAttemptV1;
    try { attempt = parsePublicationAttempt(attemptValue); }
    catch (error) { return { status: "conflict", reason: `publication recovery carrier refused: ${(error as Error).message}`.slice(0, 260) }; }
    let configured: ResolvedPublicationTarget;
    try { configured = await this.resolvedPublicationTarget(attempt.spec); }
    catch (error) {
      const message = (error as Error).message;
      const policyConflict = /(?:operator-pinned|does not equal|not explicitly permitted|forbidden|not allowlisted|malformed|noncanonical)/u.test(message);
      return { status: policyConflict ? "conflict" : "unavailable", reason: `configured publication target could not be resolved: ${message}`.slice(0, 240) };
    }
    if (attempt.publicationTarget !== configured.target) return { status: "conflict", reason: "publication target does not equal this port's configured transport identity" };
    if (!this.opts.pushRemote) {
      try {
        const observed = await this.commit(attempt.spec.baseBranch);
        if (observed === attempt.attemptedCommit) return { status: "effect-occurred", observedCommit: observed, reason: "exact local ref identifies attempted commit" };
        if (observed === attempt.priorPublishedCommit) return { status: "effect-absent", observedCommit: observed, reason: "exact local ref identifies predecessor" };
        return { status: "conflict", observedCommit: observed, reason: "local publication ref identifies a third commit" };
      } catch (error) { return { status: "unavailable", reason: `local publication ref could not be observed: ${(error as Error).message}`.slice(0, 240) }; }
    }
    if (!configured.transport) return { status: "conflict", reason: "remote publication attempt resolved without a pinned transport" };
    try {
      const observed = await this.observeRemoteCommit(configured.transport, attempt.spec.baseBranch);
      if (observed === undefined) return { status: "conflict", reason: "remote publication ref is absent" };
      if (observed === attempt.attemptedCommit) return { status: "effect-occurred", observedCommit: observed, reason: "exact remote ref identifies attempted commit" };
      if (observed === attempt.priorPublishedCommit) return { status: "effect-absent", observedCommit: observed, reason: "exact remote ref identifies predecessor" };
      return { status: "conflict", observedCommit: observed, reason: "remote publication ref identifies a third commit" };
    } catch (error) {
      return { status: "unavailable", reason: `remote publication ref could not be observed: ${(error as Error).message}`.slice(0, 240) };
    }
  }

  async reconcileAbsentPublication(attemptValue: PublicationAttemptV1): Promise<{ reconciled: boolean; reason: string }> {
    let attempt: PublicationAttemptV1;
    try { attempt = parsePublicationAttempt(attemptValue); }
    catch (error) { return { reconciled: false, reason: `publication recovery carrier refused: ${(error as Error).message}`.slice(0, 240) }; }
    try {
      await appraiseGitMutationControlPlane(this.git, await this.projectRoot(attempt.spec));
      await this.git.git(["check-ref-format", "--branch", attempt.spec.baseBranch]);
      const branch = (await this.git.git(["rev-parse", "--abbrev-ref", "HEAD"])).stdout.trim();
      if (branch !== attempt.spec.baseBranch) return { reconciled: false, reason: "checked-out branch does not equal the frozen publication base" };
      const branchCommit = await this.commit(attempt.spec.baseBranch);
      const head = await this.git.head();
      if (branchCommit === attempt.priorPublishedCommit && head === attempt.priorPublishedCommit) return { reconciled: true, reason: "local base already identifies exact predecessor" };
      if (branchCommit === head && await this.git.isClean()) {
        // A process may die after the compensating revert commit is durable but before the executor seals its
        // terminal. Recognize only the exact one-parent compensation shape and predecessor tree; never infer from a
        // clean worktree alone. This makes compensation idempotent without discarding or repeating an effect.
        const [headTree, priorTree, parent] = await Promise.all([
          this.tree(head),
          this.tree(attempt.priorPublishedCommit),
          this.commit(`${head}^`),
        ]).catch(() => ["", "", ""] as const);
        if (parent === attempt.attemptedCommit && headTree === priorTree) {
          return { reconciled: true, reason: "exact already-compensated commit restores the predecessor tree" };
        }
      }
      if (branchCommit !== attempt.attemptedCommit || head !== attempt.attemptedCommit || !(await this.git.isClean())) {
        return { reconciled: false, reason: "local base/HEAD/worktree is not the exact clean attempted publication state" };
      }
      const recoveryRef = `refs/keep/publication-recovery/${publicationAttemptDigest(attempt)}`;
      // Preserve the unpublished merge under a content-addressed recovery ref before restoring the isolated base.
      const preserved = await this.commit(recoveryRef).catch(() => "");
      if (preserved === "") {
        await this.git.git(["update-ref", recoveryRef, attempt.attemptedCommit, "0".repeat(attempt.attemptedCommit.length)]);
      } else if (preserved !== attempt.attemptedCommit) {
        return { reconciled: false, reason: "content-addressed publication recovery ref points at different bytes" };
      }
      // Exact preconditions above make this the documented safe scratch-worktree exception: no uncommitted bytes are
      // discarded, the attempted commit remains named, and only the unpublished base ref/worktree return to predecessor.
      await this.git.git(["reset", "--hard", attempt.priorPublishedCommit]);
      if (await this.commit(attempt.spec.baseBranch) !== attempt.priorPublishedCommit || await this.git.head() !== attempt.priorPublishedCommit || !(await this.git.isClean())) {
        return { reconciled: false, reason: "local predecessor restoration did not converge" };
      }
      return { reconciled: true, reason: `unpublished merge preserved at ${recoveryRef} and local base restored` };
    } catch (error) {
      return { reconciled: false, reason: `local publication residue reconciliation failed: ${(error as Error).message}`.slice(0, 260) };
    }
  }

  async confirmPublished(identity: PublishedMergeIdentity, spec: MergeSpec): Promise<{ current: boolean; reason?: string }> {
    try {
      const localCommit = await this.commit(spec.baseBranch);
      const localTree = await this.tree(localCommit);
      const project = await this.projectRoot(spec);
      await this.assertTreeMatchesWorktree(localCommit, project, spec);
      const projectDigest = await computeMicrovmProjectSourceManifestSha256(project);
      if (localCommit !== identity.mergedCommit || localTree !== identity.publishedTree || projectDigest !== identity.publishedProjectManifestDigest) {
        return { current: false, reason: "local published ref/tree/project bytes moved during verification" };
      }
      if (this.opts.pushRemote) {
        const resolved = await this.resolvedPublicationTarget(spec);
        if (identity.publicationTarget !== resolved.target || !resolved.transport) return { current: false, reason: "configured publication transport identity moved during verification" };
        const remoteCommit = await this.remoteCommit(resolved.transport, spec.baseBranch);
        if (remoteCommit !== identity.publishedCommit || remoteCommit !== identity.mergedCommit) return { current: false, reason: "remote published ref moved during verification" };
      }
      return { current: true };
    } catch (error) {
      return { current: false, reason: `publication confirmation refused: ${(error as Error).message}`.slice(0, 240) };
    }
  }

  /** Narrow recovery observation for a caller that lost the rich merge result after the exact commit landed. */
  async confirmPublicationCommit(commit: string, spec: MergeSpec, expectedPublicationTarget: string): Promise<{ current: boolean; reason?: string }> {
    try {
      const resolved = await this.resolvedPublicationTarget(spec);
      if (resolved.target !== expectedPublicationTarget) return { current: false, reason: "publication target changed during recovery" };
      if (await this.commit(spec.baseBranch) !== commit || await this.git.head() !== commit) return { current: false, reason: "local base does not identify the recovered merge" };
      if (resolved.transport && await this.remoteCommit(resolved.transport, spec.baseBranch) !== commit) return { current: false, reason: "remote base does not identify the recovered merge" };
      return { current: true };
    } catch (error) { return { current: false, reason: `publication recovery observation failed: ${(error as Error).message}`.slice(0, 240) }; }
  }

  async revert(mergeId: string, spec: MergeSpec, expectedPublicationTarget?: string): Promise<RevertOutcome> {
    try {
      const resolved = await this.resolvedPublicationTarget(spec);
      await this.git.git(["check-ref-format", "--branch", spec.baseBranch]);
      const branch = (await this.git.git(["rev-parse", "--abbrev-ref", "HEAD"])).stdout.trim();
      if (branch !== spec.baseBranch) return { reverted: false, reason: "checked-out branch does not equal the frozen publication base" };
      const head = await this.git.head();
      if (head !== mergeId) {
        const parents = (await this.git.git(["rev-list", "--parents", "-n", "1", head])).stdout.trim().split(/\s+/u);
        const message = (await this.git.git(["log", "-1", "--format=%B", head])).stdout;
        const expectedTree = await this.tree(`${mergeId}^1`).catch(() => "");
        const actualTree = await this.tree(head).catch(() => "");
        if (parents.length !== 2 || parents[0] !== head || parents[1] !== mergeId || !message.includes(`This reverts commit ${mergeId}`) || expectedTree === "" || actualTree !== expectedTree) {
          return { reverted: false, reason: "base moved after merge; refusing an ambiguous automatic revert" };
        }
        const reconciled = await this.reconcileRevertPublication(mergeId, head, spec, expectedPublicationTarget);
        return reconciled.reverted ? { ...reconciled, revertCommit: head } : reconciled;
      }
      if (resolved.transport && (!expectedPublicationTarget || expectedPublicationTarget !== resolved.target)) {
        return { reverted: false, reason: "configured publication transport identity moved before compensation" };
      }
      await this.git.revert(mergeId, 1); // -m 1: revert the merge against its first parent (the base line)
      const revertCommit = await this.git.head();
      if (resolved.transport) {
        await appraiseGitMutationControlPlane(this.git, await this.projectRoot(spec));
        await this.git.git(["push", `--force-with-lease=refs/heads/${branch}:${mergeId}`, "--", pinnedPushOperand(resolved.transport), `${revertCommit}:refs/heads/${branch}`]);
        if (await this.remoteCommit(resolved.transport, branch) !== revertCommit) return { reverted: false, reason: `local revert ${revertCommit} succeeded but remote revert publication was not observed` };
      }
      return { reverted: true, revertCommit };
    } catch (e) {
      const localHead = await this.git.head().catch(() => "unknown");
      return { reverted: false, reason: `revert transaction failed or split: localHead=${localHead}; ${(e as Error).message}`.slice(0, 260) };
    }
  }

  /** Recover a revert whose local commit survived but whose remote acknowledgement did not. */
  async reconcileRevertPublication(mergeId: string, revertCommit: string, spec: MergeSpec, expectedPublicationTarget?: string): Promise<RevertOutcome> {
    try {
      const resolved = await this.resolvedPublicationTarget(spec);
      if (await this.git.head() !== revertCommit) return { reverted: false, reason: "local revert commit moved before publication recovery" };
      if (!resolved.transport) return { reverted: true, revertCommit };
      if (!expectedPublicationTarget || expectedPublicationTarget !== resolved.target) return { reverted: false, reason: "configured publication transport identity moved before revert recovery" };
      const remote = await this.observeRemoteCommit(resolved.transport, spec.baseBranch);
      if (remote === revertCommit) return { reverted: true, revertCommit };
      if (remote !== mergeId) return { reverted: false, reason: "remote base moved outside the exact merge/revert recovery transition" };
      await appraiseGitMutationControlPlane(this.git, await this.projectRoot(spec));
      await this.git.git(["push", `--force-with-lease=refs/heads/${spec.baseBranch}:${mergeId}`, "--", pinnedPushOperand(resolved.transport), `${revertCommit}:refs/heads/${spec.baseBranch}`]);
      return await this.remoteCommit(resolved.transport, spec.baseBranch) === revertCommit
        ? { reverted: true, revertCommit }
        : { reverted: false, reason: "remote revert recovery publication was not observed" };
    } catch (error) {
      return { reverted: false, reason: `revert publication recovery failed safely: ${(error as Error).message}`.slice(0, 260) };
    }
  }
}
