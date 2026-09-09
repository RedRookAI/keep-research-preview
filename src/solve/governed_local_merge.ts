/** Human-authorized, local-only merge of one persisted installed-project proposal. */
import { createHash } from "node:crypto";
import type { Spine } from "../spine/spine.js";
import type { ProjectCheckpointStore } from "../autonomy/project_checkpoint_store.js";
import type { ProjectImplementationArtifact } from "./project_loop_wiring.js";
import { GitAdapter } from "../infra/git_adapter.js";
import { GitMergePort } from "../git/git_merge_port.js";
import { computeMicrovmProjectSourceManifestSha256 } from "../infra/microvm_boundary.js";
import type { IdentityRegistry, AgentIdentity } from "../identity/agent_identity.js";
import type { MergeSpec } from "../oversight/merge_executor.js";
import type { DevelopmentForgeTarget } from "../git/repository_materializer.js";

class CrashProbeInterruption extends Error {
  constructor(readonly interruption: unknown) { super("simulated process interruption"); }
}

export type LocalMergeDecision = "approve" | "veto";
export interface LocalMergeResult { readonly status: "merged" | "refused" | "failed"; readonly reason: string; readonly mergeId?: string; readonly publicationTarget?: string; readonly decision?: LocalMergeDecision }
export interface LocalRevertResult { readonly status: "reverted" | "refused" | "failed"; readonly reason: string; readonly mergeId?: string; readonly revertCommit?: string }

export interface GovernedLocalMergeDeps {
  readonly spine: Spine;
  /** Canonical authenticated durable state owner; merge never reconstructs from audit prose/events. */
  readonly checkpoints: ProjectCheckpointStore;
  readonly identityRegistry: IdentityRegistry;
  readonly rootIdentity: AgentIdentity;
  readonly projectDir: (repoRef: string) => string;
  readonly baseBranch: string;
  /** Captured original repository. Present only for installed materialized projects. */
  readonly sourceDir?: string;
  readonly advanceMaterialization?: (commit: string) => Promise<void>;
  readonly developmentForge?: DevelopmentForgeTarget;
  /** Test-only process-crash seam. Production composition leaves this absent. */
  readonly crashProbe?: (phase: "merge.intent-sealed" | "merge.candidate-branch-created" | "merge.candidate-committed" | "merge.effect-completed" | "revert.intent-sealed" | "revert.effect-completed") => void;
}

export class GovernedLocalMerge {
  constructor(private readonly deps: GovernedLocalMergeDeps) {}

  private async record(runId: string, result: LocalMergeResult): Promise<LocalMergeResult> {
    this.deps.spine.stage({ type: "identity.action", actor: "governed-local-merge", payload: { event: `local_merge.${result.status}`, runId, reason: result.reason, ...(result.decision ? { decision: result.decision } : {}), ...(result.mergeId ? { mergeId: result.mergeId } : {}), ...(result.publicationTarget ? { publicationTarget: result.publicationTarget } : {}) } });
    await this.deps.spine.seal();
    return result.status === "merged" && result.mergeId && this.deps.sourceDir ? this.landSource(runId, result) : result;
  }

  private async landSource(runId: string, result: LocalMergeResult): Promise<LocalMergeResult> {
    const mergeId = result.mergeId!;
    const state = this.deps.checkpoints.load(runId);
    const artifact = state?.artifacts["implement"] as ProjectImplementationArtifact | undefined;
    const evidence = artifact?.solve?.proposalEvidence;
    if (!artifact?.solve || !evidence) return { status: "failed", mergeId, reason: "source landing lacks the durable verified proposal" };
    const source = new GitAdapter(this.deps.sourceDir!);
    const workspaceDir = this.deps.projectDir(artifact.issue.repoRef);
    const workspace = new GitAdapter(workspaceDir);
    const operationId = this.operationId("merge", { runId, mergeId, sourceBase: evidence.baseRevision, sourceBranch: this.deps.baseBranch, patchSha256: evidence.rollback.patchSha256 });
    const terminal = this.deps.spine.replay().find((event) => event.type === "effect.terminal" && event.payload["kind"] === "source_landing.terminal" && event.payload["operationId"] === operationId);
    try {
      if (terminal) {
        if (await source.head() !== mergeId || !(await source.isClean())) return { status: "failed", mergeId, reason: "recorded source landing no longer matches the declared source" };
        return { ...result, reason: "reviewed proposal is already landed in the declared source repository" };
      }
      const workspaceCommit = (await workspace.git(["rev-parse", "--verify", `${mergeId}^{commit}`])).stdout.trim();
      const parents = (await workspace.git(["rev-list", "--parents", "-n", "1", mergeId])).stdout.trim().split(/\s+/u);
      const diff = (await workspace.git(["diff", "--binary", "--no-ext-diff", evidence.baseRevision, mergeId, "--"])).stdout;
      if (workspaceCommit !== mergeId || parents.length !== 3 || parents[1] !== evidence.baseRevision || diff !== evidence.diff) return { status: "failed", mergeId, reason: "workspace merge is not the exact durable reviewed proposal" };
      const intents = this.deps.spine.replay().filter((event) => event.type === "effect.intent" && event.payload["kind"] === "source_landing.intent" && event.payload["runId"] === runId);
      const intent = intents.find((event) => event.payload["operationId"] === operationId);
      if (intents.length > 1 || (intents.length === 1 && !intent)) return { status: "failed", mergeId, reason: "source landing intent is ambiguous" };
      const branch = (await source.git(["branch", "--show-current"])).stdout.trim();
      const sourceHead = await source.head();
      if (sourceHead === mergeId && branch === this.deps.baseBranch && await source.isClean()) {
        await this.deps.advanceMaterialization?.(mergeId);
        this.deps.spine.stage({ type: "effect.terminal", actor: "governed-source-landing", payload: { kind: "source_landing.terminal", operationId, runId, mergeId, sourceBase: evidence.baseRevision, sourceBranch: this.deps.baseBranch, disposition: "landed" } });
        await this.deps.spine.seal();
        return { ...result, reason: "reconciled the exact reviewed source landing without redispatch" };
      }
      if (branch !== this.deps.baseBranch || sourceHead !== evidence.baseRevision || !(await source.isClean())) return { status: "failed", mergeId, reason: "declared source branch, base, or working tree moved; source was not landed" };
      if (!intent) {
        if (!this.deps.spine.durableStorage()) return { status: "failed", mergeId, reason: "source landing requires an fsync-durable pre-effect journal" };
        this.deps.spine.stage({ type: "effect.intent", actor: "governed-source-landing", payload: { kind: "source_landing.intent", operationId, runId, mergeId, sourceBase: evidence.baseRevision, sourceBranch: this.deps.baseBranch, patchSha256: evidence.rollback.patchSha256 } });
        await this.deps.spine.seal();
      }
      await source.git(["fetch", "--no-tags", "--", workspaceDir, mergeId]);
      if ((await source.git(["branch", "--show-current"])).stdout.trim() !== this.deps.baseBranch || await source.head() !== evidence.baseRevision || !(await source.isClean())) return { status: "failed", mergeId, reason: "declared source moved during landing; its branch was not updated" };
      await source.git(["merge", "--ff-only", "--no-edit", mergeId]);
      if (await source.head() !== mergeId || !(await source.isClean())) return { status: "failed", mergeId, reason: "source landing did not produce the exact reviewed commit" };
      await this.deps.advanceMaterialization?.(mergeId);
      this.deps.spine.stage({ type: "effect.terminal", actor: "governed-source-landing", payload: { kind: "source_landing.terminal", operationId, runId, mergeId, sourceBase: evidence.baseRevision, sourceBranch: this.deps.baseBranch, disposition: "landed" } });
      await this.deps.spine.seal();
      return { ...result, reason: "authorized reviewed proposal landed in the declared source repository" };
    } catch (error) { return { status: "failed", mergeId, reason: `source landing failed closed: ${(error as Error).message}`.slice(0, 300) }; }
  }

  private operationId(kind: "merge" | "revert", fields: Record<string, string>): string {
    return createHash("sha256").update(JSON.stringify({ kind, ...fields })).digest("hex");
  }

  private probe(phase: Parameters<NonNullable<GovernedLocalMergeDeps["crashProbe"]>>[0]): void {
    try { this.deps.crashProbe?.(phase); }
    catch (error) { throw new CrashProbeInterruption(error); }
  }

  private completedMerge(runId: string): LocalMergeResult | undefined {
    const event = this.deps.spine.replay().find((row) => {
      const payload = row.payload as Record<string, unknown>;
      return payload["event"] === "local_merge.merged" && payload["runId"] === runId && typeof payload["mergeId"] === "string";
    });
    return event ? { status: "merged", reason: "authorized reversible proposal was already merged", mergeId: String(event.payload["mergeId"]), ...(typeof event.payload["publicationTarget"] === "string" ? { publicationTarget: String(event.payload["publicationTarget"]) } : {}) } : undefined;
  }

  private port(git: GitAdapter): GitMergePort {
    const forge = this.deps.developmentForge;
    return new GitMergePort(git, { publicationSpine: this.deps.spine, ...(forge ? { pushRemote: forge.remote, expectedFetchUrlSha256: forge.expectedFetchUrlSha256, expectedPushUrlSha256: forge.expectedPushUrlSha256 } : {}) });
  }

  private async exactMergeOnBase(git: GitAdapter, baseRevision: string, candidateCommit: string): Promise<string | undefined> {
    const baseTip = (await git.git(["rev-parse", "--verify", `${this.deps.baseBranch}^{commit}`])).stdout.trim();
    const rows = (await git.git(["rev-list", "--first-parent", `${baseRevision}..${baseTip}`])).stdout.trim().split("\n").filter(Boolean);
    for (const commit of rows) {
      const parents = (await git.git(["rev-list", "--parents", "-n", "1", commit])).stdout.trim().split(/\s+/u);
      if (parents.length !== 3 || parents[1] !== baseRevision || parents[2] !== candidateCommit) continue;
      const expectedTree = (await git.git(["merge-tree", "--write-tree", baseRevision, candidateCommit])).stdout.trim().split(/\s+/u)[0];
      const actualTree = (await git.git(["rev-parse", `${commit}^{tree}`])).stdout.trim();
      if (expectedTree === actualTree) return commit;
    }
    return undefined;
  }

  private async exactRevertOnBase(git: GitAdapter, headBefore: string, mergeId: string, proposalDiff: string): Promise<string | undefined> {
    const baseTip = (await git.git(["rev-parse", "--verify", `${this.deps.baseBranch}^{commit}`])).stdout.trim();
    const rows = (await git.git(["rev-list", "--first-parent", `${headBefore}..${baseTip}`])).stdout.trim().split("\n").filter(Boolean);
    for (const commit of rows) {
      const parents = (await git.git(["rev-list", "--parents", "-n", "1", commit])).stdout.trim().split(/\s+/u);
      if (parents.length !== 2 || parents[1] !== headBefore) continue;
      const message = (await git.git(["log", "-1", "--format=%B", commit])).stdout;
      if (!message.includes(`This reverts commit ${mergeId}`)) continue;
      const restoredForwardDiff = (await git.git(["diff", "--binary", "--no-ext-diff", commit, headBefore, "--"])).stdout;
      if (restoredForwardDiff === proposalDiff) return commit;
    }
    return undefined;
  }

  private async landSourceRevert(runId: string, mergeId: string, revertCommit: string, result: LocalRevertResult): Promise<LocalRevertResult> {
    if (!this.deps.sourceDir) return result;
    const state = this.deps.checkpoints.load(runId);
    const artifact = state?.artifacts["implement"] as ProjectImplementationArtifact | undefined;
    const evidence = artifact?.solve?.proposalEvidence;
    if (!artifact?.solve || !evidence) return { status: "failed", mergeId, reason: "source revert lacks the durable verified proposal" };
    const source = new GitAdapter(this.deps.sourceDir);
    const workspaceDir = this.deps.projectDir(artifact.issue.repoRef);
    const workspace = new GitAdapter(workspaceDir);
    const operationId = this.operationId("revert", { runId, mergeId, revertCommit, patchSha256: evidence.rollback.patchSha256 });
    try {
      const terminal = this.deps.spine.replay().find((event) => event.type === "effect.terminal" && event.payload["kind"] === "source_revert.terminal" && event.payload["operationId"] === operationId);
      if (terminal) {
        if (await source.head() !== revertCommit || !(await source.isClean())) return { status: "failed", mergeId, revertCommit, reason: "recorded source revert no longer matches the declared source" };
        return { ...result, reason: "source revert already completed" };
      }
      const parents = (await workspace.git(["rev-list", "--parents", "-n", "1", revertCommit])).stdout.trim().split(/\s+/u);
      const restored = (await workspace.git(["diff", "--binary", "--no-ext-diff", revertCommit, mergeId, "--"])).stdout;
      if (parents.length !== 2 || parents[1] !== mergeId || restored !== evidence.diff) return { status: "failed", mergeId, revertCommit, reason: "workspace revert is not the exact inverse of the reviewed proposal" };
      const intents = this.deps.spine.replay().filter((event) => event.type === "effect.intent" && event.payload["kind"] === "source_revert.intent" && event.payload["runId"] === runId);
      const intent = intents.find((event) => event.payload["operationId"] === operationId);
      if (intents.length > 1 || (intents.length === 1 && !intent)) return { status: "failed", mergeId, revertCommit, reason: "source revert intent is ambiguous" };
      const branch = (await source.git(["branch", "--show-current"])).stdout.trim();
      const sourceHead = await source.head();
      if (sourceHead === revertCommit && branch === this.deps.baseBranch && await source.isClean()) {
        await this.deps.advanceMaterialization?.(revertCommit);
        this.deps.spine.stage({ type: "effect.terminal", actor: "governed-source-landing", payload: { kind: "source_revert.terminal", operationId, runId, mergeId, revertCommit, disposition: "reverted" } });
        await this.deps.spine.seal();
        return { ...result, reason: "reconciled exact source revert without redispatch" };
      }
      if (branch !== this.deps.baseBranch || sourceHead !== mergeId || !(await source.isClean())) return { status: "failed", mergeId, revertCommit, reason: "declared source moved after landing; exact source revert refused" };
      if (!intent) {
        if (!this.deps.spine.durableStorage()) return { status: "failed", mergeId, revertCommit, reason: "source revert requires an fsync-durable pre-effect journal" };
        this.deps.spine.stage({ type: "effect.intent", actor: "governed-source-landing", payload: { kind: "source_revert.intent", operationId, runId, mergeId, revertCommit, patchSha256: evidence.rollback.patchSha256 } });
        await this.deps.spine.seal();
      }
      await source.git(["fetch", "--no-tags", "--", workspaceDir, revertCommit]);
      if ((await source.git(["branch", "--show-current"])).stdout.trim() !== this.deps.baseBranch || await source.head() !== mergeId || !(await source.isClean())) return { status: "failed", mergeId, revertCommit, reason: "declared source moved during revert; its branch was not updated" };
      await source.git(["merge", "--ff-only", "--no-edit", revertCommit]);
      if (await source.head() !== revertCommit || !(await source.isClean())) return { status: "failed", mergeId, revertCommit, reason: "source revert did not land the exact inverse commit" };
      await this.deps.advanceMaterialization?.(revertCommit);
      this.deps.spine.stage({ type: "effect.terminal", actor: "governed-source-landing", payload: { kind: "source_revert.terminal", operationId, runId, mergeId, revertCommit, disposition: "reverted" } });
      await this.deps.spine.seal();
      return { ...result, reason: "declared source was reverted with the exact history-preserving inverse commit" };
    } catch (error) { return { status: "failed", mergeId, revertCommit, reason: `source revert failed closed: ${(error as Error).message}`.slice(0, 300) }; }
  }

  async decide(runId: string, decision: LocalMergeDecision, proposalDigest?: string): Promise<LocalMergeResult> {
    return this.deps.spine.withCoordinationLock("local-merge.coordinator", () => this.decideLocked(runId, decision, proposalDigest));
  }

  private async decideLocked(runId: string, decision: LocalMergeDecision, proposalDigest?: string): Promise<LocalMergeResult> {
    // Finish any interrupted Spine block/cursor publication before deriving idempotency state.
    await this.deps.spine.seal();
    const live = this.deps.identityRegistry.authorize(this.deps.rootIdentity);
    if (!live.authorized) return this.record(runId, { status: "refused", reason: `solver kill switch prevents merge: ${live.reason}` });
    const previouslyVetoed = this.deps.spine.replay().some((event) => {
      const payload = event.payload as Record<string, unknown>;
      return payload["event"] === "local_merge.refused" && payload["runId"] === runId && payload["decision"] === "veto";
    });
    if (previouslyVetoed) return this.record(runId, { status: "refused", reason: "operator veto is durable for this proposal" });

    const state = this.deps.checkpoints.load(runId);
    const artifact = state?.artifacts["implement"] as ProjectImplementationArtifact | undefined;
    const solve = artifact?.solve;
    const evidence = solve?.proposalEvidence;
    if (!evidence || proposalDigest !== evidence.rollback.patchSha256) return this.record(runId, { status: "refused", decision, reason: "proposal digest is missing or does not match the durable reviewed proposal" });
    if (decision === "veto") return this.record(runId, { status: "refused", decision: "veto", reason: "operator vetoed the exact reviewed proposal" });
    if (solve?.validation && (!solve.validation.testsPassed || solve.validation.vettingCleared === false)) {
      return this.record(runId, { status: "refused", reason: "persisted proposal checks did not pass" });
    }
    if (!artifact || !solve?.solved || !solve.prProposal || !evidence?.consequence) {
      return this.record(runId, { status: "refused", reason: "no complete governed recoverable proposal is persisted" });
    }
    if (!solve.validation?.testsPassed || solve.validation.vettingCleared === false || !evidence.checks.testsPassed || evidence.checks.vettingCleared === false) {
      return this.record(runId, { status: "refused", reason: "persisted proposal checks did not pass" });
    }
    if (artifact.mergeAuthority?.verdict !== "autonomous-merge") {
      return this.record(runId, { status: "refused", reason: `merge authority is ${artifact.mergeAuthority?.verdict ?? "absent"}` });
    }
    if (createHash("sha256").update(evidence.diff).digest("hex") !== evidence.rollback.patchSha256) {
      return this.record(runId, { status: "refused", reason: "persisted proposal diff no longer matches its rollback binding" });
    }
    const completed = this.completedMerge(runId);
    if (completed) return this.deps.sourceDir ? this.landSource(runId, completed) : completed;

    const projectDir = this.deps.projectDir(artifact.issue.repoRef);
    const git = new GitAdapter(projectDir);
    const branch = solve.prProposal.branch;
    const operationId = this.operationId("merge", { runId, repoRef: artifact.issue.repoRef, baseRevision: evidence.baseRevision, branch, patchSha256: evidence.rollback.patchSha256 });
    const intents = this.deps.spine.replay().filter((event) => event.type === "effect.intent" && event.payload["kind"] === "local_merge.intent" && event.payload["runId"] === runId);
    const intent = intents.find((event) => event.payload["operationId"] === operationId);
    if (intents.length > 1 || (intents.length === 1 && !intent) || (intent && (
      intent.payload["repoRef"] !== artifact.issue.repoRef || intent.payload["baseRevision"] !== evidence.baseRevision ||
      intent.payload["branch"] !== branch || intent.payload["patchSha256"] !== evidence.rollback.patchSha256
    ))) return this.record(runId, { status: "refused", reason: "durable local merge intent is ambiguous or does not match this proposal" });
    try {
      await git.git(["check-ref-format", "--branch", branch]);
      if (!intent) {
        const base = (await git.git(["rev-parse", "--verify", `${this.deps.baseBranch}^{commit}`])).stdout.trim();
        const head = await git.head();
        if (base !== evidence.baseRevision || head !== evidence.baseRevision) return this.record(runId, { status: "refused", reason: "base is stale or HEAD moved since proposal verification" });
        const observedDiff = (await git.git(["diff", "--binary", "--no-ext-diff", evidence.baseRevision, "--"])).stdout;
        if (observedDiff !== evidence.diff) return this.record(runId, { status: "refused", reason: "working tree differs from the persisted verified proposal" });
        if (!this.deps.spine.durableStorage()) return this.record(runId, { status: "refused", reason: "local merge requires an fsync-durable pre-effect journal" });
        this.deps.spine.stage({ type: "effect.intent", actor: "governed-local-merge", payload: {
          kind: "local_merge.intent", operationId, runId, repoRef: artifact.issue.repoRef,
          baseRevision: evidence.baseRevision, branch, patchSha256: evidence.rollback.patchSha256,
        } });
        await this.deps.spine.seal();
        this.probe("merge.intent-sealed");
      }
      // The gates above precede every mutation. Bind the local candidate and merge commits to Keep's explicit identity.
      await git.git(["config", "user.name", "Keep"]);
      await git.git(["config", "user.email", "keep@local"]);
      let candidateCommit = (await git.git(["rev-parse", "--verify", `refs/heads/${branch}^{commit}`]).catch(() => ({ stdout: "", stderr: "" }))).stdout.trim();
      if (!candidateCommit) {
        await git.git(["checkout", "-b", branch]);
        this.probe("merge.candidate-branch-created");
        await git.git(["add", "-A"]);
        await git.git(["-c", "user.name=Keep", "-c", "user.email=keep@local", "commit", "--no-verify", "-m", solve.prProposal.title]);
        candidateCommit = await git.head();
        this.probe("merge.candidate-committed");
      } else if (candidateCommit === evidence.baseRevision) {
        const branchNow = (await git.git(["branch", "--show-current"])).stdout.trim();
        const pendingDiff = (await git.git(["diff", "--binary", "--no-ext-diff", evidence.baseRevision, "--"])).stdout;
        if (branchNow !== branch || await git.head() !== evidence.baseRevision || pendingDiff !== evidence.diff) throw new Error("partial recovery branch does not retain the exact prepared proposal");
        await git.git(["add", "-A"]);
        await git.git(["-c", "user.name=Keep", "-c", "user.email=keep@local", "commit", "--no-verify", "-m", solve.prProposal.title]);
        candidateCommit = await git.head();
        this.probe("merge.candidate-committed");
      } else {
        const parent = (await git.git(["rev-parse", `${candidateCommit}^`])).stdout.trim();
        const candidateDiff = (await git.git(["diff", "--binary", "--no-ext-diff", evidence.baseRevision, candidateCommit, "--"])).stdout;
        if (parent !== evidence.baseRevision || candidateDiff !== evidence.diff) throw new Error("recovery candidate does not equal the durably prepared proposal");
        const observedMerge = await this.exactMergeOnBase(git, evidence.baseRevision, candidateCommit);
        if (observedMerge) {
          let publicationTarget: string | undefined;
          if (this.deps.developmentForge) {
            const recoverySpec: MergeSpec = { issueId: solve.issueId, repoRef: artifact.issue.repoRef, branch, baseBranch: this.deps.baseBranch, expectedCandidateCommit: candidateCommit, expectedCandidateProjectManifestDigest: "0".repeat(64), expectedGuestExecutionRequestDigest: evidence.rollback.patchSha256, projectDir };
            const recoveryPort = this.port(git); publicationTarget = recoveryPort.publicationTarget(recoverySpec);
            const confirmation = await recoveryPort.confirmPublicationCommit(observedMerge, recoverySpec, publicationTarget);
            if (!confirmation.current) return this.record(runId, { status: "failed", mergeId: observedMerge, reason: confirmation.reason ?? "private forge publication could not be recovered" });
          }
          this.probe("merge.effect-completed");
          return this.record(runId, { status: "merged", mergeId: observedMerge, ...(publicationTarget ? { publicationTarget } : {}), reason: "reconciled exact repository merge without redispatch" });
        }
        const branchNow = (await git.git(["branch", "--show-current"])).stdout.trim();
        if (branchNow !== branch || await git.head() !== candidateCommit) await git.git(["checkout", branch]);
      }
      const candidateProjectManifestDigest = await computeMicrovmProjectSourceManifestSha256(projectDir);
      const spec: MergeSpec = {
        issueId: solve.issueId, repoRef: artifact.issue.repoRef, branch, baseBranch: this.deps.baseBranch,
        expectedCandidateCommit: candidateCommit, expectedCandidateProjectManifestDigest: candidateProjectManifestDigest,
        expectedGuestExecutionRequestDigest: evidence.rollback.patchSha256, projectDir,
      };
      const port = this.port(git);
      const preflight = await port.dryRun(spec);
      if (!preflight.clean || !preflight.identity) return this.record(runId, { status: "failed", reason: preflight.reason ?? "local merge preflight failed" });
      const merged = await port.merge(spec, preflight.identity, (attempt) => port.preparePublication(attempt));
      if (!merged.merged) return this.record(runId, { status: "failed", reason: merged.reason ?? "local merge failed", ...(merged.mergeId ? { mergeId: merged.mergeId } : {}) });
      this.probe("merge.effect-completed");
      return this.record(runId, { status: "merged", mergeId: merged.mergeId, ...(merged.identity?.publicationTarget ? { publicationTarget: merged.identity.publicationTarget } : {}), reason: this.deps.developmentForge ? "authorized reversible proposal merged and published to the private development forge" : "authorized reversible proposal merged locally" });
    } catch (error) {
      if (error instanceof CrashProbeInterruption) throw error.interruption;
      return this.record(runId, { status: "failed", reason: (error as Error).message.slice(0, 300) });
    }
  }

  async revert(runId: string): Promise<LocalRevertResult> {
    return this.deps.spine.withCoordinationLock("local-merge.coordinator", async () => {
      await this.deps.spine.seal();
      const replay = this.deps.spine.replay();
      const merged = replay.map((event) => event.payload as Record<string, unknown>).find((payload) =>
        payload["event"] === "local_merge.merged" && payload["runId"] === runId && typeof payload["mergeId"] === "string",
      );
      if (!merged) return { status: "refused", reason: "no accepted local merge exists for this project run" };
      const mergeId = String(merged["mergeId"]);
      const expectedPublicationTarget = typeof merged["publicationTarget"] === "string" ? String(merged["publicationTarget"]) : undefined;
      const prior = replay.find((event) => {
        const payload = event.payload as Record<string, unknown>;
        return event.type === "effect.terminal" && payload["kind"] === "local_merge.revert_terminal" && payload["runId"] === runId && payload["mergeId"] === mergeId;
      });
      if (prior) {
        const payload = prior.payload as Record<string, unknown>;
        const result = { status: "reverted" as const, reason: "workspace revert already completed", mergeId, revertCommit: String(payload["revertCommit"]) };
        return this.landSourceRevert(runId, mergeId, result.revertCommit, result);
      }
      const state = this.deps.checkpoints.load(runId);
      const artifact = state?.artifacts["implement"] as ProjectImplementationArtifact | undefined;
      if (!artifact?.solve) return { status: "refused", reason: "verified project implementation artifact is unavailable" };
      const evidence = artifact.solve.proposalEvidence;
      if (!evidence) return { status: "refused", reason: "project proposal evidence is unavailable" };
      const projectDir = this.deps.projectDir(artifact.issue.repoRef);
      const git = new GitAdapter(projectDir);
      try {
        const branch = (await git.git(["branch", "--show-current"])).stdout.trim();
        if (branch !== this.deps.baseBranch) return { status: "refused", reason: "local revert requires the configured base branch to be checked out", mergeId };
        const parents = (await git.git(["rev-list", "--parents", "-n", "1", mergeId])).stdout.trim().split(/\s+/u);
        if (parents.length !== 3 || parents[0] !== mergeId) return { status: "refused", reason: "recorded merge is not one exact two-parent merge commit", mergeId };
        await git.git(["merge-base", "--is-ancestor", mergeId, "HEAD"]);
        const mergeParents = (await git.git(["rev-list", "--parents", "-n", "1", mergeId])).stdout.trim().split(/\s+/u);
        const candidateCommit = mergeParents[2]!;
        const spec: MergeSpec = {
          issueId: artifact.solve.issueId, repoRef: artifact.issue.repoRef, branch: artifact.solve.prProposal?.branch ?? "keep/recovery",
          baseBranch: this.deps.baseBranch, expectedCandidateCommit: candidateCommit,
          expectedCandidateProjectManifestDigest: await computeMicrovmProjectSourceManifestSha256(projectDir),
          expectedGuestExecutionRequestDigest: evidence.rollback.patchSha256, projectDir,
        };
        const port = this.port(git);
        const prepared = replay.find((event) => event.type === "effect.intent" && event.payload["kind"] === "local_merge.revert_intent" && event.payload["runId"] === runId && event.payload["mergeId"] === mergeId);
        let operationId: string;
        let headBefore: string;
        if (prepared) {
          operationId = String(prepared.payload["operationId"] ?? "");
          headBefore = String(prepared.payload["headBefore"] ?? "");
          const expected = this.operationId("revert", { runId, mergeId, headBefore, patchSha256: evidence.rollback.patchSha256 });
          if (operationId !== expected || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(headBefore)) return { status: "refused", reason: "durable revert intent is malformed or does not match this proposal", mergeId };
        } else {
          if (!this.deps.spine.durableStorage()) return { status: "refused", reason: "local revert requires an fsync-durable pre-effect journal", mergeId };
          headBefore = await git.head();
          operationId = this.operationId("revert", { runId, mergeId, headBefore, patchSha256: evidence.rollback.patchSha256 });
          this.deps.spine.stage({ type: "effect.intent", actor: "governed-local-merge", payload: {
            kind: "local_merge.revert_intent", operationId, runId, mergeId, headBefore, patchSha256: evidence.rollback.patchSha256,
          } });
          await this.deps.spine.seal();
          this.probe("revert.intent-sealed");
        }
        const observed = await this.exactRevertOnBase(git, headBefore, mergeId, evidence.diff);
        if (observed) {
          if (this.deps.developmentForge) {
            const reconciled = await port.reconcileRevertPublication(mergeId, observed, spec, expectedPublicationTarget);
            if (!reconciled.reverted) return { status: "failed", reason: reconciled.reason ?? "revert publication recovery failed", mergeId, revertCommit: observed };
          }
          this.probe("revert.effect-completed");
          this.deps.spine.stage({ type: "effect.terminal", actor: "governed-local-merge", payload: {
            kind: "local_merge.revert_terminal", operationId, runId, mergeId, revertCommit: observed, disposition: "reverted",
          } });
          await this.deps.spine.seal();
          const result = { status: "reverted" as const, reason: "reconciled exact workspace revert without redispatch", mergeId, revertCommit: observed };
          return this.landSourceRevert(runId, mergeId, observed, result);
        }
        if (await git.head() !== headBefore) return { status: "refused", reason: "base moved after the durable revert intent; no exact revert effect was observed", mergeId };
        if (this.deps.developmentForge) {
          const reverted = await port.revert(mergeId, spec, expectedPublicationTarget);
          if (!reverted.reverted) return { status: "failed", reason: reverted.reason ?? "revert transaction failed", mergeId };
        } else await git.git(["revert", "--no-edit", "-m", "1", mergeId]);
        const revertCommit = await git.head();
        this.probe("revert.effect-completed");
        this.deps.spine.stage({ type: "effect.terminal", actor: "governed-local-merge", payload: {
          kind: "local_merge.revert_terminal", operationId, runId, mergeId, revertCommit, disposition: "reverted",
        } });
        await this.deps.spine.seal();
        const result = { status: "reverted" as const, reason: "accepted workspace merge was reverted with a new history-preserving commit", mergeId, revertCommit };
        return this.landSourceRevert(runId, mergeId, revertCommit, result);
      } catch (error) {
        if (error instanceof CrashProbeInterruption) throw error.interruption;
        try { await git.git(["revert", "--abort"]); } catch { /* no in-progress revert or abort unavailable */ }
        return { status: "failed", reason: `local revert failed without rewriting history: ${(error as Error).message}`.slice(0, 300), mergeId };
      }
    });
  }
}
