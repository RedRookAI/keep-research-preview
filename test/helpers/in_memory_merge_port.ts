import { makePublicationAttempt, type MergePort, type MergeSpec, type MergeOutcome, type MergePreflightIdentity, type PreparedPublicationAuthority, type PublicationAttemptV1, type PublicationObservation, type RevertOutcome } from "../../src/oversight/merge_executor.js";

/** Effect-free test double. It is outside the shipped source/package and cannot receive product authority. */
export class InMemoryMergePort implements MergePort {
  readonly log: string[] = [];
  private readonly merges = new Map<string, MergeSpec>();
  constructor(private readonly opts: { dryRunClean?: boolean; mergeSucceeds?: boolean; revertSucceeds?: boolean; confirmCurrent?: boolean; publicationUncertain?: boolean } = {}) {}
  publicationTarget(spec: MergeSpec): string { return `simulation:${spec.baseBranch}`; }
  async dryRun(spec: MergeSpec): Promise<{ clean: boolean; identity?: MergePreflightIdentity; reason?: string }> {
    return this.opts.dryRunClean === false ? { clean: false, reason: "simulated base moved" } : { clean: true, identity: {
      candidateCommit: spec.expectedCandidateCommit, candidateTree: "1".repeat(40),
      candidateProjectManifestDigest: spec.expectedCandidateProjectManifestDigest,
      baseCommit: "2".repeat(40), baseTree: "3".repeat(40), expectedMergedTree: "4".repeat(40),
    } };
  }
  async merge(spec: MergeSpec, preflight: MergePreflightIdentity, preparePublication: (attempt: PublicationAttemptV1) => Promise<PreparedPublicationAuthority>): Promise<MergeOutcome> {
    if (this.opts.mergeSucceeds === false) return { merged: false, mergeId: "", reason: "simulated merge failure" };
    const mergeId = `merge-${spec.issueId}-${this.merges.size}`;
    this.merges.set(mergeId, spec); this.log.push(`merge:${mergeId}`);
    const identity = {
      ...preflight, mergedCommit: "5".repeat(40), mergedTree: preflight.expectedMergedTree,
      publishedCommit: "5".repeat(40), publishedTree: preflight.expectedMergedTree,
      publishedProjectManifestDigest: spec.expectedCandidateProjectManifestDigest,
      publicationTarget: this.opts.publicationUncertain ? `remote:origin:refs/heads/${spec.baseBranch}` : `local:${spec.baseBranch}`,
    };
    await preparePublication(makePublicationAttempt(spec, identity));
    if (this.opts.publicationUncertain) return { merged: false, mergeId, uncertainPublication: {
      attemptedCommit: "5".repeat(40), priorPublishedCommit: "2".repeat(40),
      publicationTarget: `remote:origin:refs/heads/${spec.baseBranch}`, reason: "simulated terminal observation loss",
    } };
    return { merged: true, mergeId, identity };
  }
  async observePublication(attempt: PublicationAttemptV1): Promise<PublicationObservation> {
    return this.opts.publicationUncertain
      ? { status: "unavailable", reason: "simulated terminal observation loss" }
      : { status: "effect-occurred", observedCommit: attempt.attemptedCommit, reason: "simulated exact observation" };
  }
  async reconcileAbsentPublication(): Promise<{ reconciled: boolean; reason: string }> {
    return { reconciled: true, reason: "simulation has no persistent local residue" };
  }
  async confirmPublished(): Promise<{ current: boolean; reason?: string }> {
    return this.opts.confirmCurrent === false ? { current: false, reason: "simulated published ref movement" } : { current: true };
  }
  async revert(mergeId: string, _spec: MergeSpec, _expectedPublicationTarget?: string): Promise<RevertOutcome> {
    if (this.opts.revertSucceeds === false) return { reverted: false, reason: "simulated revert failure" };
    this.merges.delete(mergeId); this.log.push(`revert:${mergeId}`); return { reverted: true };
  }
  isLive(mergeId: string): boolean { return this.merges.has(mergeId); }
  get liveCount(): number { return this.merges.size; }
}
