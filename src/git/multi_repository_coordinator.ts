import { createHash } from "node:crypto";
import type { Spine } from "../spine/spine.js";
import type { ProjectId } from "../session/project_id.js";
import type { ProjectRuntime } from "../session/project_runtime.js";
import { canonicalize } from "../spine/event.js";
import type { StagedEvent } from "../spine/event.js";
import {
  makePublicationAttempt,
  publicationAttemptDigest,
  sealPreparedPublication,
  stagePublicationTerminal,
  type MergePort,
  type MergePreflightIdentity,
  type MergeSpec,
  type PublishedMergeIdentity,
  type PublicationAttemptV1,
} from "../oversight/merge_executor.js";

export interface RepositoryChange {
  readonly repositoryId: string;
  readonly spec: MergeSpec;
  readonly port: MergePort;
  /** Verifies the published repository in the context of the complete coordinated change. */
  readonly verify: (identity: PublishedMergeIdentity) => Promise<{ readonly passed: boolean; readonly reason?: string }>;
}

export interface RepositoryChangeResult {
  readonly repositoryId: string;
  readonly mergeId?: string;
  readonly revertCommit?: string;
  readonly reverted: boolean;
}

export interface MultiRepositoryResult {
  readonly transactionId: string;
  readonly status: "committed" | "reverted" | "refused" | "uncertain" | "rollback-failed";
  readonly reason: string;
  readonly repositories: readonly RepositoryChangeResult[];
}

function normalizedSpec(spec: MergeSpec): MergeSpec {
  return Object.freeze({ ...spec, executionAuxiliaryRoots: Object.freeze([...(spec.executionAuxiliaryRoots ?? [])]) });
}

function transactionId(changes: readonly RepositoryChange[], targets: readonly string[]): string {
  const identity = changes.map(({ repositoryId, spec }, index) => ({
    repositoryId,
    spec: normalizedSpec(spec),
    target: targets[index],
  }));
  return createHash("sha256").update(canonicalize(identity)).digest("hex");
}

type AppliedChange = { change: RepositoryChange; target: string; mergeId: string; identity: PublishedMergeIdentity };
type CoordinatorCrashPhase = "plan-sealed" | "publication-prepared" | "effect-returned" | "applied-sealed" | "compensation-started" | "compensation-effect-returned" | "compensation-sealed";
class CoordinatorCrashInterruption extends Error { constructor(readonly interruption: unknown) { super("simulated coordinator process interruption"); } }

function validSpec(spec: MergeSpec): boolean {
  if (spec === null || typeof spec !== "object") return false;
  const allowed = new Set(["issueId", "repoRef", "branch", "baseBranch", "expectedCandidateCommit", "expectedCandidateProjectManifestDigest", "expectedGuestExecutionRequestDigest", "projectDir", "executionAuxiliaryRoots"]);
  if (Object.keys(spec).some((key) => !allowed.has(key))) return false;
  const text = (value: unknown, max: number) => typeof value === "string" && value.length > 0 && value.length <= max && !value.includes("\0");
  const oid = (value: unknown) => typeof value === "string" && /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(value);
  const digest = (value: unknown) => typeof value === "string" && /^[0-9a-f]{64}$/u.test(value);
  const roots = spec.executionAuxiliaryRoots;
  return text(spec.issueId, 256) && text(spec.repoRef, 2048) && text(spec.branch, 256) && text(spec.baseBranch, 256)
    && oid(spec.expectedCandidateCommit) && digest(spec.expectedCandidateProjectManifestDigest) && digest(spec.expectedGuestExecutionRequestDigest)
    && text(spec.projectDir, 4096) && (roots === undefined || (Array.isArray(roots) && roots.length <= 32 && new Set(roots).size === roots.length
      && roots.every((root) => typeof root === "string" && /^[A-Za-z0-9._-]{1,128}$/u.test(root) && root !== "." && root !== ".." && root !== ".git")));
}

/**
 * Coordinates the existing reversible merge primitive across repository boundaries.
 * This is a bounded saga, not a claim of distributed atomicity: every repository is
 * preflighted before the first mutation and completed merges are reverted in reverse
 * order on any later failure.
 */
export class MultiRepositoryCoordinator {
  constructor(private readonly spine: Spine, private readonly crashProbe?: (phase: CoordinatorCrashPhase, repositoryId?: string) => void) {}

  private probe(phase: CoordinatorCrashPhase, repositoryId?: string): void { this.crashProbe?.(phase, repositoryId); }

  private events(event: string, id: string, replay: readonly StagedEvent[] = this.spine.replay()): readonly Record<string, unknown>[] {
    const type = event === "multi_repository.prepared" || event === "multi_repository.participant_prepared" || event === "multi_repository.compensating" ? "effect.intent"
      : event === "multi_repository.terminal" ? "effect.terminal" : "effect.receipt";
    return replay.filter((row) => row.type === type).map((row) => row.payload as Record<string, unknown>)
      .filter((payload) => payload["event"] === event && payload["transactionId"] === id);
  }

  private preparedAttempt(replay: readonly StagedEvent[], id: string, change: RepositoryChange, target: string): PublicationAttemptV1 | undefined {
    const boundDigests = new Set(this.events("multi_repository.participant_prepared", id, replay)
      .filter((payload) => payload["repositoryId"] === change.repositoryId && payload["target"] === target && typeof payload["attemptDigest"] === "string")
      .map((payload) => String(payload["attemptDigest"])));
    const matches: PublicationAttemptV1[] = [];
    const terminalDigests = new Set(replay.filter((row) => row.type === "effect.terminal" && row.payload["kind"] === "auto_merge.publication_terminal")
      .map((row) => row.payload["attemptDigest"]).filter((value): value is string => typeof value === "string"));
    for (const row of replay) {
      const payload = row.payload as Record<string, unknown>;
      if (row.type !== "effect.intent" || payload["kind"] !== "auto_merge.publication_prepared") continue;
      const attempt = payload["attempt"] as PublicationAttemptV1;
      try {
        const canonicalSpec = normalizedSpec(change.spec);
        const digest = publicationAttemptDigest(attempt);
        if (digest !== payload["attemptDigest"] || !boundDigests.has(digest) || terminalDigests.has(digest) || attempt.publicationTarget !== target ||
            canonicalize(attempt.spec) !== canonicalize(canonicalSpec)) continue;
        matches.push(attempt);
      } catch { /* malformed publication evidence is handled by its owning recovery path */ }
    }
    if (matches.length > 1 && new Set(matches.map((attempt) => publicationAttemptDigest(attempt))).size > 1) {
      throw new Error(`multiple prepared publication identities exist for ${change.repositoryId}`);
    }
    return matches[0];
  }

  private async recordApplied(id: string, row: AppliedChange): Promise<void> {
    this.spine.stage({ type: "effect.receipt", actor: "multi-repository", payload: {
      event: "multi_repository.applied", transactionId: id, repositoryId: row.change.repositoryId,
      target: row.target, mergeId: row.mergeId, identity: row.identity,
    } });
    await this.spine.seal();
    this.probe("applied-sealed", row.change.repositoryId);
  }

  async apply(changes: readonly RepositoryChange[]): Promise<MultiRepositoryResult> {
    if (!Array.isArray(changes) || changes.length === 0 || changes.length > 16) {
      return { transactionId: "unresolved", status: "refused", reason: "a coordinated change requires 1 to 16 repositories", repositories: [] };
    }
    let id: string; let targets: string[];
    try {
      const repositoryIds = new Set(changes.map((change) => change.repositoryId));
      const projectDirs = new Set(changes.map((change) => change.spec.projectDir));
      if (repositoryIds.size !== changes.length || projectDirs.size !== changes.length || changes.some((change) => !/^[A-Za-z0-9._-]{1,128}$/u.test(change.repositoryId) || !validSpec(change.spec))) {
        return { transactionId: "unresolved", status: "refused", reason: "repository identities and roots must be unique and canonical", repositories: [] };
      }
      targets = changes.map((change) => change.port.publicationTarget(change.spec));
      if (new Set(targets).size !== targets.length) return { transactionId: "unresolved", status: "refused", reason: "publication targets must be unique", repositories: [] };
      id = transactionId(changes, targets);
    }
    catch (error) {
      return { transactionId: "unresolved", status: "refused", reason: `publication target refused: ${(error as Error).message}`, repositories: [] };
    }
    return this.spine.withCoordinationLock("publication.coordinator", () => this.applyLocked(id, changes, targets));
  }

  private async applyLocked(id: string, changes: readonly RepositoryChange[], targets: readonly string[]): Promise<MultiRepositoryResult> {
    // Finish a staged prefix before deriving restart state. The plan is content-bound by `id`.
    await this.spine.seal();
    const spineVerification = this.spine.verify();
    if (!spineVerification.ok) return { transactionId: id, status: "uncertain", reason: `coordinator Spine is not verifiable: ${spineVerification.reason ?? "unknown"}`, repositories: [] };
    let replay = this.spine.replay();
    const completed = this.events("multi_repository.committed", id, replay);
    const priorTerminal = this.events("multi_repository.terminal", id, replay);
    if (completed.length + priorTerminal.length > 1 || (completed.length > 0 && priorTerminal.length > 0)) {
      return { transactionId: id, status: "uncertain", reason: "durable transaction has duplicate or contradictory terminal records", repositories: [] };
    }
    if (completed.length > 0) {
      const repositories = completed[0]!["repositories"];
      if (!Array.isArray(repositories)) return { transactionId: id, status: "uncertain", reason: "durable committed transaction record is malformed", repositories: [] };
      return { transactionId: id, status: "committed", reason: "coordinated change was already durably committed", repositories: repositories as RepositoryChangeResult[] };
    }
    if (priorTerminal.length > 0) {
      const terminal = priorTerminal[0]!;
      const status = terminal["disposition"];
      const repositories = terminal["repositories"];
      if (!Array.isArray(repositories) || !["reverted", "refused", "uncertain", "rollback-failed"].includes(String(status))) {
        return { transactionId: id, status: "uncertain", reason: "durable terminal transaction record is malformed", repositories: [] };
      }
      return { transactionId: id, status: status as "reverted" | "refused" | "uncertain" | "rollback-failed", reason: String(terminal["reason"] ?? "durable terminal result"), repositories: repositories as RepositoryChangeResult[] };
    }
    const terminalIds = new Set(replay
      .filter((row) => (row.type === "effect.receipt" && row.payload["event"] === "multi_repository.committed") || (row.type === "effect.terminal" && row.payload["event"] === "multi_repository.terminal"))
      .map((row) => row.payload["transactionId"]).filter((value): value is string => typeof value === "string"));
    for (const row of replay) {
      const payload = row.payload as Record<string, unknown>;
      const otherId = payload["transactionId"];
      if (row.type !== "effect.intent" || payload["event"] !== "multi_repository.prepared" || typeof otherId !== "string" || otherId === id || terminalIds.has(otherId)) continue;
      const repositories = payload["repositories"];
      if (!Array.isArray(repositories)) return { transactionId: id, status: "uncertain", reason: "another unfinished coordinated plan is malformed", repositories: [] };
      const otherTargets = repositories.map((entry) => entry && typeof entry === "object" ? (entry as Record<string, unknown>)["target"] : undefined);
      if (otherTargets.some((target) => typeof target === "string" && targets.includes(target))) {
        return { transactionId: id, status: "uncertain", reason: `publication target belongs to unfinished transaction ${otherId}; recover that exact plan before changing it`, repositories: [] };
      }
    }
    const planRows = this.events("multi_repository.prepared", id, replay);
    if (planRows.length > 0) {
      const expected = canonicalize(changes.map((change, index) => ({ repositoryId: change.repositoryId, target: targets[index], spec: normalizedSpec(change.spec) })));
      if (planRows.length !== 1 || canonicalize(planRows[0]!["repositories"]) !== expected) {
        return { transactionId: id, status: "uncertain", reason: "durable coordinated plan is duplicated, malformed, or changed", repositories: [] };
      }
    }

    const compensation = this.events("multi_repository.compensating", id, replay);
    const durableApplied = this.events("multi_repository.applied", id, replay);
    if (compensation.length > 0) {
      const state = this.restoreApplied(id, changes, targets, durableApplied);
      if (state.error) return { transactionId: id, status: "uncertain", reason: state.error, repositories: [] };
      const row = compensation[0]!;
      const initialStatus = row["initialStatus"];
      if (compensation.length !== 1 || !["reverted", "uncertain", "rollback-failed"].includes(String(initialStatus)) || typeof row["reason"] !== "string") {
        return { transactionId: id, status: "uncertain", reason: "durable compensation intent is duplicated or malformed", repositories: [] };
      }
      return this.compensate(id, state.applied, row["reason"], initialStatus as "reverted" | "uncertain" | "rollback-failed", true);
    }

    const restored = this.restoreApplied(id, changes, targets, durableApplied);
    if (restored.error) return { transactionId: id, status: "uncertain", reason: restored.error, repositories: [] };
    const applied: AppliedChange[] = [...restored.applied];
    const preflights: Array<MergePreflightIdentity | undefined> = new Array(changes.length);
    const preparedByIndex: Array<PublicationAttemptV1 | undefined> = new Array(changes.length);
    if (planRows.length === 0) {
      for (let index = 0; index < changes.length; index++) {
        const change = changes[index]!;
        let preflight;
        try { preflight = await change.port.dryRun(change.spec); }
        catch (error) { return { transactionId: id, status: "refused", reason: `preflight refused ${change.repositoryId}: ${(error as Error).message}`, repositories: [] }; }
        if (!preflight.clean || !preflight.identity) return { transactionId: id, status: "refused", reason: `preflight refused ${change.repositoryId}: ${preflight.reason ?? "identity unavailable"}`, repositories: [] };
        preflights[index] = preflight.identity;
      }
      this.spine.stage({ type: "effect.intent", actor: "multi-repository", payload: {
        event: "multi_repository.prepared", transactionId: id,
        repositories: changes.map((change, index) => ({ repositoryId: change.repositoryId, target: targets[index], spec: normalizedSpec(change.spec) })),
      } });
      await this.spine.seal();
      this.probe("plan-sealed");
      replay = this.spine.replay();
    } else {
      for (let index = 0; index < changes.length; index++) {
        if (applied.some((row) => row.change === changes[index])) continue;
        try { preparedByIndex[index] = this.preparedAttempt(replay, id, changes[index]!, targets[index]!); }
        catch (error) { return { transactionId: id, status: "uncertain", reason: (error as Error).message, repositories: applied.map((row) => ({ repositoryId: row.change.repositoryId, mergeId: row.mergeId, reverted: false })) }; }
        if (preparedByIndex[index]) continue;
        let preflight;
        try { preflight = await changes[index]!.port.dryRun(changes[index]!.spec); }
        catch (error) {
          const reason = `unfinished plan preflight unavailable for ${changes[index]!.repositoryId}: ${(error as Error).message}`;
          if (applied.length === 0 && this.events("multi_repository.participant_prepared", id, replay).length === 0) return this.refuseEffectFreePlan(id, reason);
          return { transactionId: id, status: "uncertain", reason, repositories: applied.map((row) => ({ repositoryId: row.change.repositoryId, mergeId: row.mergeId, reverted: false })) };
        }
        if (!preflight.clean || !preflight.identity) {
          const reason = `unfinished plan preflight refused ${changes[index]!.repositoryId}: ${preflight.reason ?? "identity unavailable"}`;
          if (applied.length === 0 && this.events("multi_repository.participant_prepared", id, replay).length === 0) return this.refuseEffectFreePlan(id, reason);
          return { transactionId: id, status: "uncertain", reason, repositories: applied.map((row) => ({ repositoryId: row.change.repositoryId, mergeId: row.mergeId, reverted: false })) };
        }
        preflights[index] = preflight.identity;
      }
    }
    for (let index = 0; index < changes.length; index++) {
      const change = changes[index]!;
      const prior = applied.find((row) => row.change.repositoryId === change.repositoryId);
      if (prior) {
        let confirmation: { current: boolean; reason?: string };
        try { confirmation = await change.port.confirmPublished(prior.identity, change.spec); }
        catch (error) { confirmation = { current: false, reason: (error as Error).message }; }
        if (!confirmation.current) return { transactionId: id, status: "uncertain", reason: `${change.repositoryId} durable applied effect cannot be confirmed: ${confirmation.reason ?? "unknown"}`, repositories: applied.map((row) => ({ repositoryId: row.change.repositoryId, mergeId: row.mergeId, reverted: false })) };
        continue;
      }

      const prepared = preparedByIndex[index];
      if (prepared) {
        let observed: Awaited<ReturnType<MergePort["observePublication"]>>;
        try { observed = await change.port.observePublication(prepared); }
        catch (error) { observed = { status: "unavailable", reason: (error as Error).message }; }
        if (observed.status === "effect-occurred" && observed.observedCommit === prepared.attemptedCommit) {
          const confirmation = await change.port.confirmPublished(prepared.identity, change.spec).catch((error) => ({ current: false, reason: (error as Error).message }));
          if (!confirmation.current) return { transactionId: id, status: "uncertain", reason: `${change.repositoryId} observed publication could not be confirmed: ${confirmation.reason ?? "unknown"}`, repositories: applied.map((row) => ({ repositoryId: row.change.repositoryId, mergeId: row.mergeId, reverted: false })) };
          const recovered = { change, target: targets[index]!, mergeId: prepared.attemptedCommit, identity: prepared.identity };
          await this.recordApplied(id, recovered); applied.push(recovered); continue;
        }
        if (observed.status !== "effect-absent") return { transactionId: id, status: "uncertain", reason: `${change.repositoryId} prepared publication is ${observed.status}: ${observed.reason}`, repositories: applied.map((row) => ({ repositoryId: row.change.repositoryId, mergeId: row.mergeId, reverted: false })) };
        const reconciled = await change.port.reconcileAbsentPublication(prepared).catch((error) => ({ reconciled: false, reason: (error as Error).message }));
        if (!reconciled.reconciled) return { transactionId: id, status: "uncertain", reason: `${change.repositoryId} absent publication could not be reconciled: ${reconciled.reason}`, repositories: applied.map((row) => ({ repositoryId: row.change.repositoryId, mergeId: row.mergeId, reverted: false })) };
        stagePublicationTerminal(this.spine, prepared, "reconciled-effect-absent", reconciled.reason || "coordinated publication was proven absent");
        this.spine.stage({ type: "effect.receipt", actor: "multi-repository", payload: {
          event: "multi_repository.participant_absent", transactionId: id, repositoryId: change.repositoryId,
          target: targets[index], attemptDigest: publicationAttemptDigest(prepared),
        } });
        await this.spine.seal();
        replay = this.spine.replay();
        const reappraised = await change.port.dryRun(change.spec).catch((error) => ({ clean: false, reason: (error as Error).message }));
        if (!reappraised.clean || !("identity" in reappraised) || !reappraised.identity) return this.compensate(id, applied, `${change.repositoryId} preflight changed after absent-effect recovery: ${reappraised.reason ?? "identity unavailable"}`, "reverted");
        preflights[index] = reappraised.identity;
      }
      let outcome: Awaited<ReturnType<MergePort["merge"]>>;
      try { outcome = await change.port.merge(change.spec, preflights[index]!, async (attempt) => {
        const attemptDigest = publicationAttemptDigest(attempt);
        if (attempt.publicationTarget !== targets[index] || canonicalize(attempt.spec) !== canonicalize(normalizedSpec(change.spec))) {
          throw new Error("participant prepared an effect outside its exact coordinated plan");
        }
        this.spine.stage({ type: "effect.intent", actor: "multi-repository", payload: {
          event: "multi_repository.participant_prepared", transactionId: id, repositoryId: change.repositoryId,
          target: targets[index], attemptDigest,
        } });
        const authority = await sealPreparedPublication(this.spine, attempt);
        try { this.probe("publication-prepared", change.repositoryId); }
        catch (error) { throw new CoordinatorCrashInterruption(error); }
        return authority;
      }); }
      catch (error) {
        if (error instanceof CoordinatorCrashInterruption) throw error.interruption;
        return this.compensate(id, applied, `${change.repositoryId} merge threw: ${(error as Error).message}`, "uncertain");
      }
      if (!outcome.merged || !outcome.identity) {
        if (outcome.uncertainPublication) {
          const residue = outcome.uncertainPublication;
          return { transactionId: id, status: "uncertain", reason: `${change.repositoryId} publication uncertain: ${residue.reason}; attempted=${residue.attemptedCommit}; prior=${residue.priorPublishedCommit}; target=${residue.publicationTarget}`.slice(0, 1024), repositories: applied.map((row) => ({ repositoryId: row.change.repositoryId, mergeId: row.mergeId, reverted: false })) };
        }
        return this.compensate(id, applied, `${change.repositoryId} merge failed: ${outcome.reason ?? "unknown failure"}`, outcome.rollbackFailed === true ? "rollback-failed" : "reverted");
      }
      let returnedAttempt: PublicationAttemptV1 | undefined;
      let returnedIdentityMatches = false;
      try {
        replay = this.spine.replay();
        returnedAttempt = this.preparedAttempt(replay, id, change, targets[index]!);
        returnedIdentityMatches = returnedAttempt !== undefined && publicationAttemptDigest(returnedAttempt) === publicationAttemptDigest(makePublicationAttempt(change.spec, outcome.identity));
      }
      catch { /* handled below as uncertain adapter output */ }
      if (outcome.mergeId !== outcome.identity.mergedCommit || !returnedIdentityMatches) {
        return { transactionId: id, status: "uncertain", reason: `${change.repositoryId} returned a merge identity or handle that differs from its durable prepared effect`, repositories: applied.map((row) => ({ repositoryId: row.change.repositoryId, mergeId: row.mergeId, reverted: false })) };
      }
      this.probe("effect-returned", change.repositoryId);
      const appliedRow = { change, target: targets[index]!, mergeId: outcome.mergeId, identity: outcome.identity };
      await this.recordApplied(id, appliedRow);
      applied.push(appliedRow);
    }

    for (const row of applied) {
      let verification: { passed: boolean; reason?: string };
      try { verification = await row.change.verify(row.identity); }
      catch (error) { verification = { passed: false, reason: (error as Error).message }; }
      if (!verification.passed) {
        return this.compensate(id, applied, `${row.change.repositoryId} verification failed: ${verification.reason ?? "no evidence"}`, "reverted");
      }
    }

    try {
      const repositories = applied.map((row) => ({ repositoryId: row.change.repositoryId, mergeId: row.mergeId, reverted: false }));
      for (const row of applied) stagePublicationTerminal(this.spine, makePublicationAttempt(row.change.spec, row.identity), "effect-occurred-verified", "coordinated transaction committed after all participant verification passed");
      this.spine.stage({ type: "effect.receipt", actor: "multi-repository", payload: { event: "multi_repository.committed", transactionId: id, repositories } });
      await this.spine.seal();
    } catch (error) { return this.compensate(id, applied, `commit receipt failed: ${(error as Error).message}`, "uncertain"); }
    return { transactionId: id, status: "committed", reason: "all repository changes merged and verified", repositories: applied.map((row) => ({ repositoryId: row.change.repositoryId, mergeId: row.mergeId, reverted: false })) };
  }

  private restoreApplied(id: string, changes: readonly RepositoryChange[], targets: readonly string[], rows: readonly Record<string, unknown>[]): { applied: AppliedChange[]; error?: string } {
    const applied: AppliedChange[] = [];
    for (const event of rows) {
      const repositoryId = event["repositoryId"];
      const index = changes.findIndex((change) => change.repositoryId === repositoryId);
      const mergeId = event["mergeId"];
      const identity = event["identity"] as PublishedMergeIdentity;
      if (index < 0 || typeof mergeId !== "string" || event["target"] !== targets[index] || !identity || typeof identity !== "object" || identity.mergedCommit !== mergeId) {
        return { applied: [], error: `durable applied record is malformed or foreign to transaction ${id}` };
      }
      if (applied.some((row) => row.change.repositoryId === repositoryId)) return { applied: [], error: `duplicate durable applied record for ${String(repositoryId)}` };
      applied.push({ change: changes[index]!, target: targets[index]!, mergeId, identity });
    }
    applied.sort((left, right) => changes.indexOf(left.change) - changes.indexOf(right.change));
    for (let index = 0; index < applied.length; index++) if (changes[index] !== applied[index]!.change) return { applied: [], error: "durable applied records are not one contiguous transaction prefix" };
    return { applied };
  }

  private async refuseEffectFreePlan(id: string, reason: string): Promise<MultiRepositoryResult> {
    this.spine.stage({ type: "effect.terminal", actor: "multi-repository", payload: {
      event: "multi_repository.terminal", transactionId: id, disposition: "refused", reason: reason.slice(0, 512), repositories: [],
    } });
    await this.spine.seal();
    return { transactionId: id, status: "refused", reason, repositories: [] };
  }

  private async compensate(id: string, applied: readonly AppliedChange[], reason: string, initialStatus: "reverted" | "uncertain" | "rollback-failed", resuming = false): Promise<MultiRepositoryResult> {
    if (!resuming) {
      this.spine.stage({ type: "effect.intent", actor: "multi-repository", payload: {
        event: "multi_repository.compensating", transactionId: id, reason: reason.slice(0, 512), initialStatus,
      } });
      await this.spine.seal();
      this.probe("compensation-started");
    }
    const priorResults = new Map<string, RepositoryChangeResult>();
    for (const row of this.events("multi_repository.compensated", id)) {
      if (typeof row["repositoryId"] !== "string" || typeof row["mergeId"] !== "string" || typeof row["reverted"] !== "boolean" || (row["revertCommit"] !== undefined && typeof row["revertCommit"] !== "string")) {
        return { transactionId: id, status: "uncertain", reason: `${reason}; durable compensation record is malformed`, repositories: [] };
      }
      if (priorResults.has(row["repositoryId"])) return { transactionId: id, status: "uncertain", reason: `${reason}; duplicate durable compensation record`, repositories: [] };
      priorResults.set(row["repositoryId"], { repositoryId: row["repositoryId"], mergeId: row["mergeId"], ...(typeof row["revertCommit"] === "string" ? { revertCommit: row["revertCommit"] } : {}), reverted: row["reverted"] });
    }
    const results: RepositoryChangeResult[] = [];
    let rollbackFailed = initialStatus === "rollback-failed";
    for (const row of [...applied].reverse()) {
      const prior = priorResults.get(row.change.repositoryId);
      if (prior) { results.unshift(prior); rollbackFailed ||= !prior.reverted; continue; }
      let reverted: Awaited<ReturnType<MergePort["revert"]>>;
      try { reverted = await row.change.port.revert(row.mergeId, row.change.spec, row.target); }
      catch (error) { reverted = { reverted: false, reason: `rollback threw: ${(error as Error).message}` }; }
      this.probe("compensation-effect-returned", row.change.repositoryId);
      const result = { repositoryId: row.change.repositoryId, mergeId: row.mergeId, ...(reverted.revertCommit ? { revertCommit: reverted.revertCommit } : {}), reverted: reverted.reverted };
      results.unshift(result);
      rollbackFailed ||= !reverted.reverted;
      if (!reverted.reverted) reason += `; ${row.change.repositoryId} rollback failed: ${reverted.reason ?? "unknown failure"}`;
      if (reverted.reverted) stagePublicationTerminal(this.spine, makePublicationAttempt(row.change.spec, row.identity), "reverted", reverted.reason || "coordinated transaction compensation completed");
      this.spine.stage({ type: "effect.receipt", actor: "multi-repository", payload: {
        event: "multi_repository.compensated", transactionId: id, ...result,
      } });
      await this.spine.seal();
      this.probe("compensation-sealed", row.change.repositoryId);
    }
    const status = rollbackFailed ? "rollback-failed" : initialStatus;
    try {
      this.spine.stage({ type: "effect.terminal", actor: "multi-repository", payload: { event: "multi_repository.terminal", transactionId: id, disposition: status, reason: reason.slice(0, 512), repositories: results } });
      await this.spine.seal();
    } catch (error) { return { transactionId: id, status: "uncertain", reason: `${reason}; terminal receipt failed: ${(error as Error).message}`, repositories: results }; }
    return { transactionId: id, status, reason, repositories: results };
  }
}

/** Product binding: repository transactions consume the existing durable project job lane. */
export class ProjectRepositoryTransactions {
  constructor(private readonly runtime: ProjectRuntime, private readonly coordinator: MultiRepositoryCoordinator) {}
  apply(projectId: ProjectId, changes: readonly RepositoryChange[]): Promise<MultiRepositoryResult> {
    return this.runtime.submit(projectId, 1, () => this.coordinator.apply(changes), "multi-repository transaction");
  }
}
