import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { InProcessLock, type DistributedLock } from "../src/lock/lock.js";
import { MultiRepositoryCoordinator, type RepositoryChange } from "../src/git/multi_repository_coordinator.js";
import { composeKeep } from "../src/compose.js";
import { makePublicationAttempt, missingPublicationActuatorRecoveryHold, type MergeOutcome, type MergePort, type MergePreflightIdentity, type MergeSpec, type PreparedPublicationAuthority, type PublicationAttemptV1, type PublicationObservation, type PublishedMergeIdentity, type RevertOutcome } from "../src/oversight/merge_executor.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";

const digest = "a".repeat(64);
const commit = (n: number) => n.toString(16).padStart(40, "0");

class RecordingPort implements MergePort {
  readonly calls: string[] = [];
  published = false;
  private mergeSequence = 4;
  constructor(readonly id: string, private readonly failMerge = false) {}
  publicationTarget(spec: MergeSpec): string { return `local:${this.id}:${spec.baseBranch}`; }
  async dryRun(_spec: MergeSpec): ReturnType<MergePort["dryRun"]> { this.calls.push("preflight"); return { clean: true, identity: this.identity() }; }
  async merge(spec: MergeSpec, preflight: MergePreflightIdentity, prepare: (attempt: PublicationAttemptV1) => Promise<PreparedPublicationAuthority>): Promise<MergeOutcome> {
    this.calls.push("merge");
    if (this.failMerge) return { merged: false, mergeId: "", reason: "injected failure" };
    const publishedCommit = commit(++this.mergeSequence);
    const identity: PublishedMergeIdentity = { ...preflight, mergedCommit: publishedCommit, mergedTree: preflight.expectedMergedTree, publishedCommit, publishedTree: preflight.expectedMergedTree, publishedProjectManifestDigest: digest, publicationTarget: this.publicationTarget(spec) };
    const attempt = makePublicationAttempt(spec, identity);
    await prepare(attempt);
    this.published = true;
    return { merged: true, mergeId: identity.mergedCommit, identity };
  }
  async revert(): Promise<RevertOutcome> { this.calls.push("revert"); this.published = false; return { reverted: true }; }
  async observePublication(attempt: PublicationAttemptV1): Promise<PublicationObservation> { return this.published ? { status: "effect-occurred", observedCommit: attempt.attemptedCommit, reason: "test" } : { status: "effect-absent", reason: "test" }; }
  async reconcileAbsentPublication() { return { reconciled: true, reason: "test" }; }
  async confirmPublished() { return { current: this.published, ...(this.published ? {} : { reason: "not published" }) }; }
  private identity(): MergePreflightIdentity { return { candidateCommit: commit(2), candidateTree: commit(3), candidateProjectManifestDigest: digest, baseCommit: commit(1), baseTree: commit(1), expectedMergedTree: commit(4) }; }
}

function change(id: string, port: RecordingPort, passed = true): RepositoryChange {
  return { repositoryId: id, port, spec: { issueId: "X2", repoRef: id, branch: "keep/x2", baseBranch: "main", expectedCandidateCommit: commit(2), expectedCandidateProjectManifestDigest: digest, expectedGuestExecutionRequestDigest: digest, projectDir: `/workspace/${id}` }, verify: async () => passed ? { passed: true } : { passed: false, reason: "cross-repository contract broke" } };
}

function reorderedChange(id: string, port: RecordingPort, passed = true): RepositoryChange {
  const ordinary = change(id, port, passed);
  const spec = ordinary.spec;
  return { ...ordinary, spec: { projectDir: spec.projectDir, expectedGuestExecutionRequestDigest: spec.expectedGuestExecutionRequestDigest, baseBranch: spec.baseBranch, issueId: spec.issueId, expectedCandidateCommit: spec.expectedCandidateCommit, branch: spec.branch, repoRef: spec.repoRef, expectedCandidateProjectManifestDigest: spec.expectedCandidateProjectManifestDigest } };
}

function coordinator(): MultiRepositoryCoordinator { return new MultiRepositoryCoordinator(new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-x2-")), { fsync: true }), new InProcessLock(), new SchemaRegistry())); }

function durableCoordinator(root: string, crashProbe?: ConstructorParameters<typeof MultiRepositoryCoordinator>[1]): MultiRepositoryCoordinator {
  return new MultiRepositoryCoordinator(new Spine(new FileSpineStore(root, { fsync: true }), new InProcessLock(), new SchemaRegistry()), crashProbe);
}

function durableSystem(root: string): { spine: Spine; coordinator: MultiRepositoryCoordinator } {
  const spine = new Spine(new FileSpineStore(root, { fsync: true }), new InProcessLock(), new SchemaRegistry());
  return { spine, coordinator: new MultiRepositoryCoordinator(spine) };
}

test("X2 preflights all repositories, then commits and verifies a coordinated change", async () => {
  const left = new RecordingPort("left"); const right = new RecordingPort("right");
  const result = await coordinator().apply([change("left", left), change("right", right)]);
  assert.equal(result.status, "committed");
  assert.deepEqual(left.calls, ["preflight", "merge"]); assert.deepEqual(right.calls, ["preflight", "merge"]);
  assert.equal(result.repositories.length, 2);
});

test("X2 reverses already-merged repositories when a later repository fails", async () => {
  const left = new RecordingPort("left"); const right = new RecordingPort("right", true);
  const result = await coordinator().apply([change("left", left), change("right", right)]);
  assert.equal(result.status, "reverted");
  assert.deepEqual(left.calls, ["preflight", "merge", "revert"]); assert.deepEqual(right.calls, ["preflight", "merge"]);
  assert.equal(result.repositories[0]?.reverted, true);
});

test("X2 keeps the solo repository path and reverts it on failed verification", async () => {
  const solo = new RecordingPort("solo");
  const result = await coordinator().apply([change("solo", solo, false)]);
  assert.equal(result.status, "reverted");
  assert.deepEqual(solo.calls, ["preflight", "merge", "revert"]);
});

test("pass-two lifecycle: committed and compensated sagas leave no orphan publication for actuator-free recovery", async () => {
  const committed = durableSystem(mkdtempSync(join(tmpdir(), "keep-repos01-terminal-commit-")));
  assert.equal((await committed.coordinator.apply([change("committed", new RecordingPort("committed"))])).status, "committed");
  assert.equal(missingPublicationActuatorRecoveryHold(committed.spine), undefined);

  const compensated = durableSystem(mkdtempSync(join(tmpdir(), "keep-repos01-terminal-revert-")));
  assert.equal((await compensated.coordinator.apply([change("reverted", new RecordingPort("reverted"), false)])).status, "reverted");
  assert.equal(missingPublicationActuatorRecoveryHold(compensated.spine), undefined);
});

test("REPOS-01 preflights every repository before the first merge and refuses a thrown preflight", async () => {
  const left = new RecordingPort("left");
  const right = new RecordingPort("right");
  right.dryRun = async () => { right.calls.push("preflight"); throw new Error("repository unavailable"); };
  const result = await coordinator().apply([change("left", left), change("right", right)]);
  assert.equal(result.status, "refused");
  assert.deepEqual(left.calls, ["preflight"]); assert.deepEqual(right.calls, ["preflight"]);
});

test("REPOS-01 compensates prior merges when a later merge throws", async () => {
  const left = new RecordingPort("left");
  const right = new RecordingPort("right");
  right.merge = async () => { right.calls.push("merge"); throw new Error("transport disappeared"); };
  const result = await coordinator().apply([change("left", left), change("right", right)]);
  assert.equal(result.status, "uncertain");
  assert.deepEqual(left.calls, ["preflight", "merge", "revert"]);
  assert.equal(result.repositories[0]?.reverted, true);
});

test("REPOS-01 attempts every reverse-order compensation even when one rollback throws", async () => {
  const calls: string[] = [];
  class OrderedPort extends RecordingPort {
    constructor(id: string, failMerge = false, private readonly throwRevert = false) { super(id, failMerge); }
    override async revert(): Promise<RevertOutcome> { calls.push(this.id); if (this.throwRevert) throw new Error("rollback transport failed"); return { reverted: true }; }
  }
  const first = new OrderedPort("first"), second = new OrderedPort("second", false, true), third = new OrderedPort("third", true);
  const result = await coordinator().apply([change("first", first), change("second", second), change("third", third)]);
  assert.equal(result.status, "rollback-failed");
  assert.deepEqual(calls, ["second", "first"], "one rollback failure cannot prevent remaining compensation");
});

test("REPOS-01 runs through the durable project lane and leaves dataDir-only N=1 inert", async () => {
  const inert = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-repos01-inert-")) });
  assert.ok(inert.repositoryTransactions, "persistent n=1 capabilities share the durable transaction substrate");
  assert.deepEqual(inert.projectRuntime!.status(), { running: 0, queued: 0 }, "composition schedules no work");
  assert.deepEqual(inert.autonomyLoop!.manager.list(), [], "composition creates no implicit project");
  await assert.rejects(
    inert.repositoryTransactions!.apply("prj_00000000000000000000000000000000" as never, [change("never", new RecordingPort("never"))]),
    /no such project/,
    "the inert substrate cannot execute without an explicitly created project",
  );

  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-repos01-project-")), solve: async () => ({ solveResult: {} }) as never });
  const project = app.autonomyLoop!.manager.create({ name: "coordinated repositories" });
  const left = new RecordingPort("left"), right = new RecordingPort("right");
  const result = await app.repositoryTransactions!.apply(project.id, [change("left", left), change("right", right)]);
  assert.equal(result.status, "committed");
  assert.deepEqual(app.projectRuntime!.status(), { running: 0, queued: 0 });
  await assert.rejects(app.repositoryTransactions!.apply("prj_00000000000000000000000000000000" as never, [change("never", new RecordingPort("never"))]), /no such project/);
});

test("REPOS-01 crash after a participant effect observes and records it without redispatch", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-repos01-effect-crash-"));
  const left = new RecordingPort("left"), right = new RecordingPort("right");
  await assert.rejects(durableCoordinator(root, (phase, repositoryId) => {
    if (phase === "effect-returned" && repositoryId === "left") throw new Error("power loss");
  }).apply([change("left", left), change("right", right)]), /power loss/);
  assert.equal(left.published, true);

  const recovered = await durableCoordinator(root).apply([change("left", left), change("right", right)]);
  assert.equal(recovered.status, "committed");
  assert.equal(left.calls.filter((call) => call === "merge").length, 1, "prepared effect must be observed, never redispatched");
  assert.equal(right.calls.filter((call) => call === "merge").length, 1);
});

test("review F1: caller key order cannot change plan identity or hide a prepared effect", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-repos01-key-order-"));
  const left = new RecordingPort("left"), right = new RecordingPort("right");
  await assert.rejects(durableCoordinator(root, (phase, repositoryId) => {
    if (phase === "effect-returned" && repositoryId === "left") throw new Error("power loss");
  }).apply([reorderedChange("left", left), reorderedChange("right", right)]), /power loss/);
  const recovered = await durableCoordinator(root).apply([change("left", left), change("right", right)]);
  assert.equal(recovered.status, "committed");
  assert.equal(left.calls.filter((call) => call === "merge").length, 1);
});

test("REPOS-01 prepared but proven-absent effect is reconciled before one safe retry", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-repos01-absent-crash-"));
  const port = new RecordingPort("solo");
  await assert.rejects(durableCoordinator(root, (phase) => {
    if (phase === "publication-prepared") throw new Error("power loss before publication");
  }).apply([change("solo", port)]), /power loss before publication/);
  const recovered = await durableCoordinator(root).apply([change("solo", port)]);
  assert.equal(recovered.status, "committed");
  assert.equal(port.calls.filter((call) => call === "merge").length, 2, "only authoritative absence permits one new effect attempt");
});

test("REPOS-01 unavailable observation leaves prepared work uncertain without redispatch", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-repos01-unavailable-"));
  const port = new RecordingPort("solo");
  await assert.rejects(durableCoordinator(root, (phase) => { if (phase === "effect-returned") throw new Error("power loss"); }).apply([change("solo", port)]), /power loss/);
  port.observePublication = async () => ({ status: "unavailable", reason: "forge offline" });
  const recovered = await durableCoordinator(root).apply([change("solo", port)]);
  assert.equal(recovered.status, "uncertain");
  assert.match(recovered.reason, /forge offline/);
  assert.equal(port.calls.filter((call) => call === "merge").length, 1);
});

test("REPOS-01 crash between participants resumes from the durable applied prefix", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-repos01-prefix-crash-"));
  const left = new RecordingPort("left"), right = new RecordingPort("right");
  await assert.rejects(durableCoordinator(root, (phase, repositoryId) => {
    if (phase === "applied-sealed" && repositoryId === "left") throw new Error("power loss");
  }).apply([change("left", left), change("right", right)]), /power loss/);

  const recovered = await durableCoordinator(root).apply([change("left", left), change("right", right)]);
  assert.equal(recovered.status, "committed");
  assert.equal(left.calls.filter((call) => call === "merge").length, 1);
  assert.equal(right.calls.filter((call) => call === "merge").length, 1);
});

test("REPOS-01 changed plan cannot route around an unfinished overlapping transaction", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-repos01-changed-plan-"));
  const left = new RecordingPort("left"), right = new RecordingPort("right");
  await assert.rejects(durableCoordinator(root, (phase, repositoryId) => {
    if (phase === "effect-returned" && repositoryId === "left") throw new Error("power loss");
  }).apply([change("left", left), change("right", right)]), /power loss/);

  const substituted = new RecordingPort("substituted");
  const result = await durableCoordinator(root).apply([change("left", left), change("substituted", substituted)]);
  assert.equal(result.status, "uncertain");
  assert.match(result.reason, /unfinished transaction/);
  assert.equal(substituted.calls.length, 0);
  assert.equal(left.calls.filter((call) => call === "merge").length, 1);
});

test("review F3: effect-free preflight refusal leaves no durable target poison", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-repos01-preflight-refusal-"));
  const left = new RecordingPort("left"), right = new RecordingPort("right");
  right.dryRun = async () => ({ clean: false, reason: "base moved" });
  const first = await durableCoordinator(root).apply([change("left", left), change("right", right)]);
  assert.equal(first.status, "refused");
  right.dryRun = RecordingPort.prototype.dryRun.bind(right);
  const second = await durableCoordinator(root).apply([change("left", left), change("right", right)]);
  assert.equal(second.status, "committed");
});

test("pass-two restart: a sealed plan with no participant effect terminalizes refusal and releases overlap", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-repos01-plan-only-crash-"));
  const port = new RecordingPort("shared-target");
  await assert.rejects(durableCoordinator(root, (phase) => { if (phase === "plan-sealed") throw new Error("power loss"); }).apply([change("first", port)]), /power loss/);
  port.dryRun = async () => ({ clean: false, reason: "base moved while offline" });
  const refused = await durableCoordinator(root).apply([change("first", port)]);
  assert.equal(refused.status, "refused");
  port.dryRun = RecordingPort.prototype.dryRun.bind(port);
  const successorBase = change("successor", port);
  const successor = { ...successorBase, spec: { ...successorBase.spec, issueId: "successor-plan" } };
  assert.equal((await durableCoordinator(root).apply([successor])).status, "committed");
});

test("pass-two replay ordering: a committed transaction replays despite a later unfinished overlap", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-repos01-terminal-before-overlap-"));
  const port = new RecordingPort("shared-target");
  const original = change("original", port);
  assert.equal((await durableCoordinator(root).apply([original])).status, "committed");
  const laterBase = change("later", port);
  const later = { ...laterBase, spec: { ...laterBase.spec, issueId: "later-plan" } };
  await assert.rejects(durableCoordinator(root, (phase) => { if (phase === "plan-sealed") throw new Error("power loss"); }).apply([later]), /power loss/);
  assert.equal((await durableCoordinator(root).apply([original])).status, "committed");
});

test("pass-two identity: omitted and empty auxiliary roots resume the same durable transaction", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-repos01-normalized-roots-"));
  const port = new RecordingPort("normalized");
  await assert.rejects(durableCoordinator(root, (phase) => { if (phase === "plan-sealed") throw new Error("power loss"); }).apply([change("normalized", port)]), /power loss/);
  const resumedBase = change("normalized", port);
  const resumed = { ...resumedBase, spec: { ...resumedBase.spec, executionAuxiliaryRoots: [] } };
  assert.equal((await durableCoordinator(root).apply([resumed])).status, "committed");
});

test("pass-two locking: multi-repository effects use the shared publication coordinator lane", async () => {
  const keys: string[] = [];
  const lock: DistributedLock = { async withLock<T>(key: string, fn: () => Promise<T>): Promise<T> { keys.push(key); return fn(); } };
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-repos01-lock-key-")), { fsync: true }), lock, new SchemaRegistry());
  assert.equal((await new MultiRepositoryCoordinator(spine).apply([change("locked", new RecordingPort("locked"))])).status, "committed");
  assert.ok(keys.includes("publication.coordinator"));
  assert.ok(!keys.includes("multi-repository.coordinator"));
});

test("pass-two replay bound: a sixteen-participant saga scans once per durable phase, not per lookup", async () => {
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-repos01-replay-bound-")), { fsync: true }), new InProcessLock(), new SchemaRegistry());
  const ordinaryReplay = spine.replay.bind(spine);
  let replayCalls = 0;
  spine.replay = () => { replayCalls += 1; return ordinaryReplay(); };
  const changes = Array.from({ length: 16 }, (_, index) => change(`repo-${index}`, new RecordingPort(`repo-${index}`)));
  assert.equal((await new MultiRepositoryCoordinator(spine).apply(changes)).status, "committed");
  assert.ok(replayCalls <= 20, `expected bounded phase replays, observed ${replayCalls}`);
});

test("review F4: a terminal transaction's prepared attempt cannot be adopted by a new saga", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-repos01-foreign-attempt-"));
  const a = new RecordingPort("a");
  const prior = await durableCoordinator(root).apply([change("a", a)]);
  assert.equal(prior.status, "committed");

  const c = new RecordingPort("c");
  const next = await durableCoordinator(root).apply([change("a", a), change("c", c, false)]);
  assert.equal(next.status, "reverted");
  assert.equal(a.calls.filter((call) => call === "merge").length, 2, "the second saga must prepare and apply its own participant effect");
  assert.equal(a.calls.filter((call) => call === "revert").length, 1);
});

test("REPOS-01 crash during compensation resumes the remaining reverse-order rollback", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-repos01-compensation-crash-"));
  const left = new RecordingPort("left"), right = new RecordingPort("right");
  await assert.rejects(durableCoordinator(root, (phase, repositoryId) => {
    if (phase === "compensation-sealed" && repositoryId === "right") throw new Error("power loss");
  }).apply([change("left", left), change("right", right, false)]), /power loss/);
  assert.equal(right.published, false); assert.equal(left.published, true);

  const recovered = await durableCoordinator(root).apply([change("left", left), change("right", right, false)]);
  assert.equal(recovered.status, "reverted");
  assert.equal(right.calls.filter((call) => call === "revert").length, 1);
  assert.equal(left.calls.filter((call) => call === "revert").length, 1);
  assert.equal(left.published, false);
});

test("review F2: crash after compensation effect but before receipt replays the idempotent compensation", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-repos01-compensation-effect-crash-"));
  const left = new RecordingPort("left"), right = new RecordingPort("right");
  await assert.rejects(durableCoordinator(root, (phase, repositoryId) => {
    if (phase === "compensation-effect-returned" && repositoryId === "right") throw new Error("power loss");
  }).apply([change("left", left), change("right", right, false)]), /power loss/);
  const recovered = await durableCoordinator(root).apply([change("left", left), change("right", right, false)]);
  assert.equal(recovered.status, "reverted");
  assert.equal(right.calls.filter((call) => call === "revert").length, 2, "replay reaches an idempotent port and must not manufacture failure");
  assert.equal(left.calls.filter((call) => call === "revert").length, 1);
});

test("review F5/F6: inconsistent handles stay uncertain and publication residue remains visible", async () => {
  const bad = new RecordingPort("bad");
  const ordinaryMerge = bad.merge.bind(bad);
  bad.merge = async (...args) => ({ ...(await ordinaryMerge(...args)), mergeId: "" });
  const invalid = await coordinator().apply([change("bad", bad)]);
  assert.equal(invalid.status, "uncertain");
  assert.match(invalid.reason, /differs from its durable prepared effect/);

  const residue = new RecordingPort("residue");
  residue.merge = async () => ({ merged: false, mergeId: commit(5), uncertainPublication: { attemptedCommit: commit(5), priorPublishedCommit: commit(1), publicationTarget: "remote:exact", reason: "unexpected remote commit" } });
  const uncertain = await coordinator().apply([change("residue", residue)]);
  assert.equal(uncertain.status, "uncertain");
  assert.match(uncertain.reason, /unexpected remote commit.*attempted=.*prior=.*target=remote:exact/);
});

test("REPOS-01 committed transaction replay returns durable result without touching participants", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-repos01-committed-replay-"));
  const left = new RecordingPort("left"), right = new RecordingPort("right");
  const first = await durableCoordinator(root).apply([change("left", left), change("right", right)]);
  assert.equal(first.status, "committed");
  const calls = [left.calls.length, right.calls.length];
  const replay = await durableCoordinator(root).apply([change("left", left), change("right", right)]);
  assert.equal(replay.status, "committed");
  assert.deepEqual([left.calls.length, right.calls.length], calls);
  assert.deepEqual(replay.repositories, first.repositories);
});
