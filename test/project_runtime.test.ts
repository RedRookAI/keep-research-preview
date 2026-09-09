import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import { encodeProjectCommand, decodeProjectCommand, type NativeProjectCommand } from "../src/session/project_command.js";
import { PrincipalRegistry } from "../src/identity/identity_provider.js";

import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import { composeKeep } from "../src/compose.js";
import { buildAutonomyLoop } from "../src/autonomy/autonomy_loop.js";
import { InMemoryProjectCheckpointStore } from "../src/autonomy/project_checkpoint_store.js";
import { FileSystemLock, InProcessLock } from "../src/lock/lock.js";
import { ProjectJobCancelledError, ProjectJobReconciliationError, ProjectSubmissionUncertainError, ProjectRuntime } from "../src/session/project_runtime.js";
import type { ProjectJobIntent, ProjectJobJournal } from "../src/session/project_job_journal.js";
import { ProjectSubmissionConflictError, SpineProjectJobJournal } from "../src/session/project_job_journal.js";
import { ProjectRegistry } from "../src/session/project_registry.js";
import { ProjectSessionManager } from "../src/session/project_session_manager.js";
import type { ProjectSessionPersistence } from "../src/session/project_session_persistence.js";
import { FileProjectSessionPersistence } from "../src/session/project_session_persistence.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";

class MemoryJobJournal implements ProjectJobJournal {
  constructor(readonly rows: ProjectJobIntent[] = [], private readonly failAfter = Number.POSITIVE_INFINITY) {}
  load(): readonly ProjectJobIntent[] { return this.rows.map((row) => ({ ...row })); }
  append(intent: ProjectJobIntent): void { if (this.rows.length >= this.failAfter) throw new Error("journal unavailable"); this.rows.push({ ...intent }); }
  renew(ownerId: string, intentIds: readonly string[], updatedAt: number, leaseUntil: number): void {
    if (this.rows.length >= this.failAfter) throw new Error("journal unavailable");
    for (const id of intentIds) {
      let index = -1;
      for (let candidate = this.rows.length - 1; candidate >= 0; candidate--) { if (this.rows[candidate]!.id === id) { index = candidate; break; } }
      if (index < 0 || this.rows[index]!.ownerId !== ownerId || !["queued", "running"].includes(this.rows[index]!.state)) continue;
      this.rows.push({ ...this.rows[index]!, updatedAt, leaseUntil });
    }
  }
}
function manager() { return new ProjectSessionManager(new ProjectRegistry(new CryptoShredKeyStore())); }
function commandManager() {
  const root = mkdtempSync(join(tmpdir(), "keep-command-documents-"));
  return new ProjectSessionManager(new ProjectRegistry(new CryptoShredKeyStore()), undefined, id => new FileProjectSessionPersistence(join(root, `${id}.json`)));
}
function newRuntime() { const m = manager(); return { manager: m, runtime: new ProjectRuntime(m, { aggregateCeiling: 2, perProjectShare: 0.5 }) }; }

function submissionJournal(root = mkdtempSync(join(tmpdir(), "keep-job-submission-"))) {
  const spine = new Spine(new FileSpineStore(root, { fsync: true }), new FileSystemLock(join(root, "locks")), new SchemaRegistry());
  return { root, spine, journal: new SpineProjectJobJournal(spine) };
}
const submissionRequest = { keyDigest: "a".repeat(64), requestDigest: "b".repeat(64) };

test("queued command recovery transfers once, keeps original identity and fences the stale owner", async () => {
  const { root, journal } = submissionJournal(), m = commandManager(), projectId = m.create({ name: "recover command" }).id;
  const policy = { aggregateCeiling: 1, perProjectShare: 1 }, binding = "c".repeat(64);
  let now = 100, calls = 0;
  const commands = { binding, validate: () => undefined, execute: async (_command: NativeProjectCommand, context: { jobId: string }) => { calls++; return context.jobId; } };
  const old = new ProjectRuntime(m, policy, journal, { ownerId: "old", now: () => now, leaseMs: 1000, paused: true, commands });
  const accepted = await old.submitOnce(submissionRequest, () => ({ projectId, command: { binding, principal: { kind: "human", id: "owner" }, goal: "private queued goal" }, run: async () => { throw new Error("volatile callback must not run"); } }));
  const completion = accepted.completion!.catch(() => undefined);
  assert.equal(calls, 0); now = 1200;
  const recovered = new ProjectRuntime(m, policy, submissionJournal(root).journal, { ownerId: "new", now: () => now, leaseMs: 1000, recoverCommands: true, commands });
  const rival = new ProjectRuntime(m, policy, submissionJournal(root).journal, { ownerId: "rival", now: () => now, leaseMs: 1000, recoverCommands: true, commands });
  await Promise.all([recovered.recoverQueuedCommands(), rival.recoverQueuedCommands()]);
  const deadline = Date.now() + 1000;
  while (journal.load().find(row => row.id === accepted.jobId)?.state !== "completed") { assert.ok(Date.now() < deadline); await new Promise(resolve => setTimeout(resolve, 5)); }
  old.resumeDispatch(); await completion;
  assert.equal(calls, 1); assert.notEqual(journal.load()[0]!.ownerId, "old");
  assert.equal(journal.load()[0]!.id, accepted.jobId); assert.equal(journal.load()[0]!.createdAt, 100);
  await assert.rejects(journal.tryDispatch(accepted.jobId, "old", policy, now, now + 1000), /owned/u);
  const retry = await recovered.submitOnce(submissionRequest, () => { throw new Error("must not prepare twice"); });
  assert.equal(retry.jobId, accepted.jobId); assert.equal(retry.replayed, true);
});

test("recovery holds changed configuration and revoked authority; cancellation cannot create dispatch", async () => {
  for (const hold of ["binding", "authority", "cancelled"] as const) {
    const { journal } = submissionJournal(), m = commandManager(), projectId = m.create({ name: hold }).id;
    let now = 100, calls = 0, permitted = true;
    const binding = "c".repeat(64), commands = { binding, validate: () => { if (!permitted) throw new Error("revoked secret subject"); }, execute: async () => { calls++; } };
    const old = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal, { now: () => now, leaseMs: 1000, paused: true, commands });
    const accepted = await old.submitOnce(submissionRequest, () => ({ projectId, command: { binding, principal: { kind: "human", id: "owner" }, goal: "private" }, run: async () => undefined }));
    void accepted.completion!.catch(() => undefined);
    now = 1200; if (hold === "authority") permitted = false;
    if (hold === "cancelled") await journal.requestCancellation(accepted.jobId);
    const recovered = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal, { now: () => now, leaseMs: 1000, recoverCommands: true, commands: { ...commands, binding: hold === "binding" ? "d".repeat(64) : binding } });
    await recovered.recoverQueuedCommands(); assert.equal(calls, 0);
    assert.equal(journal.activities(accepted.jobId).length, 0);
    if (hold !== "cancelled") assert.match(recovered.job(accepted.jobId)!.reason!, /recovery held/u);
    await old.cancel(accepted.jobId); // settle this test's owned paused queue and timer
  }
});

test("queued ownership cannot be reclaimed from running or any previously dispatched work", async () => {
  const { journal } = submissionJournal(), m = manager(), projectId = m.create({ name: "no replay" }).id;
  const job: ProjectJobIntent = { id: randomUUID(), projectId, workspaceKey: `project/${projectId}`, weight: 1, ownerId: "old", label: "command", state: "queued", createdAt: 100, updatedAt: 100, leaseUntil: 200, commandDigest: "c".repeat(64) };
  journal.append(job);
  const activity = await journal.tryDispatch(job.id, "old", { aggregateCeiling: 1, perProjectShare: 1 }, 100, 200); assert.ok(activity);
  assert.equal(await journal.reclaimQueued(job.id, job.commandDigest!, "new", 300, 400), undefined);
  await journal.settleActivity(activity.id, "old", 300);
  journal.append({ ...job, state: "completed", updatedAt: 300, leaseUntil: 300 });
  assert.equal(await journal.reclaimQueued(job.id, job.commandDigest!, "new", 400, 500), undefined);
});

test("command codec binds project/job and rejects added authority and tampering", () => {
  const m = manager(), projectId = m.create({ name: "command codec" }).id, jobId = randomUUID();
  const command: NativeProjectCommand = { binding: "c".repeat(64), principal: { kind: "human", id: "owner" }, goal: "repair" };
  const encoded = encodeProjectCommand(command, jobId, projectId);
  assert.deepEqual(decodeProjectCommand(encoded.value, encoded.digest, jobId, projectId), command);
  const expanded = encodeProjectCommand({ ...command, goal: "x" + "\u0001".repeat(900 * 1024 - 1) }, jobId, projectId);
  assert.equal(decodeProjectCommand(expanded.value, expanded.digest, jobId, projectId).goal.length, 900 * 1024);
  assert.throws(() => decodeProjectCommand(encoded.value + " ", encoded.digest, jobId, projectId), /digest/u);
  assert.throws(() => decodeProjectCommand(encoded.value, encoded.digest, randomUUID(), projectId), /identity/u);
  assert.throws(() => encodeProjectCommand({ ...command, principal: { ...command.principal, role: "owner" } } as NativeProjectCommand, jobId, projectId), /principal/u);
});

test("durable principal references resolve current unique mappings, never persisted roles", () => {
  const mappings = [{ subject: "alice", id: "alice", role: "owner" as const, tenant: "alpha" }];
  const registry = new PrincipalRegistry(mappings);
  assert.equal(registry.resolveReference("alice", "alpha")?.role, "owner");
  assert.equal(registry.resolveReference("alice", "beta"), undefined);
  mappings.splice(0); assert.equal(registry.resolveReference("alice", "alpha"), undefined);
  assert.equal(new PrincipalRegistry([{ email: "alice@example.invalid", role: "owner" }]).resolveReference("alice"), undefined);
});

test("atomic dispatch admits one owner once and does not release callback capacity on lease expiry", async () => {
  const { root, journal } = submissionJournal(), m = manager();
  const projectId = m.create({ name: "shared dispatch" }).id;
  const policy = { aggregateCeiling: 1, perProjectShare: 1 };
  const job = (ownerId: string, at: number): ProjectJobIntent => ({ id: randomUUID(), projectId, workspaceKey: `project/${projectId}`, ownerId, weight: 1, label: "dispatch", createdAt: at, updatedAt: at, leaseUntil: at + 100, state: "queued" });
  const first = job("first", 100), second = job("second", 300);
  journal.append(first);
  const activity = await journal.tryDispatch(first.id, "first", policy, 100, 200);
  assert.ok(activity);
  await assert.rejects(journal.tryDispatch(first.id, "first", policy, 100, 200), /queued job/u);
  const observed = submissionJournal(root).journal;
  observed.append(second);
  assert.equal(await observed.tryDispatch(second.id, "second", policy, 300, 400), undefined, "expiry cannot erase owned callback capacity");
  await assert.rejects(observed.tryDispatch(second.id, "wrong-owner", policy, 300, 400), /owned/u);
  await assert.rejects(observed.tryDispatch(second.id, "second", { aggregateCeiling: 2, perProjectShare: 1 }, 300, 400), /policy conflicts/u);
  await journal.settleActivity(activity.id, "first", 300);
  journal.append({ ...first, state: "completed", updatedAt: 300, leaseUntil: 300 });
  assert.ok(await observed.tryDispatch(second.id, "second", policy, 300, 400));
});

test("failed atomic dispatch append invokes no callback and a cancelled queued job cannot claim", async () => {
  const { journal, spine } = submissionJournal(), m = manager(), projectId = m.create({ name: "dispatch disk failure" }).id;
  const runtime = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal);
  const stage = spine.stage.bind(spine);
  spine.stage = input => { if (input.payload["event"] === "project.job.dispatch") throw new Error("dispatch append unavailable"); return stage(input); };
  let calls = 0;
  const tracked = runtime.submitTracked(projectId, 1, async () => { calls++; });
  await assert.rejects(tracked.completion, /dispatch append unavailable/u); assert.equal(calls, 0);
  spine.stage = stage;
  await journal.requestCancellation(tracked.jobId);
  const queued = journal.load().find(row => row.id === tracked.jobId)!;
  await assert.rejects(journal.tryDispatch(queued.id, queued.ownerId, { aggregateCeiling: 1, perProjectShare: 1 }, queued.updatedAt, queued.leaseUntil), /uncancelled/u);
});

test("successful parent waits for owned child and admission retains one slot until actual settlement", async () => {
  const m = manager(), { journal } = submissionJournal(), projectId = m.create({ name: "owned child" }).id;
  const host = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal);
  let release!: () => void, entered!: () => void, parentDone = false;
  const gate = new Promise<string>(resolve => { release = () => resolve("child done"); }), entry = new Promise<void>(resolve => { entered = resolve; });
  const parent = host.submitTracked(projectId, 1, async context => {
    void context.trackActivity("provider", async () => { entered(); return gate; }).catch(() => undefined);
    await entry; return "parent done";
  });
  void parent.completion.then(() => { parentDone = true; });
  await entry; await new Promise<void>(resolve => setImmediate(resolve));
  assert.equal(parentDone, false); assert.equal(host.status().running, 1);
  const activity = host.activities(parent.jobId)!.find(row => row.label === "provider")!;
  assert.equal(activity.state, "running"); assert.deepEqual(host.job(parent.jobId)?.activeActivityIds, [activity.id]);
  assert.equal(host.activities(parent.jobId, new Set()), undefined);
  await assert.rejects(journal.settleActivity(activity.id, "different-owner", Date.now()), /owner mismatch/u);
  release(); assert.equal(await parent.completion, "parent done");
  assert.equal(host.job(parent.jobId)?.state, "completed"); assert.ok(host.activities(parent.jobId)!.every(row => row.state === "settled"));
});

test("unresolved child survives failed parent, runtime reconstruction and lease expiry without freeing admission", { timeout: 5000 }, async t => {
  const m = manager(), { root, journal } = submissionJournal(), projectId = m.create({ name: "orphan child" }).id;
  const host = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal);
  let release!: () => void, entered!: () => void, child!: Promise<void>, nextCalls = 0;
  const gate = new Promise<void>(resolve => { release = resolve; }), entry = new Promise<void>(resolve => { entered = resolve; }); t.after(() => release());
  const parent = host.submitTracked(projectId, 1, async context => {
    child = context.trackActivity("provider", async () => { entered(); await gate; });
    await entry; throw new Error("outer callback failed");
  });
  await assert.rejects(parent.completion, /outer callback failed/u);
  assert.equal(host.job(parent.jobId)?.state, "reconciliation-required"); assert.equal(host.status().running, 1);
  const expired = Date.now() + 60_000;
  const observer = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, submissionJournal(root).journal, { now: () => expired, leaseMs: 500, heartbeatMs: 50 });
  assert.equal(observer.status().running, 1, "lease expiry cannot stand in for a child settlement receipt");
  const next = observer.submitTracked(projectId, 1, async () => { nextCalls++; return "next"; });
  assert.equal(observer.status().queued, 1); assert.equal(nextCalls, 0);
  release(); await child;
  let timer!: ReturnType<typeof setTimeout>;
  try { assert.equal(await Promise.race([next.completion, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("settled child did not release capacity")), 2000); })]), "next"); }
  finally { clearTimeout(timer); }
  assert.equal(nextCalls, 1); assert.equal(observer.status().running, 0);
  assert.equal(observer.job(parent.jobId)?.state, "reconciliation-required", "free capacity is not permission to replay failed work");
});

test("activity start persistence failure invokes no backend", async () => {
  const m = manager(), { journal } = submissionJournal(), projectId = m.create({ name: "no activity start" }).id;
  journal.beginActivity = async () => { throw new Error("activity start unavailable"); };
  const host = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal);
  let calls = 0;
  await assert.rejects(host.submit(projectId, 1, context => context.trackActivity("provider", async () => { calls++; })), /activity start unavailable/u);
  assert.equal(calls, 0);
});

test("failed activity settlement retains capacity until the exact observed child is durably settled", async () => {
  const m = manager(), { root, journal } = submissionJournal(), projectId = m.create({ name: "uncertain child" }).id;
  const settle = journal.settleActivity.bind(journal); journal.settleActivity = async () => { throw new Error("activity settlement unavailable"); };
  const host = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal);
  let calls = 0;
  const parent = host.submitTracked(projectId, 1, context => context.trackActivity("provider", async () => { calls++; return "observed done"; }));
  await assert.rejects(parent.completion, /activity settlement unavailable/u); assert.equal(calls, 1);
  const observer = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, submissionJournal(root).journal);
  assert.equal(observer.status().running, 1);
  const activities = observer.activities(parent.jobId)!;
  assert.equal(activities.length, 2, "both callback and provider settlement writes failed");
  assert.ok(activities.every(activity => activity.state === "running"));
  for (const activity of activities) await settle(activity.id, activity.ownerId, Date.now()); // trusted host directly observed both calls end
  assert.equal(observer.status().running, 0); assert.equal(observer.job(parent.jobId)?.state, "reconciliation-required");
});

test("durable cancellation removes owned queued work before dispatch and preserves its stopped receipt", async () => {
  const m = manager(), { journal, root, spine } = submissionJournal(), projectId = m.create({ name: "cancel queue" }).id;
  const host = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal);
  let release!: () => void, calls = 0;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const first = host.submitTracked(projectId, 1, () => gate);
  const queued = host.submitTracked(projectId, 1, async () => { calls++; });
  const rejected = assert.rejects(queued.completion, ProjectJobCancelledError);
  assert.equal(await host.cancel(queued.jobId, new Set()), undefined, "hidden job cannot be targeted");
  assert.equal((await host.cancel(queued.jobId))?.state, "stopped"); await rejected;
  assert.equal((await host.cancel(queued.jobId))?.cancellationRequested, true);
  assert.equal(calls, 0); assert.equal(host.status().running, 1);
  assert.equal(spine.currentEvents().filter(e => e.payload["event"] === "project.job.cancel-requested").length, 1);
  assert.equal(submissionJournal(root).journal.load().find(job => job.id === queued.jobId)?.state, "stopped");
  release(); await first.completion;
});

test("foreign runtime cancellation reaches the live owner without claiming an ignoring callback stopped", { timeout: 5000 }, async t => {
  const m = manager(), { journal, root } = submissionJournal(), projectId = m.create({ name: "cancel live" }).id;
  const host = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal, { leaseMs: 500, heartbeatMs: 50 });
  let release!: () => void, entered!: () => void, aborted!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; }), entry = new Promise<void>(resolve => { entered = resolve; });
  t.after(() => release());
  const abort = new Promise<void>(resolve => { aborted = resolve; });
  const tracked = host.submitTracked(projectId, 1, async context => { context.signal.addEventListener("abort", aborted, { once: true }); entered(); await gate; return "late result"; });
  const rejected = assert.rejects(tracked.completion, ProjectJobCancelledError);
  await entry;
  const observer = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, submissionJournal(root).journal);
  const requested = await observer.cancel(tracked.jobId);
  assert.equal(requested?.cancellationRequested, true); assert.equal(requested?.state, "running");
  // The runtime's maintenance timer is intentionally unref'd. A test observer owns
  // its own finite wait, like the live HTTP server does; a bare promise is not a host.
  let waitTimer!: ReturnType<typeof setTimeout>;
  try { await Promise.race([abort, new Promise<never>((_, reject) => { waitTimer = setTimeout(() => reject(new Error("owner did not observe cancellation")), 2000); })]); }
  finally { clearTimeout(waitTimer); }
  assert.equal(host.status().running, 1); assert.equal(host.job(tracked.jobId)?.state, "running");
  release(); await rejected;
  assert.equal(host.job(tracked.jobId)?.state, "reconciliation-required");
  assert.equal(submissionJournal(root).journal.load()[0]?.cancellationRequested, true);
});

test("failed cancellation persistence sends no abort and terminal cancellation never rewrites success", async () => {
  const m = manager(), { journal, spine } = submissionJournal(), projectId = m.create({ name: "cancel refusal" }).id;
  const host = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal);
  let release!: () => void, signal!: AbortSignal;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const tracked = host.submitTracked(projectId, 1, async context => { signal = context.signal; await gate; return "done"; });
  await new Promise<void>(resolve => setImmediate(resolve));
  const stage = spine.stage.bind(spine); spine.stage = () => { throw new Error("cancel disk unavailable"); };
  await assert.rejects(host.cancel(tracked.jobId), /cancel disk unavailable/u);
  assert.equal(signal.aborted, false);
  spine.stage = stage; release(); assert.equal(await tracked.completion, "done");
  assert.equal((await host.cancel(tracked.jobId))?.state, "completed");
  assert.equal(host.job(tracked.jobId)?.cancellationRequested, undefined);
});

test("durable submission reserves before preparation, deduplicates concurrent retries and survives terminal reconstruction", async () => {
  const m = manager(), { root, journal } = submissionJournal();
  const host = new ProjectRuntime(m, { aggregateCeiling: 2, perProjectShare: 0.5 }, journal);
  let prepared = 0, calls = 0, release!: () => void, entered!: () => void;
  const entry = new Promise<void>(resolve => { entered = resolve; });
  const gate = new Promise<void>(resolve => { release = resolve; });
  const prepare = () => { prepared++; const projectId = m.create({ name: "once" }).id; return { projectId, run: async () => { calls++; entered(); await gate; return "done"; } }; };
  const [a, b] = await Promise.all([host.submitOnce(submissionRequest, prepare), host.submitOnce(submissionRequest, prepare)]);
  assert.equal(a.jobId, b.jobId); assert.equal(a.projectId, b.projectId); assert.deepEqual([a.replayed, b.replayed], [false, true]);
  await entry; // submission identity is returned before asynchronous dispatch admission
  assert.equal(prepared, 1); assert.equal(calls, 1); assert.equal(m.list().length, 1);
  await assert.rejects(host.submitOnce({ ...submissionRequest, requestDigest: "c".repeat(64) }, prepare), ProjectSubmissionConflictError);
  assert.equal(prepared, 1);
  release(); assert.equal(await a.completion, "done");
  const reopened = new ProjectRuntime(m, { aggregateCeiling: 2, perProjectShare: 0.5 }, submissionJournal(root).journal);
  const retry = await reopened.submitOnce(submissionRequest, prepare);
  assert.equal(retry.replayed, true); assert.equal(retry.jobId, a.jobId); assert.equal(retry.completion, undefined);
  assert.equal(reopened.job(retry.jobId)?.state, "completed"); assert.equal(calls, 1); assert.equal(prepared, 1);
});

test("reservation with no queued intent holds across restart and cannot prepare again", async () => {
  const m = manager(), { root, journal } = submissionJournal();
  const host = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal);
  let prepared = 0;
  await assert.rejects(host.submitOnce(submissionRequest, () => { prepared++; throw new Error("interrupted after reservation"); }), ProjectSubmissionUncertainError);
  const reopened = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, submissionJournal(root).journal);
  await assert.rejects(reopened.submitOnce(submissionRequest, () => { prepared++; throw new Error("must not run"); }), ProjectSubmissionUncertainError);
  assert.equal(prepared, 1); assert.equal(m.list().length, 0);
});

test("submission requires durable atomic journal and failed reservation performs no preparation", async () => {
  const m = manager(); let prepared = 0;
  const prepare = () => { prepared++; throw new Error("must not run"); };
  const unsupported = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, new MemoryJobJournal());
  await assert.rejects(unsupported.submitOnce(submissionRequest, prepare), /durable atomic/u);
  const { spine, journal } = submissionJournal();
  spine.stage = () => { throw new Error("disk unavailable"); };
  const failed = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal);
  await assert.rejects(failed.submitOnce(submissionRequest, prepare), /disk unavailable/u);
  assert.equal(prepared, 0);
});

test("expired file-backed job is classified durably and idempotent retry cannot restart its callback", async () => {
  const m = manager(), projectId = m.create({ name: "interrupted once" }).id, { root, journal } = submissionJournal();
  const jobId = randomUUID();
  await journal.reserveSubmission({ ...submissionRequest, jobId });
  const intent: ProjectJobIntent = { id: jobId, projectId, workspaceKey: `project/${projectId}`, ownerId: "old-runtime", weight: 1, label: "interrupted", createdAt: 100, updatedAt: 100, leaseUntil: 200, state: "queued" };
  journal.append(intent); journal.append({ ...intent, state: "running" });
  const reopened = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, submissionJournal(root).journal, { now: () => 300 });
  let prepared = 0;
  const retry = await reopened.submitOnce(submissionRequest, () => { prepared++; throw new Error("must not run"); });
  assert.equal(retry.jobId, jobId); assert.equal(reopened.job(jobId)?.state, "reconciliation-required");
  assert.equal(submissionJournal(root).journal.load()[0]?.state, "reconciliation-required"); assert.equal(prepared, 0);
});

test("independent OS claimants and concurrent sealing retain one durable submission winner", { timeout: 10_000 }, async () => {
  const { root, spine, journal } = submissionJournal();
  const script = `
    import { Spine } from ${JSON.stringify(new URL("../src/spine/spine.js", import.meta.url).href)};
    import { FileSpineStore } from ${JSON.stringify(new URL("../src/spine/store.js", import.meta.url).href)};
    import { FileSystemLock } from ${JSON.stringify(new URL("../src/lock/lock.js", import.meta.url).href)};
    import { SchemaRegistry } from ${JSON.stringify(new URL("../src/spine/upcaster.js", import.meta.url).href)};
    import { SpineProjectJobJournal } from ${JSON.stringify(new URL("../src/session/project_job_journal.js", import.meta.url).href)};
    import { randomUUID } from "node:crypto";
    const s = new Spine(new FileSpineStore(process.argv[1], {fsync:true}), new FileSystemLock(process.argv[1] + "/locks"), new SchemaRegistry());
    const j = new SpineProjectJobJournal(s);
    const r = await j.reserveSubmission({...${JSON.stringify(submissionRequest)}, jobId:randomUUID()});
    await s.seal(); console.log(JSON.stringify(r));
  `;
  const results = await Promise.all([0, 1].map(async () => {
    const child = await promisify(execFile)(process.execPath, ["--input-type=module", "-e", script, root], { env: {}, timeout: 8000, maxBuffer: 4096 });
    return JSON.parse(child.stdout) as { created: boolean; submission: { jobId: string } };
  }));
  assert.equal(results.filter(row => row.created).length, 1); assert.equal(new Set(results.map(row => row.submission.jobId)).size, 1);
  const retry = await journal.reserveSubmission({ ...submissionRequest, jobId: randomUUID() });
  assert.equal(retry.created, false); assert.equal(retry.submission.jobId, results[0]!.submission.jobId);
  assert.equal(spine.currentEvents().filter(event => (event.payload as Record<string, unknown>)["event"] === "project.job.submission").length, 1);
});

test("runtime provides unique project workspace identities", async () => {
  const { manager, runtime } = newRuntime();
  const a = manager.create({ name: "alpha" }).id; const b = manager.create({ name: "beta" }).id;
  const [ac, bc] = await Promise.all([runtime.submit(a, 1, async (context) => context), runtime.submit(b, 1, async (context) => context)]);
  assert.equal(ac.workspaceKey, `project/${a}`); assert.equal(bc.workspaceKey, `project/${b}`); assert.notEqual(ac.workspaceKey, bc.workspaceKey);
});

test("tracked submission returns one durable identity before completion and observes its terminal record after restart", async () => {
  const m = manager(), project = m.create({ name: "tracked" }).id, journal = new MemoryJobJournal();
  const host = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal);
  let release!: () => void, calls = 0;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const tracked = host.submitTracked(project, 1, async context => {
    calls++; assert.equal(context.jobId, tracked.jobId); await gate; return "result";
  });
  assert.equal(journal.rows[0]?.id, tracked.jobId);
  assert.equal(host.job(tracked.jobId)?.state, "running");
  await new Promise<void>(resolve => setImmediate(resolve));
  for (let i = 0; i < 3; i++) assert.equal(host.job(tracked.jobId)?.state, "running");
  assert.equal(calls, 1);
  assert.equal(host.job(tracked.jobId, new Set()), undefined, "caller visibility applies to individual lookup");
  release(); assert.equal(await tracked.completion, "result");
  assert.equal(host.job(tracked.jobId)?.state, "completed");
  const restarted = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal);
  assert.equal(restarted.job(tracked.jobId)?.state, "completed"); assert.equal(calls, 1);
});

test("tracked submission cannot dispatch without a durable queued intent", () => {
  const m = manager(), project = m.create({ name: "refused tracked" }).id;
  const host = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, new MemoryJobJournal([], 0));
  let calls = 0;
  assert.throws(() => host.submitTracked(project, 1, async () => { calls++; }), /journal unavailable/u);
  assert.equal(calls, 0);
});

test("aggregate and per-project limits avoid cross-project head-of-line blocking", async () => {
  const { manager, runtime: host } = newRuntime();
  const a = manager.create({ name: "A" }).id; const b = manager.create({ name: "B" }).id; const c = manager.create({ name: "C" }).id;
  let releaseA!: () => void; let releaseB!: () => void;
  const gateA = new Promise<void>((resolve) => { releaseA = resolve; }); const gateB = new Promise<void>((resolve) => { releaseB = resolve; });
  const seen: string[] = [];
  const a1 = host.submit(a, 1, async () => { seen.push("a1"); await gateA; return "a1"; });
  const a2 = host.submit(a, 1, async () => { seen.push("a2"); return "a2"; });
  const b1 = host.submit(b, 1, async () => { seen.push("b1"); await gateB; return "b1"; });
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.deepEqual(host.status(), { running: 2, queued: 1 }); assert.deepEqual(seen, ["a1", "b1"]);
  const c1 = host.submit(c, 1, async () => { seen.push("c1"); return "c1"; });
  releaseB(); assert.equal(await b1, "b1"); assert.equal(await c1, "c1");
  releaseA(); assert.deepEqual(await Promise.all([a1, a2]), ["a1", "a2"]); assert.deepEqual(host.status(), { running: 0, queued: 0 });
});

test("restart stops queued work and quarantines running work without invoking callbacks", async () => {
  const m = manager(); const project = m.create({ name: "interrupted" }).id; const journal = new MemoryJobJournal();
  const first = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal);
  let entered!: () => void; let release!: () => void; let callbacks = 0;
  const didEnter = new Promise<void>((resolve) => { entered = resolve; }); const hold = new Promise<void>((resolve) => { release = resolve; });
  const running = first.submit(project, 1, async () => { callbacks++; entered(); await hold; return "running"; });
  const queued = first.submit(project, 1, async () => { callbacks++; return "queued"; });
  await didEnter;
  const expiredAt = Math.max(...journal.rows.map((row) => row.leaseUntil)) + 1;
  const restarted = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, new MemoryJobJournal(journal.rows.map((row) => ({ ...row }))), { now: () => expiredAt });
  assert.equal(callbacks, 1); assert.deepEqual(restarted.jobs().map((job) => job.state).sort(), ["reconciliation-required", "stopped"]);
  assert.deepEqual(restarted.status(), { running: 0, queued: 0 });
  release(); assert.equal(await running, "running"); assert.equal(await queued, "queued");
});

test("a second live runtime observes and capacity-counts unexpired work without quarantining it", async () => {
  const m = manager(); const project = m.create({ name: "live owner" }).id; const other = m.create({ name: "waiting owner" }).id; const journal = new MemoryJobJournal();
  const first = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal, { ownerId: "owner-a", leaseMs: 500, heartbeatMs: 50 });
  let release!: () => void; const gate = new Promise<void>((resolve) => { release = resolve; });
  const running = first.submit(project, 1, async () => { await gate; return "completed by owner"; });
  await new Promise<void>((resolve) => setImmediate(resolve));
  const second = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal, { ownerId: "owner-b", leaseMs: 500, heartbeatMs: 50 });
  assert.equal(second.jobs().find((job) => job.state === "running")?.ownerId, "owner-a");
  assert.deepEqual(second.status(), { running: 1, queued: 0 });
  let secondCalls = 0; const queued = second.submit(other, 1, async () => { secondCalls += 1; return "started after capacity released"; });
  assert.equal(secondCalls, 0); assert.deepEqual(second.status(), { running: 1, queued: 1 });
  release(); assert.equal(await running, "completed by owner");
  let timeout!: NodeJS.Timeout;
  const bounded = new Promise<string>((_resolve, reject) => { timeout = setTimeout(() => reject(new Error("cross-runtime queue did not drain")), 1_000); });
  assert.equal(await Promise.race([queued, bounded]).finally(() => clearTimeout(timeout)), "started after capacity released");
  assert.equal(journal.rows.some((row) => row.state === "reconciliation-required"), false);
});

test("callback never starts unless queued and running intents are durable", async () => {
  const m = manager(); const project = m.create({ name: "intent first" }).id; let calls = 0;
  const noQueue = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, new MemoryJobJournal([], 0));
  await assert.rejects(noQueue.submit(project, 1, async () => { calls++; }), /journal unavailable/u); assert.equal(calls, 0);
  const noRunning = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, new MemoryJobJournal([], 1));
  await assert.rejects(noRunning.submit(project, 1, async () => { calls++; }), /journal unavailable/u); assert.equal(calls, 0);
});

test("terminal persistence failure returns reconciliation error and never invites an automatic success claim", async () => {
  const m = manager(); const project = m.create({ name: "uncertain terminal" }).id; let calls = 0;
  const journal = new MemoryJobJournal([], 2);
  const host = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal);
  await assert.rejects(host.submit(project, 1, async () => { calls++; return "effect-complete"; }), (error: unknown) => error instanceof ProjectJobReconciliationError);
  assert.equal(calls, 1); assert.equal(host.jobs()[0]?.state, "reconciliation-required");
});

test("heartbeat failure cannot hide a still-running local callback from admission or deletion", async () => {
  const m = manager(); const runningProject = m.create({ name: "still executing" }).id; const other = m.create({ name: "must wait" }).id;
  class HeartbeatFailingJournal extends MemoryJobJournal {
    override renew(): void { throw new Error("heartbeat persistence failed"); }
  }
  const journal = new HeartbeatFailingJournal();
  const host = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal, { leaseMs: 100, heartbeatMs: 25 });
  let release!: () => void; const gate = new Promise<void>((resolve) => { release = resolve; }); let otherCalls = 0;
  const running = host.submit(runningProject, 1, async () => { await gate; return "done"; });
  await new Promise<void>((resolve) => setTimeout(resolve, 140));
  assert.deepEqual(host.status(), { running: 1, queued: 0 });
  assert.throws(() => host.delete(runningProject), /running work/u);
  const waiting = host.submit(other, 1, async () => { otherCalls++; return "other"; });
  await new Promise<void>((resolve) => setImmediate(resolve)); assert.equal(otherCalls, 0);
  assert.equal(host.jobs().find((row) => row.projectId === other)?.state, "queued");
  assert.deepEqual(host.status(), { running: 1, queued: 1 });
  release(); assert.equal(await running, "done");
  assert.equal(await waiting, "other");
});

test("stable owner restart still counts live leased intents without pretending a callback is local", async () => {
  const m = manager(); const occupied = m.create({ name: "leased owner" }).id; const waiting = m.create({ name: "wait for lease" }).id;
  const journal = new MemoryJobJournal(); const first = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal, { ownerId: "stable-owner", leaseMs: 500, heartbeatMs: 50 });
  let release!: () => void; const gate = new Promise<void>((resolve) => { release = resolve; });
  const active = first.submit(occupied, 1, async () => gate); await new Promise<void>((resolve) => setImmediate(resolve));
  const restarted = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal, { ownerId: "stable-owner", leaseMs: 500, heartbeatMs: 50 });
  assert.deepEqual(restarted.status(), { running: 1, queued: 0 });
  assert.throws(() => restarted.delete(occupied), /running work/u);
  let calls = 0; const queued = restarted.submit(waiting, 1, async () => { calls++; return "after lease"; });
  await new Promise<void>((resolve) => setImmediate(resolve)); assert.equal(calls, 0); assert.deepEqual(restarted.status(), { running: 1, queued: 1 });
  release(); await active;
  let timeout!: NodeJS.Timeout; const bounded = new Promise<string>((_resolve, reject) => { timeout = setTimeout(() => reject(new Error("stable-owner lease did not drain")), 1_000); });
  assert.equal(await Promise.race([queued, bounded]).finally(() => clearTimeout(timeout)), "after lease");
});

test("queue bounds, positive weights, and archive/delete lifecycle fail closed without cross-project damage", async () => {
  const m = manager(); const a = m.create({ name: "A" }).id; const b = m.create({ name: "B" }).id;
  const host = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, undefined, { maxQueuedJobs: 1 });
  await assert.rejects(host.submit(a, 0, async () => undefined), /greater than zero/u);
  let release!: () => void; const gate = new Promise<void>((resolve) => { release = resolve; });
  const running = host.submit(b, 1, async () => { await gate; }); const queued = host.submit(b, 1, async () => undefined);
  await assert.rejects(host.submit(a, 1, async () => undefined), /queue is full/u);
  host.archive(a); assert.throws(() => m.runnableSession(a), /archived and read-only/u); assert.throws(() => host.delete(b), /running work/u);
  release(); await running; await queued; host.delete(b); assert.equal(m.list().some((row) => row.id === b), false);
});

test("spine journal is durable, strict, monotonic, and rejects malformed matching events", () => {
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-job-spine-")), { fsync: true }), new InProcessLock(), new SchemaRegistry());
  const journal = new SpineProjectJobJournal(spine);
  const projectId = new ProjectRegistry(new CryptoShredKeyStore()).create("journal").id;
  const queued: ProjectJobIntent = { id: "00000000-0000-4000-8000-000000000001", projectId, workspaceKey: `project/${projectId}`, weight: 1, label: "job", ownerId: "owner", leaseUntil: 10, state: "queued", createdAt: 1, updatedAt: 1 };
  journal.append(queued); journal.append({ ...queued, state: "running", updatedAt: 2 });
  assert.equal(journal.load()[0]?.state, "running");
  const other = new ProjectRegistry(new CryptoShredKeyStore()).create("other").id;
  assert.throws(() => journal.append({ ...queued, projectId: other, workspaceKey: `project/${other}`, state: "completed", updatedAt: 3 }), /immutable identity/u);
  spine.stage({ type: "identity.action", actor: "attacker", payload: { event: "project.job.intent", id: "bad" } });
  assert.equal(journal.load()[0]?.state, "running", "lookalike events from another actor are not journal authority");
  const reconciled = { ...queued, state: "reconciliation-required" as const, updatedAt: 11, leaseUntil: 11, reason: "expired" };
  journal.append(reconciled);
  spine.stage({ type: "identity.action", actor: "project-runtime", payload: { event: "project.job.intent", ...reconciled, updatedAt: 12, leaseUntil: 12 } });
  assert.equal(journal.load()[0]?.state, "reconciliation-required", "duplicate recovery writers cannot poison the append-only journal");
});

test("incremental job folding resets when recovery rewrites a prefix while the view grows", () => {
  const projectId = new ProjectRegistry(new CryptoShredKeyStore()).create("fold recovery").id;
  const queued: ProjectJobIntent = { id: "00000000-0000-4000-8000-000000000099", projectId, workspaceKey: `project/${projectId}`, weight: 1, label: "job", ownerId: "owner", leaseUntil: 10, state: "queued", createdAt: 1, updatedAt: 1 };
  const event = (id: string, intent: ProjectJobIntent) => ({ id, schemaVersion: 1, type: "identity.action", ts: 1, actor: "project-runtime", payload: { event: "project.job.intent", ...intent } });
  const events: Array<{ id: string; schemaVersion: number; type: string; ts: number; actor: string; payload: Record<string, unknown> }> = [event("evt-a", queued), event("evt-b", { ...queued, state: "running" as const, updatedAt: 2 })];
  const fake = { durableStorage: () => true, currentEvents: () => events, stage: () => { throw new Error("not used"); } } as unknown as Spine;
  const journal = new SpineProjectJobJournal(fake); assert.equal(journal.load()[0]?.state, "running");
  events.splice(1, 1,
    event("evt-c", { ...queued, state: "running" as const, updatedAt: 2 }),
    event("evt-d", { ...queued, state: "completed" as const, updatedAt: 3 }),
  );
  assert.equal(journal.load()[0]?.state, "completed", "changed prefix identity forces a complete authoritative refold");
});

test("one heartbeat event durably renews a bounded batch without per-job journal amplification", () => {
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-job-heartbeat-")), { fsync: true }), new InProcessLock(), new SchemaRegistry());
  const journal = new SpineProjectJobJournal(spine);
  const projectId = new ProjectRegistry(new CryptoShredKeyStore()).create("heartbeat").id;
  const ids: string[] = [];
  for (let index = 1; index <= 64; index++) {
    const id = `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`;
    ids.push(id);
    journal.append({ id, projectId, workspaceKey: `project/${projectId}`, weight: 1, label: "job", ownerId: "owner", leaseUntil: 10, state: "queued", createdAt: 1, updatedAt: 1 });
  }
  const before = spine.currentEvents().length;
  journal.renew("owner", ids, 5, 100);
  assert.equal(spine.currentEvents().length, before + 1, "renewal cost is one event rather than one event per job");
  assert.equal(journal.load().filter((row) => row.updatedAt === 5 && row.leaseUntil === 100).length, ids.length);
});

test("spine job journal refuses non-durable storage", () => {
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-job-nondurable-"))), new InProcessLock(), new SchemaRegistry());
  assert.throws(() => new SpineProjectJobJournal(spine), /requires durable/u);
});

test("installed composition shares one durable manager across autonomy and background runtime after restart", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "keep-project-composition-"));
  const solve = async () => ({ solveResult: { issueId: "unused", solved: true, stagesRun: [], repairRounds: 0 } }) as never;
  const first = composeKeep({ dataDir, solve });
  assert.ok(first.autonomyLoop && first.projectManager && first.projectRuntime);
  assert.equal(first.autonomyLoop.manager, first.projectManager);
  assert.equal(first.projectRuntime.manager, first.projectManager);

  const record = first.projectManager.create({ name: "durable composed project" });
  first.projectManager.session(record.id).append("user", "survive composition restart", 1);
  first.projectManager.session(record.id).putSecret("provider-token", "not-in-cleartext");
  const workspaceKey = await first.projectRuntime.submit(record.id, 1, async (context) => context.workspaceKey);
  assert.equal(workspaceKey, `project/${record.id}`);

  const second = composeKeep({ dataDir, solve });
  assert.ok(second.autonomyLoop && second.projectManager && second.projectRuntime);
  assert.equal(second.autonomyLoop.manager, second.projectManager);
  assert.equal(second.projectRuntime.manager, second.projectManager);
  assert.equal(second.projectManager.list().find((row) => row.id === record.id)?.name, "durable composed project");
  assert.deepEqual(second.projectManager.session(record.id).history().map((entry) => entry.text), ["survive composition restart"]);
  assert.equal(second.projectManager.session(record.id).resolveSecret("provider-token"), "not-in-cleartext");
});

test("non-durable composition exposes no background runtime that could overstate crash safety", () => {
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-project-nondurable-composition-")),
    fsync: false,
    solve: async () => ({ solveResult: { issueId: "unused", solved: true, stagesRun: [], repairRounds: 0 } }) as never,
  });
  assert.equal(app.spineDurable, false);
  assert.ok(app.autonomyLoop && app.projectManager);
  assert.equal(app.projectRuntime, undefined);
});

test("managed autonomy never invokes work when persist-before-execution run binding fails", async () => {
  const registry = new ProjectRegistry(new CryptoShredKeyStore());
  const failed: ProjectSessionPersistence = { load: () => undefined, save: () => { throw new Error("binding disk full"); } };
  const checkpoints = new InMemoryProjectCheckpointStore();
  const managed = new ProjectSessionManager(registry, undefined, () => failed, checkpoints);
  const project = managed.create({ name: "must not execute" });
  let solves = 0;
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-bind-first-")), { fsync: true }), new InProcessLock(), new SchemaRegistry());
  const loop = buildAutonomyLoop({
    spine, checkpoints, manager: managed,
    solve: async () => { solves += 1; return { solveResult: { issueId: "forbidden", solved: true, stagesRun: [], repairRounds: 0 } } as never; },
  });
  await assert.rejects(loop.runManagedProject(project.id, "write and test a local parser"), /binding disk full/u);
  assert.equal(solves, 0);
  assert.equal(managed.session(project.id).boundRunId(), undefined);
});

test("a managed checkpoint is cryptographically and structurally bound to one project", async () => {
  const m = manager(); const a = m.create({ name: "tenant A" }).id; const b = m.create({ name: "tenant B" }).id;
  const checkpoints = new InMemoryProjectCheckpointStore();
  const loop = buildAutonomyLoop({ spine: new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-project-binding-")), { fsync: true }), new InProcessLock(), new SchemaRegistry()), checkpoints, manager: m, solve: async () => ({ solveResult: { issueId: "x", solved: true, stagesRun: [], repairRounds: 0 } }) as never });
  const first = await loop.runManagedProject(a, "write and test a local parser", { runId: "shared-run" });
  assert.equal(first.state.projectId, a);
  await assert.rejects(loop.runManagedProject(b, first.state.goal, { runId: "shared-run" }), /requires its owning managed project|different project/u);
});

test("queued callers settle even when cancellation journaling fails", async () => {
  const m = manager(); const runningProject = m.create({ name: "running" }).id; const queuedProject = m.create({ name: "queued" }).id;
  const journal = new MemoryJobJournal([], 3);
  const runtime = new ProjectRuntime(m, { aggregateCeiling: 1, perProjectShare: 1 }, journal);
  let release!: () => void; const gate = new Promise<void>((resolve) => { release = resolve; });
  const running = runtime.submit(runningProject, 1, async () => gate);
  const queued = runtime.submit(queuedProject, 1, async () => undefined);
  assert.throws(() => runtime.delete(queuedProject), /queued job cancellations were not durable/u);
  await assert.rejects(queued, /deleted before execution/u);
  assert.equal(runtime.jobs().find((row) => row.projectId === queuedProject)?.state, "reconciliation-required");
  release(); await assert.rejects(running, (error: unknown) => error instanceof ProjectJobReconciliationError);
});
