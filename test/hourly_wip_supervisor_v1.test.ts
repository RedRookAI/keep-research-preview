import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { GitAdapter } from "../src/infra/git_adapter.js";
import { InstalledEffectAdmission } from "../src/control/installed_effect_admission.js";
import {
  captureHourlyWipV1,
  GitWipPublicationPortV1,
  HourlyWipSupervisorV1,
  runYoloTicketStepWithHourlyWipV1,
  verifyHourlyWipSnapshotV1,
  type HourlyWipSnapshotV1,
  type PreparedWipPublicationV1,
  type WipPublicationPortV1,
  type WipRemoteReadbackV1,
} from "../src/backup/hourly_wip_supervisor_v1.js";
import { pinnedRemoteFetchUrlSha256, pinnedRemoteUrlSha256 } from "../src/git/pinned_remote.js";
import { FileWorkAttemptAuthorityV1, StaleWorkAttemptError, type WorkAttemptFenceV1, type WorkAttemptSnapshotV1 } from "../src/spine/work_attempt_authority_v1.js";
import { activateTicketResearch } from "../src/autonomy/project_state.js";
import { YoloTicketCoordinatorV1 } from "../src/autonomy/yolo_ticket_coordinator_v1.js";

function repository(): { readonly root: string; readonly git: GitAdapter } {
  const root = mkdtempSync(join(tmpdir(), "keep-hourly-wip-git-"));
  const git = new GitAdapter(root);
  return { root, git };
}

const digest = (value: string): string => createHash("sha256").update(value).digest("hex");
const canonical = (value: unknown): string => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value !== null && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(",")}}` : JSON.stringify(value);
const objectDigest = (value: unknown): string => createHash("sha256").update(canonical(value)).digest("hex");

function attempt(base: string, track: "n1" | "enterprise" = "n1"): WorkAttemptSnapshotV1 {
  const authority = track === "n1"
    ? { kind: "n1" as const, owner_id: "owner-1", custody_id: "custody-owner", organization_services: "ABSENT" as const }
    : { kind: "enterprise" as const, organization_id: "org-1", tenant_id: "tenant-1", actor_id: "actor-1", role_id: "builder", separation_policy_id: "sep-1", custody_id: "custody-org", isolation_id: "isolation-1", custody_evidence_digest: "1".repeat(64), isolation_evidence_digest: "2".repeat(64), local_owner_substitution: false as const };
  const ticketBody = { id: "SG-01-T004", title: "Publish hourly WIP", requirements: ["wip"], finish_conditions: ["restore"], research_contract: {}, mutation_surface: ["src/backup/hourly_wip_supervisor_v1.ts"], scope_rows: ["K-002"], resource_bounds: { peak_ram_mib: 512, peak_disk_mib: 3072, max_parallel_processes: 1 } };
  return {
    schema: "keep.work-attempt-authority/v1", schema_version: 1,
    identity: { project_id: "project-1", goal_id: "goal-1", subgoal_id: "SG-01", ticket_id: "SG-01-T004", ticket_body: ticketBody, ticket_body_digest: objectDigest(ticketBody), failure_lessons: [{ id: "FL-001", digest: "4".repeat(64) }], track, authority, product_commit: base, interpreter_identity: "node-test" },
    identity_digest: digest(`identity-${track}`), attempt_id: track === "n1" ? "a".repeat(32) : "b".repeat(32), generation: 2, transitions: [],
  };
}

async function committedFixture(): Promise<{ readonly root: string; readonly git: GitAdapter; readonly base: string }> {
  const fixture = repository(); await fixture.git.git(["init"]); await fixture.git.git(["config", "user.name", "Test"]); await fixture.git.git(["config", "user.email", "test@invalid"]);
  writeFileSync(join(fixture.root, "tracked.txt"), "base\n"); writeFileSync(join(fixture.root, "deleted.txt"), "delete me\n"); await fixture.git.git(["add", "tracked.txt", "deleted.txt"]); await fixture.git.git(["commit", "-m", "base"]);
  return { ...fixture, base: (await fixture.git.git(["rev-parse", "HEAD"])).stdout.trim() };
}

class FakePublicationPort implements WipPublicationPortV1 {
  prepare_count = 0; publish_count = 0; readback_count = 0; release_count = 0; published = false; fail_prepare_once = false; throw_after_publish = false; last_snapshot: HourlyWipSnapshotV1 | null = null;
  async prepare(snapshot: HourlyWipSnapshotV1): Promise<PreparedWipPublicationV1> {
    this.prepare_count += 1; this.last_snapshot = snapshot;
    if (this.fail_prepare_once) { this.fail_prepare_once = false; throw new Error("prepare interrupted"); }
    return { schema_version: 1, job_id: snapshot.job_id, snapshot_sha256: snapshot.manifest_sha256, recovery_ref: snapshot.recovery_ref, commit_oid: "d".repeat(40), expected_remote_oid: null, repository_path: join(tmpdir(), snapshot.job_id) };
  }
  async publish(_prepared: PreparedWipPublicationV1): Promise<void> {
    this.publish_count += 1; this.published = true;
    if (this.throw_after_publish) { this.throw_after_publish = false; throw new Error("Git result ambiguous"); }
  }
  async readBack(prepared: PreparedWipPublicationV1): Promise<WipRemoteReadbackV1> {
    this.readback_count += 1;
    if (!this.published || this.last_snapshot === null) throw new Error("remote unavailable");
    return { commit_oid: prepared.commit_oid, snapshot: this.last_snapshot };
  }
  async recover(_recoveryRef: string, _expected: { readonly attempt: HourlyWipSnapshotV1["attempt"] }): Promise<WipRemoteReadbackV1> { throw new Error("not used"); }
  async release(_prepared: PreparedWipPublicationV1): Promise<void> { this.release_count += 1; }
  async materialize(_readback: WipRemoteReadbackV1, _targetRoot: string, _expected: { readonly attempt: HourlyWipSnapshotV1["attempt"] }): Promise<void> { throw new Error("not used"); }
}

function fence(work: WorkAttemptSnapshotV1, current = true): WorkAttemptFenceV1 {
  return { reference: { identity_digest: work.identity_digest, attempt_id: work.attempt_id, generation: work.generation }, identity: work.identity,
    withCurrent: async <T>(commit: () => Promise<T>): Promise<T> => { if (!current) throw new StaleWorkAttemptError("stale"); return await commit(); } };
}

function wipRequest(fixture: { readonly root: string; readonly git: GitAdapter; readonly base: string }, work: WorkAttemptSnapshotV1, hour = 44) {
  return { project_root: fixture.root, git: fixture.git, base_commit: fixture.base, recovery_ref: `refs/heads/keep-wip/${work.identity.track}/${work.identity_digest}`, hour_bucket_utc: hour, allowlist: ["tracked.txt"], last_result: "focused pending", next_action: "continue" };
}

function researchProgress(track: "n1" | "enterprise") {
  const generation = `sha256:${"a".repeat(64)}`;
  const activation = { schema_version: 1 as const, approved_generation: { generation, publication_receipt_digest: "d".repeat(64), remote_readback_commit: "b".repeat(40), remote_ref_matched: true as const, tickets: [{ ticket_id: "PG-04-T008", track, dependency_ticket_ids: [] }, { ticket_id: "SG-01-T003B", track, dependency_ticket_ids: ["PG-04-T008"] }, { ticket_id: "SG-01-T004", track, dependency_ticket_ids: ["SG-01-T003B"] }] }, state: { schema_version: 1 as const, active_generation: generation, active_ticket_id: null, closed_ticket_ids: ["PG-04-T008", "SG-01-T003B"] }, selected_ticket_id: "SG-01-T004", expected_generation: generation, authority: track === "n1" ? { kind: "n1" as const, owner_id: "owner-1", custody_id: "custody-owner", organization_services: "ABSENT" as const } : { kind: "enterprise" as const, organization_id: "org-1", actor_id: "actor-1", role_id: "builder", separation_policy_id: "sep-1", custody_evidence_digest: "1".repeat(64), isolation_evidence_digest: "2".repeat(64), local_owner_substitution: false as const }, implementation_authorized: false as const };
  const activated = activateTicketResearch(activation); assert.equal(activated.advanced, true); assert.ok(activated.receipt);
  return { activation, receipt: activated.receipt, current_state: { schema_version: 1 as const, active_generation: generation, active_ticket_id: "SG-01-T004", closed_ticket_ids: ["PG-04-T008", "SG-01-T003B"] } };
}

test("SG-01-T004 Git plumbing accepts exact binary stdin without a pathname", async () => {
  const fixture = repository();
  await fixture.git.git(["init"]);
  const bytes = Buffer.from([0, 1, 2, 10, 13, 255, 0, 42]);
  const written = await fixture.git.gitInput(["hash-object", "-w", "--stdin"], { stdin: bytes });
  const oid = written.stdout.toString("ascii").trim();
  assert.match(oid, /^[0-9a-f]{40,64}$/u);
  const fetched = await fixture.git.gitInput(["cat-file", "blob", oid]);
  assert.deepEqual(fetched.stdout, bytes);
});

test("SG-01-T004 timed Git plumbing kills its complete POSIX process group", { skip: process.platform === "win32" }, async () => {
  const fixture = repository();
  await fixture.git.git(["init"]);
  const marker = join(fixture.root, "late-child-marker");
  const helper = join(fixture.root, "slow-helper.sh");
  writeFileSync(helper, `#!/bin/sh\n(sleep 1; printf late > '${marker}') &\nwait\n`, { mode: 0o700 });
  await assert.rejects(
    fixture.git.gitInput(["-c", `alias.keep-wait=!${helper}`, "keep-wait"], { timeoutMs: 100, killProcessGroup: true }),
    /timed out/u,
  );
  await new Promise((resolve) => setTimeout(resolve, 1_200));
  assert.equal(existsSync(marker), false, "a timed-out Git transport helper must not outlive fence release");
});

test("SG-01-T004 Git plumbing validates resource bounds before spawning", async () => {
  const fixture = repository();
  await assert.rejects(fixture.git.gitInput(["version"], { timeoutMs: 0 }), /timeoutMs/u);
  await assert.rejects(fixture.git.gitInput(["version"], { maxOutputBytes: 0 }), /maxOutputBytes/u);
  const observed: string[] = [];
  const admitted = new GitAdapter(fixture.root, new InstalledEffectAdmission((record) => observed.push(record.id)));
  await admitted.gitInput(["version"]);
  assert.deepEqual(observed, ["git.command"]);
});

test("SG-01-T004 capture binds tracked, staged, unstaged and untracked bytes without changing Git state", async () => {
  const fixture = await committedFixture();
  writeFileSync(join(fixture.root, "tracked.txt"), "staged\n"); await fixture.git.git(["add", "tracked.txt"]); writeFileSync(join(fixture.root, "tracked.txt"), "worktree\n");
  writeFileSync(join(fixture.root, "new.txt"), "untracked\n", { mode: 0o755 });
  const beforeHead = await fixture.git.head(); const beforeStatus = (await fixture.git.gitInput(["status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames"])).stdout;
  const work = attempt(fixture.base);
  const snapshot = await captureHourlyWipV1({ project_root: fixture.root, git: fixture.git, attempt: work, base_commit: fixture.base, recovery_ref: `refs/heads/keep-wip/n1/${work.identity_digest}`, hour_bucket_utc: 42, allowlist: ["tracked.txt", "new.txt"], last_result: "focused check not run", next_action: "continue ticket" });
  assert.ok(snapshot); assert.equal(verifyHourlyWipSnapshotV1(snapshot), true); assert.equal(snapshot.status, "WIP_UNVERIFIED"); assert.equal(snapshot.test_status, "NOT_RUN_WIP");
  assert.deepEqual(snapshot.files.map((file) => file.path), ["new.txt", "tracked.txt"]);
  assert.equal(Buffer.from(snapshot.files[1]!.index!.content_base64, "base64").toString(), "staged\n");
  assert.equal(Buffer.from(snapshot.files[1]!.worktree!.content_base64, "base64").toString(), "worktree\n");
  assert.equal(verifyHourlyWipSnapshotV1({ ...snapshot, unknown: true } as unknown as HourlyWipSnapshotV1), false);
  assert.equal(await fixture.git.head(), beforeHead); assert.deepEqual((await fixture.git.gitInput(["status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames"])).stdout, beforeStatus);
});

test("SG-01-T004 capture refuses secret content, excluded dirty work and paths outside its allowlist", async () => {
  const fixture = await committedFixture(); const work = attempt(fixture.base); const common = { project_root: fixture.root, git: fixture.git, attempt: work, base_commit: fixture.base, recovery_ref: `refs/heads/keep-wip/n1/${work.identity_digest}`, hour_bucket_utc: 42, last_result: "pending", next_action: "repair" };
  writeFileSync(join(fixture.root, "tracked.txt"), "ghp_abcdefghijklmnopqrstuvwxyz123456\n");
  await assert.rejects(captureHourlyWipV1({ ...common, allowlist: ["tracked.txt"] }), /credential content/u);
  writeFileSync(join(fixture.root, "tracked.txt"), "safe\n"); mkdirSync(join(fixture.root, "dist")); writeFileSync(join(fixture.root, "dist", "generated.js"), "dirty");
  await fixture.git.git(["add", "-f", "dist/generated.js"]); await assert.rejects(captureHourlyWipV1({ ...common, allowlist: ["tracked.txt"] }), /excluded/u);
  await fixture.git.git(["reset", "HEAD", "--", "dist/generated.js"]); rmSync(join(fixture.root, "dist"), { recursive: true }); writeFileSync(join(fixture.root, "outside.txt"), "work");
  await assert.rejects(captureHourlyWipV1({ ...common, allowlist: ["tracked.txt"] }), /outside the explicit allowlist/u);
});

test("SG-01-T004 capture handles literal non-ASCII paths and refuses a vanished non-delete", async () => {
  const fixture = await committedFixture(); const work = attempt(fixture.base); writeFileSync(join(fixture.root, "café.txt"), "staged\n"); await fixture.git.git(["add", "--", "café.txt"]); writeFileSync(join(fixture.root, "café.txt"), "worktree\n");
  const snapshot = await captureHourlyWipV1({ ...wipRequest(fixture, work), attempt: work, allowlist: ["café.txt"] }); assert.ok(snapshot); assert.equal(snapshot.files[0]?.path, "café.txt"); assert.equal(Buffer.from(snapshot.files[0]!.index!.content_base64, "base64").toString(), "staged\n");
  await fixture.git.git(["reset", "--hard", "HEAD"]); symlinkSync("absent-target", join(fixture.root, "dangling.txt"));
  await assert.rejects(captureHourlyWipV1({ ...wipRequest(fixture, work), attempt: work, allowlist: ["dangling.txt"] }), /vanished/u);
});

test("SG-01-T004 ignored credential carriers are counted without publishing their names", async () => {
  const fixture = await committedFixture(); const work = attempt(fixture.base); writeFileSync(join(fixture.root, ".git", "info", "exclude"), ".env.production\n"); writeFileSync(join(fixture.root, ".env.production"), "not-a-real-secret\n"); writeFileSync(join(fixture.root, "tracked.txt"), "dirty\n");
  const snapshot = await captureHourlyWipV1({ ...wipRequest(fixture, work), attempt: work }); assert.ok(snapshot); assert.equal(JSON.stringify(snapshot).includes(".env.production"), false); assert.deepEqual(snapshot.excluded_ignored, [{ class: "credential-path-redacted", count: 1 }]);
});

test("SG-01-T004 real local Git publication reads back and restores the exact dirty index/worktree", async () => {
  const fixture = await committedFixture();
  writeFileSync(join(fixture.root, "tracked.txt"), "staged\n"); await fixture.git.git(["add", "tracked.txt"]); writeFileSync(join(fixture.root, "tracked.txt"), "worktree\n"); writeFileSync(join(fixture.root, "new.txt"), "new\n", { mode: 0o755 }); rmSync(join(fixture.root, "deleted.txt"));
  const remoteRoot = mkdtempSync(join(tmpdir(), "keep-hourly-wip-remote-")); const remoteGit = new GitAdapter(remoteRoot); await remoteGit.git(["init", "--bare"]);
  const remoteUrl = `file://${remoteRoot}`; await fixture.git.git(["remote", "add", "origin", remoteUrl]); await fixture.git.git(["push", "origin", "HEAD:refs/heads/main"]);
  const work = attempt(fixture.base); const snapshot = await captureHourlyWipV1({ project_root: fixture.root, git: fixture.git, attempt: work, base_commit: fixture.base, recovery_ref: `refs/heads/keep-wip/n1/${work.identity_digest}`, hour_bucket_utc: 43, allowlist: ["deleted.txt", "tracked.txt", "new.txt"], last_result: "focused pending", next_action: "continue" });
  assert.ok(snapshot);
  const workspace = mkdtempSync(join(tmpdir(), "keep-hourly-wip-publication-"));
  const port = new GitWipPublicationPortV1({ workspace_root: workspace, remote: "recovery", fetch_url: remoteUrl, push_url: remoteUrl, fetch_url_sha256: pinnedRemoteFetchUrlSha256(remoteUrl), push_url_sha256: pinnedRemoteUrlSha256(remoteUrl), git_factory: (root) => new GitAdapter(root) });
  mkdirSync(join(workspace, snapshot.job_id), { mode: 0o700 }); writeFileSync(join(workspace, snapshot.job_id, "interrupted"), "partial");
  const prepared = await port.prepare(snapshot); await port.publish(prepared); const readback = await port.readBack(prepared);
  assert.equal(readback.snapshot.manifest_sha256, snapshot.manifest_sha256); assert.equal(readback.commit_oid, prepared.commit_oid);
  await port.release(prepared); assert.deepEqual(readdirSync(workspace), []);
  const recovered = await port.recover(snapshot.recovery_ref, { attempt: snapshot.attempt });
  const target = join(mkdtempSync(join(tmpdir(), "keep-hourly-wip-restore-parent-")), "restored"); await port.materialize(recovered, target, { attempt: snapshot.attempt });
  assert.equal(readFileSync(join(target, "tracked.txt"), "utf8"), "worktree\n"); assert.equal(readFileSync(join(target, "new.txt"), "utf8"), "new\n");
  assert.equal(existsSync(join(target, "deleted.txt")), false); assert.equal(statSync(join(target, "new.txt")).mode & 0o777, 0o755);
  assert.equal((await new GitAdapter(target).git(["show", ":tracked.txt"])).stdout, "staged\n");
  assert.equal((await new GitAdapter(target).git(["status", "--porcelain=v1", "--untracked-files=all", "--no-renames"])).stdout, (await fixture.git.git(["status", "--porcelain=v1", "--untracked-files=all", "--no-renames"])).stdout);
  const wrongRef = { ...prepared, recovery_ref: "refs/heads/work/canonical-consolidation-2026-08-27" };
  await assert.rejects(port.publish(wrongRef), /invalid/u); await assert.rejects(port.readBack(wrongRef), /invalid/u);
  assert.equal((await remoteGit.git(["rev-parse", "refs/heads/main"])).stdout.trim(), fixture.base);
  const tampered = structuredClone(recovered.snapshot) as unknown as Record<string, any>; if (tampered.attempt.authority.kind === "n1") tampered.attempt.authority = { ...tampered.attempt.authority, owner_id: "substitute" };
  const { manifest_sha256: _old, ...tamperedBody } = tampered; tampered.manifest_sha256 = objectDigest(tamperedBody);
  await assert.rejects(port.materialize({ ...recovered, snapshot: tampered as unknown as HourlyWipSnapshotV1 }, join(dirname(target), "substituted"), { attempt: snapshot.attempt }), /exact expected attempt/u);
});

test("SG-01-T004 supervisor coalesces each track's same-hour trigger without substituting custody", async () => {
  for (const track of ["n1", "enterprise"] as const) {
    const fixture = await committedFixture(); writeFileSync(join(fixture.root, "tracked.txt"), `${track} dirty\n`);
    const work = attempt(fixture.base, track); const port = new FakePublicationPort(); const state = mkdtempSync(join(tmpdir(), `keep-wip-${track}-state-`)); const supervisor = new HourlyWipSupervisorV1(state, port);
    const first = await supervisor.tick(fence(work), wipRequest(fixture, work)); const second = await supervisor.tick(fence(work), wipRequest(fixture, work));
    assert.equal(first.status, "REMOTE_VERIFIED"); assert.equal(second.status, "COALESCED"); assert.equal(port.publish_count, 1); assert.equal(port.prepare_count, 1);
    assert.equal(port.last_snapshot?.attempt.track, track); assert.deepEqual(port.last_snapshot?.attempt.authority, work.identity.authority);
    const durable = JSON.parse(readFileSync(join(state, readdirSync(state).find((name) => name.endsWith(".json"))!), "utf8")); assert.equal(durable.snapshot, null); assert.equal(durable.prepared, null); assert.ok(readFileSync(join(state, readdirSync(state).find((name) => name.endsWith(".json"))!)).length < 1024);
  }
});

test("SG-01-T004 supervisor reconciles ambiguous accepted publish before retrying the mutation", async () => {
  const fixture = await committedFixture(); writeFileSync(join(fixture.root, "tracked.txt"), "dirty\n"); const work = attempt(fixture.base);
  const port = new FakePublicationPort(); port.throw_after_publish = true; const state = mkdtempSync(join(tmpdir(), "keep-wip-ambiguous-state-")); const supervisor = new HourlyWipSupervisorV1(state, port);
  const first = await supervisor.tick(fence(work), wipRequest(fixture, work)); const carrier = join(state, readdirSync(state).find((name) => name.endsWith(".json"))!); const crashed = JSON.parse(readFileSync(carrier, "utf8")); crashed.status = "PREPARED"; writeFileSync(carrier, JSON.stringify(crashed)); const second = await supervisor.tick(fence(work), wipRequest(fixture, work));
  assert.equal(first.status, "FAILED_VISIBLE"); assert.equal(second.status, "REMOTE_VERIFIED"); assert.equal(port.publish_count, 1); assert.equal(port.prepare_count, 1); assert.equal(port.readback_count, 2);
});

test("SG-01-T004 supervisor retains the first capture failure and retries the same job", async () => {
  const fixture = await committedFixture(); writeFileSync(join(fixture.root, "tracked.txt"), "ghp_abcdefghijklmnopqrstuvwxyz123456\n"); const work = attempt(fixture.base);
  const port = new FakePublicationPort(); const supervisor = new HourlyWipSupervisorV1(mkdtempSync(join(tmpdir(), "keep-wip-failure-state-")), port);
  const first = await supervisor.tick(fence(work), wipRequest(fixture, work)); assert.equal(first.status, "FAILED_VISIBLE"); assert.match(first.first_failure, /credential content/u); assert.equal(port.publish_count, 0);
  writeFileSync(join(fixture.root, "tracked.txt"), "safe dirty\n"); const second = await supervisor.tick(fence(work), wipRequest(fixture, work));
  assert.equal(second.status, "REMOTE_VERIFIED"); assert.equal(port.publish_count, 1); assert.equal(port.last_snapshot?.first_known_failure, first.first_failure);
});

test("SG-01-T004 supervisor retries interrupted preparation under the stable job identity", async () => {
  const fixture = await committedFixture(); writeFileSync(join(fixture.root, "tracked.txt"), "dirty\n"); const work = attempt(fixture.base);
  const port = new FakePublicationPort(); port.fail_prepare_once = true; const supervisor = new HourlyWipSupervisorV1(mkdtempSync(join(tmpdir(), "keep-wip-prepare-state-")), port);
  const first = await supervisor.tick(fence(work), wipRequest(fixture, work)); const second = await supervisor.tick(fence(work), wipRequest(fixture, work));
  assert.equal(first.status, "FAILED_VISIBLE"); assert.equal(second.status, "REMOTE_VERIFIED"); assert.equal(port.prepare_count, 2); assert.equal(port.publish_count, 1); assert.equal(port.last_snapshot?.first_known_failure, first.first_failure);
});

test("SG-01-T004 stale attempt and corrupt durable state fail closed before publication", async () => {
  const fixture = await committedFixture(); writeFileSync(join(fixture.root, "tracked.txt"), "dirty\n"); const work = attempt(fixture.base);
  const stalePort = new FakePublicationPort(); const staleSupervisor = new HourlyWipSupervisorV1(mkdtempSync(join(tmpdir(), "keep-wip-stale-state-")), stalePort);
  const stale = await staleSupervisor.tick(fence(work, false), wipRequest(fixture, work)); assert.equal(stale.status, "FAILED_VISIBLE"); assert.equal(stalePort.publish_count, 0); assert.equal(stalePort.prepare_count, 0);
  const state = mkdtempSync(join(tmpdir(), "keep-wip-corrupt-state-")); const port = new FakePublicationPort(); const supervisor = new HourlyWipSupervisorV1(state, port);
  assert.equal((await supervisor.tick(fence(work), wipRequest(fixture, work, 45))).status, "REMOTE_VERIFIED"); const job = readdirSync(state).find((name) => name.endsWith(".json")); assert.ok(job); writeFileSync(join(state, job), "{\"schema_version\":1}\n");
  const corrupt = await supervisor.tick(fence(work), wipRequest(fixture, work, 45)); assert.equal(corrupt.status, "FAILED_VISIBLE"); assert.equal(corrupt.first_failure, "WIP durable job state is invalid"); assert.equal(port.publish_count, 1);
});

test("SG-01-T004 real takeover fences capture credit before any publication", async () => {
  const fixture = await committedFixture(); writeFileSync(join(fixture.root, "tracked.txt"), "dirty\n"); const template = attempt(fixture.base); const authority = new FileWorkAttemptAuthorityV1(mkdtempSync(join(tmpdir(), "keep-wip-real-fence-")));
  const admitted = await authority.admit(template.identity); const reference = { identity_digest: admitted.identity_digest, attempt_id: admitted.attempt_id, generation: admitted.generation }; const oldFence = authority.fence(reference); await authority.takeover(reference);
  const port = new FakePublicationPort(); const result = await new HourlyWipSupervisorV1(mkdtempSync(join(tmpdir(), "keep-wip-fenced-state-")), port).tick(oldFence, wipRequest(fixture, admitted));
  assert.equal(result.status, "FAILED_VISIBLE"); assert.equal(port.prepare_count, 0); assert.equal(port.publish_count, 0);
});

test("SG-01-T004 composed YOLO trigger derives hour/base, coalesces, and does not forge lifecycle completion", async () => {
  const fixture = await committedFixture(); const template = attempt(fixture.base); const authority = new FileWorkAttemptAuthorityV1(mkdtempSync(join(tmpdir(), "keep-wip-composed-attempt-"))); const admitted = await authority.admit(template.identity); const reference = { identity_digest: admitted.identity_digest, attempt_id: admitted.attempt_id, generation: admitted.generation };
  const port = new FakePublicationPort(); const supervisor = new HourlyWipSupervisorV1(mkdtempSync(join(tmpdir(), "keep-wip-composed-state-")), port); let actions = 0;
  const coordinator_input = { attempt_authority: authority, attempt: reference, configured_posture: "autonomous" as const, research_progress: researchProgress("n1"), boundary_facts: { requested_scope_ids: ["K-002"], protected_workload_effects: [], requested_effects: [{ description: "bounded local edit", class: "pure-local" as const }], requested_vet_round: 0 as const, resources: { estimated_ram_mib: 64, estimated_disk_mib: 10, estimated_processes: 1 } }, action: async () => { actions += 1; writeFileSync(join(fixture.root, "tracked.txt"), `dirty ${actions}\n`); return { outcome: "ADVANCE" as const, evidence_digest: "e".repeat(64) }; } };
  const common = { coordinator: new YoloTicketCoordinatorV1(), coordinator_input, supervisor, wip_request: { project_root: fixture.root, git: fixture.git, allowlist: ["tracked.txt"], last_result: "step complete", next_action: "continue" }, now_ms: 51 * 3_600_000 };
  const first = await runYoloTicketStepWithHourlyWipV1(common); const second = await runYoloTicketStepWithHourlyWipV1(common);
  assert.equal(first.step.attempt.transitions.length, 1); assert.equal(second.step.attempt.transitions.length, 2); assert.equal(first.wip?.status, "REMOTE_VERIFIED"); assert.equal(second.wip?.status, "COALESCED"); assert.equal(port.publish_count, 1); assert.equal(first.combined_effects_performed, true); assert.equal(second.combined_effects_performed, false);
  assert.equal(first.step.status.completion.basis_points, 6666); assert.equal(second.step.status.completion.basis_points, 6666); assert.equal(first.step.status.effects_performed, false); assert.equal(authority.load(reference).transitions.length, 2);
});
