import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  InvalidTicketClosureError, TicketClosureEffectOutcomeUnresolvedError,
  TicketClosureEvidenceMismatchError, TicketClosureFailedError, TicketClosureSupervisorV1,
  TicketClosureRetryableError,
  type TicketClosureObservationV1, type TicketClosurePortV1, type TicketClosureRequestV1,
  type TicketClosureStepResultV1, type TicketClosureSubjectV1,
} from "../src/backup/ticket_closure_supervisor_v1.js";
import {
  FileWorkAttemptAuthorityV1, StaleWorkAttemptError, type WorkAttemptFenceV1,
  type WorkAttemptIdentityV1,
} from "../src/spine/work_attempt_authority_v1.js";

const hex = (value: string): string => createHash("sha256").update(value).digest("hex");
function canonical(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const row = value as Record<string, unknown>;
  return `{${Object.keys(row).sort().map((key) => `${JSON.stringify(key)}:${canonical(row[key])}`).join(",")}}`;
}
const digest = (value: unknown): string => createHash("sha256").update(canonical(value)).digest("hex");

const ticketBody = {
  id: "SG-01-T005",
  title: "Close exact recovered ticket",
  requirements: ["close exact bytes"],
  finish_conditions: ["both tracks and remote readback pass"],
  research_contract: { outputs: ["tri-research"] },
  mutation_surface: ["src/backup/ticket_closure_supervisor_v1.ts"],
};

function authority(track: "n1" | "enterprise") {
  return track === "n1"
    ? { kind: "n1" as const, owner_id: "owner", custody_id: "owner-custody", organization_services: "ABSENT" as const }
    : { kind: "enterprise" as const, organization_id: "org", tenant_id: "tenant", actor_id: "actor", role_id: "builder", separation_policy_id: "sod", custody_id: "org-custody", isolation_id: "tenant-isolation", custody_evidence_digest: hex("custody"), isolation_evidence_digest: hex("isolation"), local_owner_substitution: false as const };
}

interface Fixture {
  root: string;
  subject: TicketClosureSubjectV1;
  supervisor: TicketClosureSupervisorV1;
  stores: { n1: FileWorkAttemptAuthorityV1; enterprise: FileWorkAttemptAuthorityV1 };
  fences: { n1: WorkAttemptFenceV1; enterprise: WorkAttemptFenceV1 };
}

async function fixture(): Promise<Fixture> {
  const root = mkdtempSync(join(tmpdir(), "keep-t005-"));
  const stores = { n1: new FileWorkAttemptAuthorityV1(join(root, "attempt-n1")), enterprise: new FileWorkAttemptAuthorityV1(join(root, "attempt-enterprise")) };
  const identities = Object.fromEntries((["n1", "enterprise"] as const).map((track) => {
    const identity: WorkAttemptIdentityV1 = { project_id: "keep", goal_id: "goal", subgoal_id: "SG-01", ticket_id: "SG-01-T005", ticket_body: ticketBody, ticket_body_digest: digest(ticketBody), failure_lessons: [{ id: "FL-009", digest: hex("lesson") }], track, authority: authority(track), product_commit: "a".repeat(40), interpreter_identity: "keep-test" };
    return [track, identity];
  })) as unknown as { n1: WorkAttemptIdentityV1; enterprise: WorkAttemptIdentityV1 };
  const snapshots = { n1: await stores.n1.admit(identities.n1), enterprise: await stores.enterprise.admit(identities.enterprise) };
  const fences = { n1: stores.n1.fence(snapshots.n1), enterprise: stores.enterprise.fence(snapshots.enterprise) };
  const subject: TicketClosureSubjectV1 = { project_id: "keep", goal_id: "goal", subgoal_id: "SG-01", ticket_id: "SG-01-T005", approved_ticket_body_json: JSON.stringify(ticketBody), approved_ticket_body_sha256: hex(JSON.stringify(ticketBody)), attempt_fence_ticket_body_digest: digest(ticketBody), product_commit: "a".repeat(40), closure_profile_sha256: hex("profile"), lockfile_sha256: hex("lock"), build_recipe_sha256: hex("recipe"), environment_identity_sha256: hex("environment"), retained_artifact_sha256: hex("tarball"), n1_authority_digest: digest(authority("n1")), enterprise_authority_digest: digest(authority("enterprise")), source_remote: "example/keep-fixture#candidate", artifact_remote: "example/keep-fixture#release", attempts: { n1: { identity_digest: snapshots.n1.identity_digest, attempt_id: snapshots.n1.attempt_id, generation: snapshots.n1.generation }, enterprise: { identity_digest: snapshots.enterprise.identity_digest, attempt_id: snapshots.enterprise.attempt_id, generation: snapshots.enterprise.generation } } };
  return { root, subject, supervisor: new TicketClosureSupervisorV1(join(root, "closure"), subject), stores, fences };
}

function result(index: number, subject: TicketClosureSubjectV1): TicketClosureStepResultV1 {
  const results = ["PASS", "REMOTE_SHA_MATCH", "PASS", "PASS", "PASS", "PASS", "PASS", "PASS", "REMOTE_IDENTITY_RECORDED", "REMOTE_IDENTITIES_MATCH", "DIGEST_ARCHIVE_REINSTALL_RESTART_BOUNDED_SMOKE_PASS", "COMPLETE"];
  const factsByIndex: readonly Record<string, unknown>[] = [
    { clean: true, source_commit: subject.product_commit },
    { authenticated: true, source_commit: subject.product_commit, source_remote: subject.source_remote },
    { focused_sha256: hex("focused"), portable_sha256: hex("portable"), full_native_sha256: hex("full") },
    { artifact_sha256: subject.retained_artifact_sha256 },
    { manifest_sha256: hex("manifest") },
    { archive_inspection_sha256: hex("inspection"), artifact_sha256: subject.retained_artifact_sha256 },
    { artifact_sha256: subject.retained_artifact_sha256, blank_install_sha256: hex("blank") },
    { artifact_sha256: subject.retained_artifact_sha256, installed_tracks_sha256: hex("tracks") },
    { artifact_remote: subject.artifact_remote, artifact_sha256: subject.retained_artifact_sha256, asset_id: "asset-1", authenticated: true, state: "uploaded" },
    { artifact_sha256: subject.retained_artifact_sha256, authenticated_readback_sha256: hex("readback"), source_commit: subject.product_commit },
    { artifact_sha256: subject.retained_artifact_sha256, retrieved_smoke_sha256: hex("smoke") },
    { conjunction_sha256: hex("conjunction") },
  ];
  const facts = factsByIndex[index]!;
  const tracks = [6, 7, 10].includes(index) ? { n1: { authority_digest: subject.n1_authority_digest, artifact_sha256: subject.retained_artifact_sha256, evidence_sha256: hex(`n1-${index}`), direct: true as const, result: "PASS" as const }, enterprise: { authority_digest: subject.enterprise_authority_digest, artifact_sha256: subject.retained_artifact_sha256, evidence_sha256: hex(`enterprise-${index}`), direct: true as const, result: "PASS" as const } } : undefined;
  return { result: results[index]!, facts, ...(tracks === undefined ? {} : { tracks }) };
}

class Port implements TicketClosurePortV1 {
  readonly executed: TicketClosureRequestV1[] = [];
  readonly observed: TicketClosureRequestV1[] = [];
  unknownAt: number | undefined;
  failAt: number | undefined;
  matches = new Set<number>([1]);
  constructor(readonly subject: TicketClosureSubjectV1) {}
  async observe(request: TicketClosureRequestV1): Promise<TicketClosureObservationV1> {
    this.observed.push(request);
    if (this.unknownAt === request.completion_index) return { status: "UNKNOWN", reason: "ambiguous transport" };
    if (this.matches.has(request.completion_index)) return { status: "MATCH", operation_id: request.operation_id, value: result(request.completion_index, this.subject) };
    return { status: "ABSENT" };
  }
  async execute(request: TicketClosureRequestV1): Promise<TicketClosureStepResultV1> {
    this.executed.push(request);
    if (this.failAt === request.completion_index) throw new TicketClosureRetryableError("classified transient");
    return result(request.completion_index, this.subject);
  }
}

async function advanceTo(f: Fixture, port: Port, count: number): Promise<void> {
  while (f.supervisor.status().completed_indices.length < count) await f.supervisor.advance(f.fences, port);
}

test("SG-01-T005-C01 stale superseded writer is refused at a closure boundary", async () => {
  const f = await fixture(), port = new Port(f.subject); const old = f.fences.n1;
  const next = await f.stores.n1.takeover(old.reference); f.fences.n1 = f.stores.n1.fence(next);
  await assert.rejects(f.supervisor.advance({ ...f.fences, n1: old }, port), StaleWorkAttemptError);
});

test("SG-01-T005-C02 exact shared candidate consumes 0..11 once and completes", async () => {
  const f = await fixture(), port = new Port(f.subject); await advanceTo(f, port, 12);
  assert.equal(f.supervisor.status().state, "COMPLETE"); assert.deepEqual(f.supervisor.status().completed_indices, [...Array(12).keys()]);
});

test("SG-01-T005-C03 enterprise proof cannot be filled by n1 evidence", async () => {
  const f = await fixture(), port = new Port(f.subject); await advanceTo(f, port, 6);
  const bad = result(6, f.subject); (bad.tracks as { enterprise: { authority_digest: string } }).enterprise.authority_digest = f.subject.n1_authority_digest;
  port.matches.add(6); port.observe = async (request) => ({ status: "MATCH", operation_id: request.operation_id, value: bad });
  await assert.rejects(f.supervisor.advance(f.fences, port), TicketClosureEvidenceMismatchError);
  const second = await fixture(), secondPort = new Port(second.subject); await advanceTo(second, secondPort, 6);
  const duplicate = result(6, second.subject); (duplicate.tracks!.enterprise as { evidence_sha256: string }).evidence_sha256 = duplicate.tracks!.n1.evidence_sha256;
  secondPort.observe = async (request) => ({ status: "MATCH", operation_id: request.operation_id, value: duplicate });
  await assert.rejects(second.supervisor.advance(second.fences, secondPort), TicketClosureEvidenceMismatchError);
});

test("SG-01-T005-C04 mixed source or authority subject refuses", async () => {
  const f = await fixture(), port = new Port(f.subject);
  assert.throws(() => new TicketClosureSupervisorV1(join(f.root, "bad"), { ...f.subject, enterprise_authority_digest: f.subject.n1_authority_digest }), InvalidTicketClosureError);
  const foreign = await fixture(); await assert.rejects(f.supervisor.advance({ n1: foreign.fences.n1, enterprise: f.fences.enterprise }, port), StaleWorkAttemptError);
  assert.throws(() => new TicketClosureSupervisorV1(join(f.root, "body-bytes"), { ...f.subject, approved_ticket_body_json: ` ${f.subject.approved_ticket_body_json}` }), InvalidTicketClosureError);
  assert.throws(() => new TicketClosureSupervisorV1(join(f.root, "body-sha"), { ...f.subject, approved_ticket_body_sha256: hex("other approved bytes") }), InvalidTicketClosureError);
  assert.throws(() => new TicketClosureSupervisorV1(join(f.root, "body-fence"), { ...f.subject, attempt_fence_ticket_body_digest: hex("other fence body") }), InvalidTicketClosureError);
});

test("SG-01-T005-C04/C09 every identity-bearing result refuses substitution", async () => {
  const mutations: ReadonlyArray<readonly [number, (value: TicketClosureStepResultV1) => void]> = [
    [0, (value) => { (value.facts as Record<string, unknown>).clean = false; }],
    [1, (value) => { (value.facts as Record<string, unknown>).source_commit = "b".repeat(40); }],
    [3, (value) => { (value.facts as Record<string, unknown>).artifact_sha256 = hex("other artifact"); }],
    [8, (value) => { (value.facts as Record<string, unknown>).authenticated = false; }],
    [9, (value) => { (value.facts as Record<string, unknown>).source_commit = "b".repeat(40); }],
    [11, (value) => { (value as { result: string }).result = "WIP"; }],
  ];
  for (const [index, mutate] of mutations) {
    const f = await fixture(), port = new Port(f.subject); await advanceTo(f, port, index);
    const bad = result(index, f.subject); mutate(bad); port.observe = async (request) => ({ status: "MATCH", operation_id: request.operation_id, value: bad });
    await assert.rejects(f.supervisor.advance(f.fences, port), TicketClosureEvidenceMismatchError);
  }
  const absent = await fixture(), port = new Port(absent.subject); await advanceTo(absent, port, 1); port.matches.delete(1);
  await assert.rejects(absent.supervisor.advance(absent.fences, port), TicketClosureEvidenceMismatchError);
});

test("SG-01-T005-C05 unchanged successful suite is credited once", async () => {
  const f = await fixture(), port = new Port(f.subject); await advanceTo(f, port, 3); await f.supervisor.advance(f.fences, port);
  assert.equal(port.executed.filter((request) => request.completion_index === 2).length, 1);
});

test("SG-01-T005-C06 retained archive step is in the durable chain", async () => {
  const f = await fixture(), port = new Port(f.subject); await advanceTo(f, port, 6);
  assert.equal(f.supervisor.load("n1").evidence[3]?.step_id, "ONE_RETAINED_TARBALL");
  assert.equal(f.supervisor.load("enterprise").subject.retained_artifact_sha256, f.subject.retained_artifact_sha256);
});

test("SG-01-T005-C07 retrieved bytes bind both direct track slots", async () => {
  const f = await fixture(), port = new Port(f.subject); await advanceTo(f, port, 11);
  const evidence = f.supervisor.load("n1").evidence[10]!; assert.equal(evidence.tracks?.n1.artifact_sha256, f.subject.retained_artifact_sha256); assert.equal(evidence.tracks?.enterprise.direct, true);
});

test("SG-01-T005-C08 known remote success is observed and never repeated", async () => {
  const f = await fixture(), port = new Port(f.subject); port.matches.add(8); await advanceTo(f, port, 9);
  assert.equal(port.executed.some((request) => request.completion_index === 8), false);
  const malformed = await fixture(), unsafe = new Port(malformed.subject);
  unsafe.observe = async () => ({ status: "MALFORMED" } as unknown as TicketClosureObservationV1);
  await assert.rejects(malformed.supervisor.advance(malformed.fences, unsafe), TicketClosureEvidenceMismatchError);
  assert.equal(unsafe.executed.length, 0);
});

test("SG-01-T005-C09 partial or missing-track evidence cannot close", async () => {
  const f = await fixture(), port = new Port(f.subject); await advanceTo(f, port, 11);
  assert.equal(f.supervisor.status().state, "IN_PROGRESS"); assert.equal(f.supervisor.status().completion_percentage, 91);
});

test("SG-01-T005-C10 unknown external outcome stops without mutation", async () => {
  const f = await fixture(), port = new Port(f.subject); await advanceTo(f, port, 8); port.unknownAt = 8;
  await assert.rejects(f.supervisor.advance(f.fences, port), TicketClosureEffectOutcomeUnresolvedError);
  assert.equal(f.supervisor.status().state, "EFFECT_OUTCOME_UNRESOLVED_OWNER_STOP"); assert.equal(port.executed.some((request) => request.completion_index === 8), false);
  port.unknownAt = undefined; await assert.rejects(f.supervisor.advance(f.fences, port), TicketClosureFailedError);
});

test("SG-01-T005-C11 n1 authority requires organization services absent", async () => {
  const f = await fixture(), port = new Port(f.subject); await f.supervisor.advance(f.fences, port);
  assert.equal(f.supervisor.load("n1").authority_digest, f.subject.n1_authority_digest); assert.notEqual(f.supervisor.load("n1").authority_digest, f.supervisor.load("enterprise").authority_digest);
});

test("SG-01-T005-C12 enterprise authority remains tenant-bound", async () => {
  const f = await fixture(), port = new Port(f.subject), store = new FileWorkAttemptAuthorityV1(join(f.root, "cross-tenant"));
  const identity = { ...f.fences.enterprise.identity, authority: { ...f.fences.enterprise.identity.authority, tenant_id: "other-tenant" } } as WorkAttemptIdentityV1;
  const admitted = await store.admit(identity); const crossTenant = store.fence(admitted);
  await assert.rejects(f.supervisor.advance({ n1: f.fences.n1, enterprise: crossTenant }, port), StaleWorkAttemptError);
});

test("SG-01-T005-C13 fresh supervisor resumes exact durable index", async () => {
  const f = await fixture(), port = new Port(f.subject); await advanceTo(f, port, 5);
  const restarted = new TicketClosureSupervisorV1(join(f.root, "closure"), f.subject); assert.equal(restarted.status().next_index, 5); await restarted.advance(f.fences, port); assert.equal(restarted.status().next_index, 6);
});

test("SG-01-T005-C13 interrupted dual-journal append converges once and larger divergence refuses", async () => {
  const f = await fixture(), port = new Port(f.subject); await advanceTo(f, port, 4);
  const enterprisePath = join(f.root, "closure", "enterprise.journal.json"), stale = readFileSync(enterprisePath);
  await f.supervisor.advance(f.fences, port); writeFileSync(enterprisePath, stale);
  assert.equal(f.supervisor.status().next_index, 4); await f.supervisor.advance(f.fences, port);
  assert.deepEqual(f.supervisor.load("n1").evidence, f.supervisor.load("enterprise").evidence);
  await f.supervisor.advance(f.fences, port); writeFileSync(enterprisePath, stale);
  await assert.rejects(f.supervisor.advance(f.fences, port), InvalidTicketClosureError);
});

test("SG-01-T005-C14 first failure survives restart and only failed index retries", async () => {
  const f = await fixture(), port = new Port(f.subject); await advanceTo(f, port, 2); port.failAt = 2;
  await assert.rejects(f.supervisor.advance(f.fences, port), /classified transient/);
  const restarted = new TicketClosureSupervisorV1(join(f.root, "closure"), f.subject); assert.equal(restarted.status().state, "FAILED"); port.failAt = undefined; await restarted.advance(f.fences, port);
  assert.match(restarted.status().first_failure?.reason ?? "", /classified transient/); assert.equal(restarted.status().next_index, 3);
  await restarted.advance(f.fences, port); assert.equal(restarted.status().next_index, 4); await advanceTo({ ...f, supervisor: restarted }, port, 12); assert.equal(restarted.status().state, "COMPLETE"); assert.match(restarted.status().first_failure?.reason ?? "", /classified transient/);
  const bounded = await fixture(), failing = new Port(bounded.subject); failing.failAt = 0;
  await assert.rejects(bounded.supervisor.advance(bounded.fences, failing), TicketClosureRetryableError);
  await assert.rejects(bounded.supervisor.advance(bounded.fences, failing), TicketClosureRetryableError);
  await assert.rejects(bounded.supervisor.advance(bounded.fences, failing), TicketClosureFailedError);
});

test("SG-01-T005-C15 takeover retains generation-independent operation identity", async () => {
  const f = await fixture(), port = new Port(f.subject); await advanceTo(f, port, 8); port.matches.add(8);
  const n1 = await f.stores.n1.takeover(f.fences.n1.reference), enterprise = await f.stores.enterprise.takeover(f.fences.enterprise.reference); f.fences = { n1: f.stores.n1.fence(n1), enterprise: f.stores.enterprise.fence(enterprise) };
  await f.supervisor.advance(f.fences, port); const actual = port.observed.at(-1)!.operation_id;
  const expected = createHash("sha256").update(f.subject.ticket_id).update("\0").update(digest(f.subject)).update("\0").update("8").digest("hex");
  assert.equal(actual, expected); assert.equal(port.executed.some((request) => request.completion_index === 8), false);
});

test("SG-01-T005-C16 unsafe closure carriers and directories refuse", async () => {
  const f = await fixture();
  const attempts = () => (["n1", "enterprise"] as const).map(track => readFileSync(join(f.root, `attempt-${track}`, "active-attempt.json"), "hex"));
  const before = attempts();
  const unsafe = join(f.root, "unsafe"); writeFileSync(unsafe, "not a directory"); assert.throws(() => new TicketClosureSupervisorV1(unsafe, f.subject));
  const open = join(f.root, "open"); new TicketClosureSupervisorV1(open, f.subject); chmodSync(open, 0o755); assert.throws(() => new TicketClosureSupervisorV1(open, f.subject), InvalidTicketClosureError);
  const target = join(f.root, "target"); new TicketClosureSupervisorV1(target, f.subject); const link = join(f.root, "link"); symlinkSync(target, link); assert.throws(() => new TicketClosureSupervisorV1(link, f.subject), InvalidTicketClosureError);
  assert.deepEqual(attempts(), before, "invalid closure storage must not mutate either track's admitted attempt");
});
