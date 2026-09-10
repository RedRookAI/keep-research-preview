import { test } from "node:test";
import assert from "node:assert/strict";
import { OutcomeAdaptation, OutcomeAdaptiveProvider, type AdaptiveBehavior, type OutcomeAdaptationPersistence } from "../src/learning/outcome_adaptation.js";
import type { ModelProvider } from "../src/gateway/gateway.js";
import { composeKeep, handleGatewayRequest } from "../src/index.js";
import type { Principal } from "../src/identity/rbac.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

const behavior = (version: string): AdaptiveBehavior => ({ prompt: { version, text: `synthetic ${version}` },
  routing: { model: "synthetic", effort: "none" }, voice: { promptFormat: "terse", verbosity: "normal" } });
const policy = { minSamplesPerArm: 4, minQualityGain: 0.1, maxRegressionRate: 0.25, rollbackQualityDrop: 0.15 };

for (const enterprise of [false, true]) test(`KEEP-07B-001 gateway window fencing and reconstructed state (${enterprise ? "delegated tenant observer" : "personal"})`, async () => {
  const owner: Principal = { id: "alice", tenant: "alpha", kind: "human", role: "owner" };
  const configuration = {
    dataDir: mkdtempSync(join(tmpdir(), "keep-adaptation-audit-")),
    outcomeAdaptation: { initial: behavior("base"), policy },
    delegationParentFor: (id: string, tenant?: string) => id === owner.id && tenant === owner.tenant ? owner : undefined,
  };
  let app = composeKeep(configuration);
  const project = app.projectManager!.create({ name: "synthetic monitoring", ...(enterprise ? { tenant: "alpha" } : {}) });
  const token = "synthetic-local-test-token";
  const ownerSecurity = { token, ...(enterprise ? { principalFor: () => owner } : {}) };
  const observer = enterprise ? await app.authorization.issue(owner, "observer", ["adaptation.observe"], Date.now() + 60_000) : undefined;
  const security = { token, ...(observer ? { principalFor: () => observer } : {}) };
  const call = (method: string, path: string, body: Record<string, unknown> = {}, auth: Parameters<typeof handleGatewayRequest>[2] = security, target = project.id) =>
    handleGatewayRequest(app, { method, path: `/project/adaptation${path}`, query: { projectId: target },
      headers: { authorization: `Bearer ${token}` }, body: JSON.stringify({ projectId: target, ...body }) }, auth);
  const initialStatus = await call("GET", "", {}, ownerSecurity);
  assert.equal(initialStatus.status, 200, initialStatus.body);
  assert.equal(JSON.parse(initialStatus.body).documentRevision, null, "absent document has no numeric revision");
  assert.equal((await call("POST", "/propose", { candidate: behavior("candidate") }, ownerSecurity)).status, 200);
  const proposedStatus = await call("GET", "", {}, ownerSecurity);
  assert.equal(proposedStatus.status, 200, proposedStatus.body);
  assert.equal(JSON.parse(proposedStatus.body).documentRevision, 1);
  for (let i = 0; i < 8; i++) {
    const response = await call("POST", "/assign", { subjectId: `subject-${i}` });
    assert.equal(response.status, 200, response.body);
    const { assignment } = JSON.parse(response.body) as { assignment: { assignmentId: string; assignedAt: number; arm: string } };
    assert.equal((await call("POST", "/present", { assignmentId: assignment.assignmentId, content: "synthetic actual presentation" })).status, 200);
    const outcome = await call("POST", "/outcome", { assignmentId: assignment.assignmentId, outcomeId: `trial-${i}`,
      observedAt: Math.max(Date.now(), assignment.assignedAt), quality: assignment.arm === "baseline" ? 0 : 1, regressed: false });
    assert.equal(outcome.status, 200, outcome.body);
  }
  const monitoring = async () => {
    const response = await call("GET", "/monitoring"); assert.equal(response.status, 200, response.body);
    return (JSON.parse(response.body) as { monitoring: { windowId: string; behaviorVersion: string } | null }).monitoring;
  };
  const windowId = (await monitoring())!.windowId;
  if (enterprise) {
    assert.equal((await call("GET", "")).status, 403, "observe-only grant does not acquire full adaptation read permission");
    const foreign = app.projectManager!.create({ name: "foreign", tenant: "beta" });
    assert.equal((await call("GET", "/monitoring", {}, security, foreign.id)).status, 404);
    assert.equal((await call("POST", "/live-outcome", { windowId, outcomeId: "human-forgery", observedAt: Date.now(), quality: 1, regressed: false }, ownerSecurity)).status, 403);
  }
  const reports = Array.from({ length: 4 }, (_, i) => ({ windowId, outcomeId: `healthy-${i}`, observedAt: Date.now(), quality: 1, regressed: false }));
  const { windowId: _omitted, ...missing } = reports[0]!;
  assert.equal((await call("POST", "/live-outcome", missing)).status, 400);
  for (const report of reports) assert.equal((await call("POST", "/live-outcome", report)).status, 200);
  const nextWindow = (await monitoring())!.windowId; assert.notEqual(nextWindow, windowId);
  // A new Node process reconstructs actual composed encrypted project state. The
  // enterprise principal is supplied through the same explicit trusted test port;
  // this is not an external identity-provider or real-model qualification.
  const child = execFileSync(process.execPath, ["--input-type=module", "-e", `
    import assert from 'node:assert/strict';
    const { composeKeep, handleGatewayRequest } = await import(process.argv[1]);
    const input = JSON.parse(process.argv[2]);
    const app = composeKeep({ ...input.configuration, delegationParentFor: (id, tenant) =>
      id === input.owner.id && tenant === input.owner.tenant ? input.owner : undefined });
    const security = { token: input.token, ...(input.observer ? { principalFor: () => input.observer } : {}) };
    const call = (method, suffix, body = {}) => handleGatewayRequest(app, { method,
      path: '/project/adaptation' + suffix, query: { projectId: input.projectId },
      headers: { authorization: 'Bearer ' + input.token }, body: JSON.stringify({ projectId: input.projectId, ...body }) }, security);
    for (const report of input.reports) assert.notEqual((await call('POST', '/live-outcome', report)).status, 200);
    const state = await call('GET', '/monitoring'); assert.equal(state.status, 200, state.body);
    assert.equal(JSON.parse(state.body).monitoring.windowId, input.nextWindow);
    process.stdout.write(JSON.stringify({ pid: process.pid, windowId: input.nextWindow, refused: input.reports.length }));
  `, new URL("../src/index.js", import.meta.url).href, JSON.stringify({ configuration, owner, observer,
    token, projectId: project.id, reports, nextWindow })], { encoding: "utf8", timeout: 15_000, maxBuffer: 128 * 1024 });
  const childResult = JSON.parse(child) as { pid: number; windowId: string; refused: number };
  assert.notEqual(childResult.pid, process.pid); assert.equal(childResult.refused, 4);
  assert.equal(childResult.windowId, nextWindow);
  for (const reconstructed of [false, true]) {
    if (reconstructed) app = composeKeep(configuration);
    assert.equal((await monitoring())!.windowId, nextWindow);
    for (const report of reports) assert.notEqual((await call("POST", "/live-outcome", report)).status, 200);
    assert.equal((await monitoring())!.windowId, nextWindow);
  }
  for (let i = 0; i < 4; i++) {
    const response = await call("POST", "/live-outcome", { windowId: nextWindow, outcomeId: `regression-${i}`, observedAt: Date.now(), quality: 0, regressed: true });
    assert.equal(response.status, 200, response.body);
    if (i === 3) assert.equal((JSON.parse(response.body) as { decision: { kind: string } }).decision.kind, "rolled-back");
  }
  app = composeKeep(configuration); assert.equal(await monitoring(), null);
});
test("adaptation distinguishes a later legacy-zero record from earlier absence", () => {
  let stored: { snapshot?: unknown; revision: number } | undefined;
  let saves = 0;
  const persistence: OutcomeAdaptationPersistence = {
    load: () => structuredClone(stored),
    save(snapshot, expected) {
      assert.equal(expected, stored?.revision);
      stored = { snapshot: structuredClone(snapshot), revision: (expected ?? 0) + 1 };
      saves++; return stored.revision;
    },
  };
  const stale = new OutcomeAdaptation(behavior("base"), policy, { persistence });
  stored = { revision: 0 };
  assert.throws(() => stale.propose(behavior("candidate")), /document conflict/u);
  assert.equal(saves, 0);
  const current = new OutcomeAdaptation(behavior("base"), policy, { persistence });
  current.propose(behavior("candidate"));
  assert.equal(stored.revision, 1); assert.equal(saves, 1);
});

function fixture() {
  let stored: { snapshot: unknown; revision: number } | undefined;
  let now = 1000, serial = 0, fail = false;
  const persistence: OutcomeAdaptationPersistence = {
    load: () => structuredClone(stored),
    save(snapshot, expected) {
      assert.equal(expected, stored?.revision);
      if (fail) throw new Error("synthetic precommit persistence failure");
      stored = { snapshot: structuredClone(snapshot), revision: (expected ?? 0) + 1 }; return stored.revision;
    },
  };
  const construct = (configuredPolicy = policy) => new OutcomeAdaptation(behavior("base"), configuredPolicy, {
    persistence, clock: () => now, id: () => `id-${++serial}`, random: () => 0.25 });
  return { construct, tick: () => ++now, get now() { return now; }, set fail(value: boolean) { fail = value; },
    replaceSnapshot(snapshot: unknown) { assert.ok(stored); stored = { revision: stored.revision, snapshot: structuredClone(snapshot) }; },
    snapshot: () => structuredClone(stored) };
}
function promote(a: OutcomeAdaptation, f: ReturnType<typeof fixture>) {
  a.propose(behavior("candidate"));
  for (let i = 0; i < 8; i++) {
    const assignment = a.assign(`subject-${i}`); a.expose(assignment.assignmentId);
    const decision = a.observe({ assignmentId: assignment.assignmentId, outcomeId: `trial-${i}`,
      observedAt: f.tick(), quality: assignment.arm === "baseline" ? 0 : 1, regressed: false, evidence: "observed-product" });
    if (i === 7) assert.equal(decision.kind, "promoted");
  }
}

for (const restart of [false, true]) test(`KEEP-07B-001 closed healthy window cannot recount exact reports (${restart ? "reconstructed component" : "live"})`, () => {
  const f = fixture(); let a = f.construct(); promote(a, f);
  const reports = Array.from({ length: 4 }, (_, i) => ({ windowId: a.monitoring()!.windowId, outcomeId: `healthy-${i}`, observedAt: f.tick(),
    quality: 1, regressed: false, evidence: "observed-product" as const }));
  for (const report of reports) a.observeLive(report);
  if (restart) a = f.construct();
  const before = f.snapshot();
  for (const report of reports) {
    assert.throws(() => a.observeLive(report), "an exact counted report must remain ineligible after window closure");
    assert.deepEqual(f.snapshot(), before, "replay must not mutate durable evidence");
  }
  for (let i = 0; i < 4; i++) {
    const result = a.observeLive({ windowId: a.monitoring()!.windowId, outcomeId: `new-regression-${i}`, observedAt: f.tick(), quality: 0,
      regressed: true, evidence: "observed-product" });
    if (i === 3) assert.equal(result.kind, "rolled-back");
  }
  assert.equal(f.construct().current().prompt.version, "base");
});

test("monitoring window permits distinct equal/out-of-order timestamps but refuses missing/wrong/duplicate identities", () => {
  const f = fixture(), a = f.construct(); promote(a, f);
  const windowId = a.monitoring()!.windowId;
  const report = { windowId, outcomeId: "equal-1", observedAt: 2000, quality: 1, regressed: false, evidence: "observed-product" as const };
  assert.throws(() => a.observeLive({ ...report, windowId: "wrong" }), /window/);
  const { windowId: _unused, ...missing } = report;
  assert.throws(() => a.observeLive(missing), /window/);
  a.observeLive(report);
  assert.throws(() => a.observeLive(report), /duplicate/);
  a.observeLive({ ...report, outcomeId: "equal-2" });
  a.observeLive({ ...report, outcomeId: "earlier", observedAt: 1999 });
  a.observeLive({ ...report, outcomeId: "equal-3" });
  assert.notEqual(a.monitoring()!.windowId, windowId);
  assert.equal(f.construct().monitoring()!.windowId, a.monitoring()!.windowId);
});

test("failed completion commit restores exact window and count; retry then rotates once", () => {
  const f = fixture(), a = f.construct(); promote(a, f); const windowId = a.monitoring()!.windowId;
  const report = (i: number) => ({ windowId, outcomeId: `healthy-${i}`, observedAt: 2000 + i,
    quality: 1, regressed: false, evidence: "observed-product" as const });
  for (let i = 0; i < 3; i++) a.observeLive(report(i));
  const before = f.snapshot(); f.fail = true;
  assert.throws(() => a.observeLive(report(3)), /precommit/);
  assert.deepEqual(f.snapshot(), before); assert.equal(a.monitoring()!.windowId, windowId);
  f.fail = false; a.observeLive(report(3)); assert.notEqual(a.monitoring()!.windowId, windowId);
  assert.throws(() => f.construct().observeLive(report(3)), /window/);
});

for (const version of [3, 4, 5]) test(`v${version} migration preserves legacy monitoring without counting it in a fresh window`, () => {
  const f = fixture(); const a = f.construct(); promote(a, f); const oldWindow = a.monitoring()!.windowId;
  for (let i = 0; i < 2; i++) a.observeLive({ windowId: oldWindow, outcomeId: `old-${i}`, observedAt: 2000,
    quality: 0, regressed: true, evidence: "observed-product" });
  const old = f.snapshot()!.snapshot as Record<string, unknown>;
  old["schema"] = `keep.outcome-adaptation/v${version}`; delete old["liveWindow"]; delete old["legacyMonitoring"];
  if (version < 5) delete old["initialDigest"];
  if (version < 4) delete old["experimentHistory"];
  f.replaceSnapshot(old);
  const migrated = f.construct(), windowId = migrated.monitoring()!.windowId;
  assert.notEqual(windowId, oldWindow);
  const snapshot = f.snapshot()!.snapshot as { schema: string; liveOutcomes: { count: number }; legacyMonitoring: { liveOutcomes: { count: number } } };
  assert.equal(snapshot.schema, "keep.outcome-adaptation/v6"); assert.equal(snapshot.liveOutcomes.count, 0);
  assert.equal(snapshot.legacyMonitoring.liveOutcomes.count, 2);
  assert.throws(() => migrated.observeLive({ windowId: oldWindow, outcomeId: "old-0", observedAt: 2000,
    quality: 0, regressed: true, evidence: "observed-product" }), /window/);
  for (let i = 0; i < 4; i++) {
    const result = migrated.observeLive({ windowId, outcomeId: `new-${i}`, observedAt: 2001,
      quality: 0, regressed: true, evidence: "observed-product" });
    assert.equal(result.kind, i === 3 ? "rolled-back" : "observing");
  }
  assert.equal(f.construct().monitoring(), undefined);
  assert.deepEqual((f.snapshot()!.snapshot as typeof snapshot).legacyMonitoring, snapshot.legacyMonitoring);
});

test("changed monitoring policy rotates the bound window and rejects old reports", () => {
  const f = fixture(), a = f.construct(); promote(a, f); const windowId = a.monitoring()!.windowId;
  const report = { windowId, outcomeId: "old-policy", observedAt: 2000, quality: 1, regressed: false, evidence: "observed-product" as const };
  a.observeLive(report);
  const next = f.construct({ ...policy, rollbackQualityDrop: 0.2 });
  assert.notEqual(next.monitoring()!.windowId, windowId); assert.throws(() => next.observeLive(report), /window/);
  assert.equal((f.snapshot()!.snapshot as { liveOutcomes: { count: number } }).liveOutcomes.count, 0);
});

test("equivalent reordered policy preserves active window and trial across restoration", () => {
  const f = fixture(), a = f.construct(); promote(a, f);
  const windowId = a.monitoring()!.windowId;
  a.propose(behavior("another-candidate"));
  const assignment = a.assign("retained-trial");
  const reordered = { rollbackQualityDrop: policy.rollbackQualityDrop, maxRegressionRate: policy.maxRegressionRate,
    minQualityGain: policy.minQualityGain, minSamplesPerArm: policy.minSamplesPerArm };
  const next = f.construct(reordered);
  assert.equal(next.monitoring()!.windowId, windowId);
  assert.equal(next.assignedBehavior(assignment.assignmentId).prompt.version, assignment.behaviorVersion);
  next.observeLive({ windowId, outcomeId: "new-order", observedAt: 2000, quality: 1, regressed: false, evidence: "observed-product" });
  assert.equal(f.construct().monitoring()!.windowId, windowId);
  assert.equal(f.construct().assignedBehavior(assignment.assignmentId).prompt.version, assignment.behaviorVersion);
});

test("first private v6 ordered policy digest is validated then normalized without a new window", () => {
  const f = fixture(), a = f.construct(); promote(a, f);
  const snapshot = f.snapshot()!.snapshot as { policy: object; liveWindow: { id: string; policyDigest: string } };
  snapshot.liveWindow.policyDigest = createHash("sha256").update(JSON.stringify(snapshot.policy)).digest("hex");
  const windowId = snapshot.liveWindow.id; f.replaceSnapshot(snapshot);
  const next = f.construct(); assert.equal(next.monitoring()!.windowId, windowId);
  next.observeLive({ windowId, outcomeId: "after-normalization", observedAt: 2000, quality: 1, regressed: false, evidence: "observed-product" });
  assert.equal(f.construct().monitoring()!.windowId, windowId);
});

test("failed legacy migration preserves old bytes and can be retried without adopting old counts", () => {
  const f = fixture(), a = f.construct(); promote(a, f);
  const old = f.snapshot()!.snapshot as Record<string, unknown>;
  old["schema"] = "keep.outcome-adaptation/v5"; delete old["liveWindow"]; delete old["legacyMonitoring"];
  f.replaceSnapshot(old); const before = f.snapshot(); f.fail = true;
  assert.throws(() => f.construct(), /precommit/); assert.deepEqual(f.snapshot(), before);
  f.fail = false; assert.ok(f.construct().monitoring());
  assert.equal(f.snapshot()!.revision, before!.revision + 1);
});

test("restoration refuses malformed window bindings and legacy evidence without rewriting them", () => {
  const f = fixture(), a = f.construct(); promote(a, f);
  const valid = f.snapshot()!.snapshot as Record<string, unknown>;
  for (const alteration of [
    { liveWindow: null },
    { liveWindow: { ...(valid["liveWindow"] as object), behaviorDigest: "0".repeat(64) } },
    { liveWindow: { ...(valid["liveWindow"] as object), policyDigest: "0".repeat(64) } },
    { legacyMonitoring: { sourceSchema: "keep.outcome-adaptation/v5", sampleLimit: 4,
      liveOutcomes: { count: 1, quality: 1, variance: 0, regressions: 0 }, liveEvidence: [] } },
  ]) {
    f.replaceSnapshot({ ...valid, ...alteration }); const before = f.snapshot();
    assert.throws(() => f.construct(), /monitoring|binding/); assert.deepEqual(f.snapshot(), before);
  }
});

for (const stream of [false, true]) test(`changed assignment during preparation prevents entry (${stream})`, async () => {
  const f = fixture(), a = f.construct(); const experimentId = a.propose(behavior("candidate"));
  const assignment = a.assign("changed-during-preparation"); let entries = 0;
  const entered = async () => { entries++; return { text: "unexpected", model: "synthetic", tokensIn: 1, tokensOut: 1 }; };
  const inner: ModelProvider = { name: "synthetic", isLocal: true, generate: entered, generateStream: entered, embed: async () => [] };
  const provider = new OutcomeAdaptiveProvider(inner, a, { current() {
    a.abandon(experimentId);
    return { effortKnob: "none", timeoutClass: "standard", asOf: "synthetic", freshness: "fresh" };
  } }, () => f.now);
  const request = { prompt: "task", hints: { adaptationAssignmentId: assignment.assignmentId } };
  await assert.rejects(stream ? provider.generateStream(request) : provider.generate(request), /assignment|experiment/);
  assert.equal(entries, 0);
});

for (const stream of [false, true]) test(`preparation and failed exposure save stay before provider entry; entered error retains uncertainty (${stream})`, async () => {
  const f = fixture(), a = f.construct(); a.propose(behavior("candidate")); const assignment = a.assign("dispatch");
  let entries = 0, failInside = false;
  const entered = async (request: import("../src/gateway/gateway.js").GenerateRequest) => {
    entries++; assert.match(request.prompt, /^synthetic base\n\ntask/);
    if (failInside) throw new Error("synthetic entered provider failure");
    return { text: "useful", model: "synthetic", tokensIn: 1, tokensOut: 1 };
  };
  const inner: ModelProvider = { name: "synthetic", isLocal: true, generate: entered, generateStream: entered, embed: async () => [] };
  const capabilities = { current: () => ({ effortKnob: "none" as const, timeoutClass: "standard" as const, asOf: "synthetic", freshness: "fresh" as const }) };
  const provider = new OutcomeAdaptiveProvider(inner, a, capabilities, () => f.now);
  const request = { prompt: "task", hints: { adaptationAssignmentId: assignment.assignmentId } };
  const run = (input = request) => stream ? provider.generateStream(input) : provider.generate(input);
  const before = f.snapshot(); f.fail = true;
  await assert.rejects(run(), /precommit/); assert.equal(entries, 0); assert.deepEqual(f.snapshot(), before);
  f.fail = false;
  const cancelled = new AbortController(); cancelled.abort();
  await assert.rejects(run({ ...request, ...{ signal: cancelled.signal } })); assert.equal(entries, 0); assert.deepEqual(f.snapshot(), before);
  const badRequest = { ...request }; Object.defineProperty(badRequest, "prompt", { get() { throw new Error("synthetic request preparation failure"); } });
  await assert.rejects(run(badRequest), /request preparation/); assert.equal(entries, 0); assert.deepEqual(f.snapshot(), before);
  assert.equal((await run()).text, "useful"); assert.equal(entries, 1);
  const exposed = f.snapshot(); failInside = true;
  await assert.rejects(run(), /entered provider failure/); assert.equal(entries, 2); assert.deepEqual(f.snapshot(), exposed);
  // Trusted observer supplies the outcome; entry/error alone is not a success claim.
  assert.equal(f.construct().observe({ assignmentId: assignment.assignmentId, outcomeId: "observed-after-entry",
    observedAt: f.tick(), evidence: "observed-product", quality: 0, regressed: true }).kind, "observing");
});

for (const stream of [false, true]) test(`KEEP-07B-002 capability preparation failure cannot authorize attribution (${stream ? "stream" : "ordinary"})`, async () => {
  const f = fixture(), a = f.construct(); a.propose(behavior("candidate"));
  const assignment = a.assign("preparation-fails"); let entries = 0;
  const entered = async () => { entries++; return { text: "synthetic", model: "synthetic", tokensIn: 1, tokensOut: 1 }; };
  const inner: ModelProvider = { name: "synthetic", isLocal: true, generate: entered, generateStream: entered, embed: async () => [] };
  const provider = new OutcomeAdaptiveProvider(inner, a, { current() { throw new Error("synthetic capability preparation failure"); } }, () => f.now);
  const request = { prompt: "task", hints: { adaptationAssignmentId: assignment.assignmentId } };
  await assert.rejects(stream ? provider.generateStream(request) : provider.generate(request), /capability preparation/);
  assert.equal(entries, 0);
  const before = f.snapshot();
  assert.throws(() => f.construct().observe({ assignmentId: assignment.assignmentId, outcomeId: "false-exposure",
    observedAt: f.tick(), evidence: "observed-product", quality: 1, regressed: false }), /expos|deliver|dispatch/);
  assert.deepEqual(f.snapshot(), before);
});
