import test from "node:test";
import assert from "node:assert/strict";
import { BoundedNeedScheduler, recognizeNeeds, type NeedSignal } from "../src/autonomy/need_scheduler.js";
import { RbacAuthorizer, type Principal, type AuthorizationPort, type Permission } from "../src/identity/rbac.js";
import type { Spine } from "../src/spine/spine.js";

const fullyQualified: NeedSignal = {
  id: "signal-1", subject: "typescript-api", goal: "repair repeated API mistakes",
  currentKnowledgeMissing: true, projectEvidenceMissing: true, repeatedSuccessfulProcedure: true,
  measuredFailureCount: 4, evaluationCoverage: 0.25, gradientFreeTried: true,
  residualFailureRate: 0.3, verifiedExampleCount: 700, verifiableRewardAvailable: true,
  narrowStableTask: true,
};

test("recognition preserves all five need kinds while training remains explicit opt-in", () => {
  assert.deepEqual(recognizeNeeds(fullyQualified).map((p) => p.kind), ["research", "rag", "skill", "evaluation-data"]);
  assert.deepEqual(recognizeNeeds(fullyQualified, true).map((p) => p.kind), ["research", "rag", "skill", "evaluation-data", "training"]);
  assert.equal(recognizeNeeds(fullyQualified, true).at(-1)?.requiresOptIn, true);
});

test("training is refused without persistence, data, reward, and exhausted cheap remedies", () => {
  assert.equal(recognizeNeeds({ ...fullyQualified, gradientFreeTried: false }, true).some((p) => p.kind === "training"), false);
});

test("scheduler prioritizes cheap proposals and enforces total and per-scope-kind bounds", () => {
  const scheduler = new BoundedNeedScheduler({ maxPerCycle: 3, maxPerKind: 1, trainingProposalsEnabled: true });
  const out = scheduler.schedule([fullyQualified]);
  assert.deepEqual(out.scheduled.map((p) => p.kind), ["research", "rag", "skill"]);
  assert.ok(out.deferred.length > 0);
  const rejected = scheduler.schedule([{ ...fullyQualified, id: "bad", scopeId: "tenant-a" }]);
  assert.ok([...rejected.scheduled, ...rejected.deferred].every((proposal) => proposal.scopeId === undefined),
    "the n=1 surface cannot assert an enterprise scope");
});

test("scheduler coalesces duplicate subjects deterministically and cools down repeats", () => {
  const scheduler = new BoundedNeedScheduler({ maxPerCycle: 5, maxPerKind: 5, cooldownCycles: 1 });
  const duplicate = { ...fullyQualified, id: "z-signal" };
  const first = scheduler.schedule([duplicate, fullyQualified]);
  assert.equal(first.scheduled.length, 4);
  assert.ok(first.scheduled.every((p) => p.signalId === "signal-1"));
  assert.equal(scheduler.schedule([fullyQualified]).scheduled.length, 0);
  assert.equal(scheduler.schedule([fullyQualified]).scheduled.length, 0,
    "cooldown expiry cannot duplicate work that is already pending");
});

test("invalid, accessor, and hostile proxy signals deny-and-continue without proposals", () => {
  let getterRan = false;
  const accessor = Object.defineProperty({}, "id", { enumerable: true, get: () => { getterRan = true; return "bad"; } });
  const hostile = new Proxy({}, { ownKeys: () => { throw new Error("trap"); } });
  const scheduler = new BoundedNeedScheduler();
  assert.deepEqual(scheduler.schedule([accessor as NeedSignal, hostile as NeedSignal]), { scheduled: [], deferred: [], rejected: 2 });
  assert.equal(getterRan, false);
});

test("durable inbox is bounded and tenant acknowledgements cannot cross scopes", () => {
  const scheduler = new BoundedNeedScheduler({ maxPerCycle: 5, maxPerKind: 5, maxPending: 1 });
  const personal = scheduler.schedule([fullyQualified]).scheduled[0]!;
  const owner: Principal = { id: "owner-a", kind: "human", role: "owner", tenant: "tenant-a" };
  const tenantView = scheduler.forPrincipal(owner, new RbacAuthorizer())!;
  const tenant = tenantView.schedule([{ ...fullyQualified, id: "tenant", subject: "other" }]);
  assert.equal(tenant.scheduled.length, 1, "one full scope cannot block a different scope");
  assert.equal(tenantView.acknowledge(personal.id), false);
  assert.equal(scheduler.acknowledge(personal.id), true);
});

test("enterprise views bind scope to authority and keep the reserved personal tenant distinct", () => {
  const scheduler = new BoundedNeedScheduler({ maxPerCycle: 5, maxPerKind: 5 });
  const auth = new RbacAuthorizer();
  const owner: Principal = { id: "owner", kind: "human", role: "owner", tenant: "personal" };
  const view = scheduler.forPrincipal(owner, auth)!;
  view.schedule([fullyQualified]);
  scheduler.schedule([fullyQualified]);
  assert.equal(view.pending().length, 4);
  assert.equal(scheduler.pending().length, 4);
  assert.ok(view.pending().every((proposal) => proposal.scopeId === "personal"));
  assert.ok(scheduler.pending().every((proposal) => proposal.scopeId === undefined));
});

test("malformed unicode and insufficient authority deny without throwing or crossing scope", () => {
  const scheduler = new BoundedNeedScheduler();
  assert.doesNotThrow(() => scheduler.schedule([{ ...fullyQualified, subject: "bad\ud800" }]));
  assert.equal(scheduler.schedule([{ ...fullyQualified, subject: "bad\ud800" }]).scheduled.length, 0);
  const viewer: Principal = { id: "viewer", kind: "human", role: "viewer", tenant: "tenant-a" };
  assert.equal(scheduler.forPrincipal(viewer, new RbacAuthorizer()), undefined);
});

test("scope rotation prevents a busy n=1 queue from starving an enterprise tenant", () => {
  const scheduler = new BoundedNeedScheduler({ maxPerCycle: 1, maxPerKind: 5, maxPending: 10 });
  scheduler.schedule([fullyQualified]);
  const owner: Principal = { id: "owner-a", kind: "human", role: "owner", tenant: "tenant-a" };
  const view = scheduler.forPrincipal(owner, new RbacAuthorizer())!;
  const tenantCycle = view.schedule([{ ...fullyQualified, id: "tenant-signal", subject: "tenant-work" }]);
  assert.equal(tenantCycle.scheduled.length, 1);
  assert.equal(tenantCycle.scheduled[0]?.scopeId, "tenant-a");
});

test("durable transition is recorded before memory changes and is safe to retry after append failure", () => {
  let fail = true;
  const staged: unknown[] = [];
  const spine = {
    currentEvents: () => [],
    stage: (event: unknown) => { if (fail) { fail = false; throw new Error("interrupted append"); } staged.push(event); return "id"; },
  } as unknown as Spine;
  const scheduler = new BoundedNeedScheduler({ maxPerCycle: 5, maxPerKind: 5 }, spine);
  assert.throws(() => scheduler.schedule([fullyQualified]), /interrupted append/);
  assert.equal(scheduler.pending().length, 0, "failed persistence cannot expose an in-memory-only queue");
  assert.equal(scheduler.schedule([fullyQualified]).scheduled.length, 4);
  assert.equal(staged.length, 1);
});

test("deferred state is per-scope bounded and transition records carry deltas, not full backlog snapshots", () => {
  const staged: Array<{ payload?: Record<string, unknown> }> = [];
  const spine = { currentEvents: () => [], stage: (event: { payload?: Record<string, unknown> }) => { staged.push(event); return "id"; } } as unknown as Spine;
  const scheduler = new BoundedNeedScheduler({ maxPerCycle: 1, maxPerKind: 1, maxPending: 1, maxDeferred: 3 }, spine);
  for (let cycle = 0; cycle < 5; cycle++) {
    scheduler.schedule(Array.from({ length: 50 }, (_, i) => ({ ...fullyQualified, id: `${cycle}-${i}`, subject: `subject-${cycle}-${i}` })));
    assert.ok(scheduler.deferred().length <= 3);
  }
  assert.ok(staged.every((event) => event.payload?.["deferred"] === undefined));
  assert.ok(staged.every((event) => JSON.stringify(event).length < 20_000));
  assert.ok(staged.some((event) => (event.payload?.["eviction"] as { count?: number } | undefined)?.count));
});

test("enterprise schedule and outcome bindings re-check revocable authority on every use", () => {
  let allowed = true;
  const authorization: AuthorizationPort = { authorize: (_principal: Principal, action: Permission) => ({
    allow: action === "change.solve" ? allowed : true, reason: allowed ? "allowed" : "revoked",
  }) };
  const scheduler = new BoundedNeedScheduler({ maxPerCycle: 5, maxPerKind: 5 });
  const principal: Principal = { id: "agent-a", kind: "agent", role: "agent", tenant: "tenant-a" };
  const view = scheduler.forPrincipal(principal, authorization)!;
  allowed = false;
  assert.equal(view.schedule([fullyQualified]).scheduled.length, 0);
  assert.equal(view.schedule([fullyQualified]).rejected, 1);
  scheduler.onOutcome({ solveId: "revoked", scopeId: "tenant-a", scopeToken: view.outcomeBinding.token,
    taskShape: "build", testsPassed: false, mergeVerdict: "pending", timestamp: 1 });
  allowed = true;
  assert.equal(view.pending().length, 0, "a revoked outcome cannot consume tenant state");
});

test("free-text whitespace is normalized while rejected inputs remain observable", () => {
  const scheduler = new BoundedNeedScheduler();
  const result = scheduler.schedule([{ ...fullyQualified, subject: "  typescript-api  ", goal: "repair API mistakes\nacross the codebase" }]);
  assert.equal(result.rejected, undefined);
  assert.equal(result.scheduled[0]?.subject, "typescript-api");
  assert.equal(result.scheduled[0]?.goal, "repair API mistakes across the codebase");
  assert.equal(scheduler.schedule([{ ...fullyQualified, id: " bad " }]).rejected, 1);
});
