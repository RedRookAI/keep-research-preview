import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, openSync, writeSync, fsyncSync, closeSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { FleetAdmissionLifecycle, type FleetAdmissionHandle, type FleetAdmissionRequest, type FleetBasis } from "../src/fleet/fleet_lifecycle.js";
import { InProcessLock } from "../src/lock/lock.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest, type GatewayRequest } from "../src/gateway/http_gateway.js";
import { canonicalize } from "../src/spine/event.js";
import { RbacAuthorizer, type Principal } from "../src/identity/rbac.js";
import { capabilityInvocationDigest, type CapabilityAdapter } from "../src/ecosystem/capability_port.js";

const spineAt = (root: string) => new Spine(new FileSpineStore(root, { fsync: true }), new InProcessLock(), new SchemaRegistry());
const basis = (over: Partial<FleetBasis> = {}): FleetBasis => ({
  model: "model-a", input: "input-a", retrieval: "retrieval-a", tool: "tool-a", policy: "policy-a",
  operator: "operator-a", infrastructure: "infra-a", specification: "spec-a", ...over,
});
const request = (operationId: string, over: Partial<FleetAdmissionRequest> = {}): FleetAdmissionRequest => ({
  operationId, tenant: "acme", agent: "agent-a", amount: 2, gateAutoProceed: true,
  writeSet: [`resource:${operationId}`], inverseDependsOn: [`resource:${operationId}`], externalSink: false,
  provenance: [{ agent: "agent-a", taint: "trusted", source: "internal" }], basis: basis({ input: `input:${operationId}` }), ...over,
});
const sha = (value: unknown) => createHash("sha256").update(canonicalize(value)).digest("hex");

test("fleet claim permits one entry, survives restart, and automatic release cannot clear it", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-fleet-claim-")), policy = { cap: 2, maxPerBasis: 8 };
  const fleet = new FleetAdmissionLifecycle(spineAt(root), policy);
  const admission = await fleet.admit(request("one")); assert.ok(admission.proceed);
  const handle = admission.handle;
  assert.deepEqual(await Promise.all([fleet.claimDispatch(handle, handle.effectDigest), fleet.claimDispatch(handle, handle.effectDigest)]), [true, false]);
  assert.equal(await fleet.release(handle), false);
  const restarted = new FleetAdmissionLifecycle(spineAt(root), policy);
  assert.equal(await restarted.claimDispatch(handle, handle.effectDigest), false);
  assert.equal(restarted.active().length, 1);
  assert.deepEqual(await restarted.inspect("one", "acme"), { operationId: "one", accounting: "active", dispatch: "claimed", effect: "unverified" });
  assert.equal((await restarted.admit(request("two"))).proceed, false);
  assert.equal(await restarted.reconcileAsOperator(handle, "commit"), true);
  assert.equal(await restarted.reconcileAsOperator(handle, "commit"), false);
  assert.equal(restarted.committedTotal(), 2);
});

test("fleet pending claim inspection does not seal; lost seal acknowledgment never allows another claim", async () => {
  for (const fault of ["before-seal", "after-seal"] as const) {
    const root = mkdtempSync(join(tmpdir(), "keep-fleet-claim-fault-")), spine = spineAt(root), policy = { cap: 2, maxPerBasis: 8 };
    const fleet = new FleetAdmissionLifecycle(spine, policy);
    const admission = await fleet.admit(request("one")); assert.ok(admission.proceed);
    const seal = spine.seal.bind(spine); let count = 0;
    spine.seal = async () => {
      if (++count === 2) { if (fault === "after-seal") await seal(); throw Error("lost acknowledgment"); }
      return await seal();
    };
    await assert.rejects(fleet.claimDispatch(admission.handle, admission.handle.effectDigest), /lost acknowledgment/);
    const before = spine.verifiedReplay().events.length;
    const observation = await fleet.inspect("one", "acme");
    assert.equal(observation?.dispatch, fault === "before-seal" ? "unknown-pending" : "claimed");
    assert.equal(spine.verifiedReplay().events.length, before, "inspection must not seal pending evidence");
    const restarted = new FleetAdmissionLifecycle(spineAt(root), policy);
    assert.equal(await restarted.claimDispatch(admission.handle, admission.handle.effectDigest), false);
    assert.equal(await restarted.release(admission.handle), false);
    assert.equal(restarted.active().length, 1);
  }
});

test("malformed claim retains capacity and quarantines dispatch instead of inventing nonexecution", async () => {
  const spine = spineAt(mkdtempSync(join(tmpdir(), "keep-fleet-claim-corrupt-")));
  const fleet = new FleetAdmissionLifecycle(spine, { cap: 2, maxPerBasis: 8 });
  const admission = await fleet.admit(request("one")); assert.ok(admission.proceed);
  spine.stage({ type: "effect.intent", actor: "fleet-lifecycle", payload: { event: "fleet.dispatch-claimed", schema: "keep.fleet-dispatch/v1", ...admission.handle, effectDigest: "0".repeat(64) } });
  await spine.seal();
  assert.equal(await fleet.claimDispatch(admission.handle, admission.handle.effectDigest), false);
  assert.equal(await fleet.release(admission.handle), false);
  assert.equal((await fleet.inspect("one", "acme"))?.dispatch, "quarantined");
  assert.equal(fleet.active().length, 1);
  assert.equal((await fleet.admit(request("two"))).proceed, false);
});

test("composed dispatch has one actual sink entry for concurrent and restarted permit reuse on both tracks", async () => {
  for (const tenant of [undefined, "alpha"] as const) {
    const root = mkdtempSync(join(tmpdir(), "keep-fleet-single-entry-")), sink = join(root, "outbox.jsonl");
    const inv = { capabilityId: "outbox", operation: "email.send", args: { target: "one", value: 1.25 } };
    const descriptor = { id: "outbox", kind: "connector" as const, name: "owned sink", credentialId: "fixture", trust: "verified" as const,
      ...(tenant === undefined ? {} : { tenant }), fleet: { admissionUnits: 1, resourceDomain: "outbox" } };
    const build = () => {
      const app = composeKeep({ dataDir: join(root, "keep"), fleetLifecycle: { cap: 1, maxPerBasis: 8 } });
      app.infra.capabilities.register({ descriptor, invoke: async (captured, context) => {
        assert.equal(context?.fleetOperation?.operationId, "one");
        assert.equal(context?.fleetOperation?.tenant, tenant ?? "keep.n1.default");
        assert.equal(context?.fleetOperation?.effectDigest, capabilityInvocationDigest(inv, descriptor, tenant));
        const fd = openSync(sink, "a");
        try { writeSync(fd, JSON.stringify({ args: captured.args, operation: context.fleetOperation }) + "\n"); fsyncSync(fd); } finally { closeSync(fd); }
        throw Error("lost sink acknowledgment");
      } });
      return app;
    };
    const app = build();
    const admitted = await app.fleetLifecycle!.admit(request("one", { tenant: tenant ?? "keep.n1.default", amount: 1, effectDigest: capabilityInvocationDigest(inv, descriptor, tenant) }));
    assert.ok(admitted.proceed);
    const opts = { confirm: true, fleetPermit: admitted.handle, ...(tenant === undefined ? {} : { tenant }) };
    const pair = await Promise.all([app.infra.capabilities.invoke(inv, opts), app.infra.capabilities.invoke(inv, opts)]);
    assert.ok(pair.every(result => !result.ok && result.held === false));
    const restarted = build();
    assert.equal((await restarted.infra.capabilities.invoke(inv, opts)).ok, false);
    assert.equal(readFileSync(sink, "utf8").trim().split("\n").length, 1);
    assert.equal(restarted.fleetLifecycle!.active().length, 1);
    assert.equal(restarted.fleetLifecycle!.committedTotal(), 0);
    assert.equal(await restarted.fleetLifecycle!.release(admitted.handle), false);
  }
});

test("composed hub refuses prior invocation protocol while retaining its reservation", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-fleet-legacy-")), fleetLifecycle: { cap: 1, maxPerBasis: 8 } });
  const inv = { capabilityId: "legacy", operation: "email.send", args: {} };
  const descriptor = { id: "legacy", kind: "connector" as const, name: "legacy", credentialId: "fixture", trust: "verified" as const };
  let calls = 0;
  app.infra.capabilities.register({ descriptor, invoke: async () => { calls++; return { ok: true }; } });
  const legacy = createHash("sha256").update("keep.capability-invocation/v1\0").update(canonicalize({ ...inv, tenant: "keep.n1.default", fleet: null })).digest("hex");
  const admitted = await app.fleetLifecycle!.admit(request("old", { tenant: "keep.n1.default", amount: 1, effectDigest: legacy })); assert.ok(admitted.proceed);
  assert.equal((await app.infra.capabilities.invoke(inv, { confirm: true, fleetPermit: admitted.handle })).held, false);
  assert.equal(calls, 0);
  assert.equal(app.fleetLifecycle!.active().length, 1);
});

test("operation inspection uses separate current observation authority without sealing or returning an executable handle", async () => {
  for (const tenant of [undefined, "alpha"] as const) {
    let observe = true;
    const base = new RbacAuthorizer();
    const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-fleet-inspect-")), fleetLifecycle: { cap: 4, maxPerBasis: 8 },
      authorization: { authorize: (principal, action) => action === "change.solve" || (action === "audit.view" && !observe)
        ? { allow: false, reason: "current policy withdrawn" } : base.authorize(principal, action) } });
    const principal: Principal = { id: "owner", kind: "human", role: "owner", ...(tenant === undefined ? {} : { tenant }) };
    const security = { token: "fixture", ...(tenant === undefined ? {} : { principalFor: () => principal }) };
    const admission = await app.fleetLifecycle!.admit(request("one", { tenant: tenant ?? "keep.n1.default" })); assert.ok(admission.proceed);
    const call = (path: string, method: "GET" | "POST" = "GET") => handleGatewayRequest(app, {
      method, path, query: method === "GET" ? { operationId: "one" } : {}, headers: { authorization: "Bearer fixture" }, body: JSON.stringify({ operationId: "one" }),
    }, security);
    assert.equal((await call("/fleet/recover", "POST")).status, 403);
    const sealedBefore = app.spine.verifiedReplay().events.length;
    const result = await call("/fleet/operation");
    assert.equal(result.status, 200);
    assert.deepEqual(JSON.parse(result.body), { operation: { operationId: "one", accounting: "active", dispatch: "no-sealed-claim", effect: "unverified" } });
    assert.equal(app.spine.verifiedReplay().events.length, sealedBefore);
    assert.equal(app.fleetLifecycle!.active().length, 1);
    observe = false;
    assert.equal((await call("/fleet/operation")).status, 403);
  }
});

test("operation inspection limits nonhuman identities to their own work and enforces tenant and grant revocation", async () => {
  const parent: Principal = { id: "parent", kind: "human", role: "maintainer", tenant: "alpha" };
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-fleet-inspect-scope-")), fleetLifecycle: { cap: 8, maxPerBasis: 8 },
    delegationParentFor: (id, tenant) => id === parent.id && tenant === parent.tenant ? parent : undefined });
  const now = Date.now(), agent = await app.authorization.issue(parent, "agent-a", ["audit.view"], now + 60_000, now, "observer-grant");
  for (const [operationId, actor, tenant] of [["own", "agent-a", "alpha"], ["other", "agent-b", "alpha"], ["foreign", "agent-a", "beta"]]) {
    assert.ok((await app.fleetLifecycle!.admit(request(operationId!, { tenant: tenant!, agent: actor!, provenance: [{ agent: actor!, taint: "trusted", source: "fixture" }] }))).proceed);
  }
  const call = (principal: Principal, operationId: string) => handleGatewayRequest(app, { method: "GET", path: "/fleet/operation", query: { operationId }, headers: { authorization: "Bearer fixture" }, body: "" }, { token: "fixture", principalFor: () => principal });
  assert.equal((await call(agent, "own")).status, 200);
  assert.equal((await call(agent, "other")).status, 404);
  assert.equal((await call(agent, "foreign")).status, 404);
  assert.equal((await call(parent, "other")).status, 200);
  assert.equal((await call(parent, "foreign")).status, 404);
  assert.equal(await app.authorization.revoke("observer-grant"), true);
  assert.equal((await call(agent, "own")).status, 403);
});

test("fleet keeps unknown effect capacity across restart, admits only real headroom, and never trusts adapter holds", async () => {
  for (const tenant of [undefined, "alpha"] as const) for (const mode of ["ack", "throw-before-effect", "throw-after-effect", "forged-hold", "response-audit", "untrusted"] as const) {
    const root = mkdtempSync(join(tmpdir(), "keep-fleet-effect-")), sink = join(root, "outbox.jsonl");
    const policy = { cap: 2, perTenantCap: 2, maxPerBasis: 8 };
    const security = { token: "fixture", ...(tenant === undefined ? {} : { principalFor: (): Principal => ({ id: "alice", kind: "human", role: "maintainer", tenant }) }) };
    let calls = 0;
    const build = (first: boolean) => {
      const app = composeKeep({ dataDir: join(root, "keep"), fleetLifecycle: policy });
      app.infra.capabilities.register({
        descriptor: { id: "outbox", kind: "connector", name: "test sink", credentialId: "fixture", trust: first && mode === "untrusted" ? "untrusted" : "verified", ...(tenant === undefined ? {} : { tenant }), fleet: { admissionUnits: 1, resourceDomain: "outbox", targetArgument: "target" } },
        invoke: async inv => {
          calls++;
          if (first && mode === "throw-before-effect") throw Error("generic failure");
          const fd = openSync(sink, "a");
          try { writeSync(fd, JSON.stringify(inv.args) + "\n"); fsyncSync(fd); } finally { closeSync(fd); }
          if (first && mode === "throw-after-effect") throw Error("generic failure");
          return first && mode === "forged-hold" ? { ok: false, held: true } : { ok: true };
        },
      });
      if (first && mode === "response-audit") {
        const stage = app.spine.stage.bind(app.spine);
        app.spine.stage = e => { if (e.payload["phase"] === "response") throw Error("lost response audit"); return stage(e); };
      }
      return app;
    };
    const invoke = (app: ReturnType<typeof composeKeep>, operationId: string, target: string) => handleGatewayRequest(app, {
      method: "POST", path: "/fleet/invoke", query: {}, headers: { authorization: "Bearer fixture" },
      body: JSON.stringify({ operationId, capabilityId: "outbox", operation: "email.send", args: { target }, confirmed: true, declassify: true }),
    }, security);
    const first = build(true), response = await invoke(first, "first", "order-a");
    const uncertain = mode !== "ack" && mode !== "untrusted";
    assert.equal(response.status, uncertain ? 409 : 200, mode + response.body);
    assert.equal(JSON.parse(response.body).settlement, uncertain ? "uncertain" : mode === "ack" ? "committed" : "released");
    assert.equal(first.fleetLifecycle!.active().length, uncertain ? 1 : 0);
    const restarted = build(false);
    assert.equal(restarted.fleetLifecycle!.active().length, uncertain ? 1 : 0);
    assert.equal(restarted.fleetLifecycle!.committedTotal(), mode === "ack" ? 1 : 0);
    const priorCalls = calls;
    assert.equal(JSON.parse((await invoke(restarted, "first", "order-a")).body).result.proceed, false);
    assert.equal(calls, priorCalls, "same identity never dispatches again");
    const benign = await invoke(restarted, "second", "order-b");
    assert.equal(JSON.parse(benign.body).settlement, "committed", "distinct target with genuine global headroom progresses");
    if (mode !== "untrusted") {
      const excess = await invoke(restarted, "third", "order-c");
      assert.equal(JSON.parse(excess.body).result.proceed, false, "unknown plus committed consumes cap2");
      assert.equal(calls, priorCalls + 1);
    }
    const rows = existsSync(sink) ? readFileSync(sink, "utf8").trim().split("\n").map(s => JSON.parse(s)) : [];
    assert.equal(rows.length, mode === "throw-before-effect" || mode === "untrusted" ? 1 : 2);
    assert.equal(rows.filter(row => row.target === "order-b").length, 1);
  }
});

test("FLEET-01 one admission atomically owns capacity, reversibility, provenance, and every correlation dimension", async () => {
  const fleet = new FleetAdmissionLifecycle(spineAt(mkdtempSync(join(tmpdir(), "keep-fleet-atomic-"))), { cap: 10, maxPerBasis: 1 });
  const admitted = await fleet.admit(request("one"));
  assert.equal(admitted.proceed, true);
  assert.equal(fleet.active("acme").length, 1);
  const denied = await fleet.admit(request("two", {
    amount: 9, gateAutoProceed: false, writeSet: ["resource:one"], inverseDependsOn: ["resource:one"],
    externalSink: true, provenance: [{ agent: "agent-a", taint: "untrusted", source: "retrieved" }],
  }));
  assert.equal(denied.proceed, false);
  if (!denied.proceed) {
    assert.match(denied.reasons.join(";"), /per-decision.*shared-cap.*reversibility-conflict.*inverse-reversibility-conflict.*cross-agent-tainted-sink.*correlated-lockstep/u);
    assert.equal(denied.reasons.some((reason) => reason.includes("resource:one") || reason.includes("@one")), false, "denials disclose no foreign resource or operation identity");
  }
  assert.equal(fleet.active("acme").length, 1, "a multi-barrier denial acquires no partial state");
});

test("FLEET-01 correlation is explicit and independently load-bearing for every common-cause dimension", async () => {
  for (const dimension of Object.keys(basis()) as Array<keyof FleetBasis>) {
    const fleet = new FleetAdmissionLifecycle(spineAt(mkdtempSync(join(tmpdir(), `keep-fleet-basis-${dimension}-`))), { cap: 100, maxPerBasis: 1 });
    const firstBasis = basis();
    assert.equal((await fleet.admit(request("first", { basis: firstBasis }))).proceed, true);
    const diverse = Object.fromEntries(Object.entries(firstBasis).map(([key, value]) => [key, key === dimension ? value : `${value}-different`])) as unknown as FleetBasis;
    const second = await fleet.admit(request("second", { agent: "agent-b", provenance: [{ agent: "agent-b", taint: "trusted", source: "internal" }], basis: diverse }));
    assert.equal(second.proceed, false, dimension);
    if (!second.proceed) assert.deepEqual(second.reasons, [`correlated-lockstep:${dimension}`]);
  }
});

test("FLEET-01 commit, release, exact-handle refusal, and interrupted admission reconstruct across restart", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-fleet-restart-"));
  const first = new FleetAdmissionLifecycle(spineAt(root), { cap: 10, maxPerBasis: 2 });
  const committed = await first.admit(request("commit")); assert.equal(committed.proceed, true);
  const interrupted = await first.admit(request("interrupted", { basis: basis({ input: "other-input" }) })); assert.equal(interrupted.proceed, true);
  if (!committed.proceed || !interrupted.proceed) return;
  assert.equal(await first.commit({ ...committed.handle, admissionDigest: "0".repeat(64) }), false, "a forged handle settles nothing");
  assert.equal(await first.commit(committed.handle), true);
  const restarted = new FleetAdmissionLifecycle(spineAt(root), { cap: 10, maxPerBasis: 2 });
  assert.deepEqual(restarted.active("acme"), [interrupted.handle]);
  assert.equal(restarted.committedTotal(), 2);
  assert.equal(await restarted.reconcile(interrupted.handle, "release"), true);
  assert.equal(new FleetAdmissionLifecycle(spineAt(root), { cap: 10, maxPerBasis: 2 }).active().length, 0);
  const changed = new FleetAdmissionLifecycle(spineAt(root), { cap: 11, maxPerBasis: 3 });
  assert.equal(changed.configurationStatus().ready, false, "an unapproved policy edit disables fleet admission without bricking Keep boot");
  assert.deepEqual(await changed.admit(request("policy-mismatch")), { proceed: false, reasons: ["fleet-policy-mismatch"] });
  await changed.rotatePolicy({ cap: 11, maxPerBasis: 3 });
  assert.equal(changed.configurationStatus().ready, true);
  assert.equal((await restarted.admit(request("interrupted"))).proceed, false, "settled operation identities cannot resurrect");
});

test("FLEET-01 concurrent admission serializes the shared-cap check and refuses hostile owned evidence", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-fleet-race-"));
  const spine = spineAt(root), fleet = new FleetAdmissionLifecycle(spine, { cap: 2, maxPerBasis: 10 });
  const [a, b] = await Promise.all([
    fleet.admit(request("race-a", { basis: basis({ input: "race-a" }) })),
    fleet.admit(request("race-b", { basis: basis({ input: "race-b" }) })),
  ]);
  assert.equal([a, b].filter((row) => row.proceed).length, 1);
  assert.equal(fleet.active().length, 1);
  const winner = [a, b].find((row) => row.proceed); assert.ok(winner?.proceed);
  spine.stage({ type: "effect.intent", actor: "fleet-lifecycle", payload: { event: "hostile" } });
  assert.equal(fleet.active().length, 1, "unsealed evidence is never authorization state");
  await spine.seal();
  assert.equal(fleet.active().length, 1, "malformed owned evidence is quarantined row-locally");
  assert.equal((await fleet.integrityStatus()).quarantined, 1, "quarantined safety evidence is operator-visible");
  spine.stage({ type: "effect.terminal", actor: "fleet-lifecycle", payload: { event: "fleet.terminal", tenant: winner.handle.tenant, operationId: winner.handle.operationId } });
  await spine.seal();
  assert.equal(await fleet.release(winner.handle), false, "automatic release cannot infer finality from quarantined evidence");
  assert.equal(await fleet.reconcileAsOperator(winner.handle, "release"), true, "a malformed sibling row does not prevent explicit trusted operator disposition");
});

test("FLEET-01 production filesystem coordination serializes composers and operation identity is tenant-scoped", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-fleet-production-lock-"));
  const first = composeKeep({ dataDir: root, fleetLifecycle: { cap: 1, perTenantCap: 1, maxPerBasis: 10 } }).fleetLifecycle!;
  const second = composeKeep({ dataDir: root, fleetLifecycle: { cap: 1, perTenantCap: 1, maxPerBasis: 10 } }).fleetLifecycle!;
  const [a, b] = await Promise.all([
    first.admit(request("cross-process-a", { amount: 1, basis: basis({ input: "a" }) })),
    second.admit(request("cross-process-b", { amount: 1, basis: basis({ input: "b" }) })),
  ]);
  assert.equal([a, b].filter((row) => row.proceed).length, 1, "the shipped filesystem lock makes check-and-reserve atomic");
  const winner = [a, b].find((row) => row.proceed); assert.ok(winner?.proceed); await first.release(winner.handle);

  const scoped = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-fleet-tenant-key-")), fleetLifecycle: { cap: 10, maxPerBasis: 10 } }).fleetLifecycle!;
  const alpha = await scoped.admit(request("same-id", { tenant: "alpha", basis: basis({ input: "alpha" }) })); assert.equal(alpha.proceed, true);
  if (alpha.proceed) await scoped.release(alpha.handle);
  const beta = await scoped.admit(request("same-id", { tenant: "beta", basis: basis({ input: "beta" }) })); assert.equal(beta.proceed, true, "a foreign tenant cannot squat or disclose an operation id");
});

test("FLEET-01 lost admission acknowledgement is explicitly recoverable from durable staging", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-fleet-lost-ack-"));
  class FailFirstSealSpine extends Spine {
    failed = false;
    override async seal(): ReturnType<Spine["seal"]> { if (!this.failed) { this.failed = true; throw new Error("simulated lost seal acknowledgement"); } return await super.seal(); }
  }
  const spine = new FailFirstSealSpine(new FileSpineStore(root, { fsync: true }), new InProcessLock(), new SchemaRegistry());
  const fleet = new FleetAdmissionLifecycle(spine, { cap: 10, maxPerBasis: 2 });
  await assert.rejects(fleet.admit(request("lost-ack")), /fleet admission indeterminate:lost-ack/u);
  assert.equal(fleet.active().length, 0, "unsealed staging is not authority");
  const recovered = await fleet.recover("lost-ack", "acme", "agent-a");
  assert.equal(recovered.status, "active");
  if (recovered.status === "active") assert.equal(await fleet.release(recovered.handle), true);
});

test("FLEET-01 historical admissions remain restrictive and settleable after effect-identity schema enrichment", async () => {
  const spine = spineAt(mkdtempSync(join(tmpdir(), "keep-fleet-legacy-admission-")));
  const policyDigest = sha({ schema: "keep.fleet-policy/v1", cap: 10, maxPerBasis: 2, perTenantCap: 10, maxActive: 10_000, maxActivePerTenant: 1_000, maxPerTenantBasis: 2 });
  const legacy = { schema: "keep.fleet-admission/v1", policyDigest, operationId: "legacy", tenant: "acme", agent: "agent-a", amount: 1,
    writeSet: ["resource:legacy"], inverseDependsOn: ["resource:legacy"], externalSink: false,
    provenance: [{ agent: "agent-a", taint: "trusted", source: "internal" }], basis: basis({ input: "legacy" }) };
  spine.stage({ type: "effect.intent", actor: "fleet-lifecycle", payload: { event: "fleet.admitted", ...legacy, admissionDigest: sha(legacy) } });
  await spine.seal();
  const fleet = new FleetAdmissionLifecycle(spine, { cap: 10, maxPerBasis: 2 });
  const [handle] = fleet.active("acme"); assert.ok(handle);
  assert.equal((await fleet.integrityStatus()).quarantined, 0);
  assert.equal(await fleet.release(handle), true);
});

test("FLEET-01 bounded active state and tenant shares prevent one principal from exhausting the fleet", async () => {
  const fleet = new FleetAdmissionLifecycle(spineAt(mkdtempSync(join(tmpdir(), "keep-fleet-fairness-"))), {
    cap: 10, perTenantCap: 2, maxPerBasis: 10, maxPerTenantBasis: 5, maxActive: 2, maxActivePerTenant: 1,
  });
  const alpha = await fleet.admit(request("alpha-one", { tenant: "alpha", amount: 2, basis: basis({ input: "alpha-one" }) })); assert.equal(alpha.proceed, true);
  const alphaSecond = await fleet.admit(request("alpha-two", { tenant: "alpha", amount: 1, basis: basis({ input: "alpha-two" }) }));
  assert.equal(alphaSecond.proceed, false); if (!alphaSecond.proceed) assert.deepEqual([...alphaSecond.reasons].sort(), ["tenant-active-limit", "tenant-shared-cap-exceeded"].sort());
  const beta = await fleet.admit(request("beta-one", { tenant: "beta", amount: 1, basis: basis({ input: "beta-one" }) })); assert.equal(beta.proceed, true);
  const gamma = await fleet.admit(request("gamma-one", { tenant: "gamma", amount: 1, basis: basis({ input: "gamma-one" }) }));
  assert.equal(gamma.proceed, false); if (!gamma.proceed) assert.deepEqual(gamma.reasons, ["fleet-active-limit"]);
});

test("FLEET-01 shared-tenancy mode requires explicit headroom while n=1 retains the full local ceiling", () => {
  assert.throws(() => new FleetAdmissionLifecycle(spineAt(mkdtempSync(join(tmpdir(), "keep-fleet-shared-policy-bad-"))), { cap: 10, maxPerBasis: 4 }, { sharedTenancy: true }), /explicit tenant shares/u);
  assert.doesNotThrow(() => new FleetAdmissionLifecycle(spineAt(mkdtempSync(join(tmpdir(), "keep-fleet-shared-policy-good-"))), {
    cap: 10, perTenantCap: 5, maxActive: 10, maxActivePerTenant: 5, maxPerBasis: 4, maxPerTenantBasis: 2,
  }, { sharedTenancy: true }));
  assert.doesNotThrow(() => new FleetAdmissionLifecycle(spineAt(mkdtempSync(join(tmpdir(), "keep-fleet-n1-policy-"))), { cap: 10, maxPerBasis: 4 }));
});

test("FLEET-01 policy mismatch is fleet-local and authorized gateway rotation restores admission", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-fleet-policy-gateway-"));
  const old = composeKeep({ dataDir: root, fleetLifecycle: { cap: 5, maxPerBasis: 2 } }).fleetLifecycle!;
  const prior = await old.admit(request("policy-anchor", { amount: 1 })); assert.equal(prior.proceed, true);
  if (prior.proceed) await old.commit(prior.handle);
  const changedApp = composeKeep({ dataDir: root, fleetLifecycle: { cap: 8, maxPerBasis: 3 } });
  assert.equal(changedApp.fleetLifecycle!.configurationStatus().ready, false, "Keep still boots while fleet policy awaits authorization");
  const maintainer: Principal = { id: "mary", kind: "human", role: "maintainer", tenant: "acme" };
  const policyCall: GatewayRequest = { method: "POST", path: "/fleet/policy", query: {}, headers: { authorization: "Bearer token" }, body: JSON.stringify({ policy: { cap: 8, maxPerBasis: 3 } }) };
  assert.equal((await handleGatewayRequest(changedApp, policyCall, { token: "token", principalFor: () => maintainer })).status, 200);
  assert.equal(composeKeep({ dataDir: root, fleetLifecycle: { cap: 8, maxPerBasis: 3 } }).fleetLifecycle!.configurationStatus().ready, true);
});

test("FLEET-01 real gateway derives the decision, binds tenant and actor, and preserves equal n=1/enterprise composition", async () => {
  const body = (operationId: string) => ({
    operationId, capability: "fs.read", amount: 1, args: { target: operationId },
  });
  const call = (payload: unknown, path = "/fleet/admit"): GatewayRequest => ({ method: "POST", path, query: {}, headers: { authorization: "Bearer token" }, body: JSON.stringify(payload) });
  const alpha: Principal = { id: "alice", kind: "human", role: "operator", tenant: "alpha" };
  const beta: Principal = { id: "bob", kind: "human", role: "operator", tenant: "beta" };
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-fleet-gateway-")), fleetLifecycle: { cap: 10, maxPerBasis: 2 } });
  const invoked: Array<{ operation: string; args: Readonly<Record<string, unknown>> }> = [];
  const adapter: CapabilityAdapter = {
    descriptor: { id: "fleet-test", kind: "connector", name: "fleet test", credentialId: "alpha-credential", trust: "verified", tenant: "alpha", fleet: { admissionUnits: 1, resourceDomain: "filesystem", targetArgument: "target" } },
    invoke: async (invocation) => { invoked.push({ operation: invocation.operation, args: invocation.args }); return { ok: true, output: "done" }; },
  };
  app.infra.capabilities.register(adapter);
  const admittedResponse = await handleGatewayRequest(app, call(body("gateway-alpha")), { token: "token", principalFor: () => alpha });
  assert.equal(admittedResponse.status, 200);
  const admitted = JSON.parse(admittedResponse.body) as { result: { proceed: boolean; handle: FleetAdmissionHandle }; mediation: { route: string } };
  assert.equal(admitted.result.proceed, true); assert.equal(admitted.mediation.route, "allow");
  assert.deepEqual({ tenant: admitted.result.handle.tenant, agent: admitted.result.handle.agent }, { tenant: "alpha", agent: "alice" });
  assert.equal((await handleGatewayRequest(app, call({ handle: admitted.result.handle, outcome: "release" }, "/fleet/settle"), { token: "token", principalFor: () => beta })).status, 404);
  assert.equal((await handleGatewayRequest(app, call({ handle: admitted.result.handle, outcome: "release" }, "/fleet/settle"), { token: "token", principalFor: () => alpha })).status, 200);

  const invokedResponse = await handleGatewayRequest(app, call({ ...body("invoked"), capabilityId: "fleet-test", operation: "fs.read" }, "/fleet/invoke"), { token: "token", principalFor: () => alpha });
  assert.equal(invokedResponse.status, 200);
  assert.deepEqual(invoked, [{ operation: "fs.read", args: { target: "invoked" } }], "the exact admitted operation and arguments reach the canonical capability hub");
  assert.equal(app.fleetLifecycle!.active("alpha").length, 0); assert.equal(app.fleetLifecycle!.committedTotal(), 1);
  const bypass = await app.infra.capabilities.invoke({ capabilityId: "fleet-test", operation: "fs.read", args: { target: "bypass" } }, { requireVerified: true, tenant: "alpha" });
  assert.deepEqual({ ok: bypass.ok, held: bypass.held }, { ok: false, held: true }, "every capability dispatch is held without an exact active fleet permit when fleet mode is composed");

  const held = JSON.parse((await handleGatewayRequest(app, call({ ...body("external"), capability: "email.send" }), { token: "token", principalFor: () => alpha })).body) as { result: { proceed: boolean }; mediation: { route: string } };
  assert.deepEqual({ proceed: held.result.proceed, route: held.mediation.route }, { proceed: false, route: "hold" }, "callers cannot assert that an external effect cleared its gate");
  assert.equal((await handleGatewayRequest(app, call({ ...body("operator-confirm"), capability: "email.send", confirmed: true }), { token: "token", principalFor: () => alpha })).status, 403,
    "effect confirmation requires approval authority");
  const maintainer: Principal = { id: "mary", kind: "human", role: "maintainer", tenant: "alpha" };
  const confirmedTainted = JSON.parse((await handleGatewayRequest(app, call({ ...body("confirmed-tainted"), capability: "email.send", confirmed: true }), { token: "token", principalFor: () => maintainer })).body) as { result: { proceed: boolean; reasons: string[] } };
  assert.equal(confirmedTainted.result.proceed, false); assert.ok(confirmedTainted.result.reasons.includes("cross-agent-tainted-sink"));
  const declassified = JSON.parse((await handleGatewayRequest(app, call({ ...body("confirmed-clean"), capability: "email.send", confirmed: true, declassify: true }), { token: "token", principalFor: () => maintainer })).body) as { result: { proceed: boolean } };
  assert.equal(declassified.result.proceed, true, "authorized declassification is distinct from effect confirmation");
  const declassifiedHandle = (declassified as unknown as { result: { handle: FleetAdmissionHandle } }).result.handle;
  assert.equal(app.fleetLifecycle!.provenanceFor([declassifiedHandle], "alpha").at(-1)?.declassifiedBy, "mary", "declassification remains explicit in durable lineage");
  await app.fleetLifecycle!.release(declassifiedHandle);
  const tenantCredentialProbe = await handleGatewayRequest(app, call({ ...body("foreign-credential"), capabilityId: "fleet-test", operation: "fs.read" }, "/fleet/invoke"), { token: "token", principalFor: () => beta });
  assert.equal(tenantCredentialProbe.status, 404, "a tenant cannot invoke another tenant's adapter credential");
  const viewer: Principal = { id: "view", kind: "human", role: "viewer", tenant: "alpha" };
  assert.equal((await handleGatewayRequest(app, call(body("viewer")), { token: "token", principalFor: () => viewer })).status, 403);

  const solo = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-fleet-solo-")), fleetLifecycle: { cap: 2, maxPerBasis: 1 } });
  const soloBody = { ...body("solo"), provenance: [{ agent: "owner", taint: "trusted", source: "internal" }] };
  const soloResponse = await handleGatewayRequest(solo, call(soloBody), { token: "token" });
  assert.equal((JSON.parse(soloResponse.body) as { result: { proceed: boolean; handle: FleetAdmissionHandle } }).result.handle.tenant, "keep.n1.default");

  const parent: Principal = { id: "parent", kind: "human", role: "maintainer", tenant: "agents" };
  const agentApp = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-fleet-agent-active-")), fleetLifecycle: { cap: 5, maxPerBasis: 2 }, delegationParentFor: (id, tenant) => id === parent.id && tenant === parent.tenant ? parent : undefined });
  const now = Date.now();
  const agent = await agentApp.authorization.issue(parent, "fleet-agent", ["change.solve"], now + 60_000, now, "fleet-agent-grant");
  const agentBody = { ...body("agent-work"), args: { target: "agent-work" } };
  assert.equal((await handleGatewayRequest(agentApp, call(agentBody), { token: "token", principalFor: () => agent })).status, 200);
  const activeRequest: GatewayRequest = { method: "GET", path: "/fleet/active", query: {}, headers: { authorization: "Bearer token" }, body: "" };
  const agentActive = JSON.parse((await handleGatewayRequest(agentApp, activeRequest, { token: "token", principalFor: () => agent })).body) as { active: FleetAdmissionHandle[] };
  assert.deepEqual(agentActive.active.map((handle) => handle.agent), ["fleet-agent"], "an issued agent can recover only its own outstanding handles");
  const operatorRecovery = await handleGatewayRequest(agentApp, call({ handle: agentActive.active[0], outcome: "release" }, "/fleet/reconcile"), { token: "token", principalFor: () => parent });
  assert.equal(operatorRecovery.status, 200, "an authorized human can release work stranded by a dead or revoked agent");
});
