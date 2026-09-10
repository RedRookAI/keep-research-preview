import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, openSync, writeSync, fsyncSync, closeSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest } from "../src/gateway/http_gateway.js";
import { OWNER, type Principal } from "../src/identity/rbac.js";
import type { FleetAdmissionHandle } from "../src/fleet/fleet_lifecycle.js";

// KEEP-08B-001: adapted from the auditor's synthetic authority/operator cases.
// Fresh child reconstruction uses only this test's private temporary state.
function fixture(root: string, tenant?: string) {
  const parent: Principal = tenant === undefined ? OWNER : { id: "parent", kind: "human", role: "maintainer", tenant };
  const app = composeKeep({ dataDir: join(root, "keep"), fleetLifecycle: { cap: 1, maxPerBasis: 8 },
    delegationParentFor: (id, t) => id === parent.id && t === tenant ? parent : undefined,
    developmentProvider: { name: "no-model", isLocal: true, generate: async () => { throw Error("unexpected model call"); }, embed: async () => { throw Error("unexpected embedding call"); } },
  });
  let loseAck = true;
  const sink = join(root, "effects.jsonl");
  app.infra.capabilities.register({ descriptor: {
    id: "sink", kind: "connector", name: "synthetic local sink", credentialId: "unused-fixture", trust: "verified",
    ...(tenant === undefined ? {} : { tenant }), fleet: { admissionUnits: 1, resourceDomain: "settlement-audit" },
  }, invoke: async inv => {
    const fd = openSync(sink, "a", 0o600);
    try { writeSync(fd, JSON.stringify({ args: inv.args, pid: process.pid }) + "\n"); fsyncSync(fd); } finally { closeSync(fd); }
    if (loseAck) throw Error("lost response after local effect");
    return { ok: true };
  } });
  const call = async (who: Principal, path: string, body: unknown) => {
    const r = await handleGatewayRequest(app, { method: "POST", path, query: {}, headers: { authorization: "Bearer synthetic-token" }, body: JSON.stringify(body) },
      { token: "synthetic-token", ...(tenant === undefined && who.id === OWNER.id && who.tenant === undefined ? {} : { principalFor: () => who }) });
    return { status: r.status, body: JSON.parse(r.body) };
  };
  const invocation = (operationId: string) => ({ operationId, capabilityId: "sink", operation: "fs.write-draft", args: { target: operationId } });
  const rows = () => existsSync(sink) ? readFileSync(sink, "utf8").trim().split("\n").map(s => JSON.parse(s)) : [];
  return { app, parent, call, invocation, rows, acknowledge: () => { loseAck = false; } };
}

if (process.argv[2] === "--settlement-restart") {
  const input = JSON.parse(process.argv[3]!) as { root: string; tenant?: string; actor: Principal; handle: FleetAdmissionHandle };
  const f = fixture(input.root, input.tenant);
  const who = input.actor.kind === "agent" ? f.app.authorization.restorePrincipal("limited-grant")! : input.actor;
  assert.ok(who);
  assert.equal((await f.call(who, "/fleet/settle", { handle: input.handle, outcome: "release" })).status, 404);
  assert.equal((await f.call(who, "/fleet/invoke", f.invocation("after-restart"))).body.result.proceed, false);
  assert.equal((await f.app.fleetLifecycle!.inspect(input.handle.operationId, input.handle.tenant))?.dispatch, "claimed");
  assert.equal(f.rows().length, 1);
  console.log(JSON.stringify({ effects: f.rows().length, committed: f.app.fleetLifecycle!.committedTotal(), active: f.app.fleetLifecycle!.active().length }));
} else {
  for (const [tenant, kind] of [[undefined, "owner"], ["alpha", "agent"], ["alpha", "operator"]] as const) {
    test(`KEEP-08B-001 ${tenant ?? "personal"}/${kind}: claimed release needs human reconciliation across restart`, async () => {
      const root = mkdtempSync(join(tmpdir(), "keep-settlement-audit-")), f = fixture(root, tenant);
      const actor: Principal = kind === "agent"
        ? await f.app.authorization.issue(f.parent, "limited-agent", ["change.solve", "audit.view"], Date.now() + 300_000, Date.now(), "limited-grant")
        : kind === "owner" ? f.parent : { id: "limited-human", kind: "human", role: "operator", tenant: "alpha" };
      const invoked = await f.call(actor, "/fleet/invoke", f.invocation("uncertain"));
      assert.equal(invoked.status, 409);
      const handle = invoked.body.admission.handle as FleetAdmissionHandle;
      assert.ok(handle);
      assert.equal(f.rows().length, 1);
      assert.equal(await f.app.fleetLifecycle!.release(handle), false);
      if (kind !== "owner") assert.equal((await f.call(actor, "/fleet/reconcile", { handle, outcome: "release" })).status, 403);
      assert.equal((await f.call(actor, "/fleet/settle", { handle, outcome: "release" })).status, 404,
        "ordinary settlement must not borrow operator-disposition authority");
      assert.equal((await f.call(actor, "/fleet/invoke", f.invocation("blocked-new-id"))).body.result.proceed, false);
      assert.equal(f.rows().length, 1);
      const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url), "--settlement-restart", JSON.stringify({ root, tenant, actor, handle })],
        { encoding: "utf8", timeout: 15_000, maxBuffer: 64 * 1024 });
      assert.equal(child.status, 0, child.stderr + child.stdout);
      assert.deepEqual(JSON.parse(child.stdout), { effects: 1, committed: 0, active: 1 });
      // Parent cannot borrow the agent's ordinary handle; foreign tenant cannot reconcile it.
      assert.equal((await f.call(f.parent, "/fleet/settle", { handle, outcome: "release" })).status, 404);
      assert.equal((await f.call({ ...actor, tenant: "foreign" }, "/fleet/settle", { handle, outcome: "release" })).status, kind === "agent" ? 403 : 404);
      assert.equal((await f.call({ ...f.parent, tenant: "foreign" }, "/fleet/reconcile", { handle, outcome: "release" })).status, 404);
      if (kind === "agent") {
        assert.equal(await f.app.authorization.revoke("limited-grant"), true);
        assert.equal((await f.call(actor, "/fleet/settle", { handle, outcome: "release" })).status, 403);
      }
      assert.equal((await f.call(f.parent, "/fleet/reconcile", { handle, outcome: "release" })).status, 200);
      assert.equal((await f.call(f.parent, "/fleet/reconcile", { handle, outcome: "commit" })).status, 404);
      assert.equal(await f.app.fleetLifecycle!.claimDispatch(handle, handle.effectDigest), false);
      f.acknowledge();
      assert.equal((await f.call(f.parent, "/fleet/invoke", f.invocation("authorized-new-id"))).body.effect.ok, true);
      assert.equal(f.rows().length, 2, "only explicit authorized disposition frees capacity");
      assert.equal(f.app.fleetLifecycle!.committedTotal(), 1);
    });
  }
  for (const tenant of [undefined, "alpha"] as const) for (const outcome of ["commit", "release"] as const) {
    test(`KEEP-08B-001 ${tenant ?? "personal"}: ordinary unclaimed ${outcome} remains useful`, async () => {
      const f = fixture(mkdtempSync(join(tmpdir(), "keep-settlement-control-")), tenant);
      const actor: Principal = tenant === undefined ? f.parent : { id: "operator", kind: "human", role: "operator", tenant };
      const admission = await f.call(actor, "/fleet/admit", { operationId: "reservation", capability: "fs.write-draft", args: { target: "reservation" } });
      assert.equal(admission.body.result.proceed, true);
      const handle = admission.body.result.handle as FleetAdmissionHandle;
      assert.equal((await f.call(actor, "/fleet/settle", { handle, outcome })).status, 200);
      assert.equal((await f.call(actor, "/fleet/settle", { handle, outcome })).status, 404);
      assert.equal((await f.call(actor, "/fleet/settle", { handle: null, outcome })).status, 404);
      assert.equal(f.app.fleetLifecycle!.active().length, 0);
      assert.equal(f.app.fleetLifecycle!.committedTotal(), outcome === "commit" ? 1 : 0);
      assert.equal(f.rows().length, 0);
    });
  }
  for (const tenant of [undefined, "alpha"] as const) {
    for (const point of ["before", "after"] as const) for (const outcome of ["commit", "release"] as const) {
      test(`KEEP-08B-001 ${tenant ?? "personal"}: ordinary ${outcome} ${point}-seal failure remains indeterminate`, async () => {
        const root = mkdtempSync(join(tmpdir(), "keep-settlement-fault-")), f = fixture(root, tenant);
        const first = outcome === "commit"
          ? await f.call(f.parent, "/fleet/invoke", f.invocation("uncertain"))
          : await f.call(f.parent, "/fleet/admit", { operationId: "unclaimed", capability: "fs.write-draft", args: { target: "unclaimed" } });
        assert.equal(first.status, outcome === "commit" ? 409 : 200);
        const handle = (outcome === "commit" ? first.body.admission.handle : first.body.result.handle) as FleetAdmissionHandle;
        const seal = f.app.spine.seal.bind(f.app.spine);
        let calls = 0;
        f.app.spine.seal = async () => {
          if (++calls === 2) { if (point === "after") await seal(); throw Error("synthetic terminal seal failure"); }
          return await seal();
        };
        assert.equal((await f.call(f.parent, "/fleet/settle", { handle, outcome })).status, 503);
        f.app.spine.seal = seal;
        const restored = fixture(root, tenant); // New composition over actual retained files.
        assert.equal((await restored.app.fleetLifecycle!.recover(handle.operationId, handle.tenant, handle.agent)).status, "terminal");
        assert.equal(restored.app.fleetLifecycle!.committedTotal(), outcome === "commit" ? 1 : 0);
        assert.equal((await restored.call(restored.parent, "/fleet/settle", { handle, outcome: "release" })).status, 404);
        assert.equal(restored.rows().length, outcome === "commit" ? 1 : 0);
        const terminals = restored.app.spine.verifiedReplay().events.filter(e => e.actor === "fleet-lifecycle" && e.payload["event"] === "fleet.terminal");
        assert.equal(terminals.length, 1);
      });
    }
    test(`KEEP-08B-001 ${tenant ?? "personal"}: ordinary commit/release cannot dispose quarantine`, async () => {
      const f = fixture(mkdtempSync(join(tmpdir(), "keep-settlement-quarantine-")), tenant);
      const admission = await f.call(f.parent, "/fleet/admit", { operationId: "quarantine", capability: "fs.write-draft", args: { target: "quarantine" } });
      const handle = admission.body.result.handle as FleetAdmissionHandle;
      assert.ok(handle);
      f.app.spine.stage({ type: "effect.intent", actor: "fleet-lifecycle", payload: {
        event: "fleet.dispatch-claimed", schema: "keep.fleet-dispatch/v1", ...handle, effectDigest: "0".repeat(64),
      } });
      await f.app.spine.seal();
      assert.equal((await f.app.fleetLifecycle!.inspect(handle.operationId, handle.tenant))?.dispatch, "quarantined");
      for (const outcome of ["commit", "release"]) assert.equal((await f.call(f.parent, "/fleet/settle", { handle, outcome })).status, 404);
      assert.equal((await f.app.fleetLifecycle!.inspect(handle.operationId, handle.tenant))?.dispatch, "quarantined");
      assert.equal(f.app.fleetLifecycle!.active().length, 1);
      assert.equal(f.rows().length, 0);
      assert.equal((await f.call(f.parent, "/fleet/reconcile", { handle, outcome: "commit" })).status, 200);
      assert.equal(f.app.fleetLifecycle!.committedTotal(), 1);
    });
    test(`KEEP-08B-001 ${tenant ?? "personal"}: ordinary claimed commit retains capacity`, async () => {
      const f = fixture(mkdtempSync(join(tmpdir(), "keep-settlement-commit-")), tenant);
      const first = await f.call(f.parent, "/fleet/invoke", f.invocation("claimed"));
      assert.equal(first.status, 409);
      const handle = first.body.admission.handle as FleetAdmissionHandle;
      assert.equal((await f.call(f.parent, "/fleet/settle", { handle, outcome: "invalid" })).status, 400);
      assert.equal((await f.call(f.parent, "/fleet/settle", { handle, outcome: "commit" })).status, 200);
      assert.equal((await f.call(f.parent, "/fleet/invoke", f.invocation("no-capacity"))).body.result.proceed, false);
      assert.equal(f.rows().length, 1);
      assert.equal(f.app.fleetLifecycle!.committedTotal(), 1);
    });
  }
}
