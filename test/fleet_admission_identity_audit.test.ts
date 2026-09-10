import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, openSync, writeSync, fsyncSync, closeSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest } from "../src/gateway/http_gateway.js";
import { OWNER, type Principal } from "../src/identity/rbac.js";
import type { FleetAdmissionRequest } from "../src/fleet/fleet_lifecycle.js";

const person = (tenant?: string): Principal => tenant === undefined ? OWNER : { id: `owner-${tenant}`, tenant, kind: "human", role: "maintainer" };
function fixture(root = mkdtempSync(join(tmpdir(), "keep-admission-identity-"))) {
  const app = composeKeep({ dataDir: join(root, "keep"), fleetLifecycle: { cap: 30, perTenantCap: 15, maxActive: 12, maxActivePerTenant: 6, maxPerBasis: 12, maxPerTenantBasis: 6 },
    developmentProvider: { name: "no-model", isLocal: true, generate: async () => { throw Error("unexpected model call"); }, embed: async () => { throw Error("unexpected embedding call"); } },
  });
  const sink = join(root, "effects.jsonl"), hooks = new Map<string | undefined, () => Promise<void>>();
  for (const tenant of [undefined, "alpha", "beta"]) app.infra.capabilities.register({ descriptor: {
    id: "sink", kind: "connector", name: "synthetic local sink", credentialId: "unused-fixture", trust: "verified",
    ...(tenant === undefined ? {} : { tenant }), fleet: { admissionUnits: 1, resourceDomain: "shared-admission-audit" },
  }, invoke: async inv => {
    const fd = openSync(sink, "a", 0o600);
    try { writeSync(fd, JSON.stringify({ tenant, operation: inv.operation, args: inv.args }) + "\n"); fsyncSync(fd); } finally { closeSync(fd); }
    await hooks.get(tenant)?.();
    return { ok: true };
  } });
  const call = async (tenant: string | undefined, path: string, body: unknown, principal = person(tenant)) => {
    const r = await handleGatewayRequest(app, { method: "POST", path, query: {}, headers: { authorization: "Bearer synthetic" }, body: JSON.stringify(body) },
      { token: "synthetic", ...(tenant === undefined ? {} : { principalFor: () => principal }) });
    return { status: r.status, body: JSON.parse(r.body) };
  };
  const rows = () => existsSync(sink) ? readFileSync(sink, "utf8").trim().split("\n").map(s => JSON.parse(s)) : [];
  return { root, app, hooks, call, rows };
}
const request = (operationId: string, target = operationId) => ({ operationId, capabilityId: "sink", capability: "fs.write-draft", operation: "fs.write-draft", args: { target } });

for (const firstTenant of [undefined, "alpha"] as const) {
  test(`KEEP-08A-001 ${firstTenant ?? "personal"}/beta: equal local IDs do not evade shared-target conflicts`, { timeout: 15_000 }, async () => {
    const f = fixture();
    let entered!: () => void, release!: () => void;
    const entry = new Promise<void>(r => { entered = r; }), hold = new Promise<void>(r => { release = r; });
    f.hooks.set(firstTenant, async () => { entered(); await hold; });
    const first = f.call(firstTenant, "/fleet/invoke", request("same-id", "shared"));
    try {
      await entry;
      for (const id of ["different-id", "same-id"]) {
        const r = await f.call("beta", "/fleet/invoke", request(id, "shared"));
        assert.equal(r.body.result?.proceed, false, JSON.stringify(r));
        assert.ok(r.body.result.reasons.includes("reversibility-conflict"));
        assert.ok(r.body.result.reasons.includes("inverse-reversibility-conflict"));
        assert.ok(r.body.result.reasons.every((reason: string) => !reason.includes(firstTenant ?? "keep.n1.default") && !reason.includes("same-id")));
      }
      assert.equal(f.rows().length, 1, "neither refused call entered the sink");
      // Same local ID in another tenant is legal when its target is independent.
      const independent = await f.call("beta", "/fleet/invoke", request("same-id", "independent"));
      assert.equal(independent.body.effect?.ok, true);
      assert.equal(f.rows().length, 2);
    } finally { release(); await first; }
    assert.equal((await first).body.effect?.ok, true);
    assert.equal((await f.call("beta", "/fleet/invoke", request("after-completion", "shared"))).body.effect?.ok, true);
    assert.equal(f.rows().length, 3);
  });
}

for (const tenant of [undefined, "alpha"] as const) {
  test(`KEEP-08A-002 ${tenant ?? "personal"}: operation-only, equivalent label and reservation contracts`, async () => {
    const f = fixture();
    for (const [id, capability] of [["absent", undefined], ["structured", { id: "FS", operation: "write-draft" }]] as const) {
      const r = await f.call(tenant, "/fleet/admit", { ...request(id), operation: " FS.WRITE-DRAFT ", capability });
      assert.equal(r.body.result?.proceed, true, JSON.stringify(r));
      const normalizedMismatch = await f.app.infra.capabilities.invoke({ capabilityId: "sink", operation: "fs.write-draft", args: { target: id }, auditArgs: "digest" },
        { ...(tenant === undefined ? {} : { tenant }), requireVerified: true, fleetPermit: r.body.result.handle });
      assert.equal(normalizedMismatch.ok, false, "equal classification does not authorize different invocation bytes");
      assert.equal(f.rows().length, id === "absent" ? 0 : 1);
      const effect = await f.app.infra.capabilities.invoke({ capabilityId: "sink", operation: " FS.WRITE-DRAFT ", args: { target: id }, auditArgs: "digest" },
        { ...(tenant === undefined ? {} : { tenant }), requireVerified: true, fleetPermit: r.body.result.handle });
      assert.equal(effect.ok, true);
      assert.equal(await f.app.fleetLifecycle!.commit(r.body.result.handle), true);
    }
    for (const invalid of [{ capabilityId: null }, { capabilityId: 42 }, { capabilityId: "" }, { operation: null }, { operation: undefined }, { args: [] }, { args: null }]) {
      assert.equal((await f.call(tenant, "/fleet/admit", { ...request("invalid"), ...invalid })).status, 400);
    }
    const unknown = await f.call(tenant, "/fleet/admit", { ...request("unknown"), operation: "unknown.op", capability: undefined, confirmed: true, declassify: true });
    assert.equal(unknown.body.result?.proceed, false);
    assert.ok(unknown.body.result.reasons.includes("per-decision-gate-hold"));
    const empty = await f.call(tenant, "/fleet/admit", { ...request("empty"), operation: "", capability: undefined, confirmed: true });
    assert.equal(empty.body.result?.proceed, false);
    assert.ok(empty.body.result.reasons.includes("per-decision-gate-hold"));
    const reservation = await f.call(tenant, "/fleet/admit", { operationId: "reservation", capability: "fs.write-draft", args: { target: "reservation" } });
    assert.equal(reservation.body.result?.proceed, true);
    const notExecutable = await f.app.infra.capabilities.invoke({ capabilityId: "sink", operation: "fs.write-draft", args: { target: "reservation" }, auditArgs: "digest" },
      { ...(tenant === undefined ? {} : { tenant }), requireVerified: true, fleetPermit: reservation.body.result.handle });
    assert.equal(notExecutable.ok, false);
    assert.equal(f.rows().length, 2);
    if (tenant !== undefined) assert.equal((await f.call(tenant, "/fleet/admit", { ...request("observer"), capability: undefined },
      { id: "observer", kind: "human", tenant, role: "viewer" })).status, 403);
  });
  test(`KEEP-08A-002 ${tenant ?? "personal"}: separate admission cannot classify local and bind external`, async () => {
    const f = fixture(), r = await f.call(tenant, "/fleet/admit", { ...request("mismatch"), operation: "email.send", confirmed: true });
    assert.equal(r.status, 400);
    assert.equal(f.app.fleetLifecycle!.active().length, 0);
    assert.equal(f.rows().length, 0);
    assert.equal(f.app.spine.verifiedReplay().events.filter(e => e.payload["event"] === "fleet.admitted").length, 0);
  });
  test(`KEEP-08A-002 ${tenant ?? "personal"}: matching local and declassified external permits remain useful`, async () => {
    const f = fixture();
    for (const operation of ["fs.write-draft", "email.send"]) {
      const external = operation === "email.send", body = { ...request(operation), operation, capability: operation, confirmed: external, declassify: external };
      const r = await f.call(tenant, "/fleet/admit", body);
      assert.equal(r.body.result?.proceed, true, JSON.stringify(r));
      const handle = r.body.result.handle;
      const admitted = f.app.spine.verifiedReplay().events.find(e => e.payload["event"] === "fleet.admitted" && e.payload["operationId"] === operation)!.payload;
      assert.equal(admitted["externalSink"], external);
      assert.equal((admitted["basis"] as Record<string, unknown>)["tool"], operation);
      const effect = await f.app.infra.capabilities.invoke({ capabilityId: "sink", operation, args: body.args, auditArgs: "digest" },
        { ...(tenant === undefined ? {} : { tenant }), requireVerified: true, confirm: external, fleetPermit: handle });
      assert.equal(effect.ok, true);
      assert.equal(await f.app.fleetLifecycle!.commit(handle), true);
    }
    assert.equal(f.rows().length, 2);
    for (const path of ["/fleet/admit", "/fleet/invoke"]) {
      const r = await f.call(tenant, path, { ...request(path.endsWith("admit") ? "tainted-admit" : "tainted-invoke"), operation: "email.send", capability: "email.send", confirmed: true });
      assert.equal(r.body.result?.proceed, false);
      assert.ok(r.body.result.reasons.includes("cross-agent-tainted-sink"));
    }
    assert.equal(f.rows().length, 2);
  });
}

for (const tenant of ["keep.n1.default", "alpha"]) for (const direction of ["forward", "reverse"] as const) {
  test(`KEEP-08A-001 ${tenant}: ${direction} dependency and duplicate checks survive reconstruction`, async () => {
    const f = fixture();
    const direct = (t: string, operationId: string, writeSet: string[], inverseDependsOn: string[]): FleetAdmissionRequest => ({
      tenant: t, operationId, agent: "actor", amount: 1, gateAutoProceed: true, writeSet, inverseDependsOn, externalSink: false,
      provenance: [{ agent: "actor", taint: "trusted", source: "synthetic" }],
      basis: { infrastructure: "test", model: "test", input: "test", retrieval: "test", tool: "test", policy: "test", specification: "test", operator: "test" },
    });
    const original = direct(tenant, "same-id", ["A"], ["A", "B"]);
    const first = await f.app.fleetLifecycle!.admit(original);
    assert.equal(first.proceed, true);
    const restored = fixture(f.root); // Actual persisted admissions, new composition.
    const duplicate = await restored.app.fleetLifecycle!.admit(original);
    assert.equal(duplicate.proceed, false);
    assert.ok(duplicate.reasons.includes("duplicate-operation-id"));
    const incoming = direction === "forward" ? direct("beta", "same-id", ["B"], ["B"]) : direct("beta", "same-id", ["C"], ["C", "A"]);
    const conflict = await restored.app.fleetLifecycle!.admit(incoming);
    assert.equal(conflict.proceed, false);
    assert.ok(conflict.reasons.includes(direction === "forward" ? "reversibility-conflict" : "inverse-reversibility-conflict"));
    for (const invalid of [{ tenant: "beta\0x" }, { operationId: "x\0same-id" }]) {
      const r = await restored.app.fleetLifecycle!.admit({ ...incoming, ...invalid });
      assert.equal(r.proceed, false);
      assert.ok(r.reasons.includes("invalid-fleet-admission"));
    }
    assert.equal((await restored.app.fleetLifecycle!.admit(direct("beta", "same-id", ["D"], ["D"]))).proceed, true);
    assert.equal(restored.app.fleetLifecycle!.active().length, 2);
    assert.equal(restored.rows().length, 0, "component reservation controls do not execute effects");
  });
}
