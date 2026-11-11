/** Authenticated local memory controls and canonical resource-owned evidence; no live issuer or erasure certification. */
import test, { type TestContext } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { composeKeep } from "../src/compose.js";
import { HmacAssertionProvider, PrincipalRegistry } from "../src/identity/identity_provider.js";
import { SessionStore } from "../src/identity/session_store.js";
import { handleGatewayRequest } from "../src/gateway/http_gateway.js";
import { exportTenantAudit } from "../src/audit/tenant_audit_export.js";
import { FileMemoryPartition, type FileMemoryPartitionOptions, type MemoryControlActor } from "../src/memory/persistence.js";
import { deliverMemoryAdmissions } from "../src/memory/memory_tools.js";

const token = "synthetic-memory-evidence", controlNames = new Set(["memory.hold.changed", "memory.erasure.requested", "memory.erasure.key-revoked"]);
function fixture(t: TestContext) {
  const root = mkdtempSync(join(tmpdir(), "keep-tenant-memory-evidence-")); t.after(() => rmSync(root, { recursive: true, force: true }));
  const mappings = [{ subject: "alice", id: "alice", role: "owner" as const, tenant: "alpha" }, { subject: "bob", id: "bob", role: "owner" as const, tenant: "beta" },
    { subject: "viewer", id: "viewer", role: "viewer" as const, tenant: "alpha" }, { subject: "operator", id: "operator", role: "operator" as const, tenant: "alpha" }];
  const identity = { provider: new HmacAssertionProvider("synthetic-evidence-secret"), registry: new PrincipalRegistry(mappings), sessions: new SessionStore() };
  let providerCalls = 0;
  const app = composeKeep({ dataDir: join(root, "state"), identity, delegationParentFor: (id, tenant) => identity.registry.resolveReference(id, tenant),
    developmentProvider: { name: "local-evidence-fixture", isLocal: true, async embed(texts) { providerCalls++; return texts.map(() => [1]); }, async generate() { providerCalls++; throw Error("unexpected generation"); } } });
  const route = (sid?: string) => (method: string, path: string, body?: unknown, query: Record<string, string> = {}) => handleGatewayRequest(app,
    { method, path, body: body === undefined ? "" : JSON.stringify(body), query, headers: { authorization: `Bearer ${token}`, ...(sid ? { "x-keep-session": sid } : {}) } }, { token, identity });
  const login = async (subject: string) => { const response = await route()("POST", "/auth/session", { assertion: identity.provider.sign({ sub: subject, exp: Date.now() + 60000 }) }); assert.equal(response.status, 200); return route(JSON.parse(response.body).session); };
  return { root, app, identity, route, login, calls: () => providerCalls };
}

test("authenticated tenant controls export their resource scope; cross-tenant and RBAC refusals cause no control effect", async t => {
  const f = fixture(t), alice = await f.login("alice"), bob = await f.login("bob"), viewer = await f.login("viewer"), operator = await f.login("operator");
  const project = f.app.projectManager!.create({ name: "alpha project", tenant: "alpha" }), other = f.app.projectManager!.create({ name: "beta project", tenant: "beta" });
  const target = { scope: "project", projectId: project.id }, otherTarget = { scope: "project", projectId: other.id };
  assert.equal((await alice("POST", "/memory/durable/init", { target, retain: true })).status, 200);
  assert.equal((await bob("POST", "/memory/durable/init", { target: otherTarget, retain: true })).status, 200);
  const stored = await alice("POST", "/memory/durable", { target, operationId: "store", command: { action: "store", content: "alpha private source", processing: "source-only" } }); assert.equal(stored.status, 200, stored.body); const id = JSON.parse(stored.body).result.id;
  const betaStored = await bob("POST", "/memory/durable", { target: otherTarget, operationId: "store", command: { action: "store", content: "beta private source", processing: "source-only" } }); assert.equal(betaStored.status, 200);
  const partition = f.app.memoryCustody.partition({ ownerId: `project:${project.id}`, kind: "project", projectId: project.id, tenantId: "alpha" });
  const before = partition.admissionEvents();
  assert.equal((await bob("GET", "/memory/durable", undefined, { ...target, action: "review", id })).status, 403);
  assert.equal((await bob("POST", "/memory/durable", { target, operationId: "foreign-erase", command: { action: "erase", id } })).status, 403);
  assert.equal((await alice("POST", "/memory/durable", { target: { ...target, tenantId: "beta", ownerId: "bob" }, operationId: "forged", command: { action: "erase", id } })).status, 400);
  for (const reader of [viewer, operator]) {
    assert.equal((await reader("GET", "/memory/durable", undefined, { ...target, action: "review", id })).status, 200);
    assert.equal((await reader("POST", "/memory/durable", { target, operationId: "denied-hold", command: { action: "hold", id, holdId: "case", active: true } })).status, 403);
    assert.equal((await reader("POST", "/memory/durable", { target, operationId: "denied-erase", command: { action: "erase", id } })).status, 403);
  }
  assert.deepEqual(partition.admissionEvents(), before); assert.equal(partition.read().entries.length, 1);
  const hold = await alice("POST", "/memory/durable", { target, tenant: "beta", actorId: "forged", operationId: "hold", command: { action: "hold", id, holdId: "case", active: true } }); assert.equal(hold.status, 200);
  const blocked = await alice("POST", "/memory/durable", { target, operationId: "erase-blocked", command: { action: "erase", id } }); assert.equal(blocked.status, 409); assert.equal(partition.read().entries.length, 1);
  assert.equal((await alice("POST", "/memory/durable", { target, operationId: "release", command: { action: "hold", id, holdId: "case", active: false } })).status, 200);
  const eraseBody = { target, operationId: "erase", command: { action: "erase", id } };
  assert.equal((await alice("POST", "/memory/durable", eraseBody)).status, 200); assert.equal(partition.read().entries.length, 0);
  const exported = await alice("GET", "/audit/export", undefined, { tenant: "beta" }); assert.equal(exported.status, 200);
  const rows = JSON.parse(exported.body).rows.filter((e: { payload: Record<string, unknown> }) => controlNames.has(String(e.payload.event)));
  assert.deepEqual(rows.map((e: { payload: Record<string, unknown> }) => e.payload.event), ["memory.hold.changed", "memory.hold.changed", "memory.erasure.requested", "memory.erasure.key-revoked"]);
  for (const row of rows) { assert.equal(row.payload.tenant, "alpha"); assert.equal(row.payload.ownerId, `project:${project.id}`); assert.equal(row.payload.projectId, project.id); assert.equal(row.payload.actorId, "alice"); assert.equal(Object.hasOwn(row.payload, "agentId"), false); }
  const replay = await alice("POST", "/memory/durable", eraseBody); assert.equal(replay.status, 200); assert.equal(JSON.parse(replay.body).reconciled, true);
  assert.deepEqual(exportTenantAudit(f.app.spine, "alpha").filter(e => controlNames.has(String(e.payload.event))), rows);
  assert.equal(exportTenantAudit(f.app.spine, "beta").filter(e => controlNames.has(String(e.payload.event))).length, 0);
  assert.equal((await bob("GET", "/memory/durable", undefined, { ...otherTarget, action: "review", id: JSON.parse(betaStored.body).result.id })).status, 200);
  assert.equal(f.calls(), 0, "source-only fixture has no model effects");
  await f.app.spine.seal();
  const child = JSON.parse(execFileSync(process.execPath, ["--input-type=module", "-e", `import {composeKeep} from ${JSON.stringify(new URL("../src/compose.js", import.meta.url).href)};import {exportTenantAudit} from ${JSON.stringify(new URL("../src/audit/tenant_audit_export.js", import.meta.url).href)};const app=composeKeep({dataDir:process.argv[1]});console.log(JSON.stringify(exportTenantAudit(app.spine,'alpha').filter(e=>String(e.payload.event).startsWith('memory.hold.')||String(e.payload.event).startsWith('memory.erasure.'))));`, join(f.root, "state")], { encoding: "utf8", timeout: 10000 }));
  assert.deepEqual(child, rows);
});

test("agent erasure preserves original agent kind and full resource-owned partition labels", async t => {
  const f = fixture(t), alice = await f.login("alice"), target = { scope: "agent", agentId: "worker" };
  assert.equal((await alice("POST", "/memory/durable/init", { target, retain: true })).status, 200);
  const stored = await alice("POST", "/memory/durable", { target, operationId: "store", command: { action: "store", content: "agent owned source", processing: "source-only" } }); assert.equal(stored.status, 200);
  const principal = f.identity.registry.resolveReference("alice", "alpha")!, agent = await f.app.authorization.issue(principal, "worker", ["memory.read", "memory.forget", "config.write"], Date.now() + 60000);
  const session = f.identity.sessions.create(agent, Date.now()), route = f.route(session.id), id = JSON.parse(stored.body).result.id;
  assert.equal((await route("POST", "/memory/durable", { target, operationId: "agent-hold", command: { action: "hold", id, holdId: "case", active: true } })).status, 403, "registered holds retain their human authority requirement");
  assert.equal((await route("POST", "/memory/durable", { target, operationId: "agent-erase", command: { action: "erase", id } })).status, 200);
  const rows = exportTenantAudit(f.app.spine, "alpha").filter(e => String(e.payload.event).startsWith("memory.erasure.")); assert.equal(rows.length, 2);
  for (const row of rows) { assert.equal(row.payload.actorId, "worker"); assert.equal(row.payload.actorKind, "agent"); assert.equal(row.payload.ownerId, "alice"); assert.equal(row.payload.agentId, "worker"); assert.equal(row.payload.tenant, "alpha"); assert.equal(Object.hasOwn(row.payload, "projectId"), false); }
});

test("personal controls stay unlabelled and visible in the existing local full audit export", async t => {
  const root = mkdtempSync(join(tmpdir(), "keep-personal-memory-evidence-")); t.after(() => rmSync(root, { recursive: true, force: true })); const app = composeKeep({ dataDir: root });
  const route = (path: string, body: unknown) => handleGatewayRequest(app, { method: "POST", path, query: {}, body: JSON.stringify(body), headers: { authorization: `Bearer ${token}` } }, { token });
  const target = { scope: "user" }; assert.equal((await route("/memory/durable/init", { target, retain: true })).status, 200);
  const stored = await route("/memory/durable", { target, operationId: "store", command: { action: "store", content: "personal source", processing: "source-only" } }); assert.equal(stored.status, 200);
  assert.equal((await route("/memory/durable", { target, operationId: "erase", command: { action: "erase", id: JSON.parse(stored.body).result.id } })).status, 200);
  const rows = exportTenantAudit(app.spine).filter(e => controlNames.has(String(e.payload.event))); assert.equal(rows.length, 2);
  for (const row of rows) { assert.equal(Object.hasOwn(row.payload, "tenant"), false); assert.equal(Object.hasOwn(row.payload, "projectId"), false); assert.equal(Object.hasOwn(row.payload, "agentId"), false); assert.equal(row.payload.ownerId, "owner"); assert.equal(row.payload.actorId, "owner"); }
  assert.equal(exportTenantAudit(app.spine, "alpha").filter(e => controlNames.has(String(e.payload.event))).length, 0);
});

test("interrupted erasure resumes in a fresh process with the original actor and resource scope, then exports once", async t => {
  const f = fixture(t), scope = { ownerId: "alice", kind: "agent" as const, tenantId: "alpha", projectId: "project-alpha", agentId: "worker" };
  const options: FileMemoryPartitionOptions = { directory: join(f.root, "partition"), scope, keyAuthority: { masterKeyPath: join(f.root, "master.key"), wrappedKeysPath: join(f.root, "wrapped.json") } };
  writeFileSync(options.keyAuthority.masterKeyPath, randomBytes(32), { flag: "wx", mode: 0o600 });
  const partition = new FileMemoryPartition(options); partition.initialize();
  assert.equal(partition.commit("seed", 0, [{ lesson: { id: "item", content: "private fixture source", tier: "candidate", origin: "self", provenanceEventId: "fixture-source", scope: "agent", kind: "fact", importance: 0.5, evidence: [], createdTs: 1, validFrom: 1 }, embedding: [1], access: { count: 0, lastAccessedTs: 1 } }]).disposition, "committed");
  const actor: MemoryControlActor = { actorId: "original-agent", actorKind: "agent", role: "agent", permission: "memory.forget" };
  const faulted = new FileMemoryPartition({ ...options, fault: point => { if (point === "after-key-revocation") throw Error("injected interruption"); } });
  assert.equal(faulted.controlCommand("erase-original", { action: "erase", id: "item" }, actor).disposition, "held");
  const pending = partition.admissionEvents().find(e => e.payload.event === "memory.erasure.requested")!;
  const child = JSON.parse(execFileSync(process.execPath, ["--input-type=module", "-e", `import {FileMemoryPartition} from ${JSON.stringify(new URL("../src/memory/persistence.js", import.meta.url).href)};const p=new FileMemoryPartition(JSON.parse(process.argv[1]));const result=p.controlCommand('erase-original',{action:'erase',id:'item'},{actorId:'recovery-carrier',actorKind:'human',role:'owner',permission:'memory.forget'});console.log(JSON.stringify({result,events:p.admissionEvents(),view:p.read()}));`, JSON.stringify(options)], { encoding: "utf8", timeout: 10000 }));
  assert.equal(child.result.disposition, "committed"); assert.equal(child.result.reconciled, true); assert.equal(child.view.entries.length, 0);
  const controls = child.events.filter((e: { payload: Record<string, unknown> }) => controlNames.has(String(e.payload.event))); assert.equal(controls.length, 2);
  assert.equal(controls[0].id, pending.id); for (const row of controls) { assert.equal(row.payload.actorId, "original-agent"); assert.equal(row.payload.actorKind, "agent"); assert.equal(row.payload.tenant, "alpha"); assert.equal(row.payload.projectId, "project-alpha"); assert.equal(row.payload.agentId, "worker"); assert.equal(row.payload.ownerId, "alice"); }
  assert.equal(await deliverMemoryAdmissions(partition, f.app.spine), "delivered"); const exported = exportTenantAudit(f.app.spine, "alpha").filter(e => controlNames.has(String(e.payload.event))); assert.equal(exported.length, 2);
  assert.equal(await deliverMemoryAdmissions(partition, f.app.spine), "delivered"); assert.deepEqual(exportTenantAudit(f.app.spine, "alpha").filter(e => controlNames.has(String(e.payload.event))), exported);
});
