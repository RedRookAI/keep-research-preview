import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest } from "../src/gateway/http_gateway.js";
import { HmacAssertionProvider, PrincipalRegistry } from "../src/identity/identity_provider.js";
import { SessionStore } from "../src/identity/session_store.js";
import type { Principal } from "../src/identity/rbac.js";
import { RbacAuthorizer } from "../src/identity/rbac.js";
import { DelegationRegistry } from "../src/identity/delegation_registry.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";

// KEEP-04B-001: adapted from the audit's signed-login/shared-gateway reproduction.
// No audit workspace, real account, model provider or HTTP listener is used.
const alpha: Principal = { id: "alice", kind: "human", role: "owner", tenant: "alpha" };
const beta: Principal = { id: "bob", kind: "human", role: "owner", tenant: "beta" };
const parents = [alpha, beta];
const parentFor = (id: string, tenant?: string) => parents.find(p => p.id === id && p.tenant === tenant);

test("KEEP-04B-001 signed foreign management cannot revoke another tenant's grant, live or after restart", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "keep-audit-revoke-"));
  const app = composeKeep({ dataDir, delegationParentFor: parentFor });
  const provider = new HmacAssertionProvider("synthetic-revocation-test-secret");
  const identity = {
    provider,
    registry: new PrincipalRegistry([
      { subject: "alice-sub", id: "alice", role: "owner", tenant: "alpha" },
      { subject: "bob-sub", id: "bob", role: "owner", tenant: "beta" },
      { subject: "viewer-sub", id: "viewer", role: "viewer", tenant: "alpha" },
    ]),
    sessions: new SessionStore(),
  };
  const security = { token: "synthetic-gateway-token", identity };
  const request = async (method: string, path: string, body: unknown, session?: string) => {
    const response = await handleGatewayRequest(app, {
      method, path, query: {},
      headers: { authorization: `Bearer ${security.token}`, ...(session === undefined ? {} : { "x-keep-session": session }) },
      body: JSON.stringify(body),
    }, security);
    await app.spine.seal();
    return { status: response.status, body: JSON.parse(response.body) as Record<string, unknown> };
  };
  const login = async (subject: string): Promise<string> => {
    const result = await request("POST", "/auth/session", { assertion: provider.sign({ sub: subject, exp: Date.now() + 300_000 }) });
    assert.equal(result.status, 200);
    assert.equal(typeof result.body["session"], "string");
    return result.body["session"] as string;
  };
  const alphaSession = await login("alice-sub"), betaSession = await login("bob-sub"), viewerSession = await login("viewer-sub");
  const issue = await request("POST", "/delegation/issue", {
    agentId: "alpha-agent", grantId: "alpha-grant", permissions: ["audit.view"], expiresAt: Date.now() + 300_000,
  }, alphaSession);
  assert.equal(issue.status, 200);
  const agentSession = issue.body["session"] as string;
  const agent = app.authorization.restorePrincipal("alpha-grant")!;
  assert.ok(agent);
  const read = () => request("GET", "/projects", {}, agentSession);
  const revocations = () => app.spine.replay().filter(row => {
    const payload = row.payload as Record<string, unknown>;
    return payload["event"] === "delegation.revoked" && payload["grantId"] === "alpha-grant";
  }).length;
  assert.equal((await read()).status, 200);
  assert.equal((await request("POST", "/delegation/revoke", { grantId: "alpha-grant" }, viewerSession)).status, 403);
  assert.equal((await request("POST", "/delegation/revoke", { grantId: "alpha-grant" }, agentSession)).status, 403);

  const foreign = await request("POST", "/delegation/revoke", { grantId: "alpha-grant", tenant: "alpha" }, betaSession);
  // False is a non-disclosing no-op, matching unknown/already-revoked identifiers.
  assert.equal(foreign.body["revoked"], false, "foreign owner must not mutate a known grant");
  assert.equal(revocations(), 0);
  assert.equal((await read()).status, 200, "the same agent session remains usable");
  assert.equal(app.authorization.authorize(agent, "audit.view").allow, true);

  const restart = (expected: boolean) => {
    // Actual separate process over existing state, not just a new registry object.
    const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
      import assert from 'node:assert/strict';
      import { composeKeep } from ${JSON.stringify(new URL("../src/compose.js", import.meta.url).href)};
      const parents = ${JSON.stringify(parents)};
      const app = composeKeep({dataDir: process.argv[1], delegationParentFor: (id, tenant) => parents.find(p => p.id === id && p.tenant === tenant)});
      const restored = app.authorization.restorePrincipal('alpha-grant');
      assert.equal(restored !== undefined, ${expected});
      const authorized = app.authorization.authorize(${JSON.stringify(agent)}, 'audit.view').allow;
      assert.equal(authorized, ${expected});
      console.log(JSON.stringify({restored: restored !== undefined, authorized}));
    `, dataDir], { encoding: "utf8", timeout: 15_000, maxBuffer: 64 * 1024 });
    assert.equal(child.status, 0, child.stderr);
    assert.deepEqual(JSON.parse(child.stdout), { restored: expected, authorized: expected });
  };
  restart(true);
  const authorized = await request("POST", "/delegation/revoke", { grantId: "alpha-grant" }, alphaSession);
  assert.equal(authorized.body["revoked"], true);
  assert.equal(revocations(), 1);
  assert.equal((await read()).status, 403);
  assert.ok(identity.sessions.get(agentSession, Date.now()), "revocation acts on authority, not by deleting the session");
  assert.equal((await request("POST", "/delegation/revoke", { grantId: "alpha-grant" }, alphaSession)).body["revoked"], false);
  assert.equal((await request("POST", "/delegation/revoke", { grantId: "unknown" }, betaSession)).body["revoked"], false);
  assert.equal(revocations(), 1);
  restart(false);
  await assert.rejects(app.authorization.issue(alpha, "replacement", ["audit.view"], Date.now() + 300_000, Date.now(), "alpha-grant"), /revoked/);
  const fresh = await request("POST", "/delegation/issue", {
    agentId: "alpha-agent-2", grantId: "alpha-grant-2", permissions: ["audit.view"], expiresAt: Date.now() + 300_000,
  }, alphaSession);
  assert.equal(fresh.status, 200);
  assert.equal((await request("GET", "/projects", {}, fresh.body["session"] as string)).status, 200, "revocation does not prevent a legitimate new grant");
});

test("KEEP-04B-001 scoped revocation keeps tenantless, expired and trusted host behavior distinct", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-revoke-scopes-"));
  const local: Principal = { id: "local", kind: "human", role: "owner" };
  const viewer: Principal = { id: "viewer", kind: "human", role: "viewer", tenant: "alpha" };
  const directory = [alpha, beta, local, viewer];
  let now = 1_000;
  const spine = new Spine(new FileSpineStore(root, { fsync: true }), new InProcessLock(), new SchemaRegistry());
  const registry = new DelegationRegistry(new RbacAuthorizer(), spine,
    (id, tenant) => directory.find(p => p.id === id && p.tenant === tenant), () => now);
  const agent = await registry.issue(alpha, "a", ["audit.view"], 1_100, now, "tenant-grant");
  await registry.issue(local, "l", ["audit.view"], 1_100, now, "local-grant");
  const before = spine.replay().length;
  for (const caller of [beta, local, viewer, agent, { ...alpha, tenant: null } as unknown as Principal, { ...alpha, tenant: "" }]) {
    assert.equal(await registry.revokeFor(caller, "tenant-grant"), false);
  }
  assert.equal(await registry.revokeFor(alpha, "local-grant"), false);
  await assert.rejects(registry.issue({ ...alpha, tenant: null } as unknown as Principal, "invalid", ["audit.view"], 1_100, now, "invalid-tenant"), /valid human parent/);
  assert.equal(spine.replay().length, before, "registry no-ops do not write target events");
  assert.equal(registry.authorize(agent, "audit.view").allow, true);
  assert.equal(await registry.revokeFor(local, "local-grant"), true);
  assert.equal(await registry.revokeFor(local, "local-grant"), false);
  now = 1_100;
  assert.equal(registry.authorize(agent, "audit.view").allow, false);
  assert.equal(await registry.revokeFor(alpha, "tenant-grant"), true, "expiry does not prevent durable revocation");
  now = 1_000;
  assert.equal(registry.authorize(agent, "audit.view").allow, false, "clock rollback cannot resurrect a tombstoned grant");
  await registry.issue(local, "trusted", ["audit.view"], 1_100, now, "trusted-grant");
  assert.equal(await registry.revoke("trusted-grant"), true, "trusted host API remains available without tenant impersonation");
});

test("KEEP-04B-001 lock wait captures caller identity but rechecks current authority", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-revoke-lock-"));
  const spine = new Spine(new FileSpineStore(root, { fsync: true }), new InProcessLock(), new SchemaRegistry());
  let liveAlpha: Principal | undefined = alpha;
  const registry = new DelegationRegistry(new RbacAuthorizer(), spine, (id, tenant) => {
    if (id === alpha.id && tenant === alpha.tenant) return liveAlpha;
    return parentFor(id, tenant);
  });
  const agent = await registry.issue(alpha, "a", ["audit.view"], Date.now() + 300_000, Date.now(), "grant");
  const queued = async (caller: Principal, change: () => void) => {
    let release!: () => void, entered!: () => void;
    const ready = new Promise<void>(resolve => { entered = resolve; });
    const barrier = new Promise<void>(resolve => { release = resolve; });
    const holder = spine.withCoordinationLock("identity.delegation", async () => { entered(); await barrier; });
    await ready;
    const result = registry.revokeFor(caller, "grant");
    try { change(); } finally { release(); }
    await holder;
    return result;
  };
  const mutable = { ...beta };
  assert.equal(await queued(mutable, () => { mutable.id = "alice"; mutable.tenant = "alpha"; }), false);
  assert.equal(registry.authorize(agent, "audit.view").allow, true);
  assert.equal(await queued(alpha, () => { liveAlpha = { ...alpha, role: "viewer" }; }), false);
  liveAlpha = alpha;
  assert.equal(await queued(alpha, () => { liveAlpha = undefined; }), false);
  liveAlpha = alpha;
  assert.deepEqual(await Promise.all([
    registry.revokeFor(beta, "grant"), registry.revokeFor(alpha, "grant"), registry.revokeFor(alpha, "grant"),
  ]), [false, true, false]);
  assert.equal(spine.replay().filter(row => (row.payload as Record<string, unknown>)["event"] === "delegation.revoked").length, 1);
});
