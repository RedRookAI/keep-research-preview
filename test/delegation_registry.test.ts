import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest, type GatewayRequest } from "../src/gateway/http_gateway.js";
import { DelegationRegistry } from "../src/identity/delegation_registry.js";
import { RbacAuthorizer, type AuthorizationPort, type AuthzDecision, type Permission, type Principal } from "../src/identity/rbac.js";
import { InProcessLock } from "../src/lock/lock.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";

const human: Principal = { id: "alice", kind: "human", role: "maintainer", tenant: "acme" };
const resolveHuman = (id: string, tenant?: string): Principal | undefined => id === human.id && tenant === human.tenant ? human : undefined;
const spineAt = (root: string) => new Spine(new FileSpineStore(root, { fsync: true }), new InProcessLock(), new SchemaRegistry());

test("TEAM-03 issued grants are attenuated, tenant-bound, expiring, and structurally unforgeable", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-delegation-issued-")), delegationParentFor: resolveHuman });
  const now = Date.now();
  const agent = await app.authorization.issue(human, "agent-1", ["change.solve", "memory.read", "review.approve", "rbac.admin", "adaptation.manage"], now + 60_000, now, "grant-1");
  assert.equal(agent.tenant, "acme"); assert.equal(agent.delegatedBy, "alice");
  assert.equal(app.authorization.authorize(agent, "change.solve").allow, true);
  assert.equal(app.authorization.authorize(agent, "memory.read").allow, true);
  assert.equal(app.authorization.authorize(agent, "review.approve").allow, false);
  assert.equal(app.authorization.authorize(agent, "rbac.admin").allow, false);
  assert.equal(app.authorization.authorize(agent, "adaptation.manage").allow, false);
  assert.equal(app.authorization.authorize({ id: "agent-1", kind: "agent", role: "agent", tenant: "acme" }, "change.solve").allow, false, "an agent role is not issuance evidence");
  assert.equal(app.authorization.authorize({ id: "service", kind: "service", role: "agent", tenant: "acme" }, "change.solve").allow, false);
  assert.equal(app.authorization.authorize({ id: "service", kind: "service", role: "owner", tenant: "acme" }, "rbac.admin").allow, false);
  assert.equal(app.authorization.attribution({ id: "service", kind: "service", role: "agent", tenant: "acme" }), undefined);
  for (const forged of [{ ...agent, delegatedBy: "mallory" }, { ...agent, tenant: "beta" }, { ...agent, grantId: "invented" }, { ...agent, role: "owner" }]) {
    assert.equal(app.authorization.authorize(forged as Principal, "change.solve").allow, false);
  }
});

test("TEAM-03 grant and revocation survive restart while expiry and live-parent tightening fail closed", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-delegation-restart-"));
  let now = 1_000;
  class MutableAuthorizer implements AuthorizationPort {
    allow = true;
    authorize(_principal: Principal, _action: Permission): AuthzDecision { return { allow: this.allow, reason: this.allow ? "allowed" : "revoked" }; }
  }
  const base = new MutableAuthorizer();
  let liveParent: Principal | undefined = human;
  const resolveParent = () => liveParent;
  const first = new DelegationRegistry(base, spineAt(root), resolveParent, () => now);
  const issued = await first.issue(human, "agent-2", ["change.solve"], 2_000, now, "grant-restart");
  const restarted = new DelegationRegistry(base, spineAt(root), resolveParent, () => now);
  assert.deepEqual(restarted.restorePrincipal("grant-restart"), issued);
  base.allow = false;
  assert.equal(restarted.authorize(issued, "change.solve").allow, false, "parent policy tightening applies without reissuance");
  base.allow = true; now = 2_000;
  assert.equal(restarted.authorize(issued, "change.solve").allow, false);
  now = 1_500;
  liveParent = undefined;
  assert.equal(restarted.authorize(issued, "change.solve").allow, false, "parent removal applies without reissuance");
  liveParent = human;
  assert.equal(await restarted.revoke("grant-restart"), true);
  assert.equal(new DelegationRegistry(base, spineAt(root), resolveParent, () => now).restorePrincipal("grant-restart"), undefined);
});

test("TEAM-03 default RBAC rechecks a live parent role rather than the issuance snapshot", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-delegation-live-parent-"));
  let live: Principal | undefined = human;
  const registry = new DelegationRegistry(new RbacAuthorizer(), spineAt(root), () => live);
  const now = Date.now();
  const issued = await registry.issue(human, "agent-live", ["memory.write"], now + 60_000, now, "grant-live");
  assert.equal(registry.authorize(issued, "memory.write").allow, true);
  live = { ...human, role: "viewer" };
  assert.equal(registry.authorize(issued, "memory.write").allow, false);
  live = undefined;
  assert.equal(registry.authorize(issued, "memory.write").allow, false);
});

test("TEAM-03 malformed, duplicate, and resurrected durable delegation evidence fails closed", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-delegation-hostile-"));
  const spine = spineAt(root);
  spine.stage({ type: "identity.action", actor: "delegation", payload: { event: "delegation.revoked", grantId: "never-issued" } });
  await spine.seal();
  const afterUnknownRevocation = new DelegationRegistry(new RbacAuthorizer(), spineAt(root), resolveHuman);
  await assert.rejects(afterUnknownRevocation.issue(human, "agent", ["change.solve"], Date.now() + 60_000, Date.now(), "never-issued"), /revoked/);

  const duplicateRoot = mkdtempSync(join(tmpdir(), "keep-delegation-duplicate-"));
  const registry = new DelegationRegistry(new RbacAuthorizer(), spineAt(duplicateRoot), resolveHuman);
  const now = Date.now();
  await registry.issue(human, "agent", ["change.solve"], now + 60_000, now, "same");
  await assert.rejects(registry.issue(human, "agent", ["change.solve"], now + 60_000, now, "same"), /already exists/);
  assert.equal(await registry.revoke("same"), true);
  await assert.rejects(registry.issue(human, "agent", ["change.solve"], now + 60_000, now, "same"), /revoked/);
  assert.equal(new DelegationRegistry(new RbacAuthorizer(), spineAt(duplicateRoot), resolveHuman).restorePrincipal("same"), undefined, "rejected resurrection does not poison durable state");
});

test("TEAM-03 malformed or foreign delegation-like rows cannot poison an unrelated valid grant", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-delegation-row-local-"));
  const spine = spineAt(root);
  const registry = new DelegationRegistry(new RbacAuthorizer(), spine, resolveHuman);
  const now = Date.now();
  const valid = await registry.issue(human, "good-agent", ["change.solve"], now + 60_000, now, "good-grant");
  spine.stage({ type: "identity.action", actor: "gateway", payload: { event: "delegation.revoked", grantId: "good-grant" } });
  spine.stage({ type: "identity.action", actor: "delegation", payload: { event: "delegation.issued", grantId: "bad-grant" } });
  await spine.seal();
  const restarted = new DelegationRegistry(new RbacAuthorizer(), spineAt(root), resolveHuman);
  assert.equal(restarted.authorize(valid, "change.solve").allow, true);
  assert.ok(restarted.restorePrincipal("good-grant"));
  await assert.rejects(restarted.issue(human, "bad", ["change.solve"], now + 60_000, now, "bad-grant"), /revoked/);
});

test("TEAM-03 a post-seal issuance verification failure durably compensates instead of leaving a ghost grant", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-delegation-compensate-"));
  const durable = spineAt(root);
  let verifies = 0;
  const flaky = {
    durableStorage: () => durable.durableStorage(),
    verify: () => (++verifies === 4 ? { ok: false } : durable.verify()),
    replay: () => durable.replay(),
    stage: (value: Parameters<Spine["stage"]>[0]) => durable.stage(value),
    seal: () => durable.seal(),
    withCoordinationLock: <T>(key: string, fn: () => Promise<T>) => durable.withCoordinationLock(key, fn),
  } as unknown as Spine;
  const registry = new DelegationRegistry(new RbacAuthorizer(), flaky, resolveHuman);
  const now = Date.now();
  await assert.rejects(registry.issue(human, "ghost-agent", ["change.solve"], now + 60_000, now, "ghost-grant"), /verified after sealing/);
  const restarted = new DelegationRegistry(new RbacAuthorizer(), spineAt(root), resolveHuman);
  assert.equal(restarted.restorePrincipal("ghost-grant"), undefined);
  await assert.rejects(restarted.issue(human, "ghost-agent", ["change.solve"], now + 60_000, now, "ghost-grant"), /revoked/);
});

test("TEAM-03 the real gateway records valid human-agent-grant attribution and denies forged identities", async () => {
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-delegation-gateway-")),
    delegationParentFor: resolveHuman,
    solve: async (issue) => ({ solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0 } }) as never,
  });
  const now = Date.now();
  const agent = await app.authorization.issue(human, "agent-gateway", ["change.solve", "review.view"], now + 60_000, now, "grant-gateway");
  const request: GatewayRequest = { method: "POST", path: "/project", query: {}, headers: { authorization: "Bearer token" }, body: JSON.stringify({ goal: "bounded delegated task", stepBudget: 1 }) };
  assert.equal((await handleGatewayRequest(app, request, { token: "token", principalFor: () => agent })).status, 200);
  const actions = app.spine.currentEvents().map((event) => event.payload as Record<string, unknown>).filter((payload) => payload["event"] === "principal.action");
  assert.ok(actions.some((row) => row["humanPrincipalId"] === "alice" && row["agentPrincipalId"] === "agent-gateway" && row["grantId"] === "grant-gateway" && row["tenant"] === "acme"));
  const before = actions.length;
  assert.equal((await handleGatewayRequest(app, request, { token: "token", principalFor: () => ({ ...agent, grantId: "fake" }) })).status, 403);
  assert.equal(app.spine.currentEvents().filter((event) => (event.payload as Record<string, unknown>)["event"] === "principal.action").length, before);
  const message: GatewayRequest = { ...request, path: "/message", body: JSON.stringify({ message: "continue safely" }) };
  assert.equal((await handleGatewayRequest(app, message, { token: "token", principalFor: () => ({ id: "unissued", kind: "agent", role: "agent", tenant: "acme" }) })).status, 403);
  const messageResponse = await handleGatewayRequest(app, message, { token: "token", principalFor: () => agent });
  assert.ok(messageResponse.status === 200 || messageResponse.status === 501, "a valid issued identity reaches the configured-capability boundary");
  assert.ok(app.spine.currentEvents().some((event) => { const row = event.payload as Record<string, unknown>; return row["event"] === "principal.action" && row["action"] === "review.view" && row["agentPrincipalId"] === "agent-gateway" && row["grantId"] === "grant-gateway"; }));
});
