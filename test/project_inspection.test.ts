import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest } from "../src/gateway/http_gateway.js";
import { buildAutonomyLoop } from "../src/autonomy/autonomy_loop.js";
import { InMemoryProjectCheckpointStore } from "../src/autonomy/project_checkpoint_store.js";
import { ProjectRegistry } from "../src/session/project_registry.js";
import { ProjectSessionManager } from "../src/session/project_session_manager.js";
import { FileProjectSessionPersistence } from "../src/session/project_session_persistence.js";
import { ProjectSessionConflictError } from "../src/session/project_session_persistence.js";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import { KeepClient, KeepClientError } from "../src/client/client_core.js";
import { GovernedLocalMerge } from "../src/solve/governed_local_merge.js";

for (const tenant of [undefined, "alpha"]) test(`gateway reports read conflicts without replay (${tenant ?? "personal"})`, async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-gateway-read-race-")), base = composeKeep({ dataDir: join(root, "app") });
  const registry = new ProjectRegistry(new CryptoShredKeyStore());
  const store = new FileProjectSessionPersistence(join(root, "session.json"));
  const manager = new ProjectSessionManager(registry, undefined, () => store);
  const record = manager.create({ name: "read race", ...(tenant ? { tenant } : {}) });
  manager.session(record.id).bindRun("existing-run");
  const sibling = new ProjectSessionManager(registry, undefined, () => store);
  const lookup = manager.session.bind(manager); let armed = false, mutations = 0, executions = 0;
  manager.session = id => {
    const old = lookup(id);
    if (armed) { armed = false; mutations++; sibling.session(id).append("user", "new sibling information"); }
    return old;
  };
  const unexpected = async (): Promise<never> => { executions++; throw new Error("lookup failure must not dispatch work"); };
  const projectMerge = new GovernedLocalMerge({ spine: base.spine, checkpoints: new InMemoryProjectCheckpointStore(),
    identityRegistry: base.identityRegistry, rootIdentity: base.identityRegistry.mint("read-race", ["."]),
    projectDir: () => root, baseBranch: "main" });
  projectMerge.decide = unexpected; projectMerge.revert = unexpected;
  const app = { ...base, projectManager: manager, projectMerge,
    autonomyLoop: { ...base.autonomyLoop!, manager, resumeManagedProject: unexpected } };
  const token = "synthetic-read-race", security = { token,
    ...(tenant ? { principalFor: () => ({ id: "alpha-owner", tenant, kind: "human" as const, role: "owner" as const }) } : {}) };
  for (const path of ["/project", "/projects", "/project/resume", "/project/merge", "/project/revert"]) {
    armed = true;
    const response = await handleGatewayRequest(app, { method: path === "/project" || path === "/projects" ? "GET" : "POST", path,
      query: { runId: "existing-run" }, headers: { authorization: `Bearer ${token}` },
      body: JSON.stringify({ runId: "existing-run", decision: "approve", proposalDigest: "a".repeat(64) }) }, security);
    assert.equal(response.status, 409, `${path}: ${response.body}`);
    const body = JSON.parse(response.body); assert.equal(body.code, "project-state-conflict");
    assert.equal(body.replayTask, false); assert.equal(response.body.includes(root), false);
  }
  assert.equal(mutations, 5); assert.equal(executions, 0);
  const healthy = await handleGatewayRequest(app, { method: "GET", path: "/projects", query: {},
    headers: { authorization: `Bearer ${token}` }, body: "" }, security);
  assert.equal(healthy.status, 200, healthy.body);
  assert.equal(lookup(record.id).history().length, 5);
});

for (const tenant of [undefined, "alpha"]) test(`project inspection uses one session/checkpoint view (${tenant ?? "personal"})`, async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-inspection-"));
  const base = composeKeep({ dataDir: join(root, "app") });
  const registry = new ProjectRegistry(new CryptoShredKeyStore());
  const store = new FileProjectSessionPersistence(join(root, "session.json"));
  const checkpoints = new InMemoryProjectCheckpointStore();
  let loads = 0;
  const port = { load: (id: string) => { loads++; return checkpoints.load(id); }, save: checkpoints.save.bind(checkpoints) };
  let sessionLoads = 0;
  const sessionPort = { load: () => { sessionLoads++; return store.load(); }, save: store.save.bind(store) };
  const manager = new ProjectSessionManager(registry, undefined, () => sessionPort, port);
  const project = manager.create({ name: "inspection", ...(tenant === undefined ? {} : { tenant }), budget: { spentTokensToday: 2, dailyTokenCap: 100 } });
  const loop = buildAutonomyLoop({ spine: base.spine, manager, checkpoints: port,
    solve: async () => { throw new Error("not a model test"); } });
  const result = await loop.runManagedProject(project.id, "write and test a local parser", { runId: "inspected-run", stepBudget: 1 });
  const app = { ...base, projectManager: manager, autonomyLoop: loop };
  const original = manager.session.bind(manager); let lookups = 0;
  manager.session = id => {
    lookups++;
    if (lookups === 3) {
      const next = { ...result.state, revision: result.state.revision + 1, note: "new sibling checkpoint" };
      checkpoints.save(next, result.state.revision);
      const sibling = new ProjectSessionManager(registry, undefined, () => store, port).session(id);
      sibling.checkpoint(next); sibling.spend(7); sibling.append("user", "new sibling history");
    }
    return original(id);
  };
  loads = 0; sessionLoads = 0;
  const token = "synthetic-inspection-token";
  const response = await handleGatewayRequest(app, { method: "GET", path: "/project", query: { runId: result.state.runId },
    headers: { authorization: `Bearer ${token}` }, body: "" }, { token,
    ...(tenant === undefined ? {} : { principalFor: () => ({ id: "alpha-owner", tenant, kind: "human" as const, role: "owner" as const }) }) });
  assert.equal(response.status, 200, response.body);
  const body = JSON.parse(response.body);
  assert.deepEqual(body.project, body.session.checkpoint, "one response must not contain two different checkpoints");
  assert.deepEqual(body.session.budget, { spentTokensToday: 2, dailyTokenCap: 100 });
  assert.equal(lookups, 1); assert.equal(loads, 1);
  assert.ok(sessionLoads <= 5, `detail must not parse the session once per returned field: ${sessionLoads}`);
  const before = readFileSync(join(root, "session.json"));
  body.session.budget.spentTokensToday = 0;
  assert.equal(original(project.id).budget.spentTokensToday, 2);
  assert.deepEqual(readFileSync(join(root, "session.json")), before);
});

for (const tenant of [undefined, "alpha"]) test(`inspection refuses a sibling session change during checkpoint read (${tenant ?? "personal"})`, async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-inspection-race-")), base = composeKeep({ dataDir: join(root, "app") });
  const registry = new ProjectRegistry(new CryptoShredKeyStore());
  const store = new FileProjectSessionPersistence(join(root, "session.json"));
  const checkpoints = new InMemoryProjectCheckpointStore();
  let duringLoad: (() => void) | undefined;
  const port = { load: (id: string) => {
    const result = checkpoints.load(id), callback = duringLoad; duringLoad = undefined; callback?.(); return result;
  }, save: checkpoints.save.bind(checkpoints) };
  const manager = new ProjectSessionManager(registry, undefined, () => store, port);
  const project = manager.create({ name: "concurrent inspection", ...(tenant ? { tenant } : {}) });
  const loop = buildAutonomyLoop({ spine: base.spine, manager, checkpoints: port, solve: async () => { throw new Error("not a model test"); } });
  const run = await loop.runManagedProject(project.id, "write and test a local parser", { stepBudget: 1 });
  const stale = manager.session(project.id);
  duringLoad = () => new ProjectSessionManager(registry, undefined, () => store, checkpoints).session(project.id).append("user", "new history during inspection");
  assert.throws(() => stale.inspect(), ProjectSessionConflictError);
  const current = manager.session(project.id), view = current.inspect();
  assert.equal(view.history.at(-1)?.text, "new history during inspection");
  const originalRevision = view.checkpoint!.revision;
  (view.checkpoint as { revision: number }).revision++;
  assert.equal(current.lastCheckpoint()!.revision, originalRevision, "mutating a view cannot alter canonical state");
  const app = { ...base, projectManager: manager, autonomyLoop: loop };
  duringLoad = () => new ProjectSessionManager(registry, undefined, () => store, checkpoints).session(project.id).append("user", "gateway-time sibling history");
  const token = "inspection-race", request = { method: "GET", path: "/project", query: { runId: run.state.runId },
    headers: { authorization: `Bearer ${token}` }, body: "" };
  const security = { token, ...(tenant ? { principalFor: () => ({ id: "alpha-owner", tenant, kind: "human" as const, role: "owner" as const }) } : {}) };
  const conflicted = await handleGatewayRequest(app, request, security);
  assert.equal(conflicted.status, 409, conflicted.body);
  const healthy = await handleGatewayRequest(app, request, security);
  assert.equal(healthy.status, 200, healthy.body);
  assert.equal(JSON.parse(healthy.body).session.history.at(-1).text, "gateway-time sibling history");
});

test("client retains reconciliation details while still throwing on409", async () => {
  const details = { error: "finalization requires reconciliation", runId: "existing-run", revision: 5,
    status: "reconciliation-required", taskStatus: "waiting-approval", finalization: { confirmed: false, replayTask: false } };
  let calls = 0;
  const client = new KeepClient({ origin: "http://127.0.0.1:8080", token: "not-in-response",
    transport: async () => { calls++; return { status: 409, body: JSON.stringify(details) }; } });
  await assert.rejects(client.startProject("synthetic task"), (error: unknown) => {
    assert.ok(error instanceof KeepClientError); assert.equal(error.status, 409);
    assert.deepEqual((error as KeepClientError & { details?: unknown }).details, details); return true;
  });
  assert.equal(calls, 1);
});
