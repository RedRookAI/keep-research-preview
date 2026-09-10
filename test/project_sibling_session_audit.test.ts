import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { composeKeep } from "../src/compose.js";
import { KeepClient, type ClientTransport } from "../src/client/client_core.js";
import { startGatewayServer } from "../src/gateway/http_gateway.js";
import { asProjectId } from "../src/session/project_id.js";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import { FileProjectRecordStore } from "../src/session/project_record_store.js";
import { ProjectRegistry } from "../src/session/project_registry.js";
import { ProjectSessionManager } from "../src/session/project_session_manager.js";
import { ProjectSessionUnavailableError } from "../src/session/project_session.js";
import { FileProjectSessionPersistence } from "../src/session/project_session_persistence.js";

const transport: ClientTransport = async request => {
  const response = await fetch(request.url, { method: request.method, headers: request.headers,
    ...(request.body === undefined ? {} : { body: request.body }) });
  return { status: response.status, body: await response.text() };
};
const writer = `
  const { composeKeep } = await import(${JSON.stringify(new URL("../src/compose.js", import.meta.url).href)});
  const manager = composeKeep({ dataDir: process.argv[1] }).projectManager;
  const tenant = process.argv[2] === 'personal' ? undefined : process.argv[2];
  const project = manager.create({ name: 'sibling-owned fixture', ...(tenant === undefined ? {} : { tenant }),
    budget: { spentTokensToday: 0, dailyTokenCap: 10, perRunStepCap: 3 } });
  if (process.argv[3] === 'write') manager.session(project.id).append('user', 'preserved synthetic instruction');
  manager.switch(project.id);
  console.log(JSON.stringify({ projectId: project.id, pid: process.pid }));
`;
function createFromSibling(dataDir: string, tenant: string, persist: boolean): string {
  const result = JSON.parse(execFileSync(process.execPath,
    ["--input-type=module", "-e", writer, dataDir, tenant, persist ? "write" : "empty"], {
      encoding: "utf8", timeout: 15000, maxBuffer: 1024 * 1024,
      env: { PATH: "/usr/local/bin:/usr/bin:/bin", LANG: "C.UTF-8" },
    })) as { projectId: string; pid: number };
  assert.notEqual(result.pid, process.pid);
  return result.projectId;
}

for (const organization of [false, true]) {
  test(`running ${organization ? "tenant" : "personal"} client can inspect a sibling-created persisted project`, async () => {
    const dataDir = mkdtempSync(join(tmpdir(), "keep-sibling-session-"));
    const reader = composeKeep({ dataDir });
    const token = "synthetic-sibling-reader";
    const server = await startGatewayServer(reader, { token, host: "127.0.0.1", port: 0,
      ...(organization ? { principalFor: () => ({ id: "alpha-owner", kind: "human" as const, role: "owner" as const, tenant: "alpha" }) } : {}) });
    try {
      const projectId = createFromSibling(dataDir, organization ? "alpha" : "personal", true);
      const foreignId = createFromSibling(dataDir, "beta", true);
      const api = new KeepClient({ origin: server.origin, token, transport });
      const projects = await api.projects();
      assert.ok(projects.projects.some(project => project.id === projectId));
      // Personal mode is the trusted local operator view; tenant-scoped identity
      // is the boundary that must exclude beta. Foreground selection stays scoped.
      assert.equal(projects.projects.some(project => project.id === foreignId), !organization);
      assert.equal(projects.active, projectId);
      const denied = await fetch(`${server.origin}/project/switch`, { method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ projectId: foreignId }) });
      assert.equal(denied.status, organization ? 404 : 200);
      if (!organization) assert.equal((await denied.json() as { tenant: string }).tenant, "beta");
      assert.equal((await api.projects()).active, projectId);
      const restored = reader.projectManager!.session(asProjectId(projectId));
      assert.equal(restored.history()[0]?.text, "preserved synthetic instruction");
      assert.deepEqual(restored.budget, { spentTokensToday: 0, dailyTokenCap: 10, perRunStepCap: 3 });
    } finally { await server.close(); }
  });

  test(`new ${organization ? "tenant" : "personal"} project retains its initial budget before any task write`, () => {
    const dataDir = mkdtempSync(join(tmpdir(), "keep-sibling-budget-"));
    const projectId = createFromSibling(dataDir, organization ? "alpha" : "personal", false);
    const restored = composeKeep({ dataDir }).projectManager!.session(asProjectId(projectId));
    assert.deepEqual(restored.budget, { spentTokensToday: 0, dailyTokenCap: 10, perRunStepCap: 3 });
    assert.equal(restored.history().length, 0);
    assert.equal(restored.boundRunId(), undefined);
  });

  test(`${organization ? "tenant" : "personal"} missing state stays visible and held; restored state keeps history and limits`, async () => {
    const dataDir = mkdtempSync(join(tmpdir(), "keep-sibling-missing-"));
    const id = asProjectId(createFromSibling(dataDir, organization ? "alpha" : "personal", true));
    const path = join(dataDir, "projects", "sessions", `${id}.json`);
    const saved = readFileSync(path);
    // This audit-owned file really existed; absence cannot justify an empty reset.
    renameSync(path, `${path}.backup`);
    const app = composeKeep({ dataDir });
    const token = "synthetic-missing-reader";
    const server = await startGatewayServer(app, { token, host: "127.0.0.1", port: 0,
      ...(organization ? { principalFor: () => ({ id: "alpha-owner", kind: "human" as const, role: "owner" as const, tenant: "alpha" }) } : {}) });
    try {
      const api = new KeepClient({ origin: server.origin, token, transport });
      const listed = await api.projects();
      assert.ok(listed.projects.some(row => row.id === id));
      assert.equal(listed.active, null);
      assert.match(app.projectManager!.quarantine(id) ?? "", /snapshot is missing/u);
      assert.throws(() => app.projectManager!.session(id), ProjectSessionUnavailableError);
      assert.throws(() => app.projectManager!.switch(id), ProjectSessionUnavailableError);
      assert.equal(existsSync(path), false, "read and selection must not fabricate saved state");
      const healthy = app.projectManager!.create({ name: "healthy peer", ...(organization ? { tenant: "alpha" } : {}) });
      app.projectManager!.switch(healthy.id);
      assert.equal((await api.projects()).active, healthy.id);
      renameSync(`${path}.backup`, path);
      assert.equal(app.projectManager!.quarantine(id), undefined);
      const restored = app.projectManager!.session(id);
      assert.equal(restored.history()[0]?.text, "preserved synthetic instruction");
      assert.deepEqual(restored.budget, { spentTokensToday: 0, dailyTokenCap: 10, perRunStepCap: 3 });
      assert.deepEqual(readFileSync(path), saved, "restoration is read-only");
      app.projectManager!.switch(id);
      assert.equal((await api.projects()).active, id);
      app.projectManager!.archive(id);
      assert.throws(() => app.projectManager!.runnableSession(id), /archived/u);
    } finally { await server.close(); }
  });
}

test("session preparation finishes before project metadata is visible to a sibling", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-session-prepare-"));
  const keys = new CryptoShredKeyStore();
  const records = new FileProjectRecordStore(join(dir, "records.json"));
  const observer = new ProjectRegistry(keys, records);
  let saves = 0;
  const manager = new ProjectSessionManager(new ProjectRegistry(keys, records), undefined, id => {
    const session = new FileProjectSessionPersistence(join(dir, `${id}.json`));
    return { load: () => session.load(), save: (snapshot, revision) => {
      assert.equal(observer.has(id), false);
      assert.equal(observer.list().length, 0);
      assert.equal(snapshot.history.length, 0);
      assert.equal(snapshot.budget.dailyTokenCap, 7);
      const result = session.save(snapshot, revision);
      assert.equal(observer.has(id), false, "even the durable initial file is not project admission");
      saves++; return result;
    } };
  });
  const project = manager.create({ name: "prepared", budget: { spentTokensToday: 0, dailyTokenCap: 7 } });
  assert.equal(saves, 1);
  assert.equal(observer.has(project.id), true);
  assert.equal(manager.session(project.id).budget.dailyTokenCap, 7);
});

for (const afterSave of [false, true]) test(`preparation failure ${afterSave ? "after" : "before"} saved state never publishes a project`, () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-session-prepare-fail-"));
  const keys = new CryptoShredKeyStore();
  const records = new FileProjectRecordStore(join(dir, "records.json"));
  const registry = new ProjectRegistry(keys, records);
  let attemptedId: string | undefined;
  const manager = new ProjectSessionManager(registry, undefined, id => {
    attemptedId = id;
    const session = new FileProjectSessionPersistence(join(dir, `${id}.json`));
    return { load: () => session.load(), save: (snapshot, revision) => {
      if (afterSave) session.save(snapshot, revision);
      throw new Error("synthetic preparation failure");
    } };
  });
  assert.throws(() => manager.create({ name: "not published" }), /preparation failure/u);
  assert.deepEqual(records.load().records, []);
  assert.deepEqual(manager.list(), []);
  assert.equal(manager.active(undefined), undefined);
  assert.ok(attemptedId);
  const id = asProjectId(attemptedId);
  assert.equal(existsSync(join(dir, `${id}.json`)), afterSave);
  assert.throws(() => manager.session(id), /no such project/u);
});

test("persisted and ephemeral creation reject invalid budgets before project or session writes", () => {
  for (const persisted of [false, true]) {
    const registry = new ProjectRegistry(new CryptoShredKeyStore());
    let writes = 0;
    const manager = new ProjectSessionManager(registry, undefined, persisted ? () => ({
      load: () => undefined, save: (_snapshot, revision) => { writes++; return (revision ?? 0) + 1; },
    }) : undefined);
    for (const dailyTokenCap of [-1, 0.5, NaN, Infinity]) {
      assert.throws(() => manager.create({ name: "invalid budget", budget: { spentTokensToday: 0, dailyTokenCap } }), /invalid dailyTokenCap/u);
    }
    assert.deepEqual(manager.list(), []); assert.equal(writes, 0);
  }
});

test("legacy metadata-only state is retained and not initialized by reads or selection", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-session-legacy-"));
  const records = new FileProjectRecordStore(join(dir, "records.json"));
  const registry = new ProjectRegistry(new CryptoShredKeyStore(), records);
  const project = registry.create("old metadata only", "active");
  const before = readFileSync(join(dir, "records.json"));
  const manager = new ProjectSessionManager(registry, undefined, id => new FileProjectSessionPersistence(join(dir, `${id}.json`)));
  assert.equal(manager.list()[0]?.id, project.id);
  assert.equal(manager.active(undefined), undefined);
  assert.throws(() => manager.session(project.id), ProjectSessionUnavailableError);
  assert.throws(() => manager.switch(project.id), ProjectSessionUnavailableError);
  assert.equal(existsSync(join(dir, `${project.id}.json`)), false);
  assert.deepEqual(readFileSync(join(dir, "records.json")), before);
});

test("corrupt sibling snapshots stay quarantined; metadata list does not load all sessions", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-session-lazy-corrupt-"));
  const keys = new CryptoShredKeyStore();
  const records = new FileProjectRecordStore(join(dir, "records.json"));
  const registry = new ProjectRegistry(keys, records);
  let loads = 0;
  const manager = new ProjectSessionManager(registry, undefined, id => {
    const session = new FileProjectSessionPersistence(join(dir, `${id}.json`));
    return { load: () => { loads++; return session.load(); }, save: (snapshot, revision) => session.save(snapshot, revision) };
  });
  const project = new ProjectRegistry(keys, records).create("corrupt sibling", "active");
  const path = join(dir, `${project.id}.json`);
  writeFileSync(path, "{invalid synthetic snapshot");
  assert.equal(manager.list()[0]?.id, project.id); assert.equal(loads, 0);
  assert.match(manager.quarantine(project.id) ?? "", /invalid project session store/u);
  assert.equal(loads, 1);
  assert.equal(manager.active(undefined), undefined);
  assert.throws(() => manager.session(project.id), /quarantined/u);
  assert.equal(loads, 1, "corrupt input is not continually reloaded");
  assert.equal(readFileSync(path, "utf8"), "{invalid synthetic snapshot");
});

test("a load failure after committed creation preserves its identity and holds execution", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-session-created-unavailable-"));
  const registry = new ProjectRegistry(new CryptoShredKeyStore(), new FileProjectRecordStore(join(dir, "records.json")));
  let fail = true;
  const manager = new ProjectSessionManager(registry, undefined, id => {
    const session = new FileProjectSessionPersistence(join(dir, `${id}.json`));
    return { load: () => { if (fail) throw new Error("synthetic post-publication read failure"); return session.load(); },
      save: (snapshot, revision) => session.save(snapshot, revision) };
  });
  const project = manager.create({ name: "committed but held", budget: { spentTokensToday: 0, dailyTokenCap: 17 } });
  assert.equal(manager.list()[0]?.id, project.id);
  assert.match(manager.quarantine(project.id) ?? "", /post-publication read failure/u);
  assert.throws(() => manager.runnableSession(project.id), /quarantined/u);
  assert.equal(manager.active(undefined), undefined);
  fail = false;
  const restored = new ProjectSessionManager(registry, undefined, id => new FileProjectSessionPersistence(join(dir, `${id}.json`)));
  assert.deepEqual(restored.session(project.id).budget, { spentTokensToday: 0, dailyTokenCap: 17 });
});

for (const organization of [false, true]) test(`${organization ? "tenant" : "personal"} listing survives deletion between metadata and session projection`, async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-session-list-delete-")) });
  const manager = app.projectManager!;
  const project = manager.create({ name: "deleted during listing", ...(organization ? { tenant: "alpha" } : {}) });
  const peer = manager.create({ name: "healthy peer", ...(organization ? { tenant: "alpha" } : {}) });
  manager.switch(project.id);
  const quarantine = manager.quarantine.bind(manager);
  let deleted = false;
  manager.quarantine = id => {
    if (id === project.id && !deleted) { manager.delete(id); deleted = true; }
    return quarantine(id);
  };
  const token = "synthetic-deletion-reader";
  const server = await startGatewayServer(app, { token, host: "127.0.0.1", port: 0,
    ...(organization ? { principalFor: () => ({ id: "alpha-owner", kind: "human" as const, role: "owner" as const, tenant: "alpha" }) } : {}) });
  try {
    const api = new KeepClient({ origin: server.origin, token, transport });
    const listed = await api.projects();
    assert.ok(deleted);
    assert.deepEqual(listed.projects.map(row => row.id), [peer.id]);
    assert.equal(listed.active, null);
    assert.equal(manager.lifecycle(project.id), "deleted");
    assert.throws(() => manager.session(project.id), /no such project/u);
  } finally { await server.close(); }
});

test("active selection skips a deletion after its metadata read", () => {
  const registry = new ProjectRegistry(new CryptoShredKeyStore());
  const manager = new ProjectSessionManager(registry);
  const project = manager.create({ name: "deleted during active read", tenant: "alpha" });
  manager.switch(project.id);
  const quarantine = manager.quarantine.bind(manager);
  manager.quarantine = id => { manager.delete(id); return quarantine(id); };
  assert.equal(manager.active("alpha"), undefined);
  assert.equal(registry.lifecycle(project.id), "deleted");
});

test("active selection does not hide a non-deletion storage failure", () => {
  const registry = new ProjectRegistry(new CryptoShredKeyStore());
  const manager = new ProjectSessionManager(registry);
  const project = manager.create({ name: "still present", tenant: "alpha" });
  manager.switch(project.id);
  manager.quarantine = () => { throw new Error("synthetic storage failure unrelated to deletion"); };
  assert.throws(() => manager.active("alpha"), /storage failure unrelated to deletion/u);
  assert.equal(registry.lifecycle(project.id), "active");
});

test("selection reports an unconfirmed change when its project disappears after lookup", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-session-select-delete-")) });
  const manager = app.projectManager!;
  const project = manager.create({ name: "deleted during selection" });
  const quarantine = manager.quarantine.bind(manager);
  manager.quarantine = id => { manager.delete(id); return quarantine(id); };
  const token = "synthetic-selection-reader";
  const server = await startGatewayServer(app, { token, host: "127.0.0.1", port: 0 });
  try {
    const response = await fetch(`${server.origin}/project/switch`, { method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ projectId: project.id }) });
    assert.equal(response.status, 409);
    assert.match((await response.json() as { error: string }).error, /could not be confirmed/u);
    assert.equal(manager.lifecycle(project.id), "deleted");
  } finally { await server.close(); }
});
