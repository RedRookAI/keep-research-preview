import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { composeKeep } from "../src/compose.js";
import { startGatewayServer } from "../src/gateway/http_gateway.js";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import { ProjectRegistry } from "../src/session/project_registry.js";
import { ProjectSession, ProjectSessionUnavailableError } from "../src/session/project_session.js";
import { FileProjectSessionPersistence, ProjectSessionConflictError } from "../src/session/project_session_persistence.js";
import { FileProjectRecordStore, ProjectRecordConflictError } from "../src/session/project_record_store.js";
import { ProjectSessionManager } from "../src/session/project_session_manager.js";

for (const tenant of [undefined, "alpha"]) test(`read failure can recover without reviving a stale session (${tenant ?? "personal"})`, () => {
  const root = mkdtempSync(join(tmpdir(), "keep-read-recovery-"));
  const path = join(root, "session.json"), store = new FileProjectSessionPersistence(path);
  const registry = new ProjectRegistry(new CryptoShredKeyStore());
  const manager = new ProjectSessionManager(registry, undefined, () => store);
  const record = manager.create({ name: "read recovery", ...(tenant ? { tenant } : {}), budget: { spentTokensToday: 7, dailyTokenCap: 10 } });
  const old = manager.session(record.id); old.append("user", "retain this history"); old.putSecret("label", "synthetic value");
  const before = readFileSync(path), original = fs.readFileSync;
  let failures = 0;
  fs.readFileSync = ((...args: Parameters<typeof fs.readFileSync>) => {
    if (args[0] === path) { failures++; throw Object.assign(new Error("injected descriptor exhaustion"), { code: "EMFILE" }); }
    return Reflect.apply(original, fs, args);
  }) as typeof fs.readFileSync;
  syncBuiltinESMExports();
  try { assert.throws(() => manager.session(record.id)); }
  finally { fs.readFileSync = original; syncBuiltinESMExports(); }
  assert.equal(failures, 1, "no automatic read retry inside the failed lookup");
  assert.throws(() => old.history(), ProjectSessionConflictError);
  const current = manager.session(record.id);
  assert.notEqual(current, old); assert.equal(current.history()[0]?.text, "retain this history");
  assert.equal(current.resolveSecret("label"), "synthetic value");
  assert.deepEqual(current.budget, { spentTokensToday: 7, dailyTokenCap: 10 });
  assert.deepEqual(readFileSync(path), before, "recovery is read-only");
  writeFileSync(path, "malformed JSON");
  assert.throws(() => manager.session(record.id), /quarantined/);
  writeFileSync(path, before);
  assert.throws(() => manager.session(record.id), /quarantined/, "corruption still requires deliberate reconstruction");
  const rebuilt = new ProjectSessionManager(registry, undefined, () => store).session(record.id);
  assert.equal(rebuilt.history()[0]?.text, "retain this history");
});

for (const tenant of [undefined, "alpha"]) test(`${tenant ?? "personal"} manager restores current sibling state without rebasing an old object`, async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-session-current-"));
  const app = composeKeep({ dataDir: dir }); const manager = app.projectManager!;
  const record = manager.create({ name: "synthetic currentness", ...(tenant ? { tenant } : {}),
    budget: { spentTokensToday: 0, dailyTokenCap: 10, perRunStepCap: 3 } });
  const old = manager.session(record.id); old.append("user", "initial synthetic fact");
  const child = `
    const { composeKeep } = await import(${JSON.stringify(new URL("../src/compose.js", import.meta.url).href)});
    const s = composeKeep({ dataDir: process.argv[1] }).projectManager.session(process.argv[2]);
    s.append('user', 'new synthetic fact'); s.putSecret('new-label', 'synthetic value');
    s.bindRun('new-run'); s.spend(7); console.log(JSON.stringify({pid:process.pid}));
  `;
  const result = JSON.parse(execFileSync(process.execPath, ["--input-type=module", "-e", child, dir, record.id],
    { encoding: "utf8", timeout: 15000, env: { PATH: "/usr/local/bin:/usr/bin:/bin", LANG: "C" } })) as { pid: number };
  assert.notEqual(result.pid, process.pid);
  for (const read of [() => old.history(), () => old.liveCount(), () => old.compactions(),
    () => old.listSecrets(), () => old.boundRunId(), () => old.lastCheckpoint(), () => old.budget,
    () => old.withinBudget(), () => old.resolveSecret("new-label"), () => old.inspect()]) assert.throws(read, ProjectSessionConflictError);
  assert.throws(() => old.append("user", "must not rebase"), ProjectSessionConflictError);
  const current = manager.session(record.id); assert.notEqual(current, old);
  assert.deepEqual(current.history().map(entry => entry.text), ["initial synthetic fact", "new synthetic fact"]);
  assert.equal(current.boundRunId(), "new-run"); assert.deepEqual(current.listSecrets(), ["new-label"]);
  assert.deepEqual(current.budget, { spentTokensToday: 7, dailyTokenCap: 10, perRunStepCap: 3 });
  const view = current.budget; view.spentTokensToday = 0;
  assert.equal(current.budget.spentTokensToday, 7, "detached view cannot reset recorded spending");
  const path = join(dir, "projects", "sessions", `${record.id}.json`), before = readFileSync(path);
  const token = "synthetic-currentness-reader";
  const server = await startGatewayServer(app, { token, host: "127.0.0.1", port: 0,
    ...(tenant ? { principalFor: () => ({ id: "alpha-owner", kind: "human" as const, role: "owner" as const, tenant }) } : {}) });
  try {
    const response = await fetch(`${server.origin}/projects`, { headers: { authorization: `Bearer ${token}` } });
    assert.equal(response.status, 200);
    const body = await response.json() as { projects: { id: string; runId: string }[] };
    assert.equal(body.projects.find(project => project.id === record.id)?.runId, "new-run");
  } finally { await server.close(); }
  assert.deepEqual(readFileSync(path), before, "inspection cannot rewrite state");
});

test("missing saved state fences cached secrets and resumes only through a newly restored object", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-session-vanished-"));
  const app = composeKeep({ dataDir: dir }), manager = app.projectManager!;
  const record = manager.create({ name: "missing snapshot" }); const old = manager.session(record.id);
  old.putSecret("token", "synthetic secret"); old.append("user", "preserved history");
  const path = join(dir, "projects", "sessions", `${record.id}.json`), before = readFileSync(path);
  renameSync(path, `${path}.retained`);
  assert.throws(() => old.resolveSecret("token"), ProjectSessionUnavailableError);
  assert.throws(() => manager.session(record.id), ProjectSessionUnavailableError);
  assert.throws(() => old.history(), ProjectSessionConflictError);
  renameSync(`${path}.retained`, path);
  const restored = manager.session(record.id); assert.notEqual(restored, old);
  assert.equal(restored.resolveSecret("token"), "synthetic secret");
  assert.equal(restored.history()[0]?.text, "preserved history");
  assert.deepEqual(readFileSync(path), before);
});

test("absence is not legacy revision zero; retained session data can be deliberately updated", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-session-presence-"));
  const registry = new ProjectRegistry(new CryptoShredKeyStore()), record = registry.create("legacy");
  const ns = registry.namespace(record.id), path = join(dir, "session.json");
  const store = new FileProjectSessionPersistence(path), stale = new ProjectSession(ns, undefined, store);
  const encrypted = ns.encrypt("legacy history");
  writeFileSync(path, JSON.stringify({ schemaVersion: 1, projectId: record.id,
    history: [{ seq: 0, role: "user", at: 1, cipher: { iv: encrypted.iv, authTag: encrypted.authTag, data: encrypted.data } }],
    secrets: [], compactions: [], nextSeq: 1, budget: { spentTokensToday: 7, dailyTokenCap: 10 }, runId: "legacy-run" }));
  const before = readFileSync(path); assert.equal(store.load()!.storageRevision, 0);
  assert.throws(() => stale.append("user", "overwrite"), ProjectSessionConflictError);
  assert.throws(() => store.save(store.load()!, undefined), ProjectSessionConflictError);
  assert.deepEqual(readFileSync(path), before);
  const restored = new ProjectSession(ns, undefined, store);
  assert.equal(restored.history()[0]?.text, "legacy history");
  restored.append("user", "legitimate addition"); assert.equal(store.load()!.storageRevision, 1);
  const next = new ProjectSession(ns, undefined, store);
  assert.equal(next.history().length, 2); assert.equal(next.boundRunId(), "legacy-run");
  assert.deepEqual(next.budget, { spentTokensToday: 7, dailyTokenCap: 10 });
});

test("legacy record restoration cannot be overwritten by a registry opened on absence", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-record-presence-")), path = join(dir, "records.json");
  const keys = new CryptoShredKeyStore(), donor = new ProjectRegistry(keys), legacy = donor.create("retained project");
  const store = new FileProjectRecordStore(path), stale = new ProjectRegistry(keys, store);
  assert.equal(store.load().revision, undefined);
  writeFileSync(path, JSON.stringify([legacy])); const before = readFileSync(path);
  assert.throws(() => stale.create("stale addition"), ProjectRecordConflictError);
  assert.deepEqual(readFileSync(path), before); assert.equal(keys.hasKey(legacy.id), true);
  assert.equal(stale.list()[0]?.id, legacy.id, "explicit current read can refresh the registry");
  const additional = stale.create("legitimate addition");
  assert.deepEqual(new Set(new ProjectRegistry(keys, store).list().map(row => row.id)), new Set([legacy.id, additional.id]));
});
