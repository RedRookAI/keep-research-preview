import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileProjectCheckpointStore, InMemoryProjectCheckpointStore } from "../src/autonomy/project_checkpoint_store.js";
import type { ProjectState } from "../src/autonomy/project_state.js";
import { PROJECT_STATE_SCHEMA_VERSION } from "../src/autonomy/project_state.js";
import { FileWrappedKeyPersistence } from "../src/keystore/file_wrapped_key_persistence.js";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import { FileProjectRecordStore } from "../src/session/project_record_store.js";
import { ProjectRegistry } from "../src/session/project_registry.js";
import { ProjectSession } from "../src/session/project_session.js";
import { defaultCompactor } from "../src/session/project_session_manager.js";
import { ProjectSessionManager } from "../src/session/project_session_manager.js";
import { FileProjectSessionPersistence, ProjectSessionConflictError, type ProjectSessionPersistence, type ProjectSessionSnapshot } from "../src/session/project_session_persistence.js";

function state(runId: string, revision = 0): ProjectState {
  return {
    schemaVersion: PROJECT_STATE_SCHEMA_VERSION, revision, runId, goal: "private canonical goal", stage: "plan", artifacts: {},
    posture: "autonomous", stepsRemaining: 5, reworkCount: 0, status: "running",
    retry: { attemptsByStage: {}, attemptsConsumed: 0, runLimit: 8 }, consumedSignals: [],
  };
}

test("encrypted history, compactions, secrets, budget, and canonical checkpoint reference restore", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-session-state-"));
  const keyOptions = { masterKeyPath: join(dir, "master.key"), wrappedKeysPath: join(dir, "keys.json") };
  const recordsPath = join(dir, "projects.json");
  const sessionsPath = join(dir, "session.json");
  const checkpoints = new FileProjectCheckpointStore(join(dir, "checkpoints"));
  const keys = new CryptoShredKeyStore(new FileWrappedKeyPersistence(keyOptions));
  const registry = new ProjectRegistry(keys, new FileProjectRecordStore(recordsPath));
  const project = registry.create("durable manuscript");
  const first = new ProjectSession(registry.namespace(project.id), { dailyTokenCap: 1000, perRunStepCap: 50, spentTokensToday: 0 }, new FileProjectSessionPersistence(sessionsPath), checkpoints);
  first.append("user", "private manuscript premise");
  first.append("assistant", "private chapter outline");
  first.compactOldest(1, defaultCompactor);
  first.putSecret("publisher-token", "private credential");
  first.putDocument("audience-performance-corpus", JSON.stringify({ private: "audience evidence" }));
  const checkpoint = state("content-run");
  checkpoints.save(checkpoint, undefined);
  first.checkpoint(checkpoint);
  assert.equal(first.spend(123), true);
  assert.equal(first.reconcileMeteredTokens(50), true);
  assert.equal(first.reconcileMeteredTokens(50), true, "same meter watermark is idempotent");

  const atRest = readFileSync(sessionsPath, "utf8");
  assert.doesNotMatch(atRest, /private manuscript|private chapter|private credential|Compacted/u);
  assert.doesNotMatch(atRest, /audience evidence/u);
  assert.doesNotMatch(atRest, /plaintextHash/u, "session persistence must not retain a post-shred plaintext oracle");
  assert.equal(statSync(sessionsPath).mode & 0o777, 0o600);

  const reopenedKeys = new CryptoShredKeyStore(new FileWrappedKeyPersistence(keyOptions));
  const reopenedRegistry = new ProjectRegistry(reopenedKeys, new FileProjectRecordStore(recordsPath));
  const restored = new ProjectSession(reopenedRegistry.namespace(project.id), undefined, new FileProjectSessionPersistence(sessionsPath), checkpoints);
  assert.deepEqual(restored.history().map(({ role, text }) => ({ role, text })), [{ role: "assistant", text: "private chapter outline" }]);
  assert.match(restored.compactions()[0]!.summary, /Compacted 1/u);
  assert.equal(restored.resolveSecret("publisher-token"), "private credential");
  assert.equal(restored.resolveDocument("audience-performance-corpus"), JSON.stringify({ private: "audience evidence" }));
  assert.equal(restored.resolveSecret("keep.document.audience-performance-corpus"), undefined);
  assert.deepEqual(restored.listSecrets(), ["publisher-token"]);
  assert.throws(() => restored.putSecret("keep.document.audience-performance-corpus", "collision"), /reserved/u);
  assert.deepEqual(restored.lastCheckpoint(), checkpoint);
  assert.deepEqual(restored.budget, { dailyTokenCap: 1000, perRunStepCap: 50, spentTokensToday: 173, meteredTraceTokens: 50 });
});

test("persistent session rejects uncommitted checkpoints and follows a newer canonical authority", () => {
  const keys = new CryptoShredKeyStore();
  const registry = new ProjectRegistry(keys);
  const project = registry.create("checkpoint owner");
  let durable: ProjectSessionSnapshot | undefined;
  const persistence: ProjectSessionPersistence = { load: () => durable, save: (next, expected) => { durable = structuredClone({ ...next, storageRevision: expected + 1 }); return expected + 1; } };
  const checkpoints = new InMemoryProjectCheckpointStore();
  const session = new ProjectSession(registry.namespace(project.id), undefined, persistence, checkpoints);
  const first = state("run");
  assert.throws(() => session.checkpoint(first), /does not match canonical/u);
  checkpoints.save(first, undefined);
  session.checkpoint(first);
  const newer = state("run", 1); checkpoints.save(newer, 0);
  assert.deepEqual(session.lastCheckpoint(), newer, "a lagging non-owning reference must not override the newer canonical checkpoint");
});

test("run ownership persists before any checkpoint and is immutable across restart", () => {
  const keys = new CryptoShredKeyStore();
  const registry = new ProjectRegistry(keys);
  const project = registry.create("run owner");
  let durable: ProjectSessionSnapshot | undefined;
  const persistence: ProjectSessionPersistence = { load: () => durable, save: (next, expected) => { durable = structuredClone({ ...next, storageRevision: expected + 1 }); return expected + 1; } };
  const first = new ProjectSession(registry.namespace(project.id), undefined, persistence, new InMemoryProjectCheckpointStore());
  first.bindRun("persist-before-callback");
  assert.equal(first.boundRunId(), "persist-before-callback");
  assert.equal(durable?.checkpointRef, undefined);
  const restarted = new ProjectSession(registry.namespace(project.id), undefined, persistence, new InMemoryProjectCheckpointStore());
  assert.equal(restarted.boundRunId(), "persist-before-callback");
  assert.throws(() => restarted.bindRun("different-run"), /already bound/u);
});

test("malformed session bytes fail closed and failed persistence publishes no mutation", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-session-bad-"));
  const path = join(dir, "session.json");
  writeFileSync(path, JSON.stringify({ schemaVersion: 1, projectId: "../escape" }));
  assert.throws(() => new FileProjectSessionPersistence(path).load(), /invalid project session store/u);

  const keys = new CryptoShredKeyStore();
  const registry = new ProjectRegistry(keys);
  const project = registry.create("atomic session");
  const persistence: ProjectSessionPersistence = { load: () => undefined, save: () => { throw new Error("disk full"); } };
  const session = new ProjectSession(registry.namespace(project.id), undefined, persistence, new InMemoryProjectCheckpointStore());
  assert.throws(() => session.bindRun("must-not-publish"), /disk full/u);
  assert.equal(session.boundRunId(), undefined);
  assert.throws(() => session.append("user", "must not publish"), /disk full/u);
  assert.equal(session.liveCount(), 0);
  assert.equal(session.listSecrets().length, 0);
  assert.throws(() => session.putSecret("token", "must not publish"), /disk full/u);
  assert.equal(session.listSecrets().length, 0);
});

test("project document persistence is all-or-none and CAS tombstones never reuse a revision", () => {
  const keys = new CryptoShredKeyStore(); const registry = new ProjectRegistry(keys); const project = registry.create("documents");
  const partial = { load: () => undefined, save: (_snapshot: ProjectSessionSnapshot, expected: number) => expected + 1, loadDocument: () => undefined };
  assert.throws(() => new ProjectSession(registry.namespace(project.id), undefined, partial), /configured together/u);

  const dir = mkdtempSync(join(tmpdir(), "keep-document-cas-"));
  const persistence = new FileProjectSessionPersistence(join(dir, "session.json"));
  const first = new ProjectSession(registry.namespace(project.id), undefined, persistence);
  const second = new ProjectSession(registry.namespace(project.id), undefined, new FileProjectSessionPersistence(join(dir, "session.json")));
  const a = first.resolveDocumentVersioned("corpus"); const b = second.resolveDocumentVersioned("corpus");
  assert.equal(first.putDocumentVersioned("corpus", "one", a.revision), 1);
  assert.throws(() => second.putDocumentVersioned("corpus", "lost update", b.revision), ProjectSessionConflictError);
  assert.equal(first.forgetDocumentVersioned("corpus", 1), true);
  assert.deepEqual(first.resolveDocumentVersioned("corpus"), { value: undefined, revision: 2 });
  assert.throws(() => second.putDocumentVersioned("corpus", "ABA resurrection", 1), ProjectSessionConflictError);
  assert.equal(first.putDocumentVersioned("corpus", "new epoch", 2), 3);
});

test("session compaction views are detached from durable authority", () => {
  const keys = new CryptoShredKeyStore(); const registry = new ProjectRegistry(keys); const project = registry.create("detached");
  const session = new ProjectSession(registry.namespace(project.id));
  session.append("assistant", "fact"); session.compactOldest(1, defaultCompactor);
  const view = session.compactions()[0]!; (view.keptFacts as string[]).push("forged");
  assert.doesNotMatch(session.compactions()[0]!.keptFacts.join(" "), /forged/u);
});

test("manager restores exactly one foreground project and archived projects remain readable but non-runnable", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-session-manager-"));
  const open = () => {
    const keys = new CryptoShredKeyStore(new FileWrappedKeyPersistence({ masterKeyPath: join(dir, "master.key"), wrappedKeysPath: join(dir, "keys.json") }));
    const registry = new ProjectRegistry(keys, new FileProjectRecordStore(join(dir, "projects.json")));
    const checkpoints = new FileProjectCheckpointStore(join(dir, "checkpoints"));
    return new ProjectSessionManager(registry, undefined, (id) => new FileProjectSessionPersistence(join(dir, "sessions", `${id}.json`)), checkpoints);
  };
  const first = open();
  const archived = first.create({ name: "finished manuscript" });
  const current = first.create({ name: "current software" });
  first.session(archived.id).append("assistant", "final archived artifact");
  first.session(current.id).append("assistant", "current project artifact");
  first.switch(archived.id);
  first.archive(archived.id);
  first.switch(current.id);

  const reopened = open();
  assert.equal(reopened.active(), current.id);
  assert.equal(reopened.lifecycle(archived.id), "archived");
  assert.deepEqual(reopened.session(archived.id).history().map((entry) => entry.text), ["final archived artifact"]);
  assert.throws(() => reopened.runnableSession(archived.id), /archived and read-only/u);
  assert.throws(() => reopened.session(archived.id).append("assistant", "forbidden rewrite"), /not writable/u);
  assert.throws(() => reopened.session(archived.id).spend(1), /not writable/u);
  assert.deepEqual(reopened.session(archived.id).history().map((entry) => entry.text), ["final archived artifact"]);
  assert.deepEqual(reopened.runnableSession(current.id).history().map((entry) => entry.text), ["current project artifact"]);
});

test("a held session cannot mutate state after another owner deletes the project", () => {
  const manager = new ProjectSessionManager(new ProjectRegistry(new CryptoShredKeyStore()));
  const project = manager.create({ name: "held then deleted" }); const held = manager.session(project.id);
  manager.delete(project.id);
  assert.throws(() => held.spend(1), /not writable/u);
  assert.throws(() => held.bindRun("late-run"), /not writable/u);
  assert.throws(() => held.checkpoint(state("late-run")), /not writable/u);
});

test("one corrupt session is quarantined without preventing healthy project recovery", () => {
  const keys = new CryptoShredKeyStore();
  const registry = new ProjectRegistry(keys);
  const broken = registry.create("broken", "background"); const healthy = registry.create("healthy", "background");
  const corrupt: ProjectSessionPersistence = { load: () => { throw new Error("authentication failed"); }, save: (_next, expected) => expected + 1 };
  const clean: ProjectSessionPersistence = { load: () => undefined, save: (_next, expected) => expected + 1 };
  const manager = new ProjectSessionManager(registry, undefined, (id) => id === broken.id ? corrupt : clean, new InMemoryProjectCheckpointStore());
  assert.match(manager.quarantine(broken.id) ?? "", /authentication failed/u);
  assert.throws(() => manager.session(broken.id), /quarantined/u);
  assert.equal(manager.session(healthy.id).projectId, healthy.id);
});

test("a stale session writer cannot erase newer encrypted history", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-session-cas-"));
  const keys = new CryptoShredKeyStore(); const registry = new ProjectRegistry(keys); const project = registry.create("shared session");
  const path = join(dir, "session.json");
  const first = new ProjectSession(registry.namespace(project.id), undefined, new FileProjectSessionPersistence(path));
  const stale = new ProjectSession(registry.namespace(project.id), undefined, new FileProjectSessionPersistence(path));
  first.append("user", "newer durable entry", 1);
  assert.throws(() => stale.append("user", "stale overwrite", 2), /project session conflict/u);
  const reopened = new ProjectSession(registry.namespace(project.id), undefined, new FileProjectSessionPersistence(path));
  assert.deepEqual(reopened.history().map((entry) => entry.text), ["newer durable entry"]);
});

test("a live sibling process loses decrypt authority immediately after durable erasure", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-session-erasure-refresh-"));
  const keyOptions = { masterKeyPath: join(dir, "master.key"), wrappedKeysPath: join(dir, "keys.json") };
  const recordPath = join(dir, "records.json");
  const firstRegistry = new ProjectRegistry(new CryptoShredKeyStore(new FileWrappedKeyPersistence(keyOptions)), new FileProjectRecordStore(recordPath));
  const project = firstRegistry.create("erasure refresh", "background");
  const siblingRegistry = new ProjectRegistry(new CryptoShredKeyStore(new FileWrappedKeyPersistence(keyOptions)), new FileProjectRecordStore(recordPath));
  const sibling = new ProjectSession(siblingRegistry.namespace(project.id)); sibling.append("user", "sensitive diagnosis");
  firstRegistry.remove(project.id);
  assert.throws(() => sibling.history(), /no such project|erased/u);
});

test("quarantined active state is durably demoted and cannot create a two-active restart outage", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-session-quarantine-active-"));
  const open = (corruptId?: string) => {
    const keys = new CryptoShredKeyStore(new FileWrappedKeyPersistence({ masterKeyPath: join(dir, "master.key"), wrappedKeysPath: join(dir, "keys.json") }));
    const registry = new ProjectRegistry(keys, new FileProjectRecordStore(join(dir, "records.json")));
    return new ProjectSessionManager(registry, undefined, (id) => corruptId === id ? { load: () => { throw new Error("corrupt active session"); }, save: (_next, expected) => expected + 1 } : new FileProjectSessionPersistence(join(dir, "sessions", `${id}.json`)), new FileProjectCheckpointStore(join(dir, "checkpoints")));
  };
  const first = open(); const broken = first.create({ name: "broken active" }); const healthy = first.create({ name: "healthy" }); first.switch(broken.id);
  const quarantining = open(broken.id); assert.match(quarantining.quarantine(broken.id) ?? "", /corrupt/u); quarantining.switch(healthy.id);
  const restarted = open(); assert.equal(restarted.active(), healthy.id); assert.equal(restarted.lifecycle(broken.id), "background");
});
