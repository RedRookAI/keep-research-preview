import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import { ProjectRegistry } from "../src/session/project_registry.js";
import { ProjectSessionManager } from "../src/session/project_session_manager.js";
import { FileProjectRecordStore, type ProjectRecordStore } from "../src/session/project_record_store.js";

function fixture() {
  const path = join(mkdtempSync(join(tmpdir(), "keep-foreground-")), "records.json");
  const keys = new CryptoShredKeyStore();
  const store = new FileProjectRecordStore(path);
  const open = (port: ProjectRecordStore = store) => new ProjectSessionManager(new ProjectRegistry(keys, port));
  return { path, store, open };
}

test("foreground switching preserves the personal and other tenant selections across reconstruction", () => {
  const f = fixture(), manager = f.open();
  const personal = manager.create({ name: "personal" });
  const alpha = manager.create({ name: "alpha", tenant: "alpha" });
  const beta = manager.create({ name: "beta", tenant: "beta" });
  manager.switch(personal.id); manager.switch(alpha.id); manager.switch(beta.id);
  for (const project of [personal, alpha, beta]) assert.equal(manager.lifecycle(project.id), "active");
  const before = readFileSync(f.path);
  const restored = f.open();
  assert.deepEqual(readFileSync(f.path), before, "loading must not rewrite another tenant's selection");
  for (const project of [personal, alpha, beta]) assert.equal(restored.lifecycle(project.id), "active");
  assert.equal(restored.active(undefined), personal.id);
  assert.equal(restored.active("alpha"), alpha.id);
  assert.equal(restored.active("beta"), beta.id);
  const next = restored.create({ name: "next alpha", tenant: "alpha" });
  assert.deepEqual(restored.switch(next.id), { outgoing: alpha.id, incoming: next.id });
  assert.equal(restored.lifecycle(alpha.id), "background");
  for (const project of [personal, beta, next]) assert.equal(restored.lifecycle(project.id), "active");
});

test("one foreground transition uses one complete durable record replacement", () => {
  const f = fixture(); let writes = 0;
  const manager = f.open({ load: () => f.store.load(), save: (records, revision) => { writes++; return f.store.save(records, revision); } });
  const first = manager.create({ name: "first" }), second = manager.create({ name: "second" });
  manager.switch(first.id); writes = 0;
  manager.switch(second.id);
  assert.equal(writes, 1, "demotion and promotion cannot be separate durable commits");
  assert.equal(f.open().active(undefined), second.id);
});

test("failed foreground persistence preserves the previously selected project", () => {
  const f = fixture(); let fail = false;
  const manager = f.open({ load: () => f.store.load(), save: (records, revision) => {
    if (fail) throw new Error("injected pre-commit storage refusal");
    return f.store.save(records, revision);
  } });
  const first = manager.create({ name: "first" }), second = manager.create({ name: "second" });
  manager.switch(first.id); const before = readFileSync(f.path); fail = true;
  assert.throws(() => manager.switch(second.id), /storage refusal/u);
  assert.deepEqual(readFileSync(f.path), before);
  assert.equal(manager.active(undefined), first.id); assert.equal(f.open().active(undefined), first.id);
});

test("foreground reads follow another live writer's durable switch and archive", () => {
  const f = fixture(), manager = f.open();
  const first = manager.create({ name: "first" }), second = manager.create({ name: "second" });
  manager.switch(first.id); const sibling = f.open(); sibling.switch(second.id);
  assert.equal(manager.active(undefined), second.id);
  sibling.archive(second.id); assert.equal(manager.active(undefined), undefined);
});

test("background cannot reactivate an archived project", () => {
  const f = fixture(), manager = f.open(), project = manager.create({ name: "archived" });
  manager.archive(project.id); const before = readFileSync(f.path);
  assert.throws(() => manager.background(project.id), /archived/u);
  assert.deepEqual(readFileSync(f.path), before);
  assert.equal(f.open().lifecycle(project.id), "archived");
});

test("background refuses an archive committed by a sibling after the initial runnable check", () => {
  const f = fixture(); let afterRead: (() => void) | undefined;
  const manager = f.open({ load: () => {
    const snapshot = f.store.load();
    const callback = afterRead; afterRead = undefined; callback?.();
    return snapshot;
  }, save: (records, revision) => f.store.save(records, revision) });
  const project = manager.create({ name: "concurrent archive" });
  const sibling = f.open();
  afterRead = () => sibling.archive(project.id);
  assert.throws(() => manager.background(project.id), /archived|conflict/u);
  assert.equal(f.open().lifecycle(project.id), "archived");
});

test("quarantined incoming selection is refused before outgoing state changes", () => {
  const keys = new CryptoShredKeyStore(), registry = new ProjectRegistry(keys);
  const good = registry.create("good", "active"), bad = registry.create("bad", "background");
  const manager = new ProjectSessionManager(registry, undefined, id => id === bad.id ? {
    load: () => { throw new Error("synthetic corrupt session"); }, save: (_record, revision) => (revision ?? 0) + 1,
  } : undefined);
  manager.session(good.id).append("assistant", "useful retained history");
  assert.throws(() => manager.switch(bad.id), /quarantined/u);
  assert.throws(() => manager.background(bad.id), /quarantined/u);
  assert.equal(manager.active(undefined), good.id);
  assert.equal(manager.session(good.id).history()[0]?.text, "useful retained history");
  assert.equal(manager.session(good.id).compactions().length, 0);
});

test("legacy multiple-active records are unchanged on load and normalized only in the selected tenant", () => {
  const f = fixture(), keys = new CryptoShredKeyStore(), registry = new ProjectRegistry(keys, f.store);
  const a = registry.create("legacy a", "active", "alpha");
  const b = registry.create("legacy b", "active", "alpha");
  const c = registry.create("legacy c", "active", "beta");
  // Prepare actual legacy duplicate-active input, bypassing current promotion policy.
  const legacy = f.store.load();
  f.store.save(legacy.records.map(record => ({ ...record, lifecycle: "active" })), legacy.revision);
  const before = readFileSync(f.path);
  const manager = new ProjectSessionManager(registry);
  assert.deepEqual(readFileSync(f.path), before);
  manager.switch(b.id);
  assert.equal(manager.lifecycle(a.id), "background");
  assert.equal(manager.lifecycle(b.id), "active");
  assert.equal(manager.lifecycle(c.id), "active");
});

for (const unreadableAfterSave of [false, true]) {
  test(`creation preserves its original key after a committed save throws; unreadable=${unreadableAfterSave}`, () => {
    const f = fixture(), keys = new CryptoShredKeyStore();
    let savedId: string | undefined, cipher: ReturnType<CryptoShredKeyStore["encrypt"]> | undefined, failed = false;
    const registry = new ProjectRegistry(keys, { load: () => {
      if (failed && unreadableAfterSave) throw new Error("injected unavailable reconciliation read");
      return f.store.load();
    }, save: (records, revision) => {
      const next = f.store.save(records, revision);
      savedId = records[0]!.id;
      cipher = keys.encrypt(savedId, "synthetic early observer content");
      failed = true; throw new Error(`injected lost creation response at ${next}`);
    } });
    assert.throws(() => registry.create("new project"), /lost creation response/u);
    assert.ok(savedId); assert.ok(cipher);
    assert.equal(keys.hasKey(savedId), true, "unknown outcome does not authorize compensating key destruction");
    new ProjectRegistry(keys, f.store);
    assert.equal(keys.decrypt(savedId, cipher), "synthetic early observer content");
  });
}

test("a confirmed uncommitted creation still cleans up only its newly allocated key", () => {
  const keys = new CryptoShredKeyStore(); let allocated: string | undefined;
  const registry = new ProjectRegistry(keys, {
    load: () => ({ revision: 0, records: [] }),
    save: records => { allocated = records[0]!.id; throw new Error("injected pre-commit failure"); },
  });
  assert.throws(() => registry.create("not saved"), /pre-commit failure/u);
  assert.ok(allocated); assert.equal(keys.hasKey(allocated), false);
});

test("a real record-version conflict preserves the competing update and permits explicit retry", () => {
  const f = fixture(); let competing: (() => void) | undefined;
  const manager = f.open({ load: () => f.store.load(), save: (records, revision) => {
    const callback = competing; competing = undefined; callback?.();
    return f.store.save(records, revision);
  } });
  const a = manager.create({ name: "first" }), b = manager.create({ name: "second" });
  manager.switch(a.id);
  const sibling = new ProjectRegistry(new CryptoShredKeyStore(), f.store);
  competing = () => sibling.rename(a.id, "competing rename");
  assert.throws(() => manager.switch(b.id), /project record conflict/u);
  assert.equal(manager.active(undefined), a.id);
  assert.equal(manager.list().find(record => record.id === a.id)?.name, "competing rename");
  manager.switch(b.id);
  assert.equal(f.open().active(undefined), b.id);
});

test("self-selection is a write-free no-op and compaction remains explicitly available", () => {
  const f = fixture(), manager = f.open(), project = manager.create({ name: "keep detail" });
  manager.session(project.id).append("user", "important operator direction");
  manager.session(project.id).append("assistant", "retained detailed text");
  manager.switch(project.id); const before = readFileSync(f.path);
  assert.deepEqual(manager.switch(project.id), { incoming: project.id });
  assert.deepEqual(readFileSync(f.path), before);
  assert.equal(manager.session(project.id).history()[1]?.text, "retained detailed text");
  assert.equal(manager.session(project.id).compactions().length, 0);
  for (const count of [undefined, -1, 0.5, NaN, Infinity]) {
    assert.throws(() => manager.compact(project.id, count as number), /explicit nonnegative/u);
  }
  manager.compact(project.id, 2);
  assert.equal(manager.session(project.id).compactions().length, 1);
  assert.match(manager.session(project.id).compactions()[0]!.keptFacts[0]!, /important operator direction/u);
  assert.match(manager.session(project.id).compactions()[0]!.keptFacts[1]!, /retained detailed text/u);
  manager.archive(project.id);
  assert.throws(() => manager.compact(project.id, 1), /archived/u);
});

test("direct creation and lifecycle promotion share the tenant-local foreground commit", () => {
  const f = fixture(), registry = new ProjectRegistry(new CryptoShredKeyStore(), f.store);
  const a = registry.create("a", "active", "alpha");
  const beta = registry.create("beta", "active", "beta");
  const b = registry.create("b", "active", "alpha");
  assert.equal(registry.lifecycle(a.id), "background");
  assert.equal(registry.lifecycle(beta.id), "active");
  assert.equal(registry.lifecycle(b.id), "active");
  const beforeRevision = f.store.load().revision;
  assert.equal(typeof beforeRevision, "number");
  registry.setLifecycle(a.id, "active");
  assert.equal(f.store.load().revision, beforeRevision! + 1);
  assert.equal(registry.lifecycle(a.id), "active");
  assert.equal(registry.lifecycle(b.id), "background");
  assert.equal(registry.lifecycle(beta.id), "active");
});

test("an injected exception after completed save is not reported as an unchanged selection", () => {
  const f = fixture(); let fail = false;
  const manager = f.open({ load: () => f.store.load(), save: (records, revision) => {
    const next = f.store.save(records, revision);
    if (fail) throw new Error("injected lost save response");
    return next;
  } });
  const a = manager.create({ name: "first" }), b = manager.create({ name: "second" });
  manager.switch(a.id); fail = true;
  assert.throws(() => manager.switch(b.id), /lost save response/u);
  assert.equal(manager.active(undefined), b.id);
  assert.equal(manager.lifecycle(a.id), "background");
  assert.equal(f.open().active(undefined), b.id);
});
