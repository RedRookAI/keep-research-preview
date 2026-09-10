import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import { ProjectRegistry } from "../src/session/project_registry.js";
import { ProjectSession } from "../src/session/project_session.js";
import { FileProjectSessionPersistence, ProjectSessionConflictError } from "../src/session/project_session_persistence.js";

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "keep-document-presence-"));
  const registry = new ProjectRegistry(new CryptoShredKeyStore()), project = registry.create("document fixture");
  const ns = registry.namespace(project.id), path = join(root, "session.json");
  const store = new FileProjectSessionPersistence(path), session = new ProjectSession(ns, undefined, store);
  session.append("user", "preserved session history");
  return { root, ns, path, store, session };
}
function installLegacy(f: ReturnType<typeof fixture>): string {
  const name = "legacy", encrypted = f.ns.encrypt("retained legacy document");
  mkdirSync(`${f.path}.documents`, { recursive: true });
  const path = join(`${f.path}.documents`, `${name}.json`);
  writeFileSync(path, JSON.stringify({ schemaVersion: 1, storageRevision: 0, name,
    cipher: { iv: encrypted.iv, authTag: encrypted.authTag, data: encrypted.data } }));
  assert.equal(f.store.loadDocument(name)!.storageRevision, 0);
  return path;
}

for (const operation of ["replace", "delete"]) test(`absence observation cannot ${operation} a later legacy-zero document`, () => {
  const f = fixture(), absent = f.session.resolveDocumentVersioned("legacy");
  assert.equal(absent.value, undefined);
  const path = installLegacy(f), before = readFileSync(path), sessionBefore = readFileSync(f.path);
  assert.throws(() => operation === "replace"
    ? f.session.putDocumentVersioned("legacy", "unchecked replacement", absent.revision)
    : f.session.forgetDocumentVersioned("legacy", absent.revision), ProjectSessionConflictError);
  assert.deepEqual(readFileSync(path), before); assert.deepEqual(readFileSync(f.path), sessionBefore);
});

test("an explicitly read legacy-zero document can be updated without losing its session", () => {
  const f = fixture(); installLegacy(f);
  const before = readFileSync(f.path), observed = f.session.resolveDocumentVersioned("legacy");
  assert.equal(observed.value, "retained legacy document"); assert.equal(observed.revision, 0);
  assert.equal(f.session.putDocumentVersioned("legacy", "deliberate update", observed.revision), 1);
  assert.throws(() => f.session.putDocumentVersioned("legacy", "stale update", observed.revision), ProjectSessionConflictError);
  assert.equal(f.session.resolveDocument("legacy"), "deliberate update");
  assert.deepEqual(readFileSync(f.path), before);
});

test("new-document creation and tombstone revival retain distinct versions", () => {
  const f = fixture(), absent = f.session.resolveDocumentVersioned("fresh");
  assert.equal(f.session.putDocumentVersioned("fresh", "first", absent.revision), 1);
  assert.equal(f.session.forgetDocumentVersioned("fresh", 1), true);
  assert.deepEqual(f.session.resolveDocumentVersioned("fresh"), { value: undefined, revision: 2 });
  assert.throws(() => f.session.putDocumentVersioned("fresh", "stale creation", absent.revision), ProjectSessionConflictError);
  assert.equal(f.session.putDocumentVersioned("fresh", "new content", 2), 3);
  assert.equal(f.session.resolveDocument("fresh"), "new content");
});
