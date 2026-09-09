import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes, createHash } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, renameSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { FileMemoryPartition, type FileMemoryPartitionOptions, type MemoryPartitionScope, type PersistedMemoryEntry, type MemoryControlActor } from "../src/memory/persistence.js";
import { FileWrappedKeyPersistence } from "../src/keystore/file_wrapped_key_persistence.js";
import { CryptoShredKeyStore, type Ciphertext } from "../src/keystore/keystore.js";
import { memoryExcerptText, memoryCurrentWithSourcesAt, type ManualMemoryCustody, type DerivedMemoryCustody } from "../src/memory/model.js";

const moduleURL = new URL("../src/memory/persistence.js", import.meta.url).href;
const controlActor: MemoryControlActor = { actorId: "fixture-owner", actorKind: "human", role: "owner", permission: "memory.forget" };
function fixture(scope: MemoryPartitionScope = { ownerId: "owner-secret", kind: "project", projectId: "project-secret" }) {
  const root = mkdtempSync(join(tmpdir(), "keep-memory-custody-"));
  const options: FileMemoryPartitionOptions = {
    directory: join(root, "data"), scope,
    keyAuthority: { masterKeyPath: join(root, "master.key"), wrappedKeysPath: join(root, "keys.json") },
  };
  // Fixture authority only: production authority initialization remains a separate boundary.
  writeFileSync(options.keyAuthority.masterKeyPath, randomBytes(32), { flag: "wx", mode: 0o600 });
  const partition = new FileMemoryPartition(options); partition.initialize();
  return { root, options, partition };
}
function entry(id = "memory-secret", scope: MemoryPartitionScope["kind"] = "project"): PersistedMemoryEntry {
  return {
    lesson: { id, content: "The customer requires a private deployment.", tier: "candidate", origin: "external", provenanceEventId: "provenance-secret",
      scope, kind: "fact", importance: 0.7, evidence: [], createdTs: 100, validFrom: 90, citation: "source-secret" },
    embedding: [0.3, 0.4, 0.5], access: { count: 0, lastAccessedTs: 100 },
  };
}
function childRead(options: FileMemoryPartitionOptions) {
  const child = spawnSync(process.execPath, ["--input-type=module", "-e",
    `import { FileMemoryPartition } from ${JSON.stringify(moduleURL)}; process.stdout.write(JSON.stringify(new FileMemoryPartition(JSON.parse(process.argv[1])).read()));`, JSON.stringify(options)],
  { encoding: "utf8", timeout: 5000, maxBuffer: 1024 * 1024 });
  assert.equal(child.status, 0, child.stderr);
  return JSON.parse(child.stdout) as ReturnType<FileMemoryPartition["read"]>;
}

function derivedFixture(useUntil: number | null = null) {
  const f = fixture({ ownerId: "owner", kind: "user" });
  const manual = (id: string, content: string): PersistedMemoryEntry => {
    const custody: ManualMemoryCustody = { schema: "keep.memory.manual-custody/v1", scope: f.options.scope,
      source: { kind: "authenticated-manual-command", operationId: id, actorId: "owner", actorKind: "human" },
      consentEventId: "consent", purpose: "explicit-manual-memory", assertion: "asserted", uncertainty: "unassessed", authority: "none",
      retention: { useUntil, expiryDisposition: "withhold-pending-erasure", legalHoldAssessment: "unassessed" },
      residency: { storage: "operator-host", region: "unverified", embeddingProcessing: "local" },
      dependencies: { embeddingProvider: "fixture", embeddingModel: null },
      derivatives: { coEncrypted: ["embedding", "access"], outsideCustody: "caller-provider-backup-copies-untracked" } };
    return { ...entry(id, "user"), lesson: { ...entry(id, "user").lesson, origin: "self", content, custody, validFrom: 100 } };
  };
  const parents = [manual("policy", "Retry policy: seven. café."), manual("pending", "Pending task: correct retry configuration.")];
  assert.equal(f.partition.commit("parents", 0, parents).disposition, "committed");
  const view = (id = "view", operationId = "consolidate", sources = parents): PersistedMemoryEntry => {
    const spans = sources.map(row => ({ itemId: row.lesson.id, provenanceEventId: row.lesson.provenanceEventId, startByte: 0, endByte: Buffer.byteLength(row.lesson.content) }));
    const custody: DerivedMemoryCustody = { schema: "keep.memory.derived-custody/v1", scope: f.options.scope,
      source: { kind: "host-extractive-command", operationId, actorId: "owner", actorKind: "human" },
      consentEventId: "consent", purpose: "source-preserving-memory", assertion: "derived", uncertainty: "unassessed", authority: "none",
      algorithm: "extractive-v1", sources: spans,
      retention: { useUntil, expiryDisposition: "withhold-pending-erasure", legalHoldAssessment: "unassessed" },
      residency: { storage: "operator-host", region: "unverified", embeddingProcessing: "none" },
      dependencies: { embeddingProvider: null, embeddingModel: null },
      derivatives: { coEncrypted: ["sources", "access"], outsideCustody: "caller-provider-backup-copies-untracked" } };
    return { lesson: { ...entry(id, "user").lesson, content: memoryExcerptText(spans, new Map(sources.map(row => [row.lesson.id, row.lesson]))),
      origin: "self", custody, createdTs: 200, validFrom: 200 }, access: { count: 0, lastAccessedTs: 200 } };
  };
  return { ...f, parents, view };
}

test("manual v2 source custody: strict no-vector inventory and mixed-version fresh-process read", () => {
  const f = derivedFixture(), original = f.parents[0]!;
  const source: PersistedMemoryEntry = { lesson: { ...original.lesson, id: "source-only", custody: {
    ...original.lesson.custody as ManualMemoryCustody, schema: "keep.memory.manual-custody/v2",
    residency: { storage: "operator-host", region: "unverified", embeddingProcessing: "none" },
    dependencies: { embeddingProvider: null, embeddingModel: null },
    derivatives: { coEncrypted: ["access"], outsideCustody: "caller-provider-backup-copies-untracked" },
  } }, access: { ...original.access } };
  for (const invalid of [
    { ...source, embedding: [0] },
    { ...source, lesson: { ...source.lesson, custody: undefined } },
    { ...source, lesson: { ...source.lesson, custody: { ...source.lesson.custody, dependencies: { embeddingProvider: "fabricated", embeddingModel: null } } } },
    { ...original, embedding: undefined },
  ]) assert.notEqual(f.partition.commit("invalid", 1, [...f.parents, invalid as unknown as PersistedMemoryEntry]).disposition, "committed");
  assert.equal(f.partition.read().revision, 1);
  assert.equal(f.partition.commit("source", 1, [...f.parents, source]).disposition, "committed");
  const restored = childRead(f.options);
  assert.deepEqual(restored.entries, [...f.parents, source]);
  assert.equal(f.partition.controlCommand("erase-source", { action: "erase", id: source.lesson.id }, controlActor).disposition, "committed");
  assert.deepEqual(childRead(f.options).entries, f.parents, "erasing source-only key does not erase old vector sources");
});

for (const erased of ["policy", "pending"]) test("derived view: erase " + erased + " revokes dependent keys, not the other parent", () => {
  const f = derivedFixture(), derived = f.view();
  assert.equal(f.partition.commit("consolidate", 1, [...f.parents, derived]).disposition, "committed");
  const restored = childRead(f.options);
  assert.deepEqual(restored.entries.slice(0, 2), f.parents);
  assert.deepEqual(restored.entries[2], derived); assert.equal("embedding" in restored.entries[2]!, false);
  assert.equal(f.partition.controlCommand("hold", { action: "hold", id: "view", holdId: "case", active: true }, controlActor).disposition, "committed");
  assert.deepEqual(f.partition.controlCommand("blocked", { action: "erase", id: erased }, controlActor),
    { disposition: "rejected", operationId: "blocked", reason: "legal-hold" });
  assert.equal(f.partition.read().entries.length, 3);
  assert.equal(f.partition.controlCommand("release", { action: "hold", id: "view", holdId: "case", active: false }, controlActor).disposition, "committed");
  assert.equal(f.partition.controlCommand("erase", { action: "erase", id: erased }, controlActor).disposition, "committed");
  const current = childRead(f.options);
  assert.deepEqual(current.entries.map(row => row.lesson.id), [erased === "policy" ? "pending" : "policy"]);
  assert.equal(f.partition.lookupCommand("consolidate", "0".repeat(64)).disposition, "withheld");
  assert.equal(f.partition.commit("replay", current.revision, [...current.entries, f.view("replacement", "replay")]).disposition, "rejected");
});

for (const invalid of ["fake-vector", "unknown-algorithm", "missing-source", "wrong-provenance", "wrong-consent", "wrong-scope", "split-utf8", "fabricated-text", "promoted", "duplicate-source", "same-transaction-parent"] as const) {
  test("derived view refuses " + invalid + " without changing the originals", () => {
    const f = derivedFixture(), row = structuredClone(f.view());
    const c = row.lesson.custody as DerivedMemoryCustody;
    const bad = row as unknown as { embedding: number[]; lesson: Record<string, any> };
    if (invalid === "fake-vector") bad.embedding = [0];
    if (invalid === "unknown-algorithm") bad.lesson.custody.algorithm = "guess-v9";
    if (invalid === "missing-source") bad.lesson.custody.sources[0].itemId = "missing";
    if (invalid === "wrong-provenance") bad.lesson.custody.sources[0].provenanceEventId = "wrong";
    if (invalid === "wrong-consent") bad.lesson.custody.consentEventId = "unadmitted";
    if (invalid === "wrong-scope") bad.lesson.custody.scope.ownerId = "foreign";
    if (invalid === "split-utf8") bad.lesson.custody.sources[0].endByte = Buffer.byteLength(f.parents[0]!.lesson.content) - 2;
    if (invalid === "fabricated-text") row.lesson.content += " Invented conclusion.";
    if (invalid === "promoted") row.lesson.tier = "confirmed";
    if (invalid === "duplicate-source") bad.lesson.custody.sources[1] = c.sources[0];
    const parents = structuredClone(f.parents);
    if (invalid === "same-transaction-parent") {
      const extra = { ...parents[0]!, lesson: { ...parents[0]!.lesson, id: "new-source" } }; parents.push(extra);
      bad.lesson.custody.sources[0].itemId = "new-source";
    }
    assert.equal(f.partition.commit("consolidate", 1, [...parents, row]).disposition, "rejected", invalid);
    assert.deepEqual(f.partition.read().entries, f.parents);
  });
}

test("derived view: retirement withholds current use but keeps loadable history, and blocks stale publication", () => {
  const f = derivedFixture(), view = f.view();
  assert.equal(f.partition.commit("consolidate", 1, [...f.parents, view]).disposition, "committed");
  const retired = structuredClone(f.parents); retired[0]!.lesson.tier = "retired"; retired[0]!.lesson.validTo = 300;
  assert.equal(f.partition.commit("retire", 2, [...retired, view]).disposition, "committed");
  const history = childRead(f.options), byId = new Map(history.entries.map(row => [row.lesson.id, row.lesson]));
  assert.equal(memoryCurrentWithSourcesAt(view.lesson, 400, byId), false);
  assert.equal(f.partition.commit("later", 3, [...history.entries, f.view("later-view", "later")]).disposition, "rejected");
  assert.equal(history.entries.length, 3);
});

test("derived view: trusted commit clock refuses expired parents, while expiry preserves administrative history", () => {
  const f = derivedFixture(350); let at = 300;
  const partition = new FileMemoryPartition({ ...f.options, clock: () => at });
  const view = f.view();
  assert.equal(partition.commit("consolidate", 1, [...f.parents, view]).disposition, "committed");
  at = 350;
  const history = partition.read(), byId = new Map(history.entries.map(row => [row.lesson.id, row.lesson]));
  assert.equal(memoryCurrentWithSourcesAt(view.lesson, at, byId), false);
  assert.equal(partition.commit("expired", 2, [...history.entries, f.view("late", "expired")]).disposition, "rejected");
  assert.equal(childRead(f.options).entries.length, 3, "expiry does not erase or break loading");
});

test("derived view: nested views inherit all erasure edges without replacing source items", () => {
  const f = derivedFixture(), first = f.view();
  assert.equal(f.partition.commit("consolidate", 1, [...f.parents, first]).disposition, "committed");
  const nested = f.view("nested", "nested-write", [first, f.parents[1]!]);
  assert.equal(f.partition.commit("nested-write", 2, [...f.parents, first, nested]).disposition, "committed");
  assert.equal(f.partition.controlCommand("erase-root", { action: "erase", id: "policy" }, controlActor).disposition, "committed");
  assert.deepEqual(childRead(f.options).entries.map(row => row.lesson.id), ["pending"]);
});

function receiptFixture(partition: FileMemoryPartition, options: FileMemoryPartitionOptions) {
  const keys = new CryptoShredKeyStore(new FileWrappedKeyPersistence(options.keyAuthority));
  const envelope = JSON.parse(readFileSync(partition.snapshotPath, "utf8")) as { key: string; payload: Ciphertext };
  const snapshot = JSON.parse(keys.decrypt(envelope.key, envelope.payload)) as {
    schema: string; operations: { id: string; revision: number; receipt: { key: string; dependencies: string[]; payload: Ciphertext } }[];
  };
  const save = (value: unknown) => {
    const { iv, authTag, data } = keys.encrypt(envelope.key, JSON.stringify(value));
    writeFileSync(partition.snapshotPath, JSON.stringify({ ...envelope, payload: { iv, authTag, data } }));
  };
  return { keys, envelope, snapshot, save };
}

test("receipt fingerprints are separately encrypted and full-view dependencies revoke retries without losing admission events", () => {
  const { partition, options } = fixture(); const rows = [entry(), entry("survivor")];
  const requestDigest = createHash("sha256").update(rows[0]!.lesson.content).digest("hex");
  const event = { id: "original-admission", payload: { event: "lesson_stored", lessonId: "memory-secret" } };
  assert.equal(partition.commit("original-store", 0, rows, { requestDigest, result: { id: "memory-secret" }, events: [event] }).disposition, "committed");
  const opened = receiptFixture(partition, options), stored = opened.snapshot.operations[0]!;
  assert.equal(opened.snapshot.schema, "keep.memory.partition/v2");
  assert.deepEqual(stored.receipt.dependencies, ["memory-secret", "survivor"]);
  const inner = JSON.parse(opened.keys.decrypt(stored.receipt.key, stored.receipt.payload));
  assert.equal(inner.operation.command.requestDigest, requestDigest);
  for (const digest of [requestDigest, inner.operation.requestDigest]) assert.equal(JSON.stringify(opened.snapshot).includes(digest), false);
  assert.equal(partition.controlCommand("erase", { action: "erase", id: "memory-secret" }, controlActor).disposition, "committed");
  const current = receiptFixture(partition, options);
  assert.equal(current.keys.hasKey(stored.receipt.key), false);
  assert.throws(() => current.keys.decrypt(stored.receipt.key, stored.receipt.payload));
  assert.deepEqual(partition.lookupCommand("original-store", requestDigest), { disposition: "withheld", revision: 1, reason: "receipt-erased" });
  assert.equal(partition.lookupCommand("original-store", "0".repeat(64)).disposition, "withheld", "erased fingerprints cannot be compared or guessed");
  assert.equal(partition.commit("original-store", 0, rows).disposition, "withheld");
  assert.deepEqual(partition.read().entries.map(row => row.lesson.id), ["survivor"]);
  assert.deepEqual(partition.admissionEvents().filter(row => row.id === event.id), [event]);
  partition.controlCommand("erase", { action: "erase", id: "memory-secret" }, controlActor);
  assert.deepEqual(partition.admissionEvents().filter(row => row.id === event.id), [event], "outbox transfer preserves the original identity exactly once");
});

test("data restored before the original write still reserves erased operation identity", () => {
  const { partition, options } = fixture(); const beforeWrite = readFileSync(partition.snapshotPath);
  partition.commit("original", 0, [entry()]);
  assert.equal(partition.controlCommand("erase", { action: "erase", id: "memory-secret" }, controlActor).disposition, "committed");
  writeFileSync(partition.snapshotPath, beforeWrite);
  assert.deepEqual(childRead(options).entries, []);
  assert.equal(partition.lookupCommand("original", "0".repeat(64)).disposition, "withheld");
  assert.equal(partition.commit("original", 0, [entry()]).disposition, "withheld");
  assert.equal(partition.commit("new-operation", 0, [entry()]).disposition, "rejected", "the original item identity is also reserved");
  assert.equal(partition.commit("independent", 0, [entry("new-item")]).disposition, "committed");
});

for (const tamper of ["missing-key", "dependencies", "identity", "swapped-payload"] as const) {
  test(`unadmitted ${tamper} receipt corruption holds the entire partition`, () => {
    const { partition, options } = fixture(); partition.commit("first", 0, [entry()]); partition.commit("second", 1, [entry(), entry("second")]);
    const opened = receiptFixture(partition, options), first = opened.snapshot.operations[0]!, second = opened.snapshot.operations[1]!;
    if (tamper === "missing-key") opened.keys.shred(first.receipt.key);
    else {
      if (tamper === "dependencies") first.receipt.dependencies = [];
      if (tamper === "identity") first.id = "forged";
      if (tamper === "swapped-payload") first.receipt.payload = second.receipt.payload;
      opened.save(opened.snapshot);
    }
    assert.throws(() => partition.read());
    assert.equal(partition.lookupCommand("first", "0".repeat(64)).disposition, "held");
    assert.equal(partition.commit("fresh", 2, [entry(), entry("second")]).disposition, "held");
  });
}

for (const scope of [
  { ownerId: "owner", kind: "user" },
  { ownerId: "project:alpha", kind: "project", tenantId: "tenant", projectId: "alpha" },
] satisfies MemoryPartitionScope[]) {
  test(`${scope.tenantId ? "enterprise" : "n1"}: holds, key revocation and old-data restore retain current deletion authority`, () => {
    const { partition, options } = fixture(scope); const rows = [entry("erased-item", scope.kind), entry("surviving-item", scope.kind)];
    assert.equal(partition.commit("seed", 0, rows).disposition, "committed");
    const oldData = readFileSync(partition.snapshotPath), oldKeys = readFileSync(options.keyAuthority.wrappedKeysPath);
    assert.equal(partition.controlCommand("hold", { action: "hold", id: "erased-item", holdId: "case-123", active: true }, { ...controlActor, permission: "config.write" }).disposition, "committed");
    assert.deepEqual(partition.controlCommand("erase", { action: "erase", id: "erased-item" }, controlActor), { disposition: "rejected", operationId: "erase", reason: "legal-hold" });
    assert.ok(oldKeys.equals(readFileSync(options.keyAuthority.wrappedKeysPath))); assert.equal(partition.read().entries.length, 2);
    assert.equal(partition.controlCommand("release", { action: "hold", id: "erased-item", holdId: "case-123", active: false }, { ...controlActor, permission: "config.write" }).disposition, "committed");
    assert.equal(partition.controlCommand("erase", { action: "erase", id: "erased-item" }, controlActor).disposition, "committed");
    const view = childRead(options); assert.deepEqual(view.entries.map(row => row.lesson.id), ["surviving-item"]);
    assert.deepEqual(view.erasures, [{ id: "erased-item", operationId: "erase", local: "key-revoked" }]);
    assert.deepEqual(partition.commit("stale-preparer", 1, rows), { disposition: "rejected", operationId: "stale-preparer", reason: "erasure-required" });
    assert.equal(partition.commit("survivor-write", 1, [...view.entries, entry("later-item", scope.kind)]).disposition, "committed");
    assert.deepEqual(partition.read().entries.map(row => row.lesson.id), ["surviving-item", "later-item"]);
    writeFileSync(partition.snapshotPath, oldData);
    assert.deepEqual(childRead(options).entries.map(row => row.lesson.id), ["surviving-item"], "data-only restore cannot resurrect the erased item");
    // Even an old wrapped-key map cannot override newer retained control. It is pending,
    // not falsely reported currently revoked, until the original command re-revokes it.
    writeFileSync(options.keyAuthority.wrappedKeysPath, oldKeys);
    assert.deepEqual(partition.read().erasures, [{ id: "erased-item", operationId: "erase", local: "revocation-pending" }]);
    assert.deepEqual(partition.read().entries.map(row => row.lesson.id), ["surviving-item"]);
    const replay = partition.controlCommand("erase", { action: "erase", id: "erased-item" }, controlActor);
    assert.deepEqual(replay, { disposition: "committed", operationId: "erase", revision: 1, reconciled: true });
    assert.deepEqual(partition.read().erasures, view.erasures);
    assert.equal(partition.admissionEvents().filter(event => event.payload["event"] === "memory.erasure.key-revoked").length, 1);
    assert.equal(partition.controlCommand("erase", { action: "erase", id: "surviving-item" }, controlActor).disposition, "rejected");
    assert.equal(partition.controlCommand("late-hold", { action: "hold", id: "erased-item", holdId: "late", active: true }, controlActor).disposition, "rejected");
    assert.equal(readFileSync(partition.controlPath, "utf8").includes("erased-item"), false);
  });
}

for (const [point, occurrence] of [
  ["before-control-write", 1], ["before-control-rename", 1], ["after-control-rename", 1], ["after-control-sync", 1],
  ["after-key-revocation", 1], ["before-control-rename", 2], ["after-control-rename", 2],
] as const) {
  test(`erasure ${point}/${occurrence}: partial deletion resumes original command in a fresh process`, () => {
    const { partition, options } = fixture(); assert.equal(partition.commit("seed", 0, [entry(), entry("survivor")]).disposition, "committed");
    let seen = 0;
    const faulted = new FileMemoryPartition({ ...options, fault: at => { if (at === point && ++seen === occurrence) throw new Error("injected custody fault"); } });
    const result = faulted.controlCommand("erase-original", { action: "erase", id: "memory-secret" }, controlActor);
    assert.equal(result.disposition, "held", JSON.stringify(result));
    const beforeIntent = occurrence === 1 && (point === "before-control-write" || point === "before-control-rename");
    assert.deepEqual(partition.read().entries.map(row => row.lesson.id), beforeIntent ? ["memory-secret", "survivor"] : ["survivor"]);
    const child = spawnSync(process.execPath, ["--input-type=module", "-e",
      `import { FileMemoryPartition } from ${JSON.stringify(moduleURL)}; const p=new FileMemoryPartition(JSON.parse(process.argv[1])); process.stdout.write(JSON.stringify(p.controlCommand('erase-original',{action:'erase',id:'memory-secret'},JSON.parse(process.argv[2]))));`,
      JSON.stringify(options), JSON.stringify(controlActor)], { encoding: "utf8", timeout: 5000, maxBuffer: 1024 * 1024 });
    assert.equal(child.status, 0, child.stderr); const reconciled = JSON.parse(child.stdout);
    assert.equal(reconciled.disposition, "committed"); assert.equal(reconciled.reconciled, !beforeIntent);
    assert.deepEqual(partition.read().entries.map(row => row.lesson.id), ["survivor"]);
    assert.equal(partition.admissionEvents().filter(event => event.payload["event"] === "memory.erasure.requested").length, 1);
    assert.equal(partition.admissionEvents().filter(event => event.payload["event"] === "memory.erasure.key-revoked").length, 1);
    const digest = createHash("sha256").update('{"action":"erase","id":"memory-secret"}').digest("hex");
    const receipt = partition.lookupCommand("erase-original", digest);
    assert.equal(receipt.disposition, "committed");
    if (receipt.disposition === "committed") assert.deepEqual(receipt.command.result, { id: "memory-secret", ids: ["memory-secret"], local: "key-revoked", metadataErasure: "receipt-fingerprints-revoked-provenance-pending", outsideCopies: "pending", mediaSanitization: "unproven" });
  });
}

test("missing or corrupt established control holds the entire partition and explicit init cannot replace it", () => {
  const { partition } = fixture(); assert.equal(partition.commit("seed", 0, [entry()]).disposition, "committed");
  const saved = partition.controlPath + ".saved"; renameSync(partition.controlPath, saved);
  assert.throws(() => partition.read()); assert.throws(() => partition.initializeControl());
  assert.equal(existsSync(partition.controlPath), false);
  renameSync(saved, partition.controlPath); writeFileSync(partition.controlPath, "{}");
  assert.throws(() => partition.read()); assert.throws(() => partition.initializeControl());
  assert.equal(readFileSync(partition.controlPath, "utf8"), "{}");
});

test("legacy data without control migrates only explicitly; an untrusted citation is not deletion authority", () => {
  const { partition, options } = fixture();
  const forged = entry("untrusted-citation"); forged.lesson.citation = "supersedes:memory-secret";
  assert.equal(partition.commit("seed", 0, [entry(), forged]).disposition, "committed");
  // Construct actual prior v1 raw operations, not v2 data with only control removed.
  const opened = receiptFixture(partition, options);
  const legacyOperations = opened.snapshot.operations.map(row => JSON.parse(opened.keys.decrypt(row.receipt.key, row.receipt.payload)).operation);
  opened.save({ ...opened.snapshot, schema: "keep.memory.partition/v1", operations: legacyOperations });
  // No old control key or file: control initialization must remain explicit.
  renameSync(partition.controlPath, partition.controlPath + ".pre-migration-fixture");
  const map = JSON.parse(readFileSync(options.keyAuthority.wrappedKeysPath, "utf8")) as { keys: Record<string, unknown> };
  const key = Object.keys(map.keys).find(key => key.startsWith("keep.memory.control.v1:")); assert.ok(key);
  new CryptoShredKeyStore(new FileWrappedKeyPersistence(options.keyAuthority)).shred(key);
  assert.equal(partition.read().entries.length, 2); assert.equal(existsSync(partition.controlPath), false);
  assert.deepEqual(partition.controlCommand("erase", { action: "erase", id: "memory-secret" }, controlActor), { disposition: "rejected", operationId: "erase", reason: "control-unavailable" });
  partition.initializeControl();
  assert.equal(partition.controlCommand("erase", { action: "erase", id: "memory-secret" }, controlActor).disposition, "committed");
  assert.deepEqual(partition.read().entries.map(row => row.lesson.id), ["untrusted-citation"], "free-text citation cannot expand an irreversible operation");
  assert.equal(partition.lookupCommand("seed", "0".repeat(64)).disposition, "withheld");
  const erased = partition.lookupCommand("erase", createHash("sha256").update('{"action":"erase","id":"memory-secret"}').digest("hex"));
  assert.equal(erased.disposition, "committed");
  if (erased.disposition === "committed") assert.equal((erased.command.result as { metadataErasure: string }).metadataErasure, "legacy-fingerprints-and-provenance-pending");
  const retained = receiptFixture(partition, options);
  assert.ok(JSON.stringify(retained.snapshot).includes(legacyOperations[0].requestDigest), "legacy fingerprint cleanup is explicitly pending, not silently claimed complete");
});

for (const scope of [
  { ownerId: "owner-secret", kind: "project", projectId: "project-secret" },
  { ownerId: "owner-secret", tenantId: "tenant-secret", kind: "agent", projectId: "project-secret", agentId: "agent-secret" },
] satisfies MemoryPartitionScope[]) {
  test(`${scope.tenantId ? "enterprise" : "n1"}: encrypted complete partition survives an actual new process`, () => {
    const { options, partition } = fixture(scope);
    const rows = [entry("memory-secret", scope.kind), entry("second-secret", scope.kind)];
    assert.deepEqual(partition.commit("operation-secret", 0, rows), { disposition: "committed", operationId: "operation-secret", revision: 1, reconciled: false });
    assert.deepEqual(childRead(options), { revision: 1, scope, entries: rows });
    const atRest = readFileSync(partition.snapshotPath, "utf8") + readFileSync(options.keyAuthority.wrappedKeysPath, "utf8");
    for (const secret of [rows[0]!.lesson.content, "memory-secret", "operation-secret", "owner-secret", "tenant-secret", "project-secret", "agent-secret", "source-secret", "provenance-secret",
      createHash("sha256").update(rows[0]!.lesson.content).digest("hex"), "plaintextHash"]) assert.equal(atRest.includes(secret), false, secret);
    assert.equal(statSync(options.directory).mode & 0o777, 0o700);
    assert.equal(statSync(partition.snapshotPath).mode & 0o777, 0o600);
    const map = JSON.parse(readFileSync(options.keyAuthority.wrappedKeysPath, "utf8")) as { keys: Record<string, unknown> };
    assert.equal(Object.keys(map.keys).filter(key => key.startsWith("keep.memory.item.v1:")).length, 2);
  });
}

test("reads and caller inputs cannot mutate persisted state or partition binding", () => {
  const { partition, options } = fixture();
  const row = entry(); assert.equal(partition.commit("add", 0, [row]).disposition, "committed");
  row.lesson.content = "caller changed";
  (options.scope as { ownerId: string }).ownerId = "caller changed";
  const view = partition.read();
  assert.throws(() => { view.entries[0]!.lesson.content = "view changed"; }, TypeError);
  assert.throws(() => { view.entries[0]!.lesson.evidence.push({ spineEventId: "forged", context: "forged", ts: 0, cleanResolved: true }); }, TypeError);
  assert.equal(partition.read().entries[0]!.lesson.content, entry().lesson.content);
  assert.equal(partition.read().scope.ownerId, "owner-secret");
});

test("expected revisions prevent lost updates and exact operation identity reconciles without replay", () => {
  const { partition, options } = fixture(); const other = new FileMemoryPartition(options);
  const original = entry();
  assert.equal(partition.commit("first", 0, [original]).disposition, "committed");
  assert.deepEqual(other.commit("stale", 0, [entry("other")]), { disposition: "conflict", operationId: "stale", revision: 1 });
  assert.equal(other.commit("second", 1, [original, entry("second")]).disposition, "committed");
  assert.deepEqual(partition.commit("first", 0, [original]), { disposition: "committed", operationId: "first", revision: 1, reconciled: true });
  assert.equal(partition.read().revision, 2);
  assert.deepEqual(partition.commit("first", 0, [entry("changed")]), { disposition: "rejected", operationId: "first", reason: "operation-reused" });
  assert.deepEqual(partition.commit("remove", 2, []), { disposition: "rejected", operationId: "remove", reason: "erasure-required" });
});

test("correction publishes retired interval and successor as one recoverable snapshot", () => {
  const { partition, options } = fixture(); const original = entry();
  assert.equal(partition.commit("first", 0, [original]).disposition, "committed");
  const retired = structuredClone(original); retired.lesson.validTo = 110; retired.lesson.tier = "retired";
  const successor = entry("successor"); successor.lesson.content = "Corrected deployment fact.";
  assert.equal(partition.commit("correct", 1, [retired, successor]).disposition, "committed");
  assert.deepEqual(childRead(options).entries, [retired, successor]);
});

for (const point of ["before-write", "before-rename", "after-rename", "after-directory-sync"] as const) {
  test(`${point}: failed publication retains old state or reconciles the original committed operation`, () => {
    const { options, partition } = fixture(); const original = entry();
    partition.commit("first", 0, [original]);
    const next = [original, entry("successor")];
    const writer = new FileMemoryPartition({ ...options, fault: observed => { if (observed === point) throw new Error("injected IO failure"); } });
    const afterRename = point === "after-rename" || point === "after-directory-sync";
    assert.deepEqual(writer.commit("second", 1, next), { disposition: "held", operationId: "second", publication: afterRename ? "unknown" : "not-attempted", reason: afterRename ? "commit-uncertain" : "unavailable" });
    assert.deepEqual(childRead(options).entries, afterRename ? next : [original]);
    assert.deepEqual(partition.commit("second", 1, next), { disposition: "committed", operationId: "second", revision: 2, reconciled: afterRename });
    assert.equal(partition.read().revision, 2);
    assert.deepEqual(readdirSync(options.directory), ["partition.json.enc"]);
  });
}

test("missing established master, wrapped authority or snapshot never initializes replacement custody", () => {
  for (const target of ["master", "wrapped", "snapshot"] as const) {
    const { partition, options } = fixture(); partition.commit("add", 0, [entry()]);
    const path = target === "master" ? options.keyAuthority.masterKeyPath : target === "wrapped" ? options.keyAuthority.wrappedKeysPath : partition.snapshotPath;
    renameSync(path, `${path}.retained`);
    assert.throws(() => partition.read());
    assert.deepEqual(partition.commit("another", 1, [entry()]), { disposition: "held", operationId: "another", publication: "not-attempted", reason: "unavailable" });
    assert.equal(existsSync(path), false);
    assert.throws(() => partition.initialize());
    assert.equal(existsSync(path), false);
  }
});

test("strict master mode refuses missing, short or public master without modifying it", () => {
  const { options } = fixture();
  renameSync(options.keyAuthority.masterKeyPath, `${options.keyAuthority.masterKeyPath}.retained`);
  assert.throws(() => new FileWrappedKeyPersistence({ ...options.keyAuthority, requireExistingMasterKey: true }));
  assert.equal(existsSync(options.keyAuthority.masterKeyPath), false);
  writeFileSync(options.keyAuthority.masterKeyPath, Buffer.alloc(3), { mode: 0o600 });
  assert.throws(() => new FileWrappedKeyPersistence({ ...options.keyAuthority, requireExistingMasterKey: true }));
  assert.equal(statSync(options.keyAuthority.masterKeyPath).size, 3);
  writeFileSync(options.keyAuthority.masterKeyPath, randomBytes(32)); chmodSync(options.keyAuthority.masterKeyPath, 0o644);
  assert.throws(() => new FileWrappedKeyPersistence({ ...options.keyAuthority, requireExistingMasterKey: true }));
  assert.equal(statSync(options.keyAuthority.masterKeyPath).mode & 0o777, 0o644);
});

test("wrong full scope, swapped partition and modified ciphertext cannot disclose or overwrite state", () => {
  const { partition, options } = fixture({ ownerId: "owner", tenantId: "tenant", projectId: "project", agentId: "agent", kind: "agent" });
  partition.commit("add", 0, [entry("one", "agent")]);
  for (const field of ["ownerId", "tenantId", "projectId", "agentId"] as const) {
    const wrong = new FileMemoryPartition({ ...options, scope: { ...options.scope, [field]: "wrong" } });
    assert.throws(() => wrong.read(), /scope mismatch/u);
    assert.equal(wrong.commit("wrong", 1, [entry("one", "agent")]).disposition, "held");
  }
  const original = readFileSync(partition.snapshotPath);
  const sibling = new FileMemoryPartition({ ...options, directory: join(dirname(options.directory), "sibling"), scope: { ...options.scope, agentId: "sibling" } });
  sibling.initialize();
  writeFileSync(partition.snapshotPath, readFileSync(sibling.snapshotPath));
  assert.throws(() => partition.read(), /scope mismatch/u);
  writeFileSync(partition.snapshotPath, original);
  const envelope = JSON.parse(original.toString()) as { payload: { data: string } };
  envelope.payload.data = `${envelope.payload.data[0] === "0" ? "1" : "0"}${envelope.payload.data.slice(1)}`;
  writeFileSync(partition.snapshotPath, JSON.stringify(envelope));
  assert.throws(() => partition.read());
  assert.equal(partition.commit("wrong", 1, [entry("one", "agent")]).disposition, "held");
});

test("existing snapshot or key lock is held without stale takeover or mutation", () => {
  for (const target of ["snapshot", "keys"] as const) {
    const { partition, options } = fixture();
    const carrier = `${target === "snapshot" ? partition.snapshotPath : options.keyAuthority.wrappedKeysPath}.mutation.lock`;
    const marker = JSON.stringify({ schema: "keep.sync-file-lock/v1", pid: 2147483647, processStart: "dead", token: "preserve" });
    writeFileSync(carrier, marker, { mode: 0o600 });
    const before = readFileSync(partition.snapshotPath);
    assert.deepEqual(partition.commit("add", 0, [entry()]), { disposition: "held", operationId: "add", publication: "not-attempted", reason: "busy" });
    assert.equal(readFileSync(carrier, "utf8"), marker);
    assert.deepEqual(readFileSync(partition.snapshotPath), before);
  }
});

test("missing item key holds the whole selected partition rather than returning a partial view", () => {
  const { partition, options } = fixture(); partition.commit("add", 0, [entry(), entry("second")]);
  const keys = new CryptoShredKeyStore(new FileWrappedKeyPersistence({ ...options.keyAuthority, requireExistingMasterKey: true }));
  const map = JSON.parse(readFileSync(options.keyAuthority.wrappedKeysPath, "utf8")) as { keys: Record<string, unknown> };
  const itemKey = Object.keys(map.keys).find(key => key.startsWith("keep.memory.item.v1:"))!;
  keys.shred(itemKey);
  assert.throws(() => partition.read(), /erased/u);
  assert.equal(partition.commit("add-more", 1, [entry(), entry("second"), entry("third")]).disposition, "held");
});

test("malformed rows are rejected before any persistent write", () => {
  const { partition, options } = fixture(); const original = readFileSync(options.keyAuthority.wrappedKeysPath);
  for (const value of [
    { ...entry(), embedding: [NaN] },
    { ...entry(), lesson: { ...entry().lesson, scope: "agent" } },
    { ...entry(), access: { count: -1, lastAccessedTs: 0 } },
  ]) assert.equal(partition.commit("invalid", 0, [value as PersistedMemoryEntry]).disposition, "rejected");
  assert.equal(partition.commit("duplicate", 0, [entry(), entry()]).disposition, "rejected");
  assert.equal(partition.read().revision, 0);
  assert.deepEqual(readFileSync(options.keyAuthority.wrappedKeysPath), original);
});

test("admitted content, provenance and evidence are immutable; correction needs a successor", () => {
  const { partition } = fixture(); const original = entry();
  original.lesson.evidence.push({ spineEventId: "evidence", cleanResolved: true, context: "independent", ts: 120 });
  original.lesson.validTo = 200;
  assert.equal(partition.commit("admit", 0, [original]).disposition, "committed");
  for (const lesson of [
    { ...original.lesson, content: "rewrite" },
    { ...original.lesson, provenanceEventId: "forged" },
    { ...original.lesson, validTo: 300 },
    { ...original.lesson, evidence: [] },
  ]) {
    assert.deepEqual(partition.commit("overwrite", 1, [{ ...original, lesson }]), { disposition: "rejected", operationId: "overwrite", reason: "immutable-version" });
  }
  assert.deepEqual(partition.read().entries, [original]);
});

test("release failure after publication is uncertain, not a rollback or silent replay", () => {
  const { partition, options } = fixture(); const carrier = `${partition.snapshotPath}.mutation.lock`;
  const writer = new FileMemoryPartition({ ...options, fault: point => {
    if (point === "after-directory-sync") writeFileSync(carrier, "{\"token\":\"unexpected-owner\"}");
  } });
  assert.deepEqual(writer.commit("original", 0, [entry()]), { disposition: "held", operationId: "original", publication: "unknown", reason: "commit-uncertain" });
  assert.equal(partition.commit("original", 0, [entry()]).disposition, "held");
  // Test-owned explicit reconciliation of the deliberately corrupted carrier; no runtime takeover.
  renameSync(carrier, `${carrier}.retained`);
  assert.deepEqual(partition.commit("original", 0, [entry()]), { disposition: "committed", operationId: "original", revision: 1, reconciled: true });
  assert.equal(childRead(options).revision, 1);
});

test("an actual competing process is busy during publication and cannot lose the winner's update", () => {
  const { partition, options } = fixture(); let childResult: unknown;
  const writer = new FileMemoryPartition({ ...options, fault: point => {
    if (point !== "before-rename") return;
    const child = spawnSync(process.execPath, ["--input-type=module", "-e",
      `import { FileMemoryPartition } from ${JSON.stringify(moduleURL)}; const [options, rows] = JSON.parse(process.argv[1]); process.stdout.write(JSON.stringify(new FileMemoryPartition(options).commit("contender", 0, rows)));`,
      JSON.stringify([options, [entry("contender")]])], { encoding: "utf8", timeout: 5000, maxBuffer: 1024 * 1024 });
    assert.equal(child.status, 0, child.stderr); childResult = JSON.parse(child.stdout);
  } });
  assert.equal(writer.commit("winner", 0, [entry()]).disposition, "committed");
  assert.deepEqual(childResult, { disposition: "held", operationId: "contender", publication: "not-attempted", reason: "busy" });
  assert.deepEqual(partition.commit("contender", 0, [entry("contender")]), { disposition: "conflict", operationId: "contender", revision: 1 });
  assert.deepEqual(childRead(options).entries, [entry()]);
});

test("ordinary open never creates a missing directory and partial initialization is not reset", () => {
  const { partition, options } = fixture();
  renameSync(options.directory, `${options.directory}.retained`);
  assert.throws(() => partition.read());
  assert.equal(partition.commit("add", 0, [entry()]).disposition, "held");
  assert.equal(existsSync(options.directory), false);
  const beforeKeys = readFileSync(options.keyAuthority.wrappedKeysPath);
  assert.throws(() => partition.initialize(), /existing control requires reconciliation/u);
  assert.equal(existsSync(options.directory), false, "moving data cannot reset the surviving authority");
  assert.ok(beforeKeys.equals(readFileSync(options.keyAuthority.wrappedKeysPath)));
  const freshRoot = mkdtempSync(join(tmpdir(), "keep-partial-memory-init-"));
  const freshOptions = { ...options, directory: join(freshRoot, "data"), keyAuthority: { masterKeyPath: join(freshRoot, "master.key"), wrappedKeysPath: join(freshRoot, "wrapped.json") } };
  writeFileSync(freshOptions.keyAuthority.masterKeyPath, randomBytes(32), { mode: 0o600, flag: "wx" });
  const partial = new FileMemoryPartition({ ...freshOptions, fault: point => { if (point === "before-write") throw new Error("initialization failure"); } });
  assert.throws(() => partial.initialize(), /initialization failure/u);
  assert.equal(existsSync(freshOptions.directory), true);
  assert.equal(existsSync(partial.snapshotPath), false);
  assert.throws(() => new FileMemoryPartition(freshOptions).initialize(), /existing control requires reconciliation/u);
  assert.throws(() => partial.read());
});
