import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ingestToSecondBrain, type SecondBrainDeps } from "../src/pipeline/second_brain.js";
import { ParserRegistry } from "../src/intake/parser_registry.js";
import { modelFirst } from "../src/intake/intake.js";
import { anticipate, type CandidateNeed } from "../src/anticipate/anticipation.js";
import { assembleDerived, applyRestored } from "../src/portability/store_io.js";
import { exportAll, importAll, erase } from "../src/portability/portability.js";
import { MemoryStore } from "../src/memory/store.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { SensitiveContextVault } from "../src/privacy/contextual_integrity.js";
import { ProjectRegistry } from "../src/session/project_registry.js";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import { priorPosterior } from "../src/routing/uncertainty_router.js";

// H4: the end-to-end second-brain composition proof. The eight moat rounds + three wired adapters COMPOSE — each
// stage's guarantee holds in composition. Verify by disproof: a break at any wired seam reddens this contract.

function newStore(): MemoryStore {
  const dir = mkdtempSync(join(tmpdir(), "keep-e2e-"));
  return new MemoryStore(new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry()), new ModelGateway(new LocalProvider()));
}
function fixture() {
  const keystore = new CryptoShredKeyStore();
  const reg = new ProjectRegistry(keystore);
  const proj = reg.create("alice-brain");
  const vault = new SensitiveContextVault(reg.namespace(proj.id));
  const registry = new ParserRegistry();
  // a voice codec (SEAM) that transcribes to a special-category disclosure
  registry.register("voice", () => ({ text: "I was diagnosed with cancer" }));
  const store = newStore();
  return { keystore, projId: proj.id as string, vault, registry, store, deps: { store, vault, registry } as SecondBrainDeps };
}
const SENSITIVE = { kind: "voice", content: "<audio bytes padding padding padding>", subject: "alice" };

test("model-first: local provider ⇒ ready with zero cloud dependency", () => {
  const r = modelFirst({ provider: "local" });
  assert.ok(r.ready && r.cloudRequired === false, "the n=1-local pipeline needs no cloud");
});

test("intake→vault→store: a sensitive item is captured in the vault AND landed in the real store", async () => {
  const f = fixture();
  const outcome = await ingestToSecondBrain(SENSITIVE, f.deps);
  assert.equal(outcome.status, "ingested");
  assert.equal(f.vault.revealToSubject("alice").length, 1, "the disclosure is captured in the CI vault");
  assert.equal(f.store.all().filter((l) => l.tier !== "retired").length, 1, "and the memory landed in the REAL store");
});

test("anticipation reads THROUGH the vault: denied flow ⇒ stay-silent; permitted flow ⇒ proceeds", async () => {
  const f = fixture();
  await ingestToSecondBrain(SENSITIVE, f.deps);
  const entry = f.vault.revealToSubject("alice")[0]!.entry;
  const cand = (): CandidateNeed => ({ description: "n", utility: 10, interruptionCost: 1, consequence: "reversible", vettable: true, confidence: priorPosterior() });
  const denied = anticipate(cand(), { sensitive: { vault: f.vault, entry, request: { recipient: "alice", purpose: "marketing" } } });
  assert.equal(denied.disposition, "stay-silent", "a disallowed cross-context flow ⇒ anticipation stays silent");
  const permitted = anticipate(cand(), { sensitive: { vault: f.vault, entry, request: { recipient: "alice", purpose: "assist-subject" } } });
  assert.notEqual(permitted.disposition, "stay-silent", "a permitted flow lets anticipation proceed");
});

test("export is CI-scoped end-to-end: another subject's memory does not leave in the bundle", async () => {
  const f = fixture();
  const alice = (await f.store.ingest("alice note", { origin: "self", scope: "user" }))!;
  await f.store.ingest("bob note", { origin: "self", scope: "user" });
  const bundle = exportAll("alice", assembleDerived("alice", { memoryStore: f.store, subjectOf: (l) => (l.id === alice.id ? "alice" : "bob") }));
  assert.deepEqual(bundle.state.memories.map((m) => m.content), ["alice note"], "only alice's memory is exported end-to-end");
});

test("round-trip lands at probation in a second store", async () => {
  const f = fixture();
  await ingestToSecondBrain(SENSITIVE, f.deps); // the sensitive text is also a memory
  const bundle = exportAll("alice", assembleDerived("alice", { memoryStore: f.store }));
  const res = importAll(bundle);
  assert.ok(res.ok);
  const store2 = newStore();
  if (res.ok) await applyRestored(res.restored, { memoryStore: store2 });
  const applied = store2.all().find((l) => l.content.includes("cancer"));
  assert.ok(applied, "the memory round-tripped into the second store");
  assert.equal(applied!.tier, "probation", "and landed at probation (no authority laundering)");
});

test("erasure is unreadable end-to-end: after erase, the vaulted context cannot be read", async () => {
  const f = fixture();
  await ingestToSecondBrain(SENSITIVE, f.deps);
  assert.equal(f.vault.revealToSubject("alice").length, 1, "readable before erasure");
  const receipt = erase(f.keystore, f.projId); // crypto-shred the vault's project key
  assert.equal(receipt.keyDestroyed, true);
  assert.throws(() => f.vault.revealToSubject("alice"), /erased|shred/, "the vaulted context is UNREADABLE after erasure");
});
