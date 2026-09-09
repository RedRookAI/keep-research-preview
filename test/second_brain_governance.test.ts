import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { secondBrainEvidence, secondBrainErase, type EvidenceDeps } from "../src/governance/second_brain_governance.js";
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
import type { ResidencyPolicy } from "../src/governance/residency.js";

// T4: second-brain governance — DSAR/ROPA completeness over every store, residency enforced, evidenced crypto-shred
// erasure. BOTH tracks: N=1 self-serve receipt + org compliance pack. Verify by disproof.

const EU: ResidencyPolicy = { allowedRegions: ["eu"], egressAllowlist: [] };

async function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "keep-t4-"));
  const memory = new MemoryStore(new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry()), new ModelGateway(new LocalProvider()));
  const keystore = new CryptoShredKeyStore();
  const reg = new ProjectRegistry(keystore);
  const project = reg.create("brain");
  const vault = new SensitiveContextVault(reg.namespace(project.id));
  // one ordinary memory + one vaulted disclosure, both for "alice"
  await memory.ingest("prefers dark mode", { origin: "self", scope: "user" });
  vault.capture("alice", "I was diagnosed with cancer");
  return { memory, vault, keystore, projectId: project.id as string };
}

test("completeness: the evidence pack enumerates a subject's memory AND vault holdings", async () => {
  const f = await fixture();
  const deps: EvidenceDeps = { memory: f.memory, vault: f.vault, residency: EU };
  const pack = secondBrainEvidence("alice", deps);
  const stores = new Set(pack.records.map((r) => r.store));
  assert.ok(stores.has("memory"), "memory holdings are in the DSAR record");
  assert.ok(stores.has("vault"), "vault holdings are in the DSAR record");
});

test("residency: a datum in a disallowed region is flagged", async () => {
  const f = await fixture();
  // force the vault datum into a non-EU region
  const deps: EvidenceDeps = { memory: f.memory, vault: f.vault, residency: EU, regionOf: (store) => (store === "vault" ? "us" : "eu") };
  const pack = secondBrainEvidence("alice", deps);
  assert.equal(pack.residencyOk, false, "a US datum violates an EU-only residency policy");
  assert.ok(pack.residencyViolations.length >= 1, "the offending record is flagged");
});

test("evidenced erasure: crypto-shred returns a receipt and the vaulted context is unreadable after", async () => {
  const f = await fixture();
  assert.equal(f.vault.revealToSubject("alice").length, 1, "readable before erasure");
  const ev = secondBrainErase("alice", { keystore: f.keystore, vault: f.vault, projectKeySubject: f.projectId });
  assert.equal(ev.receipt.keyDestroyed, true, "a verifiable crypto-shred receipt");
  assert.equal(ev.unreadable, true, "the vaulted context is unreadable after erasure");
});

test("N=1 FLOOR: the sole owner's self-serve receipt returns their holdings with zero org setup", async () => {
  const f = await fixture();
  // no residency policy tightening, no org directory — just the owner asking what Keep holds
  const pack = secondBrainEvidence("alice", { memory: f.memory, vault: f.vault, residency: { allowedRegions: ["eu"], egressAllowlist: [] } });
  assert.ok(pack.records.length >= 2, "the solo owner gets a real data receipt (memory + vault) with no org machinery");
});

test("deterministic: same subject + stores ⇒ same record set", async () => {
  const f = await fixture();
  const deps: EvidenceDeps = { memory: f.memory, vault: f.vault, residency: EU };
  assert.deepEqual(secondBrainEvidence("alice", deps).records, secondBrainEvidence("alice", deps).records);
});
