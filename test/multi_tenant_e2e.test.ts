import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { assembleSecondBrain, type SecondBrainSystem } from "../src/personalization/second_brain_system.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import type { ResidencyPolicy } from "../src/governance/residency.js";
import type { Resource } from "../src/authz/authorization.js";

// T5: the multi-tenant composition capstone. Two second-brain subsystems, provably NON-INTERFERING across every
// wired seam, AND a solo single-tenant instance still passes — the two tracks coexist. Verify by disproof.

const EU: ResidencyPolicy = { allowedRegions: ["eu"], egressAllowlist: [] };

function tenant(name: string): SecondBrainSystem {
  const dir = mkdtempSync(join(tmpdir(), `keep-mt-${name}-`));
  const spine = new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
  return assembleSecondBrain({ spine, gateway: new ModelGateway(new LocalProvider()), projectName: name });
}

test("memory/vault non-interference: tenant A's data never appears in tenant B's evidence", async () => {
  const A = tenant("acme");
  const B = tenant("beta");
  await A.ingest({ kind: "note", content: "ACME trade secret", subject: "alice" });
  A.vault.capture("alice", "I was diagnosed with cancer");
  await B.ingest({ kind: "note", content: "BETA roadmap", subject: "bob" });

  const bEvidence = B.evidenceFor("bob", EU); // B's own evidence
  assert.ok(!bEvidence.records.some((r) => r.summary.includes("ACME")), "A's data is not in B's evidence");
  assert.ok(!B.memory.all().some((l) => l.content.includes("ACME")), "A's memory is not in B's store");
  assert.equal(B.memory.all().filter((l) => l.tier !== "retired").length, 1, "B holds only its own memory (no cross-tenant leak)");
  assert.equal(B.vault.revealToSubject("alice").length, 0, "A's vaulted disclosure is not in B's vault");
});

test("authorization envelope required: an incomplete envelope defaults to deny", () => {
  const A = tenant("acme");
  const bad = { surface: "bogus", scope: "project", id: "x" } as unknown as Resource; // missing/unknown tenant surface
  assert.equal(A.authorize({ principal: { id: "owner", kind: "human", role: "owner" } }, "read", bad).allow, false, "missing/unknown envelope element ⇒ default-deny (owner would otherwise be allowed)");
});

test("per-tenant erasure: erasing tenant A leaves tenant B intact", () => {
  const A = tenant("acme");
  const B = tenant("beta");
  A.vault.capture("alice", "I was diagnosed with cancer");
  B.vault.capture("bob", "I was diagnosed with diabetes");
  const ev = A.eraseWithEvidence("alice");
  assert.equal(ev.receipt.keyDestroyed, true, "A's key is crypto-shredded");
  assert.equal(ev.unreadable, true, "A's vaulted context is unreadable");
  assert.equal(B.vault.revealToSubject("bob").length, 1, "B's vaulted context is UNAFFECTED (per-tenant erasure)");
});

test("export scoping: tenant A's export bundle contains only A's data", async () => {
  const A = tenant("acme");
  const B = tenant("beta");
  await A.ingest({ kind: "note", content: "ACME only", subject: "alice" });
  await B.ingest({ kind: "note", content: "BETA only", subject: "bob" });
  const bundle = A.exportBundle("alice");
  const contents = bundle.state.memories.map((m) => m.content);
  assert.ok(contents.some((c) => c.includes("ACME")), "A's bundle has A's data");
  assert.ok(!contents.some((c) => c.includes("BETA")), "A's bundle has NO B data");
});

test("N=1 FLOOR / coexistence: a solo single-tenant instance passes every guarantee unchanged", async () => {
  const solo = tenant("solo");
  await solo.ingest({ kind: "note", content: "my note", subject: "owner" });
  solo.vault.capture("owner", "I was diagnosed with cancer");
  assert.equal(solo.authorize({ principal: { id: "owner", kind: "human", role: "owner" } }, "write", { surface: "memory", scope: "global" }).allow, true, "solo owner authorized");
  assert.ok(solo.evidenceFor("owner", EU).records.length >= 2, "solo self-serve receipt (memory + vault)");
  const ev = solo.eraseWithEvidence("owner");
  assert.equal(ev.unreadable, true, "solo erasure works");
});

test("deterministic: two tenants built the same way are independent", async () => {
  const A = tenant("t1");
  const B = tenant("t2");
  await A.ingest({ kind: "note", content: "x", subject: "a" });
  assert.equal(B.memory.all().length, 0, "B is empty regardless of A");
});
