import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { bomDigest, recordBom, verifyBom, type AiBom } from "../src/bom/ai_bom.js";
import { composeGate, defaultGatePolicy, type GateInputs } from "../src/gate/composed_gate.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";

// Core Addition B — the signed AI-BOM. These prove the manifest is verifiable (recompute + compare),
// tamper-evident (a changed field fails), fail-safe (missing → unverifiable), and recorded to the
// spine. Verify by disproof.

function newSpine() {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "bom-spine-"))), new InProcessLock(), new SchemaRegistry());
}

const bom: AiBom = {
  subject: "run:42",
  modelId: "keep-solver",
  modelVersion: "1.0.0",
  promptHash: "p".repeat(64),
  policyHash: "q".repeat(64),
  toolSet: ["file.edit"],
  barriers: { floor: "reversible-execute", budget: "within-budget", actionTier: "reversible-internal", ownerPresent: true, provenance: "trusted", twin: "match" },
  codeHash: "c".repeat(64),
  configHash: "f".repeat(64),
  timestamp: 1000,
};

test("BOM: a complete BOM verifies against its recorded digest", () => {
  const digest = bomDigest(bom);
  assert.equal(verifyBom(bom, digest).verified, true);
});

test("BOM: a TAMPERED field (model id changed after recording) fails verification", () => {
  const digest = bomDigest(bom); // digest recorded for the original
  const tampered: AiBom = { ...bom, modelId: "evil-model" };
  const v = verifyBom(tampered, digest);
  assert.equal(v.verified, false);
  if (!v.verified) assert.ok(v.reason.startsWith("digest-mismatch"));
});

test("BOM: a tampered POLICY hash fails verification", () => {
  const digest = bomDigest(bom);
  const tampered: AiBom = { ...bom, policyHash: "0".repeat(64) };
  assert.equal(verifyBom(tampered, digest).verified, false);
});

test("BOM: a MISSING bom fails safe → unverifiable", () => {
  const v = verifyBom(undefined, bomDigest(bom));
  assert.equal(v.verified, false);
  if (!v.verified) assert.equal(v.reason, "no-bom");
});

test("BOM: a MISSING recorded digest fails safe → unverifiable", () => {
  const v = verifyBom(bom, undefined);
  assert.equal(v.verified, false);
  if (!v.verified) assert.equal(v.reason, "no-recorded-digest");
});

test("BOM: recording stages the digest to the spine AND the chain still verifies", async () => {
  const spine = newSpine();
  const before = spine.replay().length;
  const { digest } = recordBom(spine, bom);
  await spine.seal();
  assert.ok(spine.replay().length > before, "the BOM digest was recorded to the spine");
  assert.equal(spine.verify().ok, true, "the hash-chain still verifies after recording the BOM");
  // the recorded digest matches a fresh recompute (tamper-evidence anchor is consistent)
  assert.equal(digest, bomDigest(bom));
});

test("BOM: the recorded digest is observable in the chain payload", async () => {
  const spine = newSpine();
  const { digest } = recordBom(spine, bom);
  await spine.seal();
  const found = spine.replay().some((e) => (e.payload as Record<string, unknown>)?.digest === digest);
  assert.ok(found, "the BOM digest is in the sealed chain");
});

test("BOM: is deterministic — same manifest, same digest", () => {
  assert.equal(bomDigest(bom), bomDigest({ ...bom }));
});

// ── the gate veto ──
const green: GateInputs = { floor: "reversible-execute", budget: "within-budget", actionTier: "reversible-internal", ownerPresent: true };

test("BOM+GATE: an unverifiable BOM vetoes an otherwise-green op → human-hold", () => {
  const r = composeGate({ ...green, bomVerified: false }, defaultGatePolicy());
  assert.equal(r.route, "human-hold");
  assert.ok(r.reasons.includes("unverifiable-ai-bom"));
});

test("BOM+GATE: a verified BOM does not veto", () => {
  assert.equal(composeGate({ ...green, bomVerified: true }, defaultGatePolicy()).route, "auto-proceed");
});
