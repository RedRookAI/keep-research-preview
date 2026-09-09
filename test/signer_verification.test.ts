import { test } from "node:test";
import assert from "node:assert/strict";

import {
  reconcileWithWitness,
  restoredContentDigest,
  SeenNonceGuard,
  type RestorationRef,
  type RestorationVerifier,
} from "../src/spine/witness_reconcile.js";
import { signRestoration } from "../src/tcb/attestation.js";
import { sealBlock, makeWitness, type SealedBlock, type ChainWitness } from "../src/spine/hashchain.js";
import type { StagedEvent } from "../src/spine/event.js";

// BUILD-ORDER 8.44A / 8.44A-FIX — SIGNER VERIFICATION. The restore-authorization signature is CHECKED, not
// counted: it must VERIFY against the enrolled key over the canonical restore bytes (node:crypto HMAC,
// constant-time). The FIX round (cross-family veto, GPT-5.6) closes three load-bearing holes the first
// 8.44A left open:
//   - the signature bound only {seq, priorWitnessedHash, nonce}, NOT the restored CONTENT — so one valid
//     authorization transferred to any fork sharing that seq + witness hash. Now the SIGNED bytes include
//     contentDigest(blocks) and reconcile verifies it against the SUPPLIED blocks + head seq.
//   - `Buffer.from(sig,"hex")` silently dropped trailing garbage, so "<valid-hex>ZZ" slipped past. Now the
//     signature must be STRICT full-length hex before decode.
// Proven by disproof — deterministic fixtures (fixed keys + fixed bytes), no network. The neuters live in
// src/spine/witness_reconcile.ts and src/tcb/attestation.ts:
//   (a) skip the signature check          -> Test A (bogus signature refused)              RED
//   (b) skip the replay `seen` check       -> Test B (replayed signature refused)           RED
//   (c) accept-path -> `continue`          -> Test C (valid signed restore accepted)        RED
//   (d) skip the contentDigest match       -> Test D (authorization does not cross forks)   RED
//   (e) drop the strict-hex validation      -> Test E (malformed/garbage signature refused)  RED
//   (f) skip the restoredToSeq==head check  -> Test F (restore must match the authorized seq) RED
//   (g) drop the internal-validity guard     -> Test G (pasted-hash invalid blocks refused)     RED
//   (h) re-read a field (drop read-once)      -> Test H (getter/Proxy TOCTOU attestation refused) RED
//   (i) return original blocks not the snap  -> Test I (verdict returns the VERIFIED artifact)    RED
// Each reddens ONLY its target.

function ev(id: string): StagedEvent {
  return { id, schemaVersion: 1, type: "generic", ts: 1000, actor: "t", payload: {} };
}

/** A witnessed head at seq 1, plus a divergent one-block fork off the genesis (an unattested fork). */
function forkFixture(): { forked: SealedBlock[]; witness: ChainWitness } {
  const g = sealBlock(undefined, [ev("a")], 1000);
  const b1 = sealBlock(g, [ev("b")], 1001);
  const witness = makeWitness([g, b1])!; // pins seq 1 / head hash of b1
  const f1 = sealBlock(g, [ev("b-FORK")], 1001); // same seq, different content → fork
  return { forked: [g, f1], witness };
}

const ENROLLED = Buffer.alloc(32, 7); // the enrolled run/operator verify key (deterministic fixture)

/** Sign a well-formed authorization that BINDS the given restored blocks (seq + content digest + nonce). */
function authorize(blocks: readonly SealedBlock[], witness: ChainWitness, nonce: string, key = ENROLLED): RestorationRef {
  const head = blocks[blocks.length - 1]!;
  const fields = {
    restoredToSeq: head.seq,
    priorWitnessedHash: witness.headHash,
    contentDigest: restoredContentDigest(blocks),
    nonce,
  };
  return { ...fields, signature: signRestoration(key, fields) };
}

test("SIGNER (a): a nonempty-but-INVALID restoration signature is REFUSED, not authorized", () => {
  const { forked, witness } = forkFixture();
  // Signed with a DIFFERENT key than the one enrolled — a well-formed signature that does NOT verify.
  const wrongKey = Buffer.alloc(32, 9);
  const bogus = authorize(forked, witness, "nonce-A", wrongKey);
  const verifier: RestorationVerifier = { key: ENROLLED, replay: new SeenNonceGuard() };

  const v = reconcileWithWitness(forked, witness, [bogus], verifier);
  assert.equal(v.status, "tamper", "a signature that does not verify against the enrolled key authorizes nothing");
});

test("SIGNER (b): a REPLAYED valid restoration signature is REFUSED (nonce already consumed)", () => {
  const { forked, witness } = forkFixture();
  const valid = authorize(forked, witness, "nonce-B");
  const guard = new SeenNonceGuard();
  guard.remember("nonce-B"); // this nonce already authorized an earlier restore — a captured replay
  const verifier: RestorationVerifier = { key: ENROLLED, replay: guard };

  const v = reconcileWithWitness(forked, witness, [valid], verifier);
  assert.equal(v.status, "tamper", "a legitimately-signed authorization is single-use; the replay is refused");
});

test("SIGNER (c): a genuinely key-signed restore over THIS content with a fresh nonce is AUTHORIZED (control), then single-use on replay", () => {
  const { forked, witness } = forkFixture();
  const valid = authorize(forked, witness, "nonce-C");
  const guard = new SeenNonceGuard();
  const verifier: RestorationVerifier = { key: ENROLLED, replay: guard };

  const v = reconcileWithWitness(forked, witness, [valid], verifier);
  assert.equal(v.status, "authorized-restore", "a verifier is not just always-deny: a real signature binding this content + a fresh nonce is honored");
  assert.equal(guard.seen("nonce-C"), true, "the accepted nonce is consumed, so it cannot re-authorize");

  // CONTROL, second half: the SAME authorization is single-use — replaying it now reconciles as tamper.
  const again = reconcileWithWitness(forked, witness, [valid], verifier);
  assert.equal(again.status, "tamper", "the accepted authorization does not authorize a second restore");
});

test("SIGNER (d): an authorization minted for restore A does NOT transfer to a DIFFERENT fork B (content binding)", () => {
  // Two forks off the same genesis: both at seq 1, both superseding the SAME witnessed head hash, but with
  // DIFFERENT content. Without content binding one authorization would bless either; with it, it does not.
  const g = sealBlock(undefined, [ev("a")], 1000);
  const b1 = sealBlock(g, [ev("b")], 1001);
  const witness = makeWitness([g, b1])!;
  const forkA = [g, sealBlock(g, [ev("restore-A")], 1001)];
  const forkB = [g, sealBlock(g, [ev("attacker-B")], 1001)];
  // sanity: the two forks share seq 1 + the same superseded witness hash, differ only in content digest.
  assert.notEqual(restoredContentDigest(forkA), restoredContentDigest(forkB), "the two forks differ only in content");

  // A genuine, correctly-key-signed authorization for restore A.
  const authForA = authorize(forkA, witness, "nonce-D");
  const verifier: RestorationVerifier = { key: ENROLLED, replay: new SeenNonceGuard() };

  // Present the attacker's fork B together with A's real authorization.
  const v = reconcileWithWitness(forkB, witness, [authForA], verifier);
  assert.equal(v.status, "tamper", "an authorization signed for fork A's content does not authorize fork B");

  // And A's authorization DOES authorize A (the binding is exact, not a blanket deny).
  const okA = reconcileWithWitness(forkA, witness, [authForA], { key: ENROLLED, replay: new SeenNonceGuard() });
  assert.equal(okA.status, "authorized-restore", "the same authorization authorizes exactly the content it signed");
});

test("SIGNER (e): a valid-hex-PREFIX + trailing-garbage signature is REFUSED (strict hex)", () => {
  const { forked, witness } = forkFixture();
  const valid = authorize(forked, witness, "nonce-E");
  // Buffer.from("<valid 64 hex>ZZ","hex") silently decodes to the same 32 bytes as the clean signature and
  // would slip past a decoded-length-only check as if it were the clean one. Strict hex must reject it.
  const mutated: RestorationRef = { ...valid, signature: valid.signature + "ZZ" };
  const verifier: RestorationVerifier = { key: ENROLLED, replay: new SeenNonceGuard() };

  const v = reconcileWithWitness(forked, witness, [mutated], verifier);
  assert.equal(v.status, "tamper", "a signature that is not strict, full-length hex authorizes nothing");
});

test("SIGNER (f): an authorization whose restoredToSeq does not match the supplied head seq is REFUSED", () => {
  const { forked, witness } = forkFixture();
  // A signer that lies about the seq: correct content digest for the supplied blocks, but restoredToSeq is a
  // DIFFERENT number than the actual head seq (1). The signature is valid over these (inconsistent) fields,
  // so only the seq/content-correspondence check stands between this and acceptance.
  const fields = {
    restoredToSeq: 7, // supplied head is seq 1 — this does not correspond to the blocks
    priorWitnessedHash: witness.headHash,
    contentDigest: restoredContentDigest(forked),
    nonce: "nonce-F",
  };
  const mismatched: RestorationRef = { ...fields, signature: signRestoration(ENROLLED, fields) };
  const verifier: RestorationVerifier = { key: ENROLLED, replay: new SeenNonceGuard() };

  const v = reconcileWithWitness(forked, witness, [mismatched], verifier);
  assert.equal(v.status, "tamper", "restoredToSeq must correspond to the supplied blocks' head seq");
});

test("SIGNER (g): INTERNALLY-INVALID blocks that PASTE a real fork's hashes are REFUSED even when the digest matches a valid authorization (internal-validity precondition — BUILD-ORDER 8.44A-FIX2)", () => {
  // The cross-family veto (Fable) defect: restoredContentDigest folds each block's CLAIMED `hash` field, and the
  // restore branch never re-checked internal chain validity. So an attacker pastes a real fork A's head HASH onto a
  // block whose CONTENT is attacker-chosen: the {seq,hash} digest reproduces A's contentDigest (matching A's genuine
  // authorization) while the actual events are malicious. The block is internally INVALID (its hash does not
  // recompute from its content). It must be refused — an authorization binds CONTENT, not claimed metadata.
  const g = sealBlock(undefined, [ev("a")], 1000);
  const b1 = sealBlock(g, [ev("b")], 1001);
  const witness = makeWitness([g, b1])!;
  const forkA = [g, sealBlock(g, [ev("restore-A")], 1001)];
  const authForA = authorize(forkA, witness, "nonce-G"); // a genuine, correctly-key-signed authorization for A

  // Attacker's forged head: A's head hash pasted onto attacker-chosen events → same {seq,hash} digest, invalid block.
  const forgedHead: SealedBlock = { ...sealBlock(g, [ev("attacker-EVIL")], 1001), hash: forkA[1]!.hash };
  const forged = [g, forgedHead];
  assert.equal(restoredContentDigest(forged), restoredContentDigest(forkA), "the forged blocks reproduce A's content digest via the pasted hash (the attack precondition)");

  const verifier: RestorationVerifier = { key: ENROLLED, replay: new SeenNonceGuard() };
  const v = reconcileWithWitness(forged, witness, [authForA], verifier);
  assert.equal(v.status, "tamper", "internally-invalid blocks are never an authorized restore, even when the pasted-hash digest matches a real authorization");
});

test("SIGNER (h): a GETTER/Proxy attestation that returns fork-B's digest to the check and fork-A's to the signature is REFUSED (read-once, no TOCTOU — BUILD-ORDER 8.44A-FIX3)", () => {
  // Cross-family finding (GPT-5.6): RestorationRef is only compile-time readonly. An attacker supplies an
  // accessor-backed object whose `contentDigest` returns digestB (matching supplied fork B, passing the
  // correspondence check) on one read and digestA (matching A's real signature) on the next — a check-use
  // differential that would authorize fork B under A's authorization. The fix reads each field EXACTLY ONCE.
  const g = sealBlock(undefined, [ev("a")], 1000);
  const b1 = sealBlock(g, [ev("b")], 1001);
  const witness = makeWitness([g, b1])!;
  const forkA = [g, sealBlock(g, [ev("restore-A")], 1001)];
  const forkB = [g, sealBlock(g, [ev("attacker-B")], 1001)]; // valid, internally-consistent attacker fork
  const digestA = restoredContentDigest(forkA);
  const digestB = restoredContentDigest(forkB);
  assert.notEqual(digestA, digestB, "the two forks differ in content");
  const authForA = authorize(forkA, witness, "nonce-H"); // genuine authorization signed over digestA

  // Adversarial attestation: contentDigest flip-flops B (first read) → A (subsequent). All other fields = A's.
  let reads = 0;
  const evil: RestorationRef = {
    restoredToSeq: authForA.restoredToSeq,
    priorWitnessedHash: authForA.priorWitnessedHash,
    nonce: authForA.nonce,
    signature: authForA.signature,
    get contentDigest() { reads += 1; return reads === 1 ? digestB : digestA; },
  } as unknown as RestorationRef;

  const verifier: RestorationVerifier = { key: ENROLLED, replay: new SeenNonceGuard() };
  // Present the attacker's fork B (valid chain) with the flip-flopping authorization.
  const v = reconcileWithWitness(forkB, witness, [evil], verifier);
  assert.equal(v.status, "tamper", "a field read once cannot return one value to the check and another to the signature — fork B is refused");
});

test("SIGNER (i): an authorized restore RETURNS the verified snapshot blocks (distinct owned data) so the caller restores what was verified — BUILD-ORDER 8.44A-FIX4", () => {
  // Cross-family finding (GPT-5.6): reconcile verified a snapshot but returned only a verdict, so a caller would
  // restore from the ORIGINAL (possibly proxy/toJSON) input — the verified artifact and the restored artifact
  // could differ. The accepted verdict now carries the VERIFIED snapshot blocks; the caller restores THOSE.
  const { forked, witness } = forkFixture();
  const valid = authorize(forked, witness, "nonce-I");
  const verifier: RestorationVerifier = { key: ENROLLED, replay: new SeenNonceGuard() };

  const v = reconcileWithWitness(forked, witness, [valid], verifier);
  assert.equal(v.status, "authorized-restore", "control: a real authorization is honored");
  assert.ok(v.status === "authorized-restore" && Array.isArray(v.blocks), "the verdict carries the verified blocks");
  if (v.status === "authorized-restore") {
    assert.notEqual(v.blocks, forked, "the returned blocks are a DISTINCT owned snapshot, not the caller's original reference");
    assert.deepEqual(v.blocks, forked, "the returned snapshot's content is exactly what was verified");
    // FIX6: the verified artifact is deep-frozen, so it cannot be mutated between verification and restore.
    assert.ok(Object.isFrozen(v.blocks) && Object.isFrozen(v.blocks[0]) && Object.isFrozen(v.blocks[0]!.events),
      "the returned blocks are deep-frozen (immutable end-to-end)");
  }
});

test("SIGNER (j): a restore input carrying a NON-PLAIN value (exotic that survives structuredClone but not freeze) is REFUSED — BUILD-ORDER 8.44A-FIX7", () => {
  // GPT-5.6: structuredClone preserves SharedArrayBuffer/Date/Map/Set, whose internal state Object.freeze cannot
  // lock — a concurrent holder could mutate the "verified" snapshot after the fact. Normalization rejects any
  // non-plain-data value fail-closed. Here an event payload carries a Map; the restore is refused before any
  // authorization can be considered. (Behavioral/defense test — the neuter-isolated load-bearing props are a–i.)
  const { forked, witness } = forkFixture();
  const tainted = forked.map((b, i) =>
    i === forked.length - 1 ? { ...b, events: b.events.map((e) => ({ ...e, payload: { m: new Map() } })) } : b,
  ) as unknown as SealedBlock[];
  const verifier: RestorationVerifier = { key: ENROLLED, replay: new SeenNonceGuard() };

  const v = reconcileWithWitness(tainted, witness, [], verifier);
  assert.equal(v.status, "tamper", "a non-plain-data (exotic) restore input is refused fail-closed, never normalized-away silently");
});
