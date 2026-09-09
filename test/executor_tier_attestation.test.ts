import { test } from "node:test";
import assert from "node:assert/strict";

import {
  createRunAttestationChannel,
  recomputeTierFromEvidence,
  processFloorEvidence,
  seamEvidenceForTier,
  verifierWithKey,
  attestorWithKey,
  type IsolationEvidence,
  type IsolationAttestation,
  type TeeVerifier,
} from "../src/isolation/isolation_attestation.js";
import { randomBytes } from "node:crypto";

/**
 * BUILD-ORDER 1.7 (BIND-EXECUTOR-TIER-ATTESTATION) — the tier that buys the autonomy ceiling is now
 * PROVEN, not asserted. The executor EMITS a signed attestation of the tier it ran + the MEASURED
 * evidence; the router VERIFIES it (signature valid AND the evidence recomputes to at least the claim)
 * before the tier grants a ceiling. A signature over a lie is still a lie — the DISCONFIRMING core is the
 * evidence recompute, not the stamp.
 *
 * Proven by disproof. Each test names the SOURCE line whose neuter reddens it (isolation_attestation.ts),
 * and each neuter isolates. RED captures in redrook-ops/.round-artifacts/BIND-EXECUTOR-TIER-ATTESTATION/.
 */

const PROJECT = "/tmp/attest-project";
const TS = 1_700_000_000_000;

// ── recompute: the disconfirming core, independent of the claimed tier ────────────────────────────
test("1.7: recomputeTierFromEvidence derives the tier the EVIDENCE proves, never a label", () => {
  // microvm needs hardware/runtime/images AND a completed verifier-owned run receipt identity.
  assert.equal(recomputeTierFromEvidence({ platform: "linux", runtimeKind: "firecracker", kvmPresent: true, imagesPresent: true, jobObjectSupport: false, degraded: [], completedRunReceiptDigest: "a".repeat(64) }), "microvm");
  assert.equal(recomputeTierFromEvidence({ platform: "linux", runtimeKind: "firecracker", kvmPresent: true, imagesPresent: true, jobObjectSupport: false, degraded: [] }), "none", "preflight-only evidence is not a completed microVM run");
  assert.equal(recomputeTierFromEvidence({ platform: "linux", runtimeKind: "firecracker", kvmPresent: true, imagesPresent: false, jobObjectSupport: false, degraded: [] }), "none", "no images → not microvm");
  assert.equal(recomputeTierFromEvidence({ platform: "linux", runtimeKind: "firecracker", kvmPresent: false, imagesPresent: true, jobObjectSupport: false, degraded: [] }), "none", "no kvm → not microvm");
  assert.equal(recomputeTierFromEvidence(seamEvidenceForTier("gvisor")), "none", "declared gVisor seam is not completed-run evidence");
  assert.equal(recomputeTierFromEvidence(seamEvidenceForTier("container")), "none", "declared container seam is not completed-run evidence");
  assert.equal(recomputeTierFromEvidence({ platform: "win32", runtimeKind: "windows-job-object", kvmPresent: false, imagesPresent: false, jobObjectSupport: true, degraded: [] }), "process", "a Job Object backs the process floor");
  assert.equal(recomputeTierFromEvidence(processFloorEvidence("linux")), "process");
  assert.equal(recomputeTierFromEvidence({ platform: "linux", runtimeKind: "none", kvmPresent: false, imagesPresent: false, jobObjectSupport: false, degraded: [] }), "none");
});

// ── (a) forged tier: a validly-signed microvm claim over PROCESS evidence caps DOWN to process ────
test("1.7 (a): a forged-UP tier over honest evidence recomputes DOWN — never buys the higher ceiling", () => {
  // NEUTER TARGET: the recompute cap `weakerTier(att.claim.tier, proven)` in HmacVerifier.verify. Neuter
  // it to return `att.claim.tier` (trust the stamp) → the forged microvm is honoured → RED.
  const { attestor, verifier } = createRunAttestationChannel();
  // A real process-floor run that stamps `microvm` (the mislabel/supply-chain shape), signed with the RUN KEY.
  const forged = attestor.attest({ tier: "microvm", evidence: processFloorEvidence("linux"), projectDir: PROJECT, ts: TS, mechanism: "hmac-run-key" });
  const v = verifier.verify(forged);
  assert.equal(v.verifiedTier, "none", "a microVM claim without a live one-time receipt fails fully closed");
  assert.equal(v.ok, false, "and the claim is flagged evidence-insufficient");
  assert.match(v.reason, /microvm-run-receipt/);
});

// ── (b) honest microvm: verifies + is NOT falsely demoted ─────────────────────────────────────────
test("1.7 (b): static KVM/VMM/image evidence cannot stand in for a completed microVM receipt", () => {
  const { attestor, verifier } = createRunAttestationChannel();
  const honest = attestor.attest({ tier: "microvm", evidence: seamEvidenceForTier("microvm", "linux"), projectDir: PROJECT, ts: TS, mechanism: "hmac-run-key" });
  const v = verifier.verify(honest);
  assert.equal(v.verifiedTier, "none", "only the real runner can register the one-time receipt");
  assert.equal(v.ok, false);
});

// ── (c) tampered signature → weakest tier ─────────────────────────────────────────────────────────
test("1.7 (c): a TAMPERED attestation fails the signature check → weakest tier, no autonomy", () => {
  // NEUTER TARGET: the `signatureValid` guard in HmacVerifier.verify. Neuter it to skip the check →
  // the tampered claim's tier is honoured → RED.
  const { attestor, verifier } = createRunAttestationChannel();
  const good = attestor.attest({ tier: "microvm", evidence: seamEvidenceForTier("microvm", "linux"), projectDir: PROJECT, ts: TS, mechanism: "hmac-run-key" });
  // Flip one hex nibble of the signature — the claim body is unchanged; only the MAC is corrupted.
  const flipped = good.signature.slice(0, -1) + (good.signature.at(-1) === "a" ? "b" : "a");
  const tampered: IsolationAttestation = { claim: good.claim, signature: flipped };
  const v = verifier.verify(tampered);
  assert.equal(v.verifiedTier, "none", "a bad signature buys nothing");
  assert.equal(v.reason, "bad-signature");
});

test("1.7 (c-command): guest execution-request identity is inside the signed attestation", () => {
  const { attestor, verifier } = createRunAttestationChannel();
  const evidence: IsolationEvidence = { ...processFloorEvidence("linux"), completedRunGuestExecutionRequestDigest: "a".repeat(64) };
  const good = attestor.attest({ tier: "process", evidence, projectDir: PROJECT, ts: TS, mechanism: "hmac-run-key" });
  const substituted: IsolationAttestation = {
    claim: { ...good.claim, evidence: { ...good.claim.evidence, completedRunGuestExecutionRequestDigest: "b".repeat(64) } },
    signature: good.signature,
  };
  assert.equal(verifier.verify(substituted).reason, "bad-signature", "command identity substitution must invalidate the run attestation");
});

test("1.7 (c'): a foreign-key signature (a swap that never held the run key) also fails → weakest tier", () => {
  // The confused-deputy closure: an attestation forged by a component that never went through THIS run's
  // attestor (a different key) fails the signature — even if its evidence would recompute high.
  const { verifier } = createRunAttestationChannel();
  const foreign = attestorWithKey(randomBytes(32)); // NOT the run channel's key
  const att = foreign.attest({ tier: "microvm", evidence: seamEvidenceForTier("microvm", "linux"), projectDir: PROJECT, ts: TS, mechanism: "hmac-run-key" });
  const v = verifier.verify(att);
  assert.equal(v.verifiedTier, "none", "signed with the wrong key → weakest tier");
  assert.equal(v.reason, "bad-signature");
});

// ── (d) absent attestation → fail-closed to weakest, never the declared tier ──────────────────────
test("1.7 (d): an ABSENT attestation is fail-closed to the weakest tier (never trusted as declared)", () => {
  // NEUTER TARGET: the `att === undefined` guard in HmacVerifier.verify. Neuter it to default-trust a
  // missing attestation as some declared tier → RED.
  const { verifier } = createRunAttestationChannel();
  const v = verifier.verify(undefined);
  assert.equal(v.verifiedTier, "none", "no attestation → no autonomy");
  assert.equal(v.reason, "absent-attestation");
});

// ── (e) SEAM-HONESTY: a tee-* claim with no live TeeVerifier verifies as the HMAC form ────────────
test("1.7 (e): a hardware-attestation (tee-*) claim with NO TEE verifier verifies as the HMAC tier — never a false TEE claim", () => {
  // NEUTER TARGET: the mechanism downgrade `this.teeVerifier?.verifyTee(att) ?? "hmac-run-key"`. Neuter it
  // to trust `att.claim.mechanism` → a `tee-sev-snp` label with no TEE verifier reports a false TEE status → RED.
  const { attestor, verifier } = createRunAttestationChannel(); // no teeVerifier wired (the in-env case)
  const teeClaim = attestor.attest({ tier: "gvisor", evidence: seamEvidenceForTier("gvisor", "linux"), projectDir: PROJECT, ts: TS, mechanism: "tee-sev-snp" });
  const v = verifier.verify(teeClaim);
  assert.equal(v.verifiedMechanism, "hmac-run-key", "no TEE verifier → the honest HMAC form, never a claimed TEE");
  assert.equal(v.verifiedTier, "none", "the mechanism label cannot turn a declared seam into completed-run evidence");
});

test("1.7 (e'): a live TeeVerifier (the VERIFIED-SEAM) confirms a real tee-* mechanism", () => {
  // The seam is real, not a stub-out: WITH a TeeVerifier that confirms the report, the mechanism is honoured.
  const confirming: TeeVerifier = { verifyTee: (att) => (att.claim.mechanism === "tee-sev-snp" ? "tee-sev-snp" : undefined) };
  const key = randomBytes(32);
  const attestor = attestorWithKey(key);
  const verifier = verifierWithKey(key, confirming);
  const teeClaim = attestor.attest({ tier: "gvisor", evidence: seamEvidenceForTier("gvisor", "linux"), projectDir: PROJECT, ts: TS, mechanism: "tee-sev-snp" });
  const v = verifier.verify(teeClaim);
  assert.equal(v.verifiedMechanism, "tee-sev-snp", "a confirmed hardware report earns the TEE mechanism");
  assert.equal(v.verifiedTier, "none", "TEE mechanism confirmation does not fabricate the missing isolation transaction");
});
