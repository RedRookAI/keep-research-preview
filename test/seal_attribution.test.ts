import { test } from "node:test";
import assert from "node:assert/strict";

import {
  verificationProvenance, sealProvenance, verifyProvenanceSeal, attesterFrom,
  type VerificationProvenance, type SealedProvenance, type AttestingIdentity,
} from "../src/audit/decision_audit.js";

const rec = (id: string): VerificationProvenance =>
  verificationProvenance({ subjectId: id, deterministicPass: true });
const live: AttestingIdentity = { agentId: "keep-agent-7", version: "1.2.0", liveness: "live" };
// a stand-in identity registry (reuses the real isKilled shape)
const registry = (killed: string[]) => ({ isKilled: (id: string) => killed.includes(id) });

test("SEAL-ATTRIBUTION (a): a sealed record carries its attesting identity, covered by the hash", () => {
  const s = sealProvenance(rec("fix-1"), undefined, live);
  assert.deepEqual(s.attester, live, "the seal names its attester");
  assert.equal(verifyProvenanceSeal(s).valid, true);
  // the attester is COVERED by the hash: a seal WITHOUT the attester has a different hash for the same record
  const noAttest = sealProvenance(rec("fix-1"));
  assert.notEqual(s.hash, noAttest.hash, "binding the attester changes the hash — it is covered");
});

test("SEAL-ATTRIBUTION (b): swapping the claimed attester after sealing is detected as tampered", () => {
  const s = sealProvenance(rec("fix-2"), undefined, live);
  const swapped: SealedProvenance = { ...s, attester: { agentId: "impostor", liveness: "live" } };
  const v = verifyProvenanceSeal(swapped);
  assert.equal(v.valid, false, "a swapped attester breaks the hash");
  if (!v.valid) assert.match(v.reason, /TAMPERED|mismatch/);
  assert.equal(verifyProvenanceSeal(s).valid, true, "the original seal still verifies");
});

test("SEAL-ATTRIBUTION (c): a killed/unknown identity is recorded honestly, never elevated", () => {
  const killed = attesterFrom("agent-x", registry(["agent-x"]));
  assert.equal(killed.liveness, "killed", "a killed agent is recorded killed, not live");
  const unknown = attesterFrom("agent-y", undefined);
  assert.equal(unknown.liveness, "unknown", "no registry → unknown, never assumed live");
  const liveOne = attesterFrom("agent-z", registry([]));
  assert.equal(liveOne.liveness, "live");
  // sealing a killed attester records it faithfully (does not rewrite to live)
  const s = sealProvenance(rec("fix-c"), undefined, killed);
  assert.equal(s.attester!.liveness, "killed");
  assert.equal(verifyProvenanceSeal(s).valid, true, "the seal faithfully records a killed attester");
});

test("SEAL-ATTRIBUTION (d): attribution is honest — self-asserted, NOT non-repudiation", () => {
  const s = sealProvenance(rec("fix-d"), undefined, live);
  assert.equal(s.attribution, "self-asserted", "labeled attribution, not non-repudiation");
  assert.equal(s.signed, false, "no signature — not non-repudiation");
  // @ts-expect-error — the seal never asserts non-repudiation
  assert.equal(s.nonRepudiation, undefined);
});

test("SEAL-ATTRIBUTION (e): verification stays total — a malformed attester reports invalid even when its hash matches", () => {
  // seal CONSTRUCTED with a malformed attester (agentId missing): the hash is computed over it, so it MATCHES on
  // re-verify — only the explicit attester validation can catch it. It must not be silently valid.
  const malformed = { liveness: "live" } as unknown as AttestingIdentity;
  const s = sealProvenance(rec("fix-e"), undefined, malformed);
  const v = verifyProvenanceSeal(s);
  assert.equal(v.valid, false, "a malformed attester is rejected even when its hash matches (total verification)");
  if (!v.valid) assert.match(v.reason, /malformed attester/);
  // an invalid liveness value (bogus status) is likewise rejected
  const badLiveness = sealProvenance(rec("fix-e1"), undefined, { agentId: "a", liveness: "trusted" } as unknown as AttestingIdentity);
  assert.equal(verifyProvenanceSeal(badLiveness).valid, false, "a bogus liveness status is rejected — no elevation");
  // an unattributed seal is still valid (n=1 self-attested / attribution optional) — honest, not invalid
  assert.equal(verifyProvenanceSeal(sealProvenance(rec("fix-e2"))).valid, true);
});
