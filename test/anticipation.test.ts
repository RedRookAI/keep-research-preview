import { test } from "node:test";
import assert from "node:assert/strict";

import { anticipate, type CandidateNeed } from "../src/anticipate/anticipation.js";
import { priorPosterior, updatePosterior, type SuccessPosterior } from "../src/routing/uncertainty_router.js";
import { SensitiveContextVault } from "../src/privacy/contextual_integrity.js";
import { ProjectRegistry } from "../src/session/project_registry.js";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";

// Anticipation engine: Horvitz-calibrated, minimum-intervention, no rubber-stamp, prepare-silently-surface-on-pull.
// BUILT: vet/calibration/consequence-gate/pull-vs-push. SEAM: intent predictor + context-shift detector. Disprove.

function confident(): SuccessPosterior {
  let p = priorPosterior();
  for (let i = 0; i < 8; i++) p = updatePosterior(p, true);
  return p; // LCB ~0.72 ≥ CONF_THRESHOLD
}
const base = (over: Partial<CandidateNeed>): CandidateNeed => ({
  description: "x", utility: 10, interruptionCost: 1, consequence: "reversible", vettable: true, confidence: confident(), ...over,
});

test("utility−interruption gate: a low-utility/high-interruption candidate stays silent, not surface", () => {
  const d = anticipate(base({ utility: 1, interruptionCost: 5 }));
  assert.equal(d.disposition, "stay-silent", "interruption dominates ⇒ silent, not an interruption");
  // positive control: high utility, low interruption ⇒ surface
  assert.equal(anticipate(base({ utility: 10, interruptionCost: 1 })).disposition, "surface");
});

test("consequence gate: a consequential candidate is never surfaced/auto-done — at most offered on pull", () => {
  const d = anticipate(base({ consequence: "consequential", utility: 10, interruptionCost: 1 }));
  assert.notEqual(d.disposition, "surface", "a consequential action is never pushed");
  assert.equal(d.disposition, "offer-on-pull", "it is offered for the human to decide");
  assert.equal(d.autoExecuted, false, "the engine never executes");
});

test("vet gate: an un-vettable candidate is not surfaced regardless of utility", () => {
  const d = anticipate(base({ vettable: false, utility: 10, interruptionCost: 1 }));
  assert.equal(d.disposition, "stay-silent", "un-vettable ⇒ never surfaced");
});

test("pull over push: a mid-utility reversible candidate defaults to offer-on-pull, not surface", () => {
  const d = anticipate(base({ utility: 4, interruptionCost: 2 })); // net 2 < SURFACE_MARGIN 3
  assert.equal(d.disposition, "offer-on-pull", "prepared and offered on pull, not pushed");
});

test("reads through the vault: a sensitive-derived candidate whose flow is denied stays silent", () => {
  const reg = new ProjectRegistry(new CryptoShredKeyStore());
  const vault = new SensitiveContextVault(reg.namespace(reg.create("P").id));
  const entry = vault.capture("alice", "I have diabetes")!; // permitted: recipient alice, purpose assist-subject
  // a flow to a DIFFERENT purpose is denied by the vault:
  const d = anticipate(base({ utility: 10, interruptionCost: 1 }), {
    sensitive: { vault, entry, request: { recipient: "alice", purpose: "marketing" } },
  });
  assert.equal(d.disposition, "stay-silent", "sensitive context that may not flow ⇒ the candidate is not surfaced");
  // control: a permitted flow lets the candidate proceed
  const ok = anticipate(base({ utility: 10, interruptionCost: 1 }), {
    sensitive: { vault, entry, request: { recipient: "alice", purpose: "assist-subject" } },
  });
  assert.equal(ok.disposition, "surface", "a permitted flow lets anticipation proceed");
});

test("transparent + non-executing: every decision carries a reason and never auto-executes", () => {
  for (const c of [base({}), base({ vettable: false }), base({ consequence: "consequential" })]) {
    const d = anticipate(c);
    assert.ok(d.reason.length > 0, "transparent why");
    assert.equal(d.autoExecuted, false);
  }
});

test("deterministic: same candidate ⇒ same decision", () => {
  const c = base({ utility: 4, interruptionCost: 2 });
  assert.deepEqual(anticipate(c), anticipate(c));
});
