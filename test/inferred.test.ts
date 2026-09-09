import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  proposeInferred,
  admitInferred,
  applyInferred,
  provenanceOf,
  type AdmitPolicy,
} from "../src/personalize/inferred.js";
import { resolveProfile, type PolicyBounds } from "../src/personalize/personalize.js";
import { RevisionStore } from "../src/frontdoor/revision_store.js";
import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";

// Learned inference feeding the safe envelope: clamped, consequence-gated, NO rubber-stamp. BUILT: dwell/
// hysteresis/scope/clamp/provenance/auto-apply. SEAM: the estimator producing the raw signal. Verify by disproof.

function store(): RevisionStore {
  const dir = mkdtempSync(join(tmpdir(), "keep-inf-"));
  return new RevisionStore(new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry()));
}
const BOUNDS: PolicyBounds = {
  reliabilityFloor: 0.7, autonomyBackstop: "collaborator", modelCeilingTier: 3,
  defaultPromptFormat: "markdown", defaultVerbosity: "normal",
};
const POLICY: AdmitPolicy = { minDwell: 3, flipLCB: 0.55, k: 2 };
const consistent = (n: number) => Array<boolean>(n).fill(true);

test("auto-apply: an admitted cosmetic inference applies with NO human step; current view + provenance reflect it", () => {
  const s = store();
  s.create("pref:verbosity", "preference", "normal"); // operator incumbent
  const cand = proposeInferred({ dimension: "verbosity", value: "detailed" }, consistent(5));
  const r = applyInferred(s, cand, {}, BOUNDS, POLICY);
  assert.equal(r.applied, true, "auto-applied, no approval step");
  assert.equal(resolveProfile(s, {}, BOUNDS).verbosity, "detailed", "the current view reflects the inferred value");
  assert.equal(provenanceOf(s.current("pref:verbosity")?.reason), "inferred", "the write is tagged origin=inferred");
});

test("safety hard-bound: an inference reaching a safety knob is DROPPED — no application, no human", () => {
  const s = store();
  const cand = proposeInferred({ dimension: "minReliability", value: "0.3" }, consistent(20)); // tries to relax the floor
  const r = applyInferred(s, cand, {}, BOUNDS, POLICY);
  assert.equal(r.applied, false, "inference cannot touch a safety knob");
  // and even the effective floor is unmoved (the clamp is the second lock).
  assert.equal(resolveProfile(s, {}, BOUNDS).minReliability, 0.7, "the safety floor is untouched");
});

test("anti-thrash: a single/short or oscillating signal does NOT flip; a sustained consistent one does", () => {
  const incumbent = "normal";
  const single = proposeInferred({ dimension: "verbosity", value: "detailed" }, consistent(1));
  assert.equal(admitInferred(single, incumbent, POLICY), false, "one observation < dwell ⇒ no flip");
  const oscillating = proposeInferred({ dimension: "verbosity", value: "detailed" }, [true, false, true, false, true, false]);
  assert.equal(admitInferred(oscillating, incumbent, POLICY), false, "a noisy signal can't clear the dead-band");
  const sustained = proposeInferred({ dimension: "verbosity", value: "detailed" }, consistent(8));
  assert.equal(admitInferred(sustained, incumbent, POLICY), true, "a persistent consistent signal is admitted");
});

test("CP-net scope: an inferred candidate supersedes only its own scope; it doesn't apply out of scope", () => {
  const s = store();
  const cand = proposeInferred({ dimension: "promptFormat", value: "terse", scope: "project:alpha" }, consistent(5));
  const r = applyInferred(s, cand, { scope: "project:alpha" }, BOUNDS, POLICY);
  assert.equal(r.applied, true);
  assert.equal(resolveProfile(s, { scope: "project:alpha" }, BOUNDS).promptFormat, "terse", "applies in its own scope");
  assert.equal(resolveProfile(s, { scope: "project:beta" }, BOUNDS).promptFormat, "markdown", "not in another scope");
});

test("pull-agency: the operator can supersede an inferred preference and the current view + provenance flip back", () => {
  const s = store();
  s.create("pref:verbosity", "preference", "normal");
  applyInferred(s, proposeInferred({ dimension: "verbosity", value: "detailed" }, consistent(5)), {}, BOUNDS, POLICY);
  assert.equal(provenanceOf(s.current("pref:verbosity")?.reason), "inferred");
  // operator overrides — a revise WITHOUT the inferred tag.
  s.revise("pref:verbosity", "terse", "operator: I want terse");
  assert.equal(resolveProfile(s, {}, BOUNDS).verbosity, "terse", "operator override wins (reversible)");
  assert.equal(provenanceOf(s.current("pref:verbosity")?.reason), "operator", "provenance is back to operator");
});

test("deterministic: same candidate + store ⇒ same admission decision", () => {
  const cand = proposeInferred({ dimension: "verbosity", value: "detailed" }, consistent(5));
  assert.equal(admitInferred(cand, "normal", POLICY), admitInferred(cand, "normal", POLICY));
});

test("anti-thrash (dwell isolated): with the dead-band relaxed, DWELL alone still blocks a too-short signal", () => {
  // dead-band low (0.1) so a 2-obs posterior clears it (LCB≈0.36); minDwell high (5) so dwell is the sole guard.
  const dwellPolicy: AdmitPolicy = { minDwell: 5, flipLCB: 0.1, k: 2 };
  const twoObs = proposeInferred({ dimension: "verbosity", value: "detailed" }, consistent(2));
  assert.equal(admitInferred(twoObs, "normal", dwellPolicy), false, "2 observations < dwell(5) ⇒ blocked even though the dead-band passes");
  const fiveObs = proposeInferred({ dimension: "verbosity", value: "detailed" }, consistent(5));
  assert.equal(admitInferred(fiveObs, "normal", dwellPolicy), true, "dwell met ⇒ admitted");
});
