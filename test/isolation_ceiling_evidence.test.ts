import { test } from "node:test";
import assert from "node:assert/strict";

import {
  isolationCeilingFromEvidence,
  isolationAutonomyCeiling,
  weakenCeiling,
} from "../src/isolation/isolation_tier.js";
import {
  createRunAttestationChannel,
  processFloorEvidence,
  type IsolationEvidence,
} from "../src/isolation/isolation_attestation.js";
import { decideMergeAuthority, DEFAULT_MERGE_ENVELOPE } from "../src/oversight/merge_authority.js";

/**
 * BUILD-ORDER 2.3 (REVISIT-ISOLATION-GATING) — Z187: THE CEILING IS BOUND TO MEASURED CONTAINMENT.
 *
 * Round 43 gated only the `refuse-risky` tier from autonomous merge, and it did so because it
 * MEASURED that the default process floor did not confine an in-process runner. 1.3 (namespace+
 * rlimit jail) and 1.5 (Job Object) changed what is buildable, so the decision had to be re-measured.
 *
 * RE-MEASURED THIS ROUND (measurement-default-floor.txt): the jail / Job Object are CAPABILITIES,
 * not the default wiring — `buildEnforcingRunner` (the only wiring of `SandboxedCommandRunner`) is
 * called by NO src file — so the default path's evidence still recomputes to a bare `process`
 * (degraded []) and its ceiling stays `minimal`. That is now CONFIRMED by evidence, not asserted
 * from a stale table. What changes: `isolationCeilingFromEvidence` re-derives the ceiling from the
 * 1.7 verifier's `verifiedTier` + `measuredDegradations`, so a degraded run keeps a lower ceiling
 * and a forged-up label buys only the proven tier's ceiling. Bounded by what the tier PROVABLY
 * prevents (a namespace escape / shared-kernel LPE is still in scope) — it never RAISES a ceiling.
 *
 * Each test is paired with the neuter that reddens it; the neuter is applied to the SOURCE and the
 * RED bytes captured to redrook-ops/.round-artifacts/REVISIT-ISOLATION-GATING/.
 */

const DEGRADED: readonly string[] = ["net-deny-degraded"];

test("2.3(a): a FORGED-UP tier buys only the PROVEN tier's ceiling, not the label's", () => {
  // The 1.7 verifier caps a forged claim DOWN to the evidence; 2.3 reads that verified tier, so the
  // ceiling is the proven tier's. Composition test: claim `microvm` over the process floor's evidence.
  const { attestor, verifier } = createRunAttestationChannel();
  const forged = attestor.attest({ tier: "microvm", evidence: processFloorEvidence("linux"), projectDir: "/p", ts: 1, mechanism: "hmac-run-key" });
  const v = verifier.verify(forged);

  assert.equal(v.verifiedTier, "none", "an unreceipted microVM claim fails fully closed (1.7)");
  const ceiling = isolationCeilingFromEvidence({ verifiedTier: v.verifiedTier, measuredDegradations: v.measuredDegradations });
  assert.equal(ceiling, "refuse-risky", "the ceiling tracks the PROVEN tier");
  // NEUTER-a: read the ceiling from the claimed LABEL (`microvm`) instead of `verifiedTier`.
  assert.equal(isolationAutonomyCeiling("microvm"), "full", "the label alone would have bought `full`");
  assert.notEqual(ceiling, "full", "a forged label must NOT raise the ceiling on an unproven path");
});

test("2.3(b): a DEGRADED measurement keeps a LOWER ceiling than the tier's clean value", () => {
  // A degraded boundary proved LESS containment than the tier nominally guarantees → drop one rung.
  assert.equal(isolationCeilingFromEvidence({ verifiedTier: "container", measuredDegradations: [] }), "reduced", "clean container");
  assert.equal(isolationCeilingFromEvidence({ verifiedTier: "container", measuredDegradations: DEGRADED }), "minimal", "degraded container drops a rung");
  assert.equal(isolationCeilingFromEvidence({ verifiedTier: "microvm", measuredDegradations: DEGRADED }), "reduced", "degraded microvm drops a rung");
  // The default process floor, if it ever measured a degradation (net-deny unenforceable / Job Object
  // degraded), drops all the way to the floor — the gate EXTENDS to the real, weaker boundary.
  assert.equal(isolationCeilingFromEvidence({ verifiedTier: "process", measuredDegradations: DEGRADED }), "refuse-risky", "degraded process floor drops to refuse-risky");
  // NEUTER-b: delete the `measuredDegradations.length > 0` branch (always return nominal) → these
  // degraded cases return the CLEAN ceiling → every assertion above reddens.
});

test("2.3(c): the refuse-risky gate still fires for the genuinely-unisolated tier", () => {
  // `none` is the tier the codebase itself calls refuse-risky; a clean OR degraded `none` stays there.
  assert.equal(isolationCeilingFromEvidence({ verifiedTier: "none", measuredDegradations: [] }), "refuse-risky", "none is refuse-risky");
  assert.equal(isolationCeilingFromEvidence({ verifiedTier: "none", measuredDegradations: ["no-isolation"] }), "refuse-risky", "and stays there when degraded (floor)");
  // and that refuse-risky ceiling is what suppresses autonomous merge (the round-42 gate, now fed by
  // the evidence-bound ceiling). NEUTER-c: neuter merge_authority's `unisolated` check → autonomous-merge → RED.
  const verified = { testsPassed: true, vettingCleared: true };
  const benign = { actionTier: "reversible-internal" as const, consequenceBand: "low" as const, alwaysGatePath: false };
  const gated = decideMergeAuthority({ verification: verified, consequence: benign, envelope: DEFAULT_MERGE_ENVELOPE, executionUnisolated: true });
  assert.equal(gated.verdict, "human-merge", "a refuse-risky run needs a person");
});

test("2.3(d): an HONEST strong tier is NOT over-gated (no false demotion vs 1.7)", () => {
  // A clean measurement keeps the nominal ceiling — the degradation drop must not bite an honest run.
  assert.equal(isolationCeilingFromEvidence({ verifiedTier: "microvm", measuredDegradations: [] }), "full", "clean microvm keeps full");
  assert.equal(isolationCeilingFromEvidence({ verifiedTier: "gvisor", measuredDegradations: [] }), "full", "clean gvisor keeps full");
  assert.equal(isolationCeilingFromEvidence({ verifiedTier: "container", measuredDegradations: [] }), "reduced", "clean container keeps reduced");
  assert.equal(isolationCeilingFromEvidence({ verifiedTier: "process", measuredDegradations: [] }), "minimal", "clean process keeps minimal — the DEFAULT is unchanged");
  // NEUTER-d: weaken UNCONDITIONALLY (drop the length guard the other way) → clean microvm → reduced → RED.
});

test("2.3: weakenCeiling drops exactly one rung and never below the floor", () => {
  assert.equal(weakenCeiling("full"), "reduced");
  assert.equal(weakenCeiling("reduced"), "minimal");
  assert.equal(weakenCeiling("minimal"), "refuse-risky");
  assert.equal(weakenCeiling("refuse-risky"), "refuse-risky", "the floor cannot be weakened further");
});

test("2.3: the verifier SURFACES the measured degradations it appraised", () => {
  // The ceiling can only be evidence-bound if the 1.7 verifier hands the degradations forward.
  const { attestor, verifier } = createRunAttestationChannel();
  const degradedProcess: IsolationEvidence = { platform: "linux", runtimeKind: "process", kvmPresent: false, imagesPresent: false, jobObjectSupport: false, degraded: DEGRADED };
  const att = attestor.attest({ tier: "process", evidence: degradedProcess, projectDir: "/p", ts: 1, mechanism: "hmac-run-key" });
  assert.deepEqual(verifier.verify(att).measuredDegradations, DEGRADED, "verified attestation carries its degradations");
  // absent / bad-signature appraised nothing → empty (the tier already fell to none).
  assert.deepEqual(verifier.verify(undefined).measuredDegradations, [], "absent attestation degrades nothing");
});
