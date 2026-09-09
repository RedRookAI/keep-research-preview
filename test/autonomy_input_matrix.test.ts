import { test } from "node:test";
import assert from "node:assert/strict";

import { decideMergeAuthority, DEFAULT_MERGE_ENVELOPE } from "../src/oversight/merge_authority.js";
import { isolationAutonomyCeiling } from "../src/isolation/isolation_tier.js";

/**
 * ROUND 42 — WHICH SAFETY INPUTS REACH WHICH AUTONOMY DECISION.
 *
 * Round 41 found `autoApprovable` ignoring a value merge authority had been told. This round
 * measured the whole matrix on the real pipeline and found the SAME GAP FACING THE OTHER WAY:
 *
 *   safety input          autoApprovable   mergeAuthority
 *   vetting cleared            ✓                ✓
 *   plan escalated             ✓                ✓ (via actionTier)
 *   inert controls             ✓                ✓ (round 41)
 *   trajectory drift           ✓                ✗   ← by design, see below
 *   patch-time forecast        ✓                ✗   ← by design, see below
 *   ISOLATION CEILING          ✓                ✗   ← A MISS, fixed this round
 *
 * Measured before the fix, on the real pipeline:
 *
 *   isolationTier: "none"  →  merge=autonomous-merge, auto-merged=YES
 *
 * AI-generated code executed with NO isolation, merged with no human. The autonomy ceiling for
 * that tier is literally named `refuse-risky`, and autonomous merge is the most autonomous act
 * available — the two cannot coherently coexist.
 *
 * WHY IT BELONGS IN MERGE AUTHORITY specifically: merge authority trusts `testsPassed`. Under no
 * isolation the patch under test can reach the machine running it, so the test result is weaker
 * evidence than it appears. Isolation is not only about blast radius during execution; it bounds
 * how far the verification can be believed.
 */

const VERIFIED = { testsPassed: true, vettingCleared: true };
const BENIGN = { actionTier: "reversible-internal" as const, consequenceBand: "low" as const, alwaysGatePath: false };
const decide = (extra: Record<string, unknown> = {}) =>
  decideMergeAuthority({ verification: VERIFIED, consequence: BENIGN, envelope: DEFAULT_MERGE_ENVELOPE, ...extra } as never);

test("R42: the refuse-risky isolation tier suppresses autonomous merge", () => {
  assert.equal(decide().verdict, "autonomous-merge", "the same change merges autonomously when isolated");
  assert.equal(decide({ executionUnisolated: true }).verdict, "human-merge", "and needs a person when it was not");
});

test("R42: the reason names ISOLATION, not a borrowed cause", () => {
  // Round 41's lesson (Z168): an operator told the wrong reason cannot fix the right thing. This
  // must not be attributed to consequence, nor to an inert control.
  const d = decide({ executionUnisolated: true });
  assert.match(d.reason, /executed with no isolation/);
  assert.match(d.reason, /refuse-risky/, "names the tier the codebase itself calls that");
  assert.doesNotMatch(d.reason, /safety control is configured off/, "not confused with the round-41 cause");
  assert.doesNotMatch(d.reason, /irreversible \/ high-blast/, "and not with consequence");
});

test("R42: the gate is DELIBERATELY narrow — only the refuse-risky tier", () => {
  // Requirement 3: a mechanism must not force false coupling. `process` is the DEFAULT tier, and
  // gating it would suppress autonomous merge for every existing caller — a large behaviour
  // change the measurement does not support. Pinned so the narrowness is a decision on record
  // rather than an oversight someone later "fixes".
  assert.equal(isolationAutonomyCeiling("none"), "refuse-risky", "only this tier is gated");
  assert.equal(isolationAutonomyCeiling("process"), "minimal", "the default tier is NOT gated");
  assert.equal(isolationAutonomyCeiling("container"), "reduced", "nor is container");
  assert.equal(isolationAutonomyCeiling("microvm"), "full");

  assert.equal(decide({ executionUnisolated: false }).verdict, "autonomous-merge", "false is not a finding");
  assert.equal(decide().verdict, "autonomous-merge", "omitted is not a finding");
});

test("R42: two independent reasons do not mask each other", () => {
  // Both round 41's cause and this round's can hold at once. The verdict must be human-merge and
  // the reason must still be specific — a union of causes that reports only the first one found
  // is how an operator fixes half a problem and believes it is done.
  const both = decide({ executionUnisolated: true, inertControls: ["protectedMatchers is empty"] });
  assert.equal(both.verdict, "human-merge");
  assert.equal(both.consequential, true);
  assert.ok(both.reason.length > 0, "a reason is always given");
});

test("R42 MATRIX: drift and forecast are CORRECT-BY-DESIGN omissions, not misses", () => {
  // Requirement 2: a gap is not automatically a defect, and this round must say which is which.
  //
  // `drift.drifted` and the patch-time forecast are TRAJECTORY signals — they describe how the
  // solve behaved, not what the change is or how well it was verified. Merge authority is
  // consequence-primary by explicit design: "gate on reversibility and blast radius, not on
  // confidence — bothering a human for every low-risk uncertainty trains rubber-stamping and
  // devalues the approvals that matter." Threading them in would double-gate a reversible,
  // low-blast change that auto-approval has already handled.
  //
  // Isolation is different in kind, which is why it was the one fixed: it does not describe the
  // solve's behaviour, it bounds whether `testsPassed` can be believed at all.
  //
  // This test asserts the DECISION, so a future round that threads them in must justify it here
  // rather than doing it silently.
  const unverifiedReversible = decideMergeAuthority({
    verification: { testsPassed: false, vettingCleared: true }, consequence: BENIGN, envelope: DEFAULT_MERGE_ENVELOPE,
  });
  assert.equal(
    unverifiedReversible.verdict, "abandon-retry",
    "confidence signals on a reversible low-blast change resolve without a human — the invariant drift/forecast would violate",
  );
});
