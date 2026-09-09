import { test } from "node:test";
import assert from "node:assert/strict";

import { decideMergeAuthority, DEFAULT_MERGE_ENVELOPE } from "../src/oversight/merge_authority.js";
import { buildPrProposal } from "../src/solve/solve_pipeline.js";
import type { EditPlan, Issue } from "../src/solve/issue_model.js";

/**
 * ROUND 41 — PUTTING THE FINDING WHERE THE DECISION IS MADE.
 *
 * Round 40 reported a control configured into silence, through the operator's live feed. Measured
 * at the start of this round, before anything was built:
 *
 *   inert allowlist ["src","*"]  →  policy warning EMITTED
 *                                →  merge verdict autonomous-merge
 *                                →  auto-merged
 *
 * **Autonomous merge is defined by there being no human in the loop**, so a warning written for a
 * human reader reached nobody — on the one path that most needed it.
 *
 * The habituation research says the same from the other side: users "click through 50% of SSL
 * warnings in 1.7 seconds", visual processing drops "after only the second exposure", and
 * habituation to unrelated frequent notifications GENERALISES to a one-time security warning. A
 * line in a progress feed beside a successful result is exactly that case. "Actively interrupting
 * people's workflows is more effective than using passive indicators."
 *
 * So this round changes the CONTROL FLOW rather than adding another notice — and deliberately
 * does NOT add an acknowledgement click, which the same research says trains dismissal.
 */

const VERIFIED = { testsPassed: true, vettingCleared: true };
const BENIGN = { actionTier: "reversible-internal" as const, consequenceBand: "low" as const, alwaysGatePath: false };

test("R41: an inert control suppresses AUTONOMOUS merge and routes to a human", () => {
  const clean = decideMergeAuthority({ verification: VERIFIED, consequence: BENIGN, envelope: DEFAULT_MERGE_ENVELOPE });
  assert.equal(clean.verdict, "autonomous-merge", "the same change auto-merges with controls intact");

  const inert = decideMergeAuthority({
    verification: VERIFIED, consequence: BENIGN, envelope: DEFAULT_MERGE_ENVELOPE,
    inertControls: ['allowedPaths names 1 region(s) (src) but also contains a bare "*"'],
  });
  assert.equal(inert.verdict, "human-merge", "an inert control makes it a person's decision");
  assert.equal(inert.consequential, true);
  assert.equal(inert.verified, true, "the change still verified — this is about the barrier, not the change");
});

test("R41: it is NOT a block — the work is still produced, a person just owns the merge", () => {
  // Requirement 1. A misconfigured barrier is a legal state; this round must not turn it into a
  // failure. `block` is reserved for a sound safety check failing.
  const d = decideMergeAuthority({
    verification: VERIFIED, consequence: BENIGN, envelope: DEFAULT_MERGE_ENVELOPE,
    inertControls: ["protectedMatchers is empty"],
  });
  assert.notEqual(d.verdict, "block", "a legal-but-unwise configuration is never a block");
  assert.equal(d.verdict, "human-merge");
});

test("R41: the reason NAMES the inert control, not a false generic cause", () => {
  // "Irreversible / high-blast / sensitive" would be a wrong explanation here, and an operator
  // told the wrong reason cannot fix the right thing (Z168).
  const d = decideMergeAuthority({
    verification: VERIFIED, consequence: BENIGN, envelope: DEFAULT_MERGE_ENVELOPE,
    inertControls: ["protectedMatchers is empty — protected-resource screening is disabled"],
  });
  assert.match(d.reason, /safety control is configured off/);
  assert.match(d.reason, /protectedMatchers is empty/, "the specific control is named");
  assert.doesNotMatch(d.reason, /irreversible \/ high-blast/, "and not misattributed to consequence");
});

test("R41: omitted or empty inertControls changes NOTHING", () => {
  // Requirement (c) and round 38's inert-default guarantee: every existing caller is unaffected.
  const omitted = decideMergeAuthority({ verification: VERIFIED, consequence: BENIGN, envelope: DEFAULT_MERGE_ENVELOPE });
  const empty = decideMergeAuthority({ verification: VERIFIED, consequence: BENIGN, envelope: DEFAULT_MERGE_ENVELOPE, inertControls: [] });

  assert.equal(omitted.verdict, "autonomous-merge");
  assert.equal(empty.verdict, "autonomous-merge", "an empty list is not a finding");
  assert.deepEqual(omitted, empty, "omitted and empty are byte-identical decisions");
});

test("R41: an inert control does NOT bother a human about an unverified low-risk change", () => {
  // The codebase's own invariant: "bothering a human for every low-risk uncertainty trains
  // rubber-stamping and devalues the approvals that matter." An UNVERIFIED reversible low-blast
  // change is abandoned autonomously — but with an inert control it becomes consequential, so it
  // routes to a human instead of being silently dropped. Pinning which way that resolves, because
  // it is the one interaction where this round's change meets that invariant.
  const unverifiedClean = decideMergeAuthority({
    verification: { testsPassed: false, vettingCleared: true }, consequence: BENIGN, envelope: DEFAULT_MERGE_ENVELOPE,
  });
  assert.equal(unverifiedClean.verdict, "abandon-retry", "normally dropped without bothering anyone");

  const unverifiedInert = decideMergeAuthority({
    verification: { testsPassed: false, vettingCleared: true }, consequence: BENIGN, envelope: DEFAULT_MERGE_ENVELOPE,
    inertControls: ["protectedMatchers is empty"],
  });
  assert.equal(unverifiedInert.verdict, "human-merge", "with a barrier off, it is not safe to drop silently either");
});

// ── the artifact a human actually reads ──

const ISSUE: Issue = { id: "R41", text: "fix add()", repoRef: "repo" };
const PLAN: EditPlan = { rationale: "fix", edits: [{ file: "src/calc.ts", search: "a - b", replace: "a + b", intent: "fix" }] } as EditPlan;

test("R41: the PR body carries the finding, in plain language, beside the merge decision", () => {
  const pr = buildPrProposal(ISSUE, PLAN, true, ["protectedMatchers is empty — protected-resource screening is disabled"]);

  assert.match(pr.body, /A safety control was switched off for this run/, "an operator-legible heading");
  assert.match(pr.body, /protectedMatchers is empty/, "the specific finding");
  assert.match(pr.body, /Autonomous merge was suppressed/, "and what it caused, so the two agree");
});

test("R41 SWEEP: summoning a human without a decision brief was the near-miss", () => {
  // FOUND BY SWEEPING FOR OTHER CONSUMERS (Z172), after the merge-authority wiring was already
  // working. `autoApprovable` is a SECOND decision reading the same run, and it still ignored
  // `inertControls` — so under `microvm` isolation the measured result was `human-merge` with the
  // decision brief ABSENT. A person called in to own a merge, handed nothing to reason from,
  // which is precisely the rubber-stamping the brief exists to prevent.
  //
  // The near-miss has an instructive shape: the stronger the isolation, the more auto-approvable
  // a run is — right when isolation is the reason, wrong when the reason is a barrier switched
  // off. Two independent decisions consumed one fact and only one had been told.
  //
  // Pinned here as the RULE rather than the plumbing: whatever makes a change consequential must
  // also suppress auto-approval, or the human arrives uninformed.
  const consequentialByInertControl = decideMergeAuthority({
    verification: VERIFIED, consequence: BENIGN, envelope: DEFAULT_MERGE_ENVELOPE,
    inertControls: ["protectedMatchers is empty"],
  });
  assert.equal(consequentialByInertControl.verdict, "human-merge");
  assert.equal(
    consequentialByInertControl.consequential, true,
    "consequential is the flag keep_pipeline's autoApprovable must also respect — see the controlsInert clause",
  );
});

test("R41: a clean run produces a CLEAN artifact — no empty section, no '0 issues' line", () => {
  // Requirement (c). A section that is usually empty is the section people learn to skip, which
  // is the habituation failure this round exists to avoid — so on a clean run there is nothing.
  const pr = buildPrProposal(ISSUE, PLAN, true);

  assert.doesNotMatch(pr.body, /safety control/i, "nothing about controls on a clean run");
  assert.doesNotMatch(pr.body, /switched off/i);
  assert.match(pr.body, /All tests pass/, "and the ordinary body is unchanged");
});
