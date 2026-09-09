import { test } from "node:test";
import assert from "node:assert/strict";
import { decideMergeAuthority, DEFAULT_MERGE_ENVELOPE, type MergeAuthorityInputs, type MergeEnvelope } from "../src/oversight/merge_authority.js";
import type { ActionTier } from "../src/control/action_tier.js";
import type { RiskBand } from "../src/oversight/pr_risk.js";

function inputs(over: {
  testsPassed?: boolean; vettingCleared?: boolean; behavioralFork?: boolean; soundFailure?: boolean;
  actionTier?: ActionTier; consequenceBand?: RiskBand; alwaysGatePath?: boolean; envelope?: Partial<MergeEnvelope>;
} = {}): MergeAuthorityInputs {
  return {
    verification: { testsPassed: over.testsPassed ?? true, vettingCleared: over.vettingCleared ?? true, ...(over.behavioralFork !== undefined ? { behavioralFork: over.behavioralFork } : {}), ...(over.soundFailure !== undefined ? { soundFailure: over.soundFailure } : {}) },
    consequence: { actionTier: over.actionTier ?? "reversible-internal", consequenceBand: over.consequenceBand ?? "low", alwaysGatePath: over.alwaysGatePath ?? false },
    envelope: { ...DEFAULT_MERGE_ENVELOPE, ...over.envelope },
  };
}
const verdict = (o?: Parameters<typeof inputs>[0]) => decideMergeAuthority(inputs(o)).verdict;

// ── The autonomy the goal wants ──
test("AM1: a verified, reversible, low-blast change merges AUTONOMOUSLY (no human)", () => {
  assert.equal(verdict(), "autonomous-merge");
});
test("AM1: a verified reversible MEDIUM-blast change auto-merges under the default 'as autonomous as possible' envelope", () => {
  assert.equal(verdict({ consequenceBand: "medium" }), "autonomous-merge");
});

// ── The hard consequence gates — these must NEVER auto-merge, even fully verified ──
test("AM1 SAFETY: an IRREVERSIBLE change NEVER auto-merges, even fully verified", () => {
  assert.equal(verdict({ actionTier: "irreversible" }), "human-merge");
});
test("AM1 SAFETY: a sensitive ALWAYS-GATE path (auth/deploy/payment) NEVER auto-merges, even verified + low-blast", () => {
  assert.equal(verdict({ alwaysGatePath: true }), "human-merge");
});
test("AM1 SAFETY: a HIGH consequence-band change NEVER auto-merges, even verified", () => {
  assert.equal(verdict({ consequenceBand: "high" }), "human-merge");
});
test("AM1 SAFETY: an external-touching change is not in the default auto-merge tiers → human", () => {
  assert.equal(verdict({ actionTier: "external-touching" }), "human-merge");
});
test("AM1 SAFETY: a change beyond the envelope's max band → human (envelope maxBand=low, change=medium)", () => {
  assert.equal(verdict({ consequenceBand: "medium", envelope: { maxAutonomousBand: "low" } }), "human-merge");
});

// ── The anti-rubber-stamp core: uncertainty ALONE never bothers a human ──
test("AM1 ANTI-RUBBERSTAMP: an UNVERIFIED reversible low-blast change → abandon-retry, NEVER a human", () => {
  assert.equal(verdict({ testsPassed: false }), "abandon-retry");
  assert.equal(verdict({ vettingCleared: false }), "abandon-retry");
  assert.equal(verdict({ behavioralFork: true }), "abandon-retry");
});
test("AM1: uncertainty + CONSEQUENCE together (2-of-3) → human-merge", () => {
  assert.equal(verdict({ testsPassed: false, actionTier: "irreversible" }), "human-merge");
  assert.equal(verdict({ testsPassed: false, alwaysGatePath: true }), "human-merge");
});

// ── Safety floor + owner control ──
test("AM1: a SOUND safety failure is BLOCKED (never merged, never a mere 'ask')", () => {
  assert.equal(verdict({ soundFailure: true }), "block");
  // even on a trivially reversible change, a sound failure blocks
  assert.equal(verdict({ soundFailure: true, actionTier: "read-only" }), "block");
});
test("AM1: the owner can DISABLE autonomous merge — verified reversible falls back to human, nothing auto-merges", () => {
  assert.equal(verdict({ envelope: { autonomousMergeEnabled: false } }), "human-merge");
});
test("AM1: disabling autonomy never turns a block into a merge, nor a retry into a human bother", () => {
  const env = { autonomousMergeEnabled: false };
  assert.equal(verdict({ soundFailure: true, envelope: env }), "block");
  assert.equal(verdict({ testsPassed: false, envelope: env }), "abandon-retry");
});
