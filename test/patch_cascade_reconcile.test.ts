import { test } from "node:test";
import assert from "node:assert/strict";

import { buildVettingGates, type PatchVetPayload } from "../src/cascade/vetting_gates.js";
import type { SolveResult, SearchReplaceEdit } from "../src/solve/issue_model.js";

function edit(i: number): SearchReplaceEdit {
  return { file: `src/mod${i}.ts`, search: `const a${i} = 1`, replace: `const a${i} = 2`, intent: "bump" };
}
function solveResultWith(edits: readonly SearchReplaceEdit[]): SolveResult {
  return {
    issueId: "I1", solved: true, stagesRun: [], repairRounds: 0,
    validation: { testsPassed: true, detail: "ok" } as never,
    prProposal: { title: "t", body: "b", branch: "keep/solve/I1", edits, testsPassed: true },
  };
}
const cleanEdits = Array.from({ length: 3 }, (_, i) => edit(i));          // few, clean → pass
const scopeCreepEdits = Array.from({ length: 15 }, (_, i) => edit(i));    // >12 → heuristic flag → escalate-human
const testFileEdit: SearchReplaceEdit = { file: "src/foo.test.ts", search: "expect(x).toBe(1)", replace: "expect(x).toBe(2)", intent: "game the test" };

test("CROWN (reconciliation): a heuristic concern surfaces as UNRESOLVED — it does NOT silently pass the floor as verified", async () => {
  const gates = buildVettingGates({ capability: "none" }); // no model tier
  const out = await gates.vetPatch({ solveResult: solveResultWith(scopeCreepEdits), issueText: "fix the bug" } as PatchVetPayload);
  assert.equal(out.finalDecision, "escalate-human", "scope-creep is surfaced as unresolved (consequence-gated downstream), not cleared");
  assert.notEqual(out.finalDecision, "pass", "the old collapse (escalate-human → silent pass) is fixed");
});

test("CLIMB: with a model tier present, escalate-human climbs to the model (not the floor, not human directly)", async () => {
  // A model verifier that passes — it gets the chance to decide the heuristic residual the floor couldn't.
  const blessing = () => ({ decision: "pass" as const, reason: "reviewed, fine", certainty: 1 });
  const gates = buildVettingGates({ capability: "lean", patchSingleBrain: blessing });
  const out = await gates.vetPatch({ solveResult: solveResultWith(scopeCreepEdits), issueText: "fix the bug" } as PatchVetPayload);
  assert.notEqual(out.decidedAtTier, 0, "the floor did not decide it — it climbed");
  assert.equal(out.finalDecision, "pass", "the model tier weighed the heuristic residual and cleared it");
});

test("SOUND FAIL still authoritative: modifying a test file is a sound fail even when a model would bless it", async () => {
  const blessing = () => ({ decision: "pass" as const, reason: "looks fine", certainty: 1 });
  const gates = buildVettingGates({ capability: "lean", patchSingleBrain: blessing });
  const out = await gates.vetPatch({ solveResult: solveResultWith([edit(0), testFileEdit]), issueText: "fix" } as PatchVetPayload);
  assert.equal(out.finalDecision, "fail", "oracle-gaming (test-file edit) is a sound fail");
  assert.equal(out.decidedAtTier, 0, "decided at the sound floor — the model could not overturn it");
});

test("CLEAN patch passes at the floor", async () => {
  const gates = buildVettingGates({ capability: "none" });
  const out = await gates.vetPatch({ solveResult: solveResultWith(cleanEdits), issueText: "fix" } as PatchVetPayload);
  assert.equal(out.finalDecision, "pass");
  assert.equal(out.decidedAtTier, 0);
});

test("WIRE: composeKeep's vetPatch routes real patches through the reconciled 3-valued floor", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const { mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-pcr-")) });
  const out = await app.vettingGates.vetPatch({ solveResult: solveResultWith(scopeCreepEdits), issueText: "fix" } as PatchVetPayload);
  assert.equal(out.finalDecision, "escalate-human", "the composed cascade surfaces the heuristic concern for a human");
});

// ── MISSION ALIGNMENT: escalate-human is CONSEQUENCE-gated, never a direct human interrupt ──
import { decideMergeAuthority, mergeVerificationFromCascade } from "../src/oversight/merge_authority.js";

const reversible = { consequence: { actionTier: "reversible-internal" as const, consequenceBand: "low" as const, alwaysGatePath: false },
  envelope: { autonomousMergeEnabled: true, maxAutonomousBand: "medium" as const, autoMergeTiers: new Set(["read-only", "reversible-internal"] as const) } };
const consequential = { consequence: { actionTier: "irreversible" as const, consequenceBand: "high" as const, alwaysGatePath: false },
  envelope: { autonomousMergeEnabled: true, maxAutonomousBand: "medium" as const, autoMergeTiers: new Set(["read-only", "reversible-internal"] as const) } };

test("MISSION (crown): a heuristic concern on a REVERSIBLE change is handled AUTONOMOUSLY — a human is NOT bothered", async () => {
  const gates = buildVettingGates({ capability: "none" });
  const outcome = await gates.vetPatch({ solveResult: solveResultWith(scopeCreepEdits), issueText: "fix" } as PatchVetPayload);
  assert.equal(outcome.finalDecision, "escalate-human", "cascade can't auto-verify the scope-creep");
  const decision = decideMergeAuthority({
    verification: mergeVerificationFromCascade(outcome, { testsPassed: true }),
    ...reversible,
  });
  assert.equal(decision.verdict, "abandon-retry", "reversible + low-blast → retry/drop autonomously, NEVER a human interrupt");
  assert.notEqual(decision.verdict, "human-merge");
});

test("MISSION: the SAME heuristic concern on a CONSEQUENTIAL change goes to a human (Tier-4 non-negotiable)", async () => {
  const gates = buildVettingGates({ capability: "none" });
  const outcome = await gates.vetPatch({ solveResult: solveResultWith(scopeCreepEdits), issueText: "fix" } as PatchVetPayload);
  const decision = decideMergeAuthority({
    verification: mergeVerificationFromCascade(outcome, { testsPassed: true }),
    ...consequential,
  });
  assert.equal(decision.verdict, "human-merge", "irreversible / high-blast + unverified → a person owns it");
});

test("MISSION: a CLEAN patch on a reversible change merges autonomously (quiet by default)", async () => {
  const gates = buildVettingGates({ capability: "none" });
  const outcome = await gates.vetPatch({ solveResult: solveResultWith(cleanEdits), issueText: "fix" } as PatchVetPayload);
  const decision = decideMergeAuthority({
    verification: mergeVerificationFromCascade(outcome, { testsPassed: true }),
    ...reversible,
  });
  assert.equal(decision.verdict, "autonomous-merge", "verified + reversible + low-blast → merge without bothering anyone");
});

test("MISSION: a SOUND fail is blocked outright, regardless of consequence (not a human judgement call)", async () => {
  const gates = buildVettingGates({ capability: "none" });
  const outcome = await gates.vetPatch({ solveResult: solveResultWith([edit(0), testFileEdit]), issueText: "fix" } as PatchVetPayload);
  const decision = decideMergeAuthority({
    verification: mergeVerificationFromCascade(outcome, { testsPassed: true }),
    ...reversible,
  });
  assert.equal(decision.verdict, "block", "a sound safety failure is never mergeable — and never a human interrupt either");
});
