import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { withGovernance } from "../src/solve/default_solver.js";
import { buildVettingGates } from "../src/cascade/vetting_gates.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import type { Issue, SolveResult, SearchReplaceEdit } from "../src/solve/issue_model.js";
import type { SolveToPrResult } from "../src/pipeline/keep_pipeline.js";
import type { SolveFn } from "../src/loop/review_intake.js";
import type { Optimizer } from "../src/optimizer/raise_only_clamp.js";

import { InMemoryFileTree, type FileTree } from "../src/solve/patch.js";
import { mediatedTree } from "../src/solve/mediated_tree.js";
import { defaultFloorPolicy } from "../src/floor/structural_floor.js";
import { defaultGatePolicy } from "../src/gate/composed_gate.js";
import { defaultBudgetPolicy } from "../src/budget/budget_ledger.js";
import { defaultAcceptanceTest } from "../src/ree/reversible_envelope.js";
import { executeReversibly, type ReversibleIntent, type IntegrationPolicies } from "../src/integrate/reversible_execution.js";

// STEP 2 CLOSE-OUT REVIEW — attack the COMPOSITION, not the pieces. Each layer is proven in
// isolation; these tests attack the SEAMS (STPA unsafe-control-actions at the layer boundaries).
// Every test BITES (goes red if the composition property is neutered).

function newSpine() {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-comp-"))), new InProcessLock(), new SchemaRegistry());
}
function stubSolver(edits: readonly SearchReplaceEdit[], testsPassed = true): SolveFn {
  return async (issue: Issue): Promise<SolveToPrResult> => {
    const solveResult: SolveResult = {
      issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0,
      validation: { testsPassed, failures: [], vettingCleared: false, detail: "stub" } as never,
      prProposal: { title: "t", body: "b", branch: "keep/solve/x", edits, testsPassed },
    };
    return { solveResult };
  };
}
const ISSUE: Issue = { id: "C", text: "fix", repoRef: "repo" };
const cleanEdit: SearchReplaceEdit = { file: "src/math.ts", search: "a - b", replace: "a + b", intent: "fix" };

// ── HUNT (c): ORDERING / STALE-READ — the untrusted optimizer's TIGHTEN must reach the FINAL
//    decision. If any downstream step read a pre-clamp verdict, a tighten would be lost. ──
test("HUNT-C: an optimizer that tightens floor reversible→gate flips the merge decision away from autonomous", async () => {
  const gates = buildVettingGates({ capability: "none" });
  // baseline: a clean reversible edit with the noop optimizer → autonomous-merge.
  const baseline = await withGovernance(stubSolver([cleanEdit], true), { vetPatch: gates.vetPatch, spine: newSpine() })(ISSUE);
  assert.equal(baseline.mergeAuthority!.verdict, "autonomous-merge", "clean reversible fix merges autonomously by default");

  // now an optimizer that tightens the floor to "gate" must be HONORED and reach the decision.
  const tightener: Optimizer = { propose: () => ({ floor: "gate" }) };
  const tightened = await withGovernance(stubSolver([cleanEdit], true), { vetPatch: gates.vetPatch, spine: newSpine(), optimizer: tightener })(ISSUE);
  assert.notEqual(tightened.mergeAuthority!.verdict, "autonomous-merge",
    "the optimizer's clamped tighten reached the final decision — no stale pre-clamp read");
});

// ── HUNT (c'): the same channel must NOT let a LOOSEN through (the clamp holds at the seam too). ──
test("HUNT-C': an optimizer that tries to LOOSEN cannot make a destructive change auto-merge", async () => {
  const gates = buildVettingGates({ capability: "none" });
  // a scope-creep (15-edit) change is non-autonomous; an optimizer screaming "reversible-execute"
  // must not flip it to autonomous — the clamp drops the loosen.
  const edits = Array.from({ length: 15 }, (_, i) => ({ file: `src/m${i}.ts`, search: `a${i}`, replace: `b${i}`, intent: "bump" }));
  const loosener: Optimizer = { propose: () => ({ floor: "reversible-execute", budget: "within-budget", route: "auto-proceed" }) };
  const out = await withGovernance(stubSolver(edits, true), { vetPatch: gates.vetPatch, spine: newSpine(), optimizer: loosener })(ISSUE);
  assert.notEqual(out.mergeAuthority!.verdict, "autonomous-merge", "a loosen at the seam cannot widen authority");
});

// ── HUNT (a): BYPASS — in the integrated path, a FLOOR-gating op must never reach the tree. The
//    gate is composed FROM the floor; a catastrophic-raw op → floor gate → human-hold → no write. ──
test("HUNT-A: a floor-gating (catastrophic) intent never writes through the integrated path", async () => {
  const inner = new InMemoryFileTree({ "a.txt": "old" });
  const tree: FileTree = mediatedTree(inner);
  const policies: IntegrationPolicies = {
    floor: defaultFloorPolicy("repo"), gate: defaultGatePolicy(), budget: defaultBudgetPolicy(), acceptance: defaultAcceptanceTest,
  };
  // raw contains a catastrophic op → structuralFloor returns "gate" → composeGate → human-hold.
  const catastrophic: ReversibleIntent = {
    description: { kind: "file.edit", writeSet: ["a.txt"], hasInverse: true, raw: "rm -rf / --no-preserve-root" },
    apply: async (t) => { await t.write("a.txt", "pwned"); },
    actionTier: "reversible-internal",
  };
  const res = await executeReversibly(catastrophic, policies, {
    spine: newSpine(), actor: "t", operator: "o", sign: (p) => p, tree, ownerPresent: true, envelopeEnabled: true,
  });
  assert.equal(res.path, "human-hold", "floor gate composed into the gate → human-hold, no execution");
  assert.equal(await tree.read("a.txt"), "old", "the catastrophic op never reached the tree");
});

// ── HUNT (d): SEAM-MASKING — the live wire hardcodes ownerPresent:true, so the gate's
//    owner-absent HOLD cannot fire live. Is that a hole? NO — for the irreversible class the TIER
//    veto is the active barrier (irreversible ∉ autoProceedTiers), so it holds even with owner
//    present. The owner-absent HOLD is a REDUNDANT second barrier today; it becomes singly load-
//    bearing only if an operator widens autoProceedTiers (R29). This test pins that dependency. ──
test("HUNT-D: an irreversible op holds via the TIER veto even with ownerPresent:true (owner-absent HOLD is redundant today)", async () => {
  const inner = new InMemoryFileTree({ "a.txt": "old" });
  const tree: FileTree = mediatedTree(inner);
  const policies: IntegrationPolicies = {
    floor: defaultFloorPolicy("repo"), gate: defaultGatePolicy(), budget: defaultBudgetPolicy(), acceptance: defaultAcceptanceTest,
  };
  const irreversible: ReversibleIntent = {
    description: { kind: "file.edit", writeSet: ["a.txt"], hasInverse: true, raw: "new" },
    apply: async (t) => { await t.write("a.txt", "new"); },
    actionTier: "irreversible",
  };
  // ownerPresent:true (the live-wire value) — the tier veto must still hold it.
  const res = await executeReversibly(irreversible, policies, {
    spine: newSpine(), actor: "t", operator: "o", sign: (p) => p, tree, ownerPresent: true, envelopeEnabled: true,
  });
  assert.equal(res.path, "human-hold", "the tier veto holds the irreversible class independent of owner-presence");
  assert.equal(await tree.read("a.txt"), "old");
});
//    barriers. A reversible-tier op with a catastrophic raw is still gated by the FLOOR (the tier
//    being 'reversible-internal' does not rescue it). Diverse barriers, not a shared assumption. ──
test("HUNT-B: floor and tier are independent — a reversible-TIER op with catastrophic raw still gates", async () => {
  const inner = new InMemoryFileTree({ "a.txt": "old" });
  const tree: FileTree = mediatedTree(inner);
  const policies: IntegrationPolicies = {
    floor: defaultFloorPolicy("repo"), gate: defaultGatePolicy(), budget: defaultBudgetPolicy(), acceptance: defaultAcceptanceTest,
  };
  // tier says reversible-internal (the permissive class) but the FLOOR independently gates on raw.
  const intent: ReversibleIntent = {
    description: { kind: "file.edit", writeSet: ["a.txt"], hasInverse: true, raw: "git push --force origin main" },
    apply: async (t) => { await t.write("a.txt", "x"); },
    actionTier: "reversible-internal",
  };
  const res = await executeReversibly(intent, policies, {
    spine: newSpine(), actor: "t", operator: "o", sign: (p) => p, tree, ownerPresent: true, envelopeEnabled: true,
  });
  assert.equal(res.path, "human-hold", "the floor barrier held independently of the permissive tier");
  assert.equal(await tree.read("a.txt"), "old");
});
