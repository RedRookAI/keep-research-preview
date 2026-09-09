import { test } from "node:test";
import assert from "node:assert/strict";
import { GovernedAnchor, type VerifiedOutcome } from "../src/learning/governed_anchor.js";
import { composeKeep } from "../src/compose.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const core = [
  { id: "core-1", input: "fix null deref in parser", expected: "guarded" },
  { id: "core-2", input: "add retry to network client", expected: "retried" },
];

function outcome(over: Partial<VerifiedOutcome> = {}): VerifiedOutcome {
  return { outcomeId: "o1", input: "optimize the sort routine for large inputs", expected: "sorted", independentlyVerified: true, ...over };
}

// ─── bounded self-modification: the invariant ───

test("rejects an outcome that was not independently verified", () => {
  const a = new GovernedAnchor(core);
  const r = a.admit(outcome({ independentlyVerified: false }), "prompt");
  assert.equal(r.verdict, "rejected-not-verified");
});

test("rejects a self-authored outcome (produced by the component being validated)", () => {
  const a = new GovernedAnchor(core);
  const r = a.admit(outcome({ producedByComponent: "prompt" }), "prompt");
  assert.equal(r.verdict, "rejected-self-authored");
  assert.match(r.reason, /bounded self-modification/);
});

test("admits an outcome produced by a DIFFERENT component (not self-authored)", () => {
  const a = new GovernedAnchor(core);
  const r = a.admit(outcome({ producedByComponent: "memory-lesson" }), "prompt");
  assert.equal(r.verdict, "admitted");
});

// ─── novelty gate (in-distribution contamination guard) ───

test("rejects a near-duplicate of an existing case", () => {
  const a = new GovernedAnchor(core);
  // Almost identical to core-1.
  const r = a.admit(outcome({ outcomeId: "dup", input: "fix null deref in parser" }), "prompt");
  assert.equal(r.verdict, "rejected-duplicate");
});

test("admits a genuinely novel case", () => {
  const a = new GovernedAnchor(core);
  const r = a.admit(outcome({ outcomeId: "novel", input: "refactor the auth middleware into layers" }), "prompt");
  assert.equal(r.verdict, "admitted");
  assert.ok(a.has(r.caseId!));
});

// ─── stable core preserved, refresh saturates ───

test("the stable core is never retired by saturation", () => {
  const a = new GovernedAnchor(core, { saturationMinAttempts: 2, saturationRate: 0.5 });
  for (let i = 0; i < 10; i++) a.recordResult("core-1", true); // trivially solved
  assert.ok(a.has("core-1"), "core case is preserved for longitudinal comparability");
});

test("a saturated refresh case retires (evaluator rotation / saturation trigger)", () => {
  const a = new GovernedAnchor(core, { saturationMinAttempts: 3, saturationRate: 0.9 });
  const r = a.admit(outcome({ outcomeId: "sat", input: "unique novel task about widget rendering" }), "prompt");
  const id = r.caseId!;
  a.recordResult(id, true);
  a.recordResult(id, true);
  a.recordResult(id, true); // 3/3 = 1.0 >= 0.9 → retire
  assert.ok(!a.has(id), "trivially-solved refresh case retires");
});

// ─── snapshot: frozen anchor, closures not case internals ───

test("snapshot produces a frozen EvalAnchor whose score() runs and exposes only id/input/expected", () => {
  const a = new GovernedAnchor(core);
  const anchor = a.snapshot(0, (c, v) => v.includes("good"), () => false);
  assert.equal(anchor.cases.length, 2); // both core, no refresh yet
  // Exposes only the three public fields — no solves/attempts/provenance.
  for (const c of anchor.cases) {
    assert.deepEqual(Object.keys(c).sort(), ["expected", "id", "input"]);
  }
  assert.equal(anchor.score("all-good-version"), 1); // every case "passes" under the stub
  assert.equal(anchor.score("bad-version"), 0);
});

test("snapshot rotates the refresh fold across rounds (Goodhart mitigation)", () => {
  const a = new GovernedAnchor(core);
  // Admit several novel refresh cases.
  for (let i = 0; i < 9; i++) {
    a.admit(outcome({ outcomeId: `n${i}`, input: `distinct task number ${i} about subsystem ${i}` }), "prompt");
  }
  const round0 = a.snapshot(0, () => true, () => false).cases.map((c) => c.id).sort();
  const round1 = a.snapshot(1, () => true, () => false).cases.map((c) => c.id).sort();
  // Core is in both; the refresh subset should differ across rounds (rotation).
  assert.notDeepEqual(round0, round1, "refresh fold rotates across rounds");
});

// ─── the improver cannot mutate the anchor through the snapshot ───

test("the returned anchor's case list is a snapshot copy — mutating it does not affect the governed anchor", () => {
  const a = new GovernedAnchor(core);
  const anchor = a.snapshot(0, () => true, () => false);
  // Attempt to mutate the exposed cases array (readonly at type level; test runtime immutability of source).
  (anchor.cases as unknown as { id: string }[]).push({ id: "injected" } as never);
  const fresh = a.snapshot(0, () => true, () => false);
  assert.ok(!fresh.cases.some((c) => c.id === "injected"), "improver cannot inject a case via the snapshot");
});

test("growth is proposal-only and approval changes only a later anchor snapshot", () => {
  const governed = new GovernedAnchor(core);
  const active = governed.snapshot(0, () => true, () => false, 1);
  const proposal = governed.propose(outcome({ outcomeId: "future", input: "diagnose a novel cache coherence failure" }), "prompt");
  assert.equal(proposal.verdict, "proposed");
  assert.deepEqual(governed.stats(), { core: 2, refresh: 0, total: 2 });
  assert.equal(governed.pending().length, 1);
  if (proposal.verdict === "proposed") assert.equal(governed.approve(proposal.proposalId).verdict, "admitted");
  assert.equal(active.cases.length, 2, "approval cannot mutate the active evaluation epoch");
  assert.equal(governed.snapshot(0, () => true, () => false, 1).cases.length, 3);
});

test("composed real outcomes create inert proposals and never auto-admit", async () => {
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-anchor-outcome-wire-")), anchorCore: core,
    anchorCaseFromOutcome: (signal) => ({ outcome: { outcomeId: signal.solveId, input: `independent task ${signal.taskShape}`, expected: "verified", independentlyVerified: signal.testsPassed, producedByComponent: "memory-lesson" }, validatingComponent: "prompt" }),
  });
  await app.selfImprovementBus.publish({ solveId: "real-1", taskShape: "novel-cache-case", testsPassed: true, mergeVerdict: "merged", timestamp: 1 });
  assert.equal(app.governedAnchor!.pending().length, 1);
  assert.deepEqual(app.governedAnchor!.stats(), { core: 2, refresh: 0, total: 2 });
  await app.selfImprovementBus.publish({ solveId: "unverified", taskShape: "unverified-case", testsPassed: false, mergeVerdict: "pending", timestamp: 2 });
  assert.equal(app.governedAnchor!.pending().length, 1);
});
