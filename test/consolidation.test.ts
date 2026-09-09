import { test } from "node:test";
import assert from "node:assert/strict";
import { Consolidation } from "../src/loop/consolidation.js";
import { type OutcomeSignal } from "../src/loop/self_improvement_bus.js";

function sig(over: Partial<OutcomeSignal> = {}): OutcomeSignal {
  return { solveId: "s", taskShape: "build", testsPassed: true, mergeVerdict: "merged", timestamp: Date.now(), ...over };
}

// ─── promote on corroborated positive reuse ───

test("promote: a provisional artifact with ≥K positive uses is promoted to full", () => {
  const c = new Consolidation({ promoteThreshold: 3, cadenceSessions: 999 });
  c.register("skill-A", "skill", "build");
  for (let i = 0; i < 3; i++) c.observe(sig({ taskShape: "build", testsPassed: true, activeArtifacts: ["skill-A"] }));
  const report = c.consolidate();
  assert.ok(report.promoted.includes("skill-A"));
  assert.equal(c.record("skill-A")?.status, "full");
});

test("promote: below threshold stays provisional", () => {
  const c = new Consolidation({ promoteThreshold: 3, cadenceSessions: 999 });
  c.register("skill-B", "skill", "build");
  for (let i = 0; i < 2; i++) c.observe(sig({ activeArtifacts: ["skill-B"] }));
  c.consolidate();
  assert.equal(c.record("skill-B")?.status, "provisional");
});

// ─── prune by OPPORTUNITY, not calendar (K6) ───

test("prune: an artifact with a full opportunity window but zero help is pruned", () => {
  const c = new Consolidation({ opportunityWindow: 10, cadenceSessions: 999 });
  c.register("dud", "lesson", "build");
  // 10 relevant tasks appear, but "dud" is never active/helpful.
  for (let i = 0; i < 10; i++) c.observe(sig({ taskShape: "build", activeArtifacts: [] }));
  const report = c.consolidate();
  assert.ok(report.pruned.includes("dud"));
  assert.equal(c.record("dud")?.status, "pruned");
});

test("N=1 protection: a rarely-triggered but VALID artifact is NOT pruned (few opportunities)", () => {
  const c = new Consolidation({ opportunityWindow: 10, cadenceSessions: 999 });
  c.register("rare", "skill", "exotic-task");
  // Only 2 relevant tasks ever appear (low-volume operator) — below the opportunity window.
  for (let i = 0; i < 2; i++) c.observe(sig({ taskShape: "exotic-task", activeArtifacts: ["rare"], testsPassed: true }));
  c.consolidate();
  assert.notEqual(c.record("rare")?.status, "pruned"); // stays alive — not punished for low volume
});

test("prune: a net-negative artifact (hurts more than helps) is pruned", () => {
  const c = new Consolidation({ promoteThreshold: 3, cadenceSessions: 999 });
  c.register("harmful", "skill", "build");
  for (let i = 0; i < 3; i++) c.observe(sig({ taskShape: "build", activeArtifacts: ["harmful"], testsPassed: false }));
  const report = c.consolidate();
  assert.ok(report.pruned.includes("harmful"));
});

// ─── forgetting-curve decay ───

test("decay: utility decays across sleep passes for an idle artifact", () => {
  const c = new Consolidation({ decay: 0.5, cadenceSessions: 999 });
  c.register("idle", "lesson", "build");
  c.observe(sig({ taskShape: "build", activeArtifacts: ["idle"], testsPassed: true })); // 1 positive use
  c.consolidate();
  const u1 = c.record("idle")!.utility;
  c.consolidate(); // another sleep with no activity → decays
  const u2 = c.record("idle")!.utility;
  assert.ok(u2 < u1, `utility should decay (${u2} < ${u1})`);
});

// ─── merge duplicates ───

test("merge: two live artifacts of the same kind+relevanceKey merge, keeping the higher-utility one", () => {
  const c = new Consolidation({ promoteThreshold: 999, cadenceSessions: 999 });
  c.register("skill-1", "skill", "build");
  c.register("skill-2", "skill", "build");
  // skill-1 gets more positive use → higher utility → kept.
  for (let i = 0; i < 3; i++) c.observe(sig({ taskShape: "build", activeArtifacts: ["skill-1"], testsPassed: true }));
  c.observe(sig({ taskShape: "build", activeArtifacts: ["skill-2"], testsPassed: true }));
  const report = c.consolidate();
  assert.equal(report.merged.length, 1);
  assert.equal(report.merged[0]?.kept, "skill-1");
  assert.equal(report.merged[0]?.absorbed, "skill-2");
  assert.equal(c.record("skill-2")?.status, "pruned");
});

// ─── session-count cadence ───

test("cadence: a sleep pass auto-runs every cadenceSessions signals (no daemon)", () => {
  const c = new Consolidation({ cadenceSessions: 3 });
  c.register("x", "skill", "build");
  assert.equal(c.observe(sig()), null);       // 1
  assert.equal(c.observe(sig()), null);       // 2
  const report = c.observe(sig());            // 3 → sleep pass fires
  assert.notEqual(report, null);
  assert.equal(c.sleeps, 1);
});

// ─── live() ranks by utility ───

test("live() returns non-pruned artifacts ranked by utility", () => {
  const c = new Consolidation({ promoteThreshold: 999, cadenceSessions: 999 });
  c.register("low", "skill", "a");
  c.register("high", "skill", "b");
  c.observe(sig({ taskShape: "b", activeArtifacts: ["high"], testsPassed: true }));
  c.observe(sig({ taskShape: "b", activeArtifacts: ["high"], testsPassed: true }));
  c.observe(sig({ taskShape: "a", activeArtifacts: ["low"], testsPassed: true }));
  c.consolidate();
  const live = c.live();
  assert.equal(live[0]?.id, "high"); // higher utility first
});
