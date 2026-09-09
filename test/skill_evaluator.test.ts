import { test } from "node:test";
import assert from "node:assert/strict";

import { SkillCanary } from "../src/loop/skill_canary.js";
import { SkillEvaluator } from "../src/loop/skill_evaluator.js";
import type { DistilledSkill } from "../src/loop/skill_distiller.js";
import type { ExecutionOracle, SkillCase } from "../src/loop/skill_validator.js";
import { BoundedCrossFamilyCriticism } from "../src/learning/cross_family_criticism.js";
import { composeKeep } from "../src/compose.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const candidate: DistilledSkill = {
  format: "keep.skill/v1",
  requiredAuthority: ["workspace:write"],
  id: "skill:held-out",
  name: "held-out skill",
  description: "candidate under evaluation",
  relevanceKey: "bugfix",
  envelope: { preconditions: ["bugfix"], steps: [{ action: "edit", targetPattern: "{file}" }], postconditions: ["tests pass"], declaredEffects: ["local edit"] },
  provenance: ["solve-1"],
  confidence: "corroborated",
};

const cases: readonly SkillCase[] = [
  { id: "a", input: "one" },
  { id: "b", input: "two" },
  { id: "c", input: "three" },
  { id: "d", input: "four" },
];

function oracle(baseline: readonly string[], withSkill: readonly string[]): ExecutionOracle {
  return {
    runBaseline: (c) => baseline.includes(c.id),
    runWithSkill: (_skill, c) => withSkill.includes(c.id),
  };
}

function criticism(verdict: "clear" | "revise" = "clear", calls?: string[]): BoundedCrossFamilyCriticism {
  return new BoundedCrossFamilyCriticism("builder-family", {
    criticize: (request) => {
      calls?.push(request.proposalId);
      return { reviewerFamily: "independent-family", verdict, findings: verdict === "clear" ? [] : ["hidden authority expansion"] };
    },
  });
}

test("retains only a candidate that measurably beats the same held-out no-skill baseline", () => {
  const canary = new SkillCanary();
  const result = new SkillEvaluator(oracle(["a", "b"], ["a", "b", "c"]), canary, criticism()).evaluate(candidate, cases);

  assert.equal(result.verdict, "retained");
  assert.deepEqual(result.baseline, { passed: 2, total: 4, rate: 0.5 });
  assert.deepEqual(result.withSkill, { passed: 3, total: 4, rate: 0.75 });
  assert.equal(result.delta, 0.25);
  assert.equal(canary.state(candidate.id), "canary", "measured improvement is retained as a reversible canary");
});

test("high-impact skill is held after one adverse cross-family criticism and never enters canary", () => {
  const canary = new SkillCanary();
  const calls: string[] = [];
  const result = new SkillEvaluator(oracle(["a"], ["a", "b", "c"]), canary, criticism("revise", calls)).evaluate(candidate, cases);
  assert.equal(result.verdict, "held-for-criticism");
  assert.deepEqual(calls, [candidate.id]);
  assert.equal(canary.state(candidate.id), undefined);
});

test("SKILL-05: composed high-impact evaluation makes one different-family request after execution success", () => {
  let calls = 0;
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-skill-critic-")),
    skillOracle: oracle(["a"], ["a", "b", "c"]),
    skillCriticism: { builderFamily: "builder-family", critic: { criticize: (request) => {
      calls++;
      assert.equal(request.execution.passed, true);
      assert.equal(request.execution.candidateScore > request.execution.baselineScore, true);
      return { reviewerFamily: "different-family", verdict: "clear", findings: [] };
    } } },
  });
  const result = app.skillEvaluator!.evaluate(candidate, cases);
  assert.equal(result.verdict, "retained");
  assert.equal(result.criticism?.status, "cleared");
  assert.equal(calls, 1);
});

test("SKILL-06: retained skill enters retrieval, notifies, and a later measured regression demotes it", async () => {
  const notices: import("../src/loop/skill_canary.js").CanaryNotice[] = [];
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-skill-canary-wire-")), anchorThreshold: 1,
    skillOracle: oracle(["a"], ["a", "b", "c"]),
    skillCriticism: { builderFamily: "builder", critic: { criticize: () => ({ reviewerFamily: "critic", verdict: "clear", findings: [] }) } },
    skillCanaryNotifier: { notify: (notice) => notices.push(notice) },
  });
  assert.equal(app.skillEvaluator!.evaluate(candidate, cases).verdict, "retained");
  assert.equal(app.skillCanary.state(candidate.id), "canary");
  assert.equal(app.skillRetrieval.retrieve({ taskShape: "bugfix" })[0]?.skill.id, candidate.id);
  assert.ok(notices.some((notice) => notice.skillId === candidate.id && /promoted provisionally/.test(notice.message)));
  await app.selfImprovementBus.publish({ solveId: "later", taskShape: "bugfix", testsPassed: false, mergeVerdict: "pending", activeArtifacts: [candidate.id], timestamp: 1 });
  assert.equal(app.skillCanary.state(candidate.id), "rolled-back");
  assert.equal(app.skillRetrieval.retrieve({ taskShape: "bugfix" }).length, 0, "demotion immediately removes the skill from later retrieval");
  assert.ok(notices.some((notice) => notice.skillId === candidate.id && notice.tier === "ticket"));
});

test("SKILL-07: a retained skill and its measured reuse resume through composeKeep without a duplicate promotion", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "keep-skill-restart-wire-"));
  const firstNotices: import("../src/loop/skill_canary.js").CanaryNotice[] = [];
  const first = composeKeep({
    dataDir,
    skillOracle: oracle(["a"], ["a", "b", "c"]),
    skillCriticism: { builderFamily: "builder", critic: { criticize: () => ({ reviewerFamily: "critic", verdict: "clear", findings: [] }) } },
    skillCanaryNotifier: { notify: (notice) => firstNotices.push(notice) },
  });
  assert.equal(first.skillEvaluator!.evaluate(candidate, cases).verdict, "retained");
  assert.equal(first.managedSkillRegistry.activePackages().some((pkg) => pkg.skill.id === candidate.id), true);
  assert.equal(firstNotices.filter((notice) => /promoted provisionally/.test(notice.message)).length, 1);
  const equivalent = { ...candidate, id: "skill:equivalent", name: "equivalent", provenance: ["solve-2"] };
  assert.equal(first.skillEvaluator!.evaluate(equivalent, cases).verdict, "retained");
  assert.equal(first.managedSkillRegistry.lifecycle(equivalent.id)?.retired?.replacementId, candidate.id);
  assert.equal(first.skillCanary.state(equivalent.id), "rolled-back", "a merged duplicate cannot remain live outside the registry");
  assert.deepEqual(first.skillRetrieval.retrieve({ taskShape: "bugfix" }).map((item) => item.skill.id), [candidate.id]);
  const dormant = { ...candidate, id: "skill:dormant", relevanceKey: "dormant", provenance: ["solve-old"] };
  first.managedSkillRegistry.trackValidated(dormant, "local-solve", 0);
  await first.selfImprovementBus.publish({
    solveId: "maintenance-clock", taskShape: "other", testsPassed: true, mergeVerdict: "pending",
    activeArtifacts: [], timestamp: 90 * 24 * 60 * 60 * 1000,
  });
  assert.equal(first.managedSkillRegistry.lifecycle(dormant.id)?.retired?.reason, "unused", "real outcomes drive bounded retirement without a daemon");

  const restartNotices: import("../src/loop/skill_canary.js").CanaryNotice[] = [];
  const restarted = composeKeep({ dataDir, skillCanaryNotifier: { notify: (notice) => restartNotices.push(notice) } });
  assert.equal(restarted.skillCanary.state(candidate.id), "canary");
  assert.equal(restarted.skillRetrieval.retrieve({ taskShape: "bugfix" })[0]?.skill.id, candidate.id);
  assert.equal(restartNotices.length, 0, "restoring admission is not reported as a new promotion");

  await restarted.selfImprovementBus.publish({
    solveId: "post-restart", taskShape: "bugfix", testsPassed: true, mergeVerdict: "merged",
    activeArtifacts: [candidate.id], timestamp: 50,
  });
  assert.deepEqual(restarted.managedSkillRegistry.lifecycle(candidate.id), {
    skillId: candidate.id, uses: 1, reward: 2, lastUsedAt: 50,
  });
});

test("failed execution evidence never invokes or gets rescued by criticism", () => {
  const calls: string[] = [];
  const result = new SkillEvaluator(oracle(["a", "b", "c"], ["a"]), new SkillCanary(), criticism("clear", calls)).evaluate(candidate, cases);
  assert.equal(result.verdict, "rolled-back-degradation");
  assert.deepEqual(calls, []);
});

test("equal performance is not improvement and is not retained", () => {
  const canary = new SkillCanary();
  const result = new SkillEvaluator(oracle(["a", "b"], ["a", "b"]), canary).evaluate(candidate, cases);

  assert.equal(result.verdict, "rejected-no-improvement");
  assert.equal(result.delta, 0);
  assert.equal(canary.state(candidate.id), undefined);
});

test("degradation automatically rolls back an already-live candidate", () => {
  const canary = new SkillCanary();
  canary.goLive(candidate.id);
  const result = new SkillEvaluator(oracle(["a", "b", "c"], ["a"]), canary).evaluate(candidate, cases);

  assert.equal(result.verdict, "rolled-back-degradation");
  assert.equal(result.delta, -0.5);
  assert.equal(canary.state(candidate.id), "rolled-back");
  assert.ok(!canary.liveSkills().includes(candidate.id));
});

test("an empty held-out set cannot retain a candidate", () => {
  const canary = new SkillCanary();
  const result = new SkillEvaluator(oracle([], []), canary).evaluate(candidate, []);

  assert.equal(result.verdict, "rejected-no-cases");
  assert.equal(canary.state(candidate.id), undefined);
});

test("SKILL-03: both arms receive the identical frozen cases and duplicate denominators are rejected", () => {
  const baselineSeen = new Map<string, SkillCase>();
  const paired: ExecutionOracle = {
    runBaseline: (testCase) => { assert.equal(Object.isFrozen(testCase), true); baselineSeen.set(testCase.id, testCase); return false; },
    runWithSkill: (_skill, testCase) => { assert.equal(testCase, baselineSeen.get(testCase.id), "candidate and baseline share the exact frozen case"); return true; },
  };
  const lowImpact = { ...candidate, requiredAuthority: ["workspace:read"] as const };
  const improved = new SkillEvaluator(paired, new SkillCanary()).evaluate(lowImpact, cases);
  assert.equal(improved.verdict, "retained");
  const duplicate = new SkillEvaluator(oracle([], cases.map((c) => c.id)), new SkillCanary()).evaluate(candidate, [cases[0]!, cases[0]!]);
  assert.equal(duplicate.verdict, "rejected-invalid-cases");
  assert.equal(duplicate.delta, 0);
});

test("SKILL-02: held-out diagnostics measure trigger, compliance, path coverage, and quality impact", () => {
  const evaluator = new SkillEvaluator(oracle([], []), new SkillCanary());
  const diagnosticCases = [
    { id: "relevant-a", input: "fix a bug", shouldTrigger: true, requiredInstructions: ["inspect", "test"], requiredSolutionPath: ["localize", "edit", "validate"] },
    { id: "relevant-b", input: "fix another bug", shouldTrigger: true, requiredInstructions: ["inspect", "test"], requiredSolutionPath: ["localize", "edit", "validate"] },
    { id: "irrelevant", input: "write a poem", shouldTrigger: false, requiredInstructions: [], requiredSolutionPath: [] },
  ] as const;
  const profile = evaluator.diagnose(candidate, diagnosticCases, {
    run: (skill, testCase) => {
      if (!skill) return { triggered: false, followedInstructions: [], solutionPath: [], quality: 0.5 };
      if (testCase.id === "relevant-a") return { triggered: true, followedInstructions: ["inspect", "test"], solutionPath: ["localize", "edit", "validate"], quality: 0.9 };
      if (testCase.id === "relevant-b") return { triggered: true, followedInstructions: ["inspect"], solutionPath: ["localize", "validate"], quality: 0.7 };
      return { triggered: true, followedInstructions: [], solutionPath: [], quality: 0.4 };
    },
  });
  assert.equal(profile.cases, 3);
  assert.equal(profile.triggerPrecision, 2 / 3);
  assert.equal(profile.instructionCompliance, 3 / 4);
  assert.equal(profile.solutionPathCoverage, 5 / 6);
  assert.ok(Math.abs(profile.candidateQuality - 2 / 3) < 1e-12);
  assert.equal(profile.baselineQuality, 0.5);
  assert.ok(Math.abs(profile.qualityImpact - 1 / 6) < 1e-12);
});

test("SKILL-02: diagnostic denominators and quality evidence fail closed without changing canary state", () => {
  const canary = new SkillCanary();
  const evaluator = new SkillEvaluator(oracle([], []), canary);
  const observation = { triggered: false, followedInstructions: [], solutionPath: [], quality: 0.5 };
  assert.throws(() => evaluator.diagnose(candidate, [], { run: () => observation }), /non-empty held-out/);
  const duplicate = { id: "same", input: "x", shouldTrigger: true, requiredInstructions: [], requiredSolutionPath: [] };
  assert.throws(() => evaluator.diagnose(candidate, [duplicate, duplicate], { run: () => observation }), /unique/);
  assert.throws(() => evaluator.diagnose(candidate, [{ ...duplicate, id: "one" }], { run: () => ({ ...observation, quality: 2 }) }), /within \[0,1\]/);
  assert.equal(canary.state(candidate.id), undefined, "diagnostics never promote or roll back");
});
