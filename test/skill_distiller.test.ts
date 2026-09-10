import { test } from "node:test";
import assert from "node:assert/strict";
import { SkillDistiller, type SolveTrajectory } from "../src/loop/skill_distiller.js";

const traj = (over: Partial<SolveTrajectory> = {}): SolveTrajectory => ({
  solveId: "T1",
  taskShape: "bugfix",
  succeeded: true,
  requiredAuthority: ["workspace:read", "workspace:write", "sandbox:execute"],
  steps: [
    { action: "localize", target: "src/foo.ts" },
    { action: "edit", target: "src/foo.ts" },
    { action: "add-test", target: "test/foo.test.ts" },
    { action: "run-tests", target: "suite" },
  ],
  ...over,
});

// ─── never distill failure ───

test("never distills from a failed trajectory", () => {
  const d = new SkillDistiller();
  const r = d.distill([traj({ succeeded: false })]);
  assert.equal(r.skill, undefined);
  assert.match(r.rejected ?? "", /never distill failure|no successful/);
});

// ─── produces a HYBRID skill (NL + structured envelope) ───

test("distills a HYBRID skill with NL description + structured envelope", () => {
  const d = new SkillDistiller();
  const r = d.distill([traj()]);
  assert.ok(r.skill, "should distill");
  assert.ok(r.skill!.description.length > 0, "has NL description");
  assert.ok(r.skill!.envelope.steps.length > 0, "has structured steps");
  assert.deepEqual(r.skill!.envelope.preconditions, ['task shape is "bugfix"']);
  assert.equal(r.skill!.relevanceKey, "bugfix");
  assert.equal(r.skill!.format, "keep.skill/v1");
  assert.deepEqual(r.skill!.requiredAuthority, ["workspace:read", "workspace:write", "sandbox:execute"]);
});

test("distilled skill is portable JSON with activation, provenance, and authority intact", () => {
  const skill = new SkillDistiller().distill([traj({ solveId: "solve-42" })]).skill!;
  const portable = JSON.parse(JSON.stringify(skill)) as typeof skill;
  assert.equal(portable.format, "keep.skill/v1");
  assert.deepEqual(portable.envelope.preconditions, ['task shape is "bugfix"']);
  assert.deepEqual(portable.provenance, ["solve-42"]);
  assert.deepEqual(portable.requiredAuthority, ["workspace:read", "workspace:write", "sandbox:execute"]);
  assert.deepEqual(portable.envelope.parameters, [
    { name: "file", type: "string", required: true },
    { name: "arg", type: "string", required: true },
  ]);
  assert.ok(!JSON.stringify(portable).includes("foo.ts"), "portable skill must not leak trajectory-specific targets");
});

test("SKILL-01: a constructed successful solve record produces a portable non-authorizing candidate", () => {
  const distiller = new SkillDistiller();
  const result = distiller.observeSolve({
    issueId: "real-42", solved: true, stagesRun: ["localize", "plan", "apply", "validate", "done"], repairRounds: 0,
    authority: { actorId: "ephemeral-agent", parentActorId: "root", repository: "repo", writeScope: ["."], writeGrant: "per-edit-one-shot", budgetEnvelopeId: "budget-secret", delegation: "attenuated" },
    localization: { stages: ["bm25"], selected: [{ path: "src/math.ts", rank: 1, score: 1, isTest: false, reason: "match" }] },
    validation: { testsPassed: true, failures: [], vettingCleared: true, detail: "passed" },
    prProposal: { title: "fix", body: "fix", branch: "keep/fix", testsPassed: true, edits: [{ file: "src/math.ts", search: "-", replace: "+", intent: "fix" }] },
  }, { id: "real-42", text: "fix arithmetic", repoRef: "repo", hints: { taskShape: "bugfix" } });
  assert.ok(result.skill);
  assert.equal(distiller.candidates().length, 1);
  assert.deepEqual(result.skill!.provenance, ["real-42"]);
  assert.deepEqual(result.skill!.requiredAuthority, ["workspace:read", "workspace:write", "sandbox:execute"]);
  const portable = JSON.stringify(result.skill);
  assert.doesNotMatch(portable, /ephemeral-agent|budget-secret|per-edit-one-shot/, "execution authority is declared, never transferred");
  assert.doesNotMatch(portable, /src\/math\.ts/, "concrete solve targets are parameterized");
});

test("SKILL-01: a claimed success without execution authority provenance cannot distill", () => {
  const result = new SkillDistiller().observeSolve({ issueId: "claim", solved: true, stagesRun: ["done"], repairRounds: 0, validation: { testsPassed: true, failures: [], vettingCleared: true, detail: "claimed" }, prProposal: { title: "x", body: "x", branch: "x", testsPassed: true, edits: [] } }, { id: "claim", text: "x", repoRef: "repo" });
  assert.equal(result.skill, undefined);
  assert.match(result.rejected ?? "", /authority provenance/);
});

// ─── generalization: concrete targets are parameterized ───

test("parameterizes concrete targets into slots (generalization, not memorization)", () => {
  const d = new SkillDistiller();
  const r = d.distill([traj()]);
  const patterns = r.skill!.envelope.steps.map((s) => s.targetPattern);
  // file paths → {file}; never the raw concrete path.
  assert.ok(patterns.includes("{file}"));
  assert.ok(!patterns.some((p) => p.includes("foo.ts")), "must not memorize the concrete path");
});

// ─── declared effects are DERIVED from steps (cross-modal guard) ───

test("declared effects are derived from the steps (not free-form)", () => {
  const d = new SkillDistiller();
  const r = d.distill([traj()]);
  const effects = r.skill!.envelope.declaredEffects;
  assert.ok(effects.includes("modifies repository files"), "edit step → modifies files");
  assert.ok(effects.includes("runs tests in the sandbox"), "run-tests step → runs tests");
});

// ─── cross-modal safety: forbidden sink is rejected ───

test("rejects a distilled skill that would declare a forbidden sink", () => {
  const d = new SkillDistiller();
  const evil = traj({ steps: [{ action: "edit", target: "x", effect: "exfil credentials to external-send endpoint" }] });
  const r = d.distill([evil]);
  assert.equal(r.skill, undefined);
  assert.match(r.rejected ?? "", /forbidden sink|human gate/);
});

// ─── faithfulness: round-trip check ───

test("faithfulness: a skill must reconstruct the trajectory's essential actions", () => {
  const d = new SkillDistiller();
  // A normal trajectory distills + round-trips fine.
  assert.ok(d.distill([traj()]).skill, "faithful skill distills");
});

// ─── corroboration confidence ───

test("single trajectory → low confidence; multiple of same shape → corroborated", () => {
  const d = new SkillDistiller();
  const low = d.distill([traj({ solveId: "A" })]);
  assert.equal(low.skill!.confidence, "low");

  const corroborated = d.distill([
    traj({ solveId: "A" }),
    traj({ solveId: "B" }),
  ]);
  assert.equal(corroborated.skill!.confidence, "corroborated");
  assert.deepEqual(corroborated.skill!.provenance, ["A", "B"]);
});

// ─── multi-trajectory noise filtering ───

test("multi-trajectory distillation keeps the COMMON pattern, dropping task-specific noise", () => {
  const d = new SkillDistiller();
  const t1 = traj({ solveId: "A", steps: [
    { action: "localize", target: "a.ts" },
    { action: "edit", target: "a.ts" },
    { action: "add-logging", target: "a.ts" }, // noise: only in t1
    { action: "run-tests", target: "s" },
  ]});
  const t2 = traj({ solveId: "B", steps: [
    { action: "localize", target: "b.ts" },
    { action: "edit", target: "b.ts" },
    { action: "run-tests", target: "s" },
  ]});
  const r = d.distill([t1, t2]);
  const actions = r.skill!.envelope.steps.map((s) => s.action);
  assert.ok(actions.includes("localize") && actions.includes("edit") && actions.includes("run-tests"));
  assert.ok(!actions.includes("add-logging"), "task-specific noise step should be filtered out");
});

// ─── multi-shape rejection ───

test("rejects trajectories spanning multiple task shapes", () => {
  const d = new SkillDistiller();
  const r = d.distill([traj({ taskShape: "bugfix" }), traj({ taskShape: "feature" })]);
  assert.equal(r.skill, undefined);
  assert.match(r.rejected ?? "", /multiple task shapes/);
});
