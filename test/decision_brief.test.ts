import { test } from "node:test";
import assert from "node:assert/strict";
import { buildDecisionBrief, renderBrief, type BriefInputs } from "../src/pipeline/decision_brief.js";
import type { ConsequenceVerdict } from "../src/pipeline/plan_consequences.js";
import type { TrajectoryDrift } from "../src/pipeline/trajectory_checkpoint.js";

const consequences = (effects: ConsequenceVerdict["effects"], decision: ConsequenceVerdict["decision"] = "escalate"): ConsequenceVerdict =>
  ({ decision, cleared: decision === "pass", effects, checks: [], reason: "test reason" });

test("INVARIANT: the brief is NEUTRAL — no persuasive language", () => {
  const brief = buildDecisionBrief({
    issueText: "fix the login check", editFiles: ["src/auth/login.ts"],
    consequences: consequences([{ cls: "auth-access-control", blast: "high", reversible: true, evidence: "e" }]),
  });
  const text = renderBrief(brief).toLowerCase();
  for (const banned of ["safe", "looks good", "recommend approving", "should be fine", "no concerns", "trust", "confident"]) {
    assert.ok(!text.includes(banned), `brief must not contain persuasive term "${banned}"`);
  }
});

test("INVARIANT: the brief presents facts to verify + ONE verification question", () => {
  const brief = buildDecisionBrief({ issueText: "x", editFiles: ["src/a.ts", "src/b.ts"] });
  assert.ok(brief.facts.length >= 3, "presents multiple facts to acknowledge");
  assert.ok(brief.verifyThis.trim().endsWith("?"), "the verify item is a question, not a claim");
});

test("INVARIANT: a drift brief names the UNEXPECTED area in the verify question", () => {
  const traj: TrajectoryDrift = { drifted: true, decision: "escalate", newClasses: ["auth-access-control"], patchEffects: [], reason: "drift" };
  const brief = buildDecisionBrief({ issueText: "fix a typo", editFiles: ["src/x.ts"], trajectory: traj });
  assert.match(brief.verifyThis, /authentication|access control/i);
  assert.match(brief.verifyThis, /did not call for|intended/i);
});

test("INVARIANT: reversibility is reported factually", () => {
  const irr = buildDecisionBrief({ issueText: "x", editFiles: ["m.sql"], consequences: consequences([{ cls: "db-schema", blast: "high", reversible: false, evidence: "e" }]) });
  assert.equal(irr.reversible, false);
  assert.ok(irr.facts.some((f) => f.label === "Reversible" && /NO/.test(f.value)));
});

test("the brief states WHY it routed (factually, from the verdicts)", () => {
  const brief = buildDecisionBrief({
    issueText: "x", editFiles: ["src/x.ts"],
    consequences: consequences([{ cls: "auth-access-control", blast: "high", reversible: true, evidence: "e" }], "escalate"),
  });
  assert.ok(brief.routedBecause.length > 0);
  assert.ok(brief.routedBecause.join(" ").length > 0);
});

test("renderBrief produces the challenge-and-response format", () => {
  const brief = buildDecisionBrief({ issueText: "x", editFiles: ["src/x.ts"] });
  const text = renderBrief(brief);
  assert.match(text, /What changes:/);
  assert.match(text, /Please confirm each:/);
  assert.match(text, /Before approving, verify:/);
});
