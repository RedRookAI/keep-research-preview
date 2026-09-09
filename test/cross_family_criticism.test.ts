import { test } from "node:test";
import assert from "node:assert/strict";
import { BoundedCrossFamilyCriticism } from "../src/learning/cross_family_criticism.js";

const proposal = {
  proposalId: "adapter:v2",
  proposalKind: "self-modification" as const,
  summary: "change routing adapter",
  execution: { baselineScore: 0.6, candidateScore: 0.8, passed: true },
};

test("an exact high-impact proposal receives only one criticism pass", () => {
  let calls = 0;
  const gate = new BoundedCrossFamilyCriticism("builder", { criticize: () => {
    calls++;
    return { reviewerFamily: "critic", verdict: "clear", findings: [] };
  } });
  assert.equal(gate.assess(proposal, true).status, "cleared");
  assert.equal(gate.assess(proposal, true).status, "held");
  assert.equal(calls, 1);
});

test("same-family review and unavailable review fail closed for high-impact proposals", () => {
  const same = new BoundedCrossFamilyCriticism("family-a", { criticize: () => ({ reviewerFamily: "family-a", verdict: "clear", findings: [] }) });
  assert.equal(same.assess(proposal, true).status, "held");
  assert.equal(new BoundedCrossFamilyCriticism("family-a").assess(proposal, true).status, "held");
});

test("SKILL-05: the request is frozen and a throwing critic is held once without retry", () => {
  let calls = 0;
  const gate = new BoundedCrossFamilyCriticism("builder", { criticize: (request) => {
    calls++;
    assert.deepEqual(Object.keys(request).sort(), ["builderFamily", "execution", "proposalId", "proposalKind", "summary"]);
    assert.equal(Object.isFrozen(request), true);
    assert.equal(Object.isFrozen(request.execution), true);
    throw new Error("reviewer unavailable");
  } });
  const first = gate.assess(proposal, true);
  const second = gate.assess(proposal, true);
  assert.equal(first.status, "held");
  assert.equal(first.reviewCalls, 1);
  assert.equal(second.status, "held");
  assert.equal(second.reviewCalls, 0);
  assert.equal(calls, 1, "a failure never creates recursive reviewer retries");
});
