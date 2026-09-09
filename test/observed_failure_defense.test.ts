import { test } from "node:test";
import assert from "node:assert/strict";
import { ObservedFailureDefenseRegistry, type DefenseCandidate, type FailureObservation } from "../src/resilience/observed_failure_defense.js";

const observation: FailureObservation = {
  id: "obs-1", source: "competitor", mechanism: "untrusted-preview-fetch",
  evidence: ["reproducer:preview-request-17", "incident:vendor-2026-08"], observedAtMs: 900,
};

function candidate(overrides: Partial<DefenseCandidate> = {}): DefenseCandidate {
  return {
    id: "defense-1", observationId: "obs-1", mechanism: "untrusted-preview-fetch",
    protectedOperations: ["preview.fetch"], expiresAtMs: 1_500,
    rule: { field: "untrusted", operator: "equals", value: true, effect: "deny", reason: "untrusted preview denied" },
    failureProbe: { id: "reproduce-ssrf", run: (active) => active ? !active({ untrusted: true }).allowed : false },
    collateralProbes: [{ id: "public-preview", run: (active) => active?.({ untrusted: false }).allowed ?? true }],
    ...overrides,
  };
}

test("E4 converts a reproduced failure into a narrow expiring product defense", () => {
  let now = 1_000;
  const registry = new ObservedFailureDefenseRegistry({ nowMs: () => now, maxLifetimeMs: 1_000 });
  const result = registry.admit(observation, candidate());
  assert.equal(result.admitted, true);
  assert.equal(registry.protects("defense-1", "preview.fetch"), true);
  assert.equal(registry.protects("defense-1", "provider.call"), false, "defense cannot spread beyond its exact operation");
  assert.deepEqual(registry.list()[0]?.rule, candidate().rule, "operators can inspect the exact admitted restriction");
  assert.equal(Object.isFrozen(registry.list()[0]?.rule), true);
  assert.equal(registry.evaluate("preview.fetch", { untrusted: true }).allowed, false, "the admitted guard is load-bearing");
  assert.equal(registry.evaluate("preview.render", { untrusted: true }).allowed, true, "a sibling operation is untouched");
  now = 1_500;
  assert.deepEqual(registry.list(), [], "expired defenses disappear without a recurring research/audit job");
});

test("E4 rejects anecdotes, unreproduced fixes, regressions, and broad permanent controls", () => {
  const make = () => new ObservedFailureDefenseRegistry({ nowMs: () => 1_000, maxLifetimeMs: 1_000 });
  assert.match((make().admit({ ...observation, evidence: [] }, candidate()) as { reason: string }).reason, /evidence/);
  assert.match((make().admit(observation, candidate({ failureProbe: { id: "no-failure", run: () => true } })) as { reason: string }).reason, /did not reproduce/);
  assert.match((make().admit(observation, candidate({ collateralProbes: [{ id: "regression", run: (active) => active === undefined }] })) as { reason: string }).reason, /preserve safe behavior/);
  assert.match((make().admit(observation, candidate({ protectedOperations: ["*" ] })) as { reason: string }).reason, /exact tokens/);
  assert.match((make().admit(observation, candidate({ expiresAtMs: 2_001 })) as { reason: string }).reason, /bounded lifetime/);
});

test("E4 malformed rules cannot enter runtime and expiry removes the restriction", () => {
  let now = 1_000;
  const registry = new ObservedFailureDefenseRegistry({ nowMs: () => now, maxLifetimeMs: 1_000 });
  assert.match((registry.admit(observation, candidate({ rule: { field: "*", operator: "equals", value: true, effect: "deny", reason: "invalid" } })) as { reason: string }).reason, /canonical token/);
  assert.equal(registry.admit(observation, candidate()).admitted, true);
  assert.equal(registry.evaluate("preview.fetch", { untrusted: true }).allowed, false);
  now = 1_500;
  assert.deepEqual(registry.evaluate("preview.fetch", { untrusted: true }), { allowed: true, appliedDefenseIds: [] });
});

test("E4 caps the number of active defenses", () => {
  const registry = new ObservedFailureDefenseRegistry({ nowMs: () => 1_000, maxActiveDefenses: 1 });
  assert.equal(registry.admit(observation, candidate()).admitted, true);
  const secondObservation = { ...observation, id: "obs-2" };
  const second = registry.admit(secondObservation, candidate({ id: "defense-2", observationId: "obs-2" }));
  assert.deepEqual(second, { admitted: false, reason: "active defense capacity reached" });
});
