import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { GovernanceLedger } from "../src/governance/decision_record.js";
import { KillSwitch } from "../src/control/killswitch.js";
import type { AuthorizationEnvelope } from "../src/scheduler/authorization_envelope.js";
import { CostModel, type TokenUsage } from "../src/observability/cost_model.js";
import { SafetyRail, type RunResumeGrant, type BreakGlassGrant } from "../src/pipeline/safety_rail.js";

function newSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-rail-")), { fsync: true }), new InProcessLock(), new SchemaRegistry());
}
/** A cost model with real pricing so the budget math runs (not the unpriceable fail-closed path). */
function pricedCostModel(): CostModel {
  const cm = new CostModel();
  cm.registerPricing({ model: "expensive-model", inputPerMillion: 15, outputPerMillion: 75 });
  cm.registerPricing({ model: "m", inputPerMillion: 3, outputPerMillion: 15 });
  cm.registerPricing({ model: "cheap", inputPerMillion: 0.1, outputPerMillion: 0.3 });
  return cm;
}
function newRail(overrides: Partial<Parameters<typeof makeConfig>[0]> = {}) {
  const spine = newSpine();
  const governance = new GovernanceLedger(spine);
  const cfg = makeConfig({ spine, governance, costModel: pricedCostModel(), ...overrides });
  return { rail: new SafetyRail(cfg), spine, governance };
}
function makeConfig(o: { spine: Spine; governance: GovernanceLedger; killSwitch?: KillSwitch; vetPatchFn?: (r: string) => Promise<boolean>; defaultPerRunCapUsd?: number; costModel?: CostModel; clock?: () => number }) {
  return o;
}
const USAGE: TokenUsage = { freshInputTokens: 1000, cachedInputTokens: 0, outputTokens: 500 };

test("INVARIANT: killswitch tripped → pipeline refuses to run (block-killed)", async () => {
  const ks = new KillSwitch(newSpine());
  ks.register({ agentId: "a1", credentialId: "c1", terminate: () => {} });
  ks.kill("a1", "test-policy", "manual-kill");
  const { rail } = newRail({ killSwitch: ks });
  const d = rail.checkKillswitch("a1");
  assert.equal(d.outcome, "block-killed");
});

test("INVARIANT: no envelope → default RESTRICTIVE envelope synthesized (Fork C, not crash, not open)", async () => {
  const { rail, governance } = newRail();
  const d = await rail.authorize("run1", undefined, "proj1");
  assert.equal(d.outcome, "allow");
  assert.match(d.reason, /default-restrictive/);
  // A governance record shows secure-by-default was applied.
  assert.ok(governance.readTrail().some((r) => r.policy.ruleId === "default-restrictive-envelope"));
});

test("INVARIANT: an expired supplied envelope → deny (deny-by-default)", async () => {
  const { rail } = newRail({ clock: () => 1_000_000 });
  const expired: AuthorizationEnvelope = {
    id: "e1", projectId: "p", allowedClasses: ["auto-rag"], allowedTiers: [], dailyCapUsd: 10, perRunCapUsd: 2,
    perCallTokenCeiling: 8000, expiresAt: 500_000, grantedReason: "old",
  };
  const d = await rail.authorize("run1", expired, "p");
  assert.equal(d.outcome, "deny");
});

test("INVARIANT: soft cap → pause-soft with a resumable approval request (Fork B)", async () => {
  // per-run cap $2, soft at 80% = $1.60. Need a call whose cost lands in [$1.60, $2.00).
  // expensive-model output = $75/M. $1.70 ≈ 22,667 output tokens; but per-call token ceiling is 8000,
  // so instead raise the per-run cap low enough that a normal call crosses soft but not hard.
  // per-run cap $0.60 → soft $0.48; a 7000-output expensive call = $0.525 → pause-soft (>$0.48, <$0.60).
  const { rail } = newRail({ defaultPerRunCapUsd: 0.6 });
  await rail.authorize("run1", undefined, "p");
  const d = await rail.guardModelCall("run1", "auto-rag", "frontier", "expensive-model", { freshInputTokens: 0, cachedInputTokens: 0, outputTokens: 7000 });
  assert.equal(d.outcome, "pause-soft", "projected $0.525 is between soft $0.48 and hard $0.60");
  assert.ok(d.approvalRequest, "an approval request is surfaced so the operator can resume");
  assert.equal(d.approvalRequest!.kind, "soft-cap");
});

test("INVARIANT: hard ceiling → pause-hard; a valid RunResumeGrant raises the cap and allows", async () => {
  const { rail } = newRail({ defaultPerRunCapUsd: 0.0001 }); // tiny cap → any call breaches hard
  await rail.authorize("run1", undefined, "p");
  const hard = await rail.guardModelCall("run1", "auto-rag", "frontier", "m", USAGE);
  assert.equal(hard.outcome, "pause-hard");
  // Operator raises the ceiling and resumes.
  const resume: RunResumeGrant = { operatorId: "op", reason: "legit long run", raisedPerRunCapUsd: 100, expiresAt: Date.now() + 60000 };
  const resumed = await rail.guardModelCall("run1", "auto-rag", "frontier", "m", USAGE, resume);
  assert.equal(resumed.outcome, "allow", "resume grant lets the run continue");
});

test("INVARIANT: vetPatch with NO vet function → fail-closed (not cleared)", async () => {
  const { rail } = newRail(); // no vetPatchFn
  const d = await rail.vetPatch("repo");
  assert.equal(d.cleared, false, "absent vetting fails closed to human");
  assert.equal(d.viaBreakGlass, false);
});

test("INVARIANT: vetPatch when the vet function THROWS → fail-closed", async () => {
  const { rail } = newRail({ vetPatchFn: async () => { throw new Error("boom"); } });
  const d = await rail.vetPatch("repo");
  assert.equal(d.cleared, false, "erroring vetting fails closed");
});

test("vetPatch when vetting passes → cleared", async () => {
  const { rail } = newRail({ vetPatchFn: async () => true });
  const d = await rail.vetPatch("repo");
  assert.equal(d.cleared, true);
  assert.equal(d.viaBreakGlass, false);
});

test("INVARIANT: break-glass relaxes the verdict + emits a warned-and-proceeded record (Fork A)", async () => {
  const { rail, governance } = newRail({ vetPatchFn: async () => false }); // vetting would fail
  const grant: BreakGlassGrant = { operatorId: "op", reason: "emergency hotfix", expiresAt: Date.now() + 60000 };
  const d = await rail.vetPatch("repo", grant);
  assert.equal(d.cleared, true, "break-glass relaxes the verdict");
  assert.equal(d.viaBreakGlass, true);
  const rec = governance.readTrail().find((r) => r.policy.ruleId === "break-glass");
  assert.ok(rec, "break-glass is audited");
  assert.equal(rec!.outcome, "warned-and-proceeded", "loud, not silent");
});

test("INVARIANT: an EXPIRED break-glass grant is ignored → fails closed", async () => {
  const { rail } = newRail({ vetPatchFn: async () => false, clock: () => 1_000_000 });
  const expiredGrant: BreakGlassGrant = { operatorId: "op", reason: "late", expiresAt: 500_000 };
  const d = await rail.vetPatch("repo", expiredGrant);
  assert.equal(d.cleared, false, "expired break-glass does not relax");
});

test("INVARIANT: every gating decision produces a GovernanceRecord bound to the tamper-evident spine", async () => {
  const { rail, governance, spine } = newRail({ vetPatchFn: async () => true, defaultPerRunCapUsd: 0.6 });
  await rail.authorize("run1", undefined, "p");                                        // authorize record
  const paused = await rail.guardModelCall("run1", "auto-rag", "frontier", "expensive-model", { freshInputTokens: 0, cachedInputTokens: 0, outputTokens: 7000 }); // soft-pause record
  assert.equal(paused.outcome, "pause-soft");
  await rail.vetPatch("repo");                                                    // vetting record
  await spine.seal();
  const trail = governance.readTrail();
  assert.ok(trail.length >= 3, `expected >=3 governance records (authorize + budget-pause + vet), got ${trail.length}`);
  // Each record is bound to a spine event id (provenance) and the chain verifies (tamper-evident).
  assert.ok(trail.every((r) => typeof r.spineEventId === "string" && r.spineEventId.length > 0));
  assert.equal(spine.verify().ok, true, "tamper-evident chain intact");
  // The specific gating actions are present.
  const actions = new Set(trail.map((r) => r.action));
  assert.ok(actions.has("authorize") && actions.has("budget.soft") && actions.has("vet.patch"));
});

test("INVARIANT: an unpriceable model → fail-closed pause (never throws, never silently allows)", async () => {
  const { rail } = newRail(); // priced model set does NOT include "mystery-model"
  await rail.authorize("run1", undefined, "p");
  const d = await rail.guardModelCall("run1", "auto-rag", "frontier", "mystery-model", USAGE);
  assert.equal(d.outcome, "pause-soft", "cannot price → pause for approval, not crash");
  assert.ok(d.approvalRequest);
});
