import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";

import { brainFromKey, localBrain, type BrainDescriptor } from "../src/frontdoor/brain_port.js";
import { RoleRouter, isPlanningRole, type TaskRole } from "../src/frontdoor/role_router.js";
import { recordBuildOutcome, readBuildOutcomes, outcomesWithDegradedPlanning } from "../src/learning/corpus_curation.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-f18-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

const frontier: BrainDescriptor = brainFromKey("sk-ant-frontierkey1234567890", { baseURL: "https://api.anthropic.com/v1" });
const cheap: BrainDescriptor = brainFromKey("sk-cheapkey1234567890", { baseURL: "https://cheap.example/v1" });

function mixedRouter(pref?: Parameters<typeof RoleRouter.fromBrains>[1]) {
  return RoleRouter.fromBrains(
    [
      { brain: frontier, signals: { contextWindow: 1_000_000, costPerMTokUSD: 5 } }, // rich
      { brain: cheap, signals: { costPerMTokUSD: 0.3 } }, // lean
    ],
    pref,
  );
}

// --- Planning uses the best brain; mechanical economizes ---

test("planning roles route to the FRONTIER brain when one is available", () => {
  const r = mixedRouter();
  for (const role of ["plan_decompose", "sequence_work", "architecture_decision"] as TaskRole[]) {
    const res = r.route(role);
    assert.equal(res.brain.baseURL, frontier.baseURL, `${role} must use the frontier brain`);
    assert.equal(res.record.degraded, false); // a rich brain is available
  }
});

test("mechanical roles route to the CHEAP brain (correct economizing, not degradation)", () => {
  const r = mixedRouter({ costPreference: "balanced" });
  for (const role of ["converse", "extract", "classify", "format"] as TaskRole[]) {
    const res = r.route(role);
    assert.equal(res.brain.baseURL, cheap.baseURL, `${role} should economize`);
    assert.equal(res.record.degraded, false); // cheap-for-mechanical is correct, not degraded
  }
});

// --- THE MOAT: learning-loop reasoning uses the best brain ---

test("the learning-loop roles (distill_lesson, reflect_curate) are planning-class", () => {
  assert.equal(isPlanningRole("distill_lesson"), true);
  assert.equal(isPlanningRole("reflect_curate"), true);
});

test("lesson distillation and reflection route to the FRONTIER brain (moat fed by best reasoning)", () => {
  const r = mixedRouter({ costPreference: "balanced" });
  assert.equal(r.route("distill_lesson").brain.baseURL, frontier.baseURL);
  assert.equal(r.route("reflect_curate").brain.baseURL, frontier.baseURL);
});

// --- Degradation is EXPLICIT, never silent ---

test("when only a weak brain exists, planning still runs but is flagged degraded (explicit, not silent)", () => {
  const r = RoleRouter.fromBrains([{ brain: localBrain(), signals: {} }]); // lean only
  const res = r.route("plan_decompose");
  assert.equal(res.record.degraded, true); // explicitly flagged
  assert.ok(/capped by the available model/i.test(res.record.reason));
});

// --- Operator override (from the chat box) ---

test("operator 'cost' preference lets planning use the cheap brain", () => {
  const r = mixedRouter({ costPreference: "cost" });
  assert.equal(r.route("plan_decompose").brain.baseURL, cheap.baseURL);
});

test("operator 'quality' preference uses the best brain even for mechanical work", () => {
  const r = mixedRouter({ costPreference: "quality" });
  assert.equal(r.route("converse").brain.baseURL, frontier.baseURL);
});

test("default preference is quality-first for planning", () => {
  const r = mixedRouter(); // default
  assert.equal(r.route("plan_decompose").brain.baseURL, frontier.baseURL);
});

// --- Provenance flows through the learning loop ---

test("build outcomes carry planning provenance, and degraded ones are findable for re-examination", async () => {
  const spine = newSpine();
  recordBuildOutcome(spine, { buildId: "b1", context: "auth", cleanResolved: true, planningBrain: "Anthropic (Claude)", planningTier: "rich", planningDegraded: false });
  recordBuildOutcome(spine, { buildId: "b2", context: "billing", cleanResolved: true, planningBrain: "the built-in offline model", planningTier: "lean", planningDegraded: true });
  await spine.seal(); // readBuildOutcomes replays SEALED events (Phase 3.5 design) — must seal first
  const outcomes = readBuildOutcomes(spine);
  assert.equal(outcomes.length, 2);
  assert.equal(outcomes.find((o) => o.buildId === "b1")!.planningTier, "rich");
  const degraded = outcomesWithDegradedPlanning(outcomes);
  assert.equal(degraded.length, 1);
  assert.equal(degraded[0]!.buildId, "b2"); // the weak-signal build is surfaced for re-examination
});

test("router requires at least one brain", () => {
  assert.throws(() => new RoleRouter([]));
});
