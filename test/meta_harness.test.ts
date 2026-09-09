import { test } from "node:test";
import assert from "node:assert/strict";
import { MetaHarness, type EvalAnchor, type ImprovementProposal } from "../src/meta/meta_harness.js";
import { GovernanceLedger } from "../src/governance/decision_record.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function newSpine(): Spine { return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-meta-"))), new InProcessLock(), new SchemaRegistry()); }

// A frozen anchor: score = a lookup by version name; some versions "weaken the floor".
function anchor(scores: Record<string, number>, weakens: Set<string> = new Set()): EvalAnchor {
  return {
    cases: [{ id: "c1", input: "i", expected: "e" }, { id: "c2", input: "i2", expected: "e2" }],
    score: (v) => scores[v] ?? 0,
    weakensSafetyFloor: (v) => weakens.has(v),
  };
}
const prop = (o: Partial<ImprovementProposal>): ImprovementProposal =>
  ({ component: "prompt", fromVersion: "v1", toVersion: "v2", rationale: "reflected on failures", ...o });

test("INVARIANT 1: an improvement that BEATS the frozen anchor (and not the floor) is ACCEPTED + versioned", () => {
  const m = new MetaHarness({ anchor: anchor({ v1: 0.6, v2: 0.8 }) });
  m.register("prompt", "v1");
  const out = m.propose(prop({ toVersion: "v2" }));
  assert.equal(out.decision, "accepted");
  assert.equal(m.liveVersion("prompt"), "v2", "the improved version is now live");
});

test("INVARIANT 1: an improvement that does NOT beat the anchor is REJECTED (no graduation by assertion)", () => {
  const m = new MetaHarness({ anchor: anchor({ v1: 0.8, v2: 0.7 }) });
  m.register("prompt", "v1");
  const out = m.propose(prop({ toVersion: "v2" }));
  assert.equal(out.decision, "rejected-no-gain");
  assert.equal(m.liveVersion("prompt"), "v1", "live version unchanged");
});

test("INVARIANT 2: an improvement TARGETING THE SAFETY FLOOR is REJECTED (frozen allowlist)", () => {
  const m = new MetaHarness({ anchor: anchor({}) });
  for (const floor of ["consequence-floor", "patch-verifier", "isolation-tier", "eval-anchor", "spine"]) {
    const out = m.propose(prop({ component: floor }));
    assert.equal(out.decision, "rejected-not-improvable", `${floor} must be frozen`);
  }
});

test("INVARIANT 2: a candidate that WEAKENS the safety floor is REJECTED regardless of score", () => {
  const m = new MetaHarness({ anchor: anchor({ v1: 0.5, vBad: 0.99 }, new Set(["vBad"])) });
  m.register("prompt", "v1");
  const out = m.propose(prop({ toVersion: "vBad" }));
  assert.equal(out.decision, "rejected-floor", "high score does not buy a safety regression");
});

test("INVARIANT 1: ANCHOR-TAMPER is detected + rejected (can't grade its own homework)", () => {
  const a = anchor({ v1: 0.5, v2: 0.9 });
  const m = new MetaHarness({ anchor: a });
  m.register("prompt", "v1");
  // Tamper: mutate the held-out cases after construction (simulating self-editing the judge).
  (a as unknown as { cases: unknown[] }).cases = [{ id: "x", input: "easy", expected: "easy" }];
  const out = m.propose(prop({ toVersion: "v2" }));
  assert.equal(out.decision, "rejected-anchor-tamper");
});

test("INVARIANT 4: a regression after graduation HALTS + ROLLS BACK to the safe baseline (audited)", async () => {
  const spine = newSpine(); const gov = new GovernanceLedger(spine);
  // v2 graduates (0.8 > 0.6); then live outcomes reveal v2 is actually 0.4 → rollback to v1.
  const scores: Record<string, number> = { v1: 0.6, v2: 0.8 };
  const m = new MetaHarness({ anchor: anchor(scores), spine, governance: gov });
  m.register("prompt", "v1");
  assert.equal(m.propose(prop({ toVersion: "v2" })).decision, "accepted");
  scores.v2 = 0.4; // the world answered back: v2 regressed
  const r = m.checkRegression("prompt");
  assert.equal(r.rolledBack, true);
  assert.equal(m.liveVersion("prompt"), "v1", "rolled back to safe baseline");
  await spine.seal();
  assert.ok(gov.readTrail().some((x) => x.action === "meta.rollback"), "rollback audited");
});

test("INVARIANT 3: every proposal is recorded to the spine (compile-time, reviewable artifact)", async () => {
  const spine = newSpine();
  const m = new MetaHarness({ anchor: anchor({ v1: 0.5, v2: 0.9 }), spine });
  m.register("prompt", "v1");
  m.propose(prop({ toVersion: "v2" }));
  await spine.seal();
  assert.ok(spine.replay().some((e: { payload?: { event?: string } }) => e.payload?.event === "self_improvement"), "self-improvement recorded");
});

test("N=1: a single held-out anchor gates graduation (no fleet of runs needed)", () => {
  const m = new MetaHarness({ anchor: anchor({ v1: 0.5, v2: 0.7 }) });
  m.register("prompt", "v1");
  // A solo operator with just the held-out corpus can still safely graduate an improvement.
  assert.equal(m.propose(prop({ toVersion: "v2" })).decision, "accepted");
});

test("minGain guards against noise (a tiny improvement below threshold is rejected)", () => {
  const m = new MetaHarness({ anchor: anchor({ v1: 0.700, v2: 0.701 }), minGain: 0.05 });
  m.register("prompt", "v1");
  assert.equal(m.propose(prop({ toVersion: "v2" })).decision, "rejected-no-gain");
});

import { composeKeep } from "../src/compose.js";

test("WIRED: composeKeep exposes a governed MetaHarness when a held-out anchor is provided (safe default: off)", () => {
  const a = anchor({ v1: 0.6, v2: 0.8 });
  const withAnchor = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-meta-c-")), evalAnchor: a });
  assert.ok(withAnchor.metaHarness, "meta-harness present when an anchor is supplied");
  // Safe default: no anchor → no self-improvement wired at all.
  const without = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-meta-c2-")) });
  assert.equal(without.metaHarness, undefined, "no self-improvement without a held-out anchor (safe default)");
});

test("BROADENED SCOPE: memory-lesson and tool-skill are improvable axes (not just prompts)", () => {
  const m = new MetaHarness({ anchor: anchor({ mem1: 0.5, mem2: 0.7, tool1: 0.4, tool2: 0.6 }) });
  m.register("memory-lesson", "mem1");
  m.register("tool-skill", "tool1");
  assert.equal(m.propose(prop({ component: "memory-lesson", fromVersion: "mem1", toVersion: "mem2" })).decision, "accepted");
  assert.equal(m.propose(prop({ component: "tool-skill", fromVersion: "tool1", toVersion: "tool2" })).decision, "accepted");
});

test("MODEL-ADAPTER: an improvement is IN-SCOPE but must clear the EXTRA gate (provenance/poison/RLVR) BEFORE scoring", () => {
  const m = new MetaHarness({ anchor: anchor({ a1: 0.5, a2: 0.9 }) });
  m.register("model-adapter", "a1");
  // Without an extra gate → rejected (model adapters are the most-gated axis; no ungated weight change).
  const noGate = m.propose(prop({ component: "model-adapter", fromVersion: "a1", toVersion: "a2" }));
  assert.equal(noGate.decision, "rejected-extra-gate");
  // With a FAILING extra gate (e.g. poison screen failed) → rejected even though the score would improve.
  const failGate = m.propose(prop({ component: "model-adapter", fromVersion: "a1", toVersion: "a2", extraGate: () => ({ passed: false, reason: "poison screen: untrusted fraction 0.08 > 0.042" }) }));
  assert.equal(failGate.decision, "rejected-extra-gate");
  assert.match(failGate.reason, /poison/);
});

test("MODEL-ADAPTER: with the extra gate PASSING and a real anchor gain, the adapter is accepted (model-level self-improvement, gated)", () => {
  const m = new MetaHarness({ anchor: anchor({ a1: 0.5, a2: 0.9 }) });
  m.register("model-adapter", "a1");
  const out = m.propose(prop({ component: "model-adapter", fromVersion: "a1", toVersion: "a2", extraGate: () => ({ passed: true, reason: "provenance ok, poison<0.042, RLVR verifiable, sandboxed, authorized" }) }));
  assert.equal(out.decision, "accepted", "model-level improvement IS in scope when fully gated + it beats the anchor");
});

test("MODEL-ADAPTER: even a PASSING extra gate cannot save an adapter that does NOT beat the anchor", () => {
  const m = new MetaHarness({ anchor: anchor({ a1: 0.8, a2: 0.7 }) });
  m.register("model-adapter", "a1");
  const out = m.propose(prop({ component: "model-adapter", fromVersion: "a1", toVersion: "a2", extraGate: () => ({ passed: true, reason: "ok" }) }));
  assert.equal(out.decision, "rejected-no-gain", "the external anchor still governs even for a fully-gated adapter");
});

test("MODEL-ADAPTER: a weight change that weakens the safety floor is rejected BEFORE the extra gate (floor is first)", () => {
  const m = new MetaHarness({ anchor: anchor({ a1: 0.5, aBad: 0.99 }, new Set(["aBad"])) });
  m.register("model-adapter", "a1");
  const out = m.propose(prop({ component: "model-adapter", fromVersion: "a1", toVersion: "aBad", extraGate: () => ({ passed: true, reason: "ok" }) }));
  assert.equal(out.decision, "rejected-floor", "safety floor dominates even a fully-gated high-scoring adapter");
});
