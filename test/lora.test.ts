import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { RollbackLedger } from "../src/control/rollback.js";

import {
  AdapterRegistry,
  checkEntryGates,
  isVerifiableReward,
  type LoraAdapter,
  type SessionAuthorization,
} from "../src/lora/adapter_tier.js";
import {
  evalGate,
  compositionCheck,
  type EvalHarness,
  type SuiteScore,
  type RefuseThenComplyResult,
} from "../src/lora/eval_gate.js";
import {
  deployAdapter,
  rollbackCanary,
  type DeployRequest,
} from "../src/lora/deploy_orchestrator.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-lora-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

const NOW = 1_000_000;

function goodAdapter(over: Partial<LoraAdapter> = {}): LoraAdapter {
  return {
    id: "ad1", version: 1, targetSignature: "null-deref", rewardKind: "unit-tests",
    provenance: { exampleCount: 1000, untrustedFraction: 0.0, allScreened: true, backdoorProbed: true },
    weightsRef: "sandbox://ad1", status: "candidate", createdTs: NOW,
    ...over,
  };
}
function goodAuth(adapterId = "ad1"): SessionAuthorization {
  return { sessionId: "s1", operator: "lisa", authorizedAdapterId: adapterId, grantedTs: NOW, expiresTs: NOW + 600_000 };
}
function enabledRegistry(spine: Spine): AdapterRegistry {
  const r = new AdapterRegistry(spine);
  r.enableTier("lisa", "power-user opt-in for testing");
  return r;
}

// ── Verifiable-reward helper ────────────────────────────────────────────────

test("isVerifiableReward: only unit-tests/compiler/exact-match/cited-facts are RLVR-eligible", () => {
  assert.equal(isVerifiableReward("unit-tests"), true);
  assert.equal(isVerifiableReward("compiler"), true);
  assert.equal(isVerifiableReward("human-preference"), false);
  assert.equal(isVerifiableReward("model-judge"), false);
});

// ── Entry gates: fail closed ────────────────────────────────────────────────

test("INVARIANT: entry gate fails when the tier is OFF (ships off by default)", () => {
  const spine = newSpine();
  const registry = new AdapterRegistry(spine); // NOT enabled
  const r = checkEntryGates(registry, goodAdapter(), goodAuth(), true, NOW);
  assert.equal(r.passed, false);
  assert.equal(r.gate, "tier-enabled");
});

test("INVARIANT: entry gate fails without per-session authorization", () => {
  const spine = newSpine();
  const registry = enabledRegistry(spine);
  const r = checkEntryGates(registry, goodAdapter(), undefined, true, NOW);
  assert.equal(r.passed, false);
  assert.equal(r.gate, "session-authorization");
});

test("INVARIANT: entry gate fails on authorization for a different adapter", () => {
  const spine = newSpine();
  const registry = enabledRegistry(spine);
  const r = checkEntryGates(registry, goodAdapter(), goodAuth("other-adapter"), true, NOW);
  assert.equal(r.passed, false);
  assert.equal(r.gate, "session-authorization");
});

test("INVARIANT: entry gate fails on expired authorization", () => {
  const spine = newSpine();
  const registry = enabledRegistry(spine);
  const r = checkEntryGates(registry, goodAdapter(), goodAuth(), true, NOW + 700_000); // past expiry
  assert.equal(r.passed, false);
});

test("INVARIANT: entry gate fails when not sandboxed", () => {
  const spine = newSpine();
  const registry = enabledRegistry(spine);
  const r = checkEntryGates(registry, goodAdapter(), goodAuth(), false, NOW);
  assert.equal(r.passed, false);
  assert.equal(r.gate, "sandbox");
});

test("INVARIANT: entry gate fails on a non-verifiable reward", () => {
  const spine = newSpine();
  const registry = enabledRegistry(spine);
  const r = checkEntryGates(registry, goodAdapter({ rewardKind: "model-judge" }), goodAuth(), true, NOW);
  assert.equal(r.passed, false);
  assert.equal(r.gate, "verifiable-reward");
});

test("INVARIANT: entry gate fails on poisoned training data (untrusted fraction > 4.2%)", () => {
  const spine = newSpine();
  const registry = enabledRegistry(spine);
  const r = checkEntryGates(registry, goodAdapter({ provenance: { exampleCount: 1000, untrustedFraction: 0.1, allScreened: true, backdoorProbed: true } }), goodAuth(), true, NOW);
  assert.equal(r.passed, false);
  assert.equal(r.gate, "poison-screen");
});

test("INVARIANT: entry gate fails when no backdoor probe was run", () => {
  const spine = newSpine();
  const registry = enabledRegistry(spine);
  const r = checkEntryGates(registry, goodAdapter({ provenance: { exampleCount: 1000, untrustedFraction: 0, allScreened: true, backdoorProbed: false } }), goodAuth(), true, NOW);
  assert.equal(r.passed, false);
  assert.equal(r.gate, "backdoor-probe");
});

test("entry gate PASSES only when every gate holds", () => {
  const spine = newSpine();
  const registry = enabledRegistry(spine);
  const r = checkEntryGates(registry, goodAdapter(), goodAuth(), true, NOW);
  assert.equal(r.passed, true, r.reason);
});

// ── Eval gate: >5% regression on either suite ───────────────────────────────

function harnessWith(scores: Record<string, SuiteScore>, redTeam: RefuseThenComplyResult | null = { attackSuccessRate: 0, probesRun: 50 }): EvalHarness {
  return {
    evaluate: (ids) => scores[ids.join(",")] ?? scores["*"] ?? null,
    redTeamComposed: () => redTeam,
  };
}

test("INVARIANT: eval gate rejects a >5% SAFETY regression even if capability rises (Shadow Alignment)", async () => {
  const harness = harnessWith({
    "": { capability: 0.8, safety: 0.95 },        // baseline (no active adapters)
    "ad1": { capability: 0.9, safety: 0.85 },     // candidate: cap UP, safety DOWN 10%
  });
  const r = await evalGate(harness, [], goodAdapter());
  assert.equal(r.passed, false, "safety regression rejected despite capability gain");
  assert.match(r.reason, /safety regressed/);
});

test("INVARIANT: eval gate rejects a >5% CAPABILITY regression (over-specialization/forgetting)", async () => {
  const harness = harnessWith({
    "": { capability: 0.9, safety: 0.95 },
    "ad1": { capability: 0.8, safety: 0.95 }, // cap down 10%
  });
  const r = await evalGate(harness, [], goodAdapter());
  assert.equal(r.passed, false);
  assert.match(r.reason, /capability regressed/);
});

test("INVARIANT: eval gate fails closed when the harness is unavailable", async () => {
  const harness: EvalHarness = { evaluate: () => null, redTeamComposed: () => null };
  const r = await evalGate(harness, [], goodAdapter());
  assert.equal(r.passed, false);
  assert.match(r.reason, /unavailable|fail closed/);
});

test("eval gate passes when neither suite regresses beyond 5%", async () => {
  const harness = harnessWith({
    "": { capability: 0.8, safety: 0.95 },
    "ad1": { capability: 0.83, safety: 0.94 }, // cap up, safety -1% (within tolerance)
  });
  const r = await evalGate(harness, [], goodAdapter());
  assert.equal(r.passed, true, r.reason);
});

// ── Composition check: colluding-LoRA defense ───────────────────────────────

test("INVARIANT: composition check REJECTS when refuse-then-comply succeeds in composition (CoLoRA)", async () => {
  const spine = newSpine();
  const harness = harnessWith({ "*": { capability: 0.9, safety: 0.95 } }, { attackSuccessRate: 0.3, probesRun: 50 });
  const r = await compositionCheck(harness, spine, ["existing"], goodAdapter());
  assert.equal(r.passed, false);
  assert.match(r.reason, /refuse-then-comply|composed/);
});

test("INVARIANT: composition check FAILS CLOSED when the harness can't score the composition", async () => {
  const spine = newSpine();
  const harness: EvalHarness = { evaluate: () => ({ capability: 0.9, safety: 0.95 }), redTeamComposed: () => null };
  const r = await compositionCheck(harness, spine, ["existing"], goodAdapter());
  assert.equal(r.passed, false, "unverifiable composition = reject");
  assert.match(r.reason, /unverifiable|insufficient/);
});

test("INVARIANT: composition check rejects when composed safety is below the floor", async () => {
  const spine = newSpine();
  const harness = harnessWith({ "*": { capability: 0.9, safety: 0.5 } }, { attackSuccessRate: 0, probesRun: 50 });
  const r = await compositionCheck(harness, spine, ["existing"], goodAdapter(), { minComposedSafety: 0.9 });
  assert.equal(r.passed, false);
});

test("composition check clears a genuinely-safe composition", async () => {
  const spine = newSpine();
  const harness = harnessWith({ "*": { capability: 0.9, safety: 0.96 } }, { attackSuccessRate: 0, probesRun: 50 });
  const r = await compositionCheck(harness, spine, ["existing"], goodAdapter());
  assert.equal(r.passed, true, r.reason);
});

// ── Deploy orchestrator: ordered chain + canary + rollback ──────────────────

function deployDeps(spine: Spine, harness: EvalHarness, undos: string[]) {
  const registry = enabledRegistry(spine);
  const rollback = new RollbackLedger(spine);
  return {
    registry, harness, rollback, spine,
    canaryDeploy: async (a: LoraAdapter) => ({ undo: async () => { undos.push(a.id); } }),
  };
}

function goodDeployReq(): DeployRequest {
  return { adapter: goodAdapter(), auth: goodAuth(), sandboxed: true, replay: { replayFraction: 0.15, attested: true } };
}

test("INVARIANT: deploy rejects at the FIRST failing gate (ordered, fail-closed)", async () => {
  const spine = newSpine();
  const harness = harnessWith({ "*": { capability: 0.9, safety: 0.95 } });
  const undos: string[] = [];
  const deps = deployDeps(spine, harness, undos);
  // unsandboxed → must reject at entry, never reach eval/canary
  const req = { ...goodDeployReq(), sandboxed: false };
  const d = await deployAdapter(req, { ...deps, clock: () => NOW });
  assert.equal(d.deployed, false);
  assert.equal(d.stageReached, "rejected");
  assert.match(d.reason, /entry/);
  assert.equal(undos.length, 0, "no canary deployed on a rejected adapter");
});

test("INVARIANT: deploy rejects on insufficient replay buffer (over-specialization defense)", async () => {
  const spine = newSpine();
  const harness = harnessWith({ "*": { capability: 0.9, safety: 0.95 } });
  const deps = deployDeps(spine, harness, []);
  const req = { ...goodDeployReq(), replay: { replayFraction: 0.02, attested: true } };
  const d = await deployAdapter(req, { ...deps, clock: () => NOW });
  assert.equal(d.deployed, false);
  assert.match(d.reason, /replay/);
});

test("INVARIANT: a fully-passing adapter deploys as a CANARY with a one-tap rollback", async () => {
  const spine = newSpine();
  const harness = harnessWith({
    "": { capability: 0.8, safety: 0.95 },
    "ad1": { capability: 0.83, safety: 0.95 },
    "*": { capability: 0.85, safety: 0.96 },
  });
  const undos: string[] = [];
  const deps = deployDeps(spine, harness, undos);
  const d = await deployAdapter(goodDeployReq(), { ...deps, clock: () => NOW });
  assert.equal(d.deployed, true, d.reason);
  assert.equal(d.stageReached, "canary");
  assert.ok(d.canaryRollbackId, "canary rollback id issued");
  assert.equal(deps.registry.get("ad1")!.status, "canary");

  // one-tap rollback
  await rollbackCanary(deps, "ad1");
  assert.equal(undos.length, 1, "real inverse ran on rollback");
  assert.equal(deps.registry.get("ad1")!.status, "rejected");
});

test("INVARIANT: deploy never reaches canary if composition fails (colluding-LoRA blocks it)", async () => {
  const spine = newSpine();
  const harness = harnessWith(
    { "": { capability: 0.8, safety: 0.95 }, "ad1": { capability: 0.83, safety: 0.95 }, "*": { capability: 0.85, safety: 0.96 } },
    { attackSuccessRate: 0.4, probesRun: 50 }, // composition red-team succeeds → reject
  );
  const undos: string[] = [];
  const deps = deployDeps(spine, harness, undos);
  const d = await deployAdapter(goodDeployReq(), { ...deps, clock: () => NOW });
  assert.equal(d.deployed, false);
  assert.equal(d.stageReached, "rejected");
  assert.match(d.reason, /composition/);
  assert.equal(undos.length, 0, "no canary when composition fails");
});

test("INVARIANT: a failed sandbox canary backend is a rejection, not a deployment claim", async () => {
  const spine = newSpine();
  const harness = harnessWith({ "": { capability: 0.8, safety: 0.95 }, "ad1": { capability: 0.83, safety: 0.96 } });
  const deps = deployDeps(spine, harness, []);
  const d = await deployAdapter(goodDeployReq(), { ...deps, clock: () => NOW, canaryDeploy: async () => { throw new Error("sandbox runtime unavailable"); } });
  assert.equal(d.deployed, false);
  assert.match(d.reason, /canary deployment failed.*sandbox runtime unavailable/);
  assert.equal(deps.registry.get("ad1")?.status, "rejected");
});
