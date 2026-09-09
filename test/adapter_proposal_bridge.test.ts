import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { RollbackLedger } from "../src/control/rollback.js";
import { AdapterProposalBridge } from "../src/lora/adapter_proposal_bridge.js";
import { AdapterRegistry, type LoraAdapter, type SessionAuthorization } from "../src/lora/adapter_tier.js";
import type { EvalHarness } from "../src/lora/eval_gate.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-188-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

function adapter(over: Partial<LoraAdapter> = {}): LoraAdapter {
  return {
    id: "adapter-1", version: 1, targetSignature: "fix-null-deref",
    rewardKind: "unit-tests",
    provenance: { exampleCount: 500, untrustedFraction: 0.0, allScreened: true, backdoorProbed: true },
    weightsRef: "sandbox://weights/1", status: "candidate", createdTs: Date.now(),
    ...over,
  };
}

// A harness whose composed safety + red-team results are configurable.
function harness(composedSafety: number, attackSuccessRate: number): EvalHarness {
  return {
    evaluate: async () => ({ capability: 0.8, safety: composedSafety }),
    redTeamComposed: async () => ({ attackSuccessRate, probesRun: 20 }),
  } as unknown as EvalHarness;
}

function enabledRegistry(spine: Spine): AdapterRegistry {
  const r = new AdapterRegistry(spine);
  r.enableTier("owner", "opt-in rich-tier test");
  return r;
}

const auth: SessionAuthorization = { sessionId: "sess-1", operator: "owner", authorizedAdapterId: "adapter-1", grantedTs: Date.now(), expiresTs: Date.now() + 3_600_000 };
const replay = { replayFraction: 0.15, attested: true } as const;
function makeBridge(spine: Spine, registry: AdapterRegistry, evalHarness: EvalHarness, undos: string[] = []): AdapterProposalBridge {
  return new AdapterProposalBridge({ registry, harness: evalHarness, spine, rollback: new RollbackLedger(spine), canaryDeploy: async (candidate) => ({ undo: async () => { undos.push(candidate.id); } }) });
}

// ─── verifiable-reward-only ───

test("a non-verifiable-reward adapter is rejected (RLVR-only)", async () => {
  const spine = newSpine();
  const bridge = makeBridge(spine, enabledRegistry(spine), harness(0.95, 0.0));
  const d = await bridge.admit({ adapter: adapter({ rewardKind: "model-judge" }), auth, sandboxed: true, replay });
  assert.equal(d.outcome, "rejected-not-verifiable");
});

// ─── entry gate delegate shape + provenance ───

test("entryGateDelegate returns the MetaHarness gate shape and passes for a clean adapter", () => {
  const spine = newSpine();
  const registry = enabledRegistry(spine);
  const a = adapter();
  registry.register(a);
  const bridge = makeBridge(spine, registry, harness(0.95, 0.0));
  const gate = bridge.entryGateDelegate({ adapter: a, auth, sandboxed: true, replay });
  const result = gate();
  assert.equal(typeof result.passed, "boolean");
  assert.equal(typeof result.reason, "string");
});

test("entryGateDelegate blocks a non-verifiable reward before touching the registry", () => {
  const spine = newSpine();
  const bridge = makeBridge(spine, enabledRegistry(spine), harness(0.95, 0.0));
  const gate = bridge.entryGateDelegate({ adapter: adapter({ rewardKind: "human-preference" }), auth, sandboxed: true, replay });
  assert.equal(gate().passed, false);
});

test("admit rejects an adapter whose training data exceeds the poison threshold", async () => {
  const spine = newSpine();
  const registry = enabledRegistry(spine);
  const a = adapter({ provenance: { exampleCount: 500, untrustedFraction: 0.5, allScreened: false, backdoorProbed: false } });
  registry.register(a);
  const bridge = makeBridge(spine, registry, harness(0.95, 0.0));
  const d = await bridge.admit({ adapter: a, auth, sandboxed: true, replay });
  assert.equal(d.outcome, "rejected-entry");
});

// ─── Colluding-LoRA composition defense ───

test("composition eval rejects an adapter that is unsafe WHEN COMPOSED (refuse-then-comply success)", async () => {
  const spine = newSpine();
  const registry = enabledRegistry(spine);
  const a = adapter();
  registry.register(a);
  // Entry clean, but composed red-team finds an attack success → reject (Colluding-LoRA).
  const bridge = makeBridge(spine, registry, harness(0.95, 0.3));
  const d = await bridge.admit({ adapter: a, auth, sandboxed: true, replay });
  assert.equal(d.outcome, "rejected-composition");
  assert.match(d.reason, /refuse-then-comply|composed/);
});

test("composition eval rejects an adapter that drops composed safety below the floor", async () => {
  const spine = newSpine();
  const registry = enabledRegistry(spine);
  const a = adapter();
  registry.register(a);
  const bridge = makeBridge(spine, registry, harness(0.5, 0.0)); // composed safety 0.5 < 0.9
  const d = await bridge.admit({ adapter: a, auth, sandboxed: true, replay });
  assert.equal(d.outcome, "rejected-composition");
});

// ─── clean adapter admits as canary ───

test("a clean adapter clears entry + composition and admits as an instant-rollback canary", async () => {
  const spine = newSpine();
  const registry = enabledRegistry(spine);
  const a = adapter();
  registry.register(a);
  const undos: string[] = [];
  const bridge = makeBridge(spine, registry, harness(0.96, 0.0), undos);
  const d = await bridge.admit({ adapter: a, auth, sandboxed: true, replay });
  assert.equal(d.outcome, "deployed-canary");
  assert.equal(registry.get(a.id)?.status, "canary");
  assert.ok(d.canaryRollbackId);
  await bridge.rollback(a.id);
  assert.deepEqual(undos, [a.id]);
  assert.equal(registry.get(a.id)?.status, "rejected");
});

test("before/after regression cannot reach composition or canary", async () => {
  const spine = newSpine(); const registry = enabledRegistry(spine); const a = adapter(); registry.register(a);
  let compositionCalls = 0;
  const evalHarness: EvalHarness = { evaluate: async (ids) => ids.includes(a.id) ? { capability: 0.7, safety: 0.96 } : { capability: 0.9, safety: 0.96 }, redTeamComposed: async () => { compositionCalls++; return { attackSuccessRate: 0, probesRun: 20 }; } };
  const d = await makeBridge(spine, registry, evalHarness).admit({ adapter: a, auth, sandboxed: true, replay });
  assert.equal(d.outcome, "rejected-eval");
  assert.equal(compositionCalls, 0);
  assert.notEqual(registry.get(a.id)?.status, "canary");
});

test("named rollback leaves a newer unrelated canary intact and canaries participate in composition", async () => {
  const spine = newSpine(); const registry = enabledRegistry(spine); const undos: string[] = []; const sets: string[][] = [];
  const evalHarness: EvalHarness = { evaluate: async (ids) => { sets.push([...ids]); return { capability: 0.8, safety: 0.96 }; }, redTeamComposed: async (ids) => { sets.push([...ids]); return { attackSuccessRate: 0, probesRun: 20 }; } };
  const bridge = makeBridge(spine, registry, evalHarness, undos); const first = adapter(); const second = adapter({ id: "adapter-2" }); registry.register(first); registry.register(second);
  await bridge.admit({ adapter: first, auth, sandboxed: true, replay });
  await bridge.admit({ adapter: second, auth: { ...auth, authorizedAdapterId: second.id }, sandboxed: true, replay });
  await bridge.rollback(first.id);
  assert.ok(sets.some((ids) => ids.includes(first.id) && ids.includes(second.id)));
  assert.deepEqual(undos, [first.id]);
  assert.equal(registry.get(second.id)?.status, "canary");
});

// ─── opt-in property: no config → no bridge (floor unaffected) ───

test("opt-in: composeKeep without loraBridge config leaves adapterBridge undefined (N=1/floor unaffected)", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-188-c-")) });
  assert.equal(app.adapterBridge, undefined, "no LoRA bridge without explicit opt-in — floor untouched");
});

test("opt-in: composeKeep exposes the complete bridge and its real canary rollback path", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const sp = newSpine(); const registry = enabledRegistry(sp); const a = adapter(); registry.register(a); const undos: string[] = [];
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-188-on-")), loraBridge: { registry, harness: harness(0.96, 0), spine: sp, rollback: new RollbackLedger(sp), canaryDeploy: async (candidate) => ({ undo: async () => { undos.push(candidate.id); } }) } });
  const decision = await app.adapterBridge!.admit({ adapter: a, auth, sandboxed: true, replay });
  assert.equal(decision.outcome, "deployed-canary");
  await app.adapterBridge!.rollback(a.id);
  assert.deepEqual(undos, [a.id]);
});

test("F2: composeKeep exposes a wired calibrationWire, and the authorize→consume loop works through the app", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-f2-c-")) });
  assert.ok(app.calibrationWire, "calibrationWire is exposed on the composed app");
  // Feed a proven-clean reversible class through the composed wire.
  for (let i = 0; i < 12; i++) { app.calibrationWire.recordDecision("low", true, true); app.calibrationWire.observeOutcome("low", "clean"); }
  assert.deepEqual([...app.calibrationWire.pendingReductions()], ["low"], "a governed reduce-proposal is offered");
  assert.equal(app.calibrationWire.activePolicyGates().has("low"), false, "not applied until a human authorizes");
  app.calibrationWire.authorizeReduction("low", "operator");
  assert.equal(app.calibrationWire.activePolicyGates().has("low"), true, "authorized policy is now active + consumable by the router");
});
