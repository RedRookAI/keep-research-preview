import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { CostModel } from "../src/observability/cost_model.js";
import { BudgetLedger, type AuthorizationEnvelope } from "../src/scheduler/authorization_envelope.js";
import { MeteredGateway, TokenVelocityBreaker, BudgetExceeded } from "../src/scheduler/metered_gateway.js";
import { MeteredProvider, LenientCostModel } from "../src/scheduler/metered_provider.js";
import { OutcomeAdaptation, OutcomeAdaptiveProvider } from "../src/learning/outcome_adaptation.js";
import { InMemoryWorkspace } from "../src/solve/workspace.js";
import { validatorRunner } from "../src/solve/default_solver.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { FileTree } from "../src/solve/patch.js";

/**
 * ROUND 3 (ledger L7) — is autonomous model-call spend actually BOUNDED on the wired path?
 *
 * MEASURED FIRST: the money machinery (BudgetLedger.willBreach, MeteredGateway, TokenVelocityBreaker) was
 * all BUILT but had ZERO callers — `MeteredGateway.generateMetered` was never invoked in src, and
 * `buildAutonomyLoop` got no spend guard, so the unattended autonomy loop's model calls (edit_planner,
 * localize) hit `model.generate()` directly = UNBOUNDED. This round routes the autonomy loop's solve
 * through a MeteredProvider under a granted envelope: willBreach HARD-STOPS an over-budget call before it
 * is made (fail-closed), the velocity breaker trips on rate/repetition, spend is recorded. The attended
 * ingress path stays unmetered (operator present).
 *
 * PROVEN-LIVE (harness A1). Disproof neuters:
 *   - route MeteredProvider.generate through inner (bypassing generateMetered) -> HARD-STOP goes RED
 *   - in compose, point autonomyLoop back at governedSolve (unmetered) -> COMPOSE-ENFORCED goes RED
 * HONEST SEAM: one envelope bounds the whole autonomy subsystem; per-project-run granularity is L7b (filed).
 */

function recordingProvider(): { provider: ModelProvider; calls: () => number } {
  let n = 0;
  const provider: ModelProvider = {
    name: "rec",
    isLocal: true,
    async generate(_r: GenerateRequest): Promise<GenerateResult> {
      n++;
      return { text: "ok", model: "rec", tokensIn: 1, tokensOut: 1 };
    },
    async embed(t: readonly string[]): Promise<Embedding[]> {
      return t.map(() => [0]);
    },
  };
  return { provider, calls: () => n };
}

function newSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-l7-")), { fsync: true }), new InProcessLock(), new SchemaRegistry());
}

const TIGHT: AuthorizationEnvelope = {
  id: "tight", projectId: "p", allowedClasses: ["auto-research"], allowedTiers: [],
  dailyCapUsd: 999, perRunCapUsd: 999, perCallTokenCeiling: 0, expiresAt: Number.MAX_SAFE_INTEGER,
  grantedReason: "test: refuse any call (0-token ceiling)",
};

test("HARD-STOP: a metered call that would breach throws BudgetExceeded BEFORE the provider is called", async () => {
  const spine = newSpine();
  const ledger = new BudgetLedger(spine, new CostModel());
  await ledger.grant(TIGHT);
  await ledger.beginRun("r", TIGHT.id);
  const rec = recordingProvider();
  const metered = new MeteredGateway(new ModelGateway(rec.provider), ledger, new TokenVelocityBreaker(spine), spine);
  const provider = new MeteredProvider(rec.provider, metered, { runId: "r", cls: "auto-research", tier: "local" });

  await assert.rejects(() => provider.generate({ prompt: "hello", maxTokens: 100 }), (e) => e instanceof BudgetExceeded);
  assert.equal(rec.calls(), 0, "fail-closed: the underlying provider was NEVER called on breach (no spend)");
});

test("USD-CAP-BITES: with a PRICED model (via the injected price lookup) a tiny per-run USD cap hard-stops", async () => {
  const spine = newSpine();
  // the price lookup prices "rec" (as compose's pricing registry prices real models); LenientCostModel
  // lazily registers it, so willBreach/recordSpend compute REAL USD → dailyCapUsd/perRunCapUsd bite.
  const priced = new LenientCostModel((m) => (m === "rec" ? { inputPerM: 1000, outputPerM: 1000 } : undefined));
  const ledger = new BudgetLedger(spine, priced);
  const env: AuthorizationEnvelope = {
    id: "usd", projectId: "p", allowedClasses: ["auto-research"], allowedTiers: [],
    dailyCapUsd: 0.0001, perRunCapUsd: 0.0001, perCallTokenCeiling: 32_000, expiresAt: Number.MAX_SAFE_INTEGER,
    grantedReason: "test: tiny USD cap, generous token ceiling — isolates the USD dimension",
  };
  await ledger.grant(env);
  await ledger.beginRun("r", env.id);
  const rec = recordingProvider();
  const metered = new MeteredGateway(new ModelGateway(rec.provider), ledger, new TokenVelocityBreaker(spine), spine);
  const provider = new MeteredProvider(rec.provider, metered, { runId: "r", cls: "auto-research", tier: "frontier" });
  // ~1000 input tokens + 1000 output @ $1000/M ≈ $0.002 > $0.0001 cap → USD hard-stop (NOT the token ceiling)
  await assert.rejects(
    () => provider.generate({ prompt: "x".repeat(4000), maxTokens: 1000 }),
    (e) => e instanceof BudgetExceeded && (e.kind === "per-run-cap" || e.kind === "daily-cap"),
  );
  assert.equal(rec.calls(), 0, "the USD breach hard-stopped before the provider was called");
});

test("ATTENDED-UNMETERED: the plain gateway.generate() is not enforced (interactive path, operator present)", async () => {
  const spine = newSpine();
  const ledger = new BudgetLedger(spine, new CostModel());
  await ledger.grant(TIGHT);
  await ledger.beginRun("r", TIGHT.id);
  const rec = recordingProvider();
  const metered = new MeteredGateway(new ModelGateway(rec.provider), ledger, new TokenVelocityBreaker(spine), spine);
  // the ATTENDED path uses generate(), which passes straight through despite the 0-token envelope
  const res = await metered.generate({ prompt: "hello", maxTokens: 100 });
  assert.equal(res.text, "ok", "attended generate() is unmetered — passes through");
  assert.equal(rec.calls(), 1, "the provider WAS called (no enforcement on the attended path)");
});

test("ADAPTIVE-PROJECTION: injected adaptive prompt bytes are included before the budget decision", async () => {
  const spine = newSpine();
  const ledger = new BudgetLedger(spine, new LenientCostModel((model) => model === "rec" ? { inputPerM: 1000, outputPerM: 1000 } : undefined));
  const envelope: AuthorizationEnvelope = { ...TIGHT, id: "adaptive-projection", dailyCapUsd: 0.05, perRunCapUsd: 0.05, perCallTokenCeiling: 50 };
  await ledger.grant(envelope); await ledger.beginRun("r", envelope.id);
  const rec = recordingProvider();
  const gateway = new MeteredGateway(new ModelGateway(rec.provider), ledger, new TokenVelocityBreaker(spine), spine);
  const metered = new MeteredProvider(rec.provider, gateway, { runId: "r", cls: "auto-research", tier: "local" });
  const adaptation = new OutcomeAdaptation({
    prompt: { version: "large", text: "x".repeat(400) },
    routing: { model: "rec", effort: "none" },
    voice: { promptFormat: "markdown", verbosity: "normal" },
  }, { minSamplesPerArm: 4, minQualityGain: 0.1, maxRegressionRate: 0.25, rollbackQualityDrop: 0.15 });
  const provider = new OutcomeAdaptiveProvider(metered, adaptation, { current: () => ({ effortKnob: "none", timeoutClass: "standard", asOf: "2026-08-29", freshness: "fresh" }) });
  await assert.rejects(() => provider.generate({ prompt: "tiny", maxTokens: 0 }), (error) => error instanceof BudgetExceeded && (error.kind === "per-run-cap" || error.kind === "daily-cap"));
  assert.equal(rec.calls(), 0, "the adaptive request is rejected before provider spend");
});

// ── COMPOSE end-to-end: the autonomy loop's solve is the metered one ──
const BUGGY = "export function add(a: number, b: number): number {\n  return a - b;\n}\n";
const CLEAN_PLAN = JSON.stringify({ rationale: "fix", edits: [{ file: "src/math.ts", search: "return a - b;", replace: "return a + b;", intent: "fix" }] });

function scriptedModel(planJson: string): ModelProvider {
  return {
    name: "s", isLocal: true,
    async generate(_r: GenerateRequest): Promise<GenerateResult> { return { text: planJson, model: "s", tokensIn: 0, tokensOut: 0 }; },
    async embed(t: readonly string[]): Promise<Embedding[]> { return t.map(() => [0]); },
  };
}
const passRunner = (_ref: string, tree: FileTree) =>
  validatorRunner(tree, async (t) => (await t.read("src/math.ts"))?.includes("a + b") ?? false);

async function appWithBudget(budget?: AuthorizationEnvelope) {
  const { composeKeep } = await import("../src/compose.js");
  return composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-l7c-")),
    developmentProvider: scriptedModel(CLEAN_PLAN),
    workspace: new InMemoryWorkspace({ "app-repo": { "src/math.ts": BUGGY } }),
    repoRef: "app-repo",
    solverRunnerFor: passRunner,
    ...(budget ? { autonomyBudget: budget } : {}),
  });
}
function hardStopped(app: { spine: { replay(): readonly { payload: unknown }[] } }): boolean {
  return app.spine.replay().map((e) => e.payload as Record<string, unknown> | undefined).some((p) => p?.["event"] === "call_hard_stopped");
}
function mergeDecision(app: { spine: { replay(): readonly { payload: unknown }[] } }) {
  return app.spine.replay().map((e) => e.payload as Record<string, unknown> | undefined).find((p) => p?.["event"] === "merge_authority");
}

test("COMPOSE-ENFORCED: a TIGHT autonomy budget hard-stops the autonomy loop's model call on the wired path", async () => {
  const app = await appWithBudget(TIGHT);
  try { await app.autonomyLoop!.runProject("fix the add() operator", { runId: "l7-tight", stepBudget: 50 }); } catch { /* BudgetExceeded may propagate — the hard-stop event is the proof */ }
  await app.spine.seal();
  assert.ok(hardStopped(app), "the metered autonomy call was hard-stopped (call_hard_stopped on the spine)");
  assert.equal(mergeDecision(app), undefined, "the over-budget solve never reached a governed merge decision");
});

test("COMPOSE-CONTROL: the DEFAULT (generous) budget does not block a normal autonomous run", async () => {
  const app = await appWithBudget(); // default envelope
  await app.autonomyLoop!.runProject("fix the add() operator", { runId: "l7-ok", stepBudget: 50 });
  await app.spine.seal();
  assert.equal(hardStopped(app), false, "no hard-stop under the generous default");
  assert.ok(mergeDecision(app), "the run proceeds to a governed merge decision (metering does not break the normal path)");
});
