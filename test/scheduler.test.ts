import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { ModelGateway, type GenerateRequest, type GenerateResult, type ModelProvider, type Embedding } from "../src/gateway/gateway.js";
import { CostModel } from "../src/observability/cost_model.js";

import {
  BudgetLedger,
  type AuthorizationEnvelope,
} from "../src/scheduler/authorization_envelope.js";
import {
  MeteredGateway,
  TokenVelocityBreaker,
  BudgetExceeded,
  type MeteredCallContext,
} from "../src/scheduler/metered_gateway.js";
import {
  Scheduler,
  DeadLetterQueue,
  type ScheduledTask,
} from "../src/scheduler/scheduler.js";
import {
  SagaSequencer,
  NonPersistableRegistry,
  type SagaStep,
} from "../src/scheduler/saga_sequencer.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-sched-"));
  return new Spine(new FileSpineStore(dir, { fsync: true }), new InProcessLock(), new SchemaRegistry());
}

// A counting provider so we can prove NO call is made on a breach.
function countingProvider(): { provider: ModelProvider; calls: () => number } {
  let calls = 0;
  const provider: ModelProvider = {
    name: "test",
    isLocal: true,
    async generate(req: GenerateRequest): Promise<GenerateResult> {
      calls++;
      return { text: "ok", model: "test-model", tokensIn: 100, tokensOut: 50 };
    },
    async embed(texts: readonly string[]): Promise<Embedding[]> {
      return texts.map(() => [0.1, 0.2]);
    },
  };
  return { provider, calls: () => calls };
}

function costModelWithPricing(): CostModel {
  const cm = new CostModel();
  cm.registerPricing({ model: "test-model", inputPerMillion: 1000, outputPerMillion: 2000 }); // pricey → easy caps
  return cm;
}

function envelope(over: Partial<AuthorizationEnvelope> = {}): AuthorizationEnvelope {
  return {
    id: "env1", projectId: "prj1",
    allowedClasses: ["auto-research", "auto-learning"],
    allowedTiers: ["local", "small"],
    dailyCapUsd: 1.0, perRunCapUsd: 0.5, perCallTokenCeiling: 1000,
    expiresAt: Date.now() + 86_400_000, grantedReason: "nightly research on prj1",
    ...over,
  };
}

// ── BudgetLedger: hard-stop BEFORE the call, per breach kind ─────────────────

test("INVARIANT: ledger hard-stops on an expired envelope", async () => {
  const spine = newSpine();
  const ledger = new BudgetLedger(spine, costModelWithPricing());
  await ledger.grant(envelope({ expiresAt: Date.now() - 1000 }));
  await ledger.beginRun("r1", "env1");
  const check = ledger.willBreach("r1", "auto-research", "local", "test-model", { freshInputTokens: 1, cachedInputTokens: 0, outputTokens: 1 });
  assert.equal(check.wouldBreach, true);
  assert.equal(check.kind, "expired");
});

test("INVARIANT: ledger hard-stops on an unauthorized class", async () => {
  const spine = newSpine();
  const ledger = new BudgetLedger(spine, costModelWithPricing());
  await ledger.grant(envelope());
  await ledger.beginRun("r1", "env1");
  const check = ledger.willBreach("r1", "auto-training", "local", "test-model", { freshInputTokens: 1, cachedInputTokens: 0, outputTokens: 1 });
  assert.equal(check.kind, "class-not-authorized");
});

test("INVARIANT: ledger hard-stops on an unauthorized model tier", async () => {
  const spine = newSpine();
  const ledger = new BudgetLedger(spine, costModelWithPricing());
  await ledger.grant(envelope());
  await ledger.beginRun("r1", "env1");
  const check = ledger.willBreach("r1", "auto-research", "frontier", "test-model", { freshInputTokens: 1, cachedInputTokens: 0, outputTokens: 1 });
  assert.equal(check.kind, "tier-not-authorized");
});

test("INVARIANT: ledger hard-stops on the per-call token ceiling", async () => {
  const spine = newSpine();
  const ledger = new BudgetLedger(spine, costModelWithPricing());
  await ledger.grant(envelope({ perCallTokenCeiling: 100 }));
  await ledger.beginRun("r1", "env1");
  const check = ledger.willBreach("r1", "auto-research", "local", "test-model", { freshInputTokens: 1, cachedInputTokens: 0, outputTokens: 500 });
  assert.equal(check.kind, "token-ceiling");
});

test("INVARIANT: ledger hard-stops on the per-run cap", async () => {
  const spine = newSpine();
  const ledger = new BudgetLedger(spine, costModelWithPricing());
  await ledger.grant(envelope({ perRunCapUsd: 0.0001 })); // any real call exceeds this
  await ledger.beginRun("r1", "env1");
  const check = ledger.willBreach("r1", "auto-research", "local", "test-model", { freshInputTokens: 1000, cachedInputTokens: 0, outputTokens: 500 });
  assert.equal(check.kind, "per-run-cap");
});

test("INVARIANT: ledger hard-stops on the daily cap (across runs)", async () => {
  const spine = newSpine();
  const ledger = new BudgetLedger(spine, costModelWithPricing());
  await ledger.grant(envelope({ dailyCapUsd: 0.0001, perRunCapUsd: 100 }));
  await ledger.beginRun("r1", "env1");
  const check = ledger.willBreach("r1", "auto-research", "local", "test-model", { freshInputTokens: 1000, cachedInputTokens: 0, outputTokens: 500 });
  assert.equal(check.kind, "daily-cap");
});

// ── MeteredGateway: enforcement, no call on breach ──────────────────────────

test("INVARIANT: MeteredGateway makes NO provider call when a cap would breach", async () => {
  const spine = newSpine();
  const { provider, calls } = countingProvider();
  const ledger = new BudgetLedger(spine, costModelWithPricing());
  await ledger.grant(envelope({ perRunCapUsd: 0.0001 }));
  await ledger.beginRun("r1", "env1");
  const breaker = new TokenVelocityBreaker(spine);
  const mg = new MeteredGateway(new ModelGateway(provider), ledger, breaker, spine);
  const ctx: MeteredCallContext = { runId: "r1", cls: "auto-research", tier: "local", projected: { freshInputTokens: 1000, cachedInputTokens: 0, outputTokens: 500 } };
  await assert.rejects(() => mg.generateMetered({ prompt: "hi" }, ctx, "test-model"), (e) => e instanceof BudgetExceeded);
  assert.equal(calls(), 0, "no provider call was made on breach — enforcement before spend");
});

test("MeteredGateway records real spend on a successful metered call", async () => {
  const spine = newSpine();
  const { provider, calls } = countingProvider();
  const ledger = new BudgetLedger(spine, costModelWithPricing());
  await ledger.grant(envelope({ perRunCapUsd: 100, dailyCapUsd: 100 }));
  await ledger.beginRun("r1", "env1");
  const breaker = new TokenVelocityBreaker(spine, { maxUsdPerMinute: 1e9 });
  const mg = new MeteredGateway(new ModelGateway(provider), ledger, breaker, spine);
  const ctx: MeteredCallContext = { runId: "r1", cls: "auto-research", tier: "local", projected: { freshInputTokens: 100, cachedInputTokens: 0, outputTokens: 50 } };
  const res = await mg.generateMetered({ prompt: "hi" }, ctx, "test-model");
  assert.equal(res.text, "ok");
  assert.equal(calls(), 1);
  assert.ok(ledger.runSpend("r1")!.spentUsd > 0, "spend recorded");
});

// ── TokenVelocityBreaker: leading signals, independent of caps ──────────────

test("INVARIANT: velocity breaker trips on repetitive identical calls (loop) — independent of cap", async () => {
  const spine = newSpine();
  const { provider } = countingProvider();
  const ledger = new BudgetLedger(spine, costModelWithPricing());
  await ledger.grant(envelope({ perRunCapUsd: 1e9, dailyCapUsd: 1e9 })); // caps wide open
  await ledger.beginRun("r1", "env1");
  const breaker = new TokenVelocityBreaker(spine, { maxRepeatedIdentical: 3, maxUsdPerMinute: 1e9 });
  const mg = new MeteredGateway(new ModelGateway(provider), ledger, breaker, spine);
  // Match the fixture's actual100/50 usage so this isolates repetition, not projection-overrun refusal.
  const ctx: MeteredCallContext = { runId: "r1", cls: "auto-research", tier: "local", projected: { freshInputTokens: 100, cachedInputTokens: 0, outputTokens: 50 } };
  await mg.generateMetered({ prompt: "same" }, ctx, "test-model");
  await mg.generateMetered({ prompt: "same" }, ctx, "test-model");
  await assert.rejects(() => mg.generateMetered({ prompt: "same" }, ctx, "test-model"), (e) => e instanceof BudgetExceeded, "3rd identical trips the loop breaker");
  assert.equal(breaker.isTripped, true);
});

test("INVARIANT: velocity breaker stays tripped until human reset", async () => {
  const spine = newSpine();
  const breaker = new TokenVelocityBreaker(spine, { maxRepeatedIdentical: 2 });
  breaker.checkRepetition("x");
  assert.throws(() => breaker.checkRepetition("x")); // trips
  assert.equal(breaker.isTripped, true);
  breaker.reset("operator reviewed");
  assert.equal(breaker.isTripped, false);
});

// ── Scheduler: envelope-gated, halts on breach, dead-letters unrecoverable ──

async function schedulerSetup() {
  const spine = newSpine();
  const ledger = new BudgetLedger(spine, costModelWithPricing());
  await ledger.grant(envelope({ perRunCapUsd: 100, dailyCapUsd: 100 }));
  const dlq = new DeadLetterQueue(spine);
  const scheduler = new Scheduler({ spine, ledger, dlq });
  return { spine, ledger, dlq, scheduler };
}

test("INVARIANT: scheduler will not run without a valid enabled envelope", async () => {
  const { scheduler } = await schedulerSetup();
  const report = await scheduler.tick("prj1", []); // never enabled
  assert.equal(report.halted, true);
  assert.match(report.haltReason ?? "", /disabled/);
});

test("INVARIANT: scheduler dead-letters an unrecoverable task, never retries it", async () => {
  const { scheduler, dlq } = await schedulerSetup();
  scheduler.enable({ projectId: "prj1", enabledClasses: ["auto-research"], envelopeId: "env1" });
  let ran = false;
  const task: ScheduledTask = { id: "t1", projectId: "prj1", cls: "auto-research", priorFailures: 3, run: async () => { ran = true; return "x"; } };
  const report = await scheduler.tick("prj1", [task]);
  assert.equal(ran, false, "unrecoverable task NOT run");
  assert.ok(report.deadLettered.includes("t1"));
  assert.equal(dlq.list().length, 1);
});

test("INVARIANT: a BudgetExceeded halts the WHOLE tick (enforcement), remaining tasks not run", async () => {
  const { spine, ledger, dlq } = await (async () => {
    const spine = newSpine();
    const ledger = new BudgetLedger(spine, costModelWithPricing());
    await ledger.grant(envelope({ perRunCapUsd: 0.0001, dailyCapUsd: 100 })); // any call breaches
    const dlq = new DeadLetterQueue(spine);
    return { spine, ledger, dlq };
  })();
  const scheduler = new Scheduler({ spine, ledger, dlq });
  scheduler.enable({ projectId: "prj1", enabledClasses: ["auto-research"], envelopeId: "env1" });
  const { provider } = countingProvider();
  const breaker = new TokenVelocityBreaker(spine);
  const mg = new MeteredGateway(new ModelGateway(provider), ledger, breaker, spine);
  let secondRan = false;
  const t1: ScheduledTask = { id: "t1", projectId: "prj1", cls: "auto-research", run: async (runId) => {
    await mg.generateMetered({ prompt: "hi" }, { runId, cls: "auto-research", tier: "local", projected: { freshInputTokens: 1000, cachedInputTokens: 0, outputTokens: 500 } }, "test-model");
    return "should not reach";
  }};
  const t2: ScheduledTask = { id: "t2", projectId: "prj1", cls: "auto-research", run: async () => { secondRan = true; return "x"; } };
  const report = await scheduler.tick("prj1", [t1, t2]);
  assert.equal(report.halted, true, "tick halted on budget breach");
  assert.equal(secondRan, false, "remaining task not run after halt");
});

test("scheduler returns proposals for human review — never auto-merges", async () => {
  const { scheduler } = await schedulerSetup();
  scheduler.enable({ projectId: "prj1", enabledClasses: ["auto-research"], envelopeId: "env1" });
  const task: ScheduledTask = { id: "t1", projectId: "prj1", cls: "auto-research", run: async () => "proposed: add caching to module X" };
  const report = await scheduler.tick("prj1", [task]);
  assert.equal(report.halted, false);
  assert.equal(report.proposals.length, 1);
  assert.match(report.proposals[0]!.proposal, /proposed/);
});

// ── SagaSequencer: all-or-unwind ────────────────────────────────────────────

test("INVARIANT: saga commits when all steps succeed", async () => {
  const spine = newSpine();
  const saga = new SagaSequencer(spine);
  const applied: string[] = [];
  const steps: SagaStep[] = ["a", "b", "c"].map((n) => ({
    name: n, forward: async () => { applied.push(n); return { id: n, artifact: `art-${n}`, undo: async () => { applied.splice(applied.indexOf(n), 1); } }; },
  }));
  const outcome = await saga.run("s1", steps);
  assert.equal(outcome.committed, true);
  assert.deepEqual(outcome.completed, ["a", "b", "c"]);
  assert.deepEqual(applied, ["a", "b", "c"]);
});

test("INVARIANT: saga unwinds completed steps in LIFO on a partial failure", async () => {
  const spine = newSpine();
  const saga = new SagaSequencer(spine);
  const applied: string[] = [];
  const undoOrder: string[] = [];
  const steps: SagaStep[] = [
    { name: "a", forward: async () => { applied.push("a"); return { id: "a", artifact: "art-a", undo: async () => { undoOrder.push("a"); } }; } },
    { name: "b", forward: async () => { applied.push("b"); return { id: "b", artifact: "art-b", undo: async () => { undoOrder.push("b"); } }; } },
    { name: "c", forward: async () => { throw new Error("step c failed"); } },
  ];
  const outcome = await saga.run("s2", steps);
  assert.equal(outcome.committed, false);
  assert.equal(outcome.failedAt, "c");
  assert.deepEqual(outcome.compensated, ["b", "a"], "unwound in LIFO order");
});

// ── NonPersistableRegistry: no checkpoint mid-side-effect ────────────────────

test("INVARIANT: no checkpoint is allowed while a non-persistable region is open", async () => {
  const spine = newSpine();
  const reg = new NonPersistableRegistry(spine);
  assert.equal(reg.canCheckpoint(), true);
  reg.enter("commit-region");
  assert.equal(reg.canCheckpoint(), false, "checkpoint refused mid-side-effect");
  reg.exit("commit-region");
  assert.equal(reg.canCheckpoint(), true);
});

test("INVARIANT: within() always exits the region even if the body throws", async () => {
  const spine = newSpine();
  const reg = new NonPersistableRegistry(spine);
  await assert.rejects(() => reg.within("r", async () => { throw new Error("boom"); }));
  assert.equal(reg.canCheckpoint(), true, "region exited despite throw — not stuck non-persistable");
});

test("INVARIANT: run-scoped regions block their own checkpoints without blocking independent runs", async () => {
  const reg = new NonPersistableRegistry(newSpine());
  reg.enter("run-a:implement", "run-a");
  assert.equal(reg.canCheckpoint("run-a"), false);
  assert.equal(reg.canCheckpoint("run-b"), true);
  assert.deepEqual(reg.openRegionsFor("run-a"), ["run-a:implement"]);
  assert.deepEqual(reg.openRegionsFor("run-b"), []);
  reg.exit("run-a:implement", "run-a");
  assert.equal(reg.canCheckpoint("run-a"), true);
});
