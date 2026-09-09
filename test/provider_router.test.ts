import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";

import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import { ProviderError } from "../src/gateway/http_provider.js";
import { ProviderRouter, type RegisteredProvider } from "../src/gateway/provider_router.js";
import { MeasuredHardRouteBudget, MeasuredOutcomeRouter, type ModelProfile as CostProfile } from "../src/routing/cost_of_pass_router.js";
import type { CapabilityTier } from "../src/frontdoor/capability_adaptive.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-router-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

/** A fake provider whose answer + behavior are scripted. */
class Fake implements ModelProvider {
  readonly isLocal = true;
  calls = 0;
  lastRequest: GenerateRequest | undefined;
  constructor(readonly name: string, private readonly behavior: () => GenerateResult) {}
  async generate(req: GenerateRequest): Promise<GenerateResult> { this.calls++; this.lastRequest = req; return this.behavior(); }
  async embed(_t: readonly string[]): Promise<Embedding[]> { return []; }
}

function reg(id: string, tier: CapabilityTier, costWeight: number, provider: ModelProvider): RegisteredProvider {
  return { id, tier, costWeight, provider };
}

// Predictor: everything clears the firewall (so tier selection is by complexity + cost).
const alwaysClears = () => 0.9;

test("INVARIANT: a simple task routes to the cheap tier", async () => {
  const spine = newSpine();
  const cheap = new Fake("cheap", () => ({ text: "ok", model: "cheap", tokensIn: 1, tokensOut: 1 }));
  const rich = new Fake("rich", () => ({ text: "ok-rich", model: "rich", tokensIn: 1, tokensOut: 1 }));
  const router = new ProviderRouter(spine, alwaysClears);
  router.register(reg("cheap", "minimal", 1, cheap));
  router.register(reg("rich", "rich", 10, rich));

  const out = await router.run({ prompt: "hi" }); // short prompt → trivial/simple
  assert.equal(out.tier, "minimal", "cheapest tier answered");
  assert.equal(out.escalations, 0);
  assert.equal(rich.calls, 0, "frontier tier never touched");
});

test("INVARIANT: a FAILED quality check cascades up a tier", async () => {
  const spine = newSpine();
  const cheap = new Fake("cheap", () => ({ text: "bad", model: "cheap", tokensIn: 1, tokensOut: 1 }));
  const strong = new Fake("strong", () => ({ text: "good", model: "strong", tokensIn: 1, tokensOut: 1 }));
  const router = new ProviderRouter(spine, alwaysClears);
  router.register(reg("cheap", "minimal", 1, cheap));
  router.register(reg("strong", "standard", 5, strong));

  // Quality check: only "good" answers pass.
  const out = await router.run({ prompt: "hi" }, { qualityCheck: (r) => r.text === "good" });
  assert.equal(out.result.text, "good", "escalated to the tier that produced a passing answer");
  assert.equal(out.escalations, 1, "one cascade escalation");
  assert.equal(cheap.calls, 1);
  assert.equal(strong.calls, 1);
});

test("INVARIANT: cascade is BOUNDED — returns best-effort at the escalation cap", async () => {
  const spine = newSpine();
  // All tiers fail the quality check → must stop at maxEscalations, not loop forever.
  const a = new Fake("a", () => ({ text: "no", model: "a", tokensIn: 1, tokensOut: 1 }));
  const b = new Fake("b", () => ({ text: "no", model: "b", tokensIn: 1, tokensOut: 1 }));
  const c = new Fake("c", () => ({ text: "no", model: "c", tokensIn: 1, tokensOut: 1 }));
  const router = new ProviderRouter(spine, alwaysClears, { maxEscalations: 1 });
  router.register(reg("a", "minimal", 1, a));
  router.register(reg("b", "lean", 2, b));
  router.register(reg("c", "standard", 3, c));

  const out = await router.run({ prompt: "hi" }, { qualityCheck: () => false });
  assert.equal(out.escalations, 1, "stopped at the cap");
  assert.ok(out.result.text === "no", "returned best-effort answer, did not throw");
});

test("INVARIANT: failed quality at the last admitted tier returns the paid best-effort answer without a false outage", async () => {
  const spine = newSpine();
  const rich = new Fake("rich", () => ({ text: "best-effort", model: "rich", tokensIn: 1, tokensOut: 1 }));
  const router = new ProviderRouter(spine, alwaysClears);
  router.register(reg("rich", "rich", 1, rich));
  const out = await router.run({ prompt: "hard" }, { qualityCheck: () => false });
  assert.equal(out.result.text, "best-effort");
  assert.equal(out.escalations, 0, "no nonexistent escalation is charged to telemetry");
});

test("ProviderRouter refuses duplicate provider identities", () => {
  const router = new ProviderRouter(newSpine(), alwaysClears);
  const provider = new Fake("same", () => ({ text: "x", model: "same", tokensIn: 1, tokensOut: 1 }));
  router.register(reg("same", "minimal", 1, provider));
  assert.throws(() => router.register(reg("same", "minimal", 2, provider)), /duplicate provider id/u);
});

test("INVARIANT: escalation rate is tracked (the SOTA cost variable)", async () => {
  const spine = newSpine();
  const cheap = new Fake("cheap", () => ({ text: "bad", model: "cheap", tokensIn: 1, tokensOut: 1 }));
  const strong = new Fake("strong", () => ({ text: "good", model: "strong", tokensIn: 1, tokensOut: 1 }));
  const router = new ProviderRouter(spine, alwaysClears);
  router.register(reg("cheap", "minimal", 1, cheap));
  router.register(reg("strong", "standard", 5, strong));

  await router.run({ prompt: "a" }, { qualityCheck: (r) => r.text === "good" }); // escalates
  await router.run({ prompt: "b" }); // no check → no escalation
  assert.equal(router.stats.routes, 2);
  assert.equal(router.stats.escalations, 1);
  assert.equal(router.escalationRate, 0.5);
});

test("INVARIANT: a transient outage FAILS OVER to another provider in the same tier", async () => {
  const spine = newSpine();
  const down = new Fake("down", () => { throw new ProviderError("503", 503, false); });
  const up = new Fake("up", () => ({ text: "served", model: "up", tokensIn: 1, tokensOut: 1 }));
  const router = new ProviderRouter(spine, alwaysClears);
  router.register(reg("down", "minimal", 1, down));
  router.register(reg("up", "minimal", 2, up));

  const out = await router.run({ prompt: "hi" });
  assert.equal(out.providerId, "up", "failed over to the healthy provider");
  assert.equal(out.failovers, 1);
});

test("INVARIANT: a PERMANENT error does NOT fail over — it throws", async () => {
  const spine = newSpine();
  const bad = new Fake("bad", () => { throw new ProviderError("400", 400, true); });
  const other = new Fake("other", () => ({ text: "x", model: "other", tokensIn: 1, tokensOut: 1 }));
  const router = new ProviderRouter(spine, alwaysClears);
  router.register(reg("bad", "minimal", 1, bad));
  router.register(reg("other", "minimal", 2, other));

  await assert.rejects(() => router.run({ prompt: "hi" }), (e: unknown) => e instanceof ProviderError && e.permanent);
  assert.equal(other.calls, 0, "a 400 is not an availability problem — no failover");
});

test("escalation + failover events are recorded to the spine", async () => {
  const spine = newSpine();
  const cheap = new Fake("cheap", () => ({ text: "bad", model: "cheap", tokensIn: 1, tokensOut: 1 }));
  const strong = new Fake("strong", () => ({ text: "good", model: "strong", tokensIn: 1, tokensOut: 1 }));
  const router = new ProviderRouter(spine, alwaysClears);
  router.register(reg("cheap", "minimal", 1, cheap));
  router.register(reg("strong", "standard", 5, strong));
  await router.run({ prompt: "hi" }, { qualityCheck: (r) => r.text === "good" });
  await spine.seal();
  const events = spine.replay().map((e) => (e.payload as Record<string, unknown>)["event"]);
  assert.ok(events.includes("cascade_escalate"), "cascade recorded for auditability");
  assert.ok(events.includes("routed"), "final route recorded");
});

// ── Composed fallback_chain taxonomy: access-revoked failover + refusal-stop (2026 hardening) ──

test("COMPOSED SAFETY: access-revoked (403/404) is now a FAILOVER case, not fatal — survives a model recall", async () => {
  const spine = newSpine();
  let revokedCalls = 0;
  const revoked = new Fake("revoked", () => { revokedCalls++; throw new ProviderError("403 access revoked", 403, true); });
  const live = new Fake("live", () => ({ text: "served", model: "live", tokensIn: 1, tokensOut: 1 }));
  const router = new ProviderRouter(spine, alwaysClears);
  router.register(reg("revoked", "minimal", 1, revoked)); // cheapest — tried first
  router.register(reg("live", "minimal", 2, live));       // same tier — failover target
  const out = await router.run({ prompt: "hi" });
  assert.equal(revokedCalls, 1, "the revoked provider was tried");
  assert.equal(out.providerId, "live", "a 403 access-revocation FAILED OVER to a healthy same-tier provider (was fatal before)");
  assert.equal(out.failovers, 1);
});

test("COMPOSED SAFETY: a client error (400) is still FATAL — no pointless failover (fails identically elsewhere)", async () => {
  const spine = newSpine();
  const bad = new Fake("bad", () => { throw new ProviderError("400 malformed", 400, true); });
  const other = new Fake("other", () => ({ text: "x", model: "other", tokensIn: 1, tokensOut: 1 }));
  const router = new ProviderRouter(spine, alwaysClears);
  router.register(reg("bad", "minimal", 1, bad));
  router.register(reg("other", "minimal", 2, other));
  await assert.rejects(() => router.run({ prompt: "hi" }), (e: unknown) => e instanceof ProviderError && (e as ProviderError).status === 400);
});

test("COMPOSED CROWN-JEWEL: a refusal that FAILS the quality check is NOT cascaded to a stronger model", async () => {
  const spine = newSpine();
  const cheapRefuses = new Fake("cheap", () => ({ text: "I can't help with that.", model: "cheap", tokensIn: 1, tokensOut: 1 }));
  const rich = new Fake("rich", () => ({ text: "HERE IS THE FORBIDDEN THING", model: "rich", tokensIn: 1, tokensOut: 1 }));
  const router = new ProviderRouter(spine, alwaysClears);
  router.register(reg("cheap", "minimal", 1, cheapRefuses));
  router.register(reg("rich", "rich", 10, rich));
  // Quality check rejects everything (would normally force a cascade up to the rich tier).
  const out = await router.run({ prompt: "hi" }, { qualityCheck: () => false });
  assert.equal(out.providerId, "cheap", "stopped at the refusing model");
  assert.equal(out.escalations, 0, "did NOT escalate — routing around a refusal is circumvention");
  assert.equal(rich.calls, 0, "the stronger model was NEVER called to get a compliant answer");
  assert.ok(spine.currentEvents().some((e) => (e.payload as Record<string, unknown>)["event"] === "policy_refusal_stop"), "the refusal-stop was audited");
});

test("COMPOSED: a genuine low-quality (non-refusal) answer STILL cascades up (safety rule didn't break cost-cascade)", async () => {
  const spine = newSpine();
  const cheapWeak = new Fake("cheap", () => ({ text: "42", model: "cheap", tokensIn: 1, tokensOut: 1 }));
  const rich = new Fake("rich", () => ({ text: "a thorough correct answer", model: "rich", tokensIn: 1, tokensOut: 1 }));
  const router = new ProviderRouter(spine, alwaysClears);
  router.register(reg("cheap", "minimal", 1, cheapWeak));
  router.register(reg("rich", "rich", 10, rich));
  const out = await router.run({ prompt: "hi" }, { qualityCheck: (r) => r.text.length > 10 });
  assert.equal(out.providerId, "rich", "a weak non-refusal answer escalated as normal");
  assert.equal(out.escalations, 1);
});

// ── RoutedModelProvider adapter (drop-in ModelProvider over the router) ──
import { RoutedModelProvider } from "../src/gateway/provider_router.js";

test("RoutedModelProvider: is a drop-in ModelProvider — routes generate, and isLocal only when ALL providers local", async () => {
  const spine = newSpine();
  const cheap = new Fake("cheap", () => ({ text: "cheap-answer", model: "cheap", tokensIn: 1, tokensOut: 1 }));
  const m = new RoutedModelProvider(spine, { providers: [reg("cheap", "minimal", 1, cheap)], predictor: alwaysClears });
  const out = await m.generate({ prompt: "hi" });
  assert.equal(out.text, "cheap-answer");
  assert.equal(m.isLocal, true, "all providers local → air-gap safe");
  const egress = new Fake("egress", () => ({ text: "x", model: "e", tokensIn: 1, tokensOut: 1 })); (egress as { isLocal: boolean }).isLocal = false;
  const m2 = new RoutedModelProvider(spine, { providers: [reg("cheap", "minimal", 1, cheap), reg("egress", "minimal", 2, egress)], predictor: alwaysClears });
  assert.equal(m2.isLocal, false, "one egressing provider → not air-gap safe");
});

test("RoutedModelProvider: embeddings fail over to the next provider on error", async () => {
  const spine = newSpine();
  const badEmbed: ModelProvider = { name: "bad", isLocal: true, async generate(): Promise<GenerateResult> { return { text: "x", model: "bad", tokensIn: 1, tokensOut: 1 }; }, async embed(): Promise<Embedding[]> { throw new ProviderError("down", 503, false); } };
  const goodEmbed: ModelProvider = { name: "good", isLocal: true, async generate(): Promise<GenerateResult> { return { text: "x", model: "good", tokensIn: 1, tokensOut: 1 }; }, async embed(): Promise<Embedding[]> { return [[0.5]]; } };
  const m = new RoutedModelProvider(spine, { providers: [reg("bad", "minimal", 1, badEmbed), reg("good", "minimal", 2, goodEmbed)], predictor: alwaysClears });
  assert.deepEqual(await m.embed(["t"]), [[0.5]], "embed failed over to the healthy provider");
});

test("RoutedModelProvider: measured cost-of-pass selects the live provider, applies effort, and settles hard spend", async () => {
  const spine = newSpine();
  const flaky = new Fake("flaky", () => ({ text: "flaky", model: "flaky-model", tokensIn: 1, tokensOut: 1 }));
  const reliable = new Fake("reliable", () => ({ text: "reliable", model: "reliable-model", tokensIn: 3, tokensOut: 2 }));
  const budget = new MeasuredHardRouteBudget(2);
  const profiles: CostProfile[] = [
    { model: "flaky-model", provider: "flaky", promptFormat: "terse", usdPerTask: 0.1, maxCallCostUsd: 0.5, tier: 1, successByBand: { moderate: 0.1 }, capabilityTier: "lean", effortKnob: "none" },
    { model: "reliable-model", provider: "reliable", promptFormat: "xml", usdPerTask: 0.4, maxCallCostUsd: 1, tier: 2, successByBand: { moderate: 0.9 }, capabilityTier: "standard", effortKnob: "graded", timeoutClass: "reasoning" },
  ];
  const routed = new RoutedModelProvider(spine, {
    providers: [reg("flaky", "minimal", 1, flaky), reg("reliable", "standard", 10, reliable)], predictor: alwaysClears,
    costOfPass: {
      profiles, policy: { allowedModels: ["flaky-model", "reliable-model"], operatorCeilingModel: "reliable-model", minSuccess: 0.5, hardBudget: budget },
      taskSignal: () => ({ inputSize: 3_000, subGoalCount: 2, reversibilityClass: "unknown", priorFailures: 0 }),
      measuredCostUsd: () => 0.6,
    },
  });
  assert.equal((await routed.generate({ prompt: "solve" })).text, "reliable");
  assert.equal(flaky.calls, 0, "the generic cheapest-tier heuristic cannot override measured eligibility");
  assert.match(reliable.lastRequest!.prompt, /^<task>solve<\/task>/u);
  assert.deepEqual(reliable.lastRequest!.hints?.["effort"], { kind: "graded", level: "medium" });
  assert.deepEqual(budget.snapshot(), { capUsd: 2, measuredSpentUsd: 0.6, reservedUsd: 0 });
});

test("RoutedModelProvider: cost policy prevents outage failover and conservatively charges an attempted call", async () => {
  const spine = newSpine();
  const admitted = new Fake("admitted", () => { throw new ProviderError("down", 503, false); });
  const forbidden = new Fake("forbidden", () => ({ text: "must-not-run", model: "forbidden-model", tokensIn: 1, tokensOut: 1 }));
  const budget = new MeasuredHardRouteBudget(1);
  const routed = new RoutedModelProvider(spine, {
    providers: [reg("admitted", "minimal", 1, admitted), reg("forbidden", "minimal", 2, forbidden)], predictor: alwaysClears,
    costOfPass: {
      profiles: [
        { model: "admitted-model", provider: "admitted", promptFormat: "terse", usdPerTask: 0.1, maxCallCostUsd: 0.5, tier: 1, successByBand: { trivial: 0.9 } },
        { model: "forbidden-model", provider: "forbidden", promptFormat: "terse", usdPerTask: 0.01, maxCallCostUsd: 0.5, tier: 1, successByBand: { trivial: 0.99 } },
      ],
      policy: { allowedModels: ["admitted-model"], operatorCeilingModel: "admitted-model", minSuccess: 0.5, hardBudget: budget },
      taskSignal: () => ({ inputSize: 1, subGoalCount: 1, reversibilityClass: "reversible", priorFailures: 0 }), measuredCostUsd: () => 0.1,
    },
  });
  await assert.rejects(() => routed.generate({ prompt: "x" }), /all tiers exhausted/u);
  assert.equal(forbidden.calls, 0);
  assert.equal(budget.snapshot().reservedUsd, 0, "failed execution releases its exact reservation");
  assert.equal(budget.snapshot().measuredSpentUsd, 0.5, "an indeterminate provider failure retains the conservative reserved spend");
});

test("RoutedModelProvider: an actual measured failure changes the next live provider route", async () => {
  const spine = newSpine();
  const cheap = new Fake("cheap", () => ({ text: "incorrect", model: "cheap-model", tokensIn: 1, tokensOut: 1 }));
  const strong = new Fake("strong", () => ({ text: "correct", model: "strong-model", tokensIn: 1, tokensOut: 1 }));
  const profiles: CostProfile[] = [
    { model: "cheap-model", provider: "cheap", promptFormat: "terse", usdPerTask: 0.1, tier: 1, successByBand: { moderate: 0.6 } },
    { model: "strong-model", provider: "strong", promptFormat: "terse", usdPerTask: 0.6, tier: 2, successByBand: { moderate: 0.95 } },
  ];
  const learner = new MeasuredOutcomeRouter(profiles);
  let measurement = 0;
  const routed = new RoutedModelProvider(spine, {
    providers: [reg("cheap", "minimal", 1, cheap), reg("strong", "standard", 2, strong)], predictor: alwaysClears,
    costOfPass: {
      profiles, policy: { allowedModels: ["cheap-model", "strong-model"], operatorCeilingModel: "strong-model", minSuccess: 0.5 },
      taskSignal: () => ({ inputSize: 3_000, subGoalCount: 2, reversibilityClass: "unknown", priorFailures: 0 }),
      outcomeLearning: { router: learner, measurementId: () => `execution-${++measurement}`, success: (result) => result.text === "correct" },
    },
  });
  assert.equal((await routed.generate({ prompt: "first" })).text, "incorrect");
  assert.equal((await routed.generate({ prompt: "second" })).text, "correct", "the measured failure lowers the first model beneath the reliability floor");
  assert.equal(cheap.calls, 1);
  assert.equal(strong.calls, 1);
});

test("RoutedModelProvider: a quality failure with no admitted cascade target settles measured spend", async () => {
  const budget = new MeasuredHardRouteBudget(1);
  const provider = new Fake("only", () => ({ text: "weak", model: "only-model", tokensIn: 1, tokensOut: 1 }));
  const routed = new RoutedModelProvider(newSpine(), {
    providers: [reg("only", "rich", 1, provider)], predictor: alwaysClears, qualityCheck: () => false,
    costOfPass: { profiles: [{ model: "only-model", provider: "only", promptFormat: "terse", usdPerTask: 0.1, maxCallCostUsd: 0.5, tier: 1, successByBand: { trivial: 0.9 } }], policy: { allowedModels: ["only-model"], operatorCeilingModel: "only-model", minSuccess: 0.5, hardBudget: budget }, taskSignal: () => ({ inputSize: 1, subGoalCount: 1, reversibilityClass: "reversible", priorFailures: 0 }), measuredCostUsd: () => 0.2 },
  });
  assert.equal((await routed.generate({ prompt: "x" })).text, "weak");
  assert.deepEqual(budget.snapshot(), { capUsd: 1, measuredSpentUsd: 0.2, reservedUsd: 0 });
});

test("RoutedModelProvider: invalid measurement falls back to reserved spend and overrun remains charged", async () => {
  const profile: CostProfile = { model: "m", provider: "p", promptFormat: "terse", usdPerTask: 0.1, maxCallCostUsd: 0.4, tier: 1, successByBand: { trivial: 0.9 } };
  for (const [measuredCostUsd, expected] of [[() => { throw new Error("meter failed"); }, 0.4], [() => 0.7, 0.7]] as const) {
    const budget = new MeasuredHardRouteBudget(1);
    const routed = new RoutedModelProvider(newSpine(), { providers: [reg("p", "minimal", 1, new Fake("p", () => ({ text: "ok", model: "m", tokensIn: 1, tokensOut: 1 })))], predictor: alwaysClears, costOfPass: { profiles: [profile], policy: { allowedModels: ["m"], operatorCeilingModel: "m", minSuccess: 0.5, hardBudget: budget }, taskSignal: () => ({ inputSize: 1, subGoalCount: 1, reversibilityClass: "reversible", priorFailures: 0 }), measuredCostUsd } });
    await routed.generate({ prompt: "x" });
    assert.equal(budget.snapshot().measuredSpentUsd, expected);
  }
});

test("RoutedModelProvider: prompt rewriting invalidates the caller's old stable-prefix offset", async () => {
  let observedStable = "unset";
  const remote = new Fake("remote", () => ({ text: "ok", model: "m", tokensIn: 1, tokensOut: 1 }));
  (remote as { isLocal: boolean }).isLocal = false;
  const routed = new RoutedModelProvider(newSpine(), {
    providers: [reg("p", "standard", 1, remote)], predictor: alwaysClears,
    routerOptions: { egress: (prompt) => { observedStable = prompt.stablePrefix; return { skipped: false, blocked: false, outbound: prompt.stablePrefix + prompt.volatile, rehydrate: (text) => text, inspect: () => ({ flagged: false, blockRecommended: false, novelByCategory: {} }), cacheMissForced: false, surrogateCount: 0 }; } },
    costOfPass: { profiles: [{ model: "m", provider: "p", promptFormat: "markdown", usdPerTask: 0.1, tier: 1, successByBand: { trivial: 0.9 } }], policy: { allowedModels: ["m"], operatorCeilingModel: "m", minSuccess: 0.5 }, taskSignal: () => ({ inputSize: 1, subGoalCount: 1, reversibilityClass: "reversible", priorFailures: 0 }) },
  });
  await routed.generate({ prompt: "private", hints: { stablePrefixLen: 7 } });
  assert.equal(observedStable, "", "an offset for the pre-adaptation prompt is never reused after adaptation");
});

test("RoutedModelProvider: embeddings prefer local, redact remote input, and do not fan out permanent failures", async () => {
  let localCalls = 0, remoteCalls = 0, remoteText = "";
  const local: ModelProvider = { name: "local", isLocal: true, async generate() { return { text: "", model: "", tokensIn: 0, tokensOut: 0 }; }, async embed() { localCalls++; throw new ProviderError("local unavailable", 503, false); } };
  const remote: ModelProvider = { name: "remote", isLocal: false, async generate() { return { text: "", model: "", tokensIn: 0, tokensOut: 0 }; }, async embed(texts) { remoteCalls++; remoteText = texts[0]!; return [[1]]; } };
  const egress = (prompt: { stablePrefix: string; volatile: string }) => ({ skipped: false, blocked: false, outbound: prompt.volatile.replace("alice@example.com", "[redacted]"), rehydrate: (text: string) => text, inspect: () => ({ flagged: false, blockRecommended: false, novelByCategory: {} }), cacheMissForced: false, surrogateCount: 1 });
  const routed = new RoutedModelProvider(newSpine(), { providers: [reg("remote", "minimal", 1, remote), reg("local", "minimal", 10, local)], predictor: alwaysClears, routerOptions: { egress } });
  assert.deepEqual(await routed.embed(["alice@example.com"]), [[1]]);
  assert.equal(localCalls, 1, "local stays first even when its cost weight is higher");
  assert.equal(remoteCalls, 1);
  assert.equal(remoteText, "[redacted]");

  const permanent: ModelProvider = { ...remote, name: "permanent", async embed() { throw new ProviderError("bad request", 400, true); } };
  const never: ModelProvider = { ...remote, name: "never", async embed() { throw new Error("must not run"); } };
  const stopped = new RoutedModelProvider(newSpine(), { providers: [reg("permanent", "minimal", 1, permanent), reg("never", "minimal", 2, never)], predictor: alwaysClears });
  await assert.rejects(() => stopped.embed(["x"]), (error) => error instanceof ProviderError && error.status === 400);
});

test("RoutedModelProvider: a throwing hint getter cannot leak a budget reservation", async () => {
  const budget = new MeasuredHardRouteBudget(1);
  const hints = {} as Record<string, unknown>;
  Object.defineProperty(hints, "boom", { enumerable: true, get() { throw new Error("getter"); } });
  const routed = new RoutedModelProvider(newSpine(), { providers: [reg("p", "minimal", 1, new Fake("p", () => ({ text: "ok", model: "m", tokensIn: 1, tokensOut: 1 })))], predictor: alwaysClears, costOfPass: { profiles: [{ model: "m", provider: "p", promptFormat: "terse", usdPerTask: 0.1, maxCallCostUsd: 0.5, tier: 1, successByBand: { trivial: 0.9 } }], policy: { allowedModels: ["m"], operatorCeilingModel: "m", minSuccess: 0.5, hardBudget: budget }, taskSignal: () => ({ inputSize: 1, subGoalCount: 1, reversibilityClass: "reversible", priorFailures: 0 }), measuredCostUsd: () => 0.1 } });
  await assert.rejects(() => routed.generate({ prompt: "x", hints }), /getter/u);
  assert.equal(budget.snapshot().reservedUsd, 0);
  assert.equal(budget.snapshot().measuredSpentUsd, 0);
});
