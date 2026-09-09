import { test } from "node:test";
import assert from "node:assert/strict";
import { GroundedEstimator, type EstimationSample, type RatesPort } from "../src/autonomy/grounded_estimator.js";
import type { ModelPricing } from "../src/observability/cost_model.js";

const RATES: ModelPricing = { model: "test-model", inputPerMillion: 5, outputPerMillion: 25 };
const ratesOk: RatesPort = async () => RATES;
const ratesDown: RatesPort = async () => null;

function sample(shape: string, over: Partial<EstimationSample> = {}): EstimationSample {
  return { taskShape: shape, inputTokens: 1000, outputTokens: 2000, durationMs: 5000, succeeded: true, ...over };
}

test("too little history -> honest 'not enough data', NO fabricated number", async () => {
  const est = new GroundedEstimator(ratesOk, { minSamples: 3 });
  est.record(sample("novel-chapter"));
  const r = await est.estimate({ taskShape: "novel-chapter", provider: "p", model: "test-model", units: 24 });
  assert.equal(r.grounded, false);
  assert.equal(r.cost, undefined); // never guesses a dollar figure
  assert.match(r.basis, /not have enough measured history|rather not guess/i);
  assert.equal(r.sampleCount, 1);
});

test("history but rates unfetchable -> time-only, NO stale-rate dollars", async () => {
  const est = new GroundedEstimator(ratesDown, { minSamples: 2 });
  est.seed([sample("chap"), sample("chap"), sample("chap")]);
  const r = await est.estimate({ taskShape: "chap", provider: "p", model: "test-model", units: 3 });
  assert.equal(r.grounded, false);
  assert.equal(r.cost, undefined); // refuses to price from stale rates
  assert.ok(r.time); // but honest measured time is offered
  assert.match(r.basis, /couldn't fetch today's|won't state a dollar/i);
});

test("enough measured history + today's rates -> grounded p50<=p90 range", async () => {
  const est = new GroundedEstimator(ratesOk, { minSamples: 3 });
  est.seed([
    sample("ep", { outputTokens: 1000, durationMs: 3000 }),
    sample("ep", { outputTokens: 2000, durationMs: 5000 }),
    sample("ep", { outputTokens: 3000, durationMs: 9000 }),
    sample("ep", { outputTokens: 2500, durationMs: 6000 }),
  ]);
  const r = await est.estimate({ taskShape: "ep", provider: "p", model: "test-model", units: 10 });
  assert.equal(r.grounded, true);
  assert.ok(r.cost && r.cost.p50Usd > 0);
  assert.ok(r.cost!.p90Usd >= r.cost!.p50Usd); // range, not a point
  assert.ok(r.time && r.time.p90Ms >= r.time.p50Ms);
  assert.match(r.basis, /Grounded in 4 measured/);
});

test("two-rate pricing respected: output priced higher than input", async () => {
  const est = new GroundedEstimator(ratesOk, { minSamples: 1 });
  // High-output task-shape vs high-input task-shape, same total tokens.
  est.seed([sample("hi-out", { inputTokens: 100, outputTokens: 5000 })]);
  est.seed([sample("hi-in", { inputTokens: 5000, outputTokens: 100 })]);
  const out = await est.estimate({ taskShape: "hi-out", provider: "p", model: "test-model", units: 1 });
  const inp = await est.estimate({ taskShape: "hi-in", provider: "p", model: "test-model", units: 1 });
  // output is 5x input price, so the high-output task must cost more.
  assert.ok(out.cost!.p50Usd > inp.cost!.p50Usd);
});

test("failure-inflation folded in: past failures raise the p90 tail", async () => {
  const clean = new GroundedEstimator(ratesOk, { minSamples: 3, failureInflation: 3 });
  clean.seed([sample("t"), sample("t"), sample("t")]);
  const withFails = new GroundedEstimator(ratesOk, { minSamples: 3, failureInflation: 3 });
  withFails.seed([sample("t"), sample("t", { succeeded: false }), sample("t", { succeeded: false })]);
  const a = await clean.estimate({ taskShape: "t", provider: "p", model: "test-model", units: 1 });
  const b = await withFails.estimate({ taskShape: "t", provider: "p", model: "test-model", units: 1 });
  assert.ok(b.cost!.p90Usd > a.cost!.p90Usd); // failures inflate the tail
});

test("rates are fetched fresh on every estimate (never remembered)", async () => {
  let calls = 0;
  const counting: RatesPort = async () => {
    calls++;
    return RATES;
  };
  const est = new GroundedEstimator(counting, { minSamples: 1 });
  est.seed([sample("x")]);
  await est.estimate({ taskShape: "x", provider: "p", model: "test-model", units: 1 });
  await est.estimate({ taskShape: "x", provider: "p", model: "test-model", units: 1 });
  assert.equal(calls, 2); // fetched each time, not cached
});

test("knownInputTokens is used exactly when provided", async () => {
  const est = new GroundedEstimator(ratesOk, { minSamples: 2 });
  est.seed([sample("k", { inputTokens: 999999 }), sample("k", { inputTokens: 999999 }), sample("k", { inputTokens: 999999 })]);
  // Provide a tiny known input; the huge historical input should be ignored for input sizing.
  const r = await est.estimate({ taskShape: "k", provider: "p", model: "test-model", units: 1, knownInputTokens: 10 });
  const rHist = await est.estimate({ taskShape: "k", provider: "p", model: "test-model", units: 1 });
  assert.ok(r.cost!.p50Usd < rHist.cost!.p50Usd); // known-small input costs less than historical-huge
});
