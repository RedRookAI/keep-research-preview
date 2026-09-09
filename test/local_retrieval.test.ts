import { test } from "node:test";
import assert from "node:assert/strict";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { compareLocalRetrieval, LOCAL_RETRIEVAL_CASES } from "../src/research/local_retrieval_benchmark.js";

test("GPU-free local retrieval improves over the whole-text hash baseline", async () => {
  const comparison = await compareLocalRetrieval(new LocalProvider());
  assert.equal(comparison.cases, LOCAL_RETRIEVAL_CASES.length);
  assert.equal(comparison.candidateWins, true);
  assert.equal(comparison.candidateRecallAt1, 1);
  assert.ok(comparison.recallAt1Delta > 0, JSON.stringify(comparison));
});

test("local embedding backend remains deterministic, normalized, and swappable", async () => {
  const provider = new LocalProvider();
  const [first, second] = await provider.embed(["retrying failed jobs", "retrying failed jobs"]);
  assert.deepEqual(first, second);
  assert.ok(first);
  const norm = Math.sqrt(first.reduce((sum, value) => sum + value * value, 0));
  assert.ok(Math.abs(norm - 1) < 1e-12);
  assert.deepEqual(provider.info(), { model: "keep-local-feature-hash-v1", license: "permissive", isLocal: true });
});
