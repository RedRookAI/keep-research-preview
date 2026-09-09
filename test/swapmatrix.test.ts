import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { composeKeep, type KeepConfig } from "../src/compose.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { ModelGateway, type ModelProvider } from "../src/gateway/gateway.js";
import { checkBootSecrets, type SecretRequirement } from "../src/boot/secrets.js";

function dataDir(): string {
  return mkdtempSync(join(tmpdir(), "keep-swap-"));
}

/**
 * The core loop the swap-matrix must keep intact under every config:
 * stage a build record -> run a learning tick -> seal -> verify -> retrieve.
 * Returns true iff the loop completed and the chain verifies.
 */
async function runCoreLoop(config: KeepConfig): Promise<boolean> {
  const app = composeKeep(config);
  // 1. stage a build outcome (outcome-keyed, provider-agnostic)
  app.spine.stage({ type: "identity.action", actor: "agent-1", payload: { outcome: "pass", origin: "build#1" } });
  // 2. learning tick fires regardless of provider (heartbeat independence)
  const ticked = await app.heartbeat.runOnce();
  // 3. seal + verify the spine
  await app.spine.seal();
  const verified = app.spine.verify().ok;
  // 4. retrieval path works (embeddings via the gateway, not a hardcoded provider)
  const vecs = await app.gateway.embed(["build outcome pass"]);
  const retrievalOk = vecs.length === 1 && vecs[0]!.length > 0;
  return ticked && verified && retrievalOk;
}

// --- The swap matrix: the learning loop must survive all five configs ---

test("swap-matrix: FULL config keeps the loop intact", async () => {
  let ticks = 0;
  const ok = await runCoreLoop({
    dataDir: dataDir(),
    provider: new LocalProvider(),
    learningTick: async () => {
      ticks++;
    },
  });
  assert.equal(ok, true);
  assert.equal(ticks, 1);
});

test("swap-matrix: NO-CLAW (provider swapped) keeps the loop intact", async () => {
  // A different provider stands in for "claw removed". The heartbeat must still fire.
  const stub: ModelProvider = {
    name: "stub",
    isLocal: true,
    generate: async () => ({ text: "", model: "stub", tokensIn: 0, tokensOut: 0 }),
    embed: async (texts) => texts.map(() => [1, 0, 0]),
  };
  const ok = await runCoreLoop({ dataDir: dataDir(), developmentProvider: stub });
  assert.equal(ok, true);
});

test("swap-matrix: NO-OPENROUTER (no external model key) keeps the loop intact", async () => {
  // No provider given -> LocalProvider default -> works with zero external keys.
  const ok = await runCoreLoop({ dataDir: dataDir() });
  assert.equal(ok, true);
});

test("swap-matrix: NO-LINEAR (connector unbound) boots and keeps the loop intact", async () => {
  const reqs: SecretRequirement[] = [
    { name: "LINEAR_API_KEY", klass: "optional-infra", unlocks: "linear", requiredIfBound: "linear" },
  ];
  const app = composeKeep({
    dataDir: dataDir(),
    secretRequirements: reqs,
    bootPolicy: { boundConnectors: [] }, // Linear NOT bound
    hasSecret: () => false,
  });
  // Boot must succeed (no fatal) even though Linear's key is absent.
  assert.equal(app.boot.ok, true);
  assert.equal(app.boot.fatalMissing.length, 0);
  const ok = await runCoreLoop({ dataDir: dataDir() });
  assert.equal(ok, true);
});

test("swap-matrix: AIR-GAPPED (local-only, no egress) keeps the loop intact", async () => {
  const app = composeKeep({ dataDir: dataDir(), provider: new LocalProvider() });
  assert.equal(app.gateway.isLocal, true); // no network egress
  const ok = await runCoreLoop({ dataDir: dataDir(), provider: new LocalProvider() });
  assert.equal(ok, true);
});

// --- Per-coupling-fix tests ---

test("fix#1: heartbeat is independent of the provider (swap can't stop learning)", async () => {
  let ticks = 0;
  const app = composeKeep({ dataDir: dataDir(), learningTick: async () => { ticks++; } });
  await app.heartbeat.runOnce();
  await app.heartbeat.runOnce();
  assert.equal(ticks, 2); // fires regardless of any provider state
});

test("fix#1: a failing tick does not silently stop the loop", async () => {
  let calls = 0;
  const app = composeKeep({
    dataDir: dataDir(),
    learningTick: async () => {
      calls++;
      throw new Error("cycle failed");
    },
  });
  const first = await app.heartbeat.runOnce();
  const second = await app.heartbeat.runOnce();
  assert.equal(first, false); // reported failure, not a crash
  assert.equal(second, false);
  assert.equal(calls, 2); // loop kept running
});

test("fix#2/#4: fitness scoring routes through the gateway, not a hardcoded provider", async () => {
  const app = composeKeep({ dataDir: dataDir(), provider: new LocalProvider() });
  const score = await app.gateway.fitnessScore("hello world", "hello world");
  assert.ok(score > 0.99); // identical text -> ~1.0 cosine
});

test("fix#3: a missing SECURITY INVARIANT fails boot closed", () => {
  const reqs: SecretRequirement[] = [{ name: "MASTER_KEY", klass: "security-invariant" }];
  const r = checkBootSecrets(reqs, { boundConnectors: [] }, () => false);
  assert.equal(r.ok, false);
  assert.deepEqual(r.fatalMissing, ["MASTER_KEY"]);
});

test("fix#3: a bound connector's missing key fails SOFT (degraded, not fatal)", () => {
  const reqs: SecretRequirement[] = [
    { name: "GH_TOKEN", klass: "optional-infra", unlocks: "github", requiredIfBound: "github" },
  ];
  const r = checkBootSecrets(reqs, { boundConnectors: ["github"] }, () => false);
  assert.equal(r.ok, true); // NOT fatal
  assert.equal(r.degraded.length, 1);
  assert.equal(r.degraded[0]?.unlocks, "github");
});

test("licensing guard: a non-commercial default embedding backend is rejected", () => {
  assert.throws(() =>
    ModelGateway.assertUsableDefault({ model: "nv-embed-v2", license: "non-commercial", isLocal: true }),
  );
  // Permissive is fine.
  ModelGateway.assertUsableDefault({ model: "bge-m3", license: "permissive", isLocal: true });
});
