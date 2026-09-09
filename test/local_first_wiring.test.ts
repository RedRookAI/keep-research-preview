import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { composeKeep } from "../src/compose.js";
import type { EndpointProbe } from "../src/frontdoor/local_first_defaults.js";

// WIRING PROOF (P0-A #4): the n=1 no-account cold-start path is reachable + consulted.

function sb() {
  return composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-lf-")) }).secondBrain;
}
const reachable: EndpointProbe = async () => ({ reachable: true, modelId: "llama-local" });
const unreachable: EndpointProbe = async () => ({ reachable: false });

test("composeKeep exposes the n=1 cold-start path", () => {
  const s = sb();
  assert.equal(typeof s.resolveLocalFirst, "function");
  assert.equal(typeof s.seedStarter, "function");
});

test("a reachable local model ⇒ local-model plan, no account required", async () => {
  const plan = await sb().resolveLocalFirst(reachable);
  assert.equal(plan.mode, "local-model");
  assert.equal(plan.noAccountRequired, true);
  assert.ok(plan.brain, "a usable local brain is resolved");
});

test("no local model ⇒ deterministic-fallback, but STILL no account demand", async () => {
  const plan = await sb().resolveLocalFirst(unreachable);
  assert.equal(plan.mode, "deterministic-fallback");
  assert.equal(plan.noAccountRequired, true, "the back-of-house operator is never blocked behind an account");
  assert.equal(plan.brain, null);
});

test("the starter corpus seeds into memory at PROBATION (no authority laundering)", async () => {
  const s = sb();
  const seeded = await s.seedStarter();
  assert.ok(seeded.length > 0, "the cold-start corpus is non-empty");
  assert.ok(seeded.every((l) => l.tier === "probation"), "every seed enters at probation, never confirmed");
  assert.ok(s.memory.all().some((l) => l.tier === "probation"), "the seeds landed in the instance's real memory");
});

test("deterministic: resolving twice with the same probe ⇒ same plan mode", async () => {
  const a = await sb().resolveLocalFirst(reachable);
  const b = await sb().resolveLocalFirst(reachable);
  assert.equal(a.mode, b.mode);
});
