import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { composeKeep } from "../src/compose.js";
import { assembleSecondBrain } from "../src/personalization/second_brain_system.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { priorPosterior } from "../src/routing/uncertainty_router.js";

// WIRING PROOF: the second-brain subsystem is reachable from composeKeep — not a test-only island.

test("composeKeep exposes an integrated secondBrain subsystem", () => {
  const dataDir = mkdtempSync(join(tmpdir(), "keep-wire-"));
  const app = composeKeep({ dataDir });
  assert.ok(app.secondBrain, "composeKeep wires the second-brain subsystem");
  assert.ok(app.secondBrain.memory, "it has a memory store");
  assert.ok(app.secondBrain.vault, "it has a CI vault");
  assert.ok(app.secondBrain.lenses.companion, "it exposes the lens catalog");
});

test("the wired secondBrain ingests end-to-end into its real memory store", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "keep-wire-"));
  const app = composeKeep({ dataDir });
  const outcome = await app.secondBrain.ingest({ kind: "note", content: "prefers trunk-based dev", subject: "owner" });
  assert.equal(outcome.status, "ingested");
  assert.equal(app.secondBrain.memory.all().filter((l) => l.tier !== "retired").length, 1, "the memory landed in the wired store");
});

test("the wired secondBrain authorizes the owner and anticipates a need", () => {
  const dataDir = mkdtempSync(join(tmpdir(), "keep-wire-"));
  const app = composeKeep({ dataDir });
  const d = app.secondBrain.authorize({ principal: { id: "owner", kind: "human", role: "owner" } }, "write", { surface: "memory", scope: "global" });
  assert.equal(d.allow, true, "the wired owner resolver authorizes the owner (N=1 floor)");
  const decision = app.secondBrain.anticipateNeed({ description: "n", utility: 10, interruptionCost: 1, consequence: "reversible", vettable: true, confidence: priorPosterior() });
  assert.ok(decision.disposition, "anticipation is reachable and returns a disposition");
});

test("assembleSecondBrain composes standalone too (same subsystem, direct)", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-wire-"));
  const spine = new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
  const sb = assembleSecondBrain({ spine, gateway: new ModelGateway(new LocalProvider()) });
  assert.ok(sb.memory && sb.vault && sb.parsers, "the composition root assembles the subsystem");
});
