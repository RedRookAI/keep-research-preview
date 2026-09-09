import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";

import { SyntheticSuite, SyntheticInstanceRunner } from "../src/eval/synthetic_suite.js";
import { runInstance, runSuite } from "../src/eval/harness.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-evalh-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

test("INVARIANT: the correct-fix instance runs the real pipeline and the oracle marks it RESOLVED", async () => {
  const suite = new SyntheticSuite();
  const runner = new SyntheticInstanceRunner();
  const tasks = await suite.load();
  const calc = tasks.find((t) => t.instanceId === "calc__add-subtracts")!;
  const spine = newSpine();
  const run = await runInstance(calc, runner, spine);
  assert.equal(run.verdict.resolved, true, run.verdict.reason);
  assert.equal(run.failureClass, "resolved");
  assert.deepEqual(run.verdict.failToPassCleared, ["test_add_2_3_is_5"]);
  assert.equal(run.verdict.passToPassRegressed.length, 0);
});

test("INVARIANT: the unfixable instance → solver gives up → UNRESOLVED, all fail-to-pass missed", async () => {
  const runner = new SyntheticInstanceRunner();
  const tasks = await new SyntheticSuite().load();
  const unfix = tasks.find((t) => t.instanceId === "math__unfixable")!;
  const spine = newSpine();
  const run = await runInstance(unfix, runner, spine);
  assert.equal(run.verdict.resolved, false);
  assert.equal(run.failureClass, "gave-up");
  assert.deepEqual(run.verdict.failToPassMissed, ["test_square_4_is_16"]);
});

test("INVARIANT: every run records cost + latency + trajectory", async () => {
  const runner = new SyntheticInstanceRunner();
  const tasks = await new SyntheticSuite().load();
  const spine = newSpine();
  const run = await runInstance(tasks[0]!, runner, spine, (() => { let t = 0; return () => (t += 5); })());
  assert.ok(run.costUsd > 0, "cost recorded");
  assert.ok(run.latencyMs > 0, "latency recorded");
  assert.ok(run.stagesRun.length > 0, "trajectory recorded");
});

test("INVARIANT: runSuite runs all instances; known resolve count = 2 of 3", async () => {
  const suite = new SyntheticSuite();
  const runner = new SyntheticInstanceRunner();
  const tasks = await suite.load();
  const spine = newSpine();
  const runs = await runSuite(tasks, runner, spine);
  assert.equal(runs.length, 3);
  const resolved = runs.filter((r) => r.verdict.resolved).length;
  assert.equal(resolved, 2, "calc + str resolve; math gives up");
});

test("INVARIANT: the spine has an instance_run event per instance (auditable trajectory)", async () => {
  const suite = new SyntheticSuite();
  const runner = new SyntheticInstanceRunner();
  const tasks = await suite.load();
  const spine = newSpine();
  await runSuite(tasks, runner, spine);
  await spine.seal();
  const events = spine.replay().filter((e) => {
    const p = e.payload as Record<string, unknown>;
    return p["event"] === "instance_run";
  });
  assert.equal(events.length, 3, "one instance_run event per instance");
});

test("suite caveats surface the synthetic/contamination note", async () => {
  const caveats = new SyntheticSuite().caveats();
  assert.ok(caveats.some((c) => /synthetic/.test(c)), "honesty: synthetic suite is flagged, not a real number");
});
