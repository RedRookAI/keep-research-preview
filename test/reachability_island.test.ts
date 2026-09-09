import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { sweepIslands, islandRegression, ISLAND_SWEEP_SENTINEL } from "../src/graph/reachability_port.js";

/**
 * REACHABILITY / TYPE-ONLY-ISLAND gate (BUILD-ORDER 8.4).
 *
 * A real `ts.TypeChecker` two-color mark-and-sweep (tools/island_sweep.mjs, reached through the
 * typescript-free src/graph/reachability_port.ts) classifies every module RUNTIME-REACHABLE /
 * TYPE-ONLY-ISLAND / NEEDS-A-HUMAN-LOOK / UNREFERENCED. This gate proves the four things that make
 * the sweep TRUSTWORTHY, each on a FIXED FIXTURE tree (a real runtime chain + a deliberate type-only
 * island + a dynamic-import module + an unreferenced module) so the counts are deterministic:
 *
 *   (a) the erased-edge distinction: `import type` is NOT a runtime edge (the text-classifier bug);
 *   (b) FAIL-CLOSED: a sweep that cannot run THROWS — it never reads as "0 islands, all clear";
 *   (c) the baseline delta: a NEW type-only island (count above the committed baseline) trips;
 *   (d) the HONEST SEAM: a dynamic-import module is NEEDS-A-HUMAN-LOOK, never silently ISLAND.
 *
 * Each assertion is paired to an isolating disproof neuter (see the round's .round-artifacts RED bytes).
 */

// Repo root: dist/test/reachability_island.test.js -> ../.. Fixtures & engine live at their SOURCE paths.
const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");
const fixtureRoot = join(repoRoot, "test", "fixtures", "reachability");
const enginePath = join(repoRoot, "tools", "island_sweep.mjs");
const entry = join(fixtureRoot, "entry.ts");

// The COMMITTED baseline for the fixture: exactly one accepted type-only island (type_island).
const FIXTURE_ISLAND_BASELINE = 1;

function runSweep() {
  return sweepIslands({ root: fixtureRoot, entries: [entry], enginePath });
}

// (a) EDGE-TYPING — `import type` is an erased edge, not a runtime edge.
// Disproof (a): mark `import type` as RUNTIME -> type_island becomes RUNTIME-REACHABLE -> this RED.
test("type-only island: a module reached only via `import type` is TYPE-ONLY-ISLAND, not reachable", () => {
  const res = runSweep();
  assert.equal(res.classes["type_island"], "TYPE-ONLY-ISLAND", "the erased `import type` edge must not count as a runtime edge");
  assert.ok(res.islands.includes("type_island"));
  // The real runtime chain must be RUNTIME-REACHABLE — the sweep is not just flagging everything.
  assert.equal(res.classes["runtime_a"], "RUNTIME-REACHABLE");
  assert.equal(res.classes["runtime_b"], "RUNTIME-REACHABLE");
  assert.equal(res.classes["entry"], "RUNTIME-REACHABLE");
  // A module nobody imports at all is UNREFERENCED, distinct from an island (which HAS an erased importer).
  assert.equal(res.classes["unreferenced"], "UNREFERENCED");
});

// (b) FAIL-CLOSED — a sweep that cannot run must THROW, never certify by silence.
// Disproof (b): make the port swallow the crash and return {islands:[]} -> assert.throws fails -> RED.
test("fail-closed: a crashed/unrunnable sweep throws, it never reads as 0 islands", () => {
  assert.throws(
    () => sweepIslands({ root: fixtureRoot, entries: [entry], enginePath: join(repoRoot, "tools", "island_sweep_DOES_NOT_EXIST.mjs") }),
    /fail-closed/i,
    "a missing/crashed engine must fail closed, not return an empty all-clear",
  );
  // Sanity: the sentinel the port demands is the one the engine actually stamps.
  assert.equal(ISLAND_SWEEP_SENTINEL, "ISLAND-SWEEP-OK");
});

// (c) BASELINE DELTA — a NEW island (count above the committed baseline) is the regression signal.
// The delta mechanism is the PURE islandRegression; kept decoupled from the engine so this test isolates
// to the comparison alone (an engine neuter must not bleed here).
// Disproof (c): neuter islandRegression so a risen count does not trip -> the regressed===true asserts RED.
test("baseline delta: a new type-only island above the committed baseline trips the gate", () => {
  // At the committed fixture baseline (1 == type_island), one island is accepted -> NOT a regression.
  assert.equal(islandRegression(["type_island"], FIXTURE_ISLAND_BASELINE).regressed, false, "one island == baseline is not a regression");
  // A SECOND island appears (a runtime wire silently degraded to import-type-only) -> MUST trip.
  const risen = islandRegression(["type_island", "newly_islanded"], FIXTURE_ISLAND_BASELINE);
  assert.equal(risen.regressed, true, "an island count above baseline is a NEW type-only island and must trip");
  assert.equal(risen.delta, 1);
  // Any rise above baseline trips; a count at-or-below baseline does not.
  assert.equal(islandRegression(["a", "b"], 0).regressed, true);
  assert.equal(islandRegression([], 3).regressed, false);
});

// (d) HONEST SEAM — a dynamic-import module is NEEDS-A-HUMAN-LOOK, never silently ISLAND or live.
// Disproof (d): route the dynamic edge into the island bucket -> dynamic_mod becomes ISLAND -> RED.
test("honest seam: a dynamic-import()-only module is NEEDS-A-HUMAN-LOOK, not an island", () => {
  const res = runSweep();
  assert.equal(res.classes["dynamic_mod"], "NEEDS-A-HUMAN-LOOK", "dynamic import() is not statically decidable — never silently ISLAND");
  assert.ok(res.needsHumanLook.includes("dynamic_mod"));
  assert.ok(!res.islands.includes("dynamic_mod"), "a human-look module must not be counted as a hard island");
});
