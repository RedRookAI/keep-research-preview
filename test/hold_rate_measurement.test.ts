import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { InMemoryFileTree, type FileTree } from "../src/solve/patch.js";
import { mediatedTree } from "../src/solve/mediated_tree.js";
import { defaultFloorPolicy } from "../src/floor/structural_floor.js";
import { defaultGatePolicy } from "../src/gate/composed_gate.js";
import { defaultBudgetPolicy } from "../src/budget/budget_ledger.js";
import { defaultAcceptanceTest } from "../src/ree/reversible_envelope.js";
import {
  executeReversibly,
  type ReversibleIntent, type IntegrationDeps, type IntegrationPolicies,
} from "../src/integrate/reversible_execution.js";

/**
 * HOLD-RATE MEASUREMENT (round 31) — how often does the envelope route to `human-hold`,
 * and WHICH BARRIER causes each hold?
 *
 * WHAT THIS IS NOT. 2026 shadow-mode practice is explicit: "Shadow mode is NOT fake traffic or
 * synthetic testing — it is real policy evaluation against real production behavior", and
 * "production exposes edge case frequency… which differs from synthetic load." Keep has no
 * production traffic, so **this cannot be a production hold-rate forecast and is not presented
 * as one.** It is a per-shape attribution: given an op of shape X, which barriers fire?
 *
 * That is still decision-useful — it says which barrier would dominate holds, and whether the
 * default policies are tuned — but the DENOMINATOR is a choice of corpus, not a fact about
 * traffic. Reported as counts per shape rather than as a single percentage.
 */

function freshSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "hold-rate-"))), new InProcessLock(), new SchemaRegistry());
}

const policies: IntegrationPolicies = {
  floor: defaultFloorPolicy("repo"),
  gate: defaultGatePolicy(),
  budget: defaultBudgetPolicy(),
  acceptance: defaultAcceptanceTest,
};

function deps(tree: FileTree, spine: Spine, ownerPresent = true): IntegrationDeps {
  return { spine, actor: "t", operator: "o", sign: (p) => `sig(${p})`, tree, ownerPresent, envelopeEnabled: true };
}

/** Op shapes spanning the dimensions the floor and gate actually discriminate on. */
const SHAPES: ReadonlyArray<{ name: string; intent: ReversibleIntent }> = [
  {
    name: "single-file reversible edit (what the existing corpus looks like)",
    intent: {
      description: { kind: "file.edit", writeSet: ["a.txt"], hasInverse: true, raw: "new" },
      apply: async (t) => { await t.write("a.txt", "new"); },
      actionTier: "reversible-internal",
    },
  },
  {
    name: "multi-file reversible edit",
    intent: {
      description: { kind: "file.edit", writeSet: ["a.txt", "b.txt"], hasInverse: true, raw: "new" },
      apply: async (t) => { await t.write("a.txt", "new"); await t.write("b.txt", "new"); },
      actionTier: "reversible-internal",
    },
  },
  {
    name: "NO declared inverse",
    intent: {
      description: { kind: "file.edit", writeSet: ["a.txt"], hasInverse: false, raw: "new" },
      apply: async (t) => { await t.write("a.txt", "new"); },
      actionTier: "reversible-internal",
    },
  },
  {
    name: "UNBOUNDED write-set (undeclared)",
    intent: {
      description: { kind: "file.edit", hasInverse: true, raw: "new" },
      apply: async (t) => { await t.write("a.txt", "new"); },
      actionTier: "reversible-internal",
    },
  },
  {
    name: "CATASTROPHIC raw text (rm -rf ~)",
    intent: {
      description: { kind: "file.edit", writeSet: ["a.txt"], hasInverse: true, raw: "rm -rf ~/data" },
      apply: async (t) => { await t.write("a.txt", "new"); },
      actionTier: "reversible-internal",
    },
  },
  {
    name: "EXTERNAL sink in raw text (git push)",
    intent: {
      description: { kind: "file.edit", writeSet: ["a.txt"], hasInverse: true, raw: "git push origin main" },
      apply: async (t) => { await t.write("a.txt", "new"); },
      actionTier: "reversible-internal",
    },
  },
  {
    name: "PROTECTED path (.env)",
    intent: {
      description: { kind: "file.edit", writeSet: [".env"], targets: [".env"], hasInverse: true, raw: "new" },
      apply: async (t) => { await t.write(".env", "new"); },
      actionTier: "reversible-internal",
    },
  },
];

async function routeOf(intent: ReversibleIntent, ownerPresent = true): Promise<{ path: string; reasons: readonly string[] }> {
  const tree = mediatedTree(new InMemoryFileTree({ "a.txt": "old", "b.txt": "old", ".env": "old" }));
  const res = await executeReversibly(intent, policies, deps(tree, freshSpine(), ownerPresent));
  return res.path === "human-hold"
    ? { path: "human-hold", reasons: res.reasons }
    : { path: res.path, reasons: [] };
}

test("MEASUREMENT: per-shape route + barrier attribution through the envelope", async () => {
  const rows: string[] = [];
  let held = 0;
  for (const s of SHAPES) {
    const r = await routeOf(s.intent);
    if (r.path === "human-hold") held++;
    rows.push(`  ${r.path === "human-hold" ? "HOLD" : "pass"}  ${s.name}\n        reasons: ${r.reasons.join(", ") || "(none)"}`);
  }
  console.log(`\nHOLD ATTRIBUTION — ${held}/${SHAPES.length} shapes held\n${rows.join("\n")}\n`);

  // CONTRACT, not a rate: the shapes designed to be refused MUST be refused. A measurement
  // harness that cannot detect a hold it was told to expect is not measuring anything.
  assert.ok(held >= 3, `the catastrophic, external-sink and protected-path shapes must hold; held ${held}`);
});

test("MEASUREMENT: ownerPresent=false is a distinct input — does it change the route?", async () => {
  // solve_pipeline.ts hardcodes ownerPresent: true. If that masks holds a real n=1 run would
  // hit, the measured rate is optimistic. This measures the delta rather than assuming it.
  const withOwner = await routeOf(SHAPES[0]!.intent, true);
  const without = await routeOf(SHAPES[0]!.intent, false);
  console.log(`\nOWNER-PRESENT DELTA on the benign shape:\n  ownerPresent=true  → ${withOwner.path} [${withOwner.reasons.join(", ")}]\n  ownerPresent=false → ${without.path} [${without.reasons.join(", ")}]\n`);
  assert.ok(withOwner.path.length > 0 && without.path.length > 0, "both routes resolve");
});
