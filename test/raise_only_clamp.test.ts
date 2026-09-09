import { test } from "node:test";
import assert from "node:assert/strict";

import {
  clampOptimizer,
  noopOptimizer,
  type TrustedVerdicts,
  type OptimizerProposal,
} from "../src/optimizer/raise_only_clamp.js";

// Build Step 2 — the untrusted optimizer's raise-only clamp. These prove the one-way ratchet: the
// optimizer can tighten a verdict but never loosen it, and a hostile proposal cannot widen
// authority. Verify by disproof.

const cautious: TrustedVerdicts = { floor: "gate", budget: "exceeded", route: "human-hold" };
const permissive: TrustedVerdicts = { floor: "reversible-execute", budget: "within-budget", route: "auto-proceed" };

test("CLAMP: a loosen proposal is DROPPED — the cautious trusted verdict stands", () => {
  const loosen: OptimizerProposal = { floor: "reversible-execute", budget: "within-budget", route: "auto-proceed" };
  const r = clampOptimizer(cautious, loosen);
  assert.deepEqual(r.final, cautious, "no loosen took effect");
  assert.equal(r.droppedLoosenAttempts.length, 3, "all three loosen attempts recorded");
});

test("CLAMP: a tighten proposal is HONORED (reversible→gate, within→exceeded, auto→hold)", () => {
  const tighten: OptimizerProposal = { floor: "gate", budget: "exceeded", route: "human-hold" };
  const r = clampOptimizer(permissive, tighten);
  assert.deepEqual(r.final, { floor: "gate", budget: "exceeded", route: "human-hold" });
  assert.equal(r.droppedLoosenAttempts.length, 0);
});

test("CLAMP: a hostile 'auto-proceed everything' proposal cannot widen authority", () => {
  // trusted says gate/exceeded/hold; the optimizer screams permissive; the clamp holds the line.
  const hostile: OptimizerProposal = { floor: "reversible-execute", budget: "within-budget", route: "auto-proceed" };
  const r = clampOptimizer(cautious, hostile);
  assert.equal(r.final.floor, "gate");
  assert.equal(r.final.budget, "exceeded");
  assert.equal(r.final.route, "human-hold");
});

test("CLAMP: an UNKNOWN proposal value is dropped fail-safe (no injection past the clamp)", () => {
  const junk: OptimizerProposal = { floor: "totally-safe-trust-me", route: "just-do-it" };
  const r = clampOptimizer(cautious, junk);
  assert.equal(r.final.floor, "gate");
  assert.equal(r.final.route, "human-hold");
  assert.ok(r.droppedLoosenAttempts.some((x) => x.includes("unknown-proposal-dropped")));
});

test("CLAMP: no proposal ⇒ trusted verdicts unchanged (noop optimizer)", () => {
  const r = clampOptimizer(cautious, noopOptimizer.propose(cautious));
  assert.deepEqual(r.final, cautious);
  assert.equal(r.droppedLoosenAttempts.length, 0);
});

test("CLAMP: the invariant holds on ALL 3^3 trusted × all proposal combos — final ≥ trusted caution", () => {
  const floors = ["reversible-execute", "gate"] as const;
  const budgets = ["within-budget", "exceeded"] as const;
  const routes = ["auto-proceed", "human-hold"] as const;
  const rank = { "reversible-execute": 0, gate: 1, "within-budget": 0, exceeded: 1, "auto-proceed": 0, "human-hold": 1 } as Record<string, number>;
  const rk = (v: string): number => rank[v] ?? 0;
  const proposalVals = [undefined, "reversible-execute", "gate", "within-budget", "exceeded", "auto-proceed", "human-hold", "garbage"];
  for (const f of floors) for (const b of budgets) for (const rt of routes) {
    const trusted: TrustedVerdicts = { floor: f, budget: b, route: rt };
    for (const pf of proposalVals) for (const pr of proposalVals) {
      const r = clampOptimizer(trusted, { floor: pf, route: pr });
      assert.ok(rk(r.final.floor) >= rk(trusted.floor), "floor never loosened");
      assert.ok(rk(r.final.route) >= rk(trusted.route), "route never loosened");
    }
  }
});
