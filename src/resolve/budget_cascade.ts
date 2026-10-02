/**
 * Try configured candidate-selection tiers, escalating on missing patch evidence
 * or behavioral disagreement. Required generated-test ports are checked before any
 * tier runs; the retained winner keeps its own disagreement status.
 *
 * Costs here are supplied estimates and a trusted canAfford/record port, not a
 * demonstrated provider-billing ceiling. A verified stop means configured checks
 * cleared without a reported fork, not proof of correctness or approval to merge.
 */

import type { Issue, SolveResult } from "../solve/issue_model.js";
import type { CandidateSolver } from "./best_of_n.js";
import { selectBestOfN } from "./best_of_n.js";
import { selectBestOfNWithTests, type TestGenerator, type TestExecutor } from "./novel_tests.js";
import type { TaskComplexity } from "../prompt/prompt_strategy.js";
import type { Spine } from "../spine/spine.js";

export interface ResolutionTier {
  readonly name: string;
  readonly n: number;
  readonly sample: CandidateSolver;
  /** Estimated cost of running this tier, for the budget predicate (grounded, not model guesswork). */
  readonly estCostUsd: number;
  /** Use R3 generated tests at this tier (requires a generator + executor in deps). */
  readonly useTests?: boolean;
}

/** Deterministic budget predicate. Backed by the real BudgetLedger.willBreach at deploy; injected in tests. */
export interface CascadeBudget {
  canAfford(estCostUsd: number): boolean;
  record(estCostUsd: number): void;
}

export interface CascadeDeps {
  readonly tiers: readonly ResolutionTier[];
  readonly budget?: CascadeBudget;
  readonly generator?: TestGenerator;
  readonly executor?: TestExecutor;
  readonly spine?: Spine;
  /** Optional complexity pre-router: an obviously-'complex' ticket skips the cheapest tier (Firewall pre-routing). */
  readonly complexity?: (issue: Issue) => TaskComplexity;
}

export type CascadeStop = "verified" | "exhausted" | "budget";

export interface CascadeResult {
  readonly winner: SolveResult;
  readonly winnerCleared: boolean;
  readonly tiersUsed: readonly string[];
  readonly escalations: number;
  /** True → defer to the human (nothing verified within budget/tiers). The permanent final fallback. */
  readonly escalateToHuman: boolean;
  readonly stoppedReason: CascadeStop;
  readonly behavioralFork: boolean;
}

function startIndex(complexity: TaskComplexity | undefined, nTiers: number): number {
  // Conservative pre-route: only an obviously-'complex' ticket skips the cheapest (doomed) tier.
  return complexity === "complex" && nTiers >= 2 ? 1 : 0;
}

/** Run the budget-aware cascade. */
export async function resolveCascade(deps: CascadeDeps, issue: Issue, opts: { issueText?: string; maxEdits?: number } = {}): Promise<CascadeResult> {
  const tiers = deps.tiers;
  if (tiers.length === 0) throw new Error("resolveCascade requires at least one resolution tier");
  if (tiers.some(tier => tier.useTests) && (!deps.generator || !deps.executor)) throw new Error("generated-test tier requires both generator and executor");

  const start = startIndex(deps.complexity?.(issue), tiers.length);
  const tiersUsed: string[] = [];
  let escalations = 0;
  let best: SolveResult | undefined;
  let bestCleared = false;
  let bestFork = false;

  for (let i = start; i < tiers.length; i++) {
    const tier = tiers[i]!;
    // Budget gate — never spend what we can't afford. Graceful degradation (sovereignty).
    if (deps.budget && !deps.budget.canAfford(tier.estCostUsd)) {
      deps.spine?.stage({ type: "identity.action", actor: "cascade", payload: { event: "resolve.cascade.budget_stop", issueId: issue.id, tier: tier.name, estCostUsd: tier.estCostUsd, ts: Date.now() } });
      return finish(deps, issue, best, bestCleared, tiersUsed, escalations, "budget", bestFork);
    }

    deps.spine?.stage({ type: "identity.action", actor: "cascade", payload: { event: "resolve.cascade.tier", issueId: issue.id, tier: tier.name, n: tier.n, estCostUsd: tier.estCostUsd, ts: Date.now() } });
    tiersUsed.push(tier.name);

    let winner: SolveResult; let cleared: boolean; let fork = false;
    if (tier.useTests && deps.generator && deps.executor) {
      const r = await selectBestOfNWithTests({ sample: tier.sample, generator: deps.generator, executor: deps.executor, ...(deps.spine ? { spine: deps.spine } : {}) }, issue, { n: tier.n, ...(opts.issueText ? { issueText: opts.issueText } : {}), ...(opts.maxEdits !== undefined ? { maxEdits: opts.maxEdits } : {}) });
      winner = r.winner; cleared = r.winnerCleared; fork = r.behavioralFork;
    } else {
      const r = await selectBestOfN({ sample: tier.sample, ...(deps.spine ? { spine: deps.spine } : {}) }, issue, { n: tier.n, ...(opts.issueText ? { issueText: opts.issueText } : {}), ...(opts.maxEdits !== undefined ? { maxEdits: opts.maxEdits } : {}) });
      winner = r.winner; cleared = r.winnerCleared;
    }
    deps.budget?.record(tier.estCostUsd);

    // Keep the best verified result seen (a later cheap-fail shouldn't lose an earlier verified win).
    if (cleared && !bestCleared) { best = winner; bestCleared = true; bestFork = fork; }
    else if (!bestCleared && best === undefined) { best = winner; bestFork = fork; }

    // Success = a verified candidate AND no behavioral fork. Stop (early exit).
    if (cleared && !fork) {
      return finish(deps, issue, winner, true, tiersUsed, escalations, "verified", false);
    }
    // Otherwise escalate (provable failure or behavioral fork) — if a stronger tier exists.
    if (i < tiers.length - 1) {
      escalations++;
      deps.spine?.stage({ type: "identity.action", actor: "cascade", payload: { event: "resolve.cascade.escalate", issueId: issue.id, from: tier.name, reason: fork ? "behavioral-fork" : "no-verified-candidate", ts: Date.now() } });
    }
  }

  return finish(deps, issue, best, bestCleared, tiersUsed, escalations, "exhausted", bestFork);
}

function finish(deps: CascadeDeps, issue: Issue, winner: SolveResult | undefined, cleared: boolean, tiersUsed: string[], escalations: number, stoppedReason: CascadeStop, fork: boolean): CascadeResult {
  const escalateToHuman = stoppedReason !== "verified";
  const result: CascadeResult = {
    winner: winner ?? { issueId: issue.id, solved: false, stagesRun: [], repairRounds: 0, gaveUpReason: "no candidate produced within budget/tiers" },
    winnerCleared: cleared,
    tiersUsed,
    escalations,
    escalateToHuman,
    stoppedReason,
    behavioralFork: fork,
  };
  deps.spine?.stage({ type: "identity.action", actor: "cascade", payload: { event: "resolve.cascade.done", issueId: issue.id, tiersUsed, escalations, stoppedReason, escalateToHuman, winnerCleared: cleared, behavioralFork: fork, ts: Date.now() } });
  return result;
}
