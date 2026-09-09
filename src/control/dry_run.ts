/**
 * Feature #28 — Dry-run mode (Phase 2, the "R" in RAIL; kill-switch layer 4).
 *
 * A first-class run mode: given a proposed plan (a sequence of actions), produce the
 * FULL plan + a predicted diff/effect + a cost estimate, with ZERO writes. This is the
 * "propose with evidence, then act" pattern — it builds operator trust before any
 * autonomy is granted. Nothing here touches an adapter, the gate's execute path, or the
 * spine's write path: it only classifies, forecasts, and predicts. writesPerformed is 0
 * by construction.
 *
 * Composes Phase 4 forecasting (#42) for the cost band and Phase 2 action tiering for
 * the per-step approval prediction.
 */

import { classifyProposedAction, isDestructiveKind, type ProposedAction } from "../frontdoor/action_schema.js";
import { forecastTask, type CostBand } from "../observability/forecasting.js";
import type { ActionTier } from "../control/action_tier.js";

export interface PlannedStep {
  readonly action: ProposedAction;
  /** Similar past task costs for this step, if known (drives the cost band). */
  readonly similarPastCosts?: readonly number[];
  /** A short human-readable prediction of what this step would change. */
  readonly predictedEffect?: string;
}

export interface DryRunStep {
  readonly action: ProposedAction;
  readonly tier: ActionTier;
  /** Would this step require a human tap if actually executed? */
  readonly wouldRequireApproval: boolean;
  readonly isDestructive: boolean;
  readonly predictedEffect: string;
  readonly costBand: CostBand;
}

export interface DryRunReport {
  readonly steps: readonly DryRunStep[];
  /** Total predicted cost (sum of p50s) and the worst-case (sum of p95s). */
  readonly totalCostP50: number;
  readonly totalCostP95: number;
  /** How many steps would need the operator's approval if run for real. */
  readonly stepsNeedingApproval: number;
  /** Proven zero — a dry run never writes. */
  readonly writesPerformed: 0;
  /** Plain-language summary for the operator. */
  readonly summary: string;
}

/**
 * Produce a dry-run report for a plan. Pure/read-only: classifies each step, forecasts
 * its cost, and predicts approvals — without executing anything.
 */
export function dryRun(plan: readonly PlannedStep[]): DryRunReport {
  const steps: DryRunStep[] = plan.map((step) => {
    const descriptor = classifyProposedAction(step.action);
    const destructive = isDestructiveKind(step.action.kind);
    const costBand = forecastTask(step.similarPastCosts ?? []);
    return {
      action: step.action,
      tier: descriptor.tier,
      // Irreversible/destructive always need a human; external-touching may, per gate.
      wouldRequireApproval: descriptor.tier === "irreversible" || descriptor.tier === "external-touching",
      isDestructive: destructive,
      predictedEffect: step.predictedEffect ?? defaultEffect(step.action),
      costBand,
    };
  });

  const totalCostP50 = steps.reduce((s, x) => s + x.costBand.p50, 0);
  const totalCostP95 = steps.reduce((s, x) => s + x.costBand.p95, 0);
  const stepsNeedingApproval = steps.filter((s) => s.wouldRequireApproval).length;

  return {
    steps,
    totalCostP50,
    totalCostP95,
    stepsNeedingApproval,
    writesPerformed: 0,
    summary: buildSummary(steps.length, stepsNeedingApproval, totalCostP50, totalCostP95),
  };
}

function defaultEffect(action: ProposedAction): string {
  return `Would perform "${action.kind}"${action.rationale ? ` — ${action.rationale}` : ""}. (predicted; nothing was changed)`;
}

function buildSummary(stepCount: number, needApproval: number, p50: number, p95: number): string {
  const parts = [`This plan has ${stepCount} step${stepCount === 1 ? "" : "s"} and nothing has been changed yet.`];
  if (needApproval > 0) parts.push(`${needApproval} step${needApproval === 1 ? "" : "s"} would need your OK before running.`);
  if (p50 > 0 || p95 > 0) parts.push(`Estimated cost: ~${p50.toFixed(2)} (up to ~${p95.toFixed(2)} worst case).`);
  parts.push("Review it, then tell me to go ahead.");
  return parts.join(" ");
}
