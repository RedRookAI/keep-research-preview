/**
 * Eval report (Increment 16c).
 *
 * SOTA basis (2026-08-05): a credible 2026 eval reports VARIANCE, cost, and failure classes — not a
 * single peak number (appliedtechnologyindex 2026: "variance matters more than peak score"; operators
 * should ask for repeated-run results, failure classes, cost per resolved task, latency to first
 * patch). So this computes Resolve@1 AND Resolve@k across repeated runs with variance, cost-per-
 * resolved-task, a failure-class breakdown, and regression-vs-a-frozen-baseline (reusing the existing
 * computeImprovement). Contamination/reliability caveats are surfaced first-class (SWE-bench Verified is
 * contamination-compromised — OpenAI recommended discontinuing it). Zero deps.
 *
 * What would change it: if the field standardizes a richer scorecard (e.g. latency-to-first-useful-
 * patch percentiles), add fields — the per-instance InstanceRun already carries the raw signals.
 */

import { computeImprovement, type EvalResult, type ImprovementReport } from "../learning/baseline_metric.js";
import type { InstanceRun, FailureClass } from "./harness.js";
import type { Plan } from "../logicvet/deterministic_critics.js";

export interface FailureBreakdown {
  readonly resolved: number;
  readonly gaveUp: number;
  readonly fixIncomplete: number;
  readonly regression: number;
  readonly fixIncompleteAndRegression: number;
}

export interface EvalReport {
  readonly suiteName: string;
  readonly instanceCount: number;
  /** Resolve@1: fraction resolved on a single run. */
  readonly resolveAt1: number;
  /** Regression rate: fraction where the patch broke a pass-to-pass. */
  readonly regressionRate: number;
  readonly failureBreakdown: FailureBreakdown;
  /** Total + per-resolved-task cost (a headline operational number). */
  readonly totalCostUsd: number;
  readonly costPerResolvedUsd: number;
  /** Mean latency per instance (ms). */
  readonly meanLatencyMs: number;
  /** Dataset caveats (contamination/reliability) surfaced honestly. */
  readonly caveats: readonly string[];
}

/** Build a single-run report from the instance runs of one suite pass. */
export function computeReport(suiteName: string, runs: readonly InstanceRun[], caveats: readonly string[] = []): EvalReport {
  const n = runs.length;
  const resolved = runs.filter((r) => r.verdict.resolved).length;
  const regressions = runs.filter((r) => r.verdict.passToPassRegressed.length > 0).length;
  const totalCostUsd = round(runs.reduce((s, r) => s + r.costUsd, 0));
  const meanLatencyMs = n === 0 ? 0 : round(runs.reduce((s, r) => s + r.latencyMs, 0) / n);

  const fb: FailureBreakdown = {
    resolved,
    gaveUp: countClass(runs, "gave-up"),
    fixIncomplete: countClass(runs, "fix-incomplete"),
    regression: countClass(runs, "regression"),
    fixIncompleteAndRegression: countClass(runs, "fix-incomplete+regression"),
  };

  return {
    suiteName,
    instanceCount: n,
    resolveAt1: n === 0 ? 0 : round(resolved / n),
    regressionRate: n === 0 ? 0 : round(regressions / n),
    failureBreakdown: fb,
    totalCostUsd,
    costPerResolvedUsd: resolved === 0 ? 0 : round(totalCostUsd / resolved),
    meanLatencyMs,
    caveats,
  };
}

export interface ResolveAtKReport {
  readonly k: number;
  /** Resolve@1 for each of the k runs (per-run resolve fractions). */
  readonly perRunResolve: readonly number[];
  /** Mean Resolve@1 across the k runs. */
  readonly meanResolve: number;
  /** Sample standard deviation of Resolve@1 across runs (the variance signal). */
  readonly stddev: number;
  /**
   * Resolve@k in the pass-at-least-once sense: fraction of instances resolved in AT LEAST ONE of the k
   * runs (upper bound on capability; contrast with meanResolve which is the reliable-per-run rate).
   */
  readonly resolveUnion: number;
  /** Fraction resolved in EVERY run (the reliable floor). */
  readonly resolveIntersection: number;
}

/**
 * Compute Resolve@k across repeated runs of the same suite. Each run is the full set of InstanceRuns
 * for one pass; instances are matched across runs by instanceId. Reports mean, variance (stddev), and
 * the union (solved at least once) vs intersection (solved every time) — the honest capability band.
 */
export function computeResolveAtK(runsPerPass: readonly (readonly InstanceRun[])[]): ResolveAtKReport {
  const k = runsPerPass.length;
  if (k === 0) return { k: 0, perRunResolve: [], meanResolve: 0, stddev: 0, resolveUnion: 0, resolveIntersection: 0 };

  const perRunResolve = runsPerPass.map((pass) => (pass.length === 0 ? 0 : pass.filter((r) => r.verdict.resolved).length / pass.length));
  const meanResolve = perRunResolve.reduce((s, x) => s + x, 0) / k;
  const variance = perRunResolve.reduce((s, x) => s + (x - meanResolve) ** 2, 0) / (k > 1 ? k - 1 : 1);
  const stddev = Math.sqrt(variance);

  // Union / intersection per instanceId across passes.
  const ids = new Set<string>();
  for (const pass of runsPerPass) for (const r of pass) ids.add(r.instanceId);
  let union = 0, intersection = 0;
  for (const id of ids) {
    const outcomes = runsPerPass.map((pass) => pass.find((r) => r.instanceId === id)?.verdict.resolved ?? false);
    if (outcomes.some(Boolean)) union++;
    if (outcomes.every(Boolean)) intersection++;
  }
  const total = ids.size || 1;

  return {
    k,
    perRunResolve: perRunResolve.map(round),
    meanResolve: round(meanResolve),
    stddev: round(stddev),
    resolveUnion: round(union / total),
    resolveIntersection: round(intersection / total),
  };
}

/**
 * Regression-vs-frozen-baseline: reuse computeImprovement. A worse config shows a negative delta (or a
 * corroboration conflict if resolve rose while regressions also rose — the Goodhart red flag).
 */
export function compareToBaseline(baseline: EvalReport, current: EvalReport): ImprovementReport {
  const toEval = (r: EvalReport): EvalResult => ({ cleanResolvedRate: r.resolveAt1, regressionRate: r.regressionRate });
  return computeImprovement(toEval(baseline), toEval(current));
}

/** Render a report as human-readable text — honest, variance-aware, cost-aware. */
export function renderReport(report: EvalReport, atK?: ResolveAtKReport): string {
  const fb = report.failureBreakdown;
  const lines = [
    `Eval report — ${report.suiteName} (${report.instanceCount} instances)`,
    ``,
    `Resolve@1:            ${pct(report.resolveAt1)}`,
    ...(atK ? [
      `Resolve@${atK.k} (mean):    ${pct(atK.meanResolve)}  ± ${pct(atK.stddev)} stddev`,
      `  solved at least once: ${pct(atK.resolveUnion)}   solved every run: ${pct(atK.resolveIntersection)}`,
    ] : []),
    `Regression rate:      ${pct(report.regressionRate)}`,
    ``,
    `Failure breakdown:`,
    `  resolved:                    ${fb.resolved}`,
    `  gave up (no patch):          ${fb.gaveUp}`,
    `  fix incomplete:              ${fb.fixIncomplete}`,
    `  regression:                  ${fb.regression}`,
    `  fix-incomplete + regression: ${fb.fixIncompleteAndRegression}`,
    ``,
    `Cost:  $${report.totalCostUsd} total   $${report.costPerResolvedUsd} per resolved task`,
    `Mean latency: ${report.meanLatencyMs} ms/instance`,
  ];
  if (report.caveats.length > 0) {
    lines.push("", "Caveats (read before citing this number):");
    for (const c of report.caveats) lines.push(`  • ${c}`);
  }
  return lines.join("\n");
}

function countClass(runs: readonly InstanceRun[], cls: FailureClass): number {
  return runs.filter((r) => r.failureClass === cls).length;
}
function round(x: number): number { return Math.round(x * 1000) / 1000; }
function pct(x: number): string { return `${(x * 100).toFixed(1)}%`; }

/**
 * NL-FIDELITY-EVAL — an honest decomposition-fidelity eval: did the produced plan/tickets capture the REQUIRED sub-goals
 * of a natural-language request? It reports COVERAGE (which required sub-goals are present vs MISSING — the context-recall
 * axis) AND flags EXTRANEOUS steps (present but not required — the faithfulness/hallucination axis), because these are two
 * different failure modes (futureagi 2026: a 0.91 faithfulness score hid a missing statute because recall wasn't surfaced).
 *
 * A MISSING required sub-goal is a HARD miss: `fullCoverage` is false the moment ANY required sub-goal is absent — never
 * averaged into a passing "mostly covered" number (that is exactly the dashboard failure this guards against). HONEST: it
 * measures decomposition FIDELITY (plan adherence/quality — "was there a sensible route before acting", confident-ai
 * 2026), NOT execution correctness — a faithful plan can still fail to run; it reflects only the real reference-vs-produced
 * comparison (never fabricated); it reports the SOURCE (which sub-goals are missing), not a bare score; report-only,
 * changes no gate. ZERO-DEP.
 */

/** Extract the sub-goals of a produced plan (its step descriptions) — composes Plan/PlanStep. */
export function subGoalsOfPlan(plan: Plan): string[] {
  return plan.steps.map((s) => s.description);
}

export interface DecompositionFidelityInput {
  /** The required sub-goals the NL request implies (the reference — e.g. from an annotated fixture). */
  readonly requiredSubGoals: readonly string[];
  /** The sub-goals actually present in the produced plan/tickets (e.g. via subGoalsOfPlan). */
  readonly producedSubGoals: readonly string[];
}

export interface DecompositionFidelity {
  readonly covered: readonly string[];
  /** Required sub-goals absent from the plan — HARD misses. */
  readonly missing: readonly string[];
  /** Produced steps not attributable to any required sub-goal — flagged (not silently accepted). */
  readonly extraneous: readonly string[];
  /** HARD: true iff EVERY required sub-goal is covered. Any missing ⇒ false (never averaged). */
  readonly fullCoverage: boolean;
  readonly coveredCount: number;
  readonly requiredCount: number;
  /** HONEST: measures decomposition fidelity, NOT execution correctness. */
  readonly measures: "decomposition-fidelity-not-correctness";
  /** HONEST: report-only — changes no gate. */
  readonly changesGate: false;
  readonly summary: string;
}

const norm = (s: string): string => s.trim().toLowerCase();

export function decompositionFidelity(input: DecompositionFidelityInput): DecompositionFidelity {
  const producedSet = new Set(input.producedSubGoals.map(norm));
  const requiredSet = new Set(input.requiredSubGoals.map(norm));
  const covered = input.requiredSubGoals.filter((r) => producedSet.has(norm(r)));
  const missing = input.requiredSubGoals.filter((r) => !producedSet.has(norm(r)));
  const extraneous = input.producedSubGoals.filter((p) => !requiredSet.has(norm(p)));
  // HARD: any missing required sub-goal is a fidelity miss. Never averaged to "mostly covered".
  const fullCoverage = missing.length === 0;

  const summary = `decomposition fidelity: ${covered.length}/${input.requiredSubGoals.length} required covered`
    + (fullCoverage ? " (full)" : ` — MISSING ${missing.length} required sub-goal(s)`)
    + (extraneous.length > 0 ? `; ${extraneous.length} extraneous step(s)` : "")
    + " — measures fidelity, not correctness";

  return { covered, missing, extraneous, fullCoverage, coveredCount: covered.length, requiredCount: input.requiredSubGoals.length, measures: "decomposition-fidelity-not-correctness", changesGate: false, summary };
}
