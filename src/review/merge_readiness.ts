/**
 * Merge-readiness scores and reviewer-effort estimates for triage.
 *
 * Reports security, reliability, complexity, hygiene and coverage. Verification depth follows
 * blast radius: reversible internal changes get light review; irreversible changes get full review.
 * These scores inform review and do not authorize a merge.
 */

import type { DisplayedFinding } from "./finding.js";
import { inlineCount } from "./finding.js";
import type { ActionTier } from "../control/action_tier.js";

export type ReviewDepth = "light" | "standard" | "full";

/** Risk-proportional verification depth from the change's blast-radius tier (R14). */
export function verificationDepth(tier: ActionTier): ReviewDepth {
  switch (tier) {
    case "read-only":
    case "reversible-internal":
      return "light";
    case "external-touching":
      return "standard";
    case "irreversible":
      return "full"; // full heterogeneous + deep scan for high-blast changes
  }
}

export interface EffortSignals {
  readonly linesChanged: number;
  readonly filesTouched: number;
  /** Does the change touch shared/cross-cutting code (helper called from many places)? */
  readonly crossCutting: boolean;
  readonly inlineFindings: number;
}

export type EffortLevel = "trivial" | "moderate" | "high";

/** Predict review effort from cheap signals (#11) — for triage/ordering, never auto-reject. */
export function estimateReviewEffort(s: EffortSignals): EffortLevel {
  let score = 0;
  if (s.linesChanged > 400) score += 2;
  else if (s.linesChanged > 100) score += 1;
  if (s.filesTouched > 10) score += 2;
  else if (s.filesTouched > 3) score += 1;
  if (s.crossCutting) score += 2;
  if (s.inlineFindings > 3) score += 2;
  else if (s.inlineFindings > 0) score += 1;
  if (score >= 5) return "high";
  if (score >= 2) return "moderate";
  return "trivial";
}

/** The five report-card dimensions, each scored 0..1 (1 = healthy). */
export interface ReportCard {
  readonly security: number;
  readonly reliability: number;
  readonly complexity: number;
  readonly hygiene: number;
  readonly coverage: number;
}

export interface MergeReadiness {
  readonly card: ReportCard;
  /** Overall 0..1 readiness (weighted; security/reliability weigh most). */
  readonly overall: number;
  /** Whether anything blocks (inline-blocking finding or failed intent) — human still decides. */
  readonly hasBlockers: boolean;
  readonly reviewDepth: ReviewDepth;
}

export interface MergeReadinessInputs {
  readonly displayed: readonly DisplayedFinding[];
  readonly intentSatisfied: boolean;
  readonly testsPass: boolean;
  readonly coverageRatio: number; // 0..1
  readonly tier: ActionTier;
}

/** Penalty to a 0..1 dimension from findings of a category, scaled by severity. */
function dimensionScore(displayed: readonly DisplayedFinding[], categories: readonly string[]): number {
  let penalty = 0;
  for (const d of displayed) {
    if (!categories.includes(d.finding.category)) continue;
    const sevWeight = d.finding.severity === "critical" ? 0.5 : d.finding.severity === "high" ? 0.3 : d.finding.severity === "medium" ? 0.15 : 0.05;
    penalty += sevWeight;
  }
  return Math.max(0, 1 - penalty);
}

/** Compute the structured merge-readiness report card. Never auto-merges. */
export function computeMergeReadiness(inputs: MergeReadinessInputs): MergeReadiness {
  const card: ReportCard = {
    security: dimensionScore(inputs.displayed, ["security"]),
    reliability: Math.min(
      dimensionScore(inputs.displayed, ["correctness", "regression"]),
      inputs.testsPass ? 1 : 0.3,
    ),
    complexity: dimensionScore(inputs.displayed, ["convention"]),
    hygiene: dimensionScore(inputs.displayed, ["style", "docs"]),
    coverage: inputs.coverageRatio,
  };
  // Weighted overall — security & reliability dominate.
  const overall =
    card.security * 0.3 +
    card.reliability * 0.3 +
    card.complexity * 0.15 +
    card.hygiene * 0.1 +
    card.coverage * 0.15;
  const hasBlockers = inlineCount(inputs.displayed) > 0 || !inputs.intentSatisfied || !inputs.testsPass;
  return { card, overall, hasBlockers, reviewDepth: verificationDepth(inputs.tier) };
}
