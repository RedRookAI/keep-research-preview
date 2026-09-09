/**
 * Review findings + the two-tier detect->display pipeline (Phase 3 governing law).
 *
 * The law (vetting-refined): run HIGH-RECALL detection internally, then filter to
 * HIGH-PRECISION *display* before a human sees anything — with cost-asymmetry BY
 * FINDING TYPE. Favor recall where a miss is catastrophic (security, correctness);
 * favor precision hard where a miss is cheap (style, convention). A reviewer
 * developers learn to ignore is worse than none, so filtering is upstream of the
 * human — you get broad detection AND low noise.
 *
 * Validated by the 2026 Martian benchmark (300k PRs): most tools optimize precision
 * OR recall, not both; two-tier gets both. F1 is the honest metric.
 */

export type FindingCategory = "security" | "correctness" | "regression" | "convention" | "style" | "docs";

export type Severity = "critical" | "high" | "medium" | "low";

/** Whether a MISS or a FALSE ALARM is the more expensive error for this category. */
export type CostAsymmetry = "recall-favored" | "precision-favored";

export interface Finding {
  readonly id: string;
  readonly category: FindingCategory;
  readonly severity: Severity;
  /** The detector's confidence this is a true finding, 0..1. */
  readonly confidence: number;
  readonly file: string;
  readonly line: number;
  readonly message: string;
  /** Which detector produced it (for heterogeneity/provenance). */
  readonly detector: string;
}

/** How a surfaced finding is presented — the #16 noise-control ladder. */
export type DisplayTier = "inline-blocking" | "collapsed-summary" | "silently-logged";

export interface DisplayedFinding {
  readonly finding: Finding;
  readonly displayTier: DisplayTier;
}

/** Cost-asymmetry class per category: recall for catastrophic-miss, precision for cheap-miss. */
export function costAsymmetry(category: FindingCategory): CostAsymmetry {
  switch (category) {
    case "security":
    case "correctness":
    case "regression":
      return "recall-favored";
    case "convention":
    case "style":
    case "docs":
      return "precision-favored";
  }
}

export interface DisplayThresholds {
  /** Recall-favored categories surface at a LOWER confidence bar (catch more). */
  readonly recallFavoredMinConfidence: number;
  /** Precision-favored categories require HIGH confidence to surface (less noise). */
  readonly precisionFavoredMinConfidence: number;
}

export const DEFAULT_DISPLAY_THRESHOLDS: DisplayThresholds = {
  recallFavoredMinConfidence: 0.3, // security misses are catastrophic -> surface readily
  precisionFavoredMinConfidence: 0.8, // style false alarms are costly -> only if confident
};

/**
 * The two-tier filter: given internally-detected (high-recall) findings, decide what
 * a human sees and how prominently. Recall-favored high-severity -> inline-blocking;
 * recall-favored lower -> collapsed; precision-favored -> only if confident, and
 * never blocking. Below threshold -> silently logged (kept for the learning loop).
 */
export function filterForDisplay(
  findings: readonly Finding[],
  thresholds: DisplayThresholds = DEFAULT_DISPLAY_THRESHOLDS,
): DisplayedFinding[] {
  const out: DisplayedFinding[] = [];
  for (const f of findings) {
    const asymmetry = costAsymmetry(f.category);
    const bar =
      asymmetry === "recall-favored"
        ? thresholds.recallFavoredMinConfidence
        : thresholds.precisionFavoredMinConfidence;

    if (f.confidence < bar) {
      // Below display bar: keep it silently (learning loop can still use it).
      out.push({ finding: f, displayTier: "silently-logged" });
      continue;
    }
    if (asymmetry === "recall-favored" && (f.severity === "critical" || f.severity === "high")) {
      out.push({ finding: f, displayTier: "inline-blocking" });
    } else if (asymmetry === "recall-favored") {
      out.push({ finding: f, displayTier: "collapsed-summary" });
    } else {
      // precision-favored (style/convention): never blocking, at most collapsed.
      out.push({ finding: f, displayTier: "collapsed-summary" });
    }
  }
  return out;
}

/** Count of findings a human would actually see inline (the noise a reviewer feels). */
export function inlineCount(displayed: readonly DisplayedFinding[]): number {
  return displayed.filter((d) => d.displayTier === "inline-blocking").length;
}
