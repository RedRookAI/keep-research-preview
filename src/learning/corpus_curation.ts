/**
 * Corpus curation against the spine (Phase 3.5).
 *
 * The held-out regression corpus and the frozen eval set are CURATED FROM RECORDED
 * BUILD HISTORY on the spine — not supplied by the caller. This depends on build
 * history existing (Phase 4 streams it at scale), so it is built now against the
 * spine interface and lights up when real outcomes flow. Deterministic rotation
 * mitigates Goodhart overfitting to a fixed set.
 *
 * A build outcome carries: context, cleanResolved, and (for regressions) the
 * structural pattern signature that CAUSED the regression. A shadow-mode
 * RegressionCase then passes a lesson iff the lesson does NOT advocate that pattern.
 */

import { createHash } from "node:crypto";
import type { Spine } from "../spine/spine.js";
import type { RegressionCase } from "./shadow_mode.js";
import type { EvalResult } from "./baseline_metric.js";

export interface BuildOutcome {
  readonly buildId: string;
  readonly context: string;
  readonly cleanResolved: boolean;
  /** If this build regressed, the structural pattern signature that caused it. */
  readonly regressionSignature?: string;
  /** The lesson (if any) that was applied on this build — for attribution. */
  readonly appliedLessonId?: string;
  /**
   * Reasoning provenance (F1.8): which brain/tier produced the PLANNING for this
   * build. The learning loop uses this to know the quality of its own training
   * signal — a lesson distilled under a weak-brain ceiling is flagged so it can be
   * re-examined when a stronger brain becomes available, rather than silently
   * compounding mediocrity into the moat.
   */
  readonly planningBrain?: string;
  readonly planningTier?: string;
  /** True if planning ran under a capability ceiling (best available was < 'rich'). */
  readonly planningDegraded?: boolean;
  readonly ts: number;
}

/** Stage a build outcome to the spine (the real signal curation later reads). */
export function recordBuildOutcome(spine: Spine, outcome: Omit<BuildOutcome, "ts"> & { ts?: number }): string {
  return spine.stage({
    type: "identity.action",
    actor: "build",
    payload: { event: "build.outcome", ...outcome, ts: outcome.ts ?? Date.now() },
  });
}

/** Read all build outcomes back from the spine (deterministic replay). */
export function readBuildOutcomes(spine: Spine): BuildOutcome[] {
  const out: BuildOutcome[] = [];
  for (const e of spine.replay()) {
    const p = e.payload as Record<string, unknown>;
    if (p["event"] === "build.outcome") {
      out.push({
        buildId: String(p["buildId"]),
        context: String(p["context"]),
        cleanResolved: Boolean(p["cleanResolved"]),
        ...(p["regressionSignature"] !== undefined ? { regressionSignature: String(p["regressionSignature"]) } : {}),
        ...(p["appliedLessonId"] !== undefined ? { appliedLessonId: String(p["appliedLessonId"]) } : {}),
        ...(p["planningBrain"] !== undefined ? { planningBrain: String(p["planningBrain"]) } : {}),
        ...(p["planningTier"] !== undefined ? { planningTier: String(p["planningTier"]) } : {}),
        ...(p["planningDegraded"] !== undefined ? { planningDegraded: Boolean(p["planningDegraded"]) } : {}),
        ts: Number(p["ts"] ?? e.ts),
      });
    }
  }
  return out;
}

/**
 * Outcomes whose PLANNING ran under a capability ceiling (a weak brain). The learning
 * loop surfaces these so lessons distilled from them can be re-examined when a
 * stronger brain becomes available — the moat re-examines its own weak-signal history
 * instead of silently compounding it.
 */
export function outcomesWithDegradedPlanning(outcomes: readonly BuildOutcome[]): BuildOutcome[] {
  return outcomes.filter((o) => o.planningDegraded === true);
}

/**
 * Curate the held-out regression corpus from recorded regressions. Each caught
 * regression becomes a RegressionCase whose check FAILS for any lesson that
 * advocates the pattern signature that caused that regression — so shadow-mode
 * auto-revokes a lesson that would reintroduce a known regression.
 */
export function curateRegressionCorpus(outcomes: readonly BuildOutcome[]): RegressionCase[] {
  const seen = new Set<string>();
  const cases: RegressionCase[] = [];
  for (const o of outcomes) {
    if (o.cleanResolved || !o.regressionSignature) continue;
    if (seen.has(o.regressionSignature)) continue;
    seen.add(o.regressionSignature);
    const sig = o.regressionSignature;
    cases.push({
      id: `reg:${o.buildId}:${sig}`,
      // A lesson "passes" this held-out case iff it does NOT advocate the pattern
      // that caused the regression (signature or its human-readable kind).
      passesUnder: (lessonContent: string) => !lessonContent.includes(sig) && !advocatesSignature(lessonContent, sig),
    });
  }
  return cases;
}

/** Heuristic: does a lesson advocate the pattern behind a regression signature? */
function advocatesSignature(lessonContent: string, signature: string): boolean {
  // Signatures look like "op-sub:-->+" / "added-guard" / "boundary:<-><=".
  const kind = signature.split(":")[0] ?? signature;
  const kindPhrases: Record<string, RegExp> = {
    "added-guard": /remove.*(guard|null check)|skip.*(validation|guard)/i,
    "added-error-handling": /remove.*(try|catch|error handling)|ignore errors/i,
    "op-sub": /operator/i,
    "boundary": /boundary|off-by-one/i,
  };
  const rx = kindPhrases[kind];
  return rx ? rx.test(lessonContent) : false;
}

/**
 * Curate the frozen eval set's Clean-Resolved rate from recorded outcomes over a
 * context filter (or all). This is the measured metric the baseline A/B uses.
 */
export function curateEvalSet(outcomes: readonly BuildOutcome[], contextFilter?: string): EvalResult {
  const rows = contextFilter ? outcomes.filter((o) => o.context === contextFilter) : outcomes;
  if (rows.length === 0) return { cleanResolvedRate: 0, regressionRate: 0 };
  const clean = rows.filter((o) => o.cleanResolved).length;
  const regressed = rows.filter((o) => !o.cleanResolved && o.regressionSignature).length;
  return { cleanResolvedRate: clean / rows.length, regressionRate: regressed / rows.length };
}

/**
 * Deterministic k-fold rotation of a corpus, keyed by seed + round, so the held-out
 * set rotates reproducibly (Goodhart mitigation). Returns the fold for `round`.
 */
export function rotateFolds<T>(items: readonly T[], k: number, round: number, seed = "keep"): T[] {
  if (k <= 0) throw new Error("k must be >= 1");
  const fold = ((round % k) + k) % k;
  return items.filter((_, idx) => bucket(String(idx), seed, k) === fold);
}

function bucket(key: string, seed: string, k: number): number {
  const h = createHash("sha256").update(`${seed}:${key}`).digest();
  // Use the first 4 bytes as an unsigned int.
  const n = ((h[0]! << 24) | (h[1]! << 16) | (h[2]! << 8) | h[3]!) >>> 0;
  return n % k;
}
