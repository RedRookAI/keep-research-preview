/**
 * Auto-Training: labeling functions + denoising label model (Increment 8b).
 *
 * SOTA basis (2026-08-04): the Snorkel weak-supervision paradigm (Ratner et al.; re-validated for the
 * LLM era — CARE arXiv 2603.00039; MetricGate 2026). A labeling function outputs a label OR abstains
 * (-1). A LABEL MODEL denoises the LF outputs WITHOUT ground truth by estimating each LF's accuracy
 * and down-weighting the unreliable ones — beating majority vote by 2-4pts when accuracies are
 * heterogeneous. CRITICAL correctness trap (MetricGate): the label model assumes LFs are
 * conditionally independent; highly correlated LFs (e.g. regex variants of one rule) violate this and
 * produce OVERCONFIDENT weights — the pairwise-agreement matrix is the standard diagnostic, and
 * redundancy must be flagged/removed BEFORE trusting the labels. LFs must also meet minimum
 * coverage/accuracy floors (Snorkel Drybell). This module encodes all of that. Zero deps.
 */

/** The abstain sentinel (Snorkel convention). */
export const ABSTAIN = -1;

/** A weak label: a class index >= 0, or ABSTAIN. */
export type WeakLabel = number;

/** A labeling function: interpretable heuristic that labels an item or abstains. */
export interface LabelingFunction<T> {
  readonly name: string;
  readonly apply: (item: T) => WeakLabel;
  /** Optional prior accuracy estimate in [0,1]; if unset, estimated from agreement. */
  readonly priorAccuracy?: number;
}

/** Per-LF quality stats over a dataset. */
export interface LfStats {
  readonly name: string;
  /** Fraction of items the LF labeled (did not abstain). */
  readonly coverage: number;
  /** Estimated accuracy in [0,1] (from held-out labels if given, else agreement-based). */
  readonly estimatedAccuracy: number;
  /** True if below the coverage or accuracy floor (excluded from the denoised vote). */
  readonly rejected: boolean;
}

export interface LabelMatrix {
  /** rows = items, cols = LFs; each cell is a WeakLabel. */
  readonly matrix: readonly (readonly WeakLabel[])[];
  readonly lfNames: readonly string[];
}

/** Build the label matrix by applying every LF to every item. */
export function buildLabelMatrix<T>(items: readonly T[], lfs: readonly LabelingFunction<T>[]): LabelMatrix {
  const matrix = items.map((item) => lfs.map((lf) => lf.apply(item)));
  return { matrix, lfNames: lfs.map((lf) => lf.name) };
}

/**
 * Pairwise agreement matrix: for each LF pair, the fraction of items where both voted (non-abstain)
 * and agreed. High off-diagonal values flag redundant/correlated LFs (the conditional-independence
 * violation). Returns a square matrix aligned to lfNames.
 */
export function pairwiseAgreement(lm: LabelMatrix): number[][] {
  const n = lm.lfNames.length;
  const agree: number[][] = Array.from({ length: n }, () => Array<number>(n).fill(0));
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      let both = 0, same = 0;
      for (const row of lm.matrix) {
        const a = row[i]!, b = row[j]!;
        if (a !== ABSTAIN && b !== ABSTAIN) {
          both++;
          if (a === b) same++;
        }
      }
      agree[i]![j] = both === 0 ? 0 : same / both;
    }
  }
  return agree;
}

/**
 * Flag over-correlated LF pairs (agreement above a threshold — likely the same rule restated),
 * which violate conditional independence and cause overconfident label-model weights. Returns the
 * offending pairs so the operator can de-duplicate BEFORE trusting the denoised labels.
 */
export function flagCorrelatedLFs(lm: LabelMatrix, threshold = 0.95): Array<{ a: string; b: string; agreement: number }> {
  const agree = pairwiseAgreement(lm);
  const flagged: Array<{ a: string; b: string; agreement: number }> = [];
  for (let i = 0; i < lm.lfNames.length; i++) {
    const rowI = agree[i]!;
    for (let j = i + 1; j < lm.lfNames.length; j++) {
      const a = rowI[j]!;
      if (a >= threshold) flagged.push({ a: lm.lfNames[i]!, b: lm.lfNames[j]!, agreement: a });
    }
  }
  return flagged;
}

export interface DenoiseOptions {
  /** Minimum coverage for an LF to be included. Default 0.1. */
  readonly coverageFloor?: number;
  /** Minimum estimated accuracy for an LF to be included. Default 0.5 (better than chance). */
  readonly accuracyFloor?: number;
  /** If true, use plain majority vote instead of accuracy-weighting (documented baseline). */
  readonly majorityVoteOnly?: boolean;
  /** Optional held-out gold labels aligned to items — enables unbiased accuracy estimation. */
  readonly gold?: readonly WeakLabel[];
}

export interface DenoiseResult {
  /** The denoised probabilistic label per item (argmax class). */
  readonly labels: readonly WeakLabel[];
  /** Confidence per item in [0,1]. */
  readonly confidence: readonly number[];
  readonly lfStats: readonly LfStats[];
  /** Over-correlated LF pairs flagged (empty = clean). */
  readonly correlatedPairs: ReadonlyArray<{ a: string; b: string; agreement: number }>;
}

/**
 * The LABEL MODEL: denoise LF outputs into per-item labels. Estimates each LF's accuracy (from gold
 * if provided, else from agreement with the majority), rejects LFs below the floors, flags
 * over-correlated LFs, then aggregates by accuracy-weighted log-odds vote (or majority vote if asked).
 * No ground truth required for the estimate; gold sharpens it when available.
 */
export function denoise<T>(items: readonly T[], lfs: readonly LabelingFunction<T>[], opts: DenoiseOptions = {}): DenoiseResult {
  const coverageFloor = opts.coverageFloor ?? 0.1;
  const accuracyFloor = opts.accuracyFloor ?? 0.5;
  const lm = buildLabelMatrix(items, lfs);
  const n = items.length;
  const numLfs = lfs.length;

  // Provisional consensus = majority vote per item (for accuracy estimation when no gold).
  const provisional: WeakLabel[] = lm.matrix.map((row) => majority(row));

  // Per-LF coverage + estimated accuracy.
  const stats: LfStats[] = lfs.map((lf, j) => {
    let labeled = 0, correct = 0, compared = 0;
    for (let i = 0; i < n; i++) {
      const v = lm.matrix[i]![j]!;
      if (v === ABSTAIN) continue;
      labeled++;
      const ref = opts.gold ? opts.gold[i]! : provisional[i]!;
      if (ref !== ABSTAIN) { compared++; if (v === ref) correct++; }
    }
    const coverage = n === 0 ? 0 : labeled / n;
    const estimatedAccuracy = lf.priorAccuracy ?? (compared === 0 ? 0.5 : correct / compared);
    const rejected = coverage < coverageFloor || estimatedAccuracy < accuracyFloor;
    return { name: lf.name, coverage, estimatedAccuracy, rejected };
  });

  const correlatedPairs = flagCorrelatedLFs(lm);

  // Aggregate per item.
  const labels: WeakLabel[] = [];
  const confidence: number[] = [];
  for (let i = 0; i < n; i++) {
    const scores = new Map<number, number>();
    for (let j = 0; j < numLfs; j++) {
      if (stats[j]!.rejected) continue;
      const v = lm.matrix[i]![j]!;
      if (v === ABSTAIN) continue;
      const acc = Math.min(0.999, Math.max(0.001, stats[j]!.estimatedAccuracy));
      // majority vote → weight 1; accuracy-weighted → log-odds of the LF's accuracy.
      const weight = opts.majorityVoteOnly ? 1 : Math.log(acc / (1 - acc));
      scores.set(v, (scores.get(v) ?? 0) + weight);
    }
    if (scores.size === 0) { labels.push(ABSTAIN); confidence.push(0); continue; }
    let best = ABSTAIN, bestScore = -Infinity, total = 0;
    for (const [, s] of scores) total += Math.exp(s);
    for (const [label, s] of scores) if (s > bestScore) { bestScore = s; best = label; }
    labels.push(best);
    confidence.push(total === 0 ? 0 : Math.exp(bestScore) / total);
  }

  return { labels, confidence, lfStats: stats, correlatedPairs };
}

/** Plain majority vote over a row (ignoring abstains); ABSTAIN if no votes. */
function majority(row: readonly WeakLabel[]): WeakLabel {
  const counts = new Map<number, number>();
  for (const v of row) if (v !== ABSTAIN) counts.set(v, (counts.get(v) ?? 0) + 1);
  let best = ABSTAIN, bestCount = 0;
  for (const [label, c] of counts) if (c > bestCount) { bestCount = c; best = label; }
  return best;
}
