/**
 * Hybrid ranker via weighted Reciprocal Rank Fusion (Increment 14b).
 *
 * SOTA basis (2026-08-05): the dominant, near-universal hybrid-fusion method is RRF — it fuses ranked
 * lists by summing 1/(k+rank) across retrievers (k=60 default), operating on RANK POSITIONS not raw
 * scores. This is decisively better than weighted-sum here: BM25 scores (unbounded TF sums) and
 * graph-proximity scores (hop/degree) live on incompatible scales, and naive normalization "can even
 * make results worse" — one runaway BM25 outlier compresses everything else (Chauzov 2026; every 2026
 * hybrid-search reference agrees). RRF sidesteps score normalization entirely and "requires almost no
 * tuning." Weighted RRF lets us emphasize the lexical path while keeping rank-robustness.
 *
 * The pipeline is the cascaded lexical→graph pattern (LARGER 2026, beats BM25 on localization): BM25
 * seeds → bounded-hop graph expansion → RRF fuse. Scales cleanly to a 3rd (embedding) retriever in
 * 14c — RRF just fuses one more ranked list. Zero deps.
 */

import type { Issue } from "../solve/issue_model.js";
import type { RepoFile, SuspectFile } from "../solve/localize.js";
import { bm25Rank } from "../solve/localize.js";
import { CodeGraph } from "./code_graph.js";

export interface HybridRankOptions {
  /** RRF smoothing constant. 60 is the near-universal default. */
  readonly k?: number;
  /** Weight for the BM25 (lexical) ranked list. Default 1.0. */
  readonly bm25Weight?: number;
  /** Weight for the graph-proximity ranked list. Default 0.7 (lexical-leaning, per ParadeDB guidance). */
  readonly graphWeight?: number;
  /** How many BM25 seeds to expand from. Default 5. */
  readonly seedCount?: number;
  /** Graph expansion hop budget. Default 1 (one-hop is usually enough — SAP GraphRAG 2026). */
  readonly hops?: number;
}

/** A ranked list: ordered file paths, best first. */
export type RankedList = readonly string[];

/**
 * Weighted Reciprocal Rank Fusion over any number of ranked lists. Each list contributes
 * weight / (k + rank) to each of its members; scores sum across lists. Rank-based → no score
 * normalization needed, robust to incompatible score scales.
 */
export function reciprocalRankFusion(lists: readonly { ranking: RankedList; weight: number }[], k = 60): Map<string, number> {
  const fused = new Map<string, number>();
  for (const { ranking, weight } of lists) {
    for (let i = 0; i < ranking.length; i++) {
      const doc = ranking[i]!;
      const contribution = weight / (k + (i + 1)); // rank is 1-based
      fused.set(doc, (fused.get(doc) ?? 0) + contribution);
    }
  }
  return fused;
}

/**
 * The graph-proximity ranked list: starting from the BM25 seed files, collect files reachable within
 * `hops`, ranked by how many seeds reach them (a file structurally close to multiple lexical hits is
 * more suspect). Seeds themselves are included at the top (rank preserved by seed order).
 */
export function graphProximityRanking(seeds: readonly string[], graph: CodeGraph, hops: number): RankedList {
  const reachCount = new Map<string, number>();
  const firstSeedIdx = new Map<string, number>();
  for (let i = 0; i < seeds.length; i++) {
    const seed = seeds[i]!;
    // A seed is maximally proximate to itself.
    bump(reachCount, seed, seeds.length + 1);
    if (!firstSeedIdx.has(seed)) firstSeedIdx.set(seed, i);
    for (const nbr of graph.neighbors(seed, hops)) {
      bump(reachCount, nbr, 1);
      if (!firstSeedIdx.has(nbr)) firstSeedIdx.set(nbr, i);
    }
  }
  // Sort by reach count desc, then by earliest seed index (stable, deterministic).
  return [...reachCount.keys()].sort((a, b) => {
    const d = (reachCount.get(b) ?? 0) - (reachCount.get(a) ?? 0);
    if (d !== 0) return d;
    return (firstSeedIdx.get(a) ?? Infinity) - (firstSeedIdx.get(b) ?? Infinity);
  });
}

function bump(m: Map<string, number>, key: string, by: number): void { m.set(key, (m.get(key) ?? 0) + by); }

/**
 * Hybrid rank: BM25 recall → graph-proximity expansion → weighted RRF fusion. Returns SuspectFiles
 * ordered by fused rank, carrying the BM25 score for audit + the isTest flag.
 */
export function hybridRank(issue: Issue, files: readonly RepoFile[], graph: CodeGraph, opts: HybridRankOptions = {}): SuspectFile[] {
  const k = opts.k ?? 60;
  const seedCount = opts.seedCount ?? 5;
  const hops = opts.hops ?? 1;

  const bm25 = bm25Rank(issue, files);
  const bm25Ranking: RankedList = bm25.map((s) => s.path);
  const seeds = bm25Ranking.slice(0, seedCount);
  const graphRanking = graphProximityRanking(seeds, graph, hops);

  const fused = reciprocalRankFusion([
    { ranking: bm25Ranking, weight: opts.bm25Weight ?? 1.0 },
    { ranking: graphRanking, weight: opts.graphWeight ?? 0.7 },
  ], k);

  // Build SuspectFiles from the fused order, preserving BM25 score + isTest metadata.
  const byPath = new Map(bm25.map((s) => [s.path, s]));
  const fileByPath = new Map(files.map((f) => [f.path, f]));
  const ordered = [...fused.entries()].sort((a, b) => b[1] - a[1]);
  const out: SuspectFile[] = [];
  for (const [path, fusedScore] of ordered) {
    if (!fileByPath.has(path)) continue; // only real files
    const bm = byPath.get(path);
    out.push({
      path,
      score: fusedScore,
      isTest: bm?.isTest ?? isTestPath(path),
    });
  }
  return out;
}

function isTestPath(path: string): boolean {
  return /(^|\/)tests?\//.test(path) || /\.(test|spec)\.[a-z]+$/i.test(path) || /_test\.[a-z]+$/i.test(path);
}
