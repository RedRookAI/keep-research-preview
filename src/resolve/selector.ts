/**
 * Candidate selector (Increment R2) — the hybrid selector that picks among candidates which have ALREADY passed
 * verification. It is applied ONLY to the sound-cleared set, so by construction it can never promote a
 * sound-failing candidate: "selection happens after candidates are verified; it never defines labels and cannot
 * override verifier correctness" (VeRA-H Pro, arXiv 2602.13217). Verification is the floor; this only reorders
 * above it.
 *
 * SOTA basis (2026-08-06):
 *  - Agreement/self-consistency ALONE is not a correctness guarantee — a confident-but-wrong model can collapse
 *    many samples onto the same wrong behavior (SEP, arXiv 2604.06485). So consensus is only ever consulted AMONG
 *    already-verified candidates (verification is the grounding filter).
 *  - Cluster candidates by behavior and score by consensus strength with DIMINISHING RETURNS, √(cluster size), so
 *    a large group of mediocre-but-similar solutions can't dominate (Consistency-meets-Verification, arXiv
 *    2602.10522; CodeT/SRank clustering).
 *  - Consensus is the PRIOR; a challenger overrides only on stronger evidence (ARBITER, arXiv 2605.26172) — here
 *    safety (smaller blast radius) refines ties but does not overturn the consensus cluster.
 *
 * Static proxy: we cluster by the set of touched files (candidates fixing the same location are "the same
 * approach"). Zero deps, deterministic, explainable. What would change it: with a sandbox, execution pass-profiles
 * / output-equivalence clustering (CodeT/SemanticVote) replace the static proxy behind this same port; a
 * cross-model panel would decorrelate errors (arXiv 2607.10139).
 */

import { compareCandidates, type ScoredCandidate, type CandidateSelector, type SelectionResult } from "./best_of_n.js";

/** Default: R1's deterministic tie-break (safety-first). Preserves best-of-N behavior when no hybrid is configured. */
export const DEFAULT_SELECTOR: CandidateSelector = {
  select(cleared) {
    let best = 0;
    for (let i = 1; i < cleared.length; i++) if (compareCandidates(cleared[i]!, cleared[best]!) < 0) best = i;
    return { index: best, rationale: `deterministic tie-break (safety-first) among ${cleared.length} verified candidate(s)` };
  },
};

function approachKey(c: ScoredCandidate): string {
  const files = c.result.prProposal ? [...new Set(c.result.prProposal.edits.map((e) => e.file))].sort() : [];
  return files.join("|") || "<none>";
}

/**
 * Build a hybrid selector that clusters verified candidates by `keyOf` (default: static touched-file "approach";
 * R3 injects a behavioral pass-profile key), prefers the largest consensus cluster (√-damped), and refines ties by
 * safety. Never sees non-verified candidates, so it cannot override the floor.
 */
export function makeHybridSelector(keyOf: (c: ScoredCandidate) => string = approachKey): CandidateSelector {
  return {
    select(cleared) {
      const clusters = new Map<string, number[]>();
      cleared.forEach((c, i) => {
        const k = keyOf(c);
        (clusters.get(k) ?? clusters.set(k, []).get(k)!).push(i);
      });
      const agreement = (i: number): number => {
        for (const idxs of clusters.values()) if (idxs.includes(i)) return Math.sqrt(idxs.length);
        return 1;
      };
      let best = 0;
      for (let i = 1; i < cleared.length; i++) {
        const ai = agreement(i), ab = agreement(best);
        if (ai > ab) { best = i; continue; }
        if (ai === ab && compareCandidates(cleared[i]!, cleared[best]!) < 0) best = i;
      }
      const winningKey = keyOf(cleared[best]!);
      const winningSize = clusters.get(winningKey)?.length ?? 1;
      return { index: best, rationale: `hybrid: chose the '${winningKey}' cluster (consensus of ${winningSize} of ${cleared.length} verified candidates, √-weighted), safety-refined` };
    },
  };
}

/** The default hybrid selector (static touched-file approach clustering). */
export const HybridSelector: CandidateSelector = makeHybridSelector();
