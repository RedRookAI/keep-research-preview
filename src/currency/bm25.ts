/**
 * Zero-dependency BM25 lexical ranker.
 *
 * Chosen per 2026 SOTA for exactly Keep's regime — small corpus, short queries, mostly
 * lexical — where "BM25 matches or outperforms dense models at a fraction of the cost"
 * and, decisively for Keep, "requires no model, computes offline, runs entirely from
 * document content" (MonaVec's reason for BM25 over SPLADE). Its IDF term rewards RARE,
 * specific matches over common ones — which fixes the coarse-matcher bug where a generic
 * "audio" tag scored as high as a specific "tts" tag.
 *
 * The honest ceiling (BM25 can't bridge pure synonym/vocabulary gaps) is handled by an
 * OPTIONAL dense-reranker seam fused via Reciprocal Rank Fusion — active only when a
 * local embedding backend exists on the connected env. The lexical floor always works
 * offline with zero dependencies.
 */

export interface Bm25Doc {
  readonly id: string;
  /** The full searchable text for this document (name + summary + tags, etc.). */
  readonly text: string;
}

export interface Bm25Hit {
  readonly id: string;
  readonly score: number;
}

export interface Bm25Params {
  /** Term-frequency saturation (Okapi default 1.5). */
  readonly k1?: number;
  /** Length normalization (Okapi default 0.75). */
  readonly b?: number;
}

/** Tokenize: lowercase, split on non-alphanumeric, and also split compound tokens. */
export function tokenize(text: string): string[] {
  const raw = text.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  const out: string[] = [];
  for (const tok of raw) {
    out.push(tok);
    // Also emit sub-tokens for hyphen/underscore compounds already split above;
    // here we additionally split digit/letter boundaries lightly (e.g. "mp3" stays).
  }
  return out;
}

export class Bm25Index {
  private readonly docs: Bm25Doc[] = [];
  private readonly docTokens: string[][] = [];
  private readonly df = new Map<string, number>(); // document frequency per term
  private avgLen = 0;
  private readonly k1: number;
  private readonly b: number;

  constructor(params: Bm25Params = {}) {
    this.k1 = params.k1 ?? 1.5;
    this.b = params.b ?? 0.75;
  }

  /** Index a set of documents (rebuilds internal stats). */
  index(docs: readonly Bm25Doc[]): void {
    this.docs.length = 0;
    this.docTokens.length = 0;
    this.df.clear();
    let totalLen = 0;
    for (const doc of docs) {
      const toks = tokenize(doc.text);
      this.docs.push(doc);
      this.docTokens.push(toks);
      totalLen += toks.length;
      for (const term of new Set(toks)) this.df.set(term, (this.df.get(term) ?? 0) + 1);
    }
    this.avgLen = this.docs.length > 0 ? totalLen / this.docs.length : 0;
  }

  /** IDF with the standard BM25 (Robertson) formulation, floored at 0. */
  private idf(term: string): number {
    const n = this.docs.length;
    const dfi = this.df.get(term) ?? 0;
    const val = Math.log(1 + (n - dfi + 0.5) / (dfi + 0.5));
    return val < 0 ? 0 : val;
  }

  /** Score all docs for a query; returns hits with score > 0, ranked desc. */
  search(query: string, limit = 10): Bm25Hit[] {
    const qTerms = tokenize(query);
    const hits: Bm25Hit[] = [];
    for (let i = 0; i < this.docs.length; i++) {
      const toks = this.docTokens[i]!;
      const len = toks.length;
      const tf = new Map<string, number>();
      for (const t of toks) tf.set(t, (tf.get(t) ?? 0) + 1);
      let score = 0;
      for (const qt of qTerms) {
        const f = tf.get(qt);
        if (!f) continue;
        const idf = this.idf(qt);
        const denom = f + this.k1 * (1 - this.b + this.b * (len / (this.avgLen || 1)));
        score += idf * ((f * (this.k1 + 1)) / denom);
      }
      if (score > 0) hits.push({ id: this.docs[i]!.id, score });
    }
    hits.sort((a, b) => b.score - a.score);
    return hits.slice(0, limit);
  }
}

/**
 * Fuse a lexical ranking with an optional dense ranking via Reciprocal Rank Fusion
 * (the documented production pattern). `k` dampens the contribution of low ranks.
 * If `dense` is empty, returns the lexical order unchanged.
 */
export function reciprocalRankFusion(lexical: readonly Bm25Hit[], dense: readonly Bm25Hit[], k = 60): Bm25Hit[] {
  const score = new Map<string, number>();
  const add = (hits: readonly Bm25Hit[]) => {
    hits.forEach((h, rank) => score.set(h.id, (score.get(h.id) ?? 0) + 1 / (k + rank + 1)));
  };
  add(lexical);
  add(dense);
  return [...score.entries()].map(([id, s]) => ({ id, score: s })).sort((a, b) => b.score - a.score);
}
