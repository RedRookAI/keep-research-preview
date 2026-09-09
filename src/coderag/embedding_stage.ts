/**
 * Embedding retrieval stage (Increment 14c).
 *
 * SOTA basis (2026-08-05): dense embeddings specifically help NL→PL bug localization — Keep's exact
 * task (issue text is natural language, files are code). "Bug localization tasks that involve NL→PL
 * retrieval showed markedly different behaviour: dense retrieval mostly outperformed sparse" (Practical
 * Code RAG 2026). But dense-only is a black box that breaks on exact symbols (ML Journey 2026), so the
 * embedding stage is ONE ADDITIVE RRF LIST on top of the interpretable BM25 + graph base — never
 * dense-only. Behind an Embedder port: a deterministic hash-embedder here (proves the plumbing,
 * offline, zero-dep), a real small local model (EmbeddingGemma-300M class — runs on modest hardware,
 * good for sovereign/free-tier users) or hosted embeddings on Hetzner.
 *
 * What would change it: a cross-encoder reranker as a final precision stage (hybrid→rerank gave
 * +17.4% Recall@5 in 2026 benchmarks) behind a Reranker port. Zero deps.
 */

import { createHash } from "node:crypto";
import type { Embedding } from "../gateway/gateway.js";
import { cosineSimilarity } from "../gateway/gateway.js";
import type { RepoFile } from "../solve/localize.js";
import type { Issue } from "../solve/issue_model.js";
import type { RankedList } from "./hybrid_rank.js";

/** The embedder port — embeds a batch of texts into vectors. */
export interface Embedder {
  readonly name: string;
  readonly isLocal: boolean;
  embed(texts: readonly string[]): Promise<Embedding[]>;
}

/**
 * A deterministic, offline, zero-dep embedder for testing the retrieval plumbing here. Hashes tokens
 * into a fixed-dim bag-of-hashed-tokens vector — NOT semantic, but deterministic and dependency-free,
 * so the RRF fusion + localizer pipeline is fully provable in the sandbox. Real semantic embeddings
 * (a local EmbeddingGemma-class model, or hosted) replace it behind the same port on Hetzner.
 */
export class DeterministicHashEmbedder implements Embedder {
  readonly name = "deterministic-hash";
  readonly isLocal = true;
  constructor(private readonly dim = 128) {}
  async embed(texts: readonly string[]): Promise<Embedding[]> {
    return texts.map((t) => this.embedOne(t));
  }
  private embedOne(text: string): Embedding {
    const vec = new Array<number>(this.dim).fill(0);
    for (const tok of text.toLowerCase().split(/[^a-z0-9_]+/).filter((x) => x.length > 2)) {
      const h = createHash("sha1").update(tok).digest();
      const idx = ((h[0]! << 8) | h[1]!) % this.dim;
      const sign = (h[2]! & 1) === 0 ? 1 : -1;
      vec[idx] = (vec[idx] ?? 0) + sign;
    }
    // L2 normalize so cosine behaves.
    const norm = Math.sqrt(vec.reduce((s, x) => s + x * x, 0)) || 1;
    return vec.map((x) => x / norm);
  }
}

/**
 * Rank files by embedding cosine similarity to the issue text — the NL→PL semantic channel. Returns a
 * ranked list of file paths (best first). Only files with any embedding signal are included.
 */
export async function embeddingRanking(issue: Issue, files: readonly RepoFile[], embedder: Embedder): Promise<RankedList> {
  if (files.length === 0) return [];
  const [issueVec, ...fileVecs] = await embedder.embed([issue.text, ...files.map((f) => f.content)]);
  if (!issueVec) return [];
  const scored: { path: string; sim: number }[] = [];
  for (let i = 0; i < files.length; i++) {
    const v = fileVecs[i];
    if (!v) continue;
    scored.push({ path: files[i]!.path, sim: cosineSimilarity(issueVec, v) });
  }
  return scored.sort((a, b) => b.sim - a.sim).map((s) => s.path);
}
