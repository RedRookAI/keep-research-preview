/**
 * GraphLocalizer (Increment 14c) — the graph-backed Localizer that SolvePipeline.localize consumes.
 *
 * Replaces flat BM25 stage-1 with hybrid retrieval: BM25 + graph-proximity (+ optional embedding as a
 * third RRF list), then an optional LLM re-rank/narrow stage 2. Local-first: the code graph is built
 * on-device and nothing is exfiltrated. Implements the same Localizer port as HierarchicalLocalizer,
 * so it's a drop-in upgrade behind the SolvePipeline. Zero deps.
 */

import type { ModelProvider } from "../gateway/gateway.js";
import type { Issue } from "../solve/issue_model.js";
import type { Localizer, LocalizationResult, RepoFile, SuspectFile } from "../solve/localize.js";
import { extractSymbols } from "../solve/localize.js";
import { CodeGraph } from "./code_graph.js";
import { hybridRank, reciprocalRankFusion, graphProximityRanking, type HybridRankOptions } from "./hybrid_rank.js";
import { bm25Rank } from "../solve/localize.js";
import { embeddingRanking, type Embedder } from "./embedding_stage.js";

export type LocalizeStage = "bm25" | "graph" | "embedding" | "llm-rerank";

export interface GraphLocalizerDeps {
  /** Optional LLM for the stage-2 re-rank (behind the gateway; a replay provider here). */
  readonly model?: ModelProvider;
  /** Optional embedder for the third (semantic) RRF list. */
  readonly embedder?: Embedder;
  readonly hybridOptions?: HybridRankOptions;
  /** Candidate pool size for LLM re-rank. */
  readonly candidatePool?: number;
}

export class GraphLocalizer implements Localizer {
  private readonly graph = new CodeGraph();

  constructor(private readonly deps: GraphLocalizerDeps = {}) {}

  async localize(issue: Issue, files: readonly RepoFile[], k: number): Promise<LocalizationResult> {
    // Build/refresh the on-device structure graph (incremental if already built).
    if (this.graph.fileCount === 0) this.graph.build(files);
    else this.graph.update(files);

    const stages: LocalizeStage[] = ["bm25", "graph"];

    // Stage 1: hybrid BM25 + graph proximity (+ embedding if available), fused by RRF.
    let suspects: SuspectFile[];
    if (this.deps.embedder) {
      suspects = await this.hybridWithEmbedding(issue, files, k, stages);
    } else {
      suspects = hybridRank(issue, files, this.graph, this.deps.hybridOptions ?? {});
    }

    if (suspects.length === 0) return { suspects: [], stages };

    // Stage 2 (optional): LLM re-rank + narrow to suspect symbols.
    if (this.deps.model) {
      const reranked = await this.llmRerank(issue, files, suspects, k, stages);
      if (reranked) return { suspects: reranked.slice(0, k), stages };
    }

    return { suspects: suspects.slice(0, k), stages };
  }

  /** Hybrid rank that additionally fuses an embedding-similarity ranked list (RRF, 3 lists). */
  private async hybridWithEmbedding(issue: Issue, files: readonly RepoFile[], k: number, stages: LocalizeStage[]): Promise<SuspectFile[]> {
    const opts = this.deps.hybridOptions ?? {};
    const bm25 = bm25Rank(issue, files);
    const bm25Ranking = bm25.map((s) => s.path);
    const seeds = bm25Ranking.slice(0, opts.seedCount ?? 5);
    const graphRanking = graphProximityRanking(seeds, this.graph, opts.hops ?? 1);

    let embedRanking: readonly string[] = [];
    try {
      embedRanking = await embeddingRanking(issue, files, this.deps.embedder!);
      if (embedRanking.length > 0) stages.push("embedding");
    } catch {
      // embedder failed → fall back to BM25 + graph only (graceful)
      embedRanking = [];
    }

    const fused = reciprocalRankFusion([
      { ranking: bm25Ranking, weight: opts.bm25Weight ?? 1.0 },
      { ranking: graphRanking, weight: opts.graphWeight ?? 0.7 },
      ...(embedRanking.length > 0 ? [{ ranking: embedRanking, weight: 0.9 }] : []),
    ], opts.k ?? 60);

    const byPath = new Map(bm25.map((s) => [s.path, s]));
    const fileByPath = new Map(files.map((f) => [f.path, f]));
    return [...fused.entries()]
      .sort((a, b) => b[1] - a[1])
      .filter(([p]) => fileByPath.has(p))
      .map(([path, score]) => ({ path, score, isTest: byPath.get(path)?.isTest ?? false }));
  }

  /** LLM re-rank over the hybrid candidates (mirrors HierarchicalLocalizer stage 2). */
  private async llmRerank(issue: Issue, files: readonly RepoFile[], suspects: readonly SuspectFile[], k: number, stages: LocalizeStage[]): Promise<SuspectFile[] | undefined> {
    const pool = suspects.slice(0, this.deps.candidatePool ?? Math.max(k * 3, 10));
    const fileByPath = new Map(files.map((f) => [f.path, f]));
    const skeletons = pool.map((s) => {
      const file = fileByPath.get(s.path);
      return `FILE: ${s.path}\nSYMBOLS: ${file ? extractSymbols(file.content).join(", ") || "(none)" : "(none)"}`;
    }).join("\n\n");
    const prompt = [
      `Issue: ${issue.text}`,
      ``,
      `Candidate files (ranked by hybrid retrieval):`,
      skeletons,
      ``,
      `Return STRICT JSON: {"suspects":[{"path":"...","symbols":["fn1"]}]} — the ${k} most likely files to edit, most-likely first. Only paths from the candidates.`,
    ].join("\n");

    let selection: { path: string; symbols?: string[] }[];
    try {
      const res = await this.deps.model!.generate({ prompt, maxTokens: 512 });
      selection = parseSelection(res.text);
      stages.push("llm-rerank");
    } catch {
      return undefined; // graceful — keep the hybrid ranking
    }

    const byPath = new Map(suspects.map((s) => [s.path, s]));
    const merged: SuspectFile[] = [];
    for (const sel of selection) {
      const base = byPath.get(sel.path);
      if (!base) continue;
      merged.push({ ...base, ...(sel.symbols && sel.symbols.length > 0 ? { suspectSymbols: sel.symbols } : {}) });
    }
    return merged.length > 0 ? merged : undefined;
  }
}

function parseSelection(text: string): { path: string; symbols?: string[] }[] {
  const cleaned = text.replace(/```json/gi, "").replace(/```/g, "").trim();
  const start = cleaned.indexOf("{");
  const end = cleaned.lastIndexOf("}");
  if (start === -1 || end === -1) return [];
  try {
    const obj = JSON.parse(cleaned.slice(start, end + 1)) as { suspects?: { path?: unknown; symbols?: unknown }[] };
    return (obj.suspects ?? [])
      .filter((s) => typeof s.path === "string")
      .map((s) => ({ path: s.path as string, ...(Array.isArray(s.symbols) ? { symbols: (s.symbols as unknown[]).filter((x): x is string => typeof x === "string") } : {}) }));
  } catch {
    return [];
  }
}
