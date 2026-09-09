/**
 * Corpus-suite composition — the governed auto-RAG corpus, wired to real ingestion governance.
 *
 * CorpusBuilder is deliberately governance-preserving: it does NOT re-implement ingestion, it pipes research sources
 * THROUGH the project-scoped IngestionPipeline (classify → sanitize → tokenize → chunk → index → ROPA). This factory
 * supplies that real pipeline behind the GovernedCorpus port, and exposes retrieval that returns the exact RetrievedChunk
 * shape the RAG grounding floor grades — so the loop closes: build corpus → retrieve chunks → vetRagAnswer grounds on them.
 *
 * SOTA basis (2026-08-07): a RAG corpus must be built with governance (sanitized/classified/gated), project-isolated
 * (the drone corpus never bleeds into the novel corpus), and time-boundary-aware. What would change it: the current index
 * backend does not thread each source's asOf onto its chunks, so time-boundary metadata is preserved at the source level
 * but not yet per-chunk — a follow-on when the retrieval backend carries chunk-level asOf.
 */

import { CorpusBuilder, detectRetrievalNeed, type GovernedCorpus, type RetrievalNeed, type CorpusBuildResult } from "./corpus_builder.js";
import { IngestionPipeline } from "../ingest/ingestion_pipeline.js";
import { ProjectRegistry } from "../session/project_registry.js";
import { CryptoShredKeyStore } from "../keystore/keystore.js";
import type { ResearchReport } from "./research_loop.js";
import type { RetrievedChunk } from "./grounded_answer.js";

export interface CorpusSuiteConfig {
  /** Shared crypto-shred keystore for project isolation. Default: fresh. */
  readonly keys?: CryptoShredKeyStore;
  /** The corpus project name (isolation boundary). Default "keep-research-corpus". */
  readonly projectName?: string;
  /** Declared processing purpose. Default "research-corpus". */
  readonly purpose?: string;
}

export interface CorpusSuite {
  readonly builder: CorpusBuilder;
  /** Decide whether a durable corpus is warranted for a goal. */
  detectNeed(goal: string, report?: ResearchReport): RetrievalNeed;
  /** Ingest an Auto-Research report's sources into the governed project corpus. */
  buildFromResearch(goal: string, report: ResearchReport, opts?: { retainUntil?: number }): CorpusBuildResult;
  /** Retrieve chunks for a query, in the RetrievedChunk shape the RAG grounding floor grades. */
  retrieve(query: string, k?: number): RetrievedChunk[];
}

export function buildCorpusSuite(cfg: CorpusSuiteConfig = {}): CorpusSuite {
  const registry = new ProjectRegistry(cfg.keys ?? new CryptoShredKeyStore());
  const rec = registry.create(cfg.projectName ?? "keep-research-corpus");
  const ns = registry.namespace(rec.id);
  const ingestion = new IngestionPipeline({ ns });

  // Adapt the IngestionPipeline to the GovernedCorpus port (field-name normalization; no governance bypass).
  const corpus: GovernedCorpus = {
    ingest: (input) => {
      const r = ingestion.ingest(input);
      return { sourceId: r.sourceId, chunks: r.chunksIndexed };
    },
    search: (query, k) =>
      ingestion.search(query, k ?? 5).map((h) => ({ chunk: { text: h.chunk.text, sourceId: h.chunk.sourceId }, score: h.score })),
  };

  const builder = new CorpusBuilder(corpus, cfg.purpose);

  return {
    builder,
    detectNeed: (goal, report) => detectRetrievalNeed(goal, report),
    buildFromResearch: (goal, report, opts) => builder.buildFromResearch(goal, report, opts ?? {}),
    retrieve: (query, k) =>
      ingestion.search(query, k ?? 5).map((h) => ({ text: h.chunk.text, sourceId: h.chunk.sourceId, score: h.score })),
  };
}
