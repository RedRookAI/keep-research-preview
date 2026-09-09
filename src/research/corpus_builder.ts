/**
 * Auto-RAG: retrieval-need detector + CorpusBuilder (Increment 5a).
 *
 * SOTA basis (2026-08-04): RAG grounds generation in retrieved evidence, but the corpus must be
 * built with governance (sanitized/classified/gated) and preserve time boundaries (Nexumo 2026:
 * "a real document presented as current without respecting time boundaries — the citation exists,
 * the grounding does not"). So the CorpusBuilder does NOT re-implement ingestion — it pipes
 * Auto-Research's sources THROUGH the governed 4.5 IngestionPipeline (classify → sanitize →
 * tokenize → chunk → index → ROPA), into the PROJECT-SCOPED corpus (multi-project isolation: the
 * drone corpus never bleeds into the novel corpus). Each source keeps its locator + asOf for
 * time-boundary-aware grounding downstream.
 *
 * Zero deps.
 */

import type { ResearchSource } from "./research_loop.js";
import type { ResearchReport } from "./research_loop.js";

/** Why a project might benefit from a durable retrieval corpus. */
export type RetrievalTrigger =
  | "research-derived" // an Auto-Research pass produced sources worth persisting
  | "reference-heavy" // the goal implies ongoing lookups against a body of material
  | "explicit-corpus-goal" // the goal explicitly asks to build/query a knowledge base
  | "none";

export interface RetrievalNeed {
  readonly needed: boolean;
  readonly triggers: readonly RetrievalTrigger[];
  readonly reason: string;
}

const REFERENCE_RX = /\b(documentation|reference|manual|guidelines|corpus|knowledge base|spec|standard|patent|publication|paper|handbook)\b/i;
const CORPUS_GOAL_RX = /\b(build (a )?(knowledge base|corpus|index)|ingest|rag|retrieval|search (over|across)|query (the )?(docs|corpus))\b/i;

/**
 * Decide whether a durable corpus is warranted. Research-derived is the primary path (if a research
 * pass returned sources, persist them); reference-heavy / explicit-corpus goals also trigger.
 */
export function detectRetrievalNeed(goal: string, research?: ResearchReport): RetrievalNeed {
  const triggers: RetrievalTrigger[] = [];
  if (research && research.searched && research.claims.length > 0) triggers.push("research-derived");
  if (REFERENCE_RX.test(goal)) triggers.push("reference-heavy");
  if (CORPUS_GOAL_RX.test(goal)) triggers.push("explicit-corpus-goal");

  if (triggers.length === 0) {
    return { needed: false, triggers: ["none"], reason: "no durable-corpus signal" };
  }
  return { needed: true, triggers, reason: `corpus warranted: ${triggers.join(", ")}` };
}

/** The governed-ingest surface the CorpusBuilder needs (structural subset of 4.5 IngestionPipeline). */
export interface GovernedCorpus {
  ingest(input: {
    sourceId: string;
    text: string;
    purpose: string;
    lawfulBasis: "consent" | "contract" | "legitimate-interest" | "legal-obligation" | "vital-interest" | "public-task" | "none-declared";
    baseTier?: "public" | "internal" | "confidential" | "regulated";
    subjects?: readonly string[];
    retainUntil?: number;
    chunkSize?: number;
  }): { sourceId: string; chunks: number };
  search(query: string, k?: number): ReadonlyArray<{ chunk: { text: string; sourceId: string; asOf?: string }; score: number }>;
}

/** Result of building/updating the corpus from research. */
export interface CorpusBuildResult {
  readonly need: RetrievalNeed;
  readonly ingested: number; // number of sources ingested
  readonly totalChunks: number;
  readonly skipped: number; // sources with no usable text
  readonly note: string;
}

export class CorpusBuilder {
  /**
   * @param corpus the governed, project-scoped ingestion pipeline (from 4.5) — CorpusBuilder does
   *        NOT bypass governance; every source goes through classify/sanitize/tokenize/ROPA.
   * @param purpose declared processing purpose (default "research-corpus").
   */
  constructor(
    private readonly corpus: GovernedCorpus,
    private readonly purpose: string = "research-corpus",
  ) {}

  /**
   * Ingest Auto-Research's sources into the governed project corpus. Each source's snippet is the
   * indexable text; its locator + asOf travel as metadata for time-boundary grounding. Sources with
   * no text are skipped (counted honestly). Idempotent-ish: sourceId derived from locator/title.
   */
  buildFromResearch(goal: string, report: ResearchReport, opts: { retainUntil?: number } = {}): CorpusBuildResult {
    const need = detectRetrievalNeed(goal, report);
    if (!need.needed) {
      return { need, ingested: 0, totalChunks: 0, skipped: 0, note: "no corpus needed for this goal" };
    }

    // Collect distinct sources from the report's claims' citations (they carry supportingText).
    const sources = sourcesFromReport(report);
    let ingested = 0, totalChunks = 0, skipped = 0;
    for (const s of sources) {
      if (!s.snippet || s.snippet.trim().length === 0) { skipped++; continue; }
      const sourceId = s.locator ?? `title:${s.title}`;
      const res = this.corpus.ingest({
        sourceId,
        text: s.snippet,
        purpose: this.purpose,
        lawfulBasis: "legitimate-interest", // research/reference indexing
        baseTier: "internal",
        ...(opts.retainUntil !== undefined ? { retainUntil: opts.retainUntil } : {}),
      });
      ingested++;
      totalChunks += res.chunks;
    }

    return {
      need,
      ingested,
      totalChunks,
      skipped,
      note: `ingested ${ingested} source(s) into the governed project corpus (${totalChunks} chunks); ${skipped} skipped (no text)`,
    };
  }
}

/** Pull distinct sources out of a research report (from claim citations' supportingText). */
export function sourcesFromReport(report: ResearchReport): ResearchSource[] {
  const seen = new Set<string>();
  const out: ResearchSource[] = [];
  for (const claim of report.claims) {
    for (const cite of claim.citations) {
      const key = cite.locator ?? cite.title;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        title: cite.title,
        ...(cite.locator !== undefined ? { locator: cite.locator } : {}),
        snippet: cite.supportingText ?? "",
        ...(cite.asOf !== undefined ? { asOf: cite.asOf } : {}),
      });
    }
  }
  return out;
}
