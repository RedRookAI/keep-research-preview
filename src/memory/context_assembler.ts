/**
 * CONTEXT ASSEMBLER (M2) — retrieve-and-construct: the wire that feeds memory into the harness.
 *
 * The learning loop already LEARNS and MAINTAINS memory (spine, crypto-shred, lessons, consolidation, drift
 * guards). What was missing — the audit's true delta — is ASSEMBLY: pulling the relevant slice of memory into the
 * prompt at harness-construction time. Today `MemoryStore.retrieve` is wired into no prompt path and
 * `AdaptivePromptLayer.durableContext` is caller-supplied. This module is that wire.
 *
 * The design follows the rolling-memory vet (2026 SOTA + Trace Transformation Theory): NOT lossy compaction, but
 * retrieve-then-construct from two persistent tracks — the raw EPISODIC turns (M1, exact detail: the specific
 * number/decision/tool-call) and the distilled SEMANTIC lessons (generalization). Retrieval is NEVER a binary
 * selection: a deterministic weigher tilts the ranking toward episodic for exact-detail queries and toward
 * semantic for general ones, but BOTH tracks always contribute — most queries pull a blend. The assembled slice is
 * REDACTED (egress gate) and TOKEN-BOUNDED (a curated slice beats a full dump — cheaper and less lost-in-the-middle).
 *
 * BUILT + proven in-env: the weighted-blend selection, the token bound, and the egress redaction over injected
 * episodic + semantic sources. SEAM: the embedding backend behind the semantic retriever (a deployment injects a
 * real embedder) and the keyword scorer's sophistication.
 */

import { scanIngestion, type IngestionResult } from "./ingestion.js";
import type { TrustTier } from "./model.js";
import type { EpisodicTurnLog } from "./episodic_turns.js";
import type { MemoryStore } from "./store.js";

/** A semantic-track hit (a distilled lesson), track-agnostic so the assembler stays decoupled from the store. */
export interface SemanticHit {
  readonly id: string;
  readonly text: string;
  readonly score: number;
  readonly tier: TrustTier;
}

/** Pull semantic hits for a query. Adapter over MemoryStore.retrieve; injected for testability. */
export type SemanticRetriever = (query: string, k: number, minTier?: TrustTier) => Promise<readonly SemanticHit[]>;

/** An episodic-track hit (a raw turn), already decrypted + readable (erased turns are omitted upstream). */
export interface EpisodicHit {
  readonly id: string;
  readonly text: string;
  /** 0 = most recent. Recency contributes to the episodic score. */
  readonly recencyRank: number;
  /** Query keyword-overlap score in [0,1]. */
  readonly keywordScore: number;
}

/** Pull episodic hits for a query. Adapter over EpisodicTurnLog; injected for testability. */
export interface EpisodicSource {
  relevant(query: string, limit: number): readonly EpisodicHit[];
}

export interface AssembleQuery {
  readonly query: string;
  readonly kEpisodic?: number;
  readonly kSemantic?: number;
  /** Character budget for the assembled slice (a token proxy). The curated slice is bounded below the full history. */
  readonly charBudget?: number;
  readonly minTier?: TrustTier;
}

export interface SliceItem {
  readonly track: "episodic" | "semantic";
  readonly text: string;
  readonly score: number;
}

export interface BlendWeights {
  readonly episodic: number;
  readonly semantic: number;
}

export interface AssembledContext {
  /** The redacted, bounded slice, ready to pass as AdaptivePromptLayer's `durableContext`. */
  readonly durableContext: string;
  readonly items: readonly SliceItem[];
  readonly weights: BlendWeights;
  readonly redactionFindings: readonly string[];
  readonly truncated: boolean;
}

export interface AssemblerConfig {
  readonly kEpisodic: number;
  readonly kSemantic: number;
  readonly charBudget: number;
}

export const DEFAULT_ASSEMBLER_CONFIG: AssemblerConfig = { kEpisodic: 6, kSemantic: 6, charBudget: 2000 };

/** Exact-detail signals — a query that references specifics wants the raw episodic track. */
const EXACT_SIGNAL = /\d|["'`]|_|::|\/|\b(exact|specific|number|error|line|id|version|hash|value|config)\b/i;
/** Generalization signals — a query about approach/pattern wants the distilled semantic track. */
const GENERAL_SIGNAL = /\b(how|approach|generally|pattern|best practice|strategy|should i|convention|style|prefer)\b/i;

export class ContextAssembler {
  constructor(
    private readonly semantic: SemanticRetriever,
    private readonly episodic: EpisodicSource,
    private readonly redact: (content: string) => IngestionResult = scanIngestion,
    private readonly cfg: AssemblerConfig = DEFAULT_ASSEMBLER_CONFIG,
  ) {}

  /**
   * Deterministic blend weigher. NEVER binary: both tracks always get positive weight, the query only TILTS the
   * ranking. Exact-detail → episodic-heavy; general → semantic-heavy; otherwise balanced. Neutering this (returning
   * zero/one-sided weights) is the disproof for the blend property.
   */
  weigh(query: string): BlendWeights {
    const exact = EXACT_SIGNAL.test(query);
    const general = GENERAL_SIGNAL.test(query);
    if (exact && !general) return { episodic: 0.7, semantic: 0.3 };
    if (general && !exact) return { episodic: 0.3, semantic: 0.7 };
    return { episodic: 0.5, semantic: 0.5 };
  }

  async assemble(q: AssembleQuery): Promise<AssembledContext> {
    const kEpi = q.kEpisodic ?? this.cfg.kEpisodic;
    const kSem = q.kSemantic ?? this.cfg.kSemantic;
    const budget = q.charBudget ?? this.cfg.charBudget;
    const weights = this.weigh(q.query);

    // Pull BOTH tracks (never a binary selection).
    const sem = await this.semantic(q.query, kSem, q.minTier);
    const epi = this.episodic.relevant(q.query, kEpi);

    // Unified ranking under the blend weights. Episodic score folds keyword overlap + recency; semantic uses the
    // store's trust-weighted similarity score.
    const scored: SliceItem[] = [
      ...epi.map((e) => ({
        track: "episodic" as const,
        text: e.text,
        score: (e.keywordScore * 0.7 + recencyScore(e.recencyRank) * 0.3) * weights.episodic,
      })),
      ...sem.map((s) => ({ track: "semantic" as const, text: s.text, score: s.score * weights.semantic })),
    ].sort((a, b) => b.score - a.score);

    // Token-bound: keep highest-scored items until the budget is spent (curated slice < full history).
    const kept: SliceItem[] = [];
    let used = 0;
    let truncated = false;
    for (const it of scored) {
      const cost = it.text.length + 3; // "- " + newline
      if (used + cost > budget) {
        truncated = true;
        continue; // skip this one but keep scanning for smaller high-value items
      }
      kept.push(it);
      used += cost;
    }

    // Egress gate: redact the assembled slice (secrets/PII) before it becomes prompt context that leaves the machine.
    const joined = kept.map((k) => `- ${k.text}`).join("\n");
    const red = this.redact(joined);
    const durableContext = red.decision === "reject" ? "" : red.sanitized;

    return { durableContext, items: kept, weights, redactionFindings: red.findings, truncated };
  }
}

function recencyScore(rank: number): number {
  return 1 / (1 + rank);
}

// ── Adapters over the real stores (compose wires these) ─────────────────────────────────────────────────────

/** Adapt MemoryStore.retrieve into a track-agnostic SemanticRetriever. */
export function semanticRetrieverFromStore(store: MemoryStore): SemanticRetriever {
  return async (query, k, minTier) => {
    const hits = await store.retrieve(query, k, minTier ?? "candidate");
    return hits.map((h) => ({ id: h.lesson.id, text: h.lesson.content, score: h.score, tier: h.lesson.tier }));
  };
}

/**
 * Adapt an EpisodicTurnLog into an EpisodicSource: read the readable (non-erased) turns, score by query
 * keyword-overlap + recency. Erased (crypto-shredded) turns are omitted — memory that was forgotten stays forgotten.
 */
export function episodicSourceFromLog(log: EpisodicTurnLog): EpisodicSource {
  return {
    relevant(query, limit) {
      const terms = tokenize(query);
      const all = log.all();
      const hits: EpisodicHit[] = [];
      for (let i = 0; i < all.length; i++) {
        const rec = all[all.length - 1 - i]!; // newest first → recencyRank = i
        const read = log.read(rec.id);
        if (read.status !== "ok") continue; // skip erased / unreadable
        const text = [read.content.goal, read.content.action ?? "", read.content.outcome ?? ""].filter(Boolean).join(" — ");
        hits.push({ id: rec.id, text, recencyRank: i, keywordScore: keywordOverlap(terms, tokenize(text)) });
      }
      // Rank by keyword then recency; return the top `limit`.
      hits.sort((a, b) => b.keywordScore - a.keywordScore || a.recencyRank - b.recencyRank);
      return hits.slice(0, limit);
    },
  };
}

function tokenize(s: string): Set<string> {
  return new Set(s.toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length >= 3));
}

function keywordOverlap(a: Set<string>, b: Set<string>): number {
  if (a.size === 0) return 0;
  let hit = 0;
  for (const t of a) if (b.has(t)) hit++;
  return hit / a.size;
}
