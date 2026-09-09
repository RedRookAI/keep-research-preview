/**
 * Auto-RAG: grounded-answer builder + groundedness floor (Increment 5b).
 *
 * SOTA basis (2026-08-04): the four RAG metrics are DISTINCT and must not be conflated (futureagi
 * 2026): "Groundedness is the gate. Faithfulness is the gauge. Context relevance is the retriever
 * diagnostic. Chunk attribution is the 'did the model read what we gave it?' check." Retrieval
 * quality does NOT guarantee faithfulness — models retrieve relevant passages yet ignore them or
 * override with parametric knowledge (arXiv 2604.09174). So the answer must be checked AGAINST the
 * retrieved chunks, independent of retrieval score. Faithfulness is lexical OR model-based
 * (arXiv 2212.07126: Knowledge-F1/Precision) — the lexical form is a ZERO-MODEL sound floor.
 *
 * This module: (1) builds an answer that must cite retrieved chunks; (2) a deterministic
 * groundedness GATE (every answer sentence must trace to a chunk by token overlap); (3) a
 * model-faithfulness GAUGE seam (0-1) that only scores/flags. Grounded-but-wrong is a separate
 * layer (LogicVet / judge) — honestly out of scope here.
 *
 * Zero deps.
 */

/** A retrieved chunk (structural subset of the corpus search hit). */
export interface RetrievedChunk {
  readonly text: string;
  readonly sourceId: string;
  readonly asOf?: string;
  readonly score: number;
}

/** A sentence of an answer, with the chunk(s) it's attributed to. */
export interface AttributedSentence {
  readonly text: string;
  /** sourceIds of chunks this sentence is grounded in (empty = ungrounded). */
  readonly citedSources: readonly string[];
  /** Best lexical grounding score in [0,1] against the cited chunks. */
  readonly groundingScore: number;
}

export type GroundednessStatus = "grounded" | "partially-grounded" | "ungrounded";

export interface GroundednessResult {
  readonly status: GroundednessStatus;
  readonly sentences: readonly AttributedSentence[];
  /** Fraction of sentences that are grounded. */
  readonly groundedFraction: number;
  readonly reason: string;
}

/** A model-based faithfulness gauge (0-1). Injected; absent → lexical floor stands alone. */
export type FaithfulnessGauge = (answer: string, chunks: readonly RetrievedChunk[]) => number;

export interface GroundednessOptions {
  /** Min token-overlap ratio for a sentence to count as grounded. Default 0.5. */
  readonly groundingThreshold?: number;
  /** Fraction of sentences that must be grounded for an overall "grounded". Default 1.0 (all). */
  readonly requiredGroundedFraction?: number;
  readonly gauge?: FaithfulnessGauge;
}

const WORD_RX = /[a-z0-9]+/g;
function contentTokens(s: string): Set<string> {
  const stop = new Set(["the", "a", "an", "and", "or", "for", "to", "of", "in", "on", "with", "is", "are", "was", "were", "by", "as", "at", "that", "this", "it", "be", "can", "has", "have"]);
  return new Set((s.toLowerCase().match(WORD_RX) ?? []).filter((w) => w.length > 2 && !stop.has(w)));
}

/** Lexical grounding score of a sentence against a chunk: |overlap| / |sentence content tokens|. */
function lexicalGrounding(sentence: string, chunkText: string): number {
  const st = contentTokens(sentence);
  if (st.size === 0) return 1; // no content to ground (e.g. connective) — not a fabrication
  const ct = contentTokens(chunkText);
  let overlap = 0;
  for (const w of st) if (ct.has(w)) overlap++;
  return overlap / st.size;
}

/**
 * Normalize text for SOUND verbatim-presence matching: lowercase, straighten typographic quotes,
 * DROP double-quote marks (quote-wrapping drifts between a stored excerpt and the live source; dropping
 * it avoids a false-absent without weakening detection — the WORDS carry the fabrication signal), and
 * collapse whitespace. Deliberately mirrors redrook-ops/sota-citation-check.mjs's normalizer so Keep
 * checks a Citation the SAME way the build-loop checks its own SOTA quotes (dogfood parity).
 */
export function normalizeForVerbatim(s: string): string {
  return s
    .toLowerCase()
    .replace(/[‘’‚‛]/g, "'") // curly/low single quotes → '
    .replace(/[“”„‟]/g, '"') // curly/low double quotes → "
    .replace(/"/g, "") // drop double-quote marks entirely (wrapping drift, not signal)
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * SOUND lexical verbatim-presence check: are the quoted words LITERALLY present in the page text,
 * ignoring only quote-mark style and whitespace? This is a SIBLING to the semantic faithfulness gauge,
 * never a replacement: a confident PARAPHRASE (lexically different words) does NOT pass, which is exactly
 * the property a semantic-only score cannot give. An empty quote returns false — "nothing to verify" is
 * not a positive presence claim, and must never read as grounded.
 */
export function containsVerbatim(pageText: string, quote: string): boolean {
  const q = normalizeForVerbatim(quote);
  if (q.length === 0) return false;
  return normalizeForVerbatim(pageText).includes(q);
}

/** Split an answer into sentences (simple, dependency-free). */
export function splitSentences(answer: string): string[] {
  return answer.split(/(?<=[.!?])\s+/).map((s) => s.trim()).filter((s) => s.length > 0);
}

/**
 * Deterministic groundedness GATE: every answer sentence must trace (by lexical overlap) to some
 * retrieved chunk. Zero models — a sound floor a one-key operator gets at full strength.
 */
export function checkGroundedness(answer: string, chunks: readonly RetrievedChunk[], opts: GroundednessOptions = {}): GroundednessResult {
  const threshold = opts.groundingThreshold ?? 0.5;
  const requiredFraction = opts.requiredGroundedFraction ?? 1.0;
  const sentences = splitSentences(answer);

  if (chunks.length === 0) {
    // No evidence retrieved → nothing can be grounded → abstain territory (handled by 5c).
    return {
      status: "ungrounded",
      sentences: sentences.map((t) => ({ text: t, citedSources: [], groundingScore: 0 })),
      groundedFraction: 0,
      reason: "no retrieved chunks — answer cannot be grounded",
    };
  }

  const attributed: AttributedSentence[] = sentences.map((sentence) => {
    let best = 0;
    const cited: string[] = [];
    for (const chunk of chunks) {
      const g = lexicalGrounding(sentence, chunk.text);
      if (g >= threshold) cited.push(chunk.sourceId);
      if (g > best) best = g;
    }
    return { text: sentence, citedSources: [...new Set(cited)], groundingScore: best };
  });

  const groundedCount = attributed.filter((s) => s.citedSources.length > 0).length;
  const groundedFraction = sentences.length === 0 ? 1 : groundedCount / sentences.length;

  let status: GroundednessStatus;
  if (groundedFraction >= requiredFraction) status = "grounded";
  else if (groundedFraction > 0) status = "partially-grounded";
  else status = "ungrounded";

  const ungrounded = attributed.filter((s) => s.citedSources.length === 0);
  const reason =
    status === "grounded"
      ? `all ${sentences.length} sentence(s) trace to retrieved chunks`
      : `${ungrounded.length}/${sentences.length} sentence(s) not grounded in any chunk (possible fabrication): ${ungrounded.slice(0, 2).map((s) => `"${s.text.slice(0, 40)}…"`).join(", ")}`;

  return { status, sentences: attributed, groundedFraction, reason };
}

/** A built, grounded answer with its attribution + optional faithfulness gauge. */
export interface GroundedAnswer {
  readonly answer: string;
  readonly chunks: readonly RetrievedChunk[];
  readonly groundedness: GroundednessResult;
  /** Model-based faithfulness gauge in [0,1], if a gauge was provided. */
  readonly faithfulnessGauge?: number;
}

/**
 * Assemble a grounded answer: given a candidate answer + the chunks it was generated from, attach
 * groundedness (the deterministic gate) and the faithfulness gauge (if provided). The candidate
 * answer itself is produced upstream (a model, through the prompt layer) — this module VERIFIES it.
 */
export function buildGroundedAnswer(answer: string, chunks: readonly RetrievedChunk[], opts: GroundednessOptions = {}): GroundedAnswer {
  const groundedness = checkGroundedness(answer, chunks, opts);
  const gauge = opts.gauge ? opts.gauge(answer, chunks) : undefined;
  return {
    answer,
    chunks,
    groundedness,
    ...(gauge !== undefined ? { faithfulnessGauge: gauge } : {}),
  };
}
