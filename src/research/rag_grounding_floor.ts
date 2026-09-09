/**
 * Auto-RAG: retrieval-sufficiency / abstain gate (Increment 5c) — disciplined refusal.
 *
 * SOTA basis (2026-08-04): the core RAG failure is "fabricated responses despite lacking sufficient
 * supporting evidence" — the fix is to jointly assess retrieval SUFFICIENCY and ABSTAIN (GRACE
 * arXiv 2601.04525; Nexumo 2026: "the goal is disciplined refusal"). Context relevance scores
 * whether the retrieved context is sufficient to answer, INDEPENDENT of the generated answer
 * (futureagi: "context relevance is the retriever diagnostic"). So Auto-RAG never answers without
 * evidence: insufficient retrieval → abstain; ungrounded answer → sound fail.
 *
 * This registers into the VerificationCascade as a sound Tier-0, alongside the research-provenance
 * floor (4c) and the LogicVet floor (3.8) — the deterministic floor gates; the model faithfulness
 * gauge only scores. Zero deps.
 */

import { checkGroundedness, type RetrievedChunk, type GroundednessOptions } from "./grounded_answer.js";
import type { VerificationItem, VerificationTier, TierResult } from "../cascade/verification_cascade.js";

export type SufficiencyStatus = "sufficient" | "insufficient";

export interface SufficiencyResult {
  readonly status: SufficiencyStatus;
  readonly reason: string;
  /** The top retrieval score seen (0 if no chunks). */
  readonly topScore: number;
  readonly chunkCount: number;
}

export interface SufficiencyOptions {
  /** Minimum number of retrieved chunks to consider answering. Default 1. */
  readonly minChunks?: number;
  /** Minimum top relevance score to consider retrieval on-topic. Default 0 (BM25 any-hit). */
  readonly minTopScore?: number;
}

/**
 * Assess whether retrieval is sufficient to attempt an answer (the abstain decision). Deterministic:
 * too few chunks, or a top score below the relevance floor, → insufficient → abstain. This is the
 * "don't answer without evidence" gate, run BEFORE trusting any generated answer.
 */
export function assessSufficiency(chunks: readonly RetrievedChunk[], opts: SufficiencyOptions = {}): SufficiencyResult {
  const minChunks = opts.minChunks ?? 1;
  const minTopScore = opts.minTopScore ?? 0;
  const topScore = chunks.reduce((m, c) => Math.max(m, c.score), 0);

  if (chunks.length < minChunks) {
    return { status: "insufficient", reason: `only ${chunks.length} chunk(s) retrieved (< ${minChunks}) — abstain`, topScore, chunkCount: chunks.length };
  }
  if (topScore < minTopScore) {
    return { status: "insufficient", reason: `top relevance ${topScore.toFixed(2)} below floor ${minTopScore} — retrieval off-topic, abstain`, topScore, chunkCount: chunks.length };
  }
  return { status: "sufficient", reason: `${chunks.length} chunk(s), top relevance ${topScore.toFixed(2)}`, topScore, chunkCount: chunks.length };
}

/** Payload for RAG grounding verification: the candidate answer + the chunks it drew from. */
export interface RagVetPayload {
  readonly answer: string;
  readonly chunks: readonly RetrievedChunk[];
  readonly grounding?: GroundednessOptions;
  readonly sufficiency?: SufficiencyOptions;
}

/**
 * TIER 0 — the RAG grounding floor. Sound, deterministic, zero models:
 *  - retrieval insufficient → `fail` (abstain — never answer without evidence).
 *  - answer ungrounded (no sentence traces to a chunk) → `fail` (fabrication).
 *  - answer partially grounded → `undecided` (climb: a brain/human weighs the partial residual).
 *  - fully grounded + sufficient → `pass`.
 * The model faithfulness gauge (if any) is advisory and does not overturn this sound floor.
 */
export class RagGroundingFloorTier implements VerificationTier<RagVetPayload> {
  readonly tier = 0;
  readonly name = "rag-grounding-floor";
  readonly sound = true;
  available(): boolean {
    return true;
  }
  verify(item: VerificationItem<RagVetPayload>): TierResult {
    const { answer, chunks, grounding, sufficiency } = item.payload;

    // 1. sufficiency (abstain-when-insufficient) — checked first.
    const suff = assessSufficiency(chunks, sufficiency ?? {});
    if (suff.status === "insufficient") {
      return { tier: 0, name: this.name, decision: "fail", reason: `abstain: ${suff.reason}`, sound: true, certainty: 1 };
    }

    // 2. groundedness gate (every sentence must trace to a chunk).
    const g = checkGroundedness(answer, chunks, grounding ?? {});
    if (g.status === "ungrounded") {
      return { tier: 0, name: this.name, decision: "fail", reason: `ungrounded answer: ${g.reason}`, sound: true, certainty: 1 };
    }
    if (g.status === "partially-grounded") {
      return { tier: 0, name: this.name, decision: "undecided", reason: `partial grounding (${(g.groundedFraction * 100).toFixed(0)}%): ${g.reason}`, sound: true, certainty: 0.5 };
    }
    return { tier: 0, name: this.name, decision: "pass", reason: g.reason, sound: true, certainty: 1 };
  }
}
