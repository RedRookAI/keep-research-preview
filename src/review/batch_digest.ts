/**
 * Feature #20 — Batch review digests (Phase 3).
 *
 * One summary across a batch of PRs (a day's runs) instead of per-PR context-switching,
 * ORDERED by #11 reviewer-effort + #19 merge-readiness so scarce human attention goes
 * where it's most needed: blockers first, then lowest readiness, then highest effort.
 * Reads PR review outcomes (spine-sourced on the connected env; passed in here).
 *
 * Composes estimateReviewEffort (#11) and MergeReadiness (#19). Deterministic.
 */

import { estimateReviewEffort, type EffortLevel, type EffortSignals, type MergeReadiness } from "./merge_readiness.js";

export interface PrReviewItem {
  readonly prId: string;
  readonly title: string;
  readonly readiness: MergeReadiness;
  readonly effortSignals: EffortSignals;
}

export interface DigestEntry {
  readonly prId: string;
  readonly title: string;
  readonly readinessPct: number; // 0..100
  readonly effort: EffortLevel;
  readonly hasBlockers: boolean;
  /** A one-line triage summary. */
  readonly line: string;
}

export interface BatchDigest {
  readonly entries: readonly DigestEntry[]; // in triage order
  readonly total: number;
  readonly blocked: number;
  readonly readyToMerge: number; // no blockers AND high readiness
  readonly summary: string;
}

const EFFORT_RANK: Record<EffortLevel, number> = { high: 2, moderate: 1, trivial: 0 };

/**
 * Build a batch digest across a set of PR reviews, ordered so human attention goes
 * where it's scarce: blockers first, then lowest readiness, then highest effort.
 */
export function buildBatchDigest(items: readonly PrReviewItem[]): BatchDigest {
  const entries: DigestEntry[] = items.map((it) => {
    const effort = estimateReviewEffort(it.effortSignals);
    const readinessPct = Math.round(it.readiness.overall * 100);
    return {
      prId: it.prId,
      title: it.title,
      readinessPct,
      effort,
      hasBlockers: it.readiness.hasBlockers,
      line: oneLiner(it.prId, it.title, readinessPct, effort, it.readiness.hasBlockers),
    };
  });

  // Triage order: blockers first; then lowest readiness; then highest effort.
  entries.sort((a, b) => {
    if (a.hasBlockers !== b.hasBlockers) return a.hasBlockers ? -1 : 1;
    if (a.readinessPct !== b.readinessPct) return a.readinessPct - b.readinessPct;
    return EFFORT_RANK[b.effort] - EFFORT_RANK[a.effort];
  });

  const blocked = entries.filter((e) => e.hasBlockers).length;
  const readyToMerge = entries.filter((e) => !e.hasBlockers && e.readinessPct >= 80).length;

  return {
    entries,
    total: entries.length,
    blocked,
    readyToMerge,
    summary: buildSummary(entries.length, blocked, readyToMerge),
  };
}

function oneLiner(prId: string, title: string, readinessPct: number, effort: EffortLevel, hasBlockers: boolean): string {
  const flag = hasBlockers ? "⚠ blocked" : readinessPct >= 80 ? "✓ ready" : "· needs work";
  return `${prId} ${flag} — ${readinessPct}% ready, ${effort} effort — ${title}`;
}

function buildSummary(total: number, blocked: number, ready: number): string {
  if (total === 0) return "No PRs to review in this batch.";
  const parts = [`${total} PR${total === 1 ? "" : "s"} in this batch.`];
  if (blocked > 0) parts.push(`${blocked} blocked (look at ${blocked === 1 ? "it" : "these"} first).`);
  if (ready > 0) parts.push(`${ready} ready to merge.`);
  parts.push("Ordered so the ones needing you most are at the top.");
  return parts.join(" ");
}
