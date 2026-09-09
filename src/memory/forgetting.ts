/**
 * MEM-DECAY — bounded, explainable DELIBERATE-FORGETTING (Priority Decay) over the bitemporal store. The three SOTA
 * forgetting axes are recency, access-frequency, and importance (arXiv 2512.13564: "Time-based, Frequency-based, and
 * Importance-driven Forgetting"). This ranks each memory's RETENTION PRIORITY and marks only low-value, stale, un-
 * accessed, or expired memories as RETIRED — the store's existing lowest tier, a reversible archival state (NOT a
 * delete), so the audit trail and as-of history survive (Oracle 2026: "invalidate old facts without discarding them,
 * preserving historical accuracy for audit trails").
 *
 * SAFETY GUARDRAIL (the center of the design): forgetting is BOUNDED. A HIGH-IMPORTANCE memory is NEVER retired,
 * regardless of age or access — because "access frequency is a broken proxy for importance for low-frequency, high-
 * stakes data" (mem0 2026: an LRU policy quietly prunes a user's penicillin allergy it hasn't surfaced in six months).
 * A recently-accessed memory is likewise protected. HONEST: importance is DERIVED (tier + evidence), never fabricated;
 * the policy is EXPLAINABLE — it reports what it would retire and WHY, and is a deliberate rule, not a silent cron.
 * COMPOSED over the store's importance/recency/tiers + `retire`; ZERO-DEP; BOTH-TRACKS (n=1 keep-it-lean / org knob).
 */

import type { Lesson } from "./model.js";
import type { MemoryStore } from "./store.js";

export interface AccessInfo {
  /** When this memory was last successfully retrieved/used (access reinforcement). */
  readonly lastAccessedTs?: number;
  /** How many times it has been retrieved (frequency reinforcement). */
  readonly count?: number;
}

export interface ForgetConfig {
  readonly now: number;
  /** Age (by createdTs) beyond which a memory is "stale". */
  readonly staleAgeMs: number;
  /** importance ≥ this ⇒ HIGH-VALUE ⇒ NEVER retired (the rare-but-critical-fact guardrail). Default 0.7. */
  readonly importanceFloor?: number;
  /** importance ≤ this ⇒ "low importance" (eligible with staleness). Default 0.3. */
  readonly lowImportanceCeil?: number;
  /** Accessed/created within this window ⇒ protected regardless of age. Default = staleAgeMs. */
  readonly recencyWindowMs?: number;
}

export interface RetentionDecision {
  readonly lessonId: string;
  readonly retire: boolean;
  /** Human-readable WHY — the explainability requirement (deliberate rule, not a silent side-effect). */
  readonly reason: string;
  /** 0..1 retention priority (higher = keep). */
  readonly priority: number;
}

/** Compute a 0..1 retention priority from recency + access + importance (higher = more worth keeping). */
export function retentionPriority(lesson: Lesson, access: AccessInfo | undefined, cfg: ForgetConfig): number {
  const recencyWindow = cfg.recencyWindowMs ?? cfg.staleAgeMs;
  const age = Math.max(0, cfg.now - lesson.createdTs);
  const recencyScore = Math.max(0, 1 - age / (recencyWindow * 4)); // fades with age, never negative
  const accessTs = access?.lastAccessedTs;
  const accessScore = accessTs !== undefined ? Math.max(0, 1 - Math.max(0, cfg.now - accessTs) / (recencyWindow * 4)) : 0;
  const freqScore = Math.min(1, (access?.count ?? 0) / 5);
  // importance dominates (guardrail); recency/access/frequency modulate.
  return Math.min(1, 0.5 * lesson.importance + 0.2 * recencyScore + 0.2 * accessScore + 0.1 * freqScore);
}

/**
 * EXPLAIN (never mutates): for every live lesson, decide whether it WOULD be retired and WHY. This is the deliberate,
 * auditable rule — the caller can inspect it before applying.
 */
export function explainForgetting(lessons: readonly Lesson[], accessOf: (id: string) => AccessInfo | undefined, cfg: ForgetConfig): RetentionDecision[] {
  const floor = cfg.importanceFloor ?? 0.7;
  const lowCeil = cfg.lowImportanceCeil ?? 0.3;
  const recencyWindow = cfg.recencyWindowMs ?? cfg.staleAgeMs;
  const out: RetentionDecision[] = [];

  for (const l of lessons) {
    if (l.tier === "retired") continue; // already archived
    const access = accessOf(l.id);
    const priority = retentionPriority(l, access, cfg);

    // GUARDRAIL 1: high-importance is NEVER retired (rare-but-critical fact).
    if (l.importance >= floor) { out.push({ lessonId: l.id, retire: false, reason: `high-importance (${l.importance.toFixed(2)} ≥ ${floor}) — never forgotten`, priority }); continue; }

    // GUARDRAIL 2: recently accessed is protected regardless of age.
    const accessTs = access?.lastAccessedTs;
    if (accessTs !== undefined && cfg.now - accessTs <= recencyWindow) { out.push({ lessonId: l.id, retire: false, reason: "recently accessed — protected regardless of age", priority }); continue; }

    // EXPIRED / SUPERSEDED: valid interval closed in the past ⇒ retire.
    if (l.validTo !== undefined && l.validTo <= cfg.now) { out.push({ lessonId: l.id, retire: true, reason: `expired/superseded (valid interval closed at ${l.validTo} ≤ now)`, priority }); continue; }

    // STALE + LOW-IMPORTANCE + un-accessed ⇒ retire.
    const age = cfg.now - l.createdTs;
    const stale = age > cfg.staleAgeMs;
    if (stale && l.importance <= lowCeil) { out.push({ lessonId: l.id, retire: true, reason: `stale (age ${age} > ${cfg.staleAgeMs}) + low-importance (${l.importance.toFixed(2)} ≤ ${lowCeil}) + un-accessed`, priority }); continue; }

    out.push({ lessonId: l.id, retire: false, reason: stale ? "stale but not low-importance — retained" : "recent — retained", priority });
  }
  return out;
}

/** APPLY the policy: retire (supersede-not-delete) each memory the explanation marks. Returns the full decision set. */
export function applyForgetting(store: MemoryStore, accessOf: (id: string) => AccessInfo | undefined, cfg: ForgetConfig): RetentionDecision[] {
  const decisions = explainForgetting(store.all(), accessOf, cfg);
  for (const d of decisions) if (d.retire) store.retire(d.lessonId, `forgetting: ${d.reason}`);
  return decisions;
}
