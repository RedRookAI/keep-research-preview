/**
 * Consolidation (Increment 18.3, Phase G) — the "sleep" pass that manages the ARTIFACT LIFECYCLE so nothing
 * provisional accumulates forever and nothing useful is lost. Learners (18.2) create provisional artifacts
 * (prompt tweaks, lessons, later skills); this closes their lifecycle: PROMOTE the ones that earn trust,
 * PRUNE the ones that had their chance and didn't help, DECAY stale utility, MERGE duplicates.
 *
 * SOTA basis (2026-08-05), all ZERO-DEP:
 *  - GRADIENT-FREE consolidation by recency + frequency + reuse-utility (A-MemGuard dual-memory; the
 *    forgetting-curve / Ebbinghaus). No training, no embedding model — pure counters + decay.
 *  - PRUNE BY OPPORTUNITY, NOT CALENDAR (KEEP_KNOBS_RESOLVED K6): a provisional artifact is pruned only if it
 *    was ELIGIBLE across an opportunity window (~10 relevant tasks) and never helped. A rarely-triggered but
 *    valid artifact is NOT punished for a low-volume operator — it just stays dormant. This protects N=1.
 *  - SESSION-COUNT CADENCE, NO DAEMON (K4): the sleep pass runs every K sessions or on explicit invoke — a
 *    laptop is not always on. Registered on the heartbeat cadence hook (18.1), not a background process.
 *  - Promotion threshold matches the CANARY floor (K1): positive reuse ≥ 3 clean uses → full trust.
 *
 * The lifecycle registers on the bus as a PROTECT-class observer (records opportunity/reuse from every signal,
 * incl. the observing phase) so the ledger is warm; the consolidate() pass runs on the cadence tick.
 */

import type { Learner, OutcomeSignal } from "./self_improvement_bus.js";

export type ArtifactKind = "prompt" | "lesson" | "skill" | "heuristic";
export type ArtifactStatus = "provisional" | "full" | "pruned";

export interface ArtifactRecord {
  readonly id: string;
  readonly kind: ArtifactKind;
  /** The task shape this artifact is relevant to (drives opportunity counting). */
  readonly relevanceKey: string;
  status: ArtifactStatus;
  /** Times a relevant task appeared (the artifact had a CHANCE to help). */
  opportunities: number;
  /** Times the artifact was active AND the outcome was good (positive reuse). */
  positiveUses: number;
  /** Times the artifact was active AND the outcome was bad (negative reuse). */
  negativeUses: number;
  createdTick: number;
  lastActiveTick: number;
  /** Recency+frequency+reuse-utility score (decays each sleep pass). */
  utility: number;
}

export interface ConsolidationConfig {
  /** Positive reuses to promote provisional → full. Default 3 (canary floor, K1). */
  readonly promoteThreshold?: number;
  /** Opportunity window: relevant-task count after which an un-helpful provisional is pruned. Default 10 (K6). */
  readonly opportunityWindow?: number;
  /** Forgetting-curve decay factor applied to utility each sleep pass. Default 0.9. */
  readonly decay?: number;
  /** Sessions between automatic sleep passes. Default 5 (K4). */
  readonly cadenceSessions?: number;
}

export interface ConsolidationReport {
  readonly promoted: readonly string[];
  readonly pruned: readonly string[];
  readonly merged: readonly { readonly kept: string; readonly absorbed: string }[];
  readonly decayed: number;
  readonly tick: number;
}

export class Consolidation {
  private readonly promoteThreshold: number;
  private readonly opportunityWindow: number;
  private readonly decay: number;
  private readonly cadenceSessions: number;
  private readonly artifacts = new Map<string, ArtifactRecord>();
  private tickCount = 0;      // sleep passes run
  private sessionCount = 0;   // outcomes observed since last sleep

  constructor(config: ConsolidationConfig = {}) {
    this.promoteThreshold = config.promoteThreshold ?? 3;
    this.opportunityWindow = config.opportunityWindow ?? 10;
    this.decay = config.decay ?? 0.9;
    this.cadenceSessions = config.cadenceSessions ?? 5;
  }

  /** Register a provisional artifact created by a learner. Idempotent by id. */
  register(id: string, kind: ArtifactKind, relevanceKey: string): void {
    if (this.artifacts.has(id)) return;
    this.artifacts.set(id, {
      id, kind, relevanceKey, status: "provisional",
      opportunities: 0, positiveUses: 0, negativeUses: 0,
      createdTick: this.tickCount, lastActiveTick: this.tickCount, utility: 1,
    });
  }

  /** As a bus learner: protect-class observer. Records opportunity + reuse from every signal. */
  asLearner(): Learner {
    return { id: "consolidation", loopClass: "protect", onOutcome: (s) => { this.observe(s); } };
  }

  /**
   * Record opportunity + reuse from one signal. An artifact whose relevanceKey matches the task shape gets an
   * opportunity (a relevant task appeared); if it was ALSO active, the outcome's quality is a positive or
   * negative use. Auto-runs a sleep pass every `cadenceSessions` signals (session-count cadence, no daemon).
   */
  observe(signal: OutcomeSignal): ConsolidationReport | null {
    const active = new Set(signal.activeArtifacts ?? []);
    for (const rec of this.artifacts.values()) {
      if (rec.status === "pruned") continue;
      if (rec.relevanceKey === signal.taskShape) {
        rec.opportunities++;
        if (active.has(rec.id)) {
          if (signal.testsPassed) rec.positiveUses++; else rec.negativeUses++;
          rec.lastActiveTick = this.tickCount;
        }
      }
    }
    this.sessionCount++;
    if (this.sessionCount >= this.cadenceSessions) {
      return this.consolidate();
    }
    return null;
  }

  /**
   * The sleep pass. PROMOTE corroborated provisionals, PRUNE opportunity-exhausted-but-unhelpful ones and
   * net-negative ones, MERGE duplicates (same kind+relevanceKey → keep the higher-utility), DECAY utility.
   * Idempotent-safe to call directly (explicit invoke) or via the cadence.
   */
  consolidate(): ConsolidationReport {
    this.tickCount++;
    this.sessionCount = 0;
    const promoted: string[] = [];
    const pruned: string[] = [];
    const merged: { kept: string; absorbed: string }[] = [];

    // Update utility = frequency + reuse-utility, decayed by recency (forgetting-curve).
    let decayed = 0;
    for (const rec of this.artifacts.values()) {
      if (rec.status === "pruned") continue;
      const reuseUtility = rec.positiveUses - rec.negativeUses;
      const recencyGap = this.tickCount - rec.lastActiveTick;
      rec.utility = (rec.positiveUses + Math.max(0, reuseUtility)) * Math.pow(this.decay, recencyGap);
      decayed++;

      // PROMOTE: corroborated positive reuse → full trust.
      if (rec.status === "provisional" && rec.positiveUses >= this.promoteThreshold && reuseUtility > 0) {
        rec.status = "full";
        promoted.push(rec.id);
        continue;
      }
      // PRUNE (net-negative): active but hurt more than helped.
      if (reuseUtility < 0 && rec.negativeUses >= this.promoteThreshold) {
        rec.status = "pruned";
        pruned.push(rec.id);
        continue;
      }
      // PRUNE (opportunity-exhausted): had its window of relevant tasks and never helped. K6: by OPPORTUNITY.
      if (rec.status === "provisional" && rec.opportunities >= this.opportunityWindow && rec.positiveUses === 0) {
        rec.status = "pruned";
        pruned.push(rec.id);
      }
      // Otherwise: a rarely-triggered but valid artifact stays dormant (NOT punished) — protects N=1.
    }

    // MERGE duplicates: same kind + relevanceKey, both live → keep higher-utility, absorb the other.
    const groups = new Map<string, ArtifactRecord[]>();
    for (const rec of this.artifacts.values()) {
      if (rec.status === "pruned") continue;
      const key = `${rec.kind}:${rec.relevanceKey}`;
      (groups.get(key) ?? groups.set(key, []).get(key)!).push(rec);
    }
    for (const group of groups.values()) {
      if (group.length < 2) continue;
      group.sort((a, b) => b.utility - a.utility);
      const kept = group[0]!;
      for (let i = 1; i < group.length; i++) {
        const dup = group[i]!;
        kept.positiveUses += dup.positiveUses;
        kept.opportunities = Math.max(kept.opportunities, dup.opportunities);
        dup.status = "pruned";
        merged.push({ kept: kept.id, absorbed: dup.id });
      }
    }

    return { promoted, pruned, merged, decayed, tick: this.tickCount };
  }

  /** Current record for an artifact (diagnostics/tests). */
  record(id: string): ArtifactRecord | undefined {
    return this.artifacts.get(id);
  }

  /** Live (non-pruned) artifacts, highest utility first (feeds retrieval/prioritization). */
  live(): readonly ArtifactRecord[] {
    return [...this.artifacts.values()].filter((r) => r.status !== "pruned").sort((a, b) => b.utility - a.utility);
  }

  get sleeps(): number { return this.tickCount; }
}
