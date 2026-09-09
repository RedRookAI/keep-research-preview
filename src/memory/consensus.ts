/**
 * MemoryConsensus (Increment C2, Phase D) — the dual-memory consensus layer. A poisoned or spurious lesson
 * must not be trusted for retrieval on the strength of a single write. This is a SECOND, independent validation
 * view over the memory store: a lesson is only promoted to retrieval-trusted when it reaches CONSENSUS, and
 * detected anomalies are themselves recorded as lesson-memory (so the same poison is caught faster next time).
 *
 * SOTA basis (2026-08-05):
 *  - A-MemGuard (arXiv 2510.02373): consensus-based validation ("a single poisoned memory may appear valid,
 *    but the reasoning it induces diverges from the consensus of related memories") + a DUAL-MEMORY structure
 *    that stores detected anomalies as lessons. Multi-source agreement before committing a memory update;
 *    both components necessary (ablation). >95% mitigation.
 *  - THE known failure of naive consensus (SENTINEL 2607.05029): A-MemGuard "fails against amplification that
 *    FLOODS the store with consistent forged entries until the poison BECOMES the consensus." → count-based
 *    consensus is defeatable. Keep's fix: consensus requires INDEPENDENT PROVENANCE (distinct origin events),
 *    not just a count — flooding from one origin cannot manufacture agreement (pairs with the existing
 *    provenanceEventId / Origin on every Lesson).
 *  - Entry-level lineage above the consensus layer (MemLineage 2605.14421) + invariant/consistency veto
 *    (SSGM): a lesson that CONTRADICTS confirmed memory is quarantined, not silently merged.
 *
 * Zero runtime deps. Wraps the trust decision behind a port; does not modify the underlying MemoryStore.
 */

/** A minimal projection of a lesson the consensus layer reasons over (decoupled from the full Lesson type). */
export interface ConsensusLesson {
  readonly id: string;
  readonly content: string;
  /** The spine event id this lesson was first recorded under (origin-bound authority). */
  readonly provenanceEventId: string;
  /** The scope/key this lesson applies to (used to find RELATED memories for the consensus group). */
  readonly relevanceKey: string;
}

/** One corroboration: a distinct piece of evidence supporting a lesson, tagged with its ORIGIN event. */
export interface Corroboration {
  /** The provenance event this corroboration came from (independence is measured over this). */
  readonly originEventId: string;
  /** Whether this evidence AGREES with the lesson (true) or CONTRADICTS it (false). */
  readonly agrees: boolean;
}

export type ConsensusVerdict =
  | "trusted"              // reached consensus from independent origins → safe to retrieve
  | "pending-consensus"    // plausible but not yet corroborated by enough independent origins
  | "quarantined-contradiction" // contradicts confirmed memory → held as a lesson-memory anomaly
  | "rejected-flooding";   // many corroborations but from too few independent origins → amplification attack

export interface ConsensusResult {
  readonly verdict: ConsensusVerdict;
  readonly independentOrigins: number;
  readonly agreeing: number;
  readonly contradicting: number;
  readonly reason: string;
}

export interface MemoryConsensusConfig {
  /** Distinct independent origins required to reach consensus. Default 2 (dual-memory minimum). */
  readonly minIndependentOrigins?: number;
  /**
   * Max fraction of corroborations allowed to share a single origin before it's flagged as flooding.
   * Default 0.6 — if >60% of "agreement" comes from one origin, it's amplification, not consensus.
   */
  readonly maxSingleOriginShare?: number;
}

export class MemoryConsensus {
  private readonly minOrigins: number;
  private readonly maxShare: number;
  /** Lesson id → corroborations gathered so far. */
  private readonly corroborations = new Map<string, Corroboration[]>();
  /** The lesson-memory of detected anomalies (dual-memory): contradiction/flooding patterns to avoid. */
  private readonly anomalies: { lessonId: string; content: string; kind: ConsensusVerdict }[] = [];

  constructor(config: MemoryConsensusConfig = {}) {
    this.minOrigins = config.minIndependentOrigins ?? 2;
    this.maxShare = config.maxSingleOriginShare ?? 0.6;
  }

  /** Record a corroboration for a lesson (from a solve outcome, a second-view derivation, etc.). */
  corroborate(lessonId: string, corroboration: Corroboration): void {
    const list = this.corroborations.get(lessonId) ?? [];
    list.push(corroboration);
    this.corroborations.set(lessonId, list);
  }

  /**
   * The consensus verdict for a lesson. `confirmedContradictors` are the contents of already-confirmed lessons
   * that this one would contradict (supplied by the store's relevance lookup) — a contradiction quarantines.
   * Trust requires: agreement > contradiction, AND ≥minOrigins INDEPENDENT origins agree, AND no single origin
   * dominates the agreement (anti-flooding).
   */
  evaluate(lesson: ConsensusLesson, confirmedContradictors: readonly string[] = []): ConsensusResult {
    // 1. Contradiction veto (SSGM-style consistency): if this lesson contradicts confirmed memory, quarantine
    //    it as a lesson-memory anomaly rather than letting it compete on volume.
    if (this.contradictsConfirmed(lesson, confirmedContradictors)) {
      this.recordAnomaly(lesson, "quarantined-contradiction");
      return { verdict: "quarantined-contradiction", independentOrigins: 0, agreeing: 0, contradicting: confirmedContradictors.length, reason: "contradicts a confirmed lesson — held as a lesson-memory anomaly, not merged" };
    }

    const list = this.corroborations.get(lesson.id) ?? [];
    // The lesson's own origin counts as one supporting origin.
    const agreeing = list.filter((c) => c.agrees);
    const contradicting = list.filter((c) => !c.agrees).length;
    const originSet = new Set<string>([lesson.provenanceEventId, ...agreeing.map((c) => c.originEventId)]);
    const independentOrigins = originSet.size;

    // 2. Net agreement required.
    if (agreeing.length + 1 <= contradicting) {
      return { verdict: "pending-consensus", independentOrigins, agreeing: agreeing.length, contradicting, reason: "contradicting evidence outweighs agreement — not yet trusted" };
    }

    // 3. Anti-flooding: if the agreement is dominated by a single origin, it's amplification, not consensus.
    const dominant = this.dominantOriginShare(lesson, agreeing);
    if (independentOrigins >= this.minOrigins && dominant > this.maxShare) {
      this.recordAnomaly(lesson, "rejected-flooding");
      return { verdict: "rejected-flooding", independentOrigins, agreeing: agreeing.length, contradicting, reason: `agreement dominated by one origin (${(dominant * 100).toFixed(0)}%) — amplification, not consensus` };
    }

    // 4. Consensus from independent origins → trusted.
    if (independentOrigins >= this.minOrigins) {
      return { verdict: "trusted", independentOrigins, agreeing: agreeing.length, contradicting, reason: `consensus from ${independentOrigins} independent origins` };
    }

    return { verdict: "pending-consensus", independentOrigins, agreeing: agreeing.length, contradicting, reason: `needs ${this.minOrigins} independent origins, has ${independentOrigins}` };
  }

  /** The dual-memory: detected anomalies (contradictions/flooding) recorded as lessons to catch faster. */
  lessonMemory(): readonly { readonly lessonId: string; readonly content: string; readonly kind: ConsensusVerdict }[] {
    return this.anomalies;
  }

  private contradictsConfirmed(lesson: ConsensusLesson, confirmedContradictors: readonly string[]): boolean {
    // A lesson contradicts confirmed memory if its content directly negates a confirmed lesson's content.
    const neg = negate(lesson.content);
    return confirmedContradictors.some((c) => normalize(c) === normalize(neg) || normalize(c) === normalize(lesson.content) && isNegated(lesson.content) !== isNegated(c));
  }

  private dominantOriginShare(lesson: ConsensusLesson, agreeing: readonly Corroboration[]): number {
    const counts = new Map<string, number>();
    counts.set(lesson.provenanceEventId, 1);
    for (const c of agreeing) counts.set(c.originEventId, (counts.get(c.originEventId) ?? 0) + 1);
    const total = [...counts.values()].reduce((a, b) => a + b, 0);
    const max = Math.max(...counts.values());
    return total > 0 ? max / total : 0;
  }

  private recordAnomaly(lesson: ConsensusLesson, kind: ConsensusVerdict): void {
    if (!this.anomalies.some((a) => a.lessonId === lesson.id && a.kind === kind)) {
      this.anomalies.push({ lessonId: lesson.id, content: lesson.content, kind });
    }
  }
}

// ── zero-dep content helpers for the contradiction check ──
function normalize(s: string): string { return s.toLowerCase().replace(/\b(never|do not|don't|avoid)\b/g, "").replace(/[^a-z0-9 ]/g, "").replace(/\s+/g, " ").trim(); }
function isNegated(s: string): boolean { return /\b(never|do not|don't|avoid|no)\b/i.test(s); }
function negate(s: string): string { return isNegated(s) ? s.replace(/\b(never|do not|don't|avoid)\b/gi, "always") : `never ${s}`; }
