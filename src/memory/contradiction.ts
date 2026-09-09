/**
 * TOKI-CONTRADICTION — a small, DETERMINISTIC contradiction algebra for memory supersession. The naive rule (same
 * subject+relation, different object ⇒ supersede) over-fires on additive relations and misses negation. This encodes
 * the formal definition (0Latency 2026): two facts contradict when they assert INCOMPATIBLE VALUES for the SAME
 * ATTRIBUTE of the SAME ENTITY within OVERLAPPING temporal scopes. Three rules:
 *   (1) FUNCTIONAL vs MULTI-VALUED relations — a functional (single-valued: livesIn, role) relation conflicts when the
 *       object changes; a multi-valued (additive: speaks, owns) relation does NOT (both coexist). This is the
 *       "static vs dynamic relation" distinction (ROMEM, arXiv 2604.11544).
 *   (2) EXPLICIT NEGATION — `not:livesIn Boston` contradicts `livesIn Boston` (same base relation + object).
 *   (3) TEMPORAL OVERLAP required — only edges whose valid-time intervals overlap can conflict (Graphiti / Vadim 2026);
 *       sequential facts coexist.
 *
 * HONEST: per-relation cardinality is DECLARED config, not inferred; an UNKNOWN relation defaults to MULTI-VALUED —
 * never over-supersede. Deterministic (no model); semantic/LLM-based conflict detection is a separate seam. This is the
 * validated 2026 frontier stance (Eywa/TOKI): determinism + provenance + never-silently-rewrite.
 */

export type RelationCardinality = "functional" | "multi_valued";

export interface ContradictionConfig {
  /** base relation → cardinality. Absent ⇒ multi-valued (safe default: never over-supersede). */
  readonly cardinality: Readonly<Record<string, RelationCardinality>>;
}

/** A conservative seed of common functional relations. Everything not listed defaults to multi-valued. */
export const DEFAULT_CARDINALITY: ContradictionConfig = {
  cardinality: {
    livesIn: "functional", role: "functional", worksAt: "functional", status: "functional",
    locatedIn: "functional", currentEmployer: "functional", marriedTo: "functional", capitalOf: "functional",
    // additive relations declared explicitly for clarity (they would default to multi-valued anyway):
    speaks: "multi_valued", owns: "multi_valued", knows: "multi_valued", memberOf: "multi_valued", hasSkill: "multi_valued",
  },
};

const NEG_PREFIX = "not:";

/** Parse a relation into its base + whether it is a negation (`not:livesIn` → { base: "livesIn", negated: true }). */
export function parseRelation(relation: string): { base: string; negated: boolean } {
  return relation.startsWith(NEG_PREFIX)
    ? { base: relation.slice(NEG_PREFIX.length), negated: true }
    : { base: relation, negated: false };
}

export function cardinalityOf(baseRelation: string, config: ContradictionConfig): RelationCardinality {
  return config.cardinality[baseRelation] ?? "multi_valued"; // unknown → multi-valued (never over-supersede)
}

/** Half-open interval overlap: [aFrom, aTo) ∩ [bFrom, bTo) ≠ ∅. undefined `to` = open (∞). */
export function intervalsOverlap(aFrom: number, aTo: number | undefined, bFrom: number, bTo: number | undefined): boolean {
  const aEnd = aTo ?? Infinity, bEnd = bTo ?? Infinity;
  return aFrom < bEnd && bFrom < aEnd;
}

export interface EdgeFact {
  readonly subject: string;
  readonly relation: string;
  readonly object: string;
  readonly validFrom: number;
  readonly validTo?: number;
}

/**
 * Does the NEW fact contradict the EXISTING fact (⇒ the existing should be superseded)? Requires the same subject and
 * OVERLAPPING valid-time. Then: a negation of the same (base relation, object) contradicts the affirmative; OR a
 * FUNCTIONAL relation with a DIFFERENT object contradicts. Multi-valued / unknown relations never contradict on value.
 */
export function contradicts(next: EdgeFact, existing: EdgeFact, config: ContradictionConfig = DEFAULT_CARDINALITY): boolean {
  if (next.subject !== existing.subject) return false;
  if (!intervalsOverlap(next.validFrom, next.validTo, existing.validFrom, existing.validTo)) return false;

  const a = parseRelation(next.relation), b = parseRelation(existing.relation);
  if (a.base !== b.base) return false;

  // (2) NEGATION: one affirms, the other negates the SAME (base, object).
  if (a.negated !== b.negated && next.object === existing.object) return true;

  // (1) FUNCTIONAL: same base, both affirmative, DIFFERENT object, single-valued relation.
  if (!a.negated && !b.negated && next.object !== existing.object && cardinalityOf(a.base, config) === "functional") return true;

  return false; // multi-valued / unknown / same-object-affirmative → additive, no contradiction
}
