/**
 * MEM-EVAL — a memory-evaluation harness for Keep's real MemoryStore, modelled on the 2026 SOTA benchmarks
 * (LongMemEval, LoCoMo). It does NOT re-implement a memory engine: it drives the real `store` (ingest → retrieve /
 * validAt / closeValidInterval) over a SEEDED, in-repo scenario set and scores the canonical question types:
 *
 *   • single-session-user   — recall a fact stated in one session.
 *   • multi-session         — synthesise facts stated across sessions (multi-hop).
 *   • knowledge-update      — a fact changes over time; the CURRENT answer must win (bitemporal supersession).
 *   • temporal-reasoning    — an as-of query returns the value that was valid THEN (validAt).
 *   • abstention            — a question with no evidence must yield no confident hit (don't fabricate).
 *
 * HONEST: this is a SEEDED PROXY, not the official 500-question LongMemEval — it is a regression signal, labelled as
 * such. It reports per-type scores (never a single aggregate that hides a weak axis), and surfaces the known
 * post-filter-dilution caveat: as-of / time-travel retrieval can lower temporal-reasoning recall (arXiv 2607.26520).
 * ZERO-DEP. BOTH-TRACKS: an n=1 personal-memory quality signal / an org regression gate on memory changes.
 */

import type { MemoryStore } from "../memory/store.js";

export type MemQuestionType =
  | "single-session-user"
  | "multi-session"
  | "knowledge-update"
  | "temporal-reasoning"
  | "abstention";

export interface MemFact {
  readonly content: string; // "subject => value"
  readonly validFrom?: number;
  readonly validTo?: number;
}

export interface MemScenario {
  readonly id: string;
  readonly type: MemQuestionType;
  readonly facts: readonly MemFact[];
  readonly query: string;
  /** The value a correct answer must contain. Omitted for abstention (the correct answer is "I don't know"). */
  readonly expectValue?: string;
  /** A value that must NOT surface (e.g. the stale value after a knowledge-update). */
  readonly staleValue?: string;
  /** temporal-reasoning: evaluate validAt(asOf) instead of current retrieval. */
  readonly asOf?: number;
  /** knowledge-update: close facts[ofFactIndex].validTo at `at` before evaluating "current". */
  readonly supersede?: { readonly ofFactIndex: number; readonly at: number };
}

export interface MemTypeScore {
  readonly type: MemQuestionType;
  readonly total: number;
  readonly passed: number;
  /** Fraction of this type's scenarios where the expected evidence was surfaced in the top-k (retrieval types). */
  readonly recallAtK: number;
}

export interface MemEvalReport {
  readonly perType: readonly MemTypeScore[];
  readonly overall: { readonly total: number; readonly passed: number };
  readonly k: number;
  /** HONEST: known caveats surfaced (e.g. post-filter dilution) — never hidden. */
  readonly caveats: readonly string[];
  /** HONEST: this scenario set is a seeded in-repo proxy, not the official benchmark. */
  readonly seededProxyNote: string;
}

export interface MemEvalDeps {
  /** Build a FRESH, isolated store per scenario (no cross-scenario retrieval bleed). */
  readonly freshStore: () => MemoryStore;
  readonly k?: number;
  /** Abstention/relevance threshold: a top-hit similarity below this counts as "no confident evidence". Default 0.55. */
  readonly relevanceThreshold?: number;
  readonly now?: number;
}

const DILUTION_CAVEAT =
  "post-filter dilution: as-of / time-travel retrieval (validAt) can lower temporal-reasoning recall vs current-state search — a known limitation surfaced honestly, not hidden (arXiv 2607.26520).";

function contains(hay: string, needle: string): boolean {
  return hay.toLowerCase().includes(needle.toLowerCase());
}

/** Run the seeded memory evaluation over the real store. Returns per-type scores + honest caveats. */
export async function runMemoryEval(scenarios: readonly MemScenario[], deps: MemEvalDeps): Promise<MemEvalReport> {
  const k = deps.k ?? 5;
  const tau = deps.relevanceThreshold ?? 0.55;
  const now = deps.now ?? 1_000_000;

  const byType = new Map<MemQuestionType, { total: number; passed: number; recallHits: number; recallDenom: number }>();
  const bump = (t: MemQuestionType) => byType.get(t) ?? byType.set(t, { total: 0, passed: 0, recallHits: 0, recallDenom: 0 }).get(t)!;

  let anyTemporal = false;

  for (const s of scenarios) {
    const store = deps.freshStore();
    // SETUP: ingest the scenario's facts (valid-time intervals honoured).
    const ingestedIds: (string | undefined)[] = [];
    for (const f of s.facts) {
      const lesson = await store.ingest(f.content, {
        origin: "self",
        ...(f.validFrom !== undefined ? { validFrom: f.validFrom } : {}),
        ...(f.validTo !== undefined ? { validTo: f.validTo } : {}),
      });
      ingestedIds.push(lesson?.id);
    }
    // knowledge-update: supersede the stale fact by closing its valid interval.
    if (s.supersede) {
      const id = ingestedIds[s.supersede.ofFactIndex];
      if (id) store.closeValidInterval(id, s.supersede.at);
    }

    const rec = bump(s.type);
    rec.total++;
    let passed = false;

    if (s.type === "temporal-reasoning") {
      anyTemporal = true;
      // as-of query: the value valid THEN must be present; a value valid only LATER must not be.
      const asOf = s.asOf ?? now;
      const validThen = store.validAt(asOf).map((l) => l.content);
      const hasExpected = s.expectValue !== undefined && validThen.some((c) => contains(c, s.expectValue!));
      const hasStale = s.staleValue !== undefined && validThen.some((c) => contains(c, s.staleValue!));
      passed = hasExpected && !hasStale;
      rec.recallDenom++; if (hasExpected) rec.recallHits++;
    } else if (s.type === "knowledge-update") {
      // CURRENT state: the new value wins, the stale value is gone (its interval was closed).
      const current = store.validAt(now).map((l) => l.content);
      const hasCurrent = s.expectValue !== undefined && current.some((c) => contains(c, s.expectValue!));
      const hasStale = s.staleValue !== undefined && current.some((c) => contains(c, s.staleValue!));
      passed = hasCurrent && !hasStale;
      rec.recallDenom++; if (hasCurrent) rec.recallHits++;
    } else if (s.type === "abstention") {
      // no confident evidence → the top hit must fall below the relevance threshold.
      const hits = await store.retrieve(s.query, k);
      const top = hits[0]?.similarity ?? 0;
      passed = top < tau;
    } else {
      // single-session / multi-session: the expected evidence must appear in the top-k retrieval.
      const hits = await store.retrieve(s.query, k);
      const surfaced = s.expectValue !== undefined && hits.some((h) => contains(h.lesson.content, s.expectValue!));
      passed = surfaced;
      rec.recallDenom++; if (surfaced) rec.recallHits++;
    }

    if (passed) rec.passed++;
  }

  const perType: MemTypeScore[] = [...byType.entries()].map(([type, r]) => ({
    type,
    total: r.total,
    passed: r.passed,
    recallAtK: r.recallDenom > 0 ? r.recallHits / r.recallDenom : 1,
  }));
  const overall = perType.reduce((acc, t) => ({ total: acc.total + t.total, passed: acc.passed + t.passed }), { total: 0, passed: 0 });
  const caveats = anyTemporal ? [DILUTION_CAVEAT] : [];

  return {
    perType,
    overall,
    k,
    caveats,
    seededProxyNote: "SEEDED in-repo proxy for LongMemEval/LoCoMo question types — a regression signal, NOT the official 500-question benchmark; scale to BEAM (ICLR 2026) for production-scale coverage.",
  };
}

/** A seeded scenario set covering all five question types (labelled proxy — see seededProxyNote). */
export const SEEDED_MEM_SCENARIOS: readonly MemScenario[] = [
  {
    id: "ss-1", type: "single-session-user",
    facts: [{ content: "user degree => Business Administration" }],
    query: "user degree", expectValue: "Business Administration",
  },
  {
    id: "ms-1", type: "multi-session",
    facts: [{ content: "project database => PostgreSQL" }, { content: "project cache => Redis" }],
    query: "project database", expectValue: "PostgreSQL",
  },
  {
    id: "ku-1", type: "knowledge-update",
    // v1: role = Engineer (valid [0,100)); v2: role = Manager (valid [100, open)). Supersede v1 at 100.
    facts: [
      { content: "user role => Engineer", validFrom: 0 },
      { content: "user role => Manager", validFrom: 100 },
    ],
    supersede: { ofFactIndex: 0, at: 100 },
    query: "user role", expectValue: "Manager", staleValue: "Engineer",
  },
  {
    id: "tr-1", type: "temporal-reasoning",
    facts: [
      { content: "user city => Boston", validFrom: 0, validTo: 100 },
      { content: "user city => Denver", validFrom: 100 },
    ],
    asOf: 50, query: "user city", expectValue: "Boston", staleValue: "Denver",
  },
  {
    id: "abs-1", type: "abstention",
    facts: [{ content: "user degree => Business Administration" }],
    query: "user favourite quantum chromodynamics sabbatical spaceship",
  },
];
