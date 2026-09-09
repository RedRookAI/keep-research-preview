/**
 * PlanCurrencyCheck (Increment 16.9c-4) — a SOVEREIGN, currency-aware plan/proposal vetting primitive.
 *
 * A plan can be logically valid but STALE: based on a superseded best practice, a deprecated API, or an
 * outdated tool. In a fast-moving field this is a distinct failure mode, and the defense is a signal
 * INDEPENDENT of the planning model's own (possibly-stale) knowledge — a live DATE check + a research-
 * backed check. This runs on every plan/proposal and FLAGS staleness (never silently rewrites).
 *
 * SOTA basis (2026-08-05): a plan confidently based on superseded best practice is a NAMED failure mode,
 * distinct from hallucination — "the model is not hallucinating, it is remembering incorrectly" (Tacnode
 * 2026; the React-18-with-React-16-syntax example). TEMPORAL DECAY: a model assigns the SAME confidence to
 * stale and current knowledge (airuntimesecurity 2026), so the check must be independent of the planning
 * model — a live date + external research. Mechanism: inject current date, extract time-sensitive claims,
 * verify against current sources when available, flag stale (cutoff guide "+40% accuracy"). FLAG + route,
 * never silently rewrite ("the agent proposes, a person decides" — atlan/slite 2026).
 *
 * SOVEREIGN by construction (built on Keep's OWN primitives, not a SaaS staleness tool that would ingest
 * your plans): the deterministic core (date + staleness signals + landscape catalog + our BM25) is fully
 * OFFLINE; the research check is an OPT-IN, privacy-preserving egress (minimal query terms only, never the
 * plan body/IP) that degrades gracefully to the dated caveat. Zero deps.
 */

import type { TemporalContext } from "../currency/temporal_context.js";
import type { LandscapeCatalog } from "../currency/landscape_catalog.js";

/** A time-sensitive claim extracted from a plan (something that can go stale). */
export interface TimeSensitiveClaim {
  readonly kind: "named-tool" | "version-pin" | "best-practice-assertion";
  readonly text: string;
  /** If it names a catalog tool, whether that catalog entry is stale (offline check). */
  readonly catalogStale?: boolean;
}

export type CurrencyDecision = "pass" | "verify-currency" | "stale";

export interface CurrencyVerdict {
  readonly decision: CurrencyDecision;
  /** The date stamp (always present — the deterministic date check). */
  readonly dateStamp: string;
  /** Staleness magnitude if the brain cutoff is known (months since cutoff). */
  readonly monthsSinceCutoff?: number;
  readonly claims: readonly TimeSensitiveClaim[];
  /** What the reviewer should verify (never an auto-rewrite). */
  readonly verifyThese: readonly string[];
  /** If research ran, any newer/superseding finding (grounded); empty offline. */
  readonly researchNotes: readonly string[];
  readonly reason: string;
}

/** An optional, privacy-preserving research port. Receives ONLY minimal query terms — never the plan/IP. */
export interface CurrencyResearch {
  /** Verify whether a named approach/tool is still current. Returns a grounded note, or null if unknown. */
  verifyCurrent(minimalTerms: readonly string[]): Promise<{ current: boolean; note: string } | null>;
}

/** "best practice / recommended / standard / modern / latest" style assertions that can silently go stale. */
const BEST_PRACTICE_RE = /\b(best practice|recommended approach|standard approach|the modern way|current best|latest|state[- ]of[- ]the[- ]art|idiomatic)\b/i;
/** A version pin like "v18", "3.11", "React 18", "Node 22". */
const VERSION_RE = /\b([A-Za-z][A-Za-z.+-]*\s*)?v?\d+(\.\d+){0,2}\b/;

/** Tokenize a plan into candidate terms (our own, offline). */
function terms(text: string): string[] {
  return (text.toLowerCase().match(/[a-z0-9][a-z0-9.+-]{1,}/g) ?? []).filter((t) => t.length >= 2);
}

/**
 * The sovereign currency check. `research` is optional; when absent (or temporal.canVerify is false) the
 * check runs fully offline and produces an honest dated caveat — never a failure.
 */
export async function checkCurrency(
  planText: string,
  temporal: TemporalContext,
  catalog: LandscapeCatalog,
  research?: CurrencyResearch,
  now: Date = new Date(),
): Promise<CurrencyVerdict> {
  // 1) DATE CHECK — always, deterministic, offline.
  const dateStamp = temporal.todayISO;
  const claims: TimeSensitiveClaim[] = [];
  const verifyThese: string[] = [];
  const researchNotes: string[] = [];

  // 2) STALENESS SIGNALS — deterministic, cheap, offline.
  // (a) "best practice"-style assertions the brain cannot date → always worth verifying.
  const bp = BEST_PRACTICE_RE.exec(planText);
  if (bp) {
    claims.push({ kind: "best-practice-assertion", text: bp[0] });
    verifyThese.push(`the plan asserts "${bp[0]}" — confirm this is still current as of ${dateStamp}`);
  }
  // (b) version pins → can be superseded.
  const vm = VERSION_RE.exec(planText);
  if (vm && /\d/.test(vm[0])) {
    claims.push({ kind: "version-pin", text: vm[0].trim() });
    verifyThese.push(`the plan pins "${vm[0].trim()}" — confirm it is not deprecated/superseded`);
  }
  // (c) named tools present in the plan → cross-check the OFFLINE catalog's staleness (our BM25).
  const planTerms = terms(planText);
  const matches = catalog.matchesTask(planTerms);
  const catalogStale = catalog.isStale(now);
  for (const entry of matches.slice(0, 3)) {
    // Only count it as a named-tool claim if the plan actually names the tool (not just a shared tag).
    if (planTerms.includes(entry.name.toLowerCase())) {
      claims.push({ kind: "named-tool", text: entry.name, catalogStale });
      if (catalogStale) verifyThese.push(`the plan names "${entry.name}"; the options catalog is stale (>120d) — check for a newer option`);
    }
  }

  // 3) RESEARCH-BACKED CHECK — opt-in, privacy-preserving, only when verification is available.
  let researchStale = false;
  if (research && temporal.canVerify && claims.length > 0) {
    // Send ONLY minimal terms (the claim texts), never the plan body / IP.
    const minimal = claims.map((c) => c.text);
    const res = await research.verifyCurrent(minimal);
    if (res) {
      researchNotes.push(res.note);
      if (!res.current) researchStale = true;
    }
  }

  // 4) VERDICT — flag + route; never auto-rewrite.
  const farPastCutoff = (temporal.monthsSinceCutoff ?? 0) >= 12;
  let decision: CurrencyDecision;
  let reason: string;
  if (researchStale) {
    decision = "stale";
    reason = `research indicates a named approach is superseded (as of ${dateStamp}); route with the current alternative`;
  } else if (claims.length > 0 || farPastCutoff) {
    decision = "verify-currency";
    const bits: string[] = [];
    if (claims.length > 0) bits.push(`${claims.length} time-sensitive claim(s)`);
    if (farPastCutoff) bits.push(`brain is ~${temporal.monthsSinceCutoff}mo past its cutoff`);
    if (!temporal.canVerify) bits.push("no live verification this session (offline caveat stands)");
    reason = `currency check flagged: ${bits.join("; ")} — verify before proceeding`;
    if (farPastCutoff && !claims.length) verifyThese.push(`the brain is ~${temporal.monthsSinceCutoff} months past its training cutoff — sanity-check any fast-moving specifics against current sources`);
  } else {
    decision = "pass";
    reason = `no time-sensitive claims detected; dated ${dateStamp}`;
  }

  return {
    decision, dateStamp,
    ...(temporal.monthsSinceCutoff !== undefined ? { monthsSinceCutoff: temporal.monthsSinceCutoff } : {}),
    claims, verifyThese, researchNotes, reason,
  };
}
