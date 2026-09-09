/**
 * Theme 2 (Currency Layer), Part 1 — TemporalContext.
 *
 * Every planning call must know today's real date and that its training may be stale —
 * WITHOUT relying on the model to remember (SOTA: local models get NO search override,
 * the cutoff is an absolute wall). So the runtime injects this deterministically. This
 * is the permanent, structural version of the operator manually prompting the date
 * every round.
 *
 * Honesty is the safety property: if a search tool is available, the directive says
 * "verify anything time-sensitive"; if NOT (offline / local-only), it says plainly
 * "I can't check current facts — treat time-sensitive claims as unverified as of my
 * cutoff" rather than being silently confident.
 */

export interface TemporalContext {
  /** Machine date, YYYY-MM-DD. */
  readonly todayISO: string;
  /** Human date, e.g. "Tuesday, August 4, 2026". */
  readonly todayHuman: string;
  /** The brain's known training cutoff (YYYY-MM), if known. */
  readonly brainCutoff?: string;
  /** Rough months between the cutoff and today (staleness magnitude), if cutoff known. */
  readonly monthsSinceCutoff?: number;
  /** Whether a live search/verification tool is available this session. */
  readonly canVerify: boolean;
  /** The deterministic directive injected into planning prompts. */
  readonly directive: string;
}

function iso(now: Date): string {
  return now.toISOString().slice(0, 10);
}

const DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

function human(now: Date): string {
  return `${DAYS[now.getUTCDay()]}, ${MONTHS[now.getUTCMonth()]} ${now.getUTCDate()}, ${now.getUTCFullYear()}`;
}

function monthsBetween(cutoffYYYYMM: string, now: Date): number | undefined {
  const m = /^(\d{4})-(\d{2})$/.exec(cutoffYYYYMM);
  if (!m) return undefined;
  const cy = Number(m[1]);
  const cm = Number(m[2]);
  return (now.getUTCFullYear() - cy) * 12 + (now.getUTCMonth() + 1 - cm);
}

/**
 * Build the temporal context for a planning call. `canVerify` is true when a live
 * search/fetch tool is wired this session.
 */
export function buildTemporalContext(now: Date = new Date(), brainCutoff?: string, canVerify = false): TemporalContext {
  const todayISO = iso(now);
  const todayHuman = human(now);
  const months = brainCutoff ? monthsBetween(brainCutoff, now) : undefined;

  const base = `Today is ${todayHuman} (${todayISO}). Your training data may be out of date; anything about the current state of the world — model versions, prices, libraries, standards, who holds a role — can have changed since your cutoff${brainCutoff ? ` (${brainCutoff})` : ""}.`;

  const honesty = canVerify
    ? `A live search tool is available: VERIFY anything time-sensitive before relying on it, and prefer freshly-retrieved facts over memory.`
    : `No live search tool is available this session: do NOT state time-sensitive facts as current. Flag them as "as of my cutoff, unverified" so the human knows to check.`;

  return {
    todayISO,
    todayHuman,
    ...(brainCutoff !== undefined ? { brainCutoff } : {}),
    ...(months !== undefined ? { monthsSinceCutoff: months } : {}),
    canVerify,
    directive: `${base} ${honesty}`,
  };
}

// ── Recency predicates (Theme 2, Part 2 — the SAME clock, reused) ─────────────
//
// The tri-formula research gate (BUILD-ORDER 8.6) needs two DISTINCT recency
// verdicts on a source's as-of date, and both must read the SAME date arithmetic
// the same-day currency flag above reads — no second clock, no second mechanism.
// A source's age is a fact about its date, so these are pure functions of (asOf,
// today): the HISTORICAL axis demands a source that FAILS recency (old enough),
// the TODAY axis demands one that PASSES it (fresh) — the two are deliberately
// non-overlapping so a single same-day link can satisfy AT MOST one of them.

/**
 * Whole days from `asOfISO` to `todayISO` (positive = in the past). Undefined if
 * either date is not a parseable YYYY-MM-DD. UTC-anchored, matching {@link iso}.
 */
export function ageInDays(asOfISO: string | undefined, todayISO: string): number | undefined {
  if (!asOfISO) return undefined;
  const a = Date.parse(`${asOfISO.slice(0, 10)}T00:00:00Z`);
  const t = Date.parse(`${todayISO.slice(0, 10)}T00:00:00Z`);
  if (Number.isNaN(a) || Number.isNaN(t)) return undefined;
  return Math.round((t - a) / 86_400_000);
}

/**
 * HISTORICAL predicate: the source is old enough to be historical grounding —
 * it FAILS the recency filter, i.e. its age is at least `minAgeDays` (default a
 * year). A same-day link (age 0) can NEVER satisfy this; that is the point — the
 * historical axis is one a fresh URL is structurally unable to fill. A missing or
 * unparseable date returns false (we cannot assert age we do not know).
 */
export function isHistoricalSource(
  asOfISO: string | undefined,
  todayISO: string,
  minAgeDays = 365,
): boolean {
  const age = ageInDays(asOfISO, todayISO);
  return age !== undefined && age >= minAgeDays;
}

/**
 * TODAY freshness predicate: the source was retrieved recently — age within
 * `[0, maxFreshAgeDays]` (default 30). A future-dated source (age < 0) is NOT
 * fresh (it is malformed, not current). This PASSES the recency filter that
 * {@link isHistoricalSource} fails, so the two partition cleanly.
 */
export function isFreshSource(
  asOfISO: string | undefined,
  todayISO: string,
  maxFreshAgeDays = 30,
): boolean {
  const age = ageInDays(asOfISO, todayISO);
  return age !== undefined && age >= 0 && age <= maxFreshAgeDays;
}
