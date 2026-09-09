/**
 * Auto-Research: need-detector + provenance model (Increment 4a).
 *
 * SOTA basis (2026-08-04): deep-research citations fail two distinct ways (arXiv 2604.03173;
 * 2605.06635; pickaxe 2026): (1) CITATION hallucination — the reference itself doesn't exist
 * (fake DOI/URL/paper; measured 11-57%); (2) STATEMENT hallucination — the source is real but
 * does NOT support the claim ("the link works, the source is real, but the claim often isn't in
 * there" — the sneakier mode). The rule that works is structural, not prompted: "cite a retrieved
 * source for every claim; never cite from memory" enforced IN CODE, not asked-for-nicely.
 *
 * So Auto-Research models every finding as a ResearchClaim that MUST carry provenance, and tracks
 * BOTH hallucination modes explicitly. This module defines the need-detector + the verifiable
 * types; the loop (4b) produces them and the floor (4c) enforces them.
 *
 * Zero deps.
 */

/** Why a task might need a research pass. */
export type ResearchTrigger =
  | "recency-sensitive" // asks about current/latest/2026 state — training may be stale
  | "unfamiliar-domain" // specialized terms the brain likely can't ground from memory
  | "explicit-research-goal" // the goal itself is to survey/review/investigate
  | "prior-art-check" // "does X already exist" — the adopt/build/combine question
  | "none";

/** The detector's verdict for a goal. */
export interface ResearchNeed {
  readonly needed: boolean;
  readonly triggers: readonly ResearchTrigger[];
  readonly reason: string;
  /** Keywords extracted for the search seam. */
  readonly keywords: readonly string[];
}

/** A source citation attached to a claim. */
export interface Citation {
  readonly id: string;
  readonly title: string;
  /** URL / DOI / identifier. A citation with no locator can never resolve → citation-hallucination. */
  readonly locator?: string;
  /** The excerpt the claim is supposedly grounded in (for statement-faithfulness checking). */
  readonly supportingText?: string;
  /** As-of date of the source (feeds the currency/freshness honesty). */
  readonly asOf?: string;
  /**
   * The DOMAIN / discipline tag of the source (e.g. "security", "history", "journalism").
   * Load-bearing for the CROSS-DISCIPLINARY axis of the research triple: a corroborating source
   * must come from a domain DIFFERENT from the build's own, or it is same-field, not cross-checked.
   */
  readonly domain?: string;
}

/**
 * A hashed FETCH RECEIPT — the TODAY-axis primitive (BUILD-ORDER 8.6). A retrieval claim in 2026 is
 * credible only if it carries a CONTENT DIGEST + TIMESTAMP, not a bare URL (RFC 9162 CT inclusion
 * proofs, in-toto/SLSA subject-by-digest attestations). This is the minimal, offline-safe form: the
 * `bodySha256` binds the fetched bytes and the `seal` folds the receipt into the spine hashchain at
 * `priorRoot` (composed over the EXISTING spine fold — no second mechanism), so a swapped body or a
 * swapped receipt is tamper-evident and fails closed. Produced ONLY when a real fetch happens
 * (see {@link makeFetchReceipt}); its ABSENCE is a labeled seam, never a fabricated success.
 */
export interface FetchReceipt {
  /** The URL the body was fetched from. */
  readonly url: string;
  /** sha256(fetched body) as lowercase hex — binds the exact bytes retrieved. */
  readonly bodySha256: string;
  /** ISO-8601 instant of retrieval (the "seen at time T" claim). */
  readonly fetchedAt: string;
  /** The spine cumulative root this receipt is sealed against (ZERO_HASH = standalone/genesis). */
  readonly priorRoot: string;
  /** foldRoot(priorRoot, receiptEvent) — the spine-native SEAL committing this receipt to history. */
  readonly seal: string;
}

/** The three axes of the research triple — each a DISTINCT machine predicate, none implying another. */
export type ResearchAxis = "today" | "historical" | "cross-disc";

/**
 * A source slotted into ONE axis of the research triple. Only the fields its axis needs are
 * load-bearing: TODAY reads `receipt` + `fetchedBody` (freshness + a verifiable receipt);
 * HISTORICAL reads `citation.asOf` (must FAIL recency); CROSS-DISC reads `citation.domain`
 * (must differ from the build domain) + `analogicalMapping` (the explicit shape-transfer).
 */
export interface AxisSource {
  readonly axis: ResearchAxis;
  readonly citation: Citation;
  /** CROSS-DISC only: the explicit analogical mapping from the foreign domain onto this build's problem. */
  readonly analogicalMapping?: string;
  /** TODAY only: the hashed fetch receipt. Absent → the TODAY slot is an honest unverifiable seam. */
  readonly receipt?: FetchReceipt;
  /** TODAY only: the fetched body the receipt binds (for sound sha256 re-verification). */
  readonly fetchedBody?: string;
}

/**
 * A research triple: one source per axis. All three slots are load-bearing — a triple that fills
 * only one or two axes is REJECTED (a same-day-only search is a third of the picture). Evaluated by
 * `evaluateResearchTriple` in research_loop.ts against a build-domain + the currency recency logic.
 */
export interface ResearchTriple {
  readonly today: AxisSource;
  readonly historical: AxisSource;
  readonly crossDisc: AxisSource;
}

/** The provenance status of a claim — the honest verifiability label. */
export type ProvenanceStatus =
  | "grounded" // has a resolvable citation whose text supports the claim
  | "citation-unresolvable" // cited, but the source can't be resolved (citation-hallucination)
  | "unsupported" // source resolves but doesn't support the claim (statement-hallucination)
  | "ungrounded" // no citation at all
  | "unverifiable"; // couldn't check (offline / no verifier) — flagged honestly, not hidden

export interface ClaimProvenance {
  readonly status: ProvenanceStatus;
  readonly reason: string;
  /**
   * True when this verdict was reached by a SOUND, deterministic check — structural verbatim-presence
   * of the quoted `supportingText` against the FETCHED source — so a fuzzy tier can never overturn it.
   * Absent/false = a fuzzy or semantic residual (e.g. a faithfulness score) that may still climb.
   * Additive marker only; it does NOT redefine `ProvenanceStatus` (a sound `unsupported` is still the
   * statement-hallucination status, now flagged as authoritative).
   */
  readonly sound?: boolean;
}

/** A single research finding — a claim that MUST carry provenance to be usable. */
export interface ResearchClaim {
  readonly id: string;
  readonly text: string;
  readonly citations: readonly Citation[];
  /** Set by the floor (4c) after checking; undefined until verified. */
  provenance?: ClaimProvenance;
}

// ── The research-need detector (rule-first; deterministic) ────────────────────

const RECENCY_RX = /\b(current|latest|newest|today|2026|2027|recent|nowadays|as of|state of the art|sota|up to date)\b/i;
const RESEARCH_GOAL_RX = /\b(research|survey|review|investigate|literature|compare|landscape|prior art|benchmark|find out|look into)\b/i;
const PRIOR_ART_RX = /\b(does .* exist|already (built|exists|available)|alternative to|instead of building|off the shelf|adopt or build)\b/i;

/**
 * Detect whether a goal needs a research pass, and why. Deterministic (rule-first); an
 * embedding/LLM seam can refine the unfamiliar-domain signal, but recency and explicit-research
 * goals are caught structurally. `canVerify` gates recency: if there's no live search, research
 * still runs but its output is honestly marked unverifiable rather than pretending currency.
 */
export function detectResearchNeed(goal: string, opts: { unfamiliarTerms?: readonly string[] } = {}): ResearchNeed {
  const triggers: ResearchTrigger[] = [];
  if (RECENCY_RX.test(goal)) triggers.push("recency-sensitive");
  if (RESEARCH_GOAL_RX.test(goal)) triggers.push("explicit-research-goal");
  if (PRIOR_ART_RX.test(goal)) triggers.push("prior-art-check");
  if ((opts.unfamiliarTerms?.length ?? 0) > 0) triggers.push("unfamiliar-domain");

  const keywords = extractKeywords(goal);
  if (triggers.length === 0) {
    return { needed: false, triggers: ["none"], reason: "no external-knowledge signal detected", keywords };
  }
  return {
    needed: true,
    triggers,
    reason: `research warranted: ${triggers.join(", ")}`,
    keywords,
  };
}

/** Extract simple keyword tokens from a goal (content words, deduped). */
export function extractKeywords(goal: string): string[] {
  const stop = new Set(["the", "a", "an", "and", "or", "for", "to", "of", "in", "on", "with", "how", "what", "is", "are", "do", "does", "build", "make", "create", "using", "use"]);
  return [...new Set(
    goal.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length > 2 && !stop.has(w)),
  )].slice(0, 8);
}
