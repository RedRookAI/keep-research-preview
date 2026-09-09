/**
 * Citation/provenance floor + faithfulness seam (Increment 4c) — the sound research Tier-0.
 *
 * SOTA basis (2026-08-04): enforce provenance STRUCTURALLY, not by prompt — "hallucinated
 * attributions are filtered automatically, not asked-about-nicely; the contract is in code"
 * (deep-research-agent). Two failure modes checked separately (arXiv 2604.03173; 2605.06635):
 *  - CITATION hallucination (source doesn't exist) → DETERMINISTIC: a citation with no resolvable
 *    locator can never ground a claim. Caught in code, sound.
 *  - STATEMENT hallucination (source doesn't support the claim) → a FAITHFULNESS check; small
 *    encoder verifiers (MiniCheck/HHEM) match large judges at a fraction of cost (arXiv 2607.12257),
 *    used to SCORE not generate. Injected seam; when absent, unsupported-ness can't be confirmed so
 *    the claim is flagged `unverifiable` (honest) rather than passed.
 *
 * The deterministic checks GATE (sound); the faithfulness seam only downgrades/ flags. This plugs
 * into the VerificationCascade as a Tier-0 floor. Zero deps.
 */

import type { ResearchClaim, ClaimProvenance, ProvenanceStatus, Citation } from "./research_need.js";
import type { VerificationItem, VerificationTier, TierResult } from "../cascade/verification_cascade.js";
import { containsVerbatim } from "./grounded_answer.js";

/**
 * A faithfulness checker: does the citation's supportingText actually support the claim text?
 * Injected (a MiniCheck/HHEM-class encoder, or a model judge). Returns a support score in [0,1].
 * Absent → statement-faithfulness can't be confirmed (claim flagged unverifiable, not passed).
 */
export type FaithfulnessChecker = (claimText: string, supportingText: string) => number;

/** A resolver that says whether a citation locator actually resolves (URL reachable / DOI valid). */
export type LocatorResolver = (locator: string) => boolean;

/**
 * A fail-honest URL-fetch port for SOUND verbatim-presence checking — the strengthening of the WEAK
 * boolean `LocatorResolver` (does-the-URL-resolve) into the SOUND form (does the quoted text actually
 * appear there). Given a citation locator, return the fetched page's text, or `null` when
 * unreachable/offline/no-port. Modeled on research_loop's `SearchPort`: injected, offline-safe,
 * sync-or-async. The fetched text is UNTRUSTED-derived content (per effect_provenance) and is consumed
 * ONLY as a structural presence oracle — it never influences a tool argument or the verdict beyond
 * present/absent, so it carries no declassification and needs none.
 */
export type CitationFetchPort = (locator: string) => Promise<string | null> | (string | null);

export interface ProvenanceOptions {
  readonly faithfulness?: FaithfulnessChecker;
  /** Minimum support score to count as grounded. Default 0.6. */
  readonly supportThreshold?: number;
  /** Optional resolver; default treats any non-empty locator as structurally present (not fake-empty). */
  readonly resolver?: LocatorResolver;
  /**
   * Optional fail-honest fetch port. Present → a cited quote is SOUNDLY verified present/absent at its
   * source. Absent → offline: the verbatim floor is inert and the honest base verdict stands
   * (`unverifiable`, never a silent pass or a false fail).
   */
  readonly fetch?: CitationFetchPort;
}

/**
 * Verify one claim's provenance. Deterministic first (ungrounded / citation-unresolvable), then the
 * faithfulness seam (unsupported / grounded / unverifiable). Never throws.
 */
export function verifyClaim(claim: ResearchClaim, opts: ProvenanceOptions = {}): ClaimProvenance {
  const threshold = opts.supportThreshold ?? 0.6;

  if (claim.citations.length === 0) {
    return { status: "ungrounded", reason: "no citation attached (never cite from memory)" };
  }

  // Deterministic: at least one citation must have a resolvable locator.
  const withLocator = claim.citations.filter((c) => c.locator && c.locator.trim().length > 0);
  if (withLocator.length === 0) {
    return { status: "citation-unresolvable", reason: "citation has no locator (URL/DOI) — cannot be a real source" };
  }
  if (opts.resolver) {
    const anyResolves = withLocator.some((c) => opts.resolver!(c.locator!));
    if (!anyResolves) {
      return { status: "citation-unresolvable", reason: "no cited locator resolves (fake/dead reference — citation hallucination)" };
    }
  }

  // Statement faithfulness: does the source text actually support the claim?
  const grounded = withLocator.filter((c) => c.supportingText && c.supportingText.trim().length > 0);
  if (grounded.length === 0) {
    return { status: "unverifiable", reason: "citation resolves but no supporting excerpt captured to check faithfulness" };
  }
  if (!opts.faithfulness) {
    // can't confirm the source SUPPORTS the claim → honest unverifiable, not a pass
    return { status: "unverifiable", reason: "no faithfulness checker: source exists but support-of-claim unconfirmed (flagged for human)" };
  }
  const bestScore = Math.max(...grounded.map((c) => opts.faithfulness!(claim.text, c.supportingText!)));
  if (bestScore >= threshold) {
    return { status: "grounded", reason: `citation resolves and supports the claim (score ${bestScore.toFixed(2)})` };
  }
  return { status: "unsupported", reason: `source resolves but does NOT support the claim (score ${bestScore.toFixed(2)} < ${threshold}) — statement hallucination` };
}

/**
 * SOUND verbatim-presence overlay on {@link verifyClaim} — STRICTLY ADDITIVE, PER-CITATION.
 *
 * Verbatim presence proves a quote EXISTS at its source; it never proves the source SUPPORTS the claim
 * (arXiv 2604.03173: a citation can be "real but unsupportive"). So presence is a lexical VETO on
 * fabrication, never a grant of support. Given a fetch port, each checkable citation is fetched and
 * classified:
 *  - PRESENT (quote verbatim on the page)   → a genuine citation; its faithfulness score still counts.
 *  - REACHABLE-BUT-ABSENT (page fetched, quote not there) → a PROVEN fabrication; the citation is
 *    INVALIDATED — its faithfulness score is DISCARDED from the aggregation (proven-fabricated evidence
 *    grounds nothing), so a fabricated-but-high-faithfulness quote can never rescue the claim.
 *  - UNREACHABLE (offline / non-2xx / no port) → an honest seam; the citation's score is RETAINED
 *    (unreachable ≠ absent — a transient 404 must not be punished as a fabrication).
 *
 * Verdict, composed over the EXISTING {@link verifyClaim} aggregation (no second mechanism):
 *  (b) a proven fabrication with NO verbatim-present sibling is a SOUND `unsupported` — the
 *      statement-hallucination, a sound fail a fuzzy tier cannot overturn.
 *  (a)+(c) otherwise the fuzzy verdict is RECOMPUTED over the SURVIVING citations only (present +
 *      unreachable), and it is NEVER upgraded and NEVER marked sound: presence proves existence, not
 *      support. `grounded, sound:true` does not exist — grounding is never sound; only FAILS are.
 *
 * Async because fetching is a port; the sync {@link verifyClaim} stays the offline default,
 * byte-unchanged (no fetch port → this returns `verifyClaim(claim, opts)` verbatim).
 */
export async function verifyClaimSound(claim: ResearchClaim, opts: ProvenanceOptions = {}): Promise<ClaimProvenance> {
  const base = verifyClaim(claim, opts);
  // No fetch port → offline default, byte-identical to the sync floor. Hard deterministic fails
  // (no citation / no resolvable locator) have nothing to fetch → the honest base stands.
  if (!opts.fetch || base.status === "ungrounded" || base.status === "citation-unresolvable") {
    return base;
  }
  const checkable = claim.citations.filter(
    (c) => c.locator && c.locator.trim().length > 0 && c.supportingText && c.supportingText.trim().length > 0,
  );
  if (checkable.length === 0) return base;

  // Fetch-classify each citation into present / reachable-absent / unreachable.
  const present: Citation[] = [];
  const unreachable: Citation[] = [];
  const absent: Citation[] = []; // reachable-but-ABSENT = proven fabrication
  for (const c of checkable) {
    const page = await opts.fetch(c.locator!);
    if (page === null || page === undefined) unreachable.push(c); // honest seam — score retained
    else if (containsVerbatim(page, c.supportingText!)) present.push(c);
    else absent.push(c);
  }

  // (b) A proven fabrication with NO verbatim-present sibling → SOUND statement-hallucination fail.
  //     (A present sibling means real evidence exists to weigh below; the fabrication is still discarded.)
  if (absent.length > 0 && present.length === 0) {
    return {
      status: "unsupported",
      reason: "cited quote is reachable-but-ABSENT at its source — the quoted words are not there (statement hallucination)",
      sound: true,
    };
  }

  // (a)+(c) INVALIDATE the absent citations (their scores are discarded — `absent` is deliberately NOT in
  // `survivors`) and RECOMPUTE the fuzzy verdict over survivors (present + unreachable) only. Presence
  // NEVER upgrades and the recomputed verdict is NEVER marked sound: presence proves existence, not support.
  const survivors = [...present, ...unreachable];
  return verifyClaim({ ...claim, citations: survivors }, opts);
}

/** Async, fetch-aware sibling of {@link verifyProvenance}: attaches SOUND verbatim provenance per claim. */
export async function verifyProvenanceSound(
  claims: readonly ResearchClaim[],
  opts: ProvenanceOptions = {},
): Promise<{ claims: ResearchClaim[]; summary: Record<ProvenanceStatus, number> }> {
  const summary: Record<ProvenanceStatus, number> = {
    grounded: 0,
    "citation-unresolvable": 0,
    unsupported: 0,
    ungrounded: 0,
    unverifiable: 0,
  };
  const out: ResearchClaim[] = [];
  for (const c of claims) {
    const provenance = await verifyClaimSound(c, opts);
    summary[provenance.status]++;
    out.push({ ...c, provenance });
  }
  return { claims: out, summary };
}

/** Verify a batch of claims, attaching provenance to each. Returns the verified claims + a summary. */
export function verifyProvenance(
  claims: readonly ResearchClaim[],
  opts: ProvenanceOptions = {},
): { claims: ResearchClaim[]; summary: Record<ProvenanceStatus, number> } {
  const summary: Record<ProvenanceStatus, number> = {
    grounded: 0,
    "citation-unresolvable": 0,
    unsupported: 0,
    ungrounded: 0,
    unverifiable: 0,
  };
  const out = claims.map((c) => {
    const provenance = verifyClaim(c, opts);
    summary[provenance.status]++;
    return { ...c, provenance };
  });
  return { claims: out, summary };
}

/** Payload for a research-provenance verification item. */
export interface ResearchVetPayload {
  readonly claims: readonly ResearchClaim[];
  readonly options?: ProvenanceOptions;
}

/**
 * TIER 0 — the research provenance floor. A claim with a hard provenance failure (ungrounded or
 * citation-unresolvable) is a SOUND fail: no brain can bless a fabricated citation. A verbatim quote
 * that is reachable-but-ABSENT at its source (verified via an injected fetch port) is ALSO a sound fail
 * — the statement-hallucination — hard-blocked here so a fabricated citation is never exported as
 * verified. A `unsupported` from a fuzzy faithfulness score (no fetch confirmation) and `unverifiable`
 * are surfaced but not hard-blocked (they climb for a brain / human). This registers into the
 * VerificationCascade exactly like the LogicVet floor.
 */
export class ResearchProvenanceFloorTier implements VerificationTier<ResearchVetPayload> {
  readonly tier = 0;
  readonly name = "research-provenance-floor";
  readonly sound = true;
  available(): boolean {
    return true; // deterministic — always available
  }
  async verify(item: VerificationItem<ResearchVetPayload>): Promise<TierResult> {
    const { claims, options } = item.payload;
    // Sound overlay: when a fetch port is injected, a reachable-but-absent verbatim quote becomes a SOUND
    // `unsupported`; offline it is byte-identical to verifyProvenance.
    const { claims: verified, summary } = await verifyProvenanceSound(claims, options ?? {});
    // A reachable-but-absent verbatim quote is a SOUND statement-hallucination (source real, quote fabricated)
    // — hard-fail it ALONGSIDE the deterministic citation failures. A fuzzy `unsupported` (a semantic
    // faithfulness score below threshold, no fetch confirmation) is NOT sound and still climbs.
    const soundUnsupported = verified.filter(
      (c) => c.provenance?.status === "unsupported" && c.provenance.sound === true,
    ).length;
    const hardFails = summary.ungrounded + summary["citation-unresolvable"] + soundUnsupported;
    if (hardFails > 0) {
      return {
        tier: 0,
        name: this.name,
        decision: "fail",
        reason: `${hardFails} claim(s) with fabricated/absent citations (ungrounded: ${summary.ungrounded}, unresolvable: ${summary["citation-unresolvable"]}, quote-absent-at-source: ${soundUnsupported})`,
        sound: true,
        certainty: 1,
      };
    }
    const fuzzyUnsupported = summary.unsupported - soundUnsupported;
    const soft = fuzzyUnsupported + summary.unverifiable;
    if (soft > 0) {
      // can't soundly pass or fail — climb for a brain/human to weigh the faithfulness residual
      return {
        tier: 0,
        name: this.name,
        decision: "undecided",
        reason: `${summary.grounded} grounded; ${soft} need faithfulness review (unsupported: ${fuzzyUnsupported}, unverifiable: ${summary.unverifiable})`,
        sound: true,
        certainty: 0.5,
      };
    }
    return { tier: 0, name: this.name, decision: "pass", reason: `all ${summary.grounded} claims grounded + supported`, sound: true, certainty: 1 };
  }
}
