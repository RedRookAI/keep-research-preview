/**
 * ResearchLoop orchestrator (Increment 4b) — the "become a SOTA expert first" pass.
 *
 * SOTA basis (2026-08-04): bounded research agents with a critic loop cap (deep-research-agent
 * "max 2 iterations"; Agon). "Cite a retrieved source for every claim; never cite from memory."
 * When no live search is available, the pass is HONEST: it still distills what it can but marks
 * claims `unverifiable` rather than fabricating currency (the currency layer's can't-verify rule).
 *
 * The loop is provider-agnostic and offline-safe: the search + distill steps are injected seams.
 * Offline, the loop still runs (producing honestly-unverifiable notes from local knowledge); with
 * a live search seam, claims get real citations to be checked by the floor (4c).
 *
 * Zero deps.
 */

import { createHash } from "node:crypto";
import {
  detectResearchNeed,
  type ResearchNeed,
  type ResearchClaim,
  type Citation,
  type FetchReceipt,
  type ResearchAxis,
  type AxisSource,
  type ResearchTriple,
} from "./research_need.js";
import { foldRoot, ZERO_HASH } from "../spine/hashchain.js";
import { CURRENT_SCHEMA_VERSION, type StagedEvent } from "../spine/event.js";
import { isFreshSource, isHistoricalSource } from "../currency/temporal_context.js";

/** A source returned by the search seam. */
export interface ResearchSource {
  readonly title: string;
  readonly locator?: string; // URL / DOI
  readonly snippet: string; // retrieved text (the grounding excerpt)
  readonly asOf?: string;
  /** The full fetched body, when the seam actually retrieved bytes (not just a snippet). Enables a receipt. */
  readonly body?: string;
  /** ISO instant the body was fetched. Present with `body` for a real retrieval. */
  readonly fetchedAt?: string;
}

/** Injected live-search seam. Returns sources, or null when offline/unavailable. */
export type SearchPort = (query: string, keywords: readonly string[]) => Promise<readonly ResearchSource[] | null> | (readonly ResearchSource[] | null);

/**
 * Injected distiller: turn retrieved sources into claims. In production this is a model call
 * (through the Adaptive Prompt Layer); the default here is a deterministic distiller that makes
 * one claim per source grounded in that source's snippet — so the loop is testable with no model.
 */
export type Distiller = (goal: string, sources: readonly ResearchSource[]) => readonly ResearchClaim[];

/** Whether currency can be verified this session (from the currency layer's TemporalContext). */
export interface ResearchContext {
  readonly canVerify: boolean;
  readonly todayISO: string;
}

/** The output of a research pass. */
export interface ResearchReport {
  readonly need: ResearchNeed;
  readonly claims: readonly ResearchClaim[];
  /** True if a live search actually ran (else claims are from local knowledge, unverifiable). */
  readonly searched: boolean;
  /** Honest caveat surfaced to the human/plan (staleness / couldn't-verify). */
  readonly caveat?: string;
  readonly iterations: number;
  /**
   * Hashed fetch receipts, one per source that carried a real fetched `body` + `fetchedAt` — the
   * TODAY-axis evidence. Chained: each receipt seals against the prior one's seal (spine-native fold),
   * so the batch is a tamper-evident mini-chain. Empty when the seam returned only snippets (offline
   * / no bytes) — honest absence, never a fabricated receipt.
   */
  readonly receipts?: readonly FetchReceipt[];
}

export interface ResearchLoopDeps {
  readonly search: SearchPort;
  readonly distill?: Distiller;
  readonly context: ResearchContext;
  /** Max search→distill iterations (bounded critic loop — rabbit-hole guard). Default 2. */
  readonly maxIterations?: number;
}

/** Default deterministic distiller: one claim per source, grounded in that source's snippet. */
export const defaultDistiller: Distiller = (goal, sources) =>
  sources.map((s, i) => {
    const citation: Citation = {
      id: `cite_${i}`,
      title: s.title,
      ...(s.locator !== undefined ? { locator: s.locator } : {}),
      supportingText: s.snippet,
      ...(s.asOf !== undefined ? { asOf: s.asOf } : {}),
    };
    return {
      id: `claim_${i}`,
      text: `Regarding "${goal}": ${s.snippet}`,
      citations: [citation],
    };
  });

export class ResearchLoop {
  constructor(private readonly deps: ResearchLoopDeps) {}

  /**
   * Run the bounded research pass for a goal. Detects need; if needed, searches (bounded) and
   * distills into cited claims. Honest about currency: no live search → claims marked as
   * from-local-knowledge with an unverifiable caveat, never fabricated currency.
   */
  async run(goal: string, opts: { unfamiliarTerms?: readonly string[] } = {}): Promise<ResearchReport> {
    const need = detectResearchNeed(goal, opts);
    if (!need.needed) {
      return { need, claims: [], searched: false, iterations: 0 };
    }

    const distill = this.deps.distill ?? defaultDistiller;
    const maxIter = this.deps.maxIterations ?? 2;
    const allSources: ResearchSource[] = [];
    const seen = new Set<string>();
    let searched = false;
    let iterations = 0;

    for (let i = 0; i < maxIter; i++) {
      iterations++;
      const query = `${goal} ${need.keywords.slice(0, 4).join(" ")}`.trim();
      const results = await this.deps.search(query, need.keywords);
      if (results === null) break; // offline / unavailable — stop searching, stay honest
      searched = true;
      // dedup across iterations by locator (or title when no locator) — a real search often
      // returns overlapping top results; re-distilling identical sources is wasteful.
      for (const r of results) {
        const key = r.locator ?? r.title;
        if (!seen.has(key)) {
          seen.add(key);
          allSources.push(r);
        }
      }
      // bounded: if we already have enough distinct sources, stop early (avoid rabbit hole)
      if (allSources.length >= 5) break;
    }

    const claims = allSources.length > 0 ? distill(goal, allSources) : [];

    // TODAY-axis evidence: mint a hashed receipt for every source that actually delivered BYTES (a
    // real fetch), chaining each against the prior seal so the batch is a tamper-evident mini-chain
    // (spine-native fold). Snippet-only sources mint nothing — honest absence, never a fake receipt.
    const receipts: FetchReceipt[] = [];
    let priorRoot = ZERO_HASH;
    for (const s of allSources) {
      if (s.body !== undefined && s.fetchedAt !== undefined && s.locator) {
        const r = makeFetchReceipt(s.locator, s.body, s.fetchedAt, priorRoot);
        receipts.push(r);
        priorRoot = r.seal;
      }
    }

    // Honesty: currency framing.
    let caveat: string | undefined;
    if (!searched) {
      caveat = `no live search available (as of ${this.deps.context.todayISO}); findings are from local knowledge and should be treated as UNVERIFIED for anything time-sensitive`;
    } else if (!this.deps.context.canVerify) {
      caveat = `search ran but currency could not be confirmed; treat time-sensitive claims as of ${this.deps.context.todayISO} with caution`;
    }

    return {
      need,
      claims,
      searched,
      ...(caveat !== undefined ? { caveat } : {}),
      iterations,
      ...(receipts.length > 0 ? { receipts } : {}),
    };
  }
}

// ── The fetch-receipt primitive (BUILD-ORDER 8.6 OWNS this) ───────────────────
//
// A retrieval claim in 2026 is credible only if it carries sha256(body) + a timestamp — a bare URL
// is a claim, not evidence (RFC 9162 CT inclusion proofs; in-toto/SLSA subject-by-digest). This is
// the minimal offline-safe form of that posture: the receipt binds the exact fetched bytes and folds
// itself into the spine hashchain via the spine's OWN `foldRoot` (no second mechanism). A swapped body
// breaks `bodySha256`; a swapped receipt breaks `seal`. Both fail closed under {@link verifyFetchReceipt}.

function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/**
 * The canonical spine event representing a fetch receipt. Building a real StagedEvent (rather than an
 * ad-hoc string) is what makes the seal COMPOSED over the spine — foldRoot hashes exactly these bytes
 * the same way the audit chain does, so a receipt can be sealed into a live spine block unchanged.
 */
function receiptEvent(url: string, bodySha256: string, fetchedAt: string): StagedEvent {
  return {
    id: `fetch:${bodySha256}`,
    schemaVersion: CURRENT_SCHEMA_VERSION,
    type: "generic",
    ts: Number.isNaN(Date.parse(fetchedAt)) ? 0 : Date.parse(fetchedAt),
    actor: "research-loop",
    payload: { kind: "fetch-receipt", url, bodySha256, fetchedAt },
  };
}

/**
 * Mint a hashed fetch receipt from a REAL fetched body. `priorRoot` is the spine cumulative root to
 * seal against (default {@link ZERO_HASH} = standalone/genesis, so an offline mint is still valid and
 * self-consistent; wire the live spine head to bind the receipt to history). Deterministic in its
 * inputs — same (url, body, fetchedAt, priorRoot) always yields the same seal.
 */
export function makeFetchReceipt(
  url: string,
  body: string,
  fetchedAt: string,
  priorRoot: string = ZERO_HASH,
): FetchReceipt {
  const bodySha256 = sha256Hex(body);
  const seal = foldRoot(priorRoot, receiptEvent(url, bodySha256, fetchedAt));
  return { url, bodySha256, fetchedAt, priorRoot, seal };
}

/**
 * Verify a fetch receipt against the body it claims to bind. Fails closed (returns false) when the
 * body's sha256 differs from `bodySha256` (content tamper / fabricated body) OR when the receipt's
 * `seal` does not recompute from its own fields (receipt tamper). A receipt you cannot re-derive is
 * not a receipt. Never throws.
 */
export function verifyFetchReceipt(receipt: FetchReceipt, body: string): boolean {
  if (sha256Hex(body) !== receipt.bodySha256) return false;
  const seal = foldRoot(receipt.priorRoot, receiptEvent(receipt.url, receipt.bodySha256, receipt.fetchedAt));
  return seal === receipt.seal;
}

// ── The research triple predicate (three axes, three DISTINCT machine checks) ──

/** Per-axis verdict. `seam` marks an HONEST unverifiable (TODAY offline) — not a pass, not a fabrication. */
export interface AxisVerdict {
  readonly axis: ResearchAxis;
  readonly ok: boolean;
  /** TODAY only: true when the slot is an honest unverifiable seam (no receipt, offline) rather than a fail. */
  readonly seam?: boolean;
  readonly reason: string;
}

/** The composed verdict over a research triple. */
export interface TripleVerdict {
  /** All three axes satisfied (a TODAY seam does NOT count as satisfied). */
  readonly ok: boolean;
  /**
   * The only reason for `!ok` is an honest TODAY seam AND the other two axes pass AND nothing was a
   * proven fabrication. FRONT-OF-HOUSE: an offline operator lands here — unfilled TODAY, not blocked.
   */
  readonly honestSeam: boolean;
  readonly slots: Record<ResearchAxis, AxisVerdict>;
  readonly reason: string;
}

export interface TripleEvalContext {
  /** Today, YYYY-MM-DD — from the currency layer's TemporalContext. */
  readonly todayISO: string;
  /** This build's own domain. The CROSS-DISC source must NOT be from this domain. */
  readonly buildDomain: string;
  /** HISTORICAL: a source must be at least this old (days). Default 365 — a same-day link can't fill it. */
  readonly minHistoricalAgeDays?: number;
  /** TODAY: a fresh source must be at most this old (days). Default 30. */
  readonly maxFreshAgeDays?: number;
}

function evalToday(src: AxisSource, ctx: TripleEvalContext): AxisVerdict {
  const maxAge = ctx.maxFreshAgeDays ?? 30;
  // No receipt at all → honest, offline SEAM. Never a silent pass; never a fabrication accusation.
  if (!src.receipt) {
    return { axis: "today", ok: false, seam: true, reason: "no fetch receipt (offline): TODAY unverifiable — honest seam, not a pass" };
  }
  // A receipt with no body to check against cannot be re-verified → fail closed (a receipt you can't
  // check is a bare claim). This is the tamper-evident property: the receipt must carry its bytes.
  if (src.fetchedBody === undefined) {
    return { axis: "today", ok: false, reason: "receipt present but no fetched body to re-verify sha256 against — fails closed" };
  }
  if (!verifyFetchReceipt(src.receipt, src.fetchedBody)) {
    return { axis: "today", ok: false, reason: "fetch receipt does not verify (sha256(body) mismatch or broken seal) — fabricated/tampered, fails closed" };
  }
  if (!isFreshSource(src.citation.asOf, ctx.todayISO, maxAge)) {
    return { axis: "today", ok: false, reason: `receipt verifies but source as-of ${src.citation.asOf ?? "(none)"} is not fresh (> ${maxAge}d or undated) — not TODAY` };
  }
  return { axis: "today", ok: true, reason: `verified fetch receipt + fresh (as-of ${src.citation.asOf})` };
}

function evalHistorical(src: AxisSource, ctx: TripleEvalContext): AxisVerdict {
  const minAge = ctx.minHistoricalAgeDays ?? 365;
  if (!isHistoricalSource(src.citation.asOf, ctx.todayISO, minAge)) {
    return { axis: "historical", ok: false, reason: `source as-of ${src.citation.asOf ?? "(none)"} does not FAIL the recency filter (needs age >= ${minAge}d) — a fresh link cannot fill the historical axis` };
  }
  return { axis: "historical", ok: true, reason: `source is old enough (as-of ${src.citation.asOf}, >= ${minAge}d) — genuine historical grounding` };
}

function evalCrossDisc(src: AxisSource, ctx: TripleEvalContext): AxisVerdict {
  const domain = src.citation.domain?.trim();
  if (!domain) {
    return { axis: "cross-disc", ok: false, reason: "cross-disc source has no domain tag — cannot show it is from a different field" };
  }
  if (domain.toLowerCase() === ctx.buildDomain.trim().toLowerCase()) {
    return { axis: "cross-disc", ok: false, reason: `cross-disc source domain "${domain}" equals the build domain — same-field is not cross-disciplinary corroboration` };
  }
  if (!src.analogicalMapping || src.analogicalMapping.trim().length === 0) {
    return { axis: "cross-disc", ok: false, reason: `foreign-domain source ("${domain}") but no analogical mapping — a bare foreign link is not a transferred insight` };
  }
  return { axis: "cross-disc", ok: true, reason: `foreign domain "${domain}" (!= build "${ctx.buildDomain}") with an explicit analogical mapping` };
}

/**
 * Evaluate a research triple: each axis a DISTINCT machine predicate (fetched+fresh+receipt /
 * fails-recency / different-domain+mapping). All three load-bearing — a triple that fills only one or
 * two axes is REJECTED. The one honest exception is FRONT-OF-HOUSE: an offline operator who fills
 * HISTORICAL + CROSS-DISC and leaves TODAY as a labeled seam gets `honestSeam:true` (not blocked,
 * not a silent pass), distinct from a same-day-only search that FABRICATES a TODAY receipt (fails closed).
 */
export function evaluateResearchTriple(triple: ResearchTriple, ctx: TripleEvalContext): TripleVerdict {
  const today = evalToday(triple.today, ctx);
  const historical = evalHistorical(triple.historical, ctx);
  const crossDisc = evalCrossDisc(triple.crossDisc, ctx);
  const slots: Record<ResearchAxis, AxisVerdict> = { today, historical, "cross-disc": crossDisc };
  const ok = today.ok && historical.ok && crossDisc.ok;
  const honestSeam = !ok && today.seam === true && historical.ok && crossDisc.ok;
  const failed = (Object.values(slots) as AxisVerdict[]).filter((v) => !v.ok).map((v) => v.axis);
  const reason = ok
    ? "all three axes satisfied (TODAY fresh+receipt, HISTORICAL fails-recency, CROSS-DISC foreign-domain+mapping)"
    : honestSeam
      ? "HISTORICAL + CROSS-DISC filled; TODAY is an honest unverifiable seam (offline) — complete when a live fetch is available"
      : `REJECTED — unfilled/failed axes: ${failed.join(", ")} (a research claim that fills only one or two slots is a third of the picture)`;
  return { ok, honestSeam, slots, reason };
}
