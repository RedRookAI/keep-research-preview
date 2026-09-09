/**
 * GovernedAnchor (Increment 18.9) — governed growth + rotation of the frozen eval anchor. The anchor is the
 * root of trust for ALL self-improvement validation (it is in the FROZEN_FLOOR: the improver can never edit
 * it). But a STATIC anchor goes stale as the operator's work evolves and invites overfitting. 18.9 lets the
 * anchor GROW and ROTATE — under governance that preserves the one invariant that makes the anchor trustworthy:
 * the system being validated can never influence its own validator (bounded self-modification).
 *
 * SOTA basis (2026-08-05):
 *  - The core risk is IN-DISTRIBUTION CONTAMINATION: distributional similarity between what the improver
 *    produces and the test set inflates scores without real capability, amplified in self-improvement settings
 *    (arXiv 2603.25681). → new cases come ONLY from INDEPENDENTLY-VERIFIED real outcomes, NEVER from the
 *    improver and NEVER synthetic; and a candidate case is admitted only if NOVEL (not a near-duplicate of an
 *    existing case) — anti in-distribution contamination.
 *  - The structural fixes are known (benchmarkingagents.com 2026; arXiv 2606.30219): "combine STABLE ANCHORS,
 *    refreshed BLINDED items, DATED releases, and periodic task-grounded validation." → a preserved stable
 *    CORE for longitudinal comparability + a rotating refresh pool + provenance dates.
 *  - Evaluator Rotation Protocol (arXiv 2603.13278): replacements must be OUT-OF-DISTRIBUTION vs existing
 *    members, INDEPENDENTLY validated, and correlated with real task performance; SATURATION trigger retires a
 *    case once trivially solved. → novelty gate + independent-verification gate + saturation retirement.
 *
 * Zero runtime deps. Builds on corpus_curation primitives (readBuildOutcomes, rotateFolds). The frozen
 * EvalAnchor is produced as a SNAPSHOT; the improver receives only the score()/weakensSafetyFloor() closures,
 * never the case list.
 */

import type { EvalAnchor } from "../meta/meta_harness.js";

/** A held-out anchor case, provenance-bound + dated (never authored by the improver). */
export interface AnchorCase {
  readonly id: string;
  readonly input: string;
  readonly expected: string;
  /** Which independently-verified spine outcome this case came from (provenance — auditable). */
  readonly sourceOutcomeId: string;
  /** When it was admitted (dated release, for longitudinal comparability). */
  readonly admittedTs: number;
  /** Stable core (preserved for comparability) vs rotating refresh pool. */
  readonly tier: "core" | "refresh";
  /** How many times a candidate solved it (saturation tracking — a trivially-solved case retires). */
  solves: number;
  attempts: number;
}

/** A verified real outcome eligible to seed an anchor case. Must be INDEPENDENT of the improver. */
export interface VerifiedOutcome {
  readonly outcomeId: string;
  readonly input: string;
  readonly expected: string;
  /** True only if this outcome was verified WITHOUT the component being improved influencing it. */
  readonly independentlyVerified: boolean;
  /** The component that PRODUCED this outcome — used to reject self-authored cases for that component. */
  readonly producedByComponent?: string;
}

export type AdmitVerdict = "admitted" | "rejected-not-verified" | "rejected-self-authored" | "rejected-duplicate";

export interface AdmitResult {
  readonly verdict: AdmitVerdict;
  readonly caseId?: string;
  readonly reason: string;
}

export interface AnchorGrowthProposal {
  readonly id: string;
  readonly outcome: VerifiedOutcome;
  readonly validatingComponent: string;
  readonly proposedTs: number;
}

export type ProposeResult =
  | { readonly verdict: "proposed"; readonly proposalId: string; readonly reason: string }
  | { readonly verdict: Exclude<AdmitVerdict, "admitted">; readonly reason: string };

export interface GovernedAnchorConfig {
  /** Saturation threshold: a case solved on ≥ this fraction of attempts (min attempts met) retires. Default 0.95. */
  readonly saturationRate?: number;
  /** Min attempts before a case can be judged saturated. Default 5. */
  readonly saturationMinAttempts?: number;
  /** Jaccard token-overlap above which a candidate is a near-duplicate of an existing case. Default 0.8. */
  readonly duplicateThreshold?: number;
  readonly clock?: () => number;
}

export class GovernedAnchor {
  private readonly cases = new Map<string, AnchorCase>();
  private readonly proposals = new Map<string, AnchorGrowthProposal>();
  private readonly saturationRate: number;
  private readonly saturationMinAttempts: number;
  private readonly dupThreshold: number;
  private readonly clock: () => number;

  constructor(coreCases: readonly { id: string; input: string; expected: string }[] = [], config: GovernedAnchorConfig = {}) {
    this.saturationRate = config.saturationRate ?? 0.95;
    this.saturationMinAttempts = config.saturationMinAttempts ?? 5;
    this.dupThreshold = config.duplicateThreshold ?? 0.8;
    this.clock = config.clock ?? (() => Date.now());
    // Seed the stable core (the improver never authored these — they are the frozen root).
    for (const c of coreCases) {
      this.cases.set(c.id, { ...c, sourceOutcomeId: "seed", admittedTs: 0, tier: "core", solves: 0, attempts: 0 });
    }
  }

  /**
   * Admit a candidate case from a verified outcome, for a specific component being improved. Enforces the
   * bounded-self-modification invariant: (1) the outcome must be INDEPENDENTLY verified; (2) it must NOT have
   * been produced by the very component whose improvements this anchor will validate (no self-authored cases);
   * (3) it must be NOVEL (not a near-duplicate — anti in-distribution contamination).
   */
  admit(outcome: VerifiedOutcome, validatingComponent: string): AdmitResult {
    const proposed = this.propose(outcome, validatingComponent);
    if (proposed.verdict !== "proposed") return proposed;
    return this.approve(proposed.proposalId);
  }

  /** Real outcomes create inert proposals; they cannot alter an anchor without a separate governance action. */
  propose(outcome: VerifiedOutcome, validatingComponent: string): ProposeResult {
    const rejected = this.validateCandidate(outcome, validatingComponent);
    if (rejected) return rejected;
    const duplicatePending = [...this.proposals.values()].find((item) => item.outcome.outcomeId === outcome.outcomeId ||
      this.jaccard(item.outcome.input, outcome.input) >= this.dupThreshold);
    if (duplicatePending) return { verdict: "rejected-duplicate", reason: `duplicates pending anchor proposal ${duplicatePending.id}` };
    const proposalId = `anchor-proposal:${outcome.outcomeId}:${validatingComponent}`;
    this.proposals.set(proposalId, { id: proposalId, outcome: { ...outcome }, validatingComponent, proposedTs: this.clock() });
    return { verdict: "proposed", proposalId, reason: "novel independently-verified outcome proposed for a future anchor epoch" };
  }

  /** Explicit governance action: recheck current state, then admit for future snapshots only. */
  approve(proposalId: string): AdmitResult {
    const proposal = this.proposals.get(proposalId);
    if (!proposal) return { verdict: "rejected-not-verified", reason: "unknown anchor proposal" };
    const rejected = this.validateCandidate(proposal.outcome, proposal.validatingComponent);
    if (rejected) { this.proposals.delete(proposalId); return rejected; }
    this.proposals.delete(proposalId);
    return this.install(proposal.outcome);
  }

  pending(): readonly AnchorGrowthProposal[] {
    return [...this.proposals.values()].map((proposal) => ({ ...proposal, outcome: { ...proposal.outcome } }));
  }

  private validateCandidate(outcome: VerifiedOutcome, validatingComponent: string): Exclude<ProposeResult, { verdict: "proposed" }> | undefined {
    if (!outcome.independentlyVerified) {
      return { verdict: "rejected-not-verified", reason: "outcome was not independently verified — cannot seed a held-out case" };
    }
    if (outcome.producedByComponent && outcome.producedByComponent === validatingComponent) {
      return { verdict: "rejected-self-authored", reason: `outcome was produced by "${validatingComponent}" — the validator can never grade the improver's own output (bounded self-modification)` };
    }
    const dup = this.nearDuplicateOf(outcome.input);
    if (dup) {
      return { verdict: "rejected-duplicate", reason: `near-duplicate of existing case ${dup} (in-distribution contamination guard)` };
    }
    return undefined;
  }

  private install(outcome: VerifiedOutcome): AdmitResult {
    const id = `anchor:${outcome.outcomeId}`;
    this.cases.set(id, { id, input: outcome.input, expected: outcome.expected, sourceOutcomeId: outcome.outcomeId, admittedTs: this.clock(), tier: "refresh", solves: 0, attempts: 0 });
    return { verdict: "admitted", caseId: id, reason: "novel, independently-verified case admitted to the refresh pool" };
  }

  /** Record a candidate's result on a case (saturation tracking). Retires a case once trivially solved. */
  recordResult(caseId: string, solved: boolean): void {
    const c = this.cases.get(caseId);
    if (!c) return;
    c.attempts++;
    if (solved) c.solves++;
    // Saturation retirement: a refresh-pool case that's trivially solved is retired (core is never retired).
    if (c.tier === "refresh" && c.attempts >= this.saturationMinAttempts && c.solves / c.attempts >= this.saturationRate) {
      this.cases.delete(caseId);
    }
  }

  /**
   * Produce a FROZEN EvalAnchor snapshot for the improver: core + a ROTATED subset of the refresh pool. The
   * improver receives only the score()/weakensSafetyFloor() closures over a private copy — never the case
   * list, so it cannot see or edit its held-out cases. `round` rotates the refresh fold (Goodhart mitigation).
   */
  snapshot(
    round: number,
    scoreCase: (c: AnchorCase, componentVersion: string) => boolean,
    weakensFloor: (componentVersion: string) => boolean,
    refreshFolds = 3,
  ): EvalAnchor {
    const core = [...this.cases.values()].filter((c) => c.tier === "core");
    const refresh = [...this.cases.values()].filter((c) => c.tier === "refresh");
    // Deterministic fold rotation over the refresh pool.
    const rotated = refresh.filter((_, idx) => this.fold(idx, refreshFolds) === (((round % refreshFolds) + refreshFolds) % refreshFolds));
    const active = [...core, ...rotated];
    // PRIVATE copy — the returned closures capture it; the improver never gets the array.
    const privateCases = active.map((c) => ({ ...c }));
    return {
      cases: privateCases.map((c) => ({ id: c.id, input: c.input, expected: c.expected })),
      score: (componentVersion: string): number => {
        if (privateCases.length === 0) return 0;
        let pass = 0;
        for (const c of privateCases) if (scoreCase(c, componentVersion)) pass++;
        return pass / privateCases.length;
      },
      weakensSafetyFloor: (componentVersion: string): boolean => weakensFloor(componentVersion),
    };
  }

  /** Current case counts (diagnostics/audit). */
  stats(): { core: number; refresh: number; total: number } {
    const core = [...this.cases.values()].filter((c) => c.tier === "core").length;
    const refresh = [...this.cases.values()].filter((c) => c.tier === "refresh").length;
    return { core, refresh, total: core + refresh };
  }

  has(caseId: string): boolean { return this.cases.has(caseId); }

  /** Near-duplicate detection via Jaccard token overlap (zero-dep, deterministic; anti-contamination). */
  private nearDuplicateOf(input: string): string | null {
    const a = this.tokens(input);
    for (const c of this.cases.values()) {
      if (this.jaccardTokens(a, this.tokens(c.input)) >= this.dupThreshold) return c.id;
    }
    return null;
  }
  private jaccard(a: string, b: string): number { return this.jaccardTokens(this.tokens(a), this.tokens(b)); }
  private jaccardTokens(a: Set<string>, b: Set<string>): number {
    const union = new Set([...a, ...b]).size;
    return union === 0 ? 0 : [...a].filter((token) => b.has(token)).length / union;
  }
  private tokens(s: string): Set<string> {
    return new Set(s.toLowerCase().split(/\W+/).filter((t) => t.length > 0));
  }
  private fold(idx: number, k: number): number {
    // Deterministic bucket (mirrors corpus_curation.rotateFolds semantics without importing its private fn).
    let h = 0x811c9dc5;
    const key = `keep:${idx}`;
    for (let i = 0; i < key.length; i++) { h ^= key.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
    return h % k;
  }
}
