/**
 * Finding 2.5 — the fleet CORRELATION barrier (the fourth fleet-composition barrier).
 *
 * The nine-barrier gate's diversity (R38: only 2 of 9 barriers share sha256; 7 are independent) protects
 * a SINGLE decision from a common-cause fault. But that diversity is defeated ACROSS AGENTS: if N agents
 * act on the SAME common-cause basis — the same model, the same poisoned input, the same retrieval index
 * — their decisions are not independent, and a single fault in that shared basis flips them all together
 * (R39, scenario 3). Each decision is individually gate-approved; the fleet's diversity is the casualty.
 *
 * This barrier enforces a DIVERSITY FLOOR structurally: cap how many CONCURRENT effects may share one
 * common-cause basis, so no single cause exceeds a blast-radius threshold — the CCF beta-factor /
 * common-cause-component-group (CCCG) model, and the cross-industry diversity mandate (grid: not all
 * generation from one source; aviation: dissimilar redundancy; finance: concentration limits).
 *
 * DISCIPLINE (research, 2026-08-09):
 *  - CCCG: concurrent effects sharing a coupling mechanism (basis) form a common-cause group; a fault in
 *    the basis fails the whole group. The blast radius is the group size.
 *  - Beta-factor / k-of-n: bound how many may share one cause (the multiple-Greek-letter conditional:
 *    the N+1-th sharing a basis is the one to deny). Diversity + separation reduce the coupling.
 *  - Fail-safe: unknown basis ⇒ treated as correlated (deny) — diversity cannot be proven.
 *  - Transient/reversible: the count is over CONCURRENT (in-flight) effects; it clears as they complete.
 *
 * BUILT vs SEAM: BUILT + proven in-env is the correlation-threshold logic (per-basis concurrent count,
 * threshold cap, fail-safe, transient). The real CROSS-HOST CORRELATION OBSERVATION — knowing what basis
 * every agent across every host is acting on — is the SEAM.
 *
 * WHAT IT BOUNDS vs NOT: it bounds the blast radius of a MODELED shared cause (a known basis dimension:
 * model id, input hash, index id). It does NOT detect a NOVEL/unmodeled shared cause — if the coupling
 * mechanism is not represented in the basis, the barrier cannot see the correlation. Like R38, this is
 * about the DIVERSITY of the fleet's decision basis, not a guarantee of independence. Scenario 3 only.
 */

export interface CorrelationPolicy {
  /** Max concurrent effects allowed to share one common-cause basis (the diversity floor / blast cap). */
  readonly maxPerBasis: number;
}

export interface CorrelatedEffect {
  readonly id: string;
  readonly agent: string;
  /** The common-cause basis (model id / input hash / index id). `undefined` = unknown ⇒ fail-safe. */
  readonly basis: string | undefined;
}

export type CorrelationCheck =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: string };

export const FLEET_BASIS_DIMENSIONS = ["infrastructure", "input", "model", "operator", "policy", "retrieval", "specification", "tool"] as const;
export type FleetBasisDimension = typeof FLEET_BASIS_DIMENSIONS[number];
export type ExplicitCorrelationBasis = Readonly<Record<FleetBasisDimension, string>>;

/** The one explicit-dimension diversity predicate used by durable fleet admission. */
export function checkExplicitCorrelation(incoming: ExplicitCorrelationBasis, active: readonly ExplicitCorrelationBasis[], maxPerBasis: number): readonly string[] {
  if (!Number.isSafeInteger(maxPerBasis) || maxPerBasis < 1) return Object.freeze(["unknown-correlation-policy"]);
  const reasons: string[] = [];
  for (const dimension of FLEET_BASIS_DIMENSIONS) {
    const basis = incoming[dimension];
    if (typeof basis !== "string" || basis.length < 1) { reasons.push(`unknown-basis:${dimension}`); continue; }
    const count = active.filter((candidate) => candidate[dimension] === basis).length;
    if (count >= maxPerBasis) reasons.push(`correlated-lockstep:${dimension}:${count + 1}>${maxPerBasis}`);
  }
  return Object.freeze(reasons);
}

/**
 * The fleet-correlation ledger. Tracks in-flight (concurrent) effects by basis and checks an incoming
 * effect against the diversity threshold. Total + fail-safe. Registration clears on complete (transient).
 */
export class FleetCorrelationLedger {
  private readonly inFlight = new Map<string, CorrelatedEffect>();

  register(effect: CorrelatedEffect): void {
    this.inFlight.set(effect.id, effect);
  }

  /** The effect completed (committed or rolled back) → it leaves the concurrent set. */
  complete(id: string): boolean {
    return this.inFlight.delete(id);
  }

  private countSharing(basis: string, exceptId: string): number {
    let n = 0;
    for (const e of this.inFlight.values()) {
      if (e.id !== exceptId && e.basis === basis) n++;
    }
    return n;
  }

  /**
   * Check an incoming effect: deny if its basis is unknown, or if admitting it would push the count of
   * concurrent effects sharing that basis beyond the diversity threshold (correlated lockstep).
   */
  check(incoming: CorrelatedEffect, policy: CorrelationPolicy): CorrelationCheck {
    if (incoming.basis === undefined) return { ok: false, reason: "unknown-basis" }; // fail-safe
    if (!Number.isSafeInteger(policy.maxPerBasis) || policy.maxPerBasis < 1) return { ok: false, reason: "unknown-correlation-policy" };
    const sharing = this.countSharing(incoming.basis, incoming.id);
    if (sharing >= policy.maxPerBasis) {
      return { ok: false, reason: `correlated-lockstep:${incoming.basis}:${sharing + 1}>${policy.maxPerBasis}` };
    }
    return { ok: true };
  }
}
