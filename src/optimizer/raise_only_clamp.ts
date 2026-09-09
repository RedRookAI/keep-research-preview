/**
 * Raise-only optimizer clamp (Build Step 2, layer 3 — the UNTRUSTED optimizer/router).
 *
 * The optimizer may propose routing / ordering / model choices to improve efficiency. It is
 * explicitly UNTRUSTED — its proposal may be arbitrary or adversarial (model-driven, possibly
 * prompt-influenced). This module is the TRUSTED TCB piece that clamps that proposal so it can
 * only ever move a verdict TOWARD caution (tighten), never away (loosen). A loosen attempt — or
 * an unrecognised proposal value — is DROPPED and recorded; the trusted verdict stands.
 *
 * SAFETY PROPERTY (the one-way ratchet): for every verdict, final_caution_rank ≥ trusted_rank.
 * This is the ocap NO-AUTHORITY-AMPLIFICATION property — an untrusted advisor cannot amplify
 * authority, only attenuate it. The optimizer proposes; the clamp disposes.
 *
 * GROUNDING (research, 2026-08-08):
 *  - Capability attenuation / POLA (agentic-skill supply-chain security): "no skill can grant a
 *    capability it does not possess"; delegation must not amplify authority. Here: the optimizer
 *    cannot grant more authority than the trusted verdicts already permit.
 *  - Planner-untrusted / arbiter-trusted (Lingering Authority; Trinity privilege separation;
 *    Saltzer-Schroeder): the untrusted planner PROPOSES; the trusted control plane DISPOSES.
 *    Attenuation is enforced externally, not by the model — a prompt payload can influence the
 *    proposal but cannot grant itself authority past the clamp.
 *  - Advisory-only controls (aviation TCAS/EGPWS warn within an envelope; medical decision-support
 *    flags but cannot auto-dose; driver-assist brakes but never accelerates past limits): the
 *    advisor can add caution/restriction, never remove a safety limit.
 *
 * A hostile optimizer that proposes "auto-proceed everything" therefore changes nothing when the
 * trusted verdicts are cautious — every loosen is dropped. It degrades to the safe baseline.
 *
 * SCOPE: this clamps VERDICTS. The optimizer never writes effects and never touches the REE
 * directly — its only channel is a proposal that this clamp filters before the gate consumes it.
 *
 * WHAT WOULD CHANGE IT: adding a new verdict axis extends the ratchet (same rule); nothing makes
 * the clamp permit a loosen. If the optimizer needed to *widen* authority, that is not the
 * optimizer's job — only the trusted floor/gate/budget (or an owner policy change) can.
 */

export type FloorValue = "reversible-execute" | "gate";
export type BudgetValue = "within-budget" | "exceeded";
export type RouteValue = "auto-proceed" | "human-hold";

/** Caution ranks: higher = more cautious. The clamp never lets a verdict move to a lower rank. */
const FLOOR_CAUTION: Record<FloorValue, number> = { "reversible-execute": 0, gate: 1 };
const BUDGET_CAUTION: Record<BudgetValue, number> = { "within-budget": 0, exceeded: 1 };
const ROUTE_CAUTION: Record<RouteValue, number> = { "auto-proceed": 0, "human-hold": 1 };

/** The trusted verdicts (computed by the floor/budget/gate — the parts the optimizer may not lower). */
export interface TrustedVerdicts {
  readonly floor: FloorValue;
  readonly budget: BudgetValue;
  readonly route: RouteValue;
}

/** The UNTRUSTED optimizer's proposal. Any field may be absent, arbitrary, or adversarial. */
export interface OptimizerProposal {
  readonly floor?: string | undefined;
  readonly budget?: string | undefined;
  readonly route?: string | undefined;
}

export interface ClampResult {
  readonly final: TrustedVerdicts;
  /** Every loosen-or-unknown proposal that was dropped (audit trail). */
  readonly droppedLoosenAttempts: readonly string[];
}

/**
 * Ratchet one verdict. Returns the proposed value only if it is a recognised value at an EQUAL or
 * HIGHER caution rank; otherwise the trusted value stands and the attempt is recorded. Total: any
 * input (including an unrecognised string) has a defined, fail-safe result.
 */
function ratchet<T extends string>(
  trusted: T,
  proposed: string | undefined,
  ranks: Record<T, number>,
  label: string,
  dropped: string[],
): T {
  if (proposed === undefined) return trusted;
  const pr = (ranks as Record<string, number>)[proposed];
  if (pr === undefined) {
    dropped.push(`${label}:unknown-proposal-dropped:${proposed}`); // fail-safe: unknown ⇒ ignore
    return trusted;
  }
  if (pr >= ranks[trusted]) return proposed as T; // tighten or equal ⇒ honour
  dropped.push(`${label}:loosen-dropped:${trusted}->${proposed}`); // loosen ⇒ drop + record
  return trusted;
}

/**
 * Clamp the untrusted proposal against the trusted verdicts. Pure + total. Guarantees, for every
 * axis, final_rank ≥ trusted_rank — the optimizer can only raise caution.
 */
export function clampOptimizer(trusted: TrustedVerdicts, proposal: OptimizerProposal): ClampResult {
  const dropped: string[] = [];
  return {
    final: {
      floor: ratchet(trusted.floor, proposal.floor, FLOOR_CAUTION, "floor", dropped),
      budget: ratchet(trusted.budget, proposal.budget, BUDGET_CAUTION, "budget", dropped),
      route: ratchet(trusted.route, proposal.route, ROUTE_CAUTION, "route", dropped),
    },
    droppedLoosenAttempts: dropped,
  };
}

/** The untrusted optimizer interface. Its `propose` may return anything; the clamp is the guard. */
export interface Optimizer {
  propose(trusted: TrustedVerdicts): OptimizerProposal;
}

/** The default: propose nothing (the clamp then returns the trusted verdicts unchanged). */
export const noopOptimizer: Optimizer = { propose: () => ({}) };
