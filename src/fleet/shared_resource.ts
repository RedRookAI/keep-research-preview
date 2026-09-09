/**
 * Finding 2.2 — the fleet SHARED-RESOURCE barrier (the first fleet-composition barrier).
 *
 * Keep's nine-barrier gate is per-DECISION: it certifies one effect by one agent, with no view of the
 * fleet (confirmed in 2.1 — every `GateInputs` field is per-decision). So N agents each WITHIN their own
 * budget (each `checkBudget` → within-budget) can JOINTLY exhaust a shared budget / quota / rate — the
 * tragedy-of-the-commons the pointwise gate is structurally blind to (R39, scenario 1).
 *
 * This barrier enforces the AGGREGATE invariant `committed + outstanding-reservations ≤ cap` at the
 * RESOURCE, structurally — the ATC-separation / circuit-breaker model from 2.1 — NOT as a synchronous
 * central gate. It composes ABOVE the per-decision gate: an effect must clear BOTH its own gate AND a
 * fleet reservation. It does NOT modify the gate or any of the nine barriers.
 *
 * DISCIPLINE (research, 2026-08-09):
 *  - Reserve-then-commit (two-phase reservation): Phase 1 reserve LOCKS the amount against the ledger;
 *    Phase 2 commits, or the hold is released (abort). The seat-hold pattern.
 *  - Atomic check (the check-then-act race): "two threads each reading 1 token both set 0, allowing 2
 *    through — breaking the limit." So reserve is a single atomic check-and-hold: two agents each within
 *    their OWN budget cannot both reserve past the shared cap.
 *  - Fail-CLOSED: a performance rate-limiter fails open; a SAFETY barrier fails closed — unknown/absent
 *    shared state ⇒ deny.
 *  - No central bottleneck: the reservation IS the check (resource-side); a real deployment uses a
 *    distributed/consensus ledger or token leases (each agent holds 1/N of the cap, burned locally). That
 *    distributed ledger across hosts is the SEAM; the reservation logic is the in-env-provable core.
 *
 * BUILT vs SEAM: BUILT + proven in-env is the reservation ledger (atomic reserve/commit/release,
 * aggregate-cap enforcement, fail-closed, reversible-on-abort) + the compose-above-the-gate helper. The
 * real DISTRIBUTED / LEASED ledger across hosts (consensus, sharded leases) is the SEAM. This is the
 * FIRST fleet barrier — scenario 1 only; scenarios 2–5 of R39 remain open.
 */

export interface SharedResourcePolicy {
  /** The aggregate cap across the whole fleet for this resource. */
  readonly cap: number;
}

export type ReserveResult =
  | { readonly granted: true; readonly reservationId: string }
  | { readonly granted: false; readonly reason: string };

/** The one aggregate-cap predicate used by both the local ledger and durable fleet lifecycle. */
export function checkSharedCapacity(cap: number | undefined, committed: number, outstanding: number, amount: number): ReserveResult {
  if (cap === undefined || !Number.isSafeInteger(cap) || cap < 0) return { granted: false, reason: "unknown-shared-cap" };
  if (!Number.isSafeInteger(committed) || committed < 0 || !Number.isSafeInteger(outstanding) || outstanding < 0 || !Number.isSafeInteger(amount) || amount < 1) return { granted: false, reason: "invalid-amount" };
  if (committed + outstanding + amount > cap) return { granted: false, reason: `shared-cap-exceeded:${committed + outstanding + amount}>${cap}` };
  return { granted: true, reservationId: "preview" };
}

interface Hold {
  readonly agent: string;
  readonly amount: number;
}

/**
 * The shared-resource ledger. Total + fail-closed. `reserve` atomically checks the aggregate invariant
 * (committed + outstanding + amount ≤ cap) and holds; `commit` finalizes a hold; `release` drops an
 * uncommitted hold (reversible). A missing/invalid cap ⇒ every reserve denies (fail-closed).
 */
export class SharedResourceLedger {
  private committed = 0;
  private readonly holds = new Map<string, Hold>();
  private seq = 0;
  private readonly cap: number;
  private readonly capValid: boolean;

  constructor(policy: SharedResourcePolicy | undefined) {
    // fail-closed: an absent or non-finite/negative cap makes every reservation deny.
    this.capValid = policy !== undefined && Number.isFinite(policy.cap) && policy.cap >= 0;
    this.cap = this.capValid ? policy!.cap : 0;
  }

  private outstanding(): number {
    let sum = 0;
    for (const h of this.holds.values()) sum += h.amount;
    return sum;
  }

  /** Atomic reserve: hold `amount` for `agent` iff the aggregate stays within the cap; else deny. */
  reserve(agent: string, amount: number): ReserveResult {
    const check = checkSharedCapacity(this.capValid ? this.cap : undefined, this.committed, this.outstanding(), amount);
    if (!check.granted) return check;
    if (typeof agent !== "string" || agent.length < 1 || agent.length > 128) return { granted: false, reason: "invalid-agent" };
    const reservationId = `res-${++this.seq}`;
    this.holds.set(reservationId, { agent, amount });
    return { granted: true, reservationId };
  }

  /** Commit a hold → it becomes permanently committed (the resource is spent; no double-spend). */
  commit(reservationId: string): boolean {
    const h = this.holds.get(reservationId);
    if (h === undefined) return false;
    this.committed += h.amount;
    this.holds.delete(reservationId);
    return true;
  }

  /** Release an UNCOMMITTED hold → frees the cap (reversible; the abort path). */
  release(reservationId: string): boolean {
    return this.holds.delete(reservationId);
  }

  committedTotal(): number {
    return this.committed;
  }
  outstandingTotal(): number {
    return this.outstanding();
  }
}

/**
 * Compose ABOVE the per-decision gate: an effect proceeds only if its own gate auto-proceeds AND the
 * fleet reservation is granted. The fleet barrier can only ADD caution — it never overrides a gate hold.
 * This does not modify the gate; it is a second, structural check the effect must also clear.
 */
export function fleetComposedAdmit(
  gateAutoProceed: boolean,
  reserve: ReserveResult,
): { readonly proceed: boolean; readonly reason: string } {
  if (!gateAutoProceed) return { proceed: false, reason: "per-decision-gate-hold" };
  if (!reserve.granted) return { proceed: false, reason: `fleet-${reserve.reason}` };
  return { proceed: true, reason: "gate-and-fleet-cleared" };
}
