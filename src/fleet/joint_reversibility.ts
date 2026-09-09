/**
 * Finding 2.3 — the fleet JOINT-REVERSIBILITY barrier (the second fleet-composition barrier).
 *
 * The REE makes each effect individually reversible: confine → checkpoint → execute-on-a-fork →
 * accept → commit | rollback, with a registered compensating inverse. But reversibility does not
 * COMPOSE: N effects each with a valid inverse can interleave into a JOINTLY-irreversible outcome —
 * agent A opens an envelope whose rollback relies on resource X being unchanged; agent B commits an
 * effect that writes/reverts X; now A's inverse no longer restores the original state. Each effect is
 * individually reversible; the composition is not (R39, scenario 2). The per-decision gate cannot see
 * this — it evaluates one effect with no view of other agents' in-flight envelopes.
 *
 * This barrier detects the REVERSIBILITY CONFLICT and denies it, structurally, at the resource — the
 * railway-interlock model: "you cannot release/alter a route while a dependent route is set." It
 * composes ABOVE the per-decision gate and ALONGSIDE the 2.2 shared-resource barrier; it does not
 * modify the gate, the REE, or the 2.2 barrier.
 *
 * DISCIPLINE (research, 2026-08-09):
 *  - Conflict serializability / OCC: a schedule is safe iff its dependency graph is acyclic; OCC
 *    validates at commit — "abort unless WriteSet(T1) ∩ ReadSet(T2) = ∅." Here the "read set" an
 *    in-flight effect depends on is its INVERSE-DEPENDENCY set (the state its rollback relies on).
 *  - Saga compensation ordering: compensating transactions must respect dependency order; out-of-order
 *    compensation corrupts state — so an effect that would strand an in-flight compensation is denied.
 *  - Railway route-locking interlock: a set route locks the points it depends on; a conflicting request
 *    is denied until the first route clears. First-committer-wins.
 *  - Fail-safe: unknown dependency (an undeclared write-set or inverse-dependency) ⇒ deny — we cannot
 *    prove independence, so we assume conflict.
 *  - Transient: the conflict clears once the in-flight effect commits or releases (leaves in-flight).
 *
 * BUILT vs SEAM: BUILT + proven in-env is the conflict-detection logic (write-set ∩ inverse-dependency
 * intersection, fail-safe on unknown, transient clearing, reversible registration) + the compose helper.
 * The real CROSS-HOST DEPENDENCY GRAPH — tracking every agent's in-flight envelopes across hosts with
 * distributed coordination — is the SEAM. Scenario 2 ONLY; R39 scenarios 3–5 remain open.
 */

/** An effect, in-flight or incoming. `undefined` sets mean UNKNOWN ⇒ fail-safe (deny). */
export interface Effect {
  readonly id: string;
  readonly agent: string;
  /** The resources this effect writes. `undefined` = unknown ⇒ fail-safe. `[]` = known to write nothing. */
  readonly writeSet: readonly string[] | undefined;
  /**
   * The resources this effect's INVERSE relies on being unchanged to roll back cleanly (at least its
   * own write-set; may include reads its compensation assumes). `undefined` = unknown ⇒ fail-safe.
   */
  readonly inverseDependsOn: readonly string[] | undefined;
}

export type JointCheck =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: string };

function intersects(a: readonly string[], b: readonly string[]): string | undefined {
  const setB = new Set(b);
  for (const x of a) if (setB.has(x)) return x;
  return undefined;
}

/** The one both-direction conflict predicate used by local and durable fleet admission. */
export function jointReversibilityReasons(incoming: Effect, inFlight: readonly Effect[]): readonly string[] {
  if (incoming.writeSet === undefined) return Object.freeze(["unknown-writeset"]);
  if (incoming.inverseDependsOn === undefined) return Object.freeze(["unknown-inverse-dependency"]);
  const incomplete = incoming.writeSet.find((resource) => !incoming.inverseDependsOn!.includes(resource));
  if (incomplete !== undefined) return Object.freeze([`incomplete-inverse-dependency:${incomplete}`]);
  const reasons: string[] = [];
  for (const existing of inFlight) {
    if (existing.id === incoming.id) continue;
    if (existing.writeSet === undefined || existing.inverseDependsOn === undefined) { reasons.push(`unknown-dependency:${existing.id}`); continue; }
    const forward = intersects(incoming.writeSet, existing.inverseDependsOn);
    if (forward !== undefined) reasons.push(`reversibility-conflict:${forward}@${existing.id}`);
    const reverse = intersects(existing.writeSet, incoming.inverseDependsOn);
    if (reverse !== undefined) reasons.push(`inverse-reversibility-conflict:${reverse}@${existing.id}`);
  }
  return Object.freeze(reasons);
}

export function checkJointReversibility(incoming: Effect, inFlight: readonly Effect[]): JointCheck {
  const reasons = jointReversibilityReasons(incoming, inFlight);
  return reasons.length === 0 ? { ok: true } : { ok: false, reason: reasons[0]! };
}

/**
 * The joint-reversibility ledger. Tracks in-flight (open-envelope) effects and checks an incoming
 * effect against them. Total + fail-safe. Registration is removed on commit/release (transient).
 */
export class JointReversibilityLedger {
  private readonly inFlight = new Map<string, Effect>();

  /** An effect's envelope is open (executing, not yet committed) — its inverse must stay valid. */
  register(effect: Effect): void {
    this.inFlight.set(effect.id, effect);
  }

  /** The effect committed → it leaves in-flight (its inverse is no longer pending). */
  commit(id: string): boolean {
    return this.inFlight.delete(id);
  }

  /** The effect rolled back → it leaves in-flight. */
  release(id: string): boolean {
    return this.inFlight.delete(id);
  }

  inFlightCount(): number {
    return this.inFlight.size;
  }

  /**
   * Check an incoming effect: deny if its commit would invalidate any in-flight effect's inverse (its
   * write-set intersects that effect's inverse-dependency set), or if anything relevant is unknown.
   */
  check(incoming: Effect): JointCheck {
    return checkJointReversibility(incoming, [...this.inFlight.values()]);
  }
}

/**
 * Compose ABOVE the per-decision gate (and alongside 2.2): proceed only if the gate auto-proceeds AND
 * the joint-reversibility check is ok. The barrier only ADDS caution; it never overrides a gate hold.
 */
export function fleetReversibilityAdmit(
  gateAutoProceed: boolean,
  check: JointCheck,
): { readonly proceed: boolean; readonly reason: string } {
  if (!gateAutoProceed) return { proceed: false, reason: "per-decision-gate-hold" };
  if (!check.ok) return { proceed: false, reason: `fleet-${check.reason}` };
  return { proceed: true, reason: "gate-and-joint-reversibility-cleared" };
}
