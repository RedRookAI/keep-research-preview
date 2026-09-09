/**
 * REDEMPTION LEDGER (Mechanical-Enforcement Increment 7, part B).
 *
 * A verified permit conveys authority only up to its redemption budget — and a holder must not be able to MULTIPLY that
 * budget by branching the caveat chain. Redemption is therefore bounded on EVERY CHAIN PREFIX simultaneously, checked
 * and consumed atomically together: verify() returns a `budgets` list {id, cap} — one entry per prefix [c1..ci] of the
 * presented permit — where the id is the SUBTREE identity shared by every descendant carrying that prefix (prefix 0's
 * id is the root claims digest) and the cap is the effective redemption ceiling at that node. Redeeming a leaf consumes
 * one from every prefix counter, so:
 *   - the ROOT counter bounds total redemptions across the whole subtree to the root's maxRedemptions; and
 *   - every INTERMEDIATE node bounds its OWN subtree to its cap — so a holder of a delegated cap-N permit cannot exceed
 *     N total by forking it into siblings (cross-family review, GPT-5.6 r4 SEV0).
 *
 * Atomicity: JavaScript runs a redemption to completion within a single turn of the event loop, so the synchronous
 * verify → check-all → consume-all sequence has no interleaving window. (A multi-process broker replaces the in-memory
 * map with a durable, compare-and-swap-backed store behind the SAME interface — the documented persistence seam.)
 *
 * TRUST BOUNDARY: the ledger is a TRUSTED broker-internal component with a single instance per trust domain (a second
 * instance sharing the same root key would each grant the full budget — the deployment MUST use one shared/CAS store).
 * A permit HOLDER never supplies it. The counting uses captured Map primitives + bigint comparisons only (no array
 * methods, no prototype-dispatched calls on caller data), so — WITHIN the stated inert-data threat model — the subtree
 * ceiling holds. (A same-isolate adversary with code execution can corrupt any in-process structure; that adversary is
 * out of scope, matching the Increment-6 precedent, and is not claimed to be defended here.)
 *
 * Grounding: replay-resistant token redemption; at-most-once delivery; capability subtree/budget accounting.
 */
import { verify, type Permit, type PermitKey, type RedeemContext, type PermitVerdict, type PermitBudget } from "./permit.js";

const HEX64 = /^[0-9a-f]{64}$/;
// Captured Map primitives — accounting does not dispatch through the (mutable) Map prototype of caller-influenced data.
const MAP_GET = Map.prototype.get as (this: Map<string, bigint>, k: string) => bigint | undefined;
const MAP_SET = Map.prototype.set as (this: Map<string, bigint>, k: string, v: bigint) => Map<string, bigint>;

/** A prefix-budget redemption ledger keyed on subtree identities. In-memory reference impl (see the persistence seam). */
export class RedemptionLedger {
  readonly #counts = new Map<string, bigint>();
  #get(id: string): bigint { return MAP_GET.call(this.#counts, id) ?? 0n; }

  /**
   * Atomically consume one redemption iff EVERY prefix budget has room (used < cap). Returns true iff consumed (all
   * counters incremented). Total: any malformed budget consumes nothing and returns false.
   */
  tryConsume(budgets: readonly PermitBudget[]): boolean {
    if (!Array.isArray(budgets) || budgets.length === 0) return false;
    const ids = new Set<string>();
    for (let i = 0; i < budgets.length; i++) {                   // validate every entry FIRST (no partial consume)
      const b = budgets[i];
      if (b === null || typeof b !== "object" || typeof b.id !== "string" || !HEX64.test(b.id) || typeof b.cap !== "bigint" || b.cap < 1n) return false;
      if (ids.has(b.id)) return false;                           // a DUPLICATE id would double-count one counter (GPT-5.6 r5)
      ids.add(b.id);
      if (this.#get(b.id) >= b.cap) return false;                // any ceiling reached ⇒ deny (nothing consumed yet)
    }
    for (let i = 0; i < budgets.length; i++) { const b = budgets[i]!; MAP_SET.call(this.#counts, b.id, this.#get(b.id) + 1n); }
    return true;
  }

  /** Redemptions consumed for a subtree/prefix id (0 if never seen). `consumedRoot` reads the root subtree by rootId. */
  consumed(id: string): bigint { return this.#get(id); }
  consumedRoot(rootId: string): bigint { return this.#get(rootId); }
}

/**
 * REDEEM a permit: verify it, then atomically consume one redemption on EVERY prefix budget. Returns the verification
 * verdict on success, or a `valid:false` verdict whose reason is the verification failure or `already-redeemed`. Total
 * + fail-safe — never throws.
 */
export function redeem(permit: Permit, trust: PermitKey, ctx: RedeemContext, ledger: RedemptionLedger): PermitVerdict {
  try {
    const v = verify(permit, trust, ctx);
    if (!v.valid) return v;
    if (!(ledger instanceof RedemptionLedger)) return { valid: false, reason: "malformed ledger" };
    if (!ledger.tryConsume(v.budgets)) return { valid: false, reason: "already-redeemed (single-use / max redemptions reached)" };
    return v;
  } catch {
    return { valid: false, reason: "redeem error" };
  }
}
