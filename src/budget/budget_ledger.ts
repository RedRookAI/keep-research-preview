/**
 * Budget ledger (Build Step 2, layer 5) — crude, diverse, structural resource invariants
 * bounding a single reversible attempt.
 *
 * A pure, total, MODEL-INDEPENDENT accounting of several CHEAP, INDEPENDENT structural
 * quantities against pre-committed ceilings. Any one ceiling met-or-exceeded trips the
 * whole thing (diverse-OR); a MISSING count fails safe to the tripped state. There is no
 * predictor, no learned estimate — just counts vs numbers.
 *
 * WHY DIVERSE-AND-CRUDE (research, 2026-08-08):
 *  - Defence-in-depth / diversity (NRC nuclear; road-vehicle assurance): "diverse
 *    redundancy counters common-cause failures." The 2003 North American blackout is the
 *    cautionary case — the non-diverse backups "failed in the same way as the primary
 *    systems." One clever predictor covering every quantity is a common-cause failure
 *    waiting to happen; five independent crude bounds are not. So the quantities are
 *    measured separately, never derived from one another.
 *  - Fail-safe metering (circuit breaker): trips when a single quantity exceeds a
 *    predetermined value; a backup fusible link makes it fail OPEN, never welded shut.
 *    Here: a missing count is treated as OVER its ceiling (fail open), never as under.
 *  - The counter-caution (immune-inspired "autoimmune denial"): over-restrictive limits
 *    cause outage. So ceilings carry generous headroom — a budget is a fuse for runaway
 *    consumption, not a throttle on normal work. Calibration (not the trip rule) is what
 *    telemetry would tune.
 *
 * ROUTING: `exceeded` forces the cautious branch upstream (gate / forced checkpoint). The
 * budget CONSUMES but does not replace the floor verdict — an attempt proceeds only if the
 * floor says reversible-execute AND the budget is within-budget. It can only ADD caution.
 *
 * WHAT WOULD CHANGE IT: telemetry showing a quantity never trips on real overruns (a dead
 * bound → drop/replace it) or trips constantly on legitimate work (miscalibrated → widen
 * the ceiling). Never make the trip itself model-driven; only the ceilings are tunable.
 */

/** Cheap, independent structural counts of one reversible attempt. Missing ⇒ fail-safe trip. */
export interface ConsumptionRecord {
  readonly edits?: number;         // number of edits applied
  readonly bytesWritten?: number;  // total bytes across all writes
  readonly filesTouched?: number;  // distinct files written
  readonly fanOut?: number;        // sub-agents / spawned tasks
  readonly steps?: number;         // iteration / step count (or wall-clock ticks)
}

/** Pre-committed independent ceilings (config data, never model output). Max ALLOWED value each. */
export interface BudgetPolicy {
  readonly maxEdits: number;
  readonly maxBytesWritten: number;
  readonly maxFilesTouched: number;
  readonly maxFanOut: number;
  readonly maxSteps: number;
}

export type BudgetVerdict =
  | { readonly verdict: "within-budget" }
  | { readonly verdict: "exceeded"; readonly ceilings: readonly string[] };

/** One quantity's trip check. Missing ⇒ tripped (fail open). Over ceiling ⇒ tripped. */
function trip(count: number | undefined, ceiling: number, name: string): string | null {
  if (count === undefined) return `${name}:missing`; // fail-safe: unknown consumption is maxed out
  if (count > ceiling) return `${name}:${count}>${ceiling}`;
  return null;
}

/**
 * The ledger. Total and pure: a consumption record + ceilings → within-budget | exceeded.
 * Any single tripped quantity ⇒ exceeded (diverse-OR). Every quantity is checked (so the
 * report lists ALL exceedances, not just the first).
 */
export function checkBudget(rec: ConsumptionRecord, policy: BudgetPolicy): BudgetVerdict {
  const trips = [
    trip(rec.edits, policy.maxEdits, "edits"),
    trip(rec.bytesWritten, policy.maxBytesWritten, "bytesWritten"),
    trip(rec.filesTouched, policy.maxFilesTouched, "filesTouched"),
    trip(rec.fanOut, policy.maxFanOut, "fanOut"),
    trip(rec.steps, policy.maxSteps, "steps"),
  ].filter((t): t is string => t !== null);

  if (trips.length === 0) return { verdict: "within-budget" };
  return { verdict: "exceeded", ceilings: trips };
}

/**
 * A conservative default policy (data only) with generous headroom — a fuse for runaway
 * consumption, not a throttle on normal edits. Deployments narrow it per environment.
 */
/**
 * ROUND 40 — budget ceilings configured into SILENCE.
 *
 * A ceiling is the CEILING shape of the fail-open family (see `inertFloorInputs`): raise it
 * beyond reach and it stops tripping without ever saying so. Measured: with every ceiling at
 * `Infinity`, a consumption of a million edits and a terabyte written reports `within-budget`.
 *
 * Reported here rather than refused, because an unbounded ceiling is a legal configuration —
 * it is just one an operator almost never means, and currently cannot see.
 *
 * A ceiling of `0` is NOT reported: it trips on everything, which is the loud direction, and an
 * operator who sets it discovers it on the first run.
 */
export function inertBudgetInputs(policy: BudgetPolicy): string[] {
  const unbounded = (Object.entries(policy) as [string, number][])
    .filter(([, v]) => !Number.isFinite(v))
    .map(([k]) => k);
  return unbounded.length === 0
    ? []
    : [`budget ceiling(s) ${unbounded.join(", ")} are not finite — they can never trip, so the consumption fuse is disabled`];
}

export function defaultBudgetPolicy(): BudgetPolicy {
  return {
    maxEdits: 200,
    maxBytesWritten: 5_000_000, // 5 MB written in one attempt
    maxFilesTouched: 100,
    maxFanOut: 16,
    maxSteps: 1_000,
  };
}
