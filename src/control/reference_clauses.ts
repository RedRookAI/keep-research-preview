/**
 * Default Keep safety clauses (Increment C1) — the real contract clauses registered into the single
 * ReferenceMonitor. Each encodes, as a trace-level temporal invariant, a safety property that previously
 * lived scattered inside an individual module. Registering them here makes the monitor the ONE un-bypassable
 * enforcement point (and begins the islands fix: these modules' invariants now converge on one checker).
 *
 * These are built to Keep's REAL staged-event shapes:
 *  - self-improvement:   type "identity.action", payload { event: "self_improvement", decision, component, ... }
 *  - triad pass:         (18.x will stage) payload { event: "triad_pass", component }
 *  - human approval:     type "sod.approval", payload { target, tier }
 *  - gated merge:        payload { event: "merge", tier, target }
 *  - frozen-floor write: payload { event: "component_write", component } targeting a FROZEN_FLOOR name
 */

import { neverEvent, precededBy, forbidWithout, type TraceClause, type TraceEvent } from "./reference_monitor.js";
import { FROZEN_FLOOR } from "../meta/meta_harness.js";

const ev = (e: TraceEvent): string => String((e.payload as { event?: string }).event ?? "");
const str = (e: TraceEvent, k: string): string => String((e.payload as Record<string, unknown>)[k] ?? "");
const bool = (e: TraceEvent, k: string): boolean => (e.payload as Record<string, unknown>)[k] === true;

/**
 * CLAUSE 1 — the frozen safety floor is NEVER mutated. Any component_write targeting a FROZEN_FLOOR member
 * (eval-anchor, patch-verifier, consequence-floor, isolation-tier, sovereignty-manifest, spine) is a
 * violation. (H ¬mutate-floor)
 */
export function frozenFloorNeverMutated(): TraceClause<{ hit: string | null }> {
  const frozen = new Set<string>(FROZEN_FLOOR);
  return neverEvent(
    "frozen-floor-immutable",
    "the deterministic safety floor is never modified by self-improvement",
    (e) => ev(e) === "component_write" && frozen.has(str(e, "component")),
  );
}

/**
 * CLAUSE 2 — an ACCEPTED self-improvement must have been PRECEDED by a triad pass for the same component.
 * This is the trace-level backstop for the MetaHarness's internal triad gate: even if some path tried to
 * stage an "accepted" self_improvement without the triad, the monitor catches it because no matching
 * triad_pass precedes it in the trace. A per-action check on the accept event alone could NOT see this.
 * (accept → O(triad_pass for same component))
 */
export function selfImprovementRequiresTriad(): TraceClause<{ seen: string[]; badKey: string | null }> {
  return precededBy(
    "self-improvement-requires-triad",
    "an accepted self-improvement must be preceded by a triad pass for that component",
    (e) => ev(e) === "triad_pass",
    (e) => ev(e) === "self_improvement" && str(e, "decision") === "accepted",
    (e) => str(e, "component"),
  );
}

/**
 * CLAUSE 3 — a merge on a GATED tier must have been PRECEDED by a human approval (sod.approval) for the same
 * target. Encodes the MergeGateInvariant as a trace property: the human merge gate can never be bypassed,
 * enforced over the history, not just at the merge call site. (gated-merge → O(approval for same target))
 */
export function gatedMergeRequiresApproval(): TraceClause<{ seen: string[]; badKey: string | null }> {
  return precededBy(
    "gated-merge-requires-approval",
    "a merge on a human-gated tier must be preceded by a recorded human approval for that target",
    (e) => e.type === "sod.approval",
    (e) => ev(e) === "merge" && truthy(str(e, "gated")),
    (e) => str(e, "target"),
  );
}

/**
 * CLAUSE 4 — an external effect (publishing a solve) is FORBIDDEN unless patch execution ran under isolation
 * first. isolated_execution (executed:true) and solve_to_pr share no correlatable key, so this is a one-shot
 * guard-then-permit property (forbidWithout), not a keyed precedence: if the isolation path is bypassed or
 * disabled entirely, the FIRST publish with no prior isolated execution violates. This is the trace-level
 * backstop for the isolation boundary — the analogue of gated-merge-requires-approval for the merge gate.
 * (publish → forbidden unless O(isolated_execution executed:true))
 */
export function externalEffectRequiresIsolation(): TraceClause<{ guarded: boolean; violated: boolean }> {
  return forbidWithout(
    "external-effect-requires-isolation",
    "publishing a solve requires that patch execution ran under isolation (the isolation path was not bypassed)",
    (e) => ev(e) === "isolated_execution" && bool(e, "executed"),
    (e) => ev(e) === "solve_to_pr",
  );
}

function truthy(s: string): boolean {
  return s === "true" || s === "1" || s === "yes";
}

/** All default Keep clauses, ready to register into the ReferenceMonitor. */
export function defaultKeepClauses(): TraceClause<unknown>[] {
  return [
    frozenFloorNeverMutated() as TraceClause<unknown>,
    selfImprovementRequiresTriad() as TraceClause<unknown>,
    gatedMergeRequiresApproval() as TraceClause<unknown>,
    externalEffectRequiresIsolation() as TraceClause<unknown>,
  ];
}
