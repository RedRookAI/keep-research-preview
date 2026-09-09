/**
 * THE ADAPT STEP (moat-heart #4) — localized deterministic repair BEFORE reaching for the LLM.
 *
 * The execution monitor already detects when a step's actual outcome diverges from its prediction and emits a
 * REPLAN signal; the repair loop already regenerates via the LLM on failing tests, bounded and rollback-guarded.
 * But both escalate STRAIGHT TO AN LLM REPLAN. Many runtime failures are local and mechanical — a transient error,
 * a parameter nudged out of bounds, a step with a known-equivalent substitute — and paying an LLM round-trip to fix
 * them is slow, costly (fatal on an n=1 free key), and non-deterministic. This module is the cheap tier that sits
 * in front of the replan: it tries a localized deterministic repair first, and only escalates when the failure is
 * genuinely non-local or the local budget is spent.
 *
 * Five hard properties (each disproof-backed):
 *   - LOCALIZED: repair the FAILING STEP, not the whole plan, when the failure is local.
 *   - DETERMINISTIC-FIRST: a rule-based repair is tried and, if it applies, NO LLM is called (`viaLLM: false`).
 *   - ESCALATING: a non-local failure, or one with no deterministic fix, escalates to the LLM replan.
 *   - ENVELOPE-SAFE: a repair that touches a consequential/irreversible step is never auto-applied — it routes
 *     through the gate for confirmation (the envelope is never crossed by a silent repair).
 *   - BOUNDED: a repair budget caps local retries so adapt can never loop.
 *
 * BUILT + proven in-env: the classify → deterministic-fix → gate/escalate decision. SEAM: the failure CLASSIFIER
 * (mapping a raw runtime error to a FailureKind) is supplied by the caller (the monitor/runner), and the live
 * wiring that runs adapt before the monitor's replan is the next increment. Composes ConsequenceClass; zero deps.
 */

import type { ConsequenceClass } from "../routing/uncertainty_router.js";

export type FailureKind = "transient" | "param-out-of-bounds" | "step-unavailable" | "non-local" | "unknown";

export interface StepFailure {
  readonly stepId: string;
  readonly kind: FailureKind;
  /** How many times this step has already been locally repaired this run (drives the bound + backoff). */
  readonly priorAttempts: number;
  /** The consequence of the failing step's action — a consequential repair is never auto-applied. */
  readonly consequence: ConsequenceClass;
  /** For param-out-of-bounds: the offending parameter and its valid range (deterministic clamp). */
  readonly param?: { readonly name: string; readonly value: number; readonly min: number; readonly max: number };
  /** For step-unavailable: a known-equivalent substitute step id, if one exists. */
  readonly knownEquivalent?: string;
}

export type RepairAction =
  | { readonly kind: "retry"; readonly backoffMs: number }
  | { readonly kind: "substitute"; readonly withStepId: string }
  | { readonly kind: "clamp-param"; readonly name: string; readonly to: number }
  | { readonly kind: "gate"; readonly reason: string }
  | { readonly kind: "escalate-replan"; readonly reason: string }
  | { readonly kind: "give-up"; readonly reason: string };

export interface AdaptResult {
  readonly repair: RepairAction;
  readonly scope: "local" | "replan";
  /** false for deterministic local repairs (and the gate); true ONLY when escalating to the LLM replan. */
  readonly viaLLM: boolean;
  readonly rationale: string;
}

export interface AdaptConfig {
  /** The repair budget: max local deterministic attempts before escalating. Bounds the loop. */
  readonly maxLocalAttempts: number;
  readonly baseBackoffMs: number;
}

export const DEFAULT_ADAPT_CONFIG: AdaptConfig = { maxLocalAttempts: 3, baseBackoffMs: 500 };

function clamp(x: number, min: number, max: number): number {
  return x < min ? min : x > max ? max : x;
}

/** The deterministic local fix for a failure kind, or null if none applies (→ escalate). No LLM, no side effects. */
function deterministicFix(f: StepFailure, cfg: AdaptConfig): RepairAction | null {
  switch (f.kind) {
    case "transient":
      return { kind: "retry", backoffMs: cfg.baseBackoffMs * Math.pow(2, f.priorAttempts) };
    case "param-out-of-bounds":
      return f.param ? { kind: "clamp-param", name: f.param.name, to: clamp(f.param.value, f.param.min, f.param.max) } : null;
    case "step-unavailable":
      return f.knownEquivalent !== undefined ? { kind: "substitute", withStepId: f.knownEquivalent } : null;
    default:
      return null; // non-local / unknown → no deterministic fix
  }
}

/**
 * Decide how to adapt to a failed step. Cheapest-first: a localized deterministic repair before any LLM replan.
 */
export function adaptPlan(failure: StepFailure, cfg: AdaptConfig = DEFAULT_ADAPT_CONFIG): AdaptResult {
  // BOUNDED: the local repair budget is spent → escalate to the LLM replan (don't loop).
  if (failure.priorAttempts >= cfg.maxLocalAttempts) {
    return {
      repair: { kind: "escalate-replan", reason: "local repair budget exhausted" },
      scope: "replan",
      viaLLM: true,
      rationale: `${failure.stepId}: ${failure.priorAttempts} local attempts spent (budget ${cfg.maxLocalAttempts}) — escalate to replan`,
    };
  }

  const fix = deterministicFix(failure, cfg);

  // ENVELOPE-SAFE: a deterministic fix that touches a consequential/irreversible step is NEVER auto-applied.
  if (fix !== null && failure.consequence !== "reversible") {
    return {
      repair: { kind: "gate", reason: "repair touches a consequential step — confirm before applying" },
      scope: "local",
      viaLLM: false,
      rationale: `${failure.stepId}: a local fix exists but the step is ${failure.consequence} — route to the gate, not auto-applied`,
    };
  }

  // DETERMINISTIC-FIRST + LOCALIZED: a local, reversible, deterministically-fixable failure → cheap repair, no LLM.
  if (fix !== null) {
    return {
      repair: fix,
      scope: "local",
      viaLLM: false,
      rationale: `${failure.stepId}: ${failure.kind} is locally repairable (${fix.kind}) — no LLM needed`,
    };
  }

  // ESCALATING: non-local or not deterministically fixable → the LLM replan (the existing monitor/repair loop).
  return {
    repair: { kind: "escalate-replan", reason: `${failure.kind} is not locally repairable` },
    scope: "replan",
    viaLLM: true,
    rationale: `${failure.stepId}: ${failure.kind} needs a re-plan grounded in the observed failure`,
  };
}
