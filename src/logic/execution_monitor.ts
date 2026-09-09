/**
 * Plan-level EXECUTION-MONITOR (the "after" half of vet-before-and-after).
 *
 * The plan-gate vets a plan BEFORE execution (order/goal/proportionality/non-regression + the model-checked
 * state simulation). But a vetted plan can still go wrong at RUNTIME: a step's ACTUAL outcome can diverge from
 * its SIMULATED prediction (the world is not the model). The premium pattern (EvoPlan / Metagent-P
 * "verification-execution-reflection") pairs the pre-execution check with ONLINE MONITORING + REPLAN on
 * divergence. This module is that monitor.
 *
 * As each step executes, the monitor compares its ACTUAL established facts to its PREDICTED `establishes`
 * (via the R41 `divergence` primitive), and on the FIRST divergence it HALTS the remaining plan and emits a
 * replan signal carrying the OBSERVED state — so the solver can regenerate grounded in what actually happened
 * (the LLM-Modulo regenerate loop, now state-grounded), rather than continuing a plan whose assumptions have
 * already broken. Fail-safe: a missing observed outcome ⇒ replan (we cannot confirm the step did what the
 * model predicted, so we do not blindly proceed).
 *
 * BUILT vs SEAM: BUILT + proven in-env is the monitor/replan DECISION logic (walk, per-step divergence, halt-
 * at-first, observed-state capture, fail-safe). SEAM: the execution WIRING that feeds each step's actual
 * outcome (and the spine recording of divergences). It composes BELOW the plan-gate and BENEATH R11 — it is a
 * plan-level reflect/replan trigger, NOT a kill-switch; it must not duplicate or weaken R11.
 */

import { divergence } from "./effect_model.js";
import type { Plan } from "./plan_gate.js";

/** The observed actual outcome of a step: the facts it actually established. `undefined` = not observed. */
export interface ObservedOutcome {
  readonly stepId: string;
  readonly actualEstablished: readonly string[] | undefined;
}

export type MonitorResult =
  | { readonly status: "complete"; readonly observedState: readonly string[] }
  | {
      readonly status: "replan";
      readonly atStep: string;
      readonly observedState: readonly string[];
      readonly reason: string;
    };

/**
 * Walk the plan step-by-step against the observed outcomes. For each step, compare its predicted `establishes`
 * to the observed `actualEstablished` (`divergence`); apply the OBSERVED effects to the running state so the
 * replan signal carries the true state; HALT at the first divergence. Fail-safe: a step with no observed
 * outcome ⇒ replan.
 */
export function monitorExecution(
  plan: Plan,
  observed: readonly ObservedOutcome[],
): MonitorResult {
  const byId = new Map<string, ObservedOutcome>();
  for (const o of observed) byId.set(o.stepId, o);

  const state = new Set(plan.initialState);
  for (const step of plan.steps) {
    const obs = byId.get(step.id);
    const actual = obs?.actualEstablished; // undefined if the step wasn't observed
    const d = divergence(step.establishes, actual);
    if (d.replan) {
      // apply whatever WAS observed (if anything) before halting, so observedState is truthful.
      if (actual !== undefined) {
        for (const del of step.deletes) state.delete(del);
        for (const f of actual) state.add(f);
      }
      return { status: "replan", atStep: step.id, observedState: [...state], reason: d.reason };
    }
    // outcome matched prediction — advance the observed state by the ACTUAL facts.
    for (const del of step.deletes) state.delete(del);
    for (const f of actual as readonly string[]) state.add(f);
  }
  return { status: "complete", observedState: [...state] };
}
