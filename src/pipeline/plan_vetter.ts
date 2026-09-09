/**
 * Plan-vet adapter (Increment 16.8) — the PRE-SOLVE gate, now backed by REAL consequence analysis.
 *
 * Replaces the vacuous skeleton gate (16.7) — which fed a hardcoded 4-step plan to LogicVet and always
 * passed regardless of issue content — with the consequence-analysis floor (plan_consequences.ts):
 * blast-radius classification, reversibility, effect-boundary crossings, and second-order combinations
 * over the ACTUAL intended effects of the issue. Both plan- and patch-vetting run (not exclusive).
 *
 * Decision mapping: consequence `block` → block (sound, stops before solve); `escalate` → rework
 * (route to human review); `pass` → pass. Fail-closed: a thrown error → block. Model-free at the floor;
 * the optional independent second-brain tier is added in 16.8b.
 */

import { analyzeConsequences, type ConsequenceVerdict } from "./plan_consequences.js";
import { checkCurrency, type CurrencyVerdict, type CurrencyResearch } from "./plan_currency.js";
import { buildTemporalContext, type TemporalContext } from "../currency/temporal_context.js";
import { LandscapeCatalog } from "../currency/landscape_catalog.js";
import type { Issue } from "../solve/issue_model.js";
import type { SuspectFile } from "../solve/localize.js";

export interface PlanVetDecision {
  readonly cleared: boolean;
  readonly decision: "pass" | "rework" | "block";
  readonly reason: string;
  /** The full consequence verdict (effects + checks) for the audit trail. */
  readonly consequences?: ConsequenceVerdict;
  /** The currency verdict — is the plan based on current (non-stale) methods? Always present. */
  readonly currency?: CurrencyVerdict;
}

/** Optional deps for the plan vetter. All default to SOVEREIGN offline values (no external required). */
export interface PlanVetterDeps {
  readonly temporal?: TemporalContext;
  readonly catalog?: LandscapeCatalog;
  /** Opt-in privacy-preserving research (minimal terms only). Omit → offline currency check. */
  readonly currencyResearch?: CurrencyResearch;
}

/**
 * Build the pipeline's pre-solve plan-vetting function. Runs the consequence-analysis floor over the
 * issue's intended effects (optionally informed by localized suspect files). Fail-closed on error.
 */
export function defaultPlanVetter(deps: PlanVetterDeps = {}): (issue: Issue, suspects?: readonly SuspectFile[]) => Promise<PlanVetDecision> {
  const temporal = deps.temporal ?? buildTemporalContext();
  const catalog = deps.catalog ?? new LandscapeCatalog();
  return async (issue: Issue, suspects: readonly SuspectFile[] = []): Promise<PlanVetDecision> => {
    try {
      const v = analyzeConsequences(issue, suspects);
      // Currency-aware: every plan gets a date + staleness verdict (sovereign; offline by default).
      const currency = await checkCurrency(issue.text, temporal, catalog, deps.currencyResearch);
      // Consequence analysis governs cleared/block; a stale-currency finding downgrades pass → rework
      // (flag + route, never silently rewrite). verify-currency annotates but does not block a clean plan.
      const consequenceDecision = v.decision === "block" ? "block" : v.decision === "escalate" ? "rework" : "pass";
      const decision = currency.decision === "stale" && consequenceDecision === "pass" ? "rework" : consequenceDecision;
      const cleared = decision === "pass" && currency.decision !== "stale";
      const reason = currency.decision === "stale" ? `${v.reason}; CURRENCY: ${currency.reason}` : v.reason;
      return { cleared, decision, reason, consequences: v, currency };
    } catch (e) {
      return { cleared: false, decision: "block", reason: `plan vetting errored — fail-closed: ${(e as Error).message}` };
    }
  };
}
