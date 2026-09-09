/**
 * R32 — cross-process taint-tracer (tracer-interface seam + in-env propagation logic).
 *
 * Effect provenance-gating (`effect_provenance.ts`) vetoes an untrusted-derived effect at the gate,
 * but today the trust labels are CALLER-SUPPLIED. A real tracer must (1) LABEL untrusted content at
 * every boundary (tool output, fetched page, external issue text) and (2) PROPAGATE the label through
 * every transformation, so `effectProvenance` is fed real origin labels and nothing untrusted-derived
 * reaches a privileged effect unlabeled.
 *
 * DISCIPLINE (research, 2026-08-09):
 *  - DIFT: taint SOURCES (untrusted inputs are seeded tainted), taint TRACKER (any operation on
 *    tainted data yields tainted output — "the output is tainted if the input is tainted"), taint
 *    SINKS (a privileged effect reached by tainted data is trapped). Conservative "any" propagation.
 *  - Declassification = sanitization, but AUTHORITY-GATED here (reusing effect_provenance): taint
 *    clears ONLY via an authorized trusted step; the agent CANNOT self-declassify (no self-sanitize).
 *  - Over-taint vs under-taint: Keep errs toward OVER-taint (a missing/unknown label ⇒ untrusted,
 *    fail-safe) — a false gate is a human-hold, not a breach.
 *  - CaMeL / dual-LLM: untrusted data may INFLUENCE a proposal but must not CHOOSE a privileged
 *    action — the gate (privileged) consumes the label and vetoes untrusted-derived effects.
 *
 * BUILT vs SEAM: BUILT + proven in-env is the `Labeled<T>` propagation (seed, map, combine, authorized
 * declassify) + `toProvenance` feeding `effectProvenance`. The real CROSS-PROCESS INTERCEPTION — the
 * `TaintInterceptor` that stamps labels at actual tool/network boundaries and carries them through a
 * real agent's dataflow (runtime instrumentation / a CaMeL-style quarantined executor) — is the SEAM
 * (R32), the OS/runtime-enforcement family of R3/R27/R35.
 *
 * WHAT WOULD CHANGE IT: a permissive LLM-IFC label-propagation (a bounded extraction from untrusted
 * context allowed where an unconstrained string is not) refines the rule; it never lets an
 * unauthorized declassification clear taint.
 */

import type { InputProvenance, TrustLabel } from "./effect_provenance.js";

export type Taint = "trusted" | "untrusted";

/** A value carrying its taint label + the sources it was derived from. */
export interface Labeled<T> {
  readonly value: T;
  readonly taint: Taint;
  readonly sources: readonly string[];
}

/** Seed a TRUSTED value (an internal/operator origin). */
export function trusted<T>(value: T, source = "internal"): Labeled<T> {
  return { value, taint: "trusted", sources: [source] };
}

/** Seed a TAINTED value at an untrusted boundary (tool output, fetched page, external issue). */
export function tainted<T>(value: T, source: string): Labeled<T> {
  return { value, taint: "untrusted", sources: [source] };
}

/** Propagate through a unary transform: the result carries the SAME taint (DIFT "any" rule). */
export function mapL<T, U>(l: Labeled<T>, f: (v: T) => U): Labeled<U> {
  return { value: f(l.value), taint: l.taint, sources: l.sources };
}

/** Conservative join: the result is untrusted if ANY input is untrusted (least-trusted). */
export function combine<T>(inputs: ReadonlyArray<Labeled<unknown>>, value: T): Labeled<T> {
  const anyUntrusted = inputs.some((i) => i.taint !== "trusted"); // unknown/other ⇒ not trusted
  const sources = inputs.flatMap((i) => i.sources);
  return { value, taint: anyUntrusted ? "untrusted" : "trusted", sources };
}

/** An authorized declassification — only a trusted principal's authorized step clears taint. */
export interface Authority {
  readonly by: string;
  readonly authorized: boolean; // the agent cannot set this true
  readonly reason: string;
}

/**
 * Declassify: clear taint ONLY with an AUTHORIZED authority. An unauthorized attempt (the agent
 * "sanitizing" its own untrusted data) is IGNORED — the value stays tainted.
 */
export function declassify<T>(l: Labeled<T>, authority: Authority): Labeled<T> {
  if (l.taint === "trusted") return l;
  if (authority.authorized === true) {
    return { value: l.value, taint: "trusted", sources: [...l.sources, `declassified-by:${authority.by}`] };
  }
  return l; // unauthorized self-declassify ignored
}

/** Convert labeled inputs into the `InputProvenance[]` that `effectProvenance` consumes. */
export function toProvenance(inputs: ReadonlyArray<Labeled<unknown>>): InputProvenance[] {
  return inputs.map((i) => {
    const trust: TrustLabel = i.taint === "trusted" ? "trusted" : "untrusted";
    return { source: i.sources[0] ?? "unknown", trust };
  });
}

/**
 * The tracer SEAM — a real deployment implements this to intercept untrusted boundaries. `label`
 * stamps content entering from `source` as tainted (or trusted for an internal origin). The in-env
 * stub simply seeds; a real interceptor hooks tool calls / web fetches / issue intake.
 */
export interface TaintInterceptor {
  label(source: string, content: string): Labeled<string>;
}

/** In-env stub interceptor: labels a fixed set of boundary sources untrusted, everything else trusted. */
export class StubInterceptor implements TaintInterceptor {
  constructor(private readonly untrustedSources: ReadonlySet<string> = new Set(["tool", "web_fetch", "issue:external"])) {}
  label(source: string, content: string): Labeled<string> {
    return this.untrustedSources.has(source) ? tainted(content, source) : trusted(content, source);
  }
}
